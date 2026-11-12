// Command filecap sets, prints and verifies Linux file capabilities (the
// security.capability extended attribute) without libcap.
//
// The container image's build stage uses it in place of setcap(8): the Go
// build image has no libcap2-bin, and installing it would make the image
// build depend on a Debian mirror being reachable and on whatever package
// version it serves that day. What it writes is byte for byte what
// `setcap cap_dac_read_search,cap_sys_ptrace=ep FILE` writes: a revision-2
// vfs_cap_data record (linux/capability.h), so getcap(8) and the kernel read
// it the same way (filecap_test.go holds the bytes setcap produced).
//
//	filecap set    cap_dac_read_search,cap_sys_ptrace=ep FILE...
//	filecap verify cap_dac_read_search,cap_sys_ptrace=ep FILE...
//	filecap get    FILE...
//	filecap clear  FILE...
//
// Only the single-clause text form is accepted (a comma-separated list, one
// operator "=" or "+", flags from "eip"); anything else is refused rather
// than half understood. Revision-3 records (a namespaced root uid) are read
// but never written: the image is built for the initial user namespace.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Constants from linux/capability.h.
const (
	xattrName = "security.capability"

	revisionMask = 0xFF000000
	revision2    = 0x02000000
	revision3    = 0x03000000
	flagEffect   = 0x000001

	sizeRev2 = 4 * (1 + 2*2) // magic_etc + 2 x {permitted, inheritable}
	sizeRev3 = sizeRev2 + 4  // + rootid
)

// capNames is the kernel's capability numbering (include/uapi/linux/capability.h),
// index = capability number.
var capNames = []string{
	"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
	"cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
	"cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
	"cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
	"cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
	"cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
	"cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
	"cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
	"cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
	"cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
	"cap_checkpoint_restore",
}

// Set is one file capability record.
type Set struct {
	Permitted   uint64
	Inheritable uint64
	Effective   bool   // the single effective bit: raise every permitted cap at exec
	RootID      uint32 // revision 3 only
	Revision    int    // 2 or 3 (decoded); Encode always writes 2
}

func capNumber(name string) (int, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "cap_") {
		n = "cap_" + n
	}
	for i, c := range capNames {
		if c == n {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown capability %q", name)
}

// Parse reads the single-clause text form, for example
// "cap_dac_read_search,cap_sys_ptrace=ep".
func Parse(text string) (Set, error) {
	var s Set
	i := strings.IndexAny(text, "=+")
	if i <= 0 {
		return s, fmt.Errorf("capability text %q: want <caps>=<flags>, e.g. cap_sys_ptrace=ep", text)
	}
	list, flags := text[:i], text[i+1:]
	if strings.ContainsAny(flags, "=+- \t") {
		return s, fmt.Errorf("capability text %q: only one clause is supported", text)
	}
	var mask uint64
	for _, name := range strings.Split(list, ",") {
		n, err := capNumber(name)
		if err != nil {
			return s, err
		}
		mask |= 1 << uint(n)
	}
	if flags == "" {
		return s, fmt.Errorf("capability text %q: no flags (e, i, p)", text)
	}
	for _, f := range flags {
		switch f {
		case 'e':
			s.Effective = true
		case 'i':
			s.Inheritable |= mask
		case 'p':
			s.Permitted |= mask
		default:
			return s, fmt.Errorf("capability text %q: unknown flag %q", text, f)
		}
	}
	if s.Effective && s.Permitted == 0 && s.Inheritable == 0 {
		return s, fmt.Errorf("capability text %q: effective without permitted or inheritable", text)
	}
	s.Revision = 2
	return s, nil
}

// Encode returns the revision-2 xattr value.
func (s Set) Encode() []byte {
	b := make([]byte, sizeRev2)
	magic := uint32(revision2)
	if s.Effective {
		magic |= flagEffect
	}
	binary.LittleEndian.PutUint32(b[0:], magic)
	binary.LittleEndian.PutUint32(b[4:], uint32(s.Permitted))
	binary.LittleEndian.PutUint32(b[8:], uint32(s.Inheritable))
	binary.LittleEndian.PutUint32(b[12:], uint32(s.Permitted>>32))
	binary.LittleEndian.PutUint32(b[16:], uint32(s.Inheritable>>32))
	return b
}

// Decode parses a security.capability value (revision 2 or 3).
func Decode(b []byte) (Set, error) {
	var s Set
	if len(b) < 4 {
		return s, errors.New("capability record too short")
	}
	magic := binary.LittleEndian.Uint32(b)
	switch magic & revisionMask {
	case revision2:
		if len(b) != sizeRev2 {
			return s, fmt.Errorf("revision-2 capability record of %d bytes, want %d", len(b), sizeRev2)
		}
		s.Revision = 2
	case revision3:
		if len(b) != sizeRev3 {
			return s, fmt.Errorf("revision-3 capability record of %d bytes, want %d", len(b), sizeRev3)
		}
		s.Revision = 3
		s.RootID = binary.LittleEndian.Uint32(b[20:])
	default:
		return s, fmt.Errorf("unsupported capability revision %#x", magic&revisionMask)
	}
	if magic&^(revisionMask|flagEffect) != 0 {
		return s, fmt.Errorf("unknown capability flags %#x", magic&^revisionMask)
	}
	s.Effective = magic&flagEffect != 0
	s.Permitted = uint64(binary.LittleEndian.Uint32(b[4:])) | uint64(binary.LittleEndian.Uint32(b[12:]))<<32
	s.Inheritable = uint64(binary.LittleEndian.Uint32(b[8:])) | uint64(binary.LittleEndian.Uint32(b[16:]))<<32
	return s, nil
}

func names(mask uint64) []string {
	var out []string
	for i := 0; i < 64; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		if i < len(capNames) {
			out = append(out, capNames[i])
		} else {
			out = append(out, fmt.Sprintf("%d", i))
		}
	}
	return out
}

// String renders the record as getcap(8) does for the common case: the caps
// that share one flag set joined by commas, then "=" and the flags in e, i,
// p order. Caps with different flag sets are rendered as separate clauses.
func (s Set) String() string {
	// Clauses in the order of their lowest capability number.
	groups := map[string][]string{}
	var order []string
	all := s.Permitted | s.Inheritable
	for i := 0; i < 64; i++ {
		bit := uint64(1) << uint(i)
		if all&bit == 0 {
			continue
		}
		var f strings.Builder
		if s.Effective {
			f.WriteByte('e')
		}
		if s.Inheritable&bit != 0 {
			f.WriteByte('i')
		}
		if s.Permitted&bit != 0 {
			f.WriteByte('p')
		}
		k := f.String()
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], names(bit)...)
	}
	clauses := make([]string, 0, len(order))
	for _, k := range order {
		clauses = append(clauses, strings.Join(groups[k], ",")+"="+k)
	}
	return strings.Join(clauses, " ")
}

// Equal compares the parts that decide what exec grants.
func (s Set) Equal(o Set) bool {
	return s.Permitted == o.Permitted && s.Inheritable == o.Inheritable && s.Effective == o.Effective && s.RootID == o.RootID
}
