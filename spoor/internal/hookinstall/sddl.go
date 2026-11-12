package hookinstall

import (
	"strconv"
	"strings"
)

// The Windows permission check works on the SDDL text of a security
// descriptor so that the rules can be tested on any OS; only fetching the
// descriptor needs Windows.

// adminSIDs may own, and hold write access to, a managed file: SYSTEM,
// the Administrators group, TrustedInstaller, domain and enterprise admins.
var adminSIDs = map[string]bool{
	"SY": true, "S-1-5-18": true,
	"BA": true, "S-1-5-32-544": true,
	"DA": true, "EA": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
}

// writeMask is every access right that lets its holder change a file, a
// directory's contents or the descriptor itself: FILE_WRITE_DATA (add
// file), FILE_APPEND_DATA (add sub-directory), FILE_WRITE_EA,
// FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER,
// GENERIC_WRITE and GENERIC_ALL.
const writeMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000

// sddlRights are the two-letter access mnemonics SDDL uses for files.
var sddlRights = map[string]uint32{
	"GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
	"RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000,
	"FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
}

// sddlProblem explains why a descriptor lets a non-admin change the object,
// or returns "". Anything it cannot parse is reported as a problem: an
// unreadable ACL must not pass as a safe one.
func sddlProblem(sddl string) string {
	owner, dacl, ok := splitSDDL(sddl)
	if !ok {
		return "has a security descriptor that cannot be parsed"
	}
	if owner != "" && !adminSIDs[owner] {
		return "is owned by " + owner + ", not by Administrators or SYSTEM"
	}
	if dacl == "" {
		return "has no DACL (everyone has full control)"
	}
	for _, ace := range sddlACEs(dacl) {
		f := strings.Split(ace, ";")
		if len(f) < 6 {
			return "has an access control entry that cannot be parsed"
		}
		typ, flags, rights, sid := f[0], f[1], f[2], f[5]
		if typ != "A" && typ != "OA" && typ != "XA" {
			continue // deny, audit and label entries grant nothing
		}
		if adminSIDs[sid] {
			continue
		}
		// An inherit-only entry does not apply to this object. CREATOR
		// OWNER entries are of this kind; the children they would apply to
		// are checked on their own.
		if strings.Contains(flags, "IO") {
			continue
		}
		mask, ok := sddlMask(rights)
		if !ok {
			return "has an access control entry that cannot be parsed"
		}
		if mask&writeMask != 0 {
			return "grants write access to " + sid
		}
	}
	return ""
}

// splitSDDL extracts the owner SID and the DACL body.
func splitSDDL(s string) (owner, dacl string, ok bool) {
	if len(s) > 64<<10 {
		return "", "", false
	}
	idx := func(tag string) int {
		// Section tags are "O:", "G:", "D:" and "S:" outside parentheses.
		depth := 0
		for i := 0; i+1 < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 && s[i] == tag[0] && s[i+1] == ':' && (i == 0 || s[i-1] != '-') {
				return i
			}
		}
		return -1
	}
	end := func(from int) int {
		best := len(s)
		for _, tag := range []string{"O", "G", "D", "S"} {
			if j := idx(tag); j > from && j < best {
				best = j
			}
		}
		return best
	}
	if i := idx("O"); i >= 0 {
		owner = s[i+2 : end(i)]
	}
	i := idx("D")
	if i < 0 {
		return owner, "", true
	}
	dacl = s[i+2 : end(i)]
	if !strings.Contains(dacl, "(") {
		// "D:" followed only by flags is an empty DACL: nobody but the
		// owner has access, which is safe.
		return owner, "()", true
	}
	return owner, dacl, true
}

func sddlACEs(dacl string) []string {
	var out []string
	for {
		i := strings.IndexByte(dacl, '(')
		if i < 0 {
			return out
		}
		j := strings.IndexByte(dacl[i:], ')')
		if j < 0 {
			return append(out, "")
		}
		if body := dacl[i+1 : i+j]; body != "" {
			out = append(out, body)
		}
		dacl = dacl[i+j+1:]
	}
}

func sddlMask(rights string) (uint32, bool) {
	if strings.HasPrefix(rights, "0x") || strings.HasPrefix(rights, "0X") {
		v, err := strconv.ParseUint(rights[2:], 16, 32)
		return uint32(v), err == nil
	}
	if len(rights)%2 != 0 {
		return 0, false
	}
	var mask uint32
	for i := 0; i < len(rights); i += 2 {
		bits, ok := sddlRights[rights[i:i+2]]
		if !ok {
			return 0, false
		}
		mask |= bits
	}
	return mask, true
}
