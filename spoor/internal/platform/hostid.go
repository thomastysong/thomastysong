package platform

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// EnvHostID overrides the host id for this process.
const EnvHostID = "SPOOR_HOST_ID"

// EnvHostName overrides the host name for this process. In a Kubernetes pod
// the kernel's host name is the pod's name, not the node's; the node sensor
// DaemonSet sets this from spec.nodeName (the downward API), as it does
// SPOOR_HOST_ID. A value that is not a plausible host name (empty, longer
// than 253 bytes, characters outside letters, digits and "-_.") is ignored.
const EnvHostName = "SPOOR_HOST_NAME"

// maxHostNameLen is the longest DNS name (RFC 1035 as Kubernetes applies it
// to node names).
const maxHostNameLen = 253

// HostIDFileName is the override file inside the config directory. The
// osquery extension writes osquery's own system_info.uuid there (see
// WriteHostIDFile) so that every spoor process, privileged or not, reports
// the id Fleet already knows for the host.
const HostIDFileName = "host_id"

// Values returned by HostIDSource.
const (
	HostIDSourceEnv         = "env"         // SPOOR_HOST_ID
	HostIDSourceFile        = "file"        // <config dir>/host_id
	HostIDSourceDMI         = "dmi"         // Linux /sys/class/dmi/id/product_uuid
	HostIDSourceMachineID   = "machine-id"  // Linux /etc/machine-id, formatted as a UUID
	HostIDSourceGetHostUUID = "gethostuuid" // macOS gethostuuid(2), the call osquery makes
	HostIDSourceIOReg       = "ioreg"       // macOS IOPlatformUUID read through /usr/sbin/ioreg
	HostIDSourceSMBIOS      = "smbios"      // Windows SMBIOS system UUID (what WMI reports)
	HostIDSourceMachineGUID = "machineguid" // Windows HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
	HostIDSourceNone        = "none"        // nothing derivable; Host.ID is empty
)

const (
	maxHostIDLen = 128
	// A daemon must notice a host_id file written after it started, and a
	// transient failure of the hardware lookup must not stick forever, but
	// HostInfo is called per event: so both are cached, briefly.
	hostIDCacheTTL = 30 * time.Second
)

// placeholderUUIDs are firmware defaults shared by many machines. The list is
// osquery's kPlaceholderHardwareUUIDList (osquery/core/system.cpp, Apache-2.0):
// osquery refuses them and generates a random id instead, so using one here
// would both collide across hosts and fail to join.
var placeholderUUIDs = map[string]bool{
	"00000000-0000-0000-0000-000000000000": true,
	"03000200-0400-0500-0006-000700080009": true,
	"03020100-0504-0706-0809-0a0b0c0d0e0f": true,
	"10000000-0000-8000-0040-000000000000": true,
	// Not in osquery's list: SMBIOS "not present". Worthless as a join key.
	"ffffffff-ffff-ffff-ffff-ffffffffffff": true,
}

type hostIDOverrideFile struct {
	path string
	// system marks the admin-owned config directory; the other candidate is
	// the per-user directory used when spoor runs without privilege.
	system bool
}

// Seams for tests.
var (
	hostIDOverrideFiles = defaultHostIDOverrideFiles
	hostIDPlatform      = platformHostID
	hostIDNow           = time.Now
)

var hostIDState struct {
	sync.Mutex
	fileChecked bool
	fileAt      time.Time
	fileID      string
	platChecked bool
	platAt      time.Time
	platID      string
	platSrc     string
}

// HostInfo identifies this endpoint. ID equals osquery's system_info.uuid
// wherever spoor can derive the same value on its own (see HostIDSource), so
// events join to Fleet hosts. ID is empty when nothing is derivable.
func HostInfo() event.Host {
	id, _ := resolveHostID()
	return event.Host{ID: id, Name: hostName(), OS: runtime.GOOS, Arch: runtime.GOARCH}
}

// hostName is SPOOR_HOST_NAME when it is set to a plausible name, else the
// kernel's host name. Like SPOOR_HOST_ID it is only as trustworthy as the
// process environment: a privileged daemon reads its own (set by the
// service manager or the pod spec), never a hook client's.
func hostName() string {
	if v := sanitizeHostName(os.Getenv(EnvHostName)); v != "" {
		return v
	}
	name, _ := os.Hostname()
	return name
}

func sanitizeHostName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxHostNameLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return ""
		}
	}
	return s
}

// HostIDSource reports where the id returned by HostInfo came from: one of
// the HostIDSource* constants.
func HostIDSource() string {
	_, src := resolveHostID()
	return src
}

func resolveHostID() (id, src string) {
	defer func() {
		if r := recover(); r != nil {
			id, src = "", HostIDSourceNone
		}
	}()
	if v := sanitizeHostID(os.Getenv(EnvHostID)); v != "" {
		return v, HostIDSourceEnv
	}
	st := &hostIDState
	st.Lock()
	defer st.Unlock()
	now := hostIDNow()
	if !st.fileChecked || now.Sub(st.fileAt) >= hostIDCacheTTL || now.Before(st.fileAt) {
		st.fileID = ""
		for _, f := range hostIDOverrideFiles() {
			if v := readHostIDFile(f); v != "" {
				st.fileID = v
				break
			}
		}
		st.fileChecked, st.fileAt = true, now
	}
	if st.fileID != "" {
		return st.fileID, HostIDSourceFile
	}
	// Hardware ids do not change, so a hit is kept for the process lifetime.
	if !st.platChecked || (st.platID == "" && (now.Sub(st.platAt) >= hostIDCacheTTL || now.Before(st.platAt))) {
		st.platID, st.platSrc = hostIDPlatform()
		st.platChecked, st.platAt = true, now
	}
	if st.platID == "" {
		return "", HostIDSourceNone
	}
	return st.platID, st.platSrc
}

func resetHostIDCache() {
	st := &hostIDState
	st.Lock()
	defer st.Unlock()
	st.fileChecked, st.fileID = false, ""
	st.platChecked, st.platID, st.platSrc = false, "", ""
}

func defaultHostIDOverrideFiles() []hostIDOverrideFile {
	files := []hostIDOverrideFile{{path: filepath.Join(DefaultDirs().Config, HostIDFileName), system: true}}
	// A root process never reads an id from a directory a user can write.
	if !IsPrivileged() {
		if cfg := UserDirs("").Config; cfg != "" {
			files = append(files, hostIDOverrideFile{path: filepath.Join(cfg, HostIDFileName)})
		}
	}
	return files
}

func readHostIDFile(f hostIDOverrideFile) string {
	fh, err := OpenNoFollow(f.path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil || !hostIDFileTrusted(fi, f.system) {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(fh, 2*maxHostIDLen))
	if err != nil {
		return ""
	}
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	return sanitizeHostID(string(b))
}

// WriteHostIDFile stores id as the host id override in configDir, replacing
// any previous value atomically. It is meant for the component that can ask
// osquery for system_info.uuid directly.
func WriteHostIDFile(configDir, id string) error {
	clean := sanitizeHostID(id)
	if clean == "" || clean != strings.TrimSpace(id) {
		return errors.New("platform: host id must be 1-128 characters of [A-Za-z0-9._:-]")
	}
	if configDir == "" {
		return errors.New("platform: empty config directory")
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(configDir, "."+HostIDFileName+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.WriteString(clean + "\n"); err != nil {
		return fail(err)
	}
	// Unprivileged hook processes read this file, so it must be world-readable.
	if err := tmp.Chmod(0o644); err != nil && runtime.GOOS != "windows" {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(configDir, HostIDFileName)); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// sanitizeHostID accepts an id only if it is short and made of characters
// that are safe in file names, log lines and query strings. The id ends up
// in every record, so a hostile override must not be able to smuggle
// separators or control characters downstream.
func sanitizeHostID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxHostIDLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == ':':
		default:
			return ""
		}
	}
	return s
}

// isUUID reports whether s has the 8-4-4-4-12 hexadecimal shape.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// cleanHardwareUUID returns a firmware UUID exactly as the OS printed it
// (osquery reports it verbatim, so case is preserved), or "" when it is
// malformed or a known placeholder.
func cleanHardwareUUID(s string) string {
	s = strings.TrimSpace(strings.TrimRight(s, "\x00"))
	if !isUUID(s) || placeholderUUIDs[strings.ToLower(s)] {
		return ""
	}
	return s
}

// machineIDToUUID formats the 32 hex digits of /etc/machine-id as a UUID.
func machineIDToUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	id := s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
	if placeholderUUIDs[id] {
		return ""
	}
	return id
}

// formatUUID renders 16 bytes as a UUID. mixedEndian decodes the first three
// fields as little-endian, the Windows GUID layout SMBIOS 2.6+ uses.
func formatUUID(b []byte, mixedEndian, upper bool) string {
	if len(b) != 16 {
		return ""
	}
	var u [16]byte
	copy(u[:], b)
	if mixedEndian {
		u[0], u[1], u[2], u[3] = b[3], b[2], b[1], b[0]
		u[4], u[5] = b[5], b[4]
		u[6], u[7] = b[7], b[6]
	}
	var out [36]byte
	hex.Encode(out[0:8], u[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], u[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], u[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], u[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], u[10:16])
	if upper {
		return strings.ToUpper(string(out[:]))
	}
	return string(out[:])
}

// parseIORegUUID extracts IOPlatformUUID from the output of
// `ioreg -rd1 -c IOPlatformExpertDevice`, whose relevant line reads
//
//	"IOPlatformUUID" = "9C6E5B4A-0000-5000-8000-0123456789AB"
func parseIORegUUID(out []byte) string {
	const key = `"IOPlatformUUID"`
	i := bytes.Index(out, []byte(key))
	if i < 0 {
		return ""
	}
	rest := out[i+len(key):]
	if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	q1 := bytes.IndexByte(rest, '"')
	if q1 < 0 {
		return ""
	}
	rest = rest[q1+1:]
	q2 := bytes.IndexByte(rest, '"')
	if q2 < 0 {
		return ""
	}
	return cleanHardwareUUID(string(rest[:q2]))
}

// smbiosSystemUUID finds the System Information (type 1) structure in the
// buffer GetSystemFirmwareTable('RSMB') returns and formats its UUID the way
// WMI's Win32_ComputerSystemProduct.UUID does, which is what osquery reports
// on Windows.
//
// The buffer is RawSMBIOSData: 4 one-byte fields, a little-endian uint32
// table length, then the structure table. Each structure is a formatted area
// (type, length, handle, ...) followed by a string set ending in two NULs.
func smbiosSystemUUID(raw []byte) string {
	const header = 8
	if len(raw) < header {
		return ""
	}
	table := raw[header:]
	if n := int(binary.LittleEndian.Uint32(raw[4:8])); n >= 0 && n < len(table) {
		table = table[:n]
	}
	for steps := 0; len(table) >= 4 && steps < 4096; steps++ {
		typ, length := table[0], int(table[1])
		if length < 4 || length > len(table) {
			return ""
		}
		switch typ {
		case 1:
			// The UUID field (offset 8, 16 bytes) exists from SMBIOS 2.1 on.
			if length < 0x18 {
				return ""
			}
			// UNVERIFIED: WMI is assumed to decode the first three fields as
			// little-endian for every SMBIOS version (dmidecode only does so
			// from 2.6). Firmware older than 2.6 may therefore disagree.
			return cleanHardwareUUID(formatUUID(table[8:24], true, true))
		case 127: // end-of-table
			return ""
		}
		rest := table[length:]
		end := bytes.Index(rest, []byte{0, 0})
		if end < 0 {
			return ""
		}
		table = rest[end+2:]
	}
	return ""
}
