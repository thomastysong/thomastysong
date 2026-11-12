package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSanitizeHostID(t *testing.T) {
	long := strings.Repeat("a", maxHostIDLen)
	tests := []struct {
		name, in, want string
	}{
		{"uuid lower", "ba50cad6-e350-4b92-847f-5b8df3181131", "ba50cad6-e350-4b92-847f-5b8df3181131"},
		{"uuid upper kept", "9C6E5B4A-1234-5678-9ABC-0123456789AB", "9C6E5B4A-1234-5678-9ABC-0123456789AB"},
		{"hostname", "build-01.corp.example", "build-01.corp.example"},
		{"trimmed", "  abc_1:2 \n", "abc_1:2"},
		{"max length", long, long},
		{"too long", long + "a", ""},
		{"empty", "", ""},
		{"only space", " \t\n", ""},
		{"inner space", "a b", ""},
		{"inner newline", "a\nb", ""},
		{"json injection", `x","admin":"1`, ""},
		{"path traversal", "../../etc/passwd", ""},
		{"nul", "abc\x00def", ""},
		{"invalid utf8", "abc\xff\xfe", ""},
		{"non ascii", "höst", ""},
		{"shell", "$(id)", ""},
	}
	for _, tt := range tests {
		if got := sanitizeHostID(tt.in); got != tt.want {
			t.Errorf("%s: sanitizeHostID(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestCleanHardwareUUID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"4c4c4544-0042-3510-8054-b9c04f4d3233\n", "4c4c4544-0042-3510-8054-b9c04f4d3233"},
		{"4C4C4544-0042-3510-8054-B9C04F4D3233", "4C4C4544-0042-3510-8054-B9C04F4D3233"}, // case is osquery's, verbatim
		{" 4c4c4544-0042-3510-8054-b9c04f4d3233 \x00", "4c4c4544-0042-3510-8054-b9c04f4d3233"},
		// osquery's placeholder list, in either case.
		{"00000000-0000-0000-0000-000000000000", ""},
		{"03000200-0400-0500-0006-000700080009", ""},
		{"03020100-0504-0706-0809-0A0B0C0D0E0F", ""},
		{"10000000-0000-8000-0040-000000000000", ""},
		{"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", ""},
		{"", ""},
		{"Not Settable", ""},
		{"4c4c4544-0042-3510-8054-b9c04f4d323", ""},   // short
		{"4c4c4544-0042-3510-8054-b9c04f4d32333", ""}, // long
		{"4c4c4544_0042_3510_8054_b9c04f4d3233", ""},
		{"zc4c4544-0042-3510-8054-b9c04f4d3233", ""},
		{strings.Repeat("a", 1<<20), ""},
	}
	for _, tt := range tests {
		if got := cleanHardwareUUID(tt.in); got != tt.want {
			t.Errorf("cleanHardwareUUID(%.40q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMachineIDToUUID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"d165c2d88d894a4787be219662b439ad\n", "d165c2d8-8d89-4a47-87be-219662b439ad"},
		{"D165C2D88D894A4787BE219662B439AD", "d165c2d8-8d89-4a47-87be-219662b439ad"},
		{"uninitialized\n", ""}, // systemd's first-boot marker
		{"", ""},
		{"00000000000000000000000000000000", ""},
		{"d165c2d88d894a4787be219662b439a", ""},
		{"d165c2d88d894a4787be219662b439adff", ""},
		{"g165c2d88d894a4787be219662b439ad", ""},
		{"d165c2d8-8d89-4a47-87be-219662b439ad", ""}, // already dashed: not a machine-id
	}
	for _, tt := range tests {
		if got := machineIDToUUID(tt.in); got != tt.want {
			t.Errorf("machineIDToUUID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFormatUUID(t *testing.T) {
	b := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got, want := formatUUID(b, false, false), "00112233-4455-6677-8899-aabbccddeeff"; got != want {
		t.Errorf("big-endian: %q, want %q", got, want)
	}
	if got, want := formatUUID(b, true, true), "33221100-5544-7766-8899-AABBCCDDEEFF"; got != want {
		t.Errorf("mixed-endian: %q, want %q", got, want)
	}
	if got := formatUUID(b[:15], false, false); got != "" {
		t.Errorf("short input: %q", got)
	}
	if b[0] != 0x00 || b[3] != 0x33 {
		t.Error("formatUUID modified its input")
	}
}

// ioregFixture is the shape `ioreg -rd1 -c IOPlatformExpertDevice` prints.
const ioregFixture = `+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000263, registered, matched, active, busy 0 (51 ms), retain 40>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOBusyInterest" = "IOCommand is not serializable"
      "target-type" = <"J314s">
      "IOPlatformUUID" = "9C6E5B4A-1234-5678-9ABC-0123456789AB"
      "manufacturer" = <"Apple Inc.">
    }
`

func TestParseIORegUUID(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"fixture", ioregFixture, "9C6E5B4A-1234-5678-9ABC-0123456789AB"},
		{"no key", `"IOPlatformSerialNumber" = "C02"`, ""},
		{"empty", "", ""},
		{"no value", `"IOPlatformUUID" = `, ""},
		{"unterminated", `"IOPlatformUUID" = "9C6E5B4A-1234-5678-9ABC-0123456789AB`, ""},
		{"value on next line is not taken", "\"IOPlatformUUID\" =\n\"9C6E5B4A-1234-5678-9ABC-0123456789AB\"", ""},
		{"placeholder", `"IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"`, ""},
		{"garbage value", `"IOPlatformUUID" = "$(reboot)"`, ""},
		{"binary", "\x00\xff\"IOPlatformUUID\"\xff\xfe", ""},
	}
	for _, tt := range tests {
		if got := parseIORegUUID([]byte(tt.in)); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

// smbiosStructure builds one SMBIOS structure: formatted area then strings.
func smbiosStructure(typ byte, formatted []byte, strs ...string) []byte {
	out := []byte{typ, byte(4 + len(formatted)), 0x10, 0x00}
	out = append(out, formatted...)
	if len(strs) == 0 {
		return append(out, 0, 0)
	}
	for _, s := range strs {
		out = append(out, s...)
		out = append(out, 0)
	}
	return append(out, 0)
}

func rawSMBIOSFixture(structures ...[]byte) []byte {
	var table []byte
	for _, s := range structures {
		table = append(table, s...)
	}
	n := len(table)
	raw := []byte{0, 3, 2, 0, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	return append(raw, table...)
}

func TestSMBIOSSystemUUID(t *testing.T) {
	uuid := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	system := func(u []byte) []byte {
		f := []byte{1, 2, 3, 4} // manufacturer, product, version, serial string indexes
		f = append(f, u...)
		f = append(f, 6, 5, 6) // wake-up type, SKU, family
		return smbiosStructure(1, f, "Vendor", "Model", "1.0", "SN123", "SKU", "Family")
	}
	bios := smbiosStructure(0, make([]byte, 0x14), "BIOS Vendor", "1.2.3", "01/01/2026")
	end := smbiosStructure(127, nil)

	if got, want := smbiosSystemUUID(rawSMBIOSFixture(bios, system(uuid), end)), "33221100-5544-7766-8899-AABBCCDDEEFF"; got != want {
		t.Errorf("uuid = %q, want %q", got, want)
	}
	// A structure with no strings ends in a bare double NUL.
	if got := smbiosSystemUUID(rawSMBIOSFixture(smbiosStructure(0, make([]byte, 0x14)), system(uuid))); got == "" {
		t.Error("structure without strings broke the walk")
	}

	zero := make([]byte, 16)
	ff := []byte(strings.Repeat("\xff", 16))
	hostile := map[string][]byte{
		"empty":             nil,
		"header only":       {0, 3, 2, 0, 0, 0, 0, 0},
		"short header":      {0, 3, 2},
		"no type 1":         rawSMBIOSFixture(bios, end),
		"end before type 1": rawSMBIOSFixture(end, system(uuid)),
		"all zero uuid":     rawSMBIOSFixture(system(zero)),
		"all ff uuid":       rawSMBIOSFixture(system(ff)),
		"smbios 2.0 type 1": rawSMBIOSFixture(smbiosStructure(1, []byte{1, 2, 3, 4}, "a")),
		"length below 4":    rawSMBIOSFixture([]byte{1, 2, 0, 0, 0, 0}),
		"length past end":   rawSMBIOSFixture([]byte{1, 0xff, 0, 0, 1, 2, 3}),
		"no terminator":     rawSMBIOSFixture(append(smbiosStructure(0, make([]byte, 0x14))[:0x18], 'x', 'y')),
		"length field lies": append([]byte{0, 3, 2, 0, 0xff, 0xff, 0xff, 0x7f}, system(zero)...),
		"all 0x01":          []byte(strings.Repeat("\x01", 4096)),
		"zeros":             make([]byte, 1<<16),
	}
	for name, raw := range hostile {
		if got := smbiosSystemUUID(raw); got != "" {
			t.Errorf("%s: got %q, want empty", name, got)
		}
	}
	// A table truncated by the declared length must not expose a later UUID.
	raw := rawSMBIOSFixture(bios, system(uuid))
	raw[4], raw[5] = byte(len(bios)), 0
	if got := smbiosSystemUUID(raw); got != "" {
		t.Errorf("read past declared table length: %q", got)
	}
}

// withHostIDSeams replaces the override files, the platform lookup and the
// clock for one test.
func withHostIDSeams(t *testing.T, files []hostIDOverrideFile, platform func() (string, string)) *time.Time {
	t.Helper()
	oldFiles, oldPlat, oldNow := hostIDOverrideFiles, hostIDPlatform, hostIDNow
	now := time.Unix(1_800_000_000, 0)
	hostIDOverrideFiles = func() []hostIDOverrideFile { return files }
	hostIDPlatform = platform
	hostIDNow = func() time.Time { return now }
	resetHostIDCache()
	t.Setenv(EnvHostID, "")
	t.Cleanup(func() {
		hostIDOverrideFiles, hostIDPlatform, hostIDNow = oldFiles, oldPlat, oldNow
		resetHostIDCache()
	})
	return &now
}

func TestHostIDResolutionOrder(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	plat := func() (string, string) { calls++; return "11111111-2222-3333-4444-555555555555", HostIDSourceDMI }
	now := withHostIDSeams(t, []hostIDOverrideFile{{path: filepath.Join(dir, HostIDFileName)}}, plat)

	if id, src := resolveHostID(); id != "11111111-2222-3333-4444-555555555555" || src != HostIDSourceDMI {
		t.Fatalf("platform: %q %q", id, src)
	}
	h := HostInfo()
	if h.ID != "11111111-2222-3333-4444-555555555555" || h.OS != runtime.GOOS || h.Arch != runtime.GOARCH {
		t.Errorf("HostInfo = %+v", h)
	}
	if HostIDSource() != HostIDSourceDMI {
		t.Errorf("HostIDSource = %q", HostIDSource())
	}
	if calls != 1 {
		t.Errorf("hardware id looked up %d times, want 1 (cached)", calls)
	}

	// The override file appears after start (the osquery extension wrote it):
	// it is picked up once the cache expires, not before.
	if err := WriteHostIDFile(dir, "ba50cad6-e350-4b92-847f-5b8df3181131"); err != nil {
		t.Fatal(err)
	}
	if id, _ := resolveHostID(); id != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("override applied before cache expiry: %q", id)
	}
	*now = now.Add(hostIDCacheTTL + time.Second)
	if id, src := resolveHostID(); id != "ba50cad6-e350-4b92-847f-5b8df3181131" || src != HostIDSourceFile {
		t.Errorf("file override: %q %q", id, src)
	}

	// The environment beats the file, immediately.
	t.Setenv(EnvHostID, " env-host-1 ")
	if id, src := resolveHostID(); id != "env-host-1" || src != HostIDSourceEnv {
		t.Errorf("env override: %q %q", id, src)
	}
	// A hostile value in the environment is ignored, not passed through.
	t.Setenv(EnvHostID, "evil\"},{\"x\":\"")
	if id, src := resolveHostID(); id != "ba50cad6-e350-4b92-847f-5b8df3181131" || src != HostIDSourceFile {
		t.Errorf("invalid env must fall through: %q %q", id, src)
	}
}

func TestHostIDNoneAndRetry(t *testing.T) {
	answer := ""
	calls := 0
	now := withHostIDSeams(t, nil, func() (string, string) {
		calls++
		if answer == "" {
			return "", HostIDSourceNone
		}
		return answer, HostIDSourceMachineID
	})
	if id, src := resolveHostID(); id != "" || src != HostIDSourceNone {
		t.Fatalf("got %q %q, want empty/none", id, src)
	}
	if h := HostInfo(); h.ID != "" {
		t.Errorf("HostInfo.ID = %q, want empty", h.ID)
	}
	resolveHostID()
	if calls != 1 {
		t.Errorf("failed lookup repeated within TTL: %d calls", calls)
	}
	// A transient failure must not stick for the life of the daemon.
	answer = "d165c2d8-8d89-4a47-87be-219662b439ad"
	*now = now.Add(hostIDCacheTTL + time.Second)
	if id, src := resolveHostID(); id != answer || src != HostIDSourceMachineID {
		t.Errorf("after retry: %q %q", id, src)
	}
	// A clock that jumps backwards must not freeze the cache forever.
	answer = ""
	resetHostIDCache()
	resolveHostID()
	answer = "d165c2d8-8d89-4a47-87be-219662b439ad"
	*now = now.Add(-time.Hour)
	if id, _ := resolveHostID(); id != answer {
		t.Errorf("after clock step back: %q", id)
	}
}

func TestHostIDPlatformPanicIsContained(t *testing.T) {
	withHostIDSeams(t, nil, func() (string, string) { panic("boom") })
	if id, src := resolveHostID(); id != "" || src != HostIDSourceNone {
		t.Errorf("got %q %q", id, src)
	}
	_ = HostInfo()
}

func TestHostIDFileHostileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, HostIDFileName)
	withHostIDSeams(t, []hostIDOverrideFile{{path: path}}, func() (string, string) { return "", HostIDSourceNone })
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{"plain", []byte("host-1\n"), "host-1"},
		{"crlf", []byte("host-2\r\n"), "host-2"},
		{"no newline", []byte("host-3"), "host-3"},
		{"second line ignored", []byte("host-4\nextra\n"), "host-4"},
		{"empty", nil, ""},
		{"spaces", []byte("a b\n"), ""},
		{"binary", []byte{0xff, 0xfe, 0x00, 0x01}, ""},
		{"huge", []byte(strings.Repeat("a", 1<<20)), ""},
		{"huge second line", []byte("host-5\n" + strings.Repeat("b", 1<<20)), "host-5"},
		{"traversal", []byte("../../etc/shadow\n"), ""},
	}
	for _, tt := range tests {
		if err := os.WriteFile(path, tt.content, 0o644); err != nil {
			t.Fatal(err)
		}
		resetHostIDCache()
		if id, _ := resolveHostID(); id != tt.want {
			t.Errorf("%s: id = %q, want %q", tt.name, id, tt.want)
		}
	}
}

func TestWriteHostIDFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "hawkbell")
	if err := WriteHostIDFile(dir, "ba50cad6-e350-4b92-847f-5b8df3181131"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, HostIDFileName)
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "ba50cad6-e350-4b92-847f-5b8df3181131\n" {
		t.Fatalf("content %q, err %v", b, err)
	}
	// Replacing is atomic and leaves no temp files behind.
	if err := WriteHostIDFile(dir, "second"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != HostIDFileName {
		t.Errorf("directory holds %v", entries)
	}
	if got := readHostIDFile(hostIDOverrideFile{path: path}); got != "second" {
		t.Errorf("read back %q", got)
	}
	for _, bad := range []string{"", "a b", "x\ny", strings.Repeat("a", 200), "../x", "é"} {
		if err := WriteHostIDFile(dir, bad); err == nil {
			t.Errorf("WriteHostIDFile accepted %q", bad)
		}
	}
	if err := WriteHostIDFile("", "ok"); err == nil {
		t.Error("empty directory accepted")
	}
	if got := readHostIDFile(hostIDOverrideFile{path: path}); got != "second" {
		t.Errorf("rejected writes changed the file: %q", got)
	}
}

func TestHostInfoReal(t *testing.T) {
	resetHostIDCache()
	t.Cleanup(resetHostIDCache)
	h := HostInfo()
	if h.OS != runtime.GOOS || h.Arch != runtime.GOARCH {
		t.Errorf("HostInfo = %+v", h)
	}
	src := HostIDSource()
	known := map[string]bool{
		HostIDSourceEnv: true, HostIDSourceFile: true, HostIDSourceDMI: true, HostIDSourceMachineID: true,
		HostIDSourceGetHostUUID: true, HostIDSourceIOReg: true, HostIDSourceSMBIOS: true,
		HostIDSourceMachineGUID: true, HostIDSourceNone: true,
	}
	if !known[src] {
		t.Errorf("unknown source %q", src)
	}
	if (h.ID == "") != (src == HostIDSourceNone) {
		t.Errorf("id %q inconsistent with source %q", h.ID, src)
	}
	if h.ID != sanitizeHostID(h.ID) {
		t.Errorf("id %q is not in sanitized form", h.ID)
	}
	if again := HostInfo(); again != h {
		t.Errorf("HostInfo not stable: %+v then %+v", h, again)
	}
	t.Logf("host id %q from %q, name %q", h.ID, src, h.Name)
}

// TestHostNameOverride: in a pod the kernel's host name is the pod's, so
// the DaemonSet sets HAWKBELL_HOST_NAME from spec.nodeName. A value that is
// not a plausible host name is ignored, never copied into records.
func TestHostNameOverride(t *testing.T) {
	kernel, _ := os.Hostname()
	cases := []struct{ env, want string }{
		{"", kernel},
		{"node-a.us-east-1.compute.internal", "node-a.us-east-1.compute.internal"},
		{"  gke-pool-1-abcd  ", "gke-pool-1-abcd"},
		{"evil\"},{\"x\":\"", kernel},
		{"two words", kernel},
		{"tab\tname", kernel},
		{"line\nbreak", kernel},
		{"ünïcode", kernel},
		{strings.Repeat("a", 253), strings.Repeat("a", 253)},
		{strings.Repeat("a", 254), kernel},
	}
	for _, c := range cases {
		t.Setenv(EnvHostName, c.env)
		if got := HostInfo().Name; got != c.want {
			t.Errorf("HAWKBELL_HOST_NAME=%.40q: Name = %.40q, want %.40q", c.env, got, c.want)
		}
	}
	// The id override is independent of the name override.
	t.Setenv(EnvHostID, "node-a")
	t.Setenv(EnvHostName, "node-a")
	if h := HostInfo(); h.ID != "node-a" || h.Name != "node-a" {
		t.Errorf("HostInfo = %+v", h)
	}
}
