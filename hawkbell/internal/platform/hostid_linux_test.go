//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxPlatformHostID(t *testing.T) {
	root := t.TempDir()
	old := hostIDSysRoot
	hostIDSysRoot = root
	t.Cleanup(func() { hostIDSysRoot = old })
	put := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	del := func(rel string) { _ = os.Remove(filepath.Join(root, rel)) }
	check := func(step, wantID, wantSrc string) {
		t.Helper()
		if id, src := platformHostID(); id != wantID || src != wantSrc {
			t.Errorf("%s: got %q %q, want %q %q", step, id, src, wantID, wantSrc)
		}
	}

	check("nothing readable (unprivileged container)", "", HostIDSourceNone)

	put("etc/machine-id", "d165c2d88d894a4787be219662b439ad\n")
	check("machine-id only", "d165c2d8-8d89-4a47-87be-219662b439ad", HostIDSourceMachineID)

	// The DMI UUID is what osquery reports, verbatim, so it wins.
	put("sys/class/dmi/id/product_uuid", "4C4C4544-0042-3510-8054-B9C04F4D3233\n")
	check("dmi", "4C4C4544-0042-3510-8054-B9C04F4D3233", HostIDSourceDMI)

	// A firmware placeholder is refused, exactly as osquery refuses it.
	put("sys/class/dmi/id/product_uuid", "03000200-0400-0500-0006-000700080009\n")
	check("placeholder dmi", "d165c2d8-8d89-4a47-87be-219662b439ad", HostIDSourceMachineID)

	put("sys/class/dmi/id/product_uuid", "To Be Filled By O.E.M.\n")
	check("garbage dmi", "d165c2d8-8d89-4a47-87be-219662b439ad", HostIDSourceMachineID)

	del("sys/class/dmi/id/product_uuid")
	put("sys/devices/virtual/dmi/id/product_uuid", "11111111-2222-3333-4444-555555555555")
	check("dmi via the devices path", "11111111-2222-3333-4444-555555555555", HostIDSourceDMI)
	del("sys/devices/virtual/dmi/id/product_uuid")

	put("etc/machine-id", "uninitialized\n")
	check("first-boot machine-id", "", HostIDSourceNone)
	put("var/lib/dbus/machine-id", "ABCDEFABCDEFABCDEFABCDEFABCDEF12\n")
	check("dbus machine-id", "abcdefab-cdef-abcd-efab-cdefabcdef12", HostIDSourceMachineID)

	put("etc/machine-id", string(make([]byte, 1<<20)))
	check("oversized machine-id falls through", "abcdefab-cdef-abcd-efab-cdefabcdef12", HostIDSourceMachineID)
}

func TestLinuxHostIDMatchesTheLiveSystem(t *testing.T) {
	id, src := platformHostID()
	switch src {
	case HostIDSourceDMI:
		raw, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
		if err == nil && cleanHardwareUUID(string(raw)) != id {
			t.Errorf("dmi id %q does not match product_uuid %q", id, raw)
		}
	case HostIDSourceMachineID:
		if !isUUID(id) {
			t.Errorf("machine-id not formatted as a UUID: %q", id)
		}
	case HostIDSourceNone:
		if id != "" {
			t.Errorf("source none with id %q", id)
		}
	default:
		t.Errorf("unexpected source %q on linux", src)
	}
	t.Logf("live host id %q from %q", id, src)
}
