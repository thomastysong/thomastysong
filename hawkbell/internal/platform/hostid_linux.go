//go:build linux

package platform

import "path/filepath"

// sysRoot and etcRoot exist so tests can point the readers at fixtures.
var (
	hostIDSysRoot = "/"
	// product_uuid is mode 0400 root: an unprivileged process falls through
	// to machine-id, which is why the host_id override file exists.
	dmiUUIDPaths   = []string{"sys/class/dmi/id/product_uuid", "sys/devices/virtual/dmi/id/product_uuid"}
	machineIDPaths = []string{"etc/machine-id", "var/lib/dbus/machine-id"}
)

func platformHostID() (id, src string) {
	for _, p := range dmiUUIDPaths {
		b, err := readFileLimit(filepath.Join(hostIDSysRoot, p), 256)
		if err != nil {
			continue
		}
		if id := cleanHardwareUUID(string(b)); id != "" {
			return id, HostIDSourceDMI
		}
	}
	// osquery never uses machine-id: without a DMI UUID it stores a random
	// one in its own database. machine-id is still the best stable local id.
	for _, p := range machineIDPaths {
		b, err := readFileLimit(filepath.Join(hostIDSysRoot, p), 256)
		if err != nil {
			continue
		}
		if id := machineIDToUUID(string(b)); id != "" {
			return id, HostIDSourceMachineID
		}
	}
	return "", HostIDSourceNone
}
