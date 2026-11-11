//go:build windows

package platform

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procGetSystemFirmwareTable = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

func platformHostID() (id, src string) {
	if id := smbiosSystemUUID(rawSMBIOS()); id != "" {
		return id, HostIDSourceSMBIOS
	}
	if id := machineGUID(); id != "" {
		return id, HostIDSourceMachineGUID
	}
	return "", HostIDSourceNone
}

// rawSMBIOS returns the firmware's SMBIOS table without WMI: osquery asks WMI
// for Win32_ComputerSystemProduct.UUID, which is this table's type 1 UUID.
//
// UNVERIFIED: not executed on Windows in the build environment.
func rawSMBIOS() []byte {
	if procGetSystemFirmwareTable.Find() != nil {
		return nil
	}
	const rsmb = 0x52534D42 // 'RSMB'
	size, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if size == 0 || size > 1<<20 {
		return nil
	}
	buf := make([]byte, size)
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), size)
	if n == 0 || n > size {
		return nil
	}
	return buf[:n]
}

// machineGUID is the fallback id: unique per Windows installation, readable
// without privilege, but not what osquery reports.
func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return cleanHardwareUUID(strings.Trim(v, "{}"))
}
