//go:build windows

package procmon

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// canaryCommand runs "cmd.exe /d /c rem <nonce>" from the system directory
// (resolved with GetSystemDirectory, not from the environment). rem does
// nothing. UNVERIFIED: compiled and vetted, not executed; that
// process_etw_events reports this process in time was not tested.
func canaryCommand() (string, []string, bool) {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" {
		return "", nil, false
	}
	p := filepath.Join(dir, "cmd.exe")
	if !strings.EqualFold(filepath.Base(p), "cmd.exe") {
		return "", nil, false
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", nil, false
	}
	return p, []string{"cmd.exe", "/d", "/c", "rem"}, true
}

func canaryDir() string {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		return dir
	}
	return ""
}
