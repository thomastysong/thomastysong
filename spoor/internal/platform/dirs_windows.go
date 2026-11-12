//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	programDataOnce sync.Once
	programDataVal  string
)

// systemDrive returns the drive Windows is installed on ("C:"), from the
// kernel rather than from %SystemDrive%.
func systemDrive() string {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return ""
	}
	return filepath.VolumeName(dir)
}

// programDataDir locates %ProgramData% without trusting the environment and
// without the shell. The hook process runs on every tool call with whatever
// environment the agent hands it: a rewritten %ProgramData% must not be able
// to point it at a different socket, and SHGetKnownFolderPath would load
// shell32 into each of those short-lived processes.
//
// UNVERIFIED: not executed on Windows in the build environment; the
// ProfileList\ProgramData value ("%SystemDrive%\ProgramData" by default) is
// cited from memory. When it is missing or unusable the answer is
// <system drive>\ProgramData.
func programDataDir() string {
	programDataOnce.Do(func() {
		drive := systemDrive()
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			v, _, verr := k.GetStringValue("ProgramData")
			k.Close()
			if verr == nil {
				if p := expandSystemDrive(v, drive); filepath.IsAbs(p) {
					programDataVal = filepath.Clean(p)
					return
				}
			}
		}
		switch {
		case drive != "":
			programDataVal = drive + `\ProgramData`
		case filepath.IsAbs(os.Getenv("ProgramData")):
			programDataVal = filepath.Clean(os.Getenv("ProgramData"))
		default:
			programDataVal = `C:\ProgramData`
		}
	})
	return programDataVal
}
