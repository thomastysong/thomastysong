//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// programDataDir asks the shell rather than the environment: the hook process
// runs with whatever environment the agent hands it, and a rewritten
// %ProgramData% must not be able to point it at a different socket.
func programDataDir() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	if p := os.Getenv("ProgramData"); filepath.IsAbs(p) {
		return p
	}
	return `C:\ProgramData`
}

// localAppDataDir returns %LOCALAPPDATA% for home. The shell can only answer
// for the calling user; other profiles get the default location.
func localAppDataDir(home string) string {
	cur := CurrentUser().Home
	if cur != "" && strings.EqualFold(filepath.Clean(home), filepath.Clean(cur)) {
		if p, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
			return p
		}
	}
	return filepath.Join(home, "AppData", "Local")
}
