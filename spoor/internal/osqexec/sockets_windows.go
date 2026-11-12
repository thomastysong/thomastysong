//go:build windows

package osqexec

import (
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows"

	"github.com/thomastysong/spoor/internal/platform"
)

// DefaultSockets lists the named pipes an osqueryd extension manager is
// looked for on when Options.Socket is empty: Fleet's Orbit first, then
// stock osquery.
func DefaultSockets() []string {
	return []string{`\\.\pipe\orbit-osquery-extension`, `\\.\pipe\osquery.em`}
}

// checkSocket accepts a pipe only when its owner is SYSTEM or the
// Administrators group. Any local user can create a pipe with osquery's name
// while osqueryd is not running, and rows read from it become events.
//
// It returns an error wrapping fs.ErrNotExist when the pipe is absent.
//
// UNVERIFIED: compiled and vetted, never executed (no Windows host where
// this package was built). Opening the pipe with READ_CONTROL uses up one
// client instance for the duration of the check.
func checkSocket(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("osqexec: pipe name: %w", err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return fmt.Errorf("osqexec: %s: %w", path, fs.ErrNotExist)
		}
		return fmt.Errorf("osqexec: cannot inspect pipe %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("osqexec: cannot read owner of pipe %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("osqexec: pipe %s has no readable owner", path)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	if !platform.IsPrivileged() {
		// An unprivileged sensor may talk to an osqueryd of its own user.
		if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && windows.EqualSid(tu.User.Sid, owner) {
			return nil
		}
	}
	return fmt.Errorf("osqexec: pipe %s is not owned by SYSTEM or Administrators", path)
}
