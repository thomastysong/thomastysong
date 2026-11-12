//go:build windows

package spool

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// currentUID is the caller's SID: Windows has no numeric uid.
func currentUID() string {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "unknown"
	}
	return u.User.Sid.String()
}

// checkPrivate on Windows only checks that dir is a directory and not a
// reparse point. Mode bits mean nothing there; the installer sets the ACL.
// UNVERIFIED on real hardware.
func checkPrivate(dir, uid string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is not a plain directory", ErrUnsafe, dir)
	}
	return nil
}

func freeBytes(dir string) (uint64, bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, false
	}
	return free, true
}

func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		f.Close()
	}, nil
}

func openAppend(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a regular file")}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}
