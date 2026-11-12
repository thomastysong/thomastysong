//go:build windows

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
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

// tryLockDir takes the lock lockDir takes, without waiting: ok is false
// when another process holds it.
func tryLockDir(dir string) (unlock func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, false
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		f.Close()
	}, true
}

// callerOwners are the owners a file this process creates can have: the
// token's user, and the token's default owner, which Windows makes the
// owner of every object the process creates without naming one. For an
// elevated member of the Administrators group the default owner is
// usually the Administrators group (S-1-5-32-544), not the user (see
// ownerOK in internal/transcript/fs_windows.go). Such a hook therefore also
// deletes expired files that another elevated administrator created in
// this account's spool; an administrator can delete them anyway.
// UNVERIFIED on real hardware.
func callerOwners() []string {
	var out []string
	if u := currentUID(); u != "unknown" {
		out = append(out, u)
	}
	if o, ok := tokenDefaultOwner(windows.GetCurrentProcessToken()); ok && !slices.Contains(out, o) {
		out = append(out, o)
	}
	return out
}

// tokenOwner is TOKEN_OWNER.
type tokenOwner struct{ Owner *windows.SID }

// tokenDefaultOwner is the TokenOwner of t, as a SID string.
func tokenDefaultOwner(t windows.Token) (string, bool) {
	n := uint32(64)
	for range 4 {
		b := make([]byte, n)
		err := windows.GetTokenInformation(t, windows.TokenOwner, &b[0], uint32(len(b)), &n)
		if err == nil {
			o := (*tokenOwner)(unsafe.Pointer(&b[0]))
			if o.Owner == nil {
				return "", false
			}
			return o.Owner.String(), true
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || n <= uint32(len(b)) {
			return "", false
		}
	}
	return "", false
}

// fileOwner is the SID that owns the file at path.
func fileOwner(_ os.FileInfo, path string) (string, bool) {
	return platform.PathOwner(path)
}

func openAppend(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a regular file")}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}
