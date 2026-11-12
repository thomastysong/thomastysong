//go:build windows

package bundle

import (
	"errors"
	"fmt"
	"syscall"
)

// Win32 error codes that syscall does not name.
const (
	errSharingViolation syscall.Errno = 32
	errLockViolation    syscall.Errno = 33
)

// tryLock opens the lock file with a share mode of zero: while the handle
// is open every other open of the file, from this or any other process,
// fails with a sharing violation. os.OpenFile cannot do this (it always
// shares read and write), hence the direct CreateFile call.
//
// UNVERIFIED: compiled for windows/amd64 and windows/arm64 but not executed
// on Windows in the build environment.
func tryLock(path string) (release func(), ok bool, err error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, fmt.Errorf("bundle: lock: %w", err)
	}
	// A nil security descriptor means the handle is not inherited by child
	// processes, which would otherwise keep the lock alive.
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errSharingViolation) || errors.Is(err, errLockViolation) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("bundle: lock: %w", err)
	}
	return func() { syscall.CloseHandle(h) }, true, nil
}
