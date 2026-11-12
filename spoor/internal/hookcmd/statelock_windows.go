//go:build windows

package hookcmd

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// tryLock takes an exclusive lock on path, polling LockFileEx with
// LOCKFILE_FAIL_IMMEDIATELY until wait runs out. Any process of the user
// can hold the file, so the hook never blocks on it. A name that exists
// and is not a regular file (a link or a directory) is refused.
func tryLock(path string, wait time.Duration) (unlock func(), ok bool) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false
	}
	h := windows.Handle(f.Fd())
	end := time.Now().Add(wait)
	for {
		ol := new(windows.Overlapped)
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
				f.Close()
			}, true
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || !time.Now().Before(end) {
			f.Close()
			return nil, false
		}
		time.Sleep(lockPoll)
	}
}
