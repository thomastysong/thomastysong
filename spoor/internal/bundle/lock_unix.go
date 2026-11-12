//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package bundle

import (
	"fmt"
	"os"
	"syscall"
)

// tryLock takes an exclusive flock(2) on the lock file without blocking.
// flock locks belong to the open file description, so two goroutines of one
// process exclude each other exactly as two processes do.
//
// The file is created 0600: flock needs no more than a readable descriptor,
// so a lock file other users could open would let any of them hold the lock
// and stall content updates.
func tryLock(path string) (release func(), ok bool, err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("bundle: lock: %w", err)
	}
	fd := int(f.Fd())
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if err == syscall.EWOULDBLOCK {
		f.Close()
		return nil, false, nil
	}
	if err != nil {
		f.Close()
		return nil, false, fmt.Errorf("bundle: lock: %w", err)
	}
	return func() {
		syscall.Flock(fd, syscall.LOCK_UN)
		f.Close()
	}, true, nil
}
