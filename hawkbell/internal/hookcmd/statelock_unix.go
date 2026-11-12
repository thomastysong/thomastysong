//go:build linux || darwin || freebsd || openbsd || netbsd

package hookcmd

import (
	"time"

	"golang.org/x/sys/unix"
)

// tryLock takes an exclusive lock on path, polling with a non-blocking
// flock until wait runs out. Any process of the user can hold the file
// (a stopped hook, or a model told to run `flock ... sleep inf`), so the
// hook never blocks on it. The file is opened without following a symlink
// and non-blocking (a planted FIFO cannot stall the open) and must be a
// regular file.
func tryLock(path string, wait time.Duration) (unlock func(), ok bool) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, false
	}
	end := time.Now().Add(wait)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(fd, unix.LOCK_UN)
				unix.Close(fd)
			}, true
		}
		if (err != unix.EWOULDBLOCK && err != unix.EINTR) || !time.Now().Before(end) {
			unix.Close(fd)
			return nil, false
		}
		time.Sleep(lockPoll)
	}
}
