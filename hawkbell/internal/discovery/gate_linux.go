//go:build linux

package discovery

import (
	"time"

	"golang.org/x/sys/unix"
)

// openat2Supported is the starting assumption; the first ENOSYS (kernels
// before 5.6) or EPERM (container seccomp profiles) switches to the walk.
const openat2Supported = true

// O_PATH directory descriptors need no read permission on the directory
// and cannot be read from, which is all a confinement root needs.
const dirOpenFlags = unix.O_PATH

// openat2 opens rel below dirfd with kernel-enforced confinement. ok is
// false when the system call itself is unavailable.
func openat2(dirfd int, rel string, flags int, inRoot bool) (fd int, err error, ok bool) {
	how := unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_NO_MAGICLINKS}
	if inRoot {
		how.Resolve |= unix.RESOLVE_IN_ROOT
	} else {
		how.Resolve |= unix.RESOLVE_BENEATH
	}
	for {
		fd, err = unix.Openat2(dirfd, rel, &how)
		if err != unix.EINTR && err != unix.EAGAIN {
			break
		}
	}
	switch err {
	case unix.ENOSYS, unix.EPERM, unix.E2BIG:
		return -1, err, false
	}
	return fd, err, true
}

func timespecTime(st *unix.Stat_t) time.Time {
	return time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
}
