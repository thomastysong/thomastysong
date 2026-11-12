//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package discovery

import (
	"time"

	"golang.org/x/sys/unix"
)

// No openat2 outside Linux: every path below a root is walked one
// component at a time with O_NOFOLLOW.
const openat2Supported = false

const dirOpenFlags = unix.O_RDONLY

func openat2(dirfd int, rel string, flags int, inRoot bool) (int, error, bool) {
	return -1, nil, false
}

func timespecTime(st *unix.Stat_t) time.Time {
	return time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
}
