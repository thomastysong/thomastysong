//go:build unix

package hookinstall

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens for reading. O_NOFOLLOW closes the window between the
// lstat and the open in which the file could become a link; O_NONBLOCK keeps
// a FIFO planted in its place from blocking the caller forever.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, readFlags, 0)
}

// readFlags are the flags for every read of a file another program owns.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func isNotDir(err error) bool { return errors.Is(err, syscall.ENOTDIR) }
