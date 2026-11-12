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
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func isNotDir(err error) bool { return errors.Is(err, syscall.ENOTDIR) }
