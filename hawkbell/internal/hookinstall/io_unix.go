//go:build unix

package hookinstall

import (
	"errors"
	"os"
	"syscall"
)

// readFlags are the flags for every read of a file another program owns.
// O_NOFOLLOW and O_NONBLOCK (unix) keep a link or a FIFO planted in the
// file's place from being followed or from blocking the caller forever;
// the caller also compares the opened handle with its lstat result, which
// catches a link swapped in between (Windows has no O_NOFOLLOW).
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

func isNotDir(err error) bool { return errors.Is(err, syscall.ENOTDIR) }
