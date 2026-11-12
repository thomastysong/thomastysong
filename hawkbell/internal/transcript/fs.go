package transcript

import "errors"

// fileMeta is what the tailer needs to know about a file. It is filled from
// the open descriptor whenever possible, so the facts describe the file that
// is actually read and not whatever the path names a moment later.
type fileMeta struct {
	size    int64
	mtime   int64  // modification time, Unix nanoseconds
	id      string // device:inode on POSIX, volume:index on Windows, "" when unknown
	owner   string // uid on POSIX, SID on Windows, "" when unknown
	regular bool
	symlink bool // symlink or other reparse point
	dir     bool
}

var (
	errSymlink    = errors.New("symbolic link refused")
	errNotRegular = errors.New("not a regular file")
)
