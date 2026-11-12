//go:build unix

package sink

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// openFlags are common to every segment open:
//   - O_NOFOLLOW: a symlink planted under a segment name must not redirect a
//     privileged writer to another file.
//   - O_NONBLOCK: a FIFO planted under a segment name must fail (ENXIO)
//     instead of blocking the sensor forever. It has no effect on regular
//     files.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// openAppend opens a segment for appending, creating it when absent, and
// reports whether this call created it. O_APPEND makes each write(2) land
// atomically at the end of file, which is what lets many processes share a
// segment without a lock.
func openAppend(path string, mode os.FileMode) (f *os.File, created bool, err error) {
	const flags = os.O_WRONLY | os.O_APPEND | openFlags
	for attempt := 0; attempt < 2; attempt++ {
		f, err = os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			// The umask may have removed bits the Fluent Bit side needs
			// (group read by default), so set the mode explicitly.
			if cerr := f.Chmod(mode); cerr != nil {
				f.Close()
				return nil, false, cerr
			}
			return f, true, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, false, err
		}
		f, err = os.OpenFile(path, flags, 0)
		if err == nil {
			return f, false, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, false, err
		}
		// Pruned between the two opens: try to create it again.
	}
	return nil, false, err
}

// openRead opens a segment for reading without following symlinks.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|openFlags, 0)
}

// linkCount returns the number of hard links to an open file. Zero means
// the file was deleted after it was opened: writes would go nowhere.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}
