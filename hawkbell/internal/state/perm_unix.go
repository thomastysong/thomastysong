//go:build unix

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// privileged is a seam so tests can exercise the privileged checks without
// root and the unprivileged path while running as root.
var privileged = func() bool { return os.Geteuid() == 0 }

// checkDir refuses, for a privileged writer, a directory that somebody else
// could write: whoever can write the directory can swap the database for one
// of their own, and Fleet policies are evaluated against it.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// Resolve one level so "/var/lib/hawkbell -> /data/hawkbell" style layouts
		// work; the target is then held to the same rules.
		if fi, err = os.Stat(dir); err != nil {
			return fmt.Errorf("state: %w", err)
		}
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, dir)
	}
	if !privileged() {
		return nil
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory %s is group- or world-writable (mode %04o)", ErrUnsafePath, dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: directory %s is owned by uid %d, not by the sensor (uid %d)", ErrUnsafePath, dir, st.Uid, os.Geteuid())
	}
	return nil
}

// prepareFile makes sure the database path is a regular file with mode 0600,
// creating it empty when missing so SQLite never creates it with the
// process umask. Sidecars inherit the main file's mode.
func prepareFile(path string) error {
	for _, side := range []string{path + "-wal", path + "-shm", path + "-journal"} {
		if fi, err := os.Lstat(side); err == nil && !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, side)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err == nil {
		// The umask may have narrowed the mode but cannot have widened it.
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("state: create database: %w", err)
	}
	// O_NOFOLLOW makes a symlink at the final component fail with ELOOP;
	// O_NONBLOCK keeps a FIFO planted there from hanging the open.
	f, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: %s is a symbolic link", ErrUnsafePath, path)
		}
		return fmt.Errorf("state: open database: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	if privileged() {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
			return fmt.Errorf("%w: %s is owned by uid %d", ErrUnsafePath, path, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%w: %s is group- or world-writable (mode %04o): its content cannot be trusted", ErrUnsafePath, path, fi.Mode().Perm())
		}
	}
	if fi.Mode().Perm() != 0o600 {
		// A file left 0644 by an older build or a manual copy: tighten it.
		// Failure is not fatal for an unprivileged caller that does not own it.
		if err := f.Chmod(0o600); err != nil && privileged() {
			return fmt.Errorf("state: chmod database: %w", err)
		}
	}
	return nil
}

// checkExisting applies the same trust rules to a database a privileged
// reader is about to open: the osquery extension runs as root, and Fleet
// policies are evaluated against what it returns, so a file or directory
// that another user could write must not be believed.
func checkExisting(path string, fi os.FileInfo) error {
	if !privileged() {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrUnsafePath, path, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is group- or world-writable (mode %04o)", ErrUnsafePath, path, fi.Mode().Perm())
	}
	return nil
}
