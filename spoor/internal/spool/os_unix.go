//go:build linux || darwin || freebsd || openbsd || netbsd

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func currentUID() string { return strconv.Itoa(os.Geteuid()) }

// checkPrivate requires dir to be a real directory owned by uid with no
// group or other permissions.
func checkPrivate(dir, uid string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafe, dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: no ownership information", ErrUnsafe, dir)
	}
	if uid != "" && strconv.FormatUint(uint64(st.Uid), 10) != uid {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrUnsafe, dir, st.Uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %o", ErrUnsafe, dir, fi.Mode().Perm())
	}
	return nil
}

func freeBytes(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}

// lockDir takes an exclusive lock on <dir>/.lock.
func lockDir(dir string) (func(), error) {
	p := filepath.Join(dir, ".lock")
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("spool lock: %w", err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		unix.Close(fd)
	}, nil
}

// openAppend opens path for one append, refusing a symlink or a non-regular
// file at that name.
func openAppend(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a regular file")}
	}
	_ = unix.SetNonblock(fd, false)
	return os.NewFile(uintptr(fd), path), nil
}
