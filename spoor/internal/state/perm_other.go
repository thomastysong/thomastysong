//go:build !unix

package state

import (
	"errors"
	"fmt"
	"os"
)

// POSIX mode bits carry no meaning on Windows, so the ownership and
// writability checks of the unix build have nothing to test here. Protection
// of the data directory is the installer's and the daemon's job (an ACL
// limited to SYSTEM and Administrators). What still applies everywhere: the
// path must be a regular file, never a link or reparse point.

func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, dir)
	}
	return nil
}

func prepareFile(path string) error {
	for _, side := range []string{path + "-wal", path + "-shm", path + "-journal"} {
		if fi, err := os.Lstat(side); err == nil && !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, side)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("state: create database: %w", err)
	}
	// Lstat reports reparse points (symlinks, junctions) as non-regular.
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	return nil
}

func checkExisting(path string, fi os.FileInfo) error { return nil }
