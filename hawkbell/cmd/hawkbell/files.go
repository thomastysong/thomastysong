package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// writeFileAtomic replaces path with data through a temporary file in the
// same directory, so a reader never sees a half-written file. A symbolic
// link at path is refused rather than followed or replaced.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: refusing to replace a symbolic link", path)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// writeExport writes one exported file: a new file unless force, never
// through a symbolic link, with parent directories created 0755.
func writeExport(path string, data []byte, mode os.FileMode, force bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if force {
		return writeFileAtomic(path, data, mode)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s exists (use --force to replace it)", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// The process umask may have narrowed mode; exported content is meant
	// to be as readable as asked (configuration is read by unprivileged
	// hooks).
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func currentUser() platform.UserHome { return platform.CurrentUser() }
