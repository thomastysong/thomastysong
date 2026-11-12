//go:build !unix && !windows

package daemon

import (
	"errors"
	"os"
)

// Systems other than Unix and Windows have no ownership model the daemon
// knows; directories are created and checked for links, nothing else.

func currentUID() string { return "" }

func lookupGroup(string) (int, bool) { return -1, false }

func secureDataDir(path string, privileged bool) error {
	if err := os.MkdirAll(path, 0o711); err != nil {
		return err
	}
	return checkPlain(path)
}

func secureDir(path string, kind dirKind, privileged bool, ownerUID string, gid int) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPlain(path)
}

func checkPlain(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errSymlinkDir
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

func secureSegmentFile(string, bool, int) error { return nil }
