//go:build unix

package osqext

import (
	"fmt"
	"os"
	"syscall"
)

// privileged is a seam for tests.
var privileged = func() bool { return os.Geteuid() == 0 }

// checkHostIDDir refuses, for a root extension, a directory another user
// could write. The host id file decides which Fleet host every event is
// attributed to; in a writable directory any user could replace it between
// two starts of the extension.
func checkHostIDDir(dir string) error {
	if !privileged() {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing to write the host id into %s: directory is group- or world-writable (mode %04o)", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing to write the host id into %s: directory is owned by uid %d", dir, st.Uid)
	}
	return nil
}
