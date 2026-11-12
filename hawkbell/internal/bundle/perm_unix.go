//go:build unix

package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkOwner refuses a file or directory that someone other than root or
// the calling user could have written. Installed content is trusted because
// of where it lives, not because of its signature (the signature is checked
// once, at install), so a destination that is writable by group or others,
// or that belongs to another account, cannot be loaded from.
//
// Only the destination and what is inside it are checked. Parents are the
// responsibility of whoever chose the data directory.
func checkOwner(name string, fi os.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %04o); run chmod go-w on it", ErrInsecure, filepath.Base(name), perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not by root or the calling user", ErrInsecure, filepath.Base(name), uid)
	}
	return nil
}
