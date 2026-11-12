//go:build unix

package osqexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/thomastysong/spoor/internal/platform"
)

// DefaultSockets lists where an osqueryd extension-manager socket is looked
// for when Options.Socket is empty: Fleet's Orbit first, then stock osquery.
func DefaultSockets() []string {
	return []string{"/opt/orbit/orbit-osquery.em", "/var/osquery/osquery.em"}
}

// checkSocket accepts a socket only when nobody but root (or the caller,
// when the sensor itself is unprivileged) could have put it there. Rows read
// from it become root-integrity events, and any local user can create a
// socket file in a directory they can write to.
//
// It returns an error wrapping fs.ErrNotExist when the path is absent.
func checkSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("osqexec: %s is not a socket", path)
	}
	self := strconv.Itoa(os.Geteuid())
	if uid, ok := platform.OwnerUID(fi); !ok || (uid != "0" && uid != self) {
		return fmt.Errorf("osqexec: socket %s is not owned by root", path)
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("osqexec: %w", err)
	}
	if uid, ok := platform.OwnerUID(di); !ok || (uid != "0" && uid != self) {
		return fmt.Errorf("osqexec: directory %s is not owned by root", dir)
	}
	// A sticky directory (/tmp, /run/lock) lets others add entries but not
	// replace root's socket, and the socket's own owner was checked above.
	if di.Mode().Perm()&0o022 != 0 && di.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("osqexec: directory %s is writable by other users", dir)
	}
	return nil
}
