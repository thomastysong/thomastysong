//go:build unix

package procmon

import (
	"os"

	"github.com/thomastysong/spoor/internal/platform"
)

// canaryCommand returns the self-test program: the first of the usual
// locations of true(1) that is a root-owned regular file not writable by
// group or others. Its arguments are ignored by true, which is the point.
func canaryCommand() (string, []string, bool) {
	for _, p := range []string{"/usr/bin/true", "/bin/true"} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if uid, ok := platform.OwnerUID(fi); !ok || uid != "0" {
			continue
		}
		return p, []string{p}, true
	}
	return "", nil, false
}

func canaryDir() string { return "/" }
