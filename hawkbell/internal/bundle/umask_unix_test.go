//go:build unix

package bundle

import (
	"syscall"
	"testing"
)

// withUmask runs fn under a different process umask. The umask is
// process-wide, so no test in this package runs in parallel.
func withUmask(t *testing.T, mask int, fn func()) {
	t.Helper()
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}
