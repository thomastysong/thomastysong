//go:build !unix

package bundle

import "testing"

func withUmask(t *testing.T, _ int, _ func()) {
	t.Helper()
	t.Skip("no umask on this platform")
}
