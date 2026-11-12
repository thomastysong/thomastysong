//go:build !unix && !windows

package osqexec

import (
	"fmt"
	"io/fs"
)

// DefaultSockets is empty on operating systems osquery does not run on.
func DefaultSockets() []string { return nil }

func checkSocket(path string) error {
	return fmt.Errorf("osqexec: %s: %w", path, fs.ErrNotExist)
}
