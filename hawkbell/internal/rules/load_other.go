//go:build !unix && !windows

package rules

import "fmt"

// readTrustedDir is unsupported where neither POSIX ownership nor Windows
// ACLs can be checked: loading unverifiable content would defeat the point
// of the check.
func readTrustedDir(dir string) (map[string][]byte, error) {
	return nil, fmt.Errorf("%w: ownership cannot be verified on this platform", ErrInsecureDir)
}
