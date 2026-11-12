//go:build windows

package discovery

import "os"

// quarantined reports a Zone.Identifier alternate data stream (Mark of the
// Web), which Windows attaches to downloaded files. Only its presence is
// checked.
//
// UNVERIFIED: compiled for windows, not executed in the build environment.
func (s *scanner) quarantined(l loc) bool {
	fi, err := os.Lstat(realPath(s.o.HostRoot, l.String()) + ":Zone.Identifier")
	return err == nil && fi.Mode().IsRegular()
}
