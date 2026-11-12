//go:build darwin

package discovery

import "golang.org/x/sys/unix"

// quarantined reports the com.apple.quarantine extended attribute, which
// macOS sets on files that arrived through a browser or another
// quarantine-aware download path. Only its presence is read.
func (s *scanner) quarantined(l loc) bool {
	sz, err := unix.Lgetxattr(realPath(s.o.HostRoot, l.String()), "com.apple.quarantine", nil)
	return err == nil && sz > 0
}
