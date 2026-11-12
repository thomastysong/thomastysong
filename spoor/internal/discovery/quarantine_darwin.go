//go:build darwin

package discovery

import "golang.org/x/sys/unix"

// quarantined reports the com.apple.quarantine extended attribute, which
// macOS sets on files that arrived through a browser or another
// quarantine-aware download path. Only its presence is read, and it is read
// on a descriptor the gate opened (no-follow, confined), never by path: a
// path-based getxattr would resolve intermediate links the gate refuses.
//
// UNVERIFIED: compiled for darwin, not executed in the build environment.
func (s *scanner) quarantined(l loc) bool {
	f, _, err := s.g.open(l, "")
	if err != nil {
		return false
	}
	defer f.Close()
	sz, err := unix.Fgetxattr(int(f.Fd()), "com.apple.quarantine", nil)
	return err == nil && sz > 0
}
