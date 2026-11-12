//go:build !darwin && !windows

package discovery

// quarantined has no equivalent on this OS: Linux desktops record no
// download provenance on files that tools could rely on.
func (s *scanner) quarantined(l loc) bool { return false }
