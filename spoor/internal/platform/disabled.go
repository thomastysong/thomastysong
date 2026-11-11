package platform

import (
	"os"
	"path/filepath"
)

// KillSwitchName is the file whose presence in the config directory turns
// every collector into a no-op.
const KillSwitchName = "disabled"

// Disabled reports whether the operator has pulled the kill switch. The hook
// entrypoint sits in the path of every tool call of every developer, so a bad
// release needs an off switch that works without uninstalling anything and
// without a new binary: creating one file (by Fleet script, MDM or hand) makes
// `spoor hook` exit 0 at once and idles the daemon's collectors. The check is
// a single stat so it costs nothing on the hot path.
func Disabled() bool {
	return disabledIn(DefaultDirs().Config)
}

func disabledIn(configDir string) bool {
	if configDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(configDir, KillSwitchName))
	return err == nil
}
