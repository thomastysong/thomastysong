//go:build windows

package hookinstall

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// UNVERIFIED: compiled and vetted for windows/amd64 and windows/arm64, not
// executed in the build environment.

// claudeRegistryPolicy reports whether the machine-level Claude Code policy
// exists. The value is not parsed: any policy key in it wins over the files.
func claudeRegistryPolicy() (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, claudePolicyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer k.Close()
	if _, _, err := k.GetValue("Settings", nil); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
