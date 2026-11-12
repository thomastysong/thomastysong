//go:build !windows

package hookinstall

// claudeRegistryPolicy is never called off Windows; shadowOf reports the
// registry as not checked instead.
func claudeRegistryPolicy() (bool, error) { return false, nil }
