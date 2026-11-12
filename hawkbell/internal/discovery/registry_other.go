//go:build !windows

package discovery

// winInstall is one Windows Uninstall registry entry.
type winInstall struct{ display, version, location string }

// windowsInstalls has nothing to read outside Windows.
func windowsInstalls(sid string) []winInstall { return nil }

// registryProbe reports whether a registry key (and value, when named)
// exists; ok is false where the registry does not exist.
func registryProbe(key, value string) (exists, ok bool) { return false, false }
