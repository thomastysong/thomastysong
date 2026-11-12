//go:build !unix && !windows

package procmon

// canaryCommand: no known harmless system binary on this platform.
func canaryCommand() (string, []string, bool) { return "", nil, false }

func canaryDir() string { return "" }
