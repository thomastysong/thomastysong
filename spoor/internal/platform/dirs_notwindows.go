//go:build !windows

package platform

func programDataDir() string { return "" }

func localAppDataDir(string) string { return "" }
