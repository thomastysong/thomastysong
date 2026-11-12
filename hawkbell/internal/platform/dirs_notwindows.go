//go:build !windows

package platform

func programDataDir() string { return "" }
