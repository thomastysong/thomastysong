//go:build !windows

package main

// isWindowsService is false outside Windows: systemd and launchd run
// `spoor run` as a plain foreground process and stop it with SIGTERM.
func isWindowsService() bool { return false }
