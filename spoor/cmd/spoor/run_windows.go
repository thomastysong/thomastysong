//go:build windows

package main

import "golang.org/x/sys/windows/svc"

// isWindowsService reports whether the service control manager started
// this process (packaging/windows/install-service.ps1 registers
// `"...\spoor.exe" run --config "...\spoor.yaml"`). internal/daemon runs
// itself under svc.Run in that case; cmd/spoor only has to send the log
// somewhere other than a console that does not exist.
func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
