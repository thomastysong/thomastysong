//go:build windows

package main

import (
	"context"
	"io"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/thomastysong/spoor/internal/config"
)

// isWindowsService reports whether the service control manager started
// this process (packaging/windows/install-service.ps1 registers
// `"...\spoor.exe" run --config "...\spoor.yaml"`).
func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// stopWait bounds how long a stop request waits for the daemon to flush.
// The SCM's own default wait hint for a stop is 20 s on most systems.
const stopWait = 15 * time.Second

// runService runs the daemon under svc.Run. UNVERIFIED: compiled and vetted
// for windows only; the build environment has no service control manager.
func runService(cfg *config.Config, path string, lvl slog.Level, format string) int {
	var w io.Writer = io.Discard
	if f, err := openServiceLog(cfg); err == nil {
		defer f.Close()
		w = f
	}
	h := &serviceHandler{cfg: cfg, path: path, log: newLogger(w, lvl, format)}
	if err := svc.Run("spoor", h); err != nil {
		h.log.Error("service control manager", "err", err)
		return exitError
	}
	return h.code
}

type serviceHandler struct {
	cfg  *config.Config
	path string
	log  *slog.Logger
	code int
}

func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- runDaemon(ctx, h.cfg, h.path, h.log) }()
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case code := <-done:
			// The daemon ended on its own: report it as a service-specific
			// failure so the recovery actions of the service apply.
			h.code = code
			status <- svc.Status{State: svc.StopPending}
			if code != exitOK {
				return true, uint32(code)
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopWait / time.Millisecond)}
				cancel()
				select {
				case h.code = <-done:
				case <-time.After(stopWait):
					h.log.Warn("daemon did not stop in time", "wait", stopWait)
					h.code = exitError
				}
				return false, 0
			}
		}
	}
}
