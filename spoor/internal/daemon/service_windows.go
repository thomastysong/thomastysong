//go:build windows

package daemon

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sys/windows/svc"

	"github.com/thomastysong/spoor/internal/config"
)

// runService runs the daemon under the service control manager when the
// SCM started this process (the installer registers `spoor.exe run
// --config ...` as service "spoor", LocalSystem). It returns false when the
// process is not a service, and Run then runs in the foreground.
//
// UNVERIFIED: compiled and vetted only; not run under a real SCM.
func runService(ctx context.Context, cfg *config.Config, log *slog.Logger) (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, nil
	}
	h := &serviceHandler{ctx: ctx, cfg: cfg, log: log}
	if err := svc.Run(ServiceName, h); err != nil {
		return true, err
	}
	return true, h.result()
}

type serviceHandler struct {
	ctx context.Context
	cfg *config.Config
	log *slog.Logger

	mu  sync.Mutex
	err error
}

func (h *serviceHandler) result() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

// stopWaitHint is what the SCM is told a stop may take: the daemon flushes
// within its own 12 s collector timeout plus the pipeline close.
const stopWaitHint = 20000

// Execute implements svc.Handler.
func (h *serviceHandler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.cfg, h.log, defaultEnv()) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	finish := func(err error) (bool, uint32) {
		h.mu.Lock()
		h.err = err
		h.mu.Unlock()
		if err != nil {
			// A service-specific exit code makes the SCM apply the
			// recovery actions (restart) the installer configured.
			return true, 1
		}
		return false, 0
	}
	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			return finish(err)
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: stopWaitHint}
				cancel()
				return finish(<-done)
			}
		}
	}
}
