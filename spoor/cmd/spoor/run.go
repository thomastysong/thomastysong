package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/thomastysong/spoor/internal/config"
)

const runAbout = `Runs the sensor until SIGINT or SIGTERM (or a Windows service stop), then
flushes and exits 0. This is what the systemd unit, the launchd daemon and
the Windows service start. Logs go to stderr (the service manager's log);
under the Windows service control manager they go to <data_dir>\spoor.log.
While the kill switch is on the collectors idle and only a "disabled"
heartbeat is written.`

func (a *app) cmdRun(args []string) int {
	fs := a.newFlags("run", "run [--config file] [--data-dir dir] [--log-level info] [--log-format text|json]", runAbout)
	var cf cfgFlags
	cf.register(fs)
	level := fs.String("log-level", "info", "log level: debug, info, warn or error")
	format := fs.String("log-format", "text", "log format: text or json")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("run", "unexpected argument %q", pos[0])
	}
	lvl, ok := parseLevel(*level)
	if !ok {
		return a.usageErr("run", "--log-level %q: want debug, info, warn or error", *level)
	}
	if *format != "text" && *format != "json" {
		return a.usageErr("run", "--log-format %q: want text or json", *format)
	}
	cfg, path, err := loadConfig(cf)
	if err != nil {
		return a.fail("run", err)
	}
	var logw io.Writer = a.stderr
	if isWindowsService() {
		// The service has no console. internal/daemon recognises the
		// service control manager itself and runs under svc.Run.
		if f, err := openServiceLog(cfg); err == nil {
			defer f.Close()
			logw = f
		}
	}
	log := newLogger(logw, lvl, *format)
	ctx, stop := signal.NotifyContext(a.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDaemon(ctx, cfg, path, log)
}

// runDaemon runs the daemon until ctx ends; a return caused by the
// cancellation itself is a clean stop.
func runDaemon(ctx context.Context, cfg *config.Config, path string, log *slog.Logger) (code int) {
	defer func() {
		// A panic on the daemon's own goroutine becomes an orderly failure
		// with the stack in the log; the service manager restarts it.
		if r := recover(); r != nil {
			log.Error("spoor daemon panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			code = exitError
		}
	}()
	log.Info("spoor starting", "version", versionString(), "config", path, "data_dir", cfg.DataDir, "profile", cfg.Privacy.Profile)
	err := daemonRun(ctx, cfg, log)
	if err != nil && !(errors.Is(err, context.Canceled) && ctx.Err() != nil) {
		log.Error("spoor stopped with an error", "err", err)
		return exitError
	}
	log.Info("spoor stopped")
	return exitOK
}

func parseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return 0, false
}

func newLogger(w io.Writer, lvl slog.Level, format string) *slog.Logger {
	o := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, o))
	}
	return slog.New(slog.NewTextHandler(w, o))
}

// openServiceLog opens the log file used when no console is attached.
func openServiceLog(cfg *config.Config) (io.WriteCloser, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(cfg.DataDir+string(os.PathSeparator)+"spoor.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("service log: %w", err)
	}
	return f, nil
}
