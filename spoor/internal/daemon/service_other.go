//go:build !windows

package daemon

import (
	"context"
	"log/slog"

	"github.com/thomastysong/spoor/internal/config"
)

// runService: on Linux and macOS the daemon is a plain foreground process
// under systemd or launchd, which stop it with SIGTERM (the caller's
// context).
func runService(context.Context, *config.Config, *slog.Logger) (bool, error) { return false, nil }
