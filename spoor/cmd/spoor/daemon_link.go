//go:build !spoor_nodaemon

package main

import (
	"context"
	"log/slog"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/daemon"
)

// daemonRun and daemonStatus are the two calls cmd/spoor makes into
// internal/daemon. Doctor renders the snapshot through JSON, so it depends
// on nothing but the function signatures.
func daemonRun(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	daemon.Version = versionString()
	return daemon.Run(ctx, cfg, log)
}

func daemonStatus(cfg *config.Config) (any, error) {
	return daemon.Status(cfg)
}
