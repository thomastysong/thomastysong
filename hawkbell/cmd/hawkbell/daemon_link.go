package main

import (
	"context"
	"log/slog"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/daemon"
)

// daemonRun and daemonStatus are the two calls cmd/hawkbell makes into
// internal/daemon. Doctor renders the snapshot through JSON and judges the
// directory layout by the snapshot's own expectations (Dirs), so the modes
// the daemon creates and the modes doctor accepts are one table.
func daemonRun(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	daemon.Version = versionString()
	return daemon.Run(ctx, cfg, log)
}

func daemonStatus(cfg *config.Config) (daemon.Snapshot, error) {
	return daemon.Status(cfg)
}
