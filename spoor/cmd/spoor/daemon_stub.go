//go:build spoor_nodaemon

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/thomastysong/spoor/internal/config"
)

// TEMPORARY: internal/daemon is being written in parallel. Build with
// -tags spoor_nodaemon until it exists; delete this file afterwards.
var errNoDaemon = errors.New("this build has no daemon (built with -tags spoor_nodaemon)")

func daemonRun(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return errNoDaemon
}

func daemonStatus(cfg *config.Config) (any, error) { return nil, errNoDaemon }
