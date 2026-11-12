//go:build !windows

package main

import (
	"log/slog"

	"github.com/thomastysong/spoor/internal/config"
)

// isWindowsService is false outside Windows: systemd and launchd run
// `spoor run` as a plain foreground process.
func isWindowsService() bool { return false }

func runService(*config.Config, string, slog.Level, string) int { return exitError }
