package daemon

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
)

func TestStatusEmptyInstallation(t *testing.T) {
	cfg := config.Default(filepath.Join(t.TempDir(), "data"))
	cfg.Output.FluentBit.TailDB = filepath.Join(t.TempDir(), "missing.db")
	s, err := status(cfg, statusEnv{
		now: time.Now(), privileged: false, disabled: func() bool { return true },
		killPath: "/etc/spoor/disabled",
		host:     func() HostStatus { return HostStatus{Source: "none"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.KillSwitch.Engaged || s.Privileged || s.State.Readable || s.Outbox.Segments != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	joined := strings.Join(s.Problems, "\n")
	for _, want := range []string{"not running privileged", "kill switch", "no host id", "state database unreadable", "missing"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems do not mention %q:\n%s", want, joined)
		}
	}
	if len(s.Outbox.Consumers) != 1 || s.Outbox.Consumers[0].Readable {
		t.Errorf("consumers = %+v", s.Outbox.Consumers)
	}
	// It must render as JSON for `spoor doctor --json`.
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
	if _, err := status(nil, statusEnv{}); err == nil {
		t.Error("nil config accepted")
	}
	if _, err := Status(config.Default("")); err == nil {
		t.Error("empty data dir accepted")
	}
}

func TestStatusConfigHostID(t *testing.T) {
	cfg := config.Default(filepath.Join(t.TempDir(), "data"))
	cfg.HostID = "fleet-uuid"
	s, err := status(cfg, statusEnv{now: time.Now(), disabled: func() bool { return false },
		host: func() HostStatus { return HostStatus{ID: "dmi", Source: "dmi"} }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Host.ID != "fleet-uuid" || s.Host.Source != "config" {
		t.Errorf("host = %+v", s.Host)
	}
}
