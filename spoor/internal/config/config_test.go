package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreSafe(t *testing.T) {
	c, err := Load("", "/var/lib/spoor")
	if err != nil {
		t.Fatal(err)
	}
	if c.Privacy.Profile != "minimal" || c.Guard.Mode != "off" || c.Output.MaxLine != 16<<10 {
		t.Fatalf("unsafe defaults: %+v %+v %d", c.Privacy, c.Guard, c.Output.MaxLine)
	}
	if c.OutboxDir() != filepath.Join("/var/lib/spoor", "outbox") || c.Heartbeat.D() != 5*time.Minute {
		t.Fatalf("paths/heartbeat wrong: %s %s", c.OutboxDir(), c.Heartbeat.D())
	}
	if !On(c.Sources.Hooks.Enabled, false) || On(nil, false) || !On(nil, true) {
		t.Fatal("On tri-state wrong")
	}
}

func TestMissingAndEmptyFileMeanDefaults(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), "/d"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(write(t, ""), "/d")
	if err != nil || c.Privacy.Profile != "minimal" {
		t.Fatalf("empty file: %v %+v", err, c)
	}
}

func TestOverridesAndDurations(t *testing.T) {
	c, err := Load(write(t, "privacy:\n  profile: standard\nheartbeat: 90s\nsources:\n  transcripts:\n    enabled: false\n    backfill: 24h\ntags: [offsec]\n"), "/d")
	if err != nil {
		t.Fatal(err)
	}
	if c.Privacy.Profile != "standard" || c.Heartbeat.D() != 90*time.Second || On(c.Sources.Transcripts.Enabled, true) || c.Sources.Transcripts.Backfill.D() != 24*time.Hour || c.Tags[0] != "offsec" {
		t.Fatalf("override not applied: %+v", c)
	}
	// Untouched sections keep their defaults.
	if !On(c.Sources.Hooks.Enabled, false) || c.Limits.ActivityBurst != 200 {
		t.Fatal("defaults lost on partial override")
	}
}

func TestRejectsTyposAndWeakeningValues(t *testing.T) {
	bad := map[string]string{
		"unknown key":                            "privcy:\n  profile: full\n",
		"bad profile":                            "privacy:\n  profile: everything\n",
		"bad guard":                              "guard:\n  mode: enforce\n",
		"line cap too large":                     "output:\n  max_line_bytes: 1000000\n",
		"line cap below the outbox writer floor": "output:\n  max_line_bytes: 4096\n",
		"pseudonym without key":                  "privacy:\n  pseudonymize_users: true\n",
		"unsigned bundle":                        "bundle:\n  url: https://example.invalid/b.tgz\n",
		"negative duration":                      "heartbeat: -5m\n",
		"tiny heartbeat":                         "heartbeat: 1s\n",
		"unknown adapter":                        "sources:\n  adapters:\n    - format: other\n",
	}
	for name, body := range bad {
		if _, err := Load(write(t, body), "/d"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOversizeConfigRejected(t *testing.T) {
	if _, err := Load(write(t, "# "+strings.Repeat("x", 1<<20+10)+"\n"), "/d"); err == nil {
		t.Fatal("oversize config accepted")
	}
}
