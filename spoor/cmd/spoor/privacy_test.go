package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

func TestPrivacyShow(t *testing.T) {
	cfg, data := testConfig(t, "privacy:\n  exclude:\n    users: [svc-build]\noutput:\n  otlp:\n    endpoint: https://user:pw@collector.example.com:4318/v1/logs?token=x\n")
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "privacy", "show", "--config", cfg)
	for _, want := range []string{"Privacy profile: minimal", filepath.Join(data, "outbox"), "svc-build", "https://collector.example.com:4318", "local ring"} {
		if !strings.Contains(out, want) {
			t.Errorf("privacy show lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "pw@") || strings.Contains(out, "token=x") {
		t.Fatalf("endpoint credentials shown:\n%s", out)
	}
	var v privacyView
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "show", "--config", cfg, "--json"), &v)
	if v.Profile != "minimal" || len(v.Statements) < 3 || v.Retention["outbox"] == "" {
		t.Fatalf("%+v", v)
	}
}

func TestPrivacyShowUnreadableKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "missing.key")
	cfg, _ := testConfig(t, "privacy:\n  hmac_key_file: "+key+"\n  key_id: k1\n")
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "privacy", "show", "--config", cfg)
	if !strings.Contains(out, "A tenant key is configured (key id k1)") || !strings.Contains(out, "could not be read") {
		t.Fatalf("an unreadable key must not read as 'no key':\n%s", out)
	}
}

func nativeLine(t *testing.T, user, uid, cmd string, i int) string {
	t.Helper()
	e := &event.Event{V: 1, ID: "id-" + user + "-" + string(rune('a'+i)), TS: event.At(time.Date(2026, 11, 10, 9, i, 0, 0, time.UTC)),
		Kind: event.KindActivity, Type: event.TypeToolPre, Source: event.SourceHook,
		User: &event.User{Name: user, ID: uid}, Agent: &event.Agent{ID: "claude-code"}, Target: &event.Target{Command: cmd}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestPrivacyTailAndPurge(t *testing.T) {
	cfg, data := testConfig(t, "")
	me := currentUser()
	local := filepath.Join(data, "local")
	outbox := filepath.Join(data, "outbox")
	seg := "activity-20261110-09-0000.ndjson"
	writeTestFile(t, filepath.Join(local, seg),
		nativeLine(t, "alice", "1001", "make test", 0)+nativeLine(t, me.Name, me.UID, "go build ./...", 1)+nativeLine(t, "alice", "1001", "git push", 2)+`{"partial":`, 0o640)
	writeTestFile(t, filepath.Join(outbox, "detection-20261110-09-0000.ndjson"), nativeLine(t, "alice", "1001", "x", 3), 0o640)
	writeTestFile(t, filepath.Join(local, "README"), "not a segment\n", 0o640)

	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "privacy", "tail", "--config", cfg)
	if !strings.Contains(out, "go build") || strings.Contains(out, "make test") {
		t.Fatalf("tail must show only the caller's records:\n%s", out)
	}
	if me.Name != "alice" {
		ta.mustRun(t, exitOK, "privacy", "tail", "--config", cfg, "--json")
		if strings.Contains(ta.out.String(), "alice") {
			t.Fatal("another user's record in tail --json")
		}
	}

	// A state database with rows of both users.
	st, err := state.Open(filepath.Join(data, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	for i, u := range []string{"alice", me.Name} {
		d := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
		d.ID = "det-" + u
		d.TS = event.At(time.Now().Add(time.Duration(i) * time.Second))
		d.User = &event.User{Name: u, ID: "x" + u}
		d.Agent = &event.Agent{ID: "claude-code"}
		d.Session = &event.Session{ID: "s-" + u}
		d.Detection = &event.Detection{RuleID: "SPR-EXEC-001", Title: "t", Severity: "high", Class: "finding"}
		if err := st.Apply([]*event.Event{d}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	var dry purgeResult
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "alice", "--dry-run", "--json"), &dry)
	if dry.LocalLines != 2 || dry.OutboxLines != 1 || !dry.DryRun {
		t.Fatalf("dry run: %+v", dry)
	}
	before, _ := os.ReadFile(filepath.Join(local, seg))
	if !strings.Contains(string(before), "make test") {
		t.Fatal("dry run changed the ring")
	}
	var res purgeResult
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "alice", "--json"), &res)
	if res.LocalLines != 2 || res.LocalFiles != 1 || res.StateRows < 1 {
		t.Fatalf("purge: %+v", res)
	}
	after, _ := os.ReadFile(filepath.Join(local, seg))
	if strings.Contains(string(after), "alice") || !strings.Contains(string(after), "go build") || !strings.HasSuffix(string(after), `{"partial":`) {
		t.Fatalf("ring after purge:\n%s", after)
	}
	if fi, _ := os.Stat(filepath.Join(local, seg)); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", fi.Mode().Perm())
	}
	ro, err := state.OpenReadOnly(filepath.Join(data, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	rows, _ := ro.Query("detections", nil)
	for _, r := range rows {
		if strings.Contains(r["user"], "alice") {
			t.Fatalf("alice's detection survived: %v", r)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("detections left: %d, want 1", len(rows))
	}
	ta.mustRun(t, exitUsage, "privacy", "purge", "--config", cfg)
}

func TestPrivacyTailOtherUserNeedsPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	cfg, _ := testConfig(t, "")
	ta := newTestApp(t)
	ta.mustRun(t, exitError, "privacy", "tail", "--config", cfg, "--user", "someone-else")
}

func TestEndpointHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@h.example:4318/v1/logs?x=1": "https://h.example:4318",
		"tcp://127.0.0.1:24224":                  "tcp://127.0.0.1:24224",
		"unix:///run/fluent-bit/spoor.sock":      "unix:///run/fluent-bit/spoor.sock",
	} {
		if got := endpointHost(in); got != want && !(strings.HasPrefix(in, "unix") && got != "") {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}
