package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
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
		d.Detection = &event.Detection{RuleID: "HB-EXEC-001", Title: "t", Severity: "high", Class: "finding"}
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
		"unix:///run/fluent-bit/hawkbell.sock":   "unix:///run/fluent-bit/hawkbell.sock",
	} {
		if got := endpointHost(in); got != want && !(strings.HasPrefix(in, "unix") && got != "") {
			t.Errorf("endpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// -n below zero and a non-positive --interval are usage errors, not a
// slice-bounds panic or a NewTicker panic.
func TestPrivacyTailRejectsBadFlags(t *testing.T) {
	cfg, _ := testConfig(t, "")
	ta := newTestApp(t)
	for _, args := range [][]string{{"-n", "-1"}, {"--follow", "--interval", "0s"}, {"--interval", "-1s"}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("privacy tail %v panicked: %v", args, r)
				}
			}()
			if got := ta.run(append([]string{"privacy", "tail", "--config", cfg}, args...)...); got != exitUsage {
				t.Fatalf("privacy tail %v: exit %d, want %d", args, got, exitUsage)
			}
		}()
	}
	// -n 0 shows nothing before following, without an error.
	ta.mustRun(t, exitOK, "privacy", "tail", "--config", cfg, "-n", "0")
}

// An account that can read neither the outbox nor the local ring is told
// so and the command fails, instead of printing nothing as if nothing had
// been recorded (the poll itself is unit-tested here; test/e2e runs the
// binary as nobody against the daemon's layout).
func TestPrivacyTailDeniedDirs(t *testing.T) {
	cfg, _ := testConfig(t, "output:\n  group: shippers\n")
	c, _, err := loadConfig(cfgFlags{path: cfg})
	if err != nil {
		t.Fatal(err)
	}
	tl := newTailer(c)
	if tl.dirs[0].access != `readable by root and the members of "shippers"` || tl.dirs[1].access != "readable by root only" {
		t.Fatalf("access texts: %+v", tl.dirs)
	}
	if !permsChecked || os.Geteuid() == 0 {
		return
	}
	for _, d := range []string{c.OutboxDir(), c.LocalDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		os.Chmod(d, 0)
		defer os.Chmod(d, 0o700)
	}
	ta := newTestApp(t)
	if code := ta.run("privacy", "tail", "--config", cfg); code != exitError || !strings.Contains(ta.errb.String(), "cannot read the records") {
		t.Fatalf("exit %d\n%s", code, ta.errb.String())
	}
}

// With pseudonymize_users the state database holds the pseudonym (the
// pipeline stores the redacted record): purge erases by the pseudonyms of
// the name and the id as well as by the plain values.
func TestPurgePseudonymizedStateRows(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "tenant.key")
	writeTestFile(t, key, strings.Repeat("k", 48)+"\n", 0o600)
	cfg, data := testConfig(t, "privacy:\n  hmac_key_file: "+key+"\n  key_id: k1\n  pseudonymize_users: true\n")
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", fakeHostRoot(t), "--projects=false", "--state")

	countRows := func() int {
		ro, err := state.OpenReadOnly(filepath.Join(data, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		n := 0
		for _, tbl := range []string{"agents", "mcp_servers", "posture"} {
			rows, err := ro.Query(tbl, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rows {
				if strings.HasPrefix(r["owner"], "u_") {
					n++
				}
			}
		}
		return n
	}
	before := countRows()
	if before == 0 {
		t.Fatal("scan wrote no pseudonymized owned rows")
	}
	var res purgeResult
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "dev", "--json"), &res)
	if after := countRows(); after != 0 || res.StateRows < before {
		t.Fatalf("purge --user dev left %d of %d pseudonymized state row(s) (state_rows=%d, notes=%v)", after, before, res.StateRows, res.Notes)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "tenant key") {
			t.Fatalf("the key was readable, yet: %q", n)
		}
	}

	// An unreadable key is said plainly.
	cfg2, _ := testConfig(t, "privacy:\n  hmac_key_file: "+filepath.Join(dir, "missing.key")+"\n  key_id: k1\n  pseudonymize_users: true\n")
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg2, "--user", "dev", "--json"), &res)
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "tenant key could not be used") {
		t.Fatalf("notes: %v", res.Notes)
	}
}

// The hook spool <data>/spool/<uid>/ holds the account's activity WITH
// local content until the daemon has read it and retention has passed:
// purge overwrites the account's lines in place (same size, same file, so
// the daemon's byte offsets stay valid) and leaves other accounts' lines.
func TestPurgeErasesSpoolContent(t *testing.T) {
	cfg, data := testConfig(t, "")
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	alice := spoolLine(t, shellEvent(t, "sp1", "s-alice", "alice", "cat ~/.netrc", t0), map[string]any{"command": "cat ~/.netrc", "secret_prompt": "alice private prompt text"})
	bob := spoolLine(t, shellEvent(t, "sp2", "s-bob", "bob", "ls", t0), map[string]any{"command": "ls", "note": "bob keeps this"})
	sp := filepath.Join(data, "spool", "1001", "activity-20261110.ndjson")
	content := string(alice) + "\n" + string(bob) + "\n"
	writeTestFile(t, sp, content, 0o600)
	before, _ := os.Stat(sp)
	ta := newTestApp(t)

	var dry purgeResult
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "alice", "--dry-run", "--json"), &dry)
	if dry.SpoolLines != 1 {
		t.Fatalf("dry run: %+v", dry)
	}
	if b, _ := os.ReadFile(sp); string(b) != content {
		t.Fatal("the dry run changed the spool")
	}
	var res purgeResult
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "alice", "--json"), &res)
	b, _ := os.ReadFile(sp)
	if strings.Contains(string(b), "alice private prompt text") || res.SpoolLines != 1 || res.SpoolFiles != 1 {
		t.Fatalf("purge --user alice left alice's spooled content (%+v):\n%s", res, b)
	}
	if !strings.Contains(string(b), "bob keeps this") || len(b) != len(content) {
		t.Fatalf("another account's line or the file length changed:\n%q", b)
	}
	if after, _ := os.Stat(sp); !os.SameFile(before, after) {
		t.Fatal("the spool file was replaced: the daemon's reader would read it again from the start")
	}

	// --uid names the account's own spool directory: every line there is
	// the account's, whatever the lines claim, and its guard-mode session
	// state goes too.
	own := filepath.Join(data, "spool", "1002", "activity-20261110.ndjson")
	writeTestFile(t, own, string(bob)+"\n", 0o600)
	writeTestFile(t, filepath.Join(data, "spool", "1002", "state", "abc"), "{}", 0o600)
	decodeJSON(t, ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "carol", "--uid", "1002", "--json"), &res)
	if b, _ := os.ReadFile(own); strings.TrimSpace(string(b)) != "" || res.SpoolState != 1 {
		t.Fatalf("own spool after purge (%+v):\n%q", res, b)
	}
	if _, err := os.Stat(filepath.Join(data, "spool", "1002", "state", "abc")); err == nil {
		t.Fatal("guard state survived")
	}
	if b, _ := os.ReadFile(sp); !strings.Contains(string(b), "bob keeps this") {
		t.Fatal("purging carol's directory touched another directory's lines")
	}
}

// Spool directories are writable by the accounts they belong to: links
// planted there must not lead an administrator's purge to write or delete
// anything outside them.
func TestPurgeSpoolRefusesLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	cfg, data := testConfig(t, "")
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	line := string(spoolLine(t, shellEvent(t, "sp1", "s-a", "alice", "ls", t0), map[string]any{"command": "ls"})) + "\n"

	// Victims outside the spool, in the shape purge looks for.
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.ndjson")
	writeTestFile(t, victim, line, 0o644)
	victimState := filepath.Join(outside, "state", "precious")
	writeTestFile(t, victimState, "keep", 0o644)

	dir := filepath.Join(data, "spool", "1001")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(victim, filepath.Join(dir, "activity-a.ndjson")))
	must(os.Link(victim, filepath.Join(dir, "activity-b.ndjson")))
	must(os.Symlink(filepath.Join(outside, "state"), filepath.Join(dir, "state")))
	// A FIFO must not block the purge.
	if err := syscallMkfifo(filepath.Join(dir, "activity-c.ndjson")); err != nil {
		t.Log("no FIFO:", err)
	}

	ta := newTestApp(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ta.mustRun(t, exitOK, "privacy", "purge", "--config", cfg, "--user", "alice", "--uid", "1001", "--json")
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("purge blocked (FIFO?)")
	}
	if b, _ := os.ReadFile(victim); string(b) != line {
		t.Fatalf("purge wrote through a link into %s:\n%q", victim, b)
	}
	if _, err := os.Stat(victimState); err != nil {
		t.Fatalf("purge deleted through a planted state link: %v", err)
	}
}
