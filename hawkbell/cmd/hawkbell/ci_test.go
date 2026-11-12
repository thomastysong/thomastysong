package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The command stands in for an agent: it checks that the hooks were
// registered in the temporary config home it was given, and writes the
// spool line the hook would have written for a curl | sh tool call.
func TestCIExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci exec is unix only")
	}
	cfg, _ := testConfig(t, "")
	rec := spoolLine(t, shellEvent(t, "c1", "ci-session", "runner", curlPipe, time.Now()), map[string]any{"command": curlPipe})
	recFile := filepath.Join(t.TempDir(), "rec.ndjson")
	writeTestFile(t, recFile, string(rec)+"\n", 0o600)
	script := `set -e
grep -q '/usr/bin/hawkbell' "$CLAUDE_CONFIG_DIR/settings.json"
test -n "$CODEX_HOME" && test -n "$GEMINI_CLI_HOME"
cat "$REC" > "$HAWKBELL_SPOOL/activity-20261110.ndjson"
exit 7`
	t.Setenv("REC", recFile)
	ta := newTestApp(t)
	ta.env["HOME"] = t.TempDir()
	out := ta.mustRun(t, exitFindings, "ci", "exec", "--config", cfg, "--", "sh", "-c", script)
	if !strings.Contains(out, "HB-EXEC-001") || !strings.Contains(out, "exited 7") {
		t.Fatalf("ci exec:\n%s\nstderr:\n%s", out, ta.errb.String())
	}
	if !strings.Contains(ta.errb.String(), "cursor") {
		t.Errorf("skipping Cursor (no config-home variable) must be said:\n%s", ta.errb.String())
	}
	// Below --fail-on, the command's own exit code is returned.
	ta.mustRun(t, 7, "ci", "exec", "--config", cfg, "--fail-on", "critical", "--", "sh", "-c", script)
	// No findings and success.
	out = ta.mustRun(t, exitOK, "ci", "exec", "--config", cfg, "--", "true")
	if !strings.Contains(out, "no hook record was written") {
		t.Fatalf("empty run:\n%s", out)
	}
	ta.mustRun(t, exitUsage, "ci", "exec", "--config", cfg)
	ta.mustRun(t, exitError, "ci", "exec", "--config", cfg, "--", "/nonexistent/agent")
}

func TestCIExecInPlace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci exec is unix only")
	}
	cfg, _ := testConfig(t, "")
	home := t.TempDir()
	ta := newTestApp(t)
	ta.env["HOME"] = home
	settings := filepath.Join(home, ".claude", "settings.json")
	script := `grep -q '/usr/bin/hawkbell' "$HOME_SETTINGS"`
	t.Setenv("HOME_SETTINGS", settings)
	ta.mustRun(t, exitOK, "ci", "exec", "--config", cfg, "--in-place", "--agents", "claude-code", "--", "sh", "-c", script)
	// The hooks are removed afterwards (hawkbell created the file, so it goes).
	if b, err := os.ReadFile(settings); err == nil && strings.Contains(string(b), "hawkbell") {
		t.Fatalf("in-place hooks left behind:\n%s", b)
	}
}
