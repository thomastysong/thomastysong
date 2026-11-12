package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHooksInstallStatusUninstallUserScope(t *testing.T) {
	home := t.TempDir()
	secret := fakeToken("sk-ant-"+"api03-", 80, 3)
	settings := filepath.Join(home, ".claude", "settings.json")
	orig := "{\n  \"model\": \"sonnet\",\n  \"env\": {\n    \"ANTHROPIC_API_KEY\": \"" + secret + "\"\n  }\n}\n"
	writeTestFile(t, settings, orig, 0o600)

	ta := newTestApp(t)
	ta.env["HOME"] = home
	args := []string{"--scope", "user", "--home", home, "--agents", "claude-code", "--binary", "/opt/spoor/bin/spoor"}

	// Dry run: plan and redacted diff, nothing written.
	out := ta.mustRun(t, exitOK, append([]string{"hooks", "install", "--dry-run"}, args...)...)
	if strings.Contains(out, secret) {
		t.Fatalf("dry run printed a credential:\n%s", out)
	}
	if !strings.Contains(out, "claude-code") || !strings.Contains(out, "merge") || !strings.Contains(out, "hook") || !strings.Contains(out, "nothing was written") {
		t.Fatalf("dry run output:\n%s", out)
	}
	if b, _ := os.ReadFile(settings); string(b) != orig {
		t.Fatal("dry run changed the file")
	}
	var res planResult
	decodeJSON(t, ta.mustRun(t, exitOK, append([]string{"hooks", "install", "--dry-run", "--json"}, args...)...), &res)
	if len(res.Plans) != 1 || res.Plans[0].Action != "merge" || len(res.Plans[0].Diff) == 0 || !res.DryRun {
		t.Fatalf("plans: %+v", res)
	}
	for _, l := range res.Plans[0].Diff {
		if !strings.HasPrefix(l, "@@") && !strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "-") {
			t.Fatalf("context line in diff: %q", l)
		}
	}

	// Install, then status reports "user", idempotent second install.
	ta.mustRun(t, exitOK, append([]string{"hooks", "install"}, args...)...)
	b, _ := os.ReadFile(settings)
	if !strings.Contains(string(b), "/opt/spoor/bin/spoor") || !strings.Contains(string(b), secret) || !strings.Contains(string(b), `"model": "sonnet"`) {
		t.Fatalf("installed file:\n%s", b)
	}
	decodeJSON(t, ta.mustRun(t, exitOK, append([]string{"hooks", "install", "--json"}, args...)...), &res)
	if res.Plans[0].Action != "unchanged" {
		t.Fatalf("second install: %+v", res.Plans[0])
	}
	var states []hookState
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "status", "--scope", "user", "--home", home, "--agents", "claude-code", "--json"), &states)
	if len(states) != 1 || states[0].Status != "user" || states[0].Agent != "claude-code" {
		t.Fatalf("status: %+v", states)
	}
	txt := ta.mustRun(t, exitOK, "hooks", "status", "--scope", "user", "--home", home, "--agents", "claude-code")
	if !strings.Contains(txt, "claude-code") || !strings.Contains(txt, "user") {
		t.Fatalf("status table:\n%s", txt)
	}

	// Uninstall restores the original bytes.
	ta.mustRun(t, exitOK, "hooks", "uninstall", "--scope", "user", "--home", home, "--agents", "claude-code")
	if b, _ := os.ReadFile(settings); string(b) != orig {
		t.Fatalf("uninstall did not restore the file:\n%s", b)
	}
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "status", "--scope", "user", "--home", home, "--agents", "claude-code", "--json"), &states)
	if states[0].Status == "user" {
		t.Fatalf("still installed: %+v", states)
	}
}

func TestHooksRelocationEnvOnlyForOwnHome(t *testing.T) {
	home := t.TempDir()
	relocated := filepath.Join(t.TempDir(), "claude-config")
	ta := newTestApp(t)
	ta.env["HOME"] = home
	ta.env["CLAUDE_CONFIG_DIR"] = relocated
	var res planResult
	// Own home (no --home): the caller's CLAUDE_CONFIG_DIR applies.
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--agents", "claude-code", "--binary", "/usr/bin/spoor", "--dry-run", "--json"), &res)
	if !strings.HasPrefix(res.Plans[0].Path, relocated) {
		t.Fatalf("relocation ignored: %s", res.Plans[0].Path)
	}
	// Explicit --home: another account, the caller's variables do not apply.
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--home", home, "--agents", "claude-code", "--binary", "/usr/bin/spoor", "--dry-run", "--json"), &res)
	if !strings.HasPrefix(res.Plans[0].Path, home) {
		t.Fatalf("--home not used: %s", res.Plans[0].Path)
	}
}

func TestHooksUsageErrors(t *testing.T) {
	ta := newTestApp(t)
	home := t.TempDir()
	ta.mustRun(t, exitUsage, "hooks", "install", "--scope", "galaxy", "--home", home)
	ta.mustRun(t, exitUsage, "hooks", "install", "--scope", "user", "--home", home, "--fail-closed")
	ta.mustRun(t, exitUsage, "hooks", "install", "--scope", "user", "--home", home, "--binary", "relative/spoor")
	ta.mustRun(t, exitUsage, "hooks", "status", "extra")
}

func TestInTempDir(t *testing.T) {
	if !inTempDir(filepath.Join(os.TempDir(), "go-build1", "spoor")) {
		t.Fatal("temp path not recognised")
	}
	if inTempDir("/usr/bin/spoor") {
		t.Fatal("system path flagged")
	}
}
