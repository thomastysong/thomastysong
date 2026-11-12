package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryFromCommand(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`[ -x '/usr/local/bin/spoor' ] || exit 0; exec '/usr/local/bin/spoor' hook --agent codex`, "/usr/local/bin/spoor"},
		{`[ -x '/opt/O'\''Brien Tools/spoor' ] || exit 0; exec '/opt/O'\''Brien Tools/spoor' hook --agent codex`, "/opt/O'Brien Tools/spoor"},
		{`if (Test-Path -LiteralPath 'C:\Program Files\spoor\spoor.exe' -PathType Leaf) { & 'C:\Program Files\spoor\spoor.exe' hook --agent codex; exit $LASTEXITCODE } else { exit 0 }`, `C:\Program Files\spoor\spoor.exe`},
		{`if (Test-Path -LiteralPath 'C:\O''Brien\spoor.exe' -PathType Leaf) { & 'C:\O''Brien\spoor.exe' hook --agent cursor; exit $LASTEXITCODE } else { exit 0 }`, `C:\O'Brien\spoor.exe`},
		{`C:\spoor\spoor.exe hook --agent cursor`, `C:\spoor\spoor.exe`},
		{`/usr/bin/spoor hook --agent gemini-cli`, "/usr/bin/spoor"},
		{`"/opt/my tools/spoor" hook --agent x`, "/opt/my tools/spoor"},
		{`npm test`, ""},
		{` hook --agent x`, ""},
	} {
		if got := binaryFromCommand(tc.in); got != tc.want {
			t.Errorf("binaryFromCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Every agent's file, as hooks install writes it, yields the binary back.
func TestInstalledBinariesRoundTrip(t *testing.T) {
	home := t.TempDir()
	bin := "/opt/O'Brien Tools/spoor"
	ta := newTestApp(t)
	ta.env["HOME"] = home
	var res planResult
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--home", home, "--binary", bin, "--json"), &res)
	checked := 0
	for _, p := range res.Plans {
		if p.Action == "unsupported" {
			continue
		}
		bins, err := installedBinaries(p.Path)
		if err != nil {
			t.Fatalf("%s: %v", p.Path, err)
		}
		if len(bins) != 1 || bins[0] != bin {
			t.Errorf("%s (%s): binaries %q", p.Agent, p.Path, bins)
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("only %d agent files checked: %+v", checked, res.Plans)
	}
}

func TestDoctorReportsMissingHookBinary(t *testing.T) {
	cfg, _ := testConfig(t, "")
	home := t.TempDir()
	ta := newTestApp(t)
	missing := filepath.Join(t.TempDir(), "gone", "spoor")
	ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--home", home, "--agents", "claude-code,codex", "--binary", missing)
	code := ta.run("doctor", "--config", cfg, "--home", home, "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	c := checkOf(&r, "hooks")
	if c.Status != "fail" || !strings.Contains(c.Detail, "hooks.binary_missing") || code != exitCheck {
		t.Fatalf("missing binary not reported: exit %d %+v", code, c)
	}
	// With the binary in place the check passes.
	writeTestFile(t, missing, "#!/bin/sh\nexit 0\n", 0o755)
	ta.run("doctor", "--config", cfg, "--home", home, "--json")
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "hooks"); c.Status != "ok" {
		t.Fatalf("hooks with the binary present: %+v", c)
	}
	n := 0
	for _, h := range r.Hooks {
		if len(h.Binaries) > 0 {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("binaries found for %d hook files, want 2: %+v", n, r.Hooks)
	}
	if err := os.Chmod(missing, 0o644); err == nil && permsChecked {
		ta.run("doctor", "--config", cfg, "--home", home, "--json")
		decodeJSON(t, ta.out.String(), &r)
		if c := checkOf(&r, "hooks"); c.Status != "fail" || !strings.Contains(c.Detail, "not executable") {
			t.Fatalf("non-executable binary: %+v", c)
		}
	}
}

func TestQuotedStringsJSONC(t *testing.T) {
	b := []byte("{ // comment\n \"hooks\": {\"x\": [{\"command\": \"[ -x '/a b/spoor' ] || exit 0; exec '/a b/spoor' hook --agent cursor\"},]}}\n")
	dir := t.TempDir()
	p := filepath.Join(dir, "hooks.json")
	writeTestFile(t, p, string(b), 0o644)
	bins, err := installedBinaries(p)
	if err != nil || len(bins) != 1 || bins[0] != "/a b/spoor" {
		t.Fatalf("%q %v", bins, err)
	}
}

// A string in a hook file that a monitored user controls must not crash
// the administrator's `spoor doctor`: only blanks before " hook --agent "
// name no program.
func TestBinaryFromCommandHostileNoPanic(t *testing.T) {
	for _, s := range []string{"  hook --agent x", "\t hook --agent x", " \u00a0 hook --agent claude-code", "\x00 hook --agent x", `'' hook --agent x`, `"" hook --agent x`, ` hook --agent  hook --agent x`} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("binaryFromCommand(%q) panicked: %v", s, r)
				}
			}()
			_ = binaryFromCommand(s)
		}()
	}
}

// The same through the file reader doctor uses on every hook file that
// holds spoor entries (any account's settings.json when doctor runs as
// root), and strings outside the hook-command positions are not hooks.
func TestInstalledBinariesHostileSettings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, p, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/bin/spoor","args":["hook","--agent","claude-code"]},{"type":"command","command":"  hook --agent x"}]}]},`+
		`"note":"  hook --agent x","statusLine":{"type":"command","command":"/tmp/not-a-hook hook --agent x"},`+
		`"mcpServers":{"m":{"command":"/tmp/mcp hook --agent x"}}}`, 0o600)
	bins, err := installedBinaries(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(bins) != 1 || bins[0] != "/usr/bin/spoor" {
		t.Fatalf("binaries %q, want only the hook entry's /usr/bin/spoor", bins)
	}
}

// End to end: a monitored user with spoor user hooks adds one string to
// their own settings.json; `spoor doctor` (run by the administrator)
// reports instead of dying with a runtime panic, and does not take the
// status line for a hook binary.
func TestDoctorSurvivesHostileUserSettings(t *testing.T) {
	home := t.TempDir()
	ta := newTestApp(t)
	bin := filepath.Join(t.TempDir(), "spoor")
	writeTestFile(t, bin, "#!/bin/sh\nexit 0\n", 0o755)
	ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--home", home, "--agents", "claude-code", "--binary", bin)
	settings := filepath.Join(home, ".claude", "settings.json")
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["statusLine"] = map[string]any{"type": "command", "command": "  hook --agent x"}
	m["otherLine"] = map[string]any{"type": "command", "command": "/nonexistent/x hook --agent x"}
	b, _ = json.Marshal(m)
	writeTestFile(t, settings, string(b), 0o600)
	cfg, _ := testConfig(t, "")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("spoor doctor panicked on a user-controlled settings.json: %v", r)
			}
		}()
		ta.run("doctor", "--config", cfg, "--home", home, "--json")
	}()
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "hooks"); strings.Contains(c.Detail, "binary_missing") {
		t.Fatalf("a string outside the hook entries was taken for a hook binary: %+v", c)
	}
}
