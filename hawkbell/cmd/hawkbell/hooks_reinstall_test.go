package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The marker --only-installed looks for is the one internal/hookinstall
// writes into the status detail of an earlier release's entries.
func TestLegacyMarkerMatchesHookinstall(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "hookinstall", "status.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^const legacyPrefix = "([^"\\]+)"$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("legacyPrefix not found in internal/hookinstall/status.go")
	}
	if string(m[1]) != legacyEntriesMarker {
		t.Fatalf("hookinstall writes %q, --only-installed looks for %q", m[1], legacyEntriesMarker)
	}
}

func TestHooksOnlyInstalledNothingToDo(t *testing.T) {
	home := t.TempDir()
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", "/usr/bin/hawkbell")
	if !strings.Contains(out, "no agent has hawkbell hooks in the user scope: nothing to do") {
		t.Fatalf("output:\n%s", out)
	}
	var res planResult
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", "/usr/bin/hawkbell", "--json"), &res)
	if len(res.Reinstall) != 0 || len(res.Plans) != 0 {
		t.Fatalf("%+v", res)
	}
	// Nothing was created: agents that were never hooked stay unhooked.
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Fatalf("files created in the home: %v", ents)
	}
}

// legacyCommand turns the guarded command lines of one agent in a file back
// into the bare form of releases before the missing-binary guard.
func legacyCommand(t *testing.T, path, bin, agent string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cur := `[ -x '` + bin + `' ] || exit 0; exec '` + bin + `' hook --agent ` + agent
	if !bytes.Contains(b, []byte(cur)) {
		t.Fatalf("no current %s command line in %s:\n%s", agent, path, b)
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(b, []byte(cur), []byte(`'`+bin+`' hook --agent `+agent)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestHooksOnlyInstalledKeepsOptions is a package upgrade in miniature: an
// administrator registered Claude Code fail-closed with a 30 s timeout,
// Codex with a 20 s timeout, an earlier release left Gemini CLI's and
// Codex's entries in the unguarded form, Cursor's are current and Copilot's
// were edited by hand. --only-installed must rewrite exactly the earlier
// release's entries, keep every option, leave the edited file alone and
// never hook an agent that was not hooked.
func TestHooksOnlyInstalledKeepsOptions(t *testing.T) {
	home := t.TempDir()
	ta := newTestApp(t)
	bin := "/usr/bin/hawkbell"
	base := []string{"--scope", "user", "--home", home, "--binary", bin}
	install := func(extra ...string) {
		t.Helper()
		ta.mustRun(t, exitOK, append(append([]string{"hooks", "install"}, base...), extra...)...)
	}
	// --guard at user scope registers the hooks and exits 5 unless the
	// machine's configuration already has guard mode on.
	if code := ta.run(append(append([]string{"hooks", "install"}, base...), "--agents", "claude-code", "--guard", "--fail-closed", "--timeout", "30")...); code != exitOK && code != exitGuardOff {
		t.Fatalf("guarded user install: exit %d: %s", code, ta.errb.String())
	}
	install("--agents", "codex", "--timeout", "20")
	install("--agents", "gemini-cli,cursor,copilot-cli")
	var res planResult
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--dry-run", "--json", "--scope", "user", "--home", home, "--binary", bin), &res)
	paths := map[string]string{}
	for _, r := range res.Reinstall {
		paths[r.Agent] = r.Path
		if r.Outcome != reinstallCurrent {
			t.Errorf("freshly installed %s: %+v", r.Agent, r)
		}
	}
	for _, a := range []string{"claude-code", "codex", "gemini-cli", "cursor", "copilot-cli"} {
		if paths[a] == "" {
			t.Fatalf("no hook file for %s: %+v", a, res.Reinstall)
		}
	}
	legacyCommand(t, paths["gemini-cli"], bin, "gemini-cli")
	legacyCommand(t, paths["codex"], bin, "codex")
	cp, _ := os.ReadFile(paths["copilot-cli"])
	if err := os.WriteFile(paths["copilot-cli"], bytes.Replace(cp, []byte(`"timeoutSec": 10`), []byte(`"timeoutSec": 11`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for a, p := range paths {
		before[a], _ = os.ReadFile(p)
	}

	// Dry run: the plan, nothing written.
	out := ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--dry-run", "--scope", "user", "--home", home, "--binary", bin)
	for _, w := range []string{"user hooks of gemini-cli would be rewritten\n", "user hooks of codex would be rewritten with --timeout 20", "dry run: nothing was written"} {
		if !strings.Contains(out, w) {
			t.Errorf("dry run lacks %q:\n%s", w, out)
		}
	}
	for a, p := range paths {
		if b, _ := os.ReadFile(p); !bytes.Equal(b, before[a]) {
			t.Fatalf("dry run changed %s", p)
		}
	}

	out = ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", bin)
	for _, w := range []string{
		"user hooks rewritten for gemini-cli\n",
		"user hooks rewritten for codex with --timeout 20\n",
		"user hooks of claude-code left as they are: already what install writes (--guard --fail-closed --timeout 30)",
		"user hooks of cursor left as they are: already what install writes\n",
		"user hooks of copilot-cli left as they are: the hawkbell entries differ from what install writes with any options (edited by hand?)",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	for _, a := range []string{"claude-code", "cursor", "copilot-cli"} {
		if b, _ := os.ReadFile(paths[a]); !bytes.Equal(b, before[a]) {
			t.Errorf("%s changed:\n%s", a, b)
		}
	}
	if b, _ := os.ReadFile(paths["claude-code"]); !jsonHas(b, `"onFailure"`, `"block"`) || !jsonHas(b, `"timeout"`, `30`) {
		t.Errorf("claude-code lost its options:\n%s", b)
	}
	if b, _ := os.ReadFile(paths["codex"]); !jsonHas(b, `"timeout"`, `20`) || bytes.Contains(b, []byte(`'/usr/bin/hawkbell' hook --agent codex"`)) && !bytes.Contains(b, []byte(`exec '/usr/bin/hawkbell' hook --agent codex`)) {
		t.Errorf("codex lost its timeout or kept the earlier form:\n%s", b)
	}
	var states []hookState
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "status", "--scope", "user", "--home", home, "--json"), &states)
	for _, s := range states {
		// Status compares with install's default options: Claude Code's
		// fail-closed 30 s registration reads "modified" by design.
		want := map[string]string{"claude-code": "modified", "gemini-cli": "user", "cursor": "user", "copilot-cli": "modified"}[s.Agent]
		if want != "" && s.Status != want {
			t.Errorf("%s after --only-installed: %s (%s)", s.Agent, s.Status, s.Detail)
		}
		if s.Agent == "codex" && s.Status != "user" && s.Status != "modified" {
			t.Errorf("codex: %s", s.Status)
		}
		if s.Hash != "" && map[string]bool{"claude-code": true, "codex": true, "gemini-cli": true, "cursor": true, "copilot-cli": true}[s.Agent] == false {
			t.Errorf("%s was hooked by --only-installed", s.Agent)
		}
	}
	// Codex at a 20 s timeout is current only when compared with 20.
	decodeJSON(t, ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--json", "--scope", "user", "--home", home, "--binary", bin, "--agents", "codex"), &res)
	if len(res.Reinstall) != 1 || res.Reinstall[0].Outcome != reinstallCurrent || res.Reinstall[0].Options != "--timeout 20" {
		t.Errorf("codex after the rewrite: %+v", res.Reinstall)
	}

	// Options given on the command line win over the recovered ones.
	out = ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", bin, "--agents", "cursor", "--timeout", "15")
	if !strings.Contains(out, "user hooks rewritten for cursor with --timeout 15") {
		t.Errorf("explicit --timeout:\n%s", out)
	}
	if b, _ := os.ReadFile(paths["cursor"]); !jsonHas(b, `"timeout"`, `15`) {
		t.Errorf("cursor timeout not 15:\n%s", b)
	}
	// --fail-closed=false turns the administrator's fail-closed registration
	// off only when asked for.
	out = ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", bin, "--agents", "claude-code", "--guard=false")
	if b, _ := os.ReadFile(paths["claude-code"]); bytes.Contains(b, []byte(`"onFailure"`)) || !jsonHas(b, `"timeout"`, `30`) {
		t.Errorf("--guard=false: fail-closed kept or timeout lost:\n%s\n%s", out, b)
	}
}

// A new binary location (an upgrade that moved the binary) is written into
// the entries, and said.
func TestHooksOnlyInstalledMovesBinary(t *testing.T) {
	home := t.TempDir()
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "hooks", "install", "--scope", "user", "--home", home, "--binary", "/opt/old/hawkbell", "--agents", "gemini-cli")
	out := ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "user", "--home", home, "--binary", "/usr/bin/hawkbell")
	if !strings.Contains(out, "user hooks rewritten for gemini-cli (the hooks now run /usr/bin/hawkbell instead of /opt/old/hawkbell)") {
		t.Fatalf("output:\n%s", out)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".gemini", "settings.json"))
	if bytes.Contains(b, []byte("/opt/old/hawkbell")) || !bytes.Contains(b, []byte("/usr/bin/hawkbell")) {
		t.Fatalf("settings:\n%s", b)
	}
}

// Managed scope on a file-system prefix, as the package scripts and the
// Fleet install scripts run it.
func TestHooksOnlyInstalledManagedRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("managed hook files are root-owned")
	}
	prefix := t.TempDir()
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "hooks", "install", "--scope", "managed", "--root", prefix, "--binary", "/usr/bin/hawkbell", "--agents", "gemini-cli")
	gemini := filepath.Join(prefix, "etc", "gemini-cli", "settings.json")
	legacyCommand(t, gemini, "/usr/bin/hawkbell", "gemini-cli")
	out := ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "managed", "--root", prefix, "--binary", "/usr/bin/hawkbell")
	if out != "managed hooks rewritten for gemini-cli\n" {
		t.Fatalf("output %q", out)
	}
	out = ta.mustRun(t, exitOK, "hooks", "install", "--only-installed", "--scope", "managed", "--root", prefix, "--binary", "/usr/bin/hawkbell")
	if out != "managed hooks of gemini-cli left as they are: already what install writes\n" {
		t.Fatalf("second run %q", out)
	}
}

// jsonHas reports whether key: value appears in a JSON text, whatever the
// spacing hookinstall kept from the file.
func jsonHas(b []byte, key, value string) bool {
	return regexp.MustCompile(regexp.QuoteMeta(key) + `\s*:\s*` + regexp.QuoteMeta(value) + `([^0-9]|$)`).Match(b)
}

func TestHookOptsFlags(t *testing.T) {
	for _, tc := range []struct {
		o    hookOpts
		want string
	}{
		{hookOpts{timeout: 10}, ""},
		{hookOpts{}, ""},
		{hookOpts{timeout: 30}, "--timeout 30"},
		{hookOpts{failClosed: true, timeout: 10}, "--guard --fail-closed"},
		{hookOpts{failClosed: true, timeout: 5}, "--guard --fail-closed --timeout 5"},
	} {
		if got := tc.o.flags(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.o, got, tc.want)
		}
	}
}

func TestInstalledTimeouts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, p, `{"hooks":{"a":[{"hooks":[{"command":"x","timeout":30000}]}],"b":[{"timeoutSec":7},{"timeout":2.5},{"timeout":-1},{"timeout":"9"},{"timeout":99999999}]},"timeout":44}`, 0o644)
	got := installedTimeouts(p)
	want := map[int]bool{30: true, 7: true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("got %v", got)
		}
	}
	if installedTimeouts(filepath.Join(t.TempDir(), "missing.json")) != nil {
		t.Fatal("missing file")
	}
}
