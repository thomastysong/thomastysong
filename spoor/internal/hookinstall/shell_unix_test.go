//go:build unix

package hookinstall

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/thomastysong/spoor/internal/event"
)

// collectCommands pulls every POSIX shell string out of a generated hook
// file, decoded by the standard library rather than by this package.
func collectCommands(t *testing.T, path string, data []byte) []string {
	t.Helper()
	var root map[string]any
	if strings.HasSuffix(path, ".toml") {
		if _, err := toml.Decode(string(data), &root); err != nil {
			t.Fatalf("TOML: %v", err)
		}
	} else if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, k := range []string{"command", "bash"} {
				if s, ok := x[k].(string); ok {
					if _, exec := x["args"]; !exec {
						out = append(out, s)
					}
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(root["hooks"])
	return out
}

// TestShellQuotingExecutes runs the generated command lines through every
// POSIX shell installed here with a binary whose path has spaces and an
// apostrophe, and checks the exact argument vector that arrives.
func TestShellQuotingExecutes(t *testing.T) {
	var shells []string
	for _, s := range []string{"sh", "bash", "dash", "zsh", "ksh", "fish"} {
		if p, err := exec.LookPath(s); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Skip("no POSIX shell available")
	}
	dir := filepath.Join(t.TempDir(), "O'Brien Tools & co")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "spoor")
	out := filepath.Join(t.TempDir(), "argv")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$ARGV_OUT\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	c := testCatalog(t)
	cases := []struct {
		agent string
		scope event.Scope
		want  string
	}{
		{"codex", event.ScopeUser, "codex"},
		{"codex", event.ScopeManaged, "codex"},
		{"copilot-cli", event.ScopeUser, "copilot-cli"},
		{"gemini-cli", event.ScopeUser, "gemini-cli"},
		{"cursor", event.ScopeUser, "cursor"},
		{"cursor-agent", event.ScopeUser, "cursor"},
	}
	for _, tc := range cases {
		o := opts(t, "linux", tc.scope, tc.agent)
		o.Binary = bin
		p := only(t, mustPlan(t, c, o), tc.agent)
		cmds := collectCommands(t, p.Path, p.After)
		if len(cmds) == 0 {
			t.Fatalf("%s: no shell commands in %s", tc.agent, p.After)
		}
		for _, sh := range shells {
			for _, cmdline := range dedupe(cmds) {
				_ = os.Remove(out)
				cmd := exec.Command(sh, "-c", cmdline)
				cmd.Env = append(os.Environ(), "ARGV_OUT="+out)
				if b, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s via %s: %v: %s", tc.agent, sh, err, b)
				}
				got := strings.Split(strings.TrimRight(string(readBytes(t, out)), "\n"), "\n")
				if want := []string{"hook", "--agent", tc.want}; !reflect.DeepEqual(got, want) {
					t.Errorf("%s via %s: argv %q, want %q (command %q)", tc.agent, sh, got, want, cmdline)
				}
			}
		}
	}

	// Claude Code's exec form involves no shell: command plus args.
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	o.Binary = bin
	p := only(t, mustPlan(t, c, o), "claude-code")
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(p.After, &doc); err != nil {
		t.Fatal(err)
	}
	h := doc.Hooks["PreToolUse"][0].Hooks[0]
	_ = os.Remove(out)
	cmd := exec.Command(h.Command, h.Args...)
	cmd.Env = append(os.Environ(), "ARGV_OUT="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exec form: %v: %s", err, b)
	}
	if got := strings.TrimSpace(string(readBytes(t, out))); got != "hook\n--agent\nclaude-code" {
		t.Errorf("exec form argv %q", got)
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
