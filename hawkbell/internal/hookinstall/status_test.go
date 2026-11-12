package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TestStatusTransitions walks every agent through missing -> installed ->
// modified (tampering) -> foreign_only (hawkbell removed by hand) in both
// scopes.
func TestStatusTransitions(t *testing.T) {
	c := testCatalog(t)
	for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser} {
		for _, agent := range allAgents {
			t.Run(string(sc)+"/"+agent, func(t *testing.T) {
				o := opts(t, "linux", sc, agent)
				installed := StatusUser
				if sc == event.ScopeManaged {
					installed = StatusManaged
				}
				if s := stateOf(t, c, o, agent); s.Status != StatusMissing || s.Hash != "" {
					t.Fatalf("before install: %+v", s)
				}
				plans := mustPlan(t, c, o)
				mustApply(t, plans)
				s := stateOf(t, c, o, agent)
				if s.Status != installed || len(s.Hash) != 64 {
					t.Fatalf("after install: %+v", s)
				}
				// Status without a binary takes it from the file.
				o2 := o
				o2.Binary = ""
				if s2 := stateOf(t, c, o2, agent); s2.Status != installed || s2.Hash != s.Hash {
					t.Errorf("without binary: %+v", s2)
				}
				// A different expected binary is a modification.
				o2.Binary = "/opt/other/hawkbell"
				if s2 := stateOf(t, c, o2, agent); s2.Status != StatusModified {
					t.Errorf("other binary: %+v", s2)
				}

				path := plans[0].Path
				data := readBytes(t, path)
				var tampered []byte
				switch {
				case bytes.Contains(data, []byte(`"timeout": 10,`)):
					tampered = bytes.Replace(data, []byte(`"timeout": 10,`), []byte(`"timeout": 1,`), 1)
				case bytes.Contains(data, []byte(`"timeout": 10`)):
					tampered = bytes.Replace(data, []byte(`"timeout": 10`), []byte(`"timeout": 1`), 1)
				case bytes.Contains(data, []byte(`"timeoutSec": 10`)):
					tampered = bytes.Replace(data, []byte(`"timeoutSec": 10`), []byte(`"timeoutSec": 1`), 1)
				case bytes.Contains(data, []byte(`"timeout": 10000`)):
					tampered = bytes.Replace(data, []byte(`"timeout": 10000`), []byte(`"timeout": 1`), 1)
				case bytes.Contains(data, []byte("timeout = 10\n")):
					tampered = bytes.Replace(data, []byte("timeout = 10\n"), []byte("timeout = 1\n"), 1)
				default:
					t.Fatalf("no timeout to tamper with in\n%s", data)
				}
				writeFile(t, path, tampered, 0o644)
				s3 := stateOf(t, c, o, agent)
				if s3.Status != StatusModified || s3.Detail == "" || s3.Hash == s.Hash {
					t.Errorf("after tampering: %+v", s3)
				}
				// Reinstall repairs the modification.
				mustApply(t, mustPlan(t, c, o))
				if s4 := stateOf(t, c, o, agent); s4.Status != installed {
					t.Errorf("after repair: %+v", s4)
				}

				// Someone removes hawkbell's entries and leaves their own.
				mustApply(t, mustUnplan(t, c, o))
				foreign := map[string]string{
					"claude-code": `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]}}`,
					"codex":       "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"say done\"\n",
					"copilot-cli": `{"version": 1, "hooks": {"Stop": [{"type": "command", "bash": "say done"}]}}`,
					"gemini-cli":  `{"hooks": {"AfterAgent": [{"hooks": [{"type": "command", "command": "say done"}]}]}}`,
					"cursor":      `{"version": 1, "hooks": {"stop": [{"command": "say done"}]}}`,
				}[agent]
				if agent == "codex" && strings.HasSuffix(path, ".json") {
					foreign = `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]}}`
				}
				writeFile(t, path, []byte(foreign), 0o644)
				if s5 := stateOf(t, c, o, agent); s5.Status != StatusForeignOnly {
					t.Errorf("foreign only: %+v", s5)
				}
			})
		}
	}
}

func TestStatusHashIgnoresLayout(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	mustApply(t, mustPlan(t, c, o))
	path := targetPath(t, c, o, "claude-code")
	before := stateOf(t, c, o, "claude-code")
	var buf bytes.Buffer
	if err := json.Compact(&buf, readBytes(t, path)); err != nil {
		t.Fatal(err)
	}
	// The owner adds a key and the file is minified by some tool.
	min := append([]byte(`{"model":"x",`), buf.Bytes()[1:]...)
	writeFile(t, path, min, 0o644)
	after := stateOf(t, c, o, "claude-code")
	if after.Status != StatusUser || after.Hash != before.Hash {
		t.Errorf("before %+v\nafter %+v", before, after)
	}
}

func TestStatusScopes(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", "", "claude-code")
	got := states(t, c, o)
	if len(got) != 2 || got[0].Scope != event.ScopeManaged || got[1].Scope != event.ScopeUser {
		t.Fatalf("%+v", got)
	}
	o.Home = ""
	if got := states(t, c, o); len(got) != 1 {
		t.Errorf("without home: %+v", got)
	}
	o.Scope = event.ScopeSystem
	o.Agents = []string{"codex", "gemini-cli"}
	got = states(t, c, o)
	if len(got) != 2 || got[0].Status != StatusMissing || got[1].Status != StatusUnsupported {
		t.Errorf("system scope: %+v", got)
	}
}

func TestStatusUnreadable(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	writeFile(t, path, []byte(`{"hooks": `), 0o644)
	if s := stateOf(t, c, o, "gemini-cli"); s.Status != StatusUnsupported || strings.Contains(s.Detail, `"hooks"`) {
		t.Errorf("%+v", s)
	}
	writeFile(t, path, []byte(`{"hooks": []}`), 0o644)
	if s := stateOf(t, c, o, "gemini-cli"); s.Status != StatusUnsupported {
		t.Errorf("%+v", s)
	}
	// Copilot rejects a whole file whose version is not 1.
	o = opts(t, "linux", event.ScopeUser, "copilot-cli")
	mustApply(t, mustPlan(t, c, o))
	path = targetPath(t, c, o, "copilot-cli")
	writeFile(t, path, bytes.Replace(readBytes(t, path), []byte(`"version": 1`), []byte(`"version": 2`), 1), 0o644)
	if s := stateOf(t, c, o, "copilot-cli"); s.Status != StatusModified || !strings.Contains(s.Detail, "version") {
		t.Errorf("%+v", s)
	}
}

func TestStatusShadowedClaude(t *testing.T) {
	c := testCatalog(t)
	t.Run("darwin MDM profile", func(t *testing.T) {
		o := opts(t, "darwin", event.ScopeManaged, "claude-code")
		mustApply(t, mustPlan(t, c, o))
		s := stateOf(t, c, o, "claude-code")
		if s.Status != StatusManaged || !strings.Contains(s.Detail, "server-managed") || !strings.Contains(s.Detail, "checked: /Library/Managed Preferences") {
			t.Fatalf("no profile: %+v", s)
		}
		writeFile(t, filepath.Join(o.Root, "Library", "Managed Preferences", "com.anthropic.claudecode.plist"), []byte("<plist/>"), 0o644)
		s = stateOf(t, c, o, "claude-code")
		if s.Status != StatusShadowed || !strings.Contains(s.Detail, "managedSourcesBehavior") {
			t.Errorf("machine profile: %+v", s)
		}
		// The plan says so too.
		if p := only(t, mustPlan(t, c, o), "claude-code"); !strings.Contains(p.Note, "shadowed") {
			t.Errorf("plan note: %s", p.Note)
		}
	})
	t.Run("darwin per-user profile", func(t *testing.T) {
		o := opts(t, "darwin", event.ScopeManaged, "claude-code")
		mustApply(t, mustPlan(t, c, o))
		writeFile(t, filepath.Join(o.Root, "Library", "Managed Preferences", "dev", "com.anthropic.claudecode.plist"), []byte("<plist/>"), 0o644)
		if s := stateOf(t, c, o, "claude-code"); s.Status != StatusShadowed {
			t.Errorf("%+v", s)
		}
	})
	t.Run("windows registry not reachable", func(t *testing.T) {
		o := opts(t, "windows", event.ScopeManaged, "claude-code")
		mustApply(t, mustPlan(t, c, o))
		s := stateOf(t, c, o, "claude-code")
		if s.Status != StatusManaged || !strings.Contains(s.Detail, `HKLM\SOFTWARE\Policies\ClaudeCode`) || !strings.Contains(s.Detail, "not checked") {
			t.Errorf("%+v", s)
		}
	})
	t.Run("linux says what it could not see", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeManaged, "claude-code")
		mustApply(t, mustPlan(t, c, o))
		s := stateOf(t, c, o, "claude-code")
		if s.Status != StatusManaged || !strings.Contains(s.Detail, "not checked: server-managed settings") {
			t.Errorf("%+v", s)
		}
	})
	t.Run("user hooks under allowManagedHooksOnly", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "claude-code")
		mustApply(t, mustPlan(t, c, o))
		mo := o
		mo.Scope = event.ScopeManaged
		mpath := targetPath(t, c, mo, "claude-code")
		writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(mpath)), "managed-settings.json"), []byte(`{"allowManagedHooksOnly": true}`), 0o644)
		s := stateOf(t, c, o, "claude-code")
		if s.Status != StatusShadowed || !strings.Contains(s.Detail, "allowManagedHooksOnly") {
			t.Errorf("%+v", s)
		}
		if p := only(t, mustPlan(t, c, o), "claude-code"); !strings.Contains(p.Note, "allowManagedHooksOnly") {
			t.Errorf("plan note: %s", p.Note)
		}
	})
	t.Run("codex user hooks under allow_managed_hooks_only", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "codex")
		mustApply(t, mustPlan(t, c, o))
		writeFile(t, filepath.Join(o.Root, "etc", "codex", "requirements.toml"), []byte("allow_managed_hooks_only = true\n"), 0o644)
		s := stateOf(t, c, o, "codex")
		if s.Status != StatusShadowed || !strings.Contains(s.Detail, "allow_managed_hooks_only") || !strings.Contains(s.Detail, "trusted") {
			t.Errorf("%+v", s)
		}
	})
}

func TestStatusManagedSymlink(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "copilot-cli")
	path := targetPath(t, c, o, "copilot-cli")
	real := filepath.Join(o.Root, "tmp", "x.json")
	writeFile(t, real, []byte(`{"version": 1, "hooks": {}}`), 0o644)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if s := stateOf(t, c, o, "copilot-cli"); s.Status != StatusInsecure {
		t.Errorf("%+v", s)
	}
}

func TestStatusCodexBlockOutsideMarkers(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "codex")
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	path := plans[0].Path
	data := readBytes(t, path)
	// Someone strips the markers but keeps the tables.
	data = bytes.Replace(data, []byte(hooksBegin+"\n"), nil, 1)
	data = bytes.Replace(data, []byte(hooksEnd+"\n"), nil, 1)
	writeFile(t, path, data, 0o644)
	if s := stateOf(t, c, o, "codex"); s.Status != StatusModified || !strings.Contains(s.Detail, "outside") {
		t.Errorf("%+v", s)
	}
	if u := only(t, mustUnplan(t, c, o), "codex"); u.Action != ActionUnchanged || !strings.Contains(u.Note, "outside") {
		t.Errorf("uninstall: %s %s", u.Action, u.Note)
	}
	if p := only(t, mustPlan(t, c, o), "codex"); p.Action != ActionAppend || !strings.Contains(p.Note, "outside") {
		t.Errorf("install: %s %s", p.Action, p.Note)
	}
}

// TestStatusHookSwitches: a switch that turns every hook off makes an
// installed registration ineffective. Claude Code: "Only disableAllHooks
// set at the managed settings level can disable managed hooks", and the
// last managed file that sets it wins; at user level it turns off user
// hooks. Gemini CLI: hooksConfig.enabled=false, with system settings
// outranking the user's.
func TestStatusHookSwitches(t *testing.T) {
	c := testCatalog(t)
	type file struct{ rel, body string }
	cases := []struct {
		name, agent string
		scope       event.Scope
		files       []file
		self        string // merged into the target after install
		want        string
	}{
		{"claude managed off", "claude-code", event.ScopeManaged,
			[]file{{"etc/claude-code/managed-settings.json", `{"disableAllHooks": true}`}}, "", StatusShadowed},
		{"claude managed off then on in a later drop-in", "claude-code", event.ScopeManaged,
			[]file{{"etc/claude-code/managed-settings.json", `{"disableAllHooks": true}`}, {"etc/claude-code/managed-settings.d/90-on.json", `{"disableAllHooks": false}`}}, "", StatusManaged},
		{"claude managed quoted value is ignored", "claude-code", event.ScopeManaged,
			[]file{{"etc/claude-code/managed-settings.json", `{"disableAllHooks": "true"}`}}, "", StatusManaged},
		{"claude user off by managed", "claude-code", event.ScopeUser,
			[]file{{"etc/claude-code/managed-settings.d/10-x.json", `{"disableAllHooks": true}`}}, "", StatusShadowed},
		{"claude user off in own file", "claude-code", event.ScopeUser, nil, "disableAllHooks", StatusShadowed},
		{"claude user off overridden by managed", "claude-code", event.ScopeUser,
			[]file{{"etc/claude-code/managed-settings.json", `{"disableAllHooks": false}`}}, "disableAllHooks", StatusUser},
		{"gemini system off", "gemini-cli", event.ScopeManaged, nil, "hooksConfig", StatusShadowed},
		{"gemini user off by system", "gemini-cli", event.ScopeUser,
			[]file{{"etc/gemini-cli/settings.json", `{"hooksConfig": {"enabled": false}}`}}, "", StatusShadowed},
		{"gemini user off in own file", "gemini-cli", event.ScopeUser, nil, "hooksConfig", StatusShadowed},
		{"gemini user off but system on", "gemini-cli", event.ScopeUser,
			[]file{{"etc/gemini-cli/settings.json", `{"hooksConfig": {"enabled": true}}`}}, "hooksConfig", StatusUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := opts(t, "linux", tc.scope, tc.agent)
			for _, f := range tc.files {
				writeFile(t, filepath.Join(o.Root, filepath.FromSlash(f.rel)), []byte(f.body), 0o644)
			}
			plans := mustPlan(t, c, o)
			mustApply(t, plans)
			if tc.self != "" {
				path := only(t, plans, tc.agent).Path
				d := mustParse(t, readBytes(t, path))
				var v any = true
				if tc.self == "hooksConfig" {
					v = jobj{{"enabled", false}}
				}
				writeFile(t, path, d.addMember(d.root, tc.self, v), 0o644)
			}
			s := stateOf(t, c, o, tc.agent)
			if s.Status != tc.want {
				t.Errorf("Status %s, want %s (%s)", s.Status, tc.want, s.Detail)
			}
			if tc.want == StatusShadowed && !strings.Contains(s.Detail, "disableAllHooks") && !strings.Contains(s.Detail, "hooksConfig.enabled") {
				t.Errorf("Detail does not name the switch: %s", s.Detail)
			}
		})
	}
}

// TestStatusCodexMDM: Codex reads MDM requirements only on macOS, from the
// managed-preferences domain com.openai.codex, which is a file on disk.
// Detail must say what was looked at instead of calling MDM invisible.
func TestStatusCodexMDM(t *testing.T) {
	c := testCatalog(t)
	for _, goos := range []string{"linux", "windows", "darwin"} {
		o := opts(t, goos, event.ScopeManaged, "codex")
		mustApply(t, mustPlan(t, c, o))
		s := stateOf(t, c, o, "codex")
		if strings.Contains(s.Detail, "MDM requirements (not visible") || strings.Contains(s.Detail, "cloud and MDM") {
			t.Errorf("%s: %s", goos, s.Detail)
		}
		if !strings.Contains(s.Detail, "cloud requirements") {
			t.Errorf("%s: cloud requirements not mentioned: %s", goos, s.Detail)
		}
		if goos != "darwin" && !strings.Contains(s.Detail, "no MDM requirements source exists on this OS") {
			t.Errorf("%s: %s", goos, s.Detail)
		}
		if goos == "darwin" {
			if !strings.Contains(s.Detail, "/Library/Managed Preferences/com.openai.codex.plist") {
				t.Errorf("darwin: MDM location not checked: %s", s.Detail)
			}
			writeFile(t, filepath.Join(o.Root, "Library", "Managed Preferences", "com.openai.codex.plist"), []byte("bplist00"), 0o644)
			s = stateOf(t, c, o, "codex")
			if !strings.Contains(s.Detail, "com.openai.codex.plist (when its requirements define hooks") {
				t.Errorf("darwin: present profile not reported: %s", s.Detail)
			}
			p := only(t, mustPlan(t, c, o), "codex")
			if !strings.Contains(p.Note, "MDM profile for com.openai.codex is installed") {
				t.Errorf("darwin: plan note: %s", p.Note)
			}
			o.OTel = "http://127.0.0.1:4319"
			for _, p := range mustPlan(t, c, o) {
				if strings.HasSuffix(p.Path, "config.toml") && !strings.Contains(p.Note, "may set [otel]") {
					t.Errorf("darwin: otel plan note: %s", p.Note)
				}
			}
		}
	}
}
