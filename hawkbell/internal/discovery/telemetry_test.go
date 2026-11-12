package discovery

import (
	"context"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func claudeAsset(t *testing.T, f *fx, o Options) *event.Asset {
	t.Helper()
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureIndex{events: res.Events}.one(t, event.AssetAgent, "claude-code")
}

func TestManagedHookStates(t *testing.T) {
	hawkbell := func(agent string) string {
		return `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/bin/hawkbell","args":["hook","--agent","` + agent + `"]}]}]}}`
	}
	cases := []struct {
		name      string
		plant     func(f *fx)
		hooks     string
		flag      string
		wantFlags bool
	}{
		{"missing", func(f *fx) {}, hooksMissing, flagManagedMissing, true},
		{"managed", func(f *fx) {
			f.file("/etc/claude-code/managed-settings.d/50-hawkbell.json", hawkbell("claude-code"), 0o644)
		}, hooksManaged, flagManagedMissing, false},
		{"wrong agent", func(f *fx) {
			f.file("/etc/claude-code/managed-settings.d/50-hawkbell.json", hawkbell("codex"), 0o644)
		}, hooksModified, "", false},
		{"world writable", func(f *fx) {
			f.file("/etc/claude-code/managed-settings.d/50-hawkbell.json", hawkbell("claude-code"), 0o666)
		}, hooksModified, flagManagedWorldWritable, true},
		{"user only", func(f *fx) {
			f.file("/home/alice/.claude/settings.json", hawkbell("claude-code"), 0o644)
		}, hooksUser, "", false},
		{"disabled", func(f *fx) {
			f.file("/home/alice/.claude/settings.json", `{"disableAllHooks": true}`, 0o644)
		}, hooksDisabled, "hooks_disabled", true},
		{"managed survives disableAllHooks", func(f *fx) {
			f.file("/etc/claude-code/managed-settings.d/50-hawkbell.json", hawkbell("claude-code"), 0o644)
			f.file("/home/alice/.claude/settings.json", `{"disableAllHooks": true}`, 0o644)
		}, hooksManaged, "hooks_disabled", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.dir("/home/alice/.claude")
			f.file("/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json", `{"name":"@anthropic-ai/claude-code","version":"2.0.0"}`, 0o644)
			c.plant(f)
			a := claudeAsset(t, f, f.opts(f.user("alice")))
			if a.Telemetry == nil || a.Telemetry.Hooks != c.hooks {
				t.Errorf("hooks = %+v, want %s", a.Telemetry, c.hooks)
			}
			if c.flag != "" && has(a.RiskFlags, c.flag) != c.wantFlags {
				t.Errorf("flag %s present=%v in %v", c.flag, !c.wantFlags, a.RiskFlags)
			}
		})
	}
}

func TestRelocatedStateDir(t *testing.T) {
	f := newFixture(t)
	f.dir("/home/alice")
	f.file("/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json", `{"name":"@anthropic-ai/claude-code","version":"2.0.0"}`, 0o644)
	f.file("/opt/cc-alice/settings.json", `{"permissions":{"defaultMode":"bypassPermissions"}}`, 0o644)
	f.file("/opt/cc-alice/projects/p/1.jsonl", "{}\n", 0o644)
	f.dir("/home/alice/.claude")
	o := f.opts(f.user("alice"))
	o.Env = func(u platform.UserHome) map[string]string {
		return map[string]string{"CLAUDE_CONFIG_DIR": "/opt/cc-alice"}
	}
	a := claudeAsset(t, f, o)
	if a.Telemetry == nil || a.Telemetry.Transcript != transcriptRelocated {
		t.Errorf("transcript = %+v", a.Telemetry)
	}
	if !has(a.RiskFlags, "bypass_permissions_default") {
		t.Errorf("relocated settings not read: %v", a.RiskFlags)
	}
}

// TestManagedHooksShadowedByMDM: with the default managedSourcesBehavior
// "first-wins", Claude Code ignores the managed-settings.d drop-in when an
// MDM policy (macOS managed preferences, Windows policy key) exists, so
// hawkbell's entry there does not run: the hooks are not "managed".
func TestManagedHooksShadowedByMDM(t *testing.T) {
	f := newFixture(t)
	f.dir("/home/alice/.claude")
	f.file("/etc/claude-code/managed-settings.d/50-hawkbell.json",
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/bin/hawkbell","args":["hook","--agent","claude-code"]}]}]}}`, 0o644)
	for _, mdm := range []bool{false, true} {
		s, cancel, err := newScanner(context.Background(), f.opts(f.user("alice")))
		if err != nil {
			t.Fatal(err)
		}
		s.scanManagedFacts()
		i := s.byID["claude-code"]
		if mdm {
			// What the catalog's MDM probes record on macOS and Windows.
			mf := s.managed["claude-code"]
			if mf == nil {
				mf = &managedFacts{insecure: map[string]bool{}}
				s.managed["claude-code"] = mf
			}
			mf.flags = append(mf.flags, flagManagedPolicyPresent)
		}
		got := s.hookStatus(&s.products[i], s.userCtx(f.user("alice")), false)
		want := hooksManaged
		if mdm {
			want = hooksModified
		}
		if got != want {
			t.Errorf("mdm=%v: hooks = %s, want %s", mdm, got, want)
		}
		// Codex has no such precedence rule.
		if ci, ok := s.byID["codex"]; ok && mdm {
			s.managed["codex"] = &managedFacts{flags: []string{flagManagedPolicyPresent}}
			if s.managedHooksShadowed(&s.products[ci]) {
				t.Error("codex managed hooks reported shadowed")
			}
		}
		s.g.close()
		cancel()
	}
}
