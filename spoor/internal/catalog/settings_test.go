package catalog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func decodeJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSettingEval(t *testing.T) {
	doc := decodeJSON(t, `{
		"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(git *)", "Read"], "deny": []},
		"skipDangerousModePermissionPrompt": true,
		"disableAllHooks": false,
		"cleanupPeriodDays": 30,
		"ratio": 0.5,
		"sandbox": {"enabled": false},
		"env": {"ANTHROPIC_BASE_URL": "https://user:s3cr3t-token@proxy.example/v1", "X": null},
		"projects": {
			"/home/dev/a.b": {"trust_level": "trusted"},
			"/home/dev/c": {"trust_level": "untrusted"}
		},
		"chat.tools.global.autoApprove": true,
		"list": [{"name": "a"}, {"name": "b"}]
	}`)
	tests := []struct {
		desc       string
		key, op, v string
		hit        bool
		actual     string
	}{
		{"eq string", "permissions.defaultMode", "eq", "bypassPermissions", true, "bypassPermissions"},
		{"eq string miss", "permissions.defaultMode", "eq", "plan", false, "(other value)"},
		{"eq bool", "skipDangerousModePermissionPrompt", "eq", "true", true, "true"},
		{"eq bool false", "disableAllHooks", "eq", "true", false, "false"},
		{"eq number", "cleanupPeriodDays", "eq", "30", true, "30"},
		{"eq float", "ratio", "eq", "0.5", true, "0.5"},
		{"eq nested bool", "sandbox.enabled", "eq", "false", true, "false"},
		{"eq missing key", "sandbox.missing", "eq", "false", false, "absent"},
		{"eq through a scalar", "cleanupPeriodDays.x", "eq", "30", false, "absent"},
		{"ne equal", "disableAllHooks", "ne", "false", false, "false"},
		{"ne different", "disableAllHooks", "ne", "true", true, "false"},
		{"ne missing key is a hit", "allowManagedHooksOnly", "ne", "true", true, "absent"},
		{"ne different string does not echo it", "permissions.defaultMode", "ne", "plan", true, "(other value)"},
		{"in", "permissions.defaultMode", "in", "dontAsk, bypassPermissions ,auto", true, "bypassPermissions"},
		{"in miss", "permissions.defaultMode", "in", "dontAsk,auto", false, "(other value)"},
		{"exists", "env.ANTHROPIC_BASE_URL", "exists", "", true, "present"},
		{"exists null value", "env.X", "exists", "", true, "present"},
		{"exists missing", "env.NOPE", "exists", "", false, "absent"},
		{"exists any top-level key", "*", "exists", "", true, "present"},
		{"contains list element", "permissions.allow", "contains", "Read", true, "Read"},
		{"contains list miss", "permissions.allow", "contains", "Write", false, "(other value)"},
		{"contains empty list", "permissions.deny", "contains", "Read", false, "(other value)"},
		{"contains substring", "permissions.defaultMode", "contains", "bypass", true, "bypass"},
		{"contains map key", "sandbox", "contains", "enabled", true, "enabled"},
		{"wildcard over map", "projects.*.trust_level", "eq", "trusted", true, "trusted"},
		{"wildcard no hit", "projects.*.trust_level", "eq", "admin", false, "(other value)"},
		{"quoted segment with dots", `projects."/home/dev/a.b".trust_level`, "eq", "trusted", true, "trusted"},
		{"quoted whole key", `"chat.tools.global.autoApprove"`, "eq", "true", true, "true"},
		{"unquoted dotted key does not find a flat key", "chat.tools.global.autoApprove", "eq", "true", false, "absent"},
		{"wildcard over list", "list.*.name", "eq", "b", true, "b"},
		{"list index", "list.1.name", "eq", "b", true, "b"},
		{"list index out of range", "list.7.name", "exists", "", false, "absent"},
		{"negative list index", "list.-1.name", "exists", "", false, "absent"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			s := Setting{Key: tc.key, Op: tc.op, Value: tc.v}
			hit, actual := s.Eval(doc)
			if hit != tc.hit || actual != tc.actual {
				t.Errorf("Eval(%s %s %q) = %v, %q; want %v, %q", tc.key, tc.op, tc.v, hit, actual, tc.hit, tc.actual)
			}
			// Whatever the outcome, the credential in the document must
			// never come back through "actual".
			if strings.Contains(actual, "s3cr3t") {
				t.Errorf("actual leaks a config value: %q", actual)
			}
		})
	}
}

func TestSettingEvalNeverEchoesFreeText(t *testing.T) {
	doc := decodeJSON(t, `{"apiKeyHelper": "echo sk-ant-api03-CANARYCANARYCANARY", "n": {"k": "sk-ant-api03-CANARYCANARYCANARY"}, "l": ["sk-ant-api03-CANARYCANARYCANARY"]}`)
	for _, key := range []string{"apiKeyHelper", "n.k", "n.*", "l", "l.0", "*", "n"} {
		for _, op := range []string{"eq", "ne", "in", "exists", "contains"} {
			_, actual := Setting{Key: key, Op: op, Value: "x"}.Eval(doc)
			if strings.Contains(actual, "CANARY") {
				t.Errorf("Eval(%s %s) leaked the value: %q", key, op, actual)
			}
		}
	}
}

func TestSettingEvalEnvAndOtherDocShapes(t *testing.T) {
	env := map[string]string{"COPILOT_ALLOW_ALL": "1", "PATH": "/usr/bin"}
	if hit, actual := (Setting{Format: "env", Key: "COPILOT_ALLOW_ALL", Op: "exists"}).Eval(env); !hit || actual != "present" {
		t.Errorf("env exists: %v %q", hit, actual)
	}
	if hit, _ := (Setting{Format: "env", Key: "CLAUDE_CODE_SIMPLE", Op: "exists"}).Eval(env); hit {
		t.Error("env var that is not set reported present")
	}
	if hit, actual := (Setting{Format: "env", Key: "COPILOT_ALLOW_ALL", Op: "eq", Value: "1"}).Eval(env); !hit || actual != "1" {
		t.Errorf("env eq: %v %q", hit, actual)
	}

	// YAML documents decode to map[string]any with yaml.v3, TOML integers
	// arrive as int64.
	var y any
	if err := yaml.Unmarshal([]byte("a:\n  b: true\n  n: 7\n"), &y); err != nil {
		t.Fatal(err)
	}
	if hit, _ := (Setting{Key: "a.b", Op: "eq", Value: "true"}).Eval(y); !hit {
		t.Error("yaml bool")
	}
	if hit, _ := (Setting{Key: "a.n", Op: "eq", Value: "7"}).Eval(y); !hit {
		t.Error("yaml int")
	}
	toml := map[string]any{"approval_policy": "never", "n": int64(3), "u": uint64(4), "history": map[string]any{"persistence": "none"}}
	if hit, _ := (Setting{Key: "approval_policy", Op: "eq", Value: "never"}).Eval(toml); !hit {
		t.Error("toml string")
	}
	if hit, _ := (Setting{Key: "n", Op: "eq", Value: "3"}).Eval(toml); !hit {
		t.Error("toml int64")
	}
	if hit, _ := (Setting{Key: "u", Op: "in", Value: "1,4"}).Eval(toml); !hit {
		t.Error("uint64")
	}
	legacy := map[any]any{"a": map[any]any{"b": "x"}}
	if hit, _ := (Setting{Key: "a.b", Op: "eq", Value: "x"}).Eval(legacy); !hit {
		t.Error("map[any]any documents must be walkable")
	}

	// Nil, scalars and wrong shapes are "absent", never a panic.
	for _, doc := range []any{nil, "string", 42, []any{}, map[string]any{}, map[string]string{}, struct{}{}} {
		if hit, actual := (Setting{Key: "a.b", Op: "eq", Value: "x"}).Eval(doc); hit || actual != "absent" {
			t.Errorf("Eval(%T) = %v %q", doc, hit, actual)
		}
		if hit, _ := (Setting{Key: "a.b", Op: "ne", Value: "x"}).Eval(doc); !hit {
			t.Errorf("ne on %T must hit", doc)
		}
	}
	// Unknown op and malformed key never hit.
	if hit, _ := (Setting{Key: "a", Op: "regex", Value: "x"}).Eval(map[string]any{"a": "x"}); hit {
		t.Error("unknown op hit")
	}
	if hit, _ := (Setting{Key: "a..b", Op: "exists"}).Eval(map[string]any{"a": map[string]any{"": map[string]any{"b": 1}}}); hit {
		t.Error("malformed key hit")
	}
}

func TestSettingEvalBounded(t *testing.T) {
	// A wildcard over a huge, deeply nested document must stay bounded.
	wide := map[string]any{}
	for i := 0; i < 5000; i++ {
		inner := map[string]any{}
		for j := 0; j < 50; j++ {
			inner[itoa(j)] = map[string]any{"v": "x"}
		}
		wide[itoa(i)] = inner
	}
	s := Setting{Key: "*.*.v", Op: "eq", Value: "nope"}
	if hit, _ := s.Eval(wide); hit {
		t.Error("unexpected hit")
	}
	// Self-referential documents cannot be built from decoded files, but a
	// deep one can: the key length bounds the walk.
	deep := any("leaf")
	for i := 0; i < 100000; i++ {
		deep = map[string]any{"a": deep}
	}
	if hit, actual := (Setting{Key: strings.TrimSuffix(strings.Repeat("a.", maxKeySegments), "."), Op: "exists"}).Eval(deep); !hit || actual != "present" {
		t.Errorf("deep doc: %v %q", hit, actual)
	}
	if _, err := splitKey(strings.TrimSuffix(strings.Repeat("a.", maxKeySegments+1), ".")); err == nil {
		t.Error("a key with too many segments must be rejected")
	}
}

func TestSplitKey(t *testing.T) {
	good := map[string][]string{
		"a":                         {"a"},
		"a.b.c":                     {"a", "b", "c"},
		`projects."/x/a.b".trust`:   {"projects", "/x/a.b", "trust"},
		`"chat.tools.autoApprove"`:  {"chat.tools.autoApprove"},
		`a."b.c"`:                   {"a", "b.c"},
		"*":                         {"*"},
		"projects.*.trust_level":    {"projects", "*", "trust_level"},
		`"".a`:                      {"", "a"},
		"permissions.defaultMode":   {"permissions", "defaultMode"},
		"hooksConfig.enabled":       {"hooksConfig", "enabled"},
		"security.disableYoloMode":  {"security", "disableYoloMode"},
		"env.ANTHROPIC_BASE_URL":    {"env", "ANTHROPIC_BASE_URL"},
		`a."b"."c"`:                 {"a", "b", "c"},
		"list.0.name":               {"list", "0", "name"},
		"key with spaces.and-dash":  {"key with spaces", "and-dash"},
		`"only quoted"`:             {"only quoted"},
		"a.b.c.d.e.f.g.h.i.j.k.l.m": strings.Split("a.b.c.d.e.f.g.h.i.j.k.l.m", "."),
	}
	for in, want := range good {
		got, err := splitKey(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("splitKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "a.", ".a", "a..b", `a."b`, `"a"b`, `a."b"c`, `"a".`} {
		if got, err := splitKey(in); err == nil {
			t.Errorf("splitKey(%q) = %q, want an error", in, got)
		}
	}
}

// Every setting probe in the shipped data must have a parsable key and a
// file list on at least one OS (or be an env probe).
func TestShippedSettingsAreEvaluable(t *testing.T) {
	c := mustLoad(t)
	n := 0
	for _, p := range c.Products() {
		for _, s := range p.Settings {
			n++
			if _, err := splitKey(s.Key); err != nil {
				t.Errorf("%s: setting key %q: %v", p.ID, s.Key, err)
			}
			if s.Format != "env" && s.File.IsZero() {
				t.Errorf("%s: setting %s has no file", p.ID, s.Key)
			}
			if s.Severity == "" {
				t.Errorf("%s: setting %s has no severity", p.ID, s.Key)
			}
			// Must be safe on an empty document.
			s.Eval(map[string]any{})
			s.Eval(map[string]string{})
		}
	}
	if n < 40 {
		t.Errorf("only %d setting probes shipped", n)
	}

	// End to end on realistic files.
	cc, _ := c.Get("claude-code")
	risky := decodeJSON(t, `{"permissions":{"defaultMode":"bypassPermissions"},"skipDangerousModePermissionPrompt":true,"disableAllHooks":true,"sandbox":{"enabled":false},"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:3456"}}`)
	safe := decodeJSON(t, `{"permissions":{"defaultMode":"default"},"sandbox":{"enabled":true}}`)
	var riskyFlags, safeFlags []string
	for _, s := range cc.Settings {
		if s.Format != "json" || !strings.Contains(strings.Join(s.File.Linux, " "), "/.claude/settings.json") {
			continue
		}
		if hit, _ := s.Eval(risky); hit {
			riskyFlags = append(riskyFlags, s.Flag)
		}
		if hit, _ := s.Eval(safe); hit {
			safeFlags = append(safeFlags, s.Flag)
		}
	}
	wantEq(t, "risky claude settings", riskyFlags, []string{"bypass_permissions_default", "bypass_warning_accepted", "hooks_disabled", "sandbox_disabled", "api_base_url_override"})
	if len(safeFlags) != 0 {
		t.Errorf("safe claude settings raised %v", safeFlags)
	}

	cx, _ := c.Get("codex")
	codexDoc := map[string]any{
		"approval_policy": "never", "sandbox_mode": "danger-full-access",
		"projects": map[string]any{"/home/dev/app": map[string]any{"trust_level": "trusted"}},
		"history":  map[string]any{"persistence": "none"},
	}
	var got []string
	for _, s := range cx.Settings {
		if s.Format == "toml" && strings.Contains(strings.Join(s.File.Linux, " "), "config.toml") {
			if hit, _ := s.Eval(codexDoc); hit {
				got = append(got, s.Flag)
			}
		}
	}
	wantEq(t, "risky codex settings", got, []string{"approvals_disabled", "sandbox_disabled", "project_trusted", "prompt_history_disabled"})

	// "Lock not set" probes hit on an empty managed file.
	for _, s := range cc.Settings {
		if s.Flag == "managed_hooks_not_exclusive" || s.Flag == "bypass_mode_not_locked" {
			if hit, actual := s.Eval(map[string]any{}); !hit || actual != "absent" {
				t.Errorf("%s on an empty policy: %v %q", s.Flag, hit, actual)
			}
		}
	}
	locked := decodeJSON(t, `{"allowManagedHooksOnly":true,"permissions":{"disableBypassPermissionsMode":"disable"}}`)
	for _, s := range cc.Settings {
		if s.Flag == "managed_hooks_not_exclusive" || s.Flag == "bypass_mode_not_locked" {
			if hit, _ := s.Eval(locked); hit {
				t.Errorf("%s hit on a locked policy", s.Flag)
			}
		}
	}

	vs, _ := c.Get("vscode")
	vsDoc := decodeJSON(t, `{"chat.tools.global.autoApprove": true, "editor.fontSize": 12}`)
	found := false
	for _, s := range vs.Settings {
		if hit, _ := s.Eval(vsDoc); hit && s.Flag == "auto_approve_all_tools" {
			found = true
		}
	}
	if !found {
		t.Error("VS Code global auto-approve was not detected")
	}
}

func TestRiskyArgs(t *testing.T) {
	c := mustLoad(t)
	tests := []struct {
		id   string
		args []string
		want []string
	}{
		{"claude-code", []string{"claude", "--dangerously-skip-permissions"}, []string{"--dangerously-skip-permissions"}},
		{"claude-code", []string{"claude", "-p", "hi", "--permission-mode", "bypassPermissions"}, []string{"--permission-mode bypassPermissions"}},
		{"claude-code", []string{"claude", "--permission-mode=bypassPermissions"}, []string{"--permission-mode bypassPermissions"}},
		{"claude-code", []string{"claude", "--permission-mode", "plan"}, nil},
		{"claude-code", []string{"claude", "--permission-mode"}, nil},
		{"claude-code", []string{"claude", "--bare", "--no-session-persistence", "--dangerously-skip-permissions"}, []string{"--dangerously-skip-permissions", "--bare", "--no-session-persistence"}},
		{"claude-code", []string{"claude", "--", "--dangerously-skip-permissions"}, nil},
		{"claude-code", []string{"claude", "-p", "please explain --dangerously-skip-permissions-like flags"}, nil},
		{"claude-code", []string{"claude", "--dangerously-skip-permissionsX"}, nil},
		{"claude-code", []string{"claude", "--bare=false"}, nil},
		{"claude-code", []string{"claude", "--bare=true"}, []string{"--bare"}},
		{"claude-code", nil, nil},
		{"claude-code", []string{}, nil},
		{"codex", []string{"codex", "exec", "--yolo", "fix it"}, []string{"--yolo"}},
		{"codex", []string{"codex", "--sandbox", "danger-full-access", "--ask-for-approval", "never"}, []string{"--sandbox danger-full-access", "--ask-for-approval never"}},
		{"codex", []string{"codex", "--sandbox=danger-full-access"}, []string{"--sandbox danger-full-access"}},
		{"codex", []string{"codex", "--sandbox", "workspace-write"}, nil},
		{"codex", []string{"codex", "--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-hook-trust"}, []string{"--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-hook-trust"}},
		{"copilot-cli", []string{"copilot", "--allow-all-tools", "--autopilot"}, []string{"--allow-all-tools", "--autopilot"}},
		{"gemini-cli", []string{"gemini", "--approval-mode=yolo"}, []string{"--approval-mode yolo"}},
		{"gemini-cli", []string{"gemini", "--approval-mode", "default"}, nil},
		{"gemini-cli", []string{"gemini", "--yolo"}, []string{"--yolo"}},
		{"aider", []string{"aider", "--yes-always"}, []string{"--yes-always"}},
		{"ollama", []string{"ollama", "serve", "--yolo"}, nil}, // no risky flags declared
	}
	for _, tc := range tests {
		p, ok := c.Get(tc.id)
		if !ok {
			t.Fatalf("no product %s", tc.id)
		}
		if got := p.RiskyArgs(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s RiskyArgs(%q) = %q, want %q", tc.id, tc.args, got, tc.want)
		}
	}
	// A secret passed next to a risky flag is never echoed: results are
	// catalog strings only.
	p, _ := c.Get("claude-code")
	got := p.RiskyArgs([]string{"claude", "--dangerously-skip-permissions=sk-ant-api03-CANARY", "--settings", `{"apiKey":"sk-ant-api03-CANARY"}`})
	if strings.Contains(strings.Join(got, " "), "CANARY") {
		t.Errorf("RiskyArgs echoed an argument value: %q", got)
	}
	// Bounded on a hostile command line.
	huge := make([]string, 1<<20)
	for i := range huge {
		huge[i] = "--x"
	}
	huge[len(huge)-1] = "--dangerously-skip-permissions"
	if got := p.RiskyArgs(huge); got != nil {
		t.Errorf("a flag beyond the scan limit was reported: %q", got)
	}
}
