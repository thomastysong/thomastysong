package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

var allAgents = []string{"claude-code", "codex", "copilot-cli", "gemini-cli", "cursor"}

func TestOptionsValidation(t *testing.T) {
	c := testCatalog(t)
	base := func() Options {
		return Options{Binary: unixBin, Scope: event.ScopeManaged, Root: t.TempDir(), GOOS: "linux"}
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"no binary", func(o *Options) { o.Binary = "" }},
		{"relative binary", func(o *Options) { o.Binary = "bin/spoor" }},
		{"windows-style binary on linux", func(o *Options) { o.Binary = winBin }},
		{"unix binary on windows", func(o *Options) { o.GOOS = "windows" }},
		{"newline in binary", func(o *Options) { o.Binary = "/usr/bin/spoor\nrm -rf /" }},
		{"dollar in binary", func(o *Options) { o.Binary = "/opt/$GEMINI_PROJECT_DIR/spoor" }},
		{"backtick in binary", func(o *Options) { o.Binary = "/opt/`id`/spoor" }},
		{"backslash in posix binary", func(o *Options) { o.Binary = `/opt/a\b/spoor` }},
		{"huge binary", func(o *Options) { o.Binary = "/" + strings.Repeat("a", 5000) }},
		{"no scope", func(o *Options) { o.Scope = "" }},
		{"project scope", func(o *Options) { o.Scope = event.ScopeProject }},
		{"negative timeout", func(o *Options) { o.Timeout = -1 }},
		{"huge timeout", func(o *Options) { o.Timeout = 100000 }},
		{"user scope without home", func(o *Options) { o.Scope = event.ScopeUser; o.Home = "" }},
		{"relative home", func(o *Options) { o.Scope = event.ScopeUser; o.Home = "home/dev" }},
		{"control char in agent", func(o *Options) { o.Agents = []string{"claude\x00code"} }},
		{"empty agent", func(o *Options) { o.Agents = []string{""} }},
		{"otel with credentials", func(o *Options) { o.OTel = "http://user:pw@127.0.0.1:4319" }},
		{"otel not http", func(o *Options) { o.OTel = "file:///etc/passwd" }},
		{"otel with query", func(o *Options) { o.OTel = "http://127.0.0.1:4319/?x=1" }},
		// JSON and TOML would carry U+FFFD instead: a file that does not
		// exist would be registered.
		{"binary not utf-8", func(o *Options) { o.Binary = "/opt/sp\xffor/spoor" }},
		{"otel not utf-8", func(o *Options) { o.OTel = "http://h\xff:4319" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			tc.mutate(&o)
			if _, err := PlanInstall(c, o); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	if _, err := PlanInstall(nil, base()); err == nil {
		t.Error("nil catalog accepted")
	}
	// Uninstall and Status do not need a binary.
	o := base()
	o.Binary = ""
	if _, err := PlanUninstall(c, o); err != nil {
		t.Errorf("uninstall without binary: %v", err)
	}
	o.Scope = ""
	if _, err := Status(c, o); err != nil {
		t.Errorf("status without scope: %v", err)
	}
}

func TestPlanCoversEveryHookAgent(t *testing.T) {
	c := testCatalog(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser} {
			plans := mustPlan(t, c, opts(t, goos, sc))
			got := map[string]bool{}
			for _, p := range plans {
				if p.Action != ActionCreate {
					t.Errorf("%s/%s/%s: action %s (%s)", goos, sc, p.AgentID, p.Action, p.Note)
				}
				got[p.AgentID] = true
			}
			for _, a := range allAgents {
				if !got[a] {
					t.Errorf("%s/%s: no plan for %s: %s", goos, sc, a, summarize(plans))
				}
			}
			// The Cursor IDE and CLI share one file: one registration.
			if got["cursor-agent"] {
				t.Errorf("%s/%s: cursor-agent planned separately", goos, sc)
			}
		}
	}
}

func TestUnknownAndDialectlessAgents(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "no-such-agent", "../../etc/passwd", "kiro-cli")
	plans := mustPlan(t, c, o)
	if len(plans) != 3 {
		t.Fatalf("plans: %s", summarize(plans))
	}
	for _, p := range plans {
		if p.Action != ActionUnsupported || p.Note == "" || p.After != nil {
			t.Errorf("%s: %s %q", p.AgentID, p.Action, p.Note)
		}
	}
	if err := Apply(plans); err != nil {
		t.Errorf("unsupported plans must be skipped: %v", err)
	}
	// Codex is the only agent with a system tier.
	o = opts(t, "linux", event.ScopeSystem, "claude-code", "codex")
	plans = mustPlan(t, c, o)
	if only(t, plans, "claude-code").Action != ActionUnsupported || only(t, plans, "codex").Action != ActionCreate {
		t.Errorf("system scope: %s", summarize(plans))
	}
	if !strings.HasSuffix(only(t, plans, "codex").Path, filepath.Join("etc", "codex", "hooks.json")) {
		t.Errorf("codex system path: %s", only(t, plans, "codex").Path)
	}
}

// TestRegistrationRules checks the rules every handler must follow: the
// session-start event is always registered, every handler carries an
// explicit timeout, and only notification-type events run in the
// background (a background hook dies with the session and loses the record).
func TestRegistrationRules(t *testing.T) {
	sessionStart := map[string]string{
		"claude": "SessionStart", "codex": "SessionStart", "copilot": "SessionStart",
		"gemini": "SessionStart", "cursor": "sessionStart",
	}
	for id, spec := range dialects {
		for _, guard := range []bool{false, true} {
			p := params{binary: unixBin, agentID: "x", goos: "linux", timeout: 10, guard: guard, failClosed: true}
			want, ok := spec.entries(p)
			if !ok {
				t.Fatalf("%s: no entries", id)
			}
			hd, _ := hookio.Get(id)
			if len(want) != len(hd.Events()) {
				t.Errorf("%s: %d entries for %d hookio events", id, len(want), len(hd.Events()))
			}
			seen := false
			for _, e := range want {
				if e.event == sessionStart[id] {
					seen = true
				}
				h := plain(e.handler).(map[string]any)
				hasTimeout := false
				for _, k := range []string{"timeout", "timeoutSec"} {
					if v, ok := h[k].(float64); ok && v > 0 {
						hasTimeout = true
					}
				}
				if !hasTimeout {
					t.Errorf("%s/%s: no explicit timeout", id, e.event)
				}
				if h["async"] == true && !notificationEvents[e.event] {
					t.Errorf("%s/%s: registered async", id, e.event)
				}
				if h["onFailure"] != nil && (!guard || id != "claude") {
					t.Errorf("%s/%s: onFailure without guard", id, e.event)
				}
				if h["failClosed"] != nil && (!guard || id != "cursor") {
					t.Errorf("%s/%s: failClosed without guard", id, e.event)
				}
			}
			if !seen {
				t.Errorf("%s: session start not registered", id)
			}
		}
	}
}

func TestTimeoutUnits(t *testing.T) {
	c := testCatalog(t)
	read := func(agent string, o Options) map[string]any {
		p := only(t, mustPlan(t, c, o), agent)
		var doc map[string]any
		if err := json.Unmarshal(p.After, &doc); err != nil {
			t.Fatalf("%s: %v", agent, err)
		}
		return doc
	}
	first := func(doc map[string]any, ev string, grouped bool) map[string]any {
		arr := doc["hooks"].(map[string]any)[ev].([]any)
		h := arr[0].(map[string]any)
		if grouped {
			h = h["hooks"].([]any)[0].(map[string]any)
		}
		return h
	}
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	o.Timeout = 7
	if v := first(read("gemini-cli", o), "BeforeTool", true)["timeout"]; v != float64(7000) {
		t.Errorf("gemini timeout %v, want 7000 ms", v)
	}
	o = opts(t, "linux", event.ScopeUser, "copilot-cli")
	o.Timeout = 7
	if v := first(read("copilot-cli", o), "PreToolUse", false)["timeoutSec"]; v != float64(7) {
		t.Errorf("copilot timeoutSec %v", v)
	}
	o = opts(t, "linux", event.ScopeUser, "codex")
	doc := read("codex", o)
	if v := first(doc, "SessionEnd", true)["timeout"]; v != float64(codexSessionEndMax) {
		t.Errorf("codex SessionEnd timeout %v, want the %ds cap", v, codexSessionEndMax)
	}
	if v := first(doc, "PreToolUse", true)["timeout"]; v != float64(10) {
		t.Errorf("codex default timeout %v", v)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	c := testCatalog(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser} {
			o := opts(t, goos, sc)
			o.OTel = "http://127.0.0.1:4319"
			mustApply(t, mustPlan(t, c, o))
			for _, p := range mustPlan(t, c, o) {
				if p.Action != ActionUnchanged {
					t.Errorf("%s/%s/%s second install: %s (%s)", goos, sc, p.AgentID, p.Action, p.Note)
				}
				if !bytes.Equal(p.Before, p.After) {
					t.Errorf("%s/%s/%s: unchanged plan with different bytes", goos, sc, p.AgentID)
				}
			}
			// A changed binary path is a merge in place, not a second entry.
			o.Binary = strings.Replace(o.Binary, "spoor", "spoor2", 1)
			plans := mustPlan(t, c, o)
			mustApply(t, plans)
			for _, s := range states(t, c, o) {
				if s.Status != StatusManaged && s.Status != StatusUser {
					t.Errorf("%s/%s/%s after binary change: %s (%s)", goos, sc, s.AgentID, s.Status, s.Detail)
				}
			}
		}
	}
}

const foreignClaude = `{
    "model": "opus",
    "permissions": {"allow": ["Bash(git status)"], "deny": []},
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {"type": "command", "command": "/opt/acme/check.sh", "timeout": 5}
                ]
            }
        ],
        "Notification": [
            {"hooks": [{"type": "command", "command": "notify-send hi"}]}
        ]
    },
    "zzz": 1.50e+2,
    "env": {"FOO": "bar"}
}
`

// TestForeignHooksPreserved installs into a settings file that already has
// other hooks and keys, checks that nothing of the owner's changed, and
// that uninstall gives back the original bytes exactly.
func TestForeignHooksPreserved(t *testing.T) {
	c := testCatalog(t)
	for _, style := range []struct{ name, data string }{
		{"pretty4", foreignClaude},
		{"crlf", strings.ReplaceAll(foreignClaude, "\n", "\r\n")},
		{"tabs", strings.ReplaceAll(foreignClaude, "    ", "\t")},
		{"minified", `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/acme/check.sh"}]}]},"zzz":1.50e+2}`},
		{"bom", "\ufeff" + foreignClaude},
		{"other hooks only elsewhere", `{"a": [1, 2], "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}}`},
	} {
		t.Run(style.name, func(t *testing.T) {
			o := opts(t, "linux", event.ScopeUser, "claude-code")
			path := targetPath(t, c, o, "claude-code")
			orig := []byte(style.data)
			writeFile(t, path, orig, 0o600)

			p := only(t, mustPlan(t, c, o), "claude-code")
			if p.Action != ActionMerge {
				t.Fatalf("action %s: %s", p.Action, p.Note)
			}
			mustApply(t, []Plan{p})
			got := readBytes(t, path)
			var before, after map[string]any
			_ = json.Unmarshal(bytes.TrimPrefix(orig, []byte("\ufeff")), &before)
			if err := json.Unmarshal(bytes.TrimPrefix(got, []byte("\ufeff")), &after); err != nil {
				t.Fatalf("result is not JSON: %v\n%s", err, got)
			}
			for k, v := range before {
				if k == "hooks" {
					continue
				}
				if !jsonEqual(v, after[k]) {
					t.Errorf("key %s changed", k)
				}
			}
			if strings.Contains(style.data, "check.sh") && !contains(got, `"/opt/acme/check.sh"`) {
				t.Error("foreign hook lost")
			}
			// Key order of the owner's keys is kept.
			if strings.Contains(style.data, `"model"`) && bytes.Index(got, []byte(`"model"`)) > bytes.Index(got, []byte(`"hooks"`)) {
				t.Error("key order changed")
			}
			if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
				t.Errorf("mode %v: an existing file keeps its mode", fi.Mode().Perm())
			}
			if s := stateOf(t, c, o, "claude-code"); s.Status != StatusUser {
				t.Errorf("status %s (%s)", s.Status, s.Detail)
			}

			u := only(t, mustUnplan(t, c, o), "claude-code")
			if u.Action != ActionMerge {
				t.Fatalf("uninstall action %s: %s", u.Action, u.Note)
			}
			mustApply(t, []Plan{u})
			if back := readBytes(t, path); !bytes.Equal(back, orig) {
				t.Errorf("uninstall did not restore the original bytes:\n%q\n%q", back, orig)
			}
		})
	}

	// Known limit: an empty "hooks" object the file had before cannot be
	// told apart from one spoor created, and goes with spoor's entries.
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	writeFile(t, path, []byte(`{"hooks": {}, "a": [1, 2]}`), 0o644)
	mustApply(t, mustPlan(t, c, o))
	mustApply(t, mustUnplan(t, c, o))
	if got := readBytes(t, path); string(got) != `{"a": [1, 2]}` {
		t.Errorf("empty hooks: %q", got)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// TestUninstallRemovesCreatedFiles: a file spoor created is gone after
// uninstall, in every format, and the backup keeps its bytes.
func TestUninstallRemovesCreatedFiles(t *testing.T) {
	c := testCatalog(t)
	for _, goos := range []string{"linux", "windows"} {
		for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser, event.ScopeSystem} {
			agents := allAgents
			if sc == event.ScopeSystem {
				agents = []string{"codex"}
			}
			o := opts(t, goos, sc, agents...)
			o.OTel = "http://127.0.0.1:4319"
			plans := mustPlan(t, c, o)
			mustApply(t, plans)
			un := mustUnplan(t, c, o)
			for _, p := range un {
				if p.Action != ActionRemove {
					t.Errorf("%s/%s/%s: uninstall action %s (%s)", goos, sc, p.AgentID, p.Action, p.Note)
				}
			}
			mustApply(t, un)
			for _, p := range plans {
				if exists(p.Path) {
					t.Errorf("%s/%s/%s: %s still exists", goos, sc, p.AgentID, p.Path)
				}
				if len(backups(t, filepath.Dir(p.Path))) == 0 {
					t.Errorf("%s/%s/%s: no backup kept", goos, sc, p.AgentID)
				}
			}
			for _, p := range mustUnplan(t, c, o) {
				if p.Action != ActionUnchanged {
					t.Errorf("%s/%s/%s: second uninstall %s", goos, sc, p.AgentID, p.Action)
				}
			}
		}
	}
}

func TestOwnedDropInWithOtherKeysIsKept(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "claude-code")
	mustApply(t, mustPlan(t, c, o))
	path := targetPath(t, c, o, "claude-code")
	data := readBytes(t, path)
	data = bytes.Replace(data, []byte("{\n"), []byte("{\n  \"model\": \"opus\",\n"), 1)
	writeFile(t, path, data, 0o644)
	u := only(t, mustUnplan(t, c, o), "claude-code")
	if u.Action != ActionMerge || !bytes.Equal(u.After, []byte("{\n  \"model\": \"opus\"\n}\n")) {
		t.Fatalf("got %s %q", u.Action, u.After)
	}
}

func TestJSONC(t *testing.T) {
	c := testCatalog(t)
	const jsonc = "{\n  // owner's comment\n  \"theme\": \"dark\", /* inline */\n  \"ui\": {\"a\": 1,}, // trailing\n}\n"
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	writeFile(t, path, []byte(jsonc), 0o644)
	p := only(t, mustPlan(t, c, o), "gemini-cli")
	if p.Action != ActionUnsupported || !strings.Contains(p.Note, "JSONC") {
		t.Fatalf("without force: %s %s", p.Action, p.Note)
	}
	o.Force = true
	p = only(t, mustPlan(t, c, o), "gemini-cli")
	if p.Action != ActionMerge {
		t.Fatalf("with force: %s %s", p.Action, p.Note)
	}
	if !contains(p.After, "// owner's comment") || !contains(p.After, "/* inline */") {
		t.Errorf("comments lost:\n%s", p.After)
	}
	mustApply(t, []Plan{p})
	if s := stateOf(t, c, o, "gemini-cli"); s.Status != StatusUser {
		t.Errorf("status %s %s", s.Status, s.Detail)
	}
	u := only(t, mustUnplan(t, c, o), "gemini-cli")
	mustApply(t, []Plan{u})
	if got := readBytes(t, path); string(got) != jsonc {
		t.Errorf("uninstall with force did not restore:\n%q", got)
	}
}

func TestUnreadableFilesAreNeverRewritten(t *testing.T) {
	c := testCatalog(t)
	cases := map[string]string{
		"invalid":           `{"hooks": {`,
		"array top level":   `[1, 2]`,
		"hooks is a string": `{"hooks": "none"}`,
		"event not array":   `{"hooks": {"BeforeTool": {"x": 1}}}`,
		"trailing garbage":  `{} {}`,
		"deep":              strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200),
		"bad number":        `{"x": 01}`,
		"control char":      "{\"x\": \"a\x01b\"}",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			o := opts(t, "linux", event.ScopeUser, "gemini-cli")
			path := targetPath(t, c, o, "gemini-cli")
			writeFile(t, path, []byte(data), 0o644)
			p := only(t, mustPlan(t, c, o), "gemini-cli")
			if p.Action != ActionUnsupported {
				t.Fatalf("action %s", p.Action)
			}
			if strings.Contains(p.Note, data) && len(data) > 3 {
				t.Errorf("note quotes file content: %s", p.Note)
			}
			u := only(t, mustUnplan(t, c, o), "gemini-cli")
			if u.Action != ActionUnsupported && u.Action != ActionUnchanged {
				t.Errorf("uninstall action %s", u.Action)
			}
		})
	}
	// Oversized file.
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	writeFile(t, path, append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), maxFileSize)...), 0o644)
	if p := only(t, mustPlan(t, c, o), "gemini-cli"); p.Action != ActionUnsupported {
		t.Errorf("oversized: %s", p.Action)
	}
	// Invalid UTF-8 inside a string survives byte for byte.
	o = opts(t, "linux", event.ScopeUser, "gemini-cli")
	path = targetPath(t, c, o, "gemini-cli")
	weird := []byte("{\"name\": \"\xff\xfe bytes\"}\n")
	writeFile(t, path, weird, 0o644)
	p := only(t, mustPlan(t, c, o), "gemini-cli")
	if p.Action != ActionMerge || !bytes.Contains(p.After, []byte("\xff\xfe bytes")) {
		t.Errorf("invalid UTF-8: %s", p.Action)
	}
	// An empty file is treated as an empty object.
	writeFile(t, path, []byte("  \n"), 0o644)
	if p := only(t, mustPlan(t, c, o), "gemini-cli"); p.Action != ActionMerge {
		t.Errorf("empty file: %s %s", p.Action, p.Note)
	}
}

func TestFlatVersion(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "cursor")
	path := targetPath(t, c, o, "cursor")
	writeFile(t, path, []byte(`{"hooks": {"stop": [{"command": "./audit.sh"}]}}`), 0o644)
	p := only(t, mustPlan(t, c, o), "cursor")
	var doc map[string]any
	if err := json.Unmarshal(p.After, &doc); err != nil || doc["version"] != float64(1) {
		t.Fatalf("version not added: %s", p.After)
	}
	writeFile(t, path, []byte(`{"version": 2, "hooks": {}}`), 0o644)
	p = only(t, mustPlan(t, c, o), "cursor")
	if !strings.Contains(p.Note, "version") {
		t.Errorf("no note about the version: %s", p.Note)
	}
}

func TestCoexist(t *testing.T) {
	c := testCatalog(t)
	numbat := `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/usr/local/bin/numbat hook pre-tool-use --agent claude"}]}]}}`
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	writeFile(t, path, []byte(numbat), 0o644)
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionUnsupported || !strings.Contains(p.Note, "numbat") {
		t.Fatalf("without coexist: %s %s", p.Action, p.Note)
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusForeignOnly || !strings.Contains(s.Detail, "numbat") {
		t.Errorf("status %s %s", s.Status, s.Detail)
	}
	o.Coexist = true
	p = only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionMerge || !strings.Contains(p.Note, "numbat") {
		t.Fatalf("with coexist: %s %s", p.Action, p.Note)
	}
	mustApply(t, []Plan{p})
	// Already installed: reported as it is even without Coexist.
	o.Coexist = false
	if p := only(t, mustPlan(t, c, o), "claude-code"); p.Action != ActionUnchanged {
		t.Errorf("reinstall: %s %s", p.Action, p.Note)
	}
	// Uninstall leaves numbat alone.
	mustApply(t, mustUnplan(t, c, o))
	if got := readBytes(t, path); string(got) != numbat {
		t.Errorf("numbat entry changed:\n%s", got)
	}

	// Another sensor in a different file of the same agent counts too:
	// a managed Snyk guard while installing user hooks.
	o = opts(t, "linux", event.ScopeUser, "claude-code")
	mo := o
	mo.Scope = event.ScopeManaged
	mpath := targetPath(t, c, mo, "claude-code")
	writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(mpath)), "managed-settings.json"),
		[]byte(`{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "snyk-agent-guard hook"}]}]}}`), 0o644)
	if p := only(t, mustPlan(t, c, o), "claude-code"); p.Action != ActionUnsupported || !strings.Contains(p.Note, "snyk-agent-guard") {
		t.Errorf("related sensor: %s %s", p.Action, p.Note)
	}
}

func TestOTel(t *testing.T) {
	c := testCatalog(t)
	t.Run("claude refused when managed pins an endpoint", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeManaged, "claude-code")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "claude-code")
		writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(path)), "managed-settings.json"),
			[]byte(`{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.corp:4318"}}`), 0o644)
		plans := mustPlan(t, c, o)
		if len(plans) != 2 {
			t.Fatalf("want a hook plan and a refused OTel plan: %s", summarize(plans))
		}
		if plans[0].Action != ActionCreate || contains(plans[0].After, "OTEL_") {
			t.Errorf("hook plan: %s %s", plans[0].Action, plans[0].After)
		}
		if plans[1].Action != ActionUnsupported || !strings.Contains(plans[1].Note, "OTEL_EXPORTER_OTLP_ENDPOINT") {
			t.Errorf("otel plan: %s %s", plans[1].Action, plans[1].Note)
		}
		mustApply(t, plans)
	})
	t.Run("gemini refused when the file has its own telemetry", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "gemini-cli")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "gemini-cli")
		writeFile(t, path, []byte(`{"telemetry": {"enabled": true, "otlpEndpoint": "http://10.0.0.1:4317"}}`), 0o644)
		plans := mustPlan(t, c, o)
		if len(plans) != 2 || plans[0].Action != ActionMerge || plans[1].Action != ActionUnsupported {
			t.Fatalf("%s", summarize(plans))
		}
		if !contains(plans[0].After, "10.0.0.1") || contains(plans[0].After, "127.0.0.1") {
			t.Errorf("existing telemetry touched:\n%s", plans[0].After)
		}
	})
	t.Run("gemini owner choice of logPrompts is kept", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "gemini-cli")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "gemini-cli")
		orig := []byte(`{"telemetry": {"logPrompts": true}}`)
		writeFile(t, path, orig, 0o644)
		plans := mustPlan(t, c, o)
		if len(plans) != 1 || plans[0].Action != ActionMerge {
			t.Fatalf("%s", summarize(plans))
		}
		mustApply(t, plans)
		mustApply(t, mustUnplan(t, c, o))
		if got := readBytes(t, path); !bytes.Equal(got, orig) {
			t.Errorf("uninstall left %s", got)
		}
	})
	t.Run("uninstall without the endpoint leaves merged telemetry and says so", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "claude-code")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "claude-code")
		writeFile(t, path, []byte(`{"model": "opus"}`), 0o644)
		mustApply(t, mustPlan(t, c, o))
		o.OTel = ""
		u := only(t, mustUnplan(t, c, o), "claude-code")
		if u.Action != ActionMerge || !contains(u.After, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") || !strings.Contains(u.Note, "telemetry") {
			t.Errorf("%s %s\n%s", u.Action, u.Note, u.After)
		}
	})
	t.Run("codex config.toml block", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "codex")
		o.OTel = "https://otel.example.com:4318/"
		dir := filepath.Dir(mustPlan(t, c, o)[0].Path)
		cfg := filepath.Join(dir, "config.toml")
		orig := []byte("model = \"gpt-5\"\n\n[projects.\"/src\"]\ntrust_level = \"trusted\"\n")
		writeFile(t, cfg, orig, 0o600)
		plans := mustPlan(t, c, o)
		if len(plans) != 2 || plans[0].Action != ActionCreate || plans[1].Path != cfg || plans[1].Action != ActionAppend {
			t.Fatalf("%s", summarize(plans))
		}
		if !contains(plans[1].After, `endpoint = "https://otel.example.com:4318/v1/logs"`) {
			t.Errorf("otel block:\n%s", plans[1].After)
		}
		mustApply(t, plans)
		for _, p := range mustPlan(t, c, o) {
			if p.Action != ActionUnchanged {
				t.Errorf("second install %s: %s", p.Path, p.Action)
			}
		}
		mustApply(t, mustUnplan(t, c, o))
		if got := readBytes(t, cfg); !bytes.Equal(got, orig) {
			t.Errorf("config.toml not restored:\n%s", got)
		}
	})
	t.Run("codex refused when config pins otel", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeManaged, "codex")
		o.OTel = "http://127.0.0.1:4319"
		dir := filepath.Dir(mustPlan(t, c, o)[0].Path)
		writeFile(t, filepath.Join(dir, "config.toml"), []byte("[otel]\nexporter = \"none\"\n"), 0o644)
		plans := mustPlan(t, c, o)
		if len(plans) != 2 || plans[0].Action != ActionCreate || plans[1].Action != ActionUnsupported {
			t.Fatalf("%s", summarize(plans))
		}
	})
	t.Run("uninstall keeps a switch the user's own export needs", func(t *testing.T) {
		// The user exports metrics with CLAUDE_CODE_ENABLE_TELEMETRY=1;
		// install adds the logs settings, uninstall must take only those.
		o := opts(t, "linux", event.ScopeUser, "claude-code")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "claude-code")
		orig := []byte(`{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "https://metrics.example.com/v1/metrics"
  }
}
`)
		writeFile(t, path, orig, 0o600)
		plans := mustPlan(t, c, o)
		if len(plans) != 1 || plans[0].Action != ActionMerge || !contains(plans[0].After, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") {
			t.Fatalf("%s", summarize(plans))
		}
		mustApply(t, plans)
		u := mustUnplan(t, c, o)
		if !strings.Contains(only(t, u, "claude-code").Note, "CLAUDE_CODE_ENABLE_TELEMETRY") {
			t.Errorf("uninstall note: %s", only(t, u, "claude-code").Note)
		}
		mustApply(t, u)
		if got := readBytes(t, path); !bytes.Equal(got, orig) {
			t.Errorf("install + uninstall did not restore the file:\n%s", got)
		}
	})
	t.Run("an env spoor created goes as a whole", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "claude-code")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "claude-code")
		orig := []byte("{\n  \"model\": \"opus\",\n  \"env\": {\n    \"FOO\": \"bar\"\n  }\n}\n")
		writeFile(t, path, orig, 0o644)
		mustApply(t, mustPlan(t, c, o))
		mustApply(t, mustUnplan(t, c, o))
		if got := readBytes(t, path); !bytes.Equal(got, orig) {
			t.Errorf("not restored:\n%s", got)
		}
	})
	for _, tc := range []struct{ name, env string }{
		// A logs destination the user already has: the default endpoint
		// of an otlp exporter, or a protocol choice.
		{"existing logs exporter", `{"OTEL_LOGS_EXPORTER": "otlp"}`},
		{"existing logs protocol", `{"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "grpc"}`},
		// Switching telemetry on would also start this dormant export.
		{"dormant metrics export", `{"OTEL_METRICS_EXPORTER": "otlp"}`},
		{"telemetry switched off", `{"CLAUDE_CODE_ENABLE_TELEMETRY": "0"}`},
	} {
		t.Run("claude refused: "+tc.name, func(t *testing.T) {
			o := opts(t, "linux", event.ScopeUser, "claude-code")
			o.OTel = "http://127.0.0.1:4319"
			path := targetPath(t, c, o, "claude-code")
			writeFile(t, path, []byte(`{"env": `+tc.env+`}`), 0o644)
			plans := mustPlan(t, c, o)
			if len(plans) != 2 || plans[1].Action != ActionUnsupported || contains(plans[0].After, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") {
				t.Fatalf("%s", summarize(plans))
			}
		})
	}
	t.Run("gemini refused when telemetry is already enabled", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "gemini-cli")
		o.OTel = "http://127.0.0.1:4319"
		path := targetPath(t, c, o, "gemini-cli")
		writeFile(t, path, []byte(`{"telemetry": {"enabled": true}}`), 0o644)
		plans := mustPlan(t, c, o)
		if len(plans) != 2 || plans[1].Action != ActionUnsupported || !strings.Contains(plans[1].Note, "telemetry.enabled") {
			t.Fatalf("%s", summarize(plans))
		}
	})
	t.Run("codex user refused when the system layer pins otel", func(t *testing.T) {
		// Addendum 2: refused when managed config already pins a telemetry
		// endpoint. A user-level [otel] would also override the system
		// config.toml's.
		for _, file := range []string{"requirements.toml", "config.toml"} {
			o := opts(t, "linux", event.ScopeUser, "codex")
			o.OTel = "http://127.0.0.1:4319"
			writeFile(t, filepath.Join(o.Root, "etc", "codex", file),
				[]byte("[otel]\nexporter = { otlp-http = { endpoint = \"https://siem.example.com/v1/logs\", protocol = \"json\" } }\n"), 0o644)
			n := 0
			for _, p := range mustPlan(t, c, o) {
				if strings.HasSuffix(p.Path, "config.toml") {
					n++
					if p.Action != ActionUnsupported || !strings.Contains(p.Note, file) {
						t.Errorf("%s pins [otel]: user-scope OTel plan %s for %s: %s", file, p.Action, p.Path, p.Note)
					}
				}
			}
			if n != 1 {
				t.Errorf("%s: %d OTel plans", file, n)
			}
		}
	})
	t.Run("codex user allowed next to spoor's own system block", func(t *testing.T) {
		m := opts(t, "linux", event.ScopeManaged, "codex")
		m.OTel = "http://127.0.0.1:4319"
		mustApply(t, mustPlan(t, c, m))
		o := opts(t, "linux", event.ScopeUser, "codex")
		o.Root, o.OTel = m.Root, m.OTel
		plans := mustPlan(t, c, o)
		if len(plans) != 2 || plans[1].Action != ActionCreate {
			t.Fatalf("%s", summarize(plans))
		}
	})
	t.Run("copilot has no native otel", func(t *testing.T) {
		o := opts(t, "linux", event.ScopeUser, "copilot-cli")
		o.OTel = "http://127.0.0.1:4319"
		p := only(t, mustPlan(t, c, o), "copilot-cli")
		if !strings.Contains(p.Note, "OpenTelemetry") {
			t.Errorf("note: %s", p.Note)
		}
	})
}

const requirementsTOML = `# Corporate Codex requirements
allowed_approval_policies = ["untrusted", "on-request"]

[mcp_servers.docs]
identity = { command = "docs-mcp" }

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/opt/corp/guard.sh"
`

func TestCodexRequirements(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "codex")
	path := targetPath(t, c, o, "codex")
	if filepath.Base(path) != "requirements.toml" {
		t.Fatalf("managed codex path %s", path)
	}
	writeFile(t, path, []byte(requirementsTOML), 0o644)
	p := only(t, mustPlan(t, c, o), "codex")
	if p.Action != ActionAppend || !bytes.HasPrefix(p.After, []byte(requirementsTOML)) {
		t.Fatalf("%s %s\n%s", p.Action, p.Note, p.After)
	}
	if contains(p.After, "managed_dir") {
		t.Error("managed_dir must never be written")
	}
	mustApply(t, []Plan{p})
	if p := only(t, mustPlan(t, c, o), "codex"); p.Action != ActionUnchanged {
		t.Errorf("second install: %s", p.Action)
	}
	if s := stateOf(t, c, o, "codex"); s.Status != StatusManaged || s.Hash == "" {
		t.Errorf("status %s %s", s.Status, s.Detail)
	}
	// A new binary replaces the block in place.
	o.Binary = "/opt/spoor/bin/spoor"
	p = only(t, mustPlan(t, c, o), "codex")
	if p.Action != ActionAppend || bytes.Count(p.After, []byte(hooksBegin)) != 1 || contains(p.After, unixBin) {
		t.Fatalf("replace: %s\n%s", p.Action, p.After)
	}
	mustApply(t, []Plan{p})
	mustApply(t, mustUnplan(t, c, o))
	if got := readBytes(t, path); string(got) != requirementsTOML {
		t.Errorf("uninstall did not restore:\n%s", got)
	}

	for name, data := range map[string]string{
		"invalid toml":     "hooks = [",
		"unbalanced":       hooksBegin + "\n",
		"repeated":         hooksBegin + "\n" + hooksEnd + "\n" + hooksBegin + "\n" + hooksEnd + "\n",
		"inline hooks":     "[hooks]\nPreToolUse = []\n",
		"key after block":  hooksBegin + "\n" + hooksEnd + "\nstray = 1\n",
		"inline hooks tbl": "hooks = { PreToolUse = [] }\n",
	} {
		t.Run(name, func(t *testing.T) {
			o := opts(t, "linux", event.ScopeManaged, "codex")
			path := targetPath(t, c, o, "codex")
			writeFile(t, path, []byte(data), 0o644)
			if p := only(t, mustPlan(t, c, o), "codex"); p.Action != ActionUnsupported {
				t.Errorf("%s: %s\n%s", name, p.Action, p.After)
			}
		})
	}
}

func TestCRLFRequirements(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "windows", event.ScopeManaged, "codex")
	path := targetPath(t, c, o, "codex")
	orig := []byte("allow_managed_hooks_only = true\r\n")
	writeFile(t, path, orig, 0o644)
	p := only(t, mustPlan(t, c, o), "codex")
	if p.Action != ActionAppend || bytes.Count(p.After, []byte("\n")) != bytes.Count(p.After, []byte("\r\n")) {
		t.Fatalf("line endings not kept: %q", p.After)
	}
	mustApply(t, []Plan{p})
	mustApply(t, mustUnplan(t, c, o))
	if got := readBytes(t, path); !bytes.Equal(got, orig) {
		t.Errorf("not restored: %q", got)
	}
}

func TestEnvRelocatesUserFilesOnly(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code", "codex")
	o.Env = map[string]string{"CLAUDE_CONFIG_DIR": "/srv/claude", "CODEX_HOME": "/srv/codex"}
	plans := mustPlan(t, c, o)
	if !strings.HasSuffix(only(t, plans, "claude-code").Path, "/srv/claude/settings.json") ||
		!strings.HasSuffix(only(t, plans, "codex").Path, "/srv/codex/hooks.json") {
		t.Errorf("%s", summarize(plans))
	}
	// Managed paths are fixed: an env value cannot move them.
	o = opts(t, "windows", event.ScopeManaged, "codex")
	o.Env = map[string]string{"ProgramData": `C:\Users\evil`}
	if p := only(t, mustPlan(t, c, o), "codex"); !strings.Contains(filepath.ToSlash(p.Path), "/C/ProgramData/OpenAI/Codex/") {
		t.Errorf("managed path moved: %s", p.Path)
	}
	// A relative or traversing relocation is unusable.
	o = opts(t, "linux", event.ScopeUser, "claude-code")
	o.Env = map[string]string{"CLAUDE_CONFIG_DIR": "../../etc"}
	if p := only(t, mustPlan(t, c, o), "claude-code"); p.Action != ActionUnsupported {
		t.Errorf("relative relocation: %s %s", p.Action, p.Path)
	}
}

func TestCursorAliasesShareOneRegistration(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "cursor-agent")
	p := only(t, mustPlan(t, c, o), "cursor-agent")
	if !contains(p.After, "--agent cursor\"") {
		t.Fatalf("command does not use the canonical id:\n%s", p.After)
	}
	mustApply(t, []Plan{p})
	o.Agents = nil
	for _, s := range states(t, c, o) {
		if s.AgentID == "cursor" && s.Status != StatusUser {
			t.Errorf("cursor status %s %s", s.Status, s.Detail)
		}
	}
}

func TestCrossOSPlanWithoutRoot(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("host is windows")
	}
	c := testCatalog(t)
	o := Options{Binary: winBin, Scope: event.ScopeManaged, GOOS: "windows", Agents: []string{"claude-code"}}
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionCreate || !strings.Contains(p.Note, "rendered for windows") {
		t.Fatalf("%s %s", p.Action, p.Note)
	}
	if err := Apply([]Plan{p}); err == nil {
		t.Error("a Windows path was applied on a unix host")
	}
}

// TestHostileTOMLIsBounded: the TOML decoder's cost grows with size times
// nesting, and ~/.codex/config.toml belongs to the user whose agent a root
// installer configures. A 24 KB file of nested inline tables made
// PlanInstall allocate 4 GiB (a 400 KB one got the process OOM-killed).
// Such files are now refused before they reach the decoder.
func TestHostileTOMLIsBounded(t *testing.T) {
	c := testCatalog(t)
	const n = 6000
	for name, cfg := range map[string][]byte{
		"nested inline tables": []byte("a = " + strings.Repeat("{b=", n) + "1" + strings.Repeat("}", n) + "\n"),
		"nested arrays":        []byte("a = " + strings.Repeat("[", n) + "1" + strings.Repeat("]", n) + "\n"),
		"dotted key":           []byte("a" + strings.Repeat(".b", n) + " = 1\n"),
		"oversized":            bytes.Repeat([]byte("k = { x = { y = 1 } }\n"), (maxTOMLSize/22)+1),
	} {
		for _, scope := range []event.Scope{event.ScopeUser, event.ScopeManaged} {
			o := opts(t, "linux", scope, "codex")
			path := targetPath(t, c, o, "codex")
			o.OTel = "http://127.0.0.1:4319"
			writeFile(t, filepath.Join(filepath.Dir(path), "config.toml"), cfg, 0o644)
			var plans []Plan
			alloc := allocDuring(func() { plans = mustPlan(t, c, o) })
			if alloc > 64<<20 {
				t.Errorf("%s (%s): a %d-byte config.toml made PlanInstall allocate %d MiB", name, scope, len(cfg), alloc>>20)
			}
			for _, p := range plans {
				if strings.HasSuffix(p.Path, "config.toml") && p.Action != ActionUnsupported {
					t.Errorf("%s (%s): %s %s", name, scope, p.Action, p.Note)
				}
			}
			alloc = allocDuring(func() { _ = states(t, c, o) })
			if alloc > 64<<20 {
				t.Errorf("%s (%s): Status allocated %d MiB", name, scope, alloc>>20)
			}
		}
	}
	// The managed tier's own file: refused as unreadable, never rewritten.
	o := opts(t, "linux", event.ScopeManaged, "codex")
	path := targetPath(t, c, o, "codex")
	writeFile(t, path, []byte("x = "+strings.Repeat("[", 40)+strings.Repeat("]", 40)+"\n"), 0o644)
	if p := only(t, mustPlan(t, c, o), "codex"); p.Action != ActionUnsupported || !strings.Contains(p.Note, "nested") {
		t.Errorf("requirements.toml: %s %s", p.Action, p.Note)
	}
}

// TestRelatedFilesStayInRoot: with Options.Root (a container or host
// root), the files read beside the target (managed settings, drop-in
// siblings, Codex requirements) are reached through the same confined walk
// as the target: a link below the root that leads out of it is not
// followed, so another tree's policy is never reported as this one's.
func TestRelatedFilesStayInRoot(t *testing.T) {
	c := testCatalog(t)
	outside := t.TempDir()
	numbat := `{"allowManagedHooksOnly": true, "env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://x"}, "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/usr/bin/numbat hook pre --agent claude"}]}]}}`
	writeFile(t, filepath.Join(outside, "managed-settings.json"), []byte(numbat), 0o644)
	writeFile(t, filepath.Join(outside, "managed-settings.d", "10-x.json"), []byte(numbat), 0o644)
	writeFile(t, filepath.Join(outside, "requirements.toml"), []byte("allow_managed_hooks_only = true\n[otel]\nexporter = \"none\"\n"), 0o644)
	cases := []struct {
		agent, link, target string
		scope               event.Scope
	}{
		{"claude-code", "etc/claude-code", outside, event.ScopeUser},
		{"claude-code", "etc/claude-code/managed-settings.d", filepath.Join(outside, "managed-settings.d"), event.ScopeUser},
		{"codex", "etc/codex", outside, event.ScopeUser},
	}
	for _, tc := range cases {
		o := opts(t, "linux", tc.scope, tc.agent)
		o.OTel = "http://127.0.0.1:4319"
		link := filepath.Join(o.Root, filepath.FromSlash(tc.link))
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		// An absolute link: inside the container it names the container's
		// own path, read from the host it is the host's.
		if err := os.Symlink(tc.target, link); err != nil {
			t.Fatal(err)
		}
		plans := mustPlan(t, c, o)
		for _, p := range plans {
			for _, leak := range []string{"numbat", "allowManagedHooksOnly", "allow_managed_hooks_only", outside} {
				if strings.Contains(p.Note, leak) {
					t.Errorf("%s via %s: a file outside Root was read through a link below it: %s %s", tc.agent, tc.link, p.Action, p.Note)
				}
			}
		}
		mustApply(t, plans)
		for _, s := range states(t, c, o) {
			if strings.Contains(s.Detail, outside) || s.Status == StatusShadowed {
				t.Errorf("%s via %s: Status read outside Root: %s %s", tc.agent, tc.link, s.Status, s.Detail)
			}
		}
	}
}
