package catalog

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	tests := []struct {
		desc string
		p    string
		home string
		env  map[string]string
		goos string
		want string
	}{
		// --- POSIX --------------------------------------------------------
		{"tilde", "~/.claude/settings.json", "/home/dev", nil, "linux", "/home/dev/.claude/settings.json"},
		{"bare tilde", "~", "/home/dev", nil, "linux", "/home/dev"},
		{"tilde on darwin", "~/Library/Application Support/Claude", "/Users/dev", nil, "darwin", "/Users/dev/Library/Application Support/Claude"},
		{"tilde is only the first element", "/tmp/~/x~", "/home/dev", nil, "linux", "/tmp/~/x~"},
		{"~user is not ours to resolve", "~root/.claude", "/home/dev", nil, "linux", "~root/.claude"},
		{"absolute path untouched", "/etc/claude-code/managed-settings.json", "/home/dev", nil, "linux", "/etc/claude-code/managed-settings.json"},
		{"$VAR", "$CODEX_HOME/sessions", "/home/dev", map[string]string{"CODEX_HOME": "/data/codex"}, "linux", "/data/codex/sessions"},
		{"${VAR}", "${CODEX_HOME}/sessions", "/home/dev", map[string]string{"CODEX_HOME": "/data/codex"}, "linux", "/data/codex/sessions"},
		{"unset variable stays, never becomes /sessions", "$CODEX_HOME/sessions", "/home/dev", nil, "linux", "$CODEX_HOME/sessions"},
		{"unset braced variable stays", "${CODEX_HOME}/sessions", "/home/dev", map[string]string{}, "linux", "${CODEX_HOME}/sessions"},
		{"empty value counts as unset", "$CODEX_HOME/sessions", "/home/dev", map[string]string{"CODEX_HOME": ""}, "linux", "$CODEX_HOME/sessions"},
		{"default used when unset", "${CODEX_HOME:-~/.codex}/sessions/*/*/*/rollout-*.jsonl", "/home/dev", nil, "linux", "/home/dev/.codex/sessions/*/*/*/rollout-*.jsonl"},
		{"default ignored when set", "${CODEX_HOME:-~/.codex}/config.toml", "/home/dev", map[string]string{"CODEX_HOME": "/srv/codex"}, "linux", "/srv/codex/config.toml"},
		{"default that is the home itself", "${GEMINI_CLI_HOME:-~}/.gemini/settings.json", "/home/dev", nil, "linux", "/home/dev/.gemini/settings.json"},
		{"relocated gemini home", "${GEMINI_CLI_HOME:-~}/.gemini/settings.json", "/home/dev", map[string]string{"GEMINI_CLI_HOME": "/mnt/g"}, "linux", "/mnt/g/.gemini/settings.json"},
		{"default naming another variable", "${CRUSH_GLOBAL_CONFIG:-$XDG_CONFIG_HOME/crush}/crush.json", "/home/dev", nil, "linux", "/home/dev/.config/crush/crush.json"},
		{"$HOME is the given home, not the daemon's", "$HOME/.codex", "/home/dev", map[string]string{"HOME": "/root"}, "linux", "/home/dev/.codex"},
		{"$HOME from env when no home is given", "$HOME/.codex", "", map[string]string{"HOME": "/root"}, "linux", "/root/.codex"},
		{"XDG default", "${XDG_CONFIG_HOME}/kilo/plugin", "/home/dev", nil, "linux", "/home/dev/.config/kilo/plugin"},
		{"XDG from env", "$XDG_CONFIG_HOME/kilo", "/home/dev", map[string]string{"XDG_CONFIG_HOME": "/cfg"}, "linux", "/cfg/kilo"},
		{"XDG data default", "$XDG_DATA_HOME/opencode/opencode.db", "/home/dev", nil, "linux", "/home/dev/.local/share/opencode/opencode.db"},
		{"XDG state and cache", "$XDG_STATE_HOME:$XDG_CACHE_HOME", "/h", nil, "linux", "/h/.local/state:/h/.cache"},
		{"percent is literal on POSIX", "%APPDATA%/x", "/home/dev", map[string]string{"APPDATA": "nope"}, "linux", "%APPDATA%/x"},
		{"backslash is literal on POSIX", `~/a\b`, "/home/dev", nil, "linux", `/home/dev/a\b`},
		{"lone dollar", "/tmp/a$", "/home/dev", nil, "linux", "/tmp/a$"},
		{"dollar digit is not a variable", "/tmp/$1", "/home/dev", nil, "linux", "/tmp/$1"},
		{"unterminated brace", "${CODEX_HOME/x", "/home/dev", map[string]string{"CODEX_HOME": "/c"}, "linux", "${CODEX_HOME/x"},
		{"no home: tilde stays", "~/.claude", "", nil, "linux", "~/.claude"},
		{"values are not re-expanded", "$A/x", "/home/dev", map[string]string{"A": "$B", "B": "/etc"}, "linux", "$B/x"},
		{"glob characters pass through", "~/.claude/projects/*/*.jsonl", "/home/dev", nil, "linux", "/home/dev/.claude/projects/*/*.jsonl"},
		{"empty", "", "/home/dev", nil, "linux", ""},

		// --- Windows ------------------------------------------------------
		{"windows tilde and slashes", "~/.claude/settings.json", `C:\Users\dev`, nil, "windows", `C:\Users\dev\.claude\settings.json`},
		{"windows %APPDATA% default", `%APPDATA%\Claude\claude_desktop_config.json`, `C:\Users\dev`, nil, "windows", `C:\Users\dev\AppData\Roaming\Claude\claude_desktop_config.json`},
		{"windows %LOCALAPPDATA% default", `%LOCALAPPDATA%\Programs\Goose`, `C:\Users\dev`, nil, "windows", `C:\Users\dev\AppData\Local\Programs\Goose`},
		{"windows %APPDATA% from env", `%APPDATA%\amp\settings.json`, `C:\Users\dev`, map[string]string{"APPDATA": `D:\Roam`}, "windows", `D:\Roam\amp\settings.json`},
		{"windows names are case-insensitive", `%AppData%\Zed`, `C:\Users\dev`, map[string]string{"APPDATA": `D:\Roam`}, "windows", `D:\Roam\Zed`},
		{"windows env keys in any case", `%APPDATA%\Zed`, `C:\Users\dev`, map[string]string{"AppData": `D:\Roam`}, "windows", `D:\Roam\Zed`},
		{"windows %USERPROFILE% is the given home", `%USERPROFILE%\.codex`, `C:\Users\dev`, map[string]string{"USERPROFILE": `C:\Windows\system32\config\systemprofile`}, "windows", `C:\Users\dev\.codex`},
		{"windows %ProgramData%", `%ProgramData%\OpenAI\Codex\requirements.toml`, `C:\Users\dev`, nil, "windows", `C:\ProgramData\OpenAI\Codex\requirements.toml`},
		{"windows %ProgramData% relocated", `%ProgramData%\OpenAI\Codex`, `C:\Users\dev`, map[string]string{"ProgramData": `E:\PD`}, "windows", `E:\PD\OpenAI\Codex`},
		{"windows %ProgramFiles%", `%ProgramFiles%\GitHubCopilot\managed-settings.json`, "", nil, "windows", `C:\Program Files\GitHubCopilot\managed-settings.json`},
		{"windows %ProgramFiles(x86)%", `%ProgramFiles(x86)%\X`, "", nil, "windows", `C:\Program Files (x86)\X`},
		{"windows literal drive path", `C:\Program Files\ClaudeCode\managed-settings.json`, `C:\Users\dev`, nil, "windows", `C:\Program Files\ClaudeCode\managed-settings.json`},
		{"windows unset variable stays", `%NOPE%\x`, `C:\Users\dev`, nil, "windows", `%NOPE%\x`},
		{"windows stray percent", `C:\100%\x`, `C:\Users\dev`, nil, "windows", `C:\100%\x`},
		{"windows double percent", `a%%b`, `C:\Users\dev`, nil, "windows", `a%%b`},
		{"windows ${VAR:-default}", "${CLAUDE_CONFIG_DIR:-~/.claude}/projects/*/*.jsonl", `C:\Users\dev`, nil, "windows", `C:\Users\dev\.claude\projects\*\*.jsonl`},
		{"windows ${VAR:-default} relocated", "${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json", `C:\Users\dev`, map[string]string{"CLAUDE_CONFIG_DIR": `D:\cc`}, "windows", `D:\cc\settings.json`},
		{"windows no home: APPDATA stays", `%APPDATA%\x`, "", nil, "windows", `%APPDATA%\x`},
		{"windows XDG default (xdg-basedir tools)", "${XDG_DATA_HOME}/opencode/opencode.db", `C:\Users\dev`, nil, "windows", `C:\Users\dev\.local\share\opencode\opencode.db`},
		{"windows UNC home", "~/x", `\\server\share\dev`, nil, "windows", `\\server\share\dev\x`},

		// --- hostile environment values -----------------------------------
		{"NUL in value is treated as unset", "$CODEX_HOME/s", "/home/dev", map[string]string{"CODEX_HOME": "/a\x00/b"}, "linux", "$CODEX_HOME/s"},
		{"newline in value is treated as unset", "$CODEX_HOME/s", "/home/dev", map[string]string{"CODEX_HOME": "/a\n/b"}, "linux", "$CODEX_HOME/s"},
		{"over-long value is treated as unset", "$CODEX_HOME/s", "/home/dev", map[string]string{"CODEX_HOME": strings.Repeat("a", maxVarValue+1)}, "linux", "$CODEX_HOME/s"},
		{"over-long value falls back to the default", "${CODEX_HOME:-~/.codex}/s", "/home/dev", map[string]string{"CODEX_HOME": strings.Repeat("a", maxVarValue+1)}, "linux", "/home/dev/.codex/s"},
		{"bad home is ignored", "~/x", "/home/\x00dev", nil, "linux", "~/x"},
		{"traversal in a value is passed through for the caller to judge", "$CODEX_HOME/s", "/home/dev", map[string]string{"CODEX_HOME": "/home/dev/../../etc"}, "linux", "/home/dev/../../etc/s"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if got := Expand(tc.p, tc.home, tc.env, tc.goos); got != tc.want {
				t.Errorf("Expand(%q, %q, %v, %q)\n got %q\nwant %q", tc.p, tc.home, tc.env, tc.goos, got, tc.want)
			}
		})
	}
}

func TestExpandHostileInput(t *testing.T) {
	huge := strings.Repeat("$A/", 1<<20)
	if got := Expand(huge, "/h", map[string]string{"A": "x"}, "linux"); got != huge {
		t.Error("an over-long pattern must be returned untouched")
	}
	withNUL := "~/a\x00b"
	if got := Expand(withNUL, "/h", nil, "linux"); got != withNUL {
		t.Error("a pattern with NUL must be returned untouched")
	}
	// Deep nesting of defaults must terminate and must not explode.
	nested := strings.Repeat("${A:-", 500) + "x" + strings.Repeat("}", 500)
	if got := Expand(nested, "/h", nil, "linux"); len(got) > len(nested)+16 {
		t.Errorf("nested defaults grew to %d bytes", len(got))
	}
	// Output is bounded by the input plus one value per reference.
	many := strings.Repeat("$A", 2000)
	got := Expand(many, "/h", map[string]string{"A": strings.Repeat("v", maxVarValue)}, "linux")
	if len(got) > 2000*maxVarValue {
		t.Errorf("output %d bytes", len(got))
	}
	for _, p := range []string{"${", "${}", "${:-}", "$", "%", "%%", "~", "${A:-${B:-${C:-~}}}", "\xff\xfe${\xff}", "%\xff%"} {
		for _, goos := range []string{"linux", "darwin", "windows", ""} {
			Expand(p, "/h", map[string]string{"A": "1"}, goos) // must not panic
			Unexpanded(p, goos)
		}
	}
}

func TestExpandEveryCatalogPath(t *testing.T) {
	// With a home and no environment, every path in the shipped data must
	// expand completely on its own OS, except the ones that deliberately
	// depend on a variable with no default.
	c := mustLoad(t)
	homes := map[string]string{"linux": "/home/dev", "darwin": "/Users/dev", "windows": `C:\Users\dev`}
	check := func(id, field string, o OSPaths) {
		for goos, home := range homes {
			for _, p := range o.For(goos) {
				if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "HK") {
					continue // project-relative, registry
				}
				got := Expand(p, home, nil, goos)
				if left := Unexpanded(got, goos); len(left) > 0 {
					t.Errorf("%s %s (%s): %q expands to %q, leaving %v", id, field, goos, p, got, left)
				}
				if goos == "windows" && strings.Contains(got, "/") {
					t.Errorf("%s %s: windows path keeps a forward slash: %q", id, field, got)
				}
				if goos != "windows" && strings.HasPrefix(p, "~") && !strings.HasPrefix(got, home) {
					t.Errorf("%s %s (%s): %q did not land in the home: %q", id, field, goos, p, got)
				}
			}
		}
	}
	for _, p := range c.Products() {
		check(p.ID, "state_dirs", p.StateDirs)
		check(p.ID, "install_paths", p.InstallPaths)
		for _, m := range p.MCP {
			check(p.ID, "mcp.paths", m.Paths)
		}
		if p.Transcript != nil {
			check(p.ID, "transcript.globs", p.Transcript.Globs)
		}
		if p.Hooks != nil {
			check(p.ID, "hooks.managed_paths", p.Hooks.ManagedPaths)
			check(p.ID, "hooks.user_paths", p.Hooks.UserPaths)
		}
		for _, s := range p.Settings {
			check(p.ID, "settings.file", s.File)
		}
		all := OSPaths{}
		for _, l := range [][]string{p.Skills, p.Rules, p.Plugins, p.Subagents, p.Commands} {
			all.addAll(l)
		}
		check(p.ID, "skills/rules/plugins/subagents/commands", all)
	}
}

func TestUnexpanded(t *testing.T) {
	tests := []struct {
		p, goos string
		want    []string
	}{
		{"/home/dev/.codex/sessions", "linux", nil},
		{"$CODEX_HOME/sessions", "linux", []string{"CODEX_HOME"}},
		{"${CODEX_HOME}/sessions", "linux", []string{"CODEX_HOME"}},
		{"~/.codex", "linux", []string{"~"}},
		{"~", "linux", []string{"~"}},
		{`%APPDATA%\x`, "windows", []string{"APPDATA"}},
		{`%APPDATA%/x`, "linux", nil},
		{`C:\Users\dev\x`, "windows", nil},
		{"/a/$B/${C}", "linux", []string{"B", "C"}},
	}
	for _, tc := range tests {
		if got := Unexpanded(tc.p, tc.goos); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Unexpanded(%q, %q) = %v, want %v", tc.p, tc.goos, got, tc.want)
		}
	}
	// A hostile value that smuggles a variable reference is caught by the
	// same check, so the caller skips the path.
	got := Expand("$CLAUDE_CONFIG_DIR/projects", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": "$HOME/../victim"}, "linux")
	if len(Unexpanded(got, "linux")) == 0 {
		t.Errorf("smuggled reference not reported: %q", got)
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, path, goos string
		want                bool
	}{
		{"/home/dev/.claude/projects/*/*.jsonl", "/home/dev/.claude/projects/-home-dev-app/abc.jsonl", "linux", true},
		{"/home/dev/.claude/projects/*/*.jsonl", "/home/dev/.claude/projects/-home-dev-app/sub/abc.jsonl", "linux", false},
		{"/home/dev/.claude/projects/*/*.jsonl", "/home/dev/.claude/projects/abc.jsonl", "linux", false},
		{"/home/dev/.claude/projects/*/*.jsonl", "/home/dev/.claude/projects/x/abc.json", "linux", false},
		{"/h/.gemini/tmp/*/chats/**/*.jsonl", "/h/.gemini/tmp/ab12/chats/s.jsonl", "linux", true},
		{"/h/.gemini/tmp/*/chats/**/*.jsonl", "/h/.gemini/tmp/ab12/chats/a/b/s.jsonl", "linux", true},
		{"/h/.gemini/tmp/*/chats/**/*.jsonl", "/h/.gemini/tmp/ab12/logs/s.jsonl", "linux", false},
		{"/h/.codex/sessions/*/*/*/rollout-*.jsonl", "/h/.codex/sessions/2026/11/11/rollout-2026-11-11T10-00-00-uuid.jsonl", "linux", true},
		{"/h/.codex/sessions/*/*/*/rollout-*.jsonl", "/h/.codex/sessions/2026/11/11/rollout-x.jsonl.zst", "linux", false},
		{"/h/a?c", "/h/abc", "linux", true},
		{"/h/a?c", "/h/a/c", "linux", false},
		{"/h/**", "/h/a/b/c", "linux", true},
		{"/h/file.txt", "/h/fileXtxt", "linux", false},
		{"/h/[ab].txt", "/h/a.txt", "linux", false}, // classes are literal
		{"/h/[ab].txt", "/h/[ab].txt", "linux", true},
		{"/h/Claude", "/h/claude", "linux", false},
		{"/Users/dev/Library/Application Support/Claude/*.json", "/users/DEV/library/application support/claude/x.JSON", "darwin", true},
		{`C:\Users\dev\.claude\projects\*\*.jsonl`, `c:\users\dev\.claude\projects\p\s.jsonl`, "windows", true},
		{`C:\Users\dev\.claude\projects\*\*.jsonl`, `C:/Users/dev/.claude/projects/p/s.jsonl`, "windows", true},
		{`C:\Users\dev\.claude\projects\*\*.jsonl`, `C:\Users\dev\.claude\projects\p\q\s.jsonl`, "windows", false},
		{"", "", "linux", true},
		{"*", "", "linux", true},
		{"/h/x", "/h/x/../../etc/passwd", "linux", false},
		{"/h/projects/*/*.jsonl", "/h/projects/../x.jsonl", "linux", false},
		{"/h/**", "/h/a/../../etc/shadow", "linux", false},
		{`C:\h\**`, `C:\h\..\Windows\x`, "windows", false},
		{strings.Repeat("*", maxGlobLen+1), "x", "linux", false},
		{"/h/(a+)+$", "/h/" + strings.Repeat("a", 64) + "!", "linux", false},
	}
	for _, tc := range tests {
		if got := MatchGlob(tc.pattern, tc.path, tc.goos); got != tc.want {
			t.Errorf("MatchGlob(%.60q, %.60q, %q) = %v, want %v", tc.pattern, tc.path, tc.goos, got, tc.want)
		}
	}
}

// The transcript globs of the five majors, expanded, must match the paths
// the agents really write (shapes from research/agent-surfaces-a.md).
func TestTranscriptGlobsMatchRealPaths(t *testing.T) {
	c := mustLoad(t)
	tests := []struct {
		id, goos, home string
		env            map[string]string
		path           string
	}{
		{"claude-code", "linux", "/home/dev", nil, "/home/dev/.claude/projects/-home-dev-my-project/0f3a.jsonl"},
		{"claude-code", "linux", "/home/dev", nil, "/home/dev/.claude/projects/-home-dev-my-project/0f3a/subagents/agent-a1.jsonl"},
		{"claude-code", "linux", "/home/dev", map[string]string{"CLAUDE_CONFIG_DIR": "/mnt/cc"}, "/mnt/cc/projects/-x/0f3a.jsonl"},
		{"claude-code", "windows", `C:\Users\dev`, nil, `C:\Users\dev\.claude\projects\C--Users-dev-app\0f3a.jsonl`},
		{"codex", "darwin", "/Users/dev", nil, "/Users/dev/.codex/sessions/2026/11/11/rollout-2026-11-11T09-12-00-6b1d.jsonl"},
		{"codex", "darwin", "/Users/dev", nil, "/Users/dev/.codex/sessions/2026/10/01/rollout-2026-10-01T09-12-00-6b1d.jsonl.zst"},
		{"codex", "linux", "/home/dev", map[string]string{"CODEX_HOME": "/srv/codex"}, "/srv/codex/sessions/2026/11/11/rollout-x.jsonl"},
		{"copilot-cli", "linux", "/home/dev", nil, "/home/dev/.copilot/session-state/3c9e/events.jsonl"},
		{"copilot-cli", "linux", "/home/dev", map[string]string{"COPILOT_HOME": "/c"}, "/c/session-state/3c9e/events.jsonl"},
		{"gemini-cli", "linux", "/home/dev", nil, "/home/dev/.gemini/tmp/9f8e7d/chats/session-1.jsonl"},
		{"gemini-cli", "linux", "/home/dev", nil, "/home/dev/.gemini/tmp/9f8e7d/chats/session-1.json"},
		{"gemini-cli", "linux", "/home/dev", map[string]string{"GEMINI_CLI_HOME": "/g"}, "/g/.gemini/tmp/9f8e7d/chats/sub/agent.jsonl"},
		{"cursor", "darwin", "/Users/dev", nil, "/Users/dev/Library/Application Support/Cursor/User/globalStorage/state.vscdb"},
		{"cursor", "linux", "/home/dev", nil, "/home/dev/.config/Cursor/User/globalStorage/state.vscdb"},
		{"cursor", "windows", `C:\Users\dev`, nil, `C:\Users\dev\AppData\Roaming\Cursor\User\globalStorage\state.vscdb`},
	}
	for _, tc := range tests {
		p, ok := c.Get(tc.id)
		if !ok || p.Transcript == nil {
			t.Fatalf("%s has no transcript", tc.id)
		}
		matched := false
		for _, g := range p.Transcript.Globs.For(tc.goos) {
			if MatchGlob(Expand(g, tc.home, tc.env, tc.goos), tc.path, tc.goos) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s (%s, env %v): no transcript glob matches %s", tc.id, tc.goos, tc.env, tc.path)
		}
	}
	// And they must not match a look-alike outside the agent's tree.
	cc, _ := c.Get("claude-code")
	for _, g := range cc.Transcript.Globs.For("linux") {
		if MatchGlob(Expand(g, "/home/dev", nil, "linux"), "/home/dev/.claude/projects/../../.ssh/id_rsa.jsonl", "linux") {
			t.Errorf("glob %q matches a traversal path", g)
		}
	}
}
