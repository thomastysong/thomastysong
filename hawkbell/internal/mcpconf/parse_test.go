package mcpconf

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// ---- one fixture per dialect ----

const fixtureMCPServers = `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}
    },
    "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"},
    "legacy": {"type": "sse", "url": "https://mcp.example.com/sse", "headers": {"X-Api-Key": "${KEY}"}},
    "socket": {"type": "ws", "url": "wss://mcp.example.com/socket"},
    "cline-off": {"command": "node", "args": ["/opt/srv/index.js", 8080, true], "disabled": true},
    "windsurf": {"serverUrl": "https://windsurf.example.com/mcp"},
    "gemini-http": {"httpUrl": "https://gemini.example.com/mcp"},
    "gemini-sse": {"url": "http://localhost:8080/sse"},
    "bare-url": {"url": "https://bare.example.com/mcp"}
  }
}`

func TestParseMCPServers(t *testing.T) {
	ss := mustParse(t, "/home/a/.cursor/mcp.json", fixtureMCPServers, FormatMCPServers)
	m := index(t, ss)
	if len(m) != 9 {
		t.Fatalf("got %d servers %v, want 9", len(ss), names(ss))
	}
	gh := m["github"]
	eq(t, "github.Transport", gh.Transport, "stdio")
	eq(t, "github.Command", gh.Command, "npx")
	eq(t, "github.Args", gh.Args, []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"})
	eq(t, "github.Env", gh.Env, map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"})
	eq(t, "github.SourcePath", gh.SourcePath, "/home/a/.cursor/mcp.json")
	eq(t, "github.Project", gh.Project, "")
	eq(t, "github.Enabled", enabledString(gh.Enabled), "unset")

	want := map[string]string{
		"sentry": "http", "legacy": "sse", "socket": "ws", "cline-off": "stdio",
		"windsurf": "http", "gemini-http": "http", "gemini-sse": "sse", "bare-url": "http",
	}
	for name, tr := range want {
		eq(t, name+".Transport", m[name].Transport, tr)
	}
	eq(t, "windsurf.URL", m["windsurf"].URL, "https://windsurf.example.com/mcp")
	eq(t, "gemini-http.URL", m["gemini-http"].URL, "https://gemini.example.com/mcp")
	eq(t, "legacy.Headers", m["legacy"].Headers, map[string]string{"X-Api-Key": "${KEY}"})
	// Non-string scalars in args arrive as the strings a process would see.
	eq(t, "cline-off.Args", m["cline-off"].Args, []string{"/opt/srv/index.js", "8080", "true"})
	eq(t, "cline-off.Enabled", enabledString(m["cline-off"].Enabled), "false")

	// Output order is stable: sorted by name.
	sorted := append([]string(nil), names(ss)...)
	eq(t, "order", names(ss), sortedStrings(sorted))
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

const fixtureClaudeJSON = `{
  "numStartups": 42,
  "tipsHistory": {"a": 1},
  "mcpServers": {
    "user-scope": {"type": "stdio", "command": "uvx", "args": ["mcp-server-git"]}
  },
  "projects": {
    "/home/a/src/zeta": {
      "allowedTools": [],
      "mcpServers": {
        "local-db": {"command": "docker", "args": ["run", "-i", "--rm", "mcp/postgres"]},
        "paused": {"command": "npx", "args": ["-y", "pkg"]}
      },
      "disabledMcpServers": ["paused", "user-scope"],
      "enabledMcpjsonServers": ["x"]
    },
    "/home/a/src/alpha": {
      "mcpServers": {"api": {"type": "http", "url": "https://api.example.com/mcp"}}
    },
    "/home/a/src/empty": {"mcpServers": {}},
    "/home/a/src/none": {"history": []},
    "/home/a/src/bad": "not an object"
  }
}`

func TestParseClaudeJSONProjects(t *testing.T) {
	ss := mustParse(t, "/home/a/.claude.json", fixtureClaudeJSON, FormatClaudeJSON)
	m := index(t, ss)
	if len(m) != 4 {
		t.Fatalf("got %v, want 4 servers", names(ss))
	}
	eq(t, "user scope project", m["user-scope"].Project, "")
	eq(t, "user scope enabled", enabledString(m["user-scope"].Enabled), "unset") // a per-project opt-out does not disable it everywhere
	eq(t, "local-db project", m["/home/a/src/zeta|local-db"].Project, "/home/a/src/zeta")
	eq(t, "local-db enabled", enabledString(m["/home/a/src/zeta|local-db"].Enabled), "unset")
	eq(t, "paused enabled", enabledString(m["/home/a/src/zeta|paused"].Enabled), "false")
	eq(t, "api transport", m["/home/a/src/alpha|api"].Transport, "http")

	// User scope first, then projects in path order, names sorted within.
	var order []string
	for _, s := range ss {
		order = append(order, s.Project+"|"+s.Name)
	}
	eq(t, "order", order, []string{"|user-scope", "/home/a/src/alpha|api", "/home/a/src/zeta|local-db", "/home/a/src/zeta|paused"})

	// FormatMCPServers reads the same file without the projects.
	eq(t, "FormatMCPServers", names(mustParse(t, "/home/a/.claude.json", fixtureClaudeJSON, FormatMCPServers)), []string{"user-scope"})
	// Auto finds everything.
	eq(t, "auto", len(mustParse(t, "/home/a/.claude.json", fixtureClaudeJSON, FormatAuto)), 4)
}

const fixtureJSONC = "\uFEFF{\r\n" +
	"  // Cursor writes comments nowhere, people do\r\n" +
	"  \"mcpServers\": {\r\n" +
	"    /* block */ \"a\": {\"command\": \"node\", \"args\": [\"s.js\",],},\r\n" +
	"    \"b\": {\"url\": \"https://x.example/mcp\", /* \"url\": \"https://commented.example\" */ },\r\n" +
	"  },\r\n" +
	"}\r\n"

func TestParseJSONC(t *testing.T) {
	ss := mustParse(t, "/home/a/.cursor/mcp.json", fixtureJSONC, FormatMCPServers)
	m := index(t, ss)
	if len(m) != 2 {
		t.Fatalf("got %v", names(ss))
	}
	eq(t, "a.Args", m["a"].Args, []string{"s.js"})
	eq(t, "b.URL", m["b"].URL, "https://x.example/mcp")
}

const fixtureVSCode = `{
  // .vscode/mcp.json
  "inputs": [
    {"type": "promptString", "id": "perplexity-key", "description": "Perplexity API Key", "password": true},
    {"type": "promptString", "id": "github_token", "password": true}
  ],
  "servers": {
    "Perplexity": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "server-perplexity-ask", "--api-key", "${input:perplexity-key}"],
      "env": {"PERPLEXITY_API_KEY": "${input:perplexity-key}", "DEBUG": null, "PORT": 3000}
    },
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": {"Authorization": "Bearer ${input:github_token}"}
    }
  }
}`

func TestParseVSCodeInputsAreNotSecrets(t *testing.T) {
	ss := mustParse(t, "/work/repo/.vscode/mcp.json", fixtureVSCode, FormatVSCode)
	m := index(t, ss)
	if len(m) != 2 {
		t.Fatalf("got %v, want the two servers and nothing from \"inputs\"", names(ss))
	}
	p, g := m["/work/repo|Perplexity"], m["/work/repo|github"]
	eq(t, "project from path", p.Project, "/work/repo")
	eq(t, "env", p.Env, map[string]string{"PERPLEXITY_API_KEY": "${input:perplexity-key}", "DEBUG": "", "PORT": "3000"})

	for _, s := range []Server{p, g} {
		n := Normalize(s)
		if n.HasInlineSecret {
			t.Errorf("%s: ${input:...} placeholder reported as an inline secret", s.Name)
		}
		if flags := RiskFlags(s); hasFlag(flags, RiskInlineSecret) || hasFlag(flags, RiskTokenInURL) {
			t.Errorf("%s: flags %v", s.Name, flags)
		}
	}
	// The placeholder is not a secret, so it is not redacted either.
	eq(t, "perplexity args", Normalize(p).Args, []string{"-y", "server-perplexity-ask", "--api-key", "${input:perplexity-key}"})
	eq(t, "github auth", Normalize(g).AuthMode, "env")
	eq(t, "perplexity auth", Normalize(p).AuthMode, "env")
}

func TestParseVSCodeNestedLocations(t *testing.T) {
	entry := `{"type": "stdio", "command": "uvx", "args": ["mcp-server-time"]}`
	cases := []struct{ name, path, doc string }{
		{"settings nested", "/home/a/.config/Code/User/settings.json", `{"editor.fontSize": 12, "mcp": {"inputs": [], "servers": {"t": ` + entry + `}}}`},
		{"settings dotted", "/home/a/.config/Code/User/settings.json", `{"mcp.servers": {"t": ` + entry + `}}`},
		{"code-workspace", "/w/x.code-workspace", `{"folders": [{"path": "."}], "settings": {"mcp": {"servers": {"t": ` + entry + `}}}}`},
		{"code-workspace dotted", "/w/x.code-workspace", `{"settings": {"mcp.servers": {"t": ` + entry + `}}}`},
		{"devcontainer", "/w/.devcontainer/devcontainer.json", `{"image": "x", "customizations": {"vscode": {"mcp": {"servers": {"t": ` + entry + `}}}}}`},
	}
	for _, c := range cases {
		for _, f := range []Format{FormatVSCode, FormatAuto} {
			ss := mustParse(t, c.path, c.doc, f)
			if len(ss) != 1 || ss[0].Name != "t" || ss[0].Command != "uvx" {
				t.Errorf("%s (%q): got %+v", c.name, f, ss)
			}
		}
	}
	// devcontainer.json is always project scope.
	ss := mustParse(t, cases[4].path, cases[4].doc, FormatAuto)
	eq(t, "devcontainer project", ss[0].Project, "/w")
}

const fixtureZed = `{
  "theme": "One Dark",
  "context_servers": {
    "current": {"source": "custom", "command": "some-command", "args": ["arg-1", "arg-2"], "env": {}},
    "legacy": {"command": {"path": "node", "args": ["/home/a/srv/index.js"], "env": {"TOKEN": "x"}}, "settings": {}},
    "remote": {"url": "https://example.com/mcp", "headers": {"Authorization": "Bearer ${ZED_TOKEN}"}},
    "remote-oauth": {"url": "https://mcp.example.com/mcp"},
    "off": {"command": "x", "enabled": false},
    "extension-with-token": {"source": "extension", "settings": {"github_personal_access_token": "PLACEHOLDER", "nested": {"a": 1}}},
    "extension-bare": {"source": "extension", "enabled": true, "settings": {}}
  }
}`

func TestParseZed(t *testing.T) {
	ss := mustParse(t, "/home/a/.config/zed/settings.json", fixtureZed, FormatZed)
	m := index(t, ss)
	eq(t, "names", names(ss), []string{"current", "extension-with-token", "legacy", "off", "remote", "remote-oauth"})
	eq(t, "current", []any{m["current"].Command, m["current"].Args}, []any{"some-command", []string{"arg-1", "arg-2"}})
	eq(t, "legacy", []any{m["legacy"].Command, m["legacy"].Args, m["legacy"].Env}, []any{"node", []string{"/home/a/srv/index.js"}, map[string]string{"TOKEN": "x"}})
	eq(t, "remote transport", m["remote"].Transport, "http")
	eq(t, "off", enabledString(m["off"].Enabled), "false")
	// An extension-provided server has no launch line; its settings are
	// where the token lives, so the names are kept.
	ext := m["extension-with-token"]
	eq(t, "ext transport", ext.Transport, "stdio")
	eq(t, "ext env keys", sortedMapKeys(ext.Env), []string{"github_personal_access_token"})
	eq(t, "auto", len(mustParse(t, "/home/a/.config/zed/settings.json", fixtureZed, FormatAuto)), 6)
}

const fixtureCodex = `
model = "gpt-5-codex"
approval_policy = "on-request"

[mcp_servers.docs]
command = "uvx"
args = ["--from", "mcp-server-fetch==2025.1.17", "mcp-server-fetch"]
env_vars = ["HTTPS_PROXY", { name = "CORP_CA", source = "local" }]
startup_timeout_sec = 20

[mcp_servers.docs.env]
FETCH_UA = "codex"

[mcp_servers.figma]
url = "https://mcp.figma.com/mcp"
bearer_token_env_var = "FIGMA_OAUTH_TOKEN"
enabled = false

[mcp_servers.internal]
url = "https://mcp.corp.example/mcp"
http_headers = { "X-Team" = "platform" }
env_http_headers = { "X-Api-Key" = "CORP_MCP_KEY" }

[mcp_servers.linear]
url = "https://mcp.linear.app/mcp"
auth = "oauth"

[mcp_servers."quoted name"]
command = 'C:\Tools\server.exe'

[mcp_servers.helper]
url = "https://mcp.corp.example/h"
http_headers_helper = "/opt/bin/mint-headers"

[projects."/home/a/src/app"]
trust_level = "trusted"
`

func TestParseCodexTOML(t *testing.T) {
	for _, f := range []Format{FormatCodexTOML, FormatAuto} {
		ss := mustParse(t, "/home/a/.codex/config.toml", fixtureCodex, f)
		m := index(t, ss)
		eq(t, "names", names(ss), []string{"docs", "figma", "helper", "internal", "linear", "quoted name"})

		docs := m["docs"]
		eq(t, "docs", []any{docs.Transport, docs.Command, docs.Args}, []any{"stdio", "uvx", []string{"--from", "mcp-server-fetch==2025.1.17", "mcp-server-fetch"}})
		// env table values plus the names Codex forwards from its own environment.
		eq(t, "docs.Env", docs.Env, map[string]string{"FETCH_UA": "codex", "HTTPS_PROXY": "", "CORP_CA": ""})

		figma := m["figma"]
		eq(t, "figma", []any{figma.Transport, figma.URL, enabledString(figma.Enabled)}, []any{"http", "https://mcp.figma.com/mcp", "false"})
		eq(t, "figma header", figma.Headers, map[string]string{"Authorization": "Bearer ${FIGMA_OAUTH_TOKEN}"})
		eq(t, "figma env", figma.Env, map[string]string{"FIGMA_OAUTH_TOKEN": ""})
		eq(t, "figma auth", Normalize(figma).AuthMode, "env")
		if Normalize(figma).HasInlineSecret {
			t.Error("figma: an env var name is not an inline secret")
		}

		internal := m["internal"]
		eq(t, "internal headers", internal.Headers, map[string]string{"X-Team": "platform", "X-Api-Key": "${CORP_MCP_KEY}"})
		eq(t, "internal env", internal.Env, map[string]string{"CORP_MCP_KEY": ""})
		eq(t, "internal auth", Normalize(internal).AuthMode, "env")

		eq(t, "linear auth", Normalize(m["linear"]).AuthMode, "oauth")
		eq(t, "quoted", m["quoted name"].Command, `C:\Tools\server.exe`)
		eq(t, "helper auth", Normalize(m["helper"]).AuthMode, "header")
	}
}

const fixtureOpenCode = `{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-5",
  "mcp": {
    "local-array": {
      "type": "local",
      "command": ["bun", "x", "@acme/mcp@1.4.0", "--stdio"],
      "environment": {"ACME_REGION": "eu"},
      "enabled": true
    },
    "remote": {"type": "remote", "url": "https://mcp.acme.example/mcp", "headers": {"Authorization": "Bearer {env:ACME_TOKEN}"}, "enabled": false},
    "crush-style": {"type": "stdio", "command": "node", "args": ["server.js"], "disabled": true},
    "empty-array": {"type": "local", "command": []},
    "unknown-type": {"type": "quantum"}
  }
}`

func TestParseOpenCodeCommandArrays(t *testing.T) {
	for _, f := range []Format{FormatOpenCode, FormatAuto} {
		ss := mustParse(t, "/p/opencode.jsonc", fixtureOpenCode, f)
		m := index(t, ss)
		eq(t, "names", names(ss), []string{"crush-style", "local-array", "remote"})
		la := m["local-array"]
		eq(t, "command array", []any{la.Transport, la.Command, la.Args}, []any{"stdio", "bun", []string{"x", "@acme/mcp@1.4.0", "--stdio"}})
		eq(t, "environment", la.Env, map[string]string{"ACME_REGION": "eu"})
		eq(t, "enabled", enabledString(la.Enabled), "true")
		n := Normalize(la)
		eq(t, "normalized", []any{n.Runner, n.Ecosystem, n.Package, n.Version, n.Pinned}, []any{"bunx", "npm", "@acme/mcp", "1.4.0", true})

		r := m["remote"]
		eq(t, "remote", []any{r.Transport, enabledString(r.Enabled)}, []any{"http", "false"})
		eq(t, "remote auth is a reference", Normalize(r).AuthMode, "env")
		eq(t, "crush disabled", enabledString(m["crush-style"].Enabled), "false")
	}
}

const fixtureContinueYAML = `name: Local Assistant
version: 1.0.0
schema: v1
models: []
mcpServers:
  - name: SQLite MCP
    command: npx
    args:
      - "-y"
      - "mcp-sqlite"
      - "/path/to/your/database.db"
  - name: Supabase MCP
    type: stdio
    command: npx
    args: [-y, "@supabase/mcp-server-supabase@latest", --access-token, "${{ secrets.SUPABASE_TOKEN }}"]
    env:
      SUPABASE_TOKEN: ${{ secrets.SUPABASE_TOKEN }}
  - name: Streaming
    type: streamable-http
    url: https://stream.example.com/mcp
    requestOptions:
      headers:
        Authorization: Bearer ${{ secrets.STREAM_TOKEN }}
  - name: Events
    type: sse
    url: https://events.example.com/sse
  - command: uvx
    args: [mcp-server-time]
  - just a string
`

func TestParseContinueYAML(t *testing.T) {
	for _, f := range []Format{FormatContinue, FormatAuto} {
		ss := mustParse(t, "/home/a/.continue/config.yaml", fixtureContinueYAML, f)
		m := index(t, ss)
		eq(t, "names", names(ss), []string{"Events", "SQLite MCP", "Streaming", "Supabase MCP", "unnamed-5"})
		eq(t, "sqlite", m["SQLite MCP"].Args, []string{"-y", "mcp-sqlite", "/path/to/your/database.db"})
		eq(t, "streaming", []any{m["Streaming"].Transport, m["Streaming"].Headers}, []any{"http", map[string]string{"Authorization": "Bearer ${{ secrets.STREAM_TOKEN }}"}})
		eq(t, "events", m["Events"].Transport, "sse")
		sb := Normalize(m["Supabase MCP"])
		if sb.HasInlineSecret {
			t.Error("${{ secrets.X }} is a reference, not a secret")
		}
		eq(t, "supabase args untouched", sb.Args[3], "${{ secrets.SUPABASE_TOKEN }}")
	}
}

func TestParseContinueOtherShapes(t *testing.T) {
	// A Claude-format JSON file dropped into .continue/mcpServers/.
	ss := mustParse(t, "/w/.continue/mcpServers/mcp.json", `{"mcpServers": {"a": {"command": "npx", "args": ["-y", "x"]}}}`, FormatContinue)
	eq(t, "json map", names(ss), []string{"a"})
	// Legacy config.json.
	legacy := `{"models": [], "experimental": {"modelContextProtocolServers": [
	  {"transport": {"type": "stdio", "command": "uvx", "args": ["mcp-server-sqlite", "--db-path", "/tmp/test.db"]}},
	  {"name": "named", "transport": {"type": "sse", "url": "https://legacy.example.com/sse"}}
	]}}`
	for _, f := range []Format{FormatContinue, FormatAuto} {
		ss = mustParse(t, "/home/a/.continue/config.json", legacy, f)
		m := index(t, ss)
		eq(t, "legacy names", names(ss), []string{"named", "unnamed-1"})
		eq(t, "legacy stdio", []any{m["unnamed-1"].Transport, m["unnamed-1"].Command, m["unnamed-1"].Args}, []any{"stdio", "uvx", []string{"mcp-server-sqlite", "--db-path", "/tmp/test.db"}})
		eq(t, "legacy sse", []any{m["named"].Transport, m["named"].URL}, []any{"sse", "https://legacy.example.com/sse"})
	}
}

const fixtureGoose = `GOOSE_PROVIDER: anthropic
GOOSE_MODEL: claude-sonnet-4-5
extensions:
  developer:
    bundled: true
    enabled: true
    name: developer
    timeout: 300
    type: builtin
  computercontroller:
    type: platform
    name: computercontroller
    enabled: true
  filesystem:
    type: stdio
    name: filesystem
    enabled: true
    cmd: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    env_keys: [FS_TOKEN]
    envs: {FS_MODE: ro}
    timeout: 300
  remote-tools:
    type: streamable_http
    name: remote-tools
    enabled: false
    uri: "https://example.com/mcp"
    headers: {X-Team: core}
    env_keys: []
    envs: {}
  old-sse:
    type: sse
    uri: https://old.example.com/sse
`

func TestParseGooseYAML(t *testing.T) {
	for _, f := range []Format{FormatGoose, FormatAuto} {
		ss := mustParse(t, "/home/a/.config/goose/config.yaml", fixtureGoose, f)
		m := index(t, ss)
		// builtin and platform extensions run inside goose: nothing to launch.
		eq(t, "names", names(ss), []string{"filesystem", "old-sse", "remote-tools"})
		fs := m["filesystem"]
		eq(t, "fs", []any{fs.Transport, fs.Command, fs.Args, enabledString(fs.Enabled)},
			[]any{"stdio", "npx", []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, "true"})
		eq(t, "fs env", fs.Env, map[string]string{"FS_MODE": "ro", "FS_TOKEN": ""})
		rt := m["remote-tools"]
		eq(t, "remote", []any{rt.Transport, rt.URL, enabledString(rt.Enabled), rt.Headers},
			[]any{"http", "https://example.com/mcp", "false", map[string]string{"X-Team": "core"}})
		eq(t, "sse", m["old-sse"].Transport, "sse")
	}
}

func TestParseOtherMCPServersHomes(t *testing.T) {
	entry := `{"command": "npx", "args": ["-y", "pkg"]}`
	cases := []struct{ name, path, doc string }{
		{"amp dotted key", "/home/a/.config/amp/settings.json", `{"amp.url": "https://ampcode.com", "amp.mcpServers": {"s": ` + entry + `}}`},
		{"amp nested", "/w/.amp/settings.json", `{"amp": {"mcpServers": {"s": ` + entry + `}}}`},
		{"plugin flat map", "/home/a/.claude/plugins/cache/m/p/1.0/.mcp.json", `{"s": ` + entry + `}`},
		{"gemini settings", "/home/a/.gemini/settings.json", `{"theme": "x", "mcpServers": {"s": ` + entry + `}, "mcp": {"allowed": ["s"]}}`},
		{"copilot local type", "/home/a/.copilot/mcp-config.json", `{"mcpServers": {"s": {"type": "local", "command": "npx", "args": ["-y", "pkg"], "tools": ["*"]}}}`},
		{"plugin.json inline", "/p/.claude-plugin/plugin.json", `{"name": "p", "mcpServers": {"s": ` + entry + `}}`},
	}
	for _, c := range cases {
		for _, f := range []Format{FormatMCPServers, FormatAuto} {
			ss := mustParse(t, c.path, c.doc, f)
			if len(ss) != 1 || ss[0].Name != "s" || ss[0].Command != "npx" || ss[0].Transport != "stdio" {
				t.Errorf("%s (%q): got %+v", c.name, f, ss)
			}
		}
	}
	// plugin.json may point at a file instead of declaring servers inline.
	if ss := mustParse(t, "/p/plugin.json", `{"mcpServers": "./.mcp.json"}`, FormatAuto); ss != nil {
		t.Errorf("string mcpServers: got %+v", ss)
	}
}

func TestParseAutoOtherSyntaxes(t *testing.T) {
	// Hermes: YAML mcp_servers map. Mistral Vibe style: TOML array of tables.
	hermes := "model: x\nmcp_servers:\n  time:\n    command: uvx\n    args: [mcp-server-time]\n  web:\n    url: https://h.example/mcp\n"
	eq(t, "hermes yaml", names(mustParse(t, "/home/a/.hermes/config.yaml", hermes, FormatAuto)), []string{"time", "web"})
	vibe := "[[mcp_servers]]\nname = \"fetch\"\ntransport = \"stdio\"\ncommand = \"uvx\"\nargs = [\"mcp-server-fetch\"]\n\n[[mcp_servers]]\nname = \"api\"\ntransport = \"http\"\nurl = \"https://v.example/mcp\"\n"
	ss := mustParse(t, "/home/a/.vibe/config.toml", vibe, FormatAuto)
	eq(t, "toml list", names(ss), []string{"api", "fetch"})
	eq(t, "toml list transports", []string{ss[0].Transport, ss[1].Transport}, []string{"http", "stdio"})

	// No extension, no format: content decides.
	eq(t, "toml sniffed", names(mustParse(t, "/etc/codex/config", fixtureCodex, FormatAuto))[0], "docs")
	eq(t, "yaml sniffed", len(mustParse(t, "/x/config", fixtureGoose, FormatAuto)), 3)
	eq(t, "json sniffed", len(mustParse(t, "/x/config", fixtureMCPServers, FormatAuto)), 9)
	// A JSON document in a .yaml file is still read.
	eq(t, "json in yaml file", len(mustParse(t, "/x/servers.yaml", fixtureMCPServers, FormatAuto)), 9)
}

func TestParseEncodings(t *testing.T) {
	doc := `{"mcpServers": {"ünïcode": {"command": "npx", "args": ["-y", "pkg"]}}}`
	u16 := utf16.Encode([]rune(doc))
	le := []byte{0xFF, 0xFE}
	be := []byte{0xFE, 0xFF}
	bare := []byte{}
	for _, u := range u16 {
		le = append(le, byte(u), byte(u>>8))
		be = append(be, byte(u>>8), byte(u))
		bare = append(bare, byte(u), byte(u>>8))
	}
	for name, data := range map[string][]byte{
		"utf-8":            []byte(doc),
		"utf-8 bom":        append([]byte{0xEF, 0xBB, 0xBF}, doc...),
		"utf-16le bom":     le, // what Windows PowerShell 5 writes for "> managed-mcp.json"
		"utf-16be bom":     be,
		"utf-16le no bom":  bare,
		"crlf":             []byte(strings.ReplaceAll(strings.ReplaceAll(doc, "{", "{\r\n"), "}", "\r\n}")),
		"leading newlines": []byte("\n\n\t " + doc),
	} {
		ss, err := Parse(`C:\ProgramData\ClaudeCode\managed-mcp.json`, data, FormatMCPServers)
		if err != nil || len(ss) != 1 || ss[0].Name != "ünïcode" {
			t.Errorf("%s: got %+v, %v", name, ss, err)
		}
	}
}

func TestParseInvalidUTF8IsTolerated(t *testing.T) {
	// JavaScript agents read files leniently; one bad byte must not hide the
	// servers they will happily load.
	bad := "\xff\xfe\x80"
	cases := []struct {
		path, doc string
		f         Format
	}{
		{"/a/mcp.json", `{"note": "x` + bad[2:] + `y", "mcpServers": {"s": {"command": "npx", "args": ["a` + bad[2:] + `"]}}}`, FormatMCPServers},
		{"/a/config.toml", "# comment " + bad[2:] + "\n[mcp_servers.s]\ncommand = \"npx\"\n", FormatCodexTOML},
		{"/a/config.yaml", "# comment " + bad[2:] + "\nextensions:\n  s:\n    type: stdio\n    cmd: npx\n", FormatGoose},
	}
	for _, c := range cases {
		ss, err := Parse(c.path, []byte(c.doc), c.f)
		if err != nil || len(ss) != 1 || ss[0].Command != "npx" {
			t.Errorf("%s: got %+v, %v", c.path, ss, err)
		}
	}
}

func TestParseUnknownShapes(t *testing.T) {
	cases := []struct{ name, path, doc string }{
		{"empty", "/a.json", ""},
		{"whitespace", "/a.json", " \n\t\r\n"},
		{"only comments", "/a.json", "// nothing here\n/* at all */"},
		{"empty object", "/a.json", "{}"},
		{"array root", "/a.json", `[{"command": "npx"}]`},
		{"string root", "/a.json", `"mcpServers"`},
		{"number root", "/a.json", `42`},
		{"null root", "/a.json", `null`},
		{"unrelated object", "/package.json", `{"name": "x", "version": "1.0.0", "scripts": {"start": "node ."}}`},
		{"mcpServers null", "/a.json", `{"mcpServers": null}`},
		{"mcpServers empty", "/a.json", `{"mcpServers": {}}`},
		{"mcpServers number", "/a.json", `{"mcpServers": 7}`},
		{"vscode extensions.json", "/w/.vscode/extensions.json", `{"recommendations": ["a.b"], "servers": {"x": {"port": 1}}}`},
		{"compose servers key", "/w/x.json", `{"servers": {"web": {"image": "nginx", "ports": [80]}}}`},
		{"gemini extensions unrelated", "/a.json", `{"extensions": {"disabled": ["a"], "foo": {"version": "1"}}}`},
		{"one object with url is not a server list", "/a.json", `{"homepage": {"url": "https://x.example"}, "name": "pkg"}`},
		{"yaml scalar", "/a.yaml", "just some text"},
		{"yaml list", "/a.yaml", "- a\n- b\n"},
		{"yaml unrelated", "/a.yaml", "services:\n  web:\n    image: nginx\n"},
		{"toml unrelated", "/a.toml", "[tool.ruff]\nline-length = 100\n"},
		{"toml mcp_servers scalar", "/a.toml", "mcp_servers = 3\n"},
		{"plain text no extension", "/README", "This project uses MCP servers."},
	}
	for _, c := range cases {
		ss, err := Parse(c.path, []byte(c.doc), FormatAuto)
		if ss != nil || err != nil {
			t.Errorf("%s: got (%+v, %v), want (nil, nil)", c.name, ss, err)
		}
	}
}

func TestParseMalformedEntriesAreSkipped(t *testing.T) {
	doc := `{"mcpServers": {
	  "ok": {"command": "npx", "args": ["-y", "pkg"]},
	  "string": "npx -y pkg",
	  "number": 5,
	  "null": null,
	  "array": [1, 2],
	  "bool": true,
	  "empty": {},
	  "no-launch": {"args": ["x"], "env": {"A": "b"}},
	  "blank-command": {"command": "   "},
	  "command-number": {"command": 7},
	  "args-object": {"command": "node", "args": {"0": "x"}},
	  "args-nested": {"command": "node", "args": ["a", ["b"], {"c": 1}, null, "d"]},
	  "args-string": {"command": "node", "args": "server.js"},
	  "env-list": {"command": "node", "env": ["A=1", "B", "=x"]},
	  "env-nested": {"command": "node", "env": {"A": {"deep": 1}, "B": 2}},
	  "url-number": {"url": 80},
	  "headers-list": {"url": "https://x.example/mcp", "headers": ["a"]},
	  "enabled-string": {"command": "node", "enabled": "no"}
	}}`
	ss := mustParse(t, "/a/mcp.json", doc, FormatMCPServers)
	m := index(t, ss)
	eq(t, "kept", names(ss), []string{"args-nested", "args-object", "args-string", "enabled-string", "env-list", "env-nested", "headers-list", "ok"})
	eq(t, "args-object", m["args-object"].Args, []string(nil))
	eq(t, "args-nested", m["args-nested"].Args, []string{"a", "d"})
	eq(t, "args-string", m["args-string"].Args, []string{"server.js"})
	eq(t, "env-list", m["env-list"].Env, map[string]string{"A": "1", "B": ""})
	eq(t, "env-nested keeps the name", m["env-nested"].Env, map[string]string{"A": "", "B": "2"})
	eq(t, "headers-list", m["headers-list"].Headers, map[string]string(nil))
	eq(t, "enabled-string", enabledString(m["enabled-string"].Enabled), "unset")
}

func TestParseSyntaxErrors(t *testing.T) {
	secret := "hunter2-" + synth("leak", 24, base62)
	cases := []struct {
		name, path, doc, syntax string
		line                    int
	}{
		{"json", "/a/mcp.json", "{\n  \"mcpServers\": {\n    \"a\": {\"command\": " + secret + "}\n  }\n}", "json", 3},
		{"json unterminated", "/a/mcp.json", `{"mcpServers": {"a": {"command": "` + secret, "json", 0},
		{"json single quotes", "/a/mcp.json", `{'mcpServers': {'a': {'command': '` + secret + `'}}}`, "json", 1},
		{"toml", "/a/config.toml", "[mcp_servers.a]\ncommand = " + secret + "\n", "toml", 2},
		{"toml duplicate", "/a/config.toml", "[mcp_servers.a]\ncommand = 'x'\n[mcp_servers.a]\ncommand = '" + secret + "'\n", "toml", 3},
		{"yaml", "/a/config.yaml", "extensions:\n  a: [unclosed, " + secret + "\n  b: c\n", "yaml", 0},
		{"yaml complex key", "/a/config.yaml", "? [" + secret + "]\n: v\n", "yaml", 0},
	}
	for _, c := range cases {
		ss, err := Parse(c.path, []byte(c.doc), FormatAuto)
		var se *SyntaxError
		if !errors.As(err, &se) || ss != nil {
			t.Errorf("%s: got (%v, %v), want a *SyntaxError", c.name, ss, err)
			continue
		}
		if se.Syntax != c.syntax {
			t.Errorf("%s: syntax %q, want %q", c.name, se.Syntax, c.syntax)
		}
		if c.line != 0 && se.Line != c.line {
			t.Errorf("%s: line %d, want %d", c.name, se.Line, c.line)
		}
		// Parser messages quote the offending token; ours must not.
		if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%#v", se), secret) {
			t.Errorf("%s: error leaks file content: %v", c.name, err)
		}
	}
}

func TestParseLimitsAndFormats(t *testing.T) {
	big := make([]byte, MaxFileSize+1)
	for i := range big {
		big[i] = ' '
	}
	if _, err := Parse("/a.json", big, FormatAuto); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: %v", err)
	}
	if _, err := Parse("/a.json", big[:MaxFileSize], FormatAuto); err != nil {
		t.Errorf("exactly at the limit: %v", err)
	}
	if _, err := Parse("/a.json", []byte(`{}`), Format("jsonnet")); err == nil || !strings.Contains(err.Error(), "jsonnet") {
		t.Errorf("unknown format: %v", err)
	}

	var b strings.Builder
	b.WriteString(`{"mcpServers": {`)
	for i := 0; i < MaxServers+50; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"s%05d": {"command": "x"}`, i)
	}
	b.WriteString(`}}`)
	ss, err := Parse("/a.json", []byte(b.String()), FormatMCPServers)
	if !errors.Is(err, ErrTooManyServers) || len(ss) != MaxServers {
		t.Fatalf("too many servers: %d servers, err %v", len(ss), err)
	}
	// The cut is deterministic: the first MaxServers in name order.
	eq(t, "first", ss[0].Name, "s00000")
	eq(t, "last", ss[len(ss)-1].Name, fmt.Sprintf("s%05d", MaxServers-1))
}

func TestParseProjectFromPath(t *testing.T) {
	doc := `{"mcpServers": {"s": {"command": "x"}}, "servers": {"s2": {"command": "y"}}}`
	cases := []struct{ path, want string }{
		{"/home/a/src/app/.mcp.json", "/home/a/src/app"},
		{"/home/a/.mcp.json", "/home/a"},
		{"/.mcp.json", "/"},
		{".mcp.json", ""},
		{`C:\Users\a\src\app\.mcp.json`, `C:\Users\a\src\app`},
		{`C:\Users\a\src\app\.vscode\mcp.json`, `C:\Users\a\src\app`},
		{"/w/repo/.vscode/mcp.json", "/w/repo"},
		{"/w/repo/.roo/mcp.json", "/w/repo"},
		{"/w/repo/.amp/settings.json", "/w/repo"},
		{"/w/repo/.github/mcp.json", "/w/repo"},
		{"/w/repo/.devcontainer.json", "/w/repo"},
		// Plugin scope reuses the file name; it is not a project.
		{"/home/a/.claude/plugins/cache/m/p/1.0.0/.mcp.json", ""},
		// These layouts also exist under a home directory: the caller decides.
		{"/home/a/.cursor/mcp.json", ""},
		{"/home/a/.codex/config.toml", ""},
		{"/home/a/.gemini/settings.json", ""},
		{"/home/a/.claude.json", ""},
		// Path traversal in a path is just a string here; nothing is opened.
		{"/w/../../etc/.mcp.json", "/w/../../etc"},
	}
	for _, c := range cases {
		ss := mustParse(t, c.path, doc, FormatAuto)
		if len(ss) == 0 {
			t.Errorf("%s: nothing parsed", c.path)
			continue
		}
		for _, s := range ss {
			if s.Project != c.want || s.SourcePath != c.path {
				t.Errorf("%s: Project %q SourcePath %q, want Project %q", c.path, s.Project, s.SourcePath, c.want)
			}
		}
	}
}

func TestParseHostileNames(t *testing.T) {
	long := strings.Repeat("n", 5000)
	doc := `{"mcpServers": {
	  "../../../etc/passwd": {"command": "x"},
	  "a\u0000b\nc\u001b[31m": {"command": "x"},
	  "` + long + `": {"command": "x"},
	  "` + long + `2": {"command": "x"},
	  "": {"command": "x"}
	}, "projects": {
	  "../../outside": {"mcpServers": {"p": {"command": "x"}}},
	  "": {"mcpServers": {"q": {"command": "x"}}},
	  "` + long + `": {"mcpServers": {"r": {"command": "x"}}}
	}}`
	ss := mustParse(t, "/home/a/.claude.json", doc, FormatClaudeJSON)
	if len(ss) != 8 {
		t.Fatalf("got %d servers", len(ss))
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if len(s.Name) > maxNameLen || len(s.Project) > maxProjectLen {
			t.Errorf("unbounded name or project: %d / %d bytes", len(s.Name), len(s.Project))
		}
		seen[s.Project+"|"+s.Name] = true
	}
	// Names are data: traversal sequences and control bytes are kept verbatim.
	for _, k := range []string{"|../../../etc/passwd", "|a\x00b\nc\x1b[31m", "|", "../../outside|p", ".|q"} {
		if !seen[k] {
			t.Errorf("missing %q in %v", k, seen)
		}
	}
	// Two different over-long names stay different after capping.
	if len(seen) != 8 {
		t.Errorf("capped names collided: %d distinct keys", len(seen))
	}
}

func TestTransportOf(t *testing.T) {
	cases := []struct {
		typ         string
		hasCmd      bool
		urlKey, url string
		want        string
	}{
		{"stdio", true, "", "", "stdio"},
		{"STDIO", true, "", "", "stdio"},
		{"local", true, "", "", "stdio"},
		{"http", false, "url", "https://x/mcp", "http"},
		{"streamable-http", false, "url", "https://x/mcp", "http"},
		{"streamable_http", false, "uri", "https://x/mcp", "http"},
		{"streamableHttp", false, "url", "https://x/mcp", "http"},
		{"Streamable-HTTPS", false, "url", "https://x/mcp", "http"},
		{"sse", false, "url", "https://x/mcp", "sse"},
		{"ws", false, "url", "wss://x/s", "ws"},
		{"websocket", false, "url", "wss://x/s", "ws"},
		{"remote", false, "url", "https://x/mcp", "http"},
		{"remote", false, "url", "https://x/sse", "sse"},
		{"remote", true, "url", "https://x/mcp", "http"},
		{"", true, "", "", "stdio"},
		{"", true, "url", "https://x/mcp", "stdio"}, // clients that default to stdio ignore the url
		{"", false, "url", "https://x/mcp", "http"},
		{"", false, "url", "https://x/v1/sse/", "sse"},
		{"", false, "url", "ws://x/s", "ws"},
		{"", false, "httpUrl", "https://x/sse", "http"},
		{"quantum", false, "url", "https://x/mcp", "http"},
		{"quantum", true, "", "", "stdio"},
		{"", false, "", "", "stdio"},
	}
	for _, c := range cases {
		if got := transportOf(c.typ, c.hasCmd, c.urlKey, c.url); got != c.want {
			t.Errorf("transportOf(%q, %v, %q, %q) = %q, want %q", c.typ, c.hasCmd, c.urlKey, c.url, got, c.want)
		}
	}
}

func TestParseAuthFacts(t *testing.T) {
	doc := `{"mcpServers": {
	  "oauth-block": {"type": "http", "url": "https://a.example/mcp", "oauth": {"clientId": "abc", "callbackPort": 8080}},
	  "oauth-off": {"type": "http", "url": "https://a.example/mcp", "oauth": false},
	  "oauth-disabled": {"type": "http", "url": "https://a.example/mcp", "oauth": {"enabled": false}},
	  "gemini-google": {"httpUrl": "https://run.example/mcp", "authProviderType": "google_credentials"},
	  "copilot-flat": {"type": "http", "url": "https://a.example/mcp", "oauthClientId": "abc"},
	  "helper": {"type": "http", "url": "https://a.example/mcp", "headersHelper": "/opt/bin/get-mcp-auth-headers.sh"},
	  "static": {"type": "http", "url": "https://a.example/mcp", "headers": {"Authorization": "Bearer literal-value"}},
	  "reference": {"type": "http", "url": "https://a.example/mcp", "headers": {"Authorization": "Bearer ${API_KEY}"}},
	  "default-is-literal": {"type": "http", "url": "https://a.example/mcp", "headers": {"X-Api-Key": "${API_KEY:-fallback}"}},
	  "non-auth-header": {"type": "http", "url": "https://a.example/mcp", "headers": {"X-Trace": "on"}},
	  "anonymous": {"type": "http", "url": "https://a.example/mcp"},
	  "stdio-env": {"command": "x", "env": {"A": "b"}},
	  "stdio-empty-env": {"command": "x", "env": {}},
	  "stdio-no-env": {"command": "x"}
	}}`
	want := map[string]string{
		"oauth-block": "oauth", "oauth-off": "none", "oauth-disabled": "none", "gemini-google": "oauth",
		"copilot-flat": "oauth", "helper": "header", "static": "header", "reference": "env",
		"default-is-literal": "header", "non-auth-header": "none", "anonymous": "none",
		"stdio-env": "env", "stdio-empty-env": "inherited", "stdio-no-env": "inherited",
	}
	ss := mustParse(t, "/a/.mcp.json", doc, FormatMCPServers)
	if len(ss) != len(want) {
		t.Fatalf("got %v", names(ss))
	}
	for _, s := range ss {
		if got := Normalize(s).AuthMode; got != want[s.Name] {
			t.Errorf("%s: AuthMode %q, want %q", s.Name, got, want[s.Name])
		}
	}
}
