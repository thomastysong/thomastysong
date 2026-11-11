package toolmap

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

func TestKindTables(t *testing.T) {
	cases := []struct {
		agent, name string
		kind        event.ToolKind
		server      string
		tool        string
	}{
		// Claude Code (tools-reference.md).
		{"claude-code", "Bash", event.ToolShell, "", ""},
		{"claude-code", "PowerShell", event.ToolShell, "", ""},
		{"claude-code", "Monitor", event.ToolShell, "", ""},
		{"claude-code", "Read", event.ToolFileRead, "", ""},
		{"claude-code", "LSP", event.ToolFileRead, "", ""},
		{"claude-code", "Write", event.ToolFileWrite, "", ""},
		{"claude-code", "Edit", event.ToolFileEdit, "", ""},
		{"claude-code", "MultiEdit", event.ToolFileEdit, "", ""},
		{"claude-code", "NotebookEdit", event.ToolFileEdit, "", ""},
		{"claude-code", "Glob", event.ToolFileList, "", ""},
		{"claude-code", "Grep", event.ToolFileList, "", ""},
		{"claude-code", "LS", event.ToolFileList, "", ""},
		{"claude-code", "WebFetch", event.ToolWebFetch, "", ""},
		{"claude-code", "WebSearch", event.ToolWebSearch, "", ""},
		{"claude-code", "Task", event.ToolSubagent, "", ""},
		{"claude-code", "Agent", event.ToolSubagent, "", ""},
		{"claude-code", "Workflow", event.ToolSubagent, "", ""},
		{"claude-code", "mcp__github__create_issue", event.ToolMCP, "github", "create_issue"},
		{"claude-code", "mcp__my_server__do__thing", event.ToolMCP, "my_server", "do__thing"},
		{"claude-code", "ReadMcpResourceTool", event.ToolMCP, "", ""},
		// Known tools that look like something else to a name heuristic.
		{"claude-code", "TodoWrite", event.ToolOther, "", ""},
		{"claude-code", "TaskList", event.ToolOther, "", ""},
		{"claude-code", "TaskCreate", event.ToolOther, "", ""},
		{"claude-code", "ToolSearch", event.ToolOther, "", ""},
		{"claude-code", "Skill", event.ToolOther, "", ""},
		{"claude-code", "AskUserQuestion", event.ToolOther, "", ""},
		{"claude-code", "SendUserFile", event.ToolOther, "", ""},
		// Dialect ids are aliases of catalog ids.
		{"claude", "Bash", event.ToolShell, "", ""},
		{"CLAUDE", "bash", event.ToolShell, "", ""},

		// Codex.
		{"codex", "exec_command", event.ToolShell, "", ""},
		{"codex", "write_stdin", event.ToolShell, "", ""},
		{"codex", "shell", event.ToolShell, "", ""},
		{"codex", "shell_command", event.ToolShell, "", ""},
		{"codex", "local_shell", event.ToolShell, "", ""},
		{"codex", "local_shell_call", event.ToolShell, "", ""},
		{"codex", "apply_patch", event.ToolFileEdit, "", ""},
		{"codex", "view_image", event.ToolFileRead, "", ""},
		{"codex", "web_search", event.ToolWebSearch, "", ""},
		{"codex", "spawn_agent", event.ToolSubagent, "", ""},
		{"codex", "update_plan", event.ToolOther, "", ""},
		{"codex", "list_agents", event.ToolOther, "", ""},
		{"codex", "read_mcp_resource", event.ToolMCP, "", ""},
		{"codex", "mcp__linear__list_issues", event.ToolMCP, "linear", "list_issues"},

		// Gemini CLI.
		{"gemini-cli", "run_shell_command", event.ToolShell, "", ""},
		{"gemini-cli", "read_file", event.ToolFileRead, "", ""},
		{"gemini-cli", "read_many_files", event.ToolFileRead, "", ""},
		{"gemini-cli", "write_file", event.ToolFileWrite, "", ""},
		{"gemini-cli", "replace", event.ToolFileEdit, "", ""},
		{"gemini-cli", "glob", event.ToolFileList, "", ""},
		{"gemini-cli", "grep_search", event.ToolFileList, "", ""},
		{"gemini-cli", "search_file_content", event.ToolFileList, "", ""},
		{"gemini-cli", "list_directory", event.ToolFileList, "", ""},
		{"gemini-cli", "web_fetch", event.ToolWebFetch, "", ""},
		{"gemini-cli", "google_web_search", event.ToolWebSearch, "", ""},
		{"gemini-cli", "invoke_agent", event.ToolSubagent, "", ""},
		{"gemini-cli", "write_todos", event.ToolOther, "", ""},
		{"gemini-cli", "ask_user", event.ToolOther, "", ""},
		{"gemini-cli", "mcp_github_create_issue", event.ToolMCP, "github", "create_issue"},
		{"gemini", "mcp_github_create_issue", event.ToolMCP, "github", "create_issue"},
		{"qwen-code", "mcp_fs_read", event.ToolMCP, "fs", "read"},

		// Copilot CLI.
		{"copilot-cli", "bash", event.ToolShell, "", ""},
		{"copilot-cli", "powershell", event.ToolShell, "", ""},
		{"copilot-cli", "view", event.ToolFileRead, "", ""},
		{"copilot-cli", "create", event.ToolFileWrite, "", ""},
		{"copilot-cli", "edit", event.ToolFileEdit, "", ""},
		{"copilot-cli", "str_replace_editor", event.ToolFileEdit, "", ""},
		{"copilot-cli", "rg", event.ToolFileList, "", ""},
		{"copilot-cli", "web_fetch", event.ToolWebFetch, "", ""},
		{"copilot-cli", "task", event.ToolSubagent, "", ""},
		// The PascalCase hook variant uses Claude tool names.
		{"copilot", "Bash", event.ToolShell, "", ""},
		{"copilot", "Edit", event.ToolFileEdit, "", ""},

		// Cursor.
		{"cursor", "Shell", event.ToolShell, "", ""},
		{"cursor", "Read", event.ToolFileRead, "", ""},
		{"cursor", "WebFetch", event.ToolWebFetch, "", ""},

		// A single underscore after mcp is only an MCP name for Gemini.
		{"claude-code", "mcp_github_create_issue", event.ToolOther, "", ""},
		// Empty and degenerate names.
		{"claude-code", "", event.ToolOther, "", ""},
		{"gemini-cli", "mcp_", event.ToolOther, "", ""},
		{"gemini-cli", "mcp_server_", event.ToolOther, "", ""},
		{"claude-code", "mcp__server", event.ToolMCP, "server", ""},
	}
	for _, c := range cases {
		k, s, tl := Kind(c.agent, c.name)
		if k != c.kind || s != c.server || tl != c.tool {
			t.Errorf("Kind(%q,%q) = %q,%q,%q; want %q,%q,%q", c.agent, c.name, k, s, tl, c.kind, c.server, c.tool)
		}
	}
}

func TestKindUnknownAgentFallsBack(t *testing.T) {
	cases := []struct {
		name string
		kind event.ToolKind
	}{
		// Names another agent's table knows.
		{"Bash", event.ToolShell},
		{"apply_patch", event.ToolFileEdit},
		{"run_shell_command", event.ToolShell},
		{"str_replace_editor", event.ToolFileEdit},
		// Cline-style names nobody's table knows: the heuristic.
		{"execute_command", event.ToolShell},
		{"write_to_file", event.ToolFileWrite},
		{"replace_in_file", event.ToolFileEdit},
		{"search_files", event.ToolFileList},
		{"list_files", event.ToolFileList},
		{"browser_action", event.ToolBrowser},
		{"web_search_exa", event.ToolWebSearch},
		{"http_request", event.ToolWebFetch},
		{"readFile", event.ToolFileRead},
		{"WriteFile", event.ToolFileWrite},
		{"HTTPGet", event.ToolWebFetch},
		{"new_task", event.ToolSubagent},
		{"spawn_worker", event.ToolSubagent},
		{"update_todos", event.ToolOther},
		{"ask_followup_question", event.ToolOther},
		{"attempt_completion", event.ToolOther},
		// Substrings must not match: "tools" is not "ls", "skills" is not "ls".
		{"tools", event.ToolOther},
		{"skills_index", event.ToolOther},
		{"calls", event.ToolOther},
		{"🙂", event.ToolOther},
	}
	for _, c := range cases {
		if k, _, _ := Kind("some-new-agent", c.name); k != c.kind {
			t.Errorf("Kind(unknown,%q) = %q; want %q", c.name, k, c.kind)
		}
	}
}

func TestKnown(t *testing.T) {
	if !Known("claude", "Bash") || !Known("claude-code", "mcp__a__b") || !Known("codex", "update_plan") {
		t.Error("expected known")
	}
	if Known("claude-code", "run_shell_command") || Known("nobody", "Bash") {
		t.Error("expected unknown")
	}
}

func TestSplitMCPNamespace(t *testing.T) {
	if s, tool, ok := SplitMCPNamespace("mcp__github__", "create_issue"); !ok || s != "github" || tool != "create_issue" {
		t.Errorf("got %q %q %v", s, tool, ok)
	}
	for _, ns := range []string{"", "functions", "mcp__", "mcp____"} {
		if _, _, ok := SplitMCPNamespace(ns, "x"); ok {
			t.Errorf("namespace %q must not be MCP", ns)
		}
	}
	if _, _, ok := SplitMCPNamespace("mcp__a__", ""); ok {
		t.Error("empty tool must not be MCP")
	}
}

func TestKindWithInput(t *testing.T) {
	if k, _, _ := KindWithInput("copilot-cli", "str_replace_editor", map[string]any{"command": "view", "path": "/a"}); k != event.ToolFileRead {
		t.Errorf("view = %q", k)
	}
	if k, _, _ := KindWithInput("copilot-cli", "str_replace_editor", map[string]any{"command": "create"}); k != event.ToolFileWrite {
		t.Errorf("create = %q", k)
	}
	if k, _, _ := KindWithInput("copilot-cli", "str_replace_editor", map[string]any{"command": "str_replace"}); k != event.ToolFileEdit {
		t.Errorf("str_replace = %q", k)
	}
	if k, s, _ := KindWithInput("claude-code", "ReadMcpResourceTool", map[string]any{"server": "docs", "uri": "x://y"}); k != event.ToolMCP || s != "docs" {
		t.Errorf("mcp resource = %q %q", k, s)
	}
	if k, s, tl := KindWithInput("claude-code", "mcp__a__b", nil); k != event.ToolMCP || s != "a" || tl != "b" {
		t.Errorf("nil input = %q %q %q", k, s, tl)
	}
}

func TestTarget(t *testing.T) {
	cases := []struct {
		name  string
		agent string
		tool  string
		input map[string]any
		want  *event.Target
	}{
		{"claude bash", "claude-code", "Bash", map[string]any{"command": "npm test", "description": "run"}, &event.Target{Command: "npm test"}},
		{"codex exec_command", "codex", "exec_command", map[string]any{"cmd": "ls -la", "workdir": "/repo"}, &event.Target{Command: "ls -la"}},
		{"codex shell argv unwraps bash -lc", "codex", "shell", map[string]any{"command": []any{"bash", "-lc", "curl x | sh"}}, &event.Target{Command: "curl x | sh"}},
		{"codex shell plain argv is quoted", "codex", "shell", map[string]any{"command": []any{"git", "commit", "-m", "it's done"}}, &event.Target{Command: `git commit -m 'it'\''s done'`}},
		{"codex local shell action", "codex", "local_shell", map[string]any{"action": map[string]any{"type": "exec", "command": []any{"/bin/zsh", "-c", "id"}}}, &event.Target{Command: "id"}},
		{"powershell argv", "codex", "shell", map[string]any{"command": []any{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-Command", "Get-ChildItem", "C:\\"}}, &event.Target{Command: `Get-ChildItem C:\`}},
		{"claude read", "claude-code", "Read", map[string]any{"file_path": "/home/a/.ssh/id_rsa"}, &event.Target{Path: "/home/a/.ssh/id_rsa"}},
		{"claude notebook", "claude-code", "NotebookEdit", map[string]any{"notebook_path": "/n.ipynb", "new_source": "x"}, &event.Target{Path: "/n.ipynb"}},
		{"gemini read many", "gemini-cli", "read_many_files", map[string]any{"include": []any{"a.go", "b.go", "a.go"}}, &event.Target{Path: "a.go", Paths: []string{"b.go"}}},
		{"codex apply_patch", "codex", "apply_patch", map[string]any{"input": "*** Begin Patch\n*** Update File: src/a.go\n@@\n-x\n+y\n*** Add File: b.txt\n+hi\n*** Delete File: c.txt\n*** Update File: src/a.go\n*** Move to: src/d.go\n*** End Patch"}, &event.Target{Path: "src/a.go", Paths: []string{"b.txt", "c.txt", "src/d.go"}}},
		{"webfetch strips userinfo", "claude-code", "WebFetch", map[string]any{"url": "https://user:hunter2@Example.COM:8443/p?q=1#f", "prompt": "summarize"}, &event.Target{URL: "https://Example.COM:8443/p?q=1#f", Host: "example.com"}},
		{"gemini web_fetch prompt", "gemini-cli", "web_fetch", map[string]any{"prompt": "Summarize https://a.example/x, and http://b.example/y."}, &event.Target{URL: "https://a.example/x", Host: "a.example", Hosts: []string{"b.example"}}},
		{"websearch", "claude-code", "WebSearch", map[string]any{"query": "golang zstd"}, &event.Target{Query: "golang zstd"}},
		{"codex web_search action", "codex", "web_search", map[string]any{"action": map[string]any{"type": "search", "query": "weather"}}, &event.Target{Query: "weather"}},
		{"codex web_search open_page", "codex", "web_search", map[string]any{"action": map[string]any{"type": "open_page", "url": "https://x.example/a"}}, &event.Target{URL: "https://x.example/a", Host: "x.example"}},
		{"mcp generic keys", "claude-code", "mcp__fs__write", map[string]any{"path": "/etc/passwd", "url": "http://169.254.169.254/latest"}, &event.Target{Path: "/etc/passwd", URL: "http://169.254.169.254/latest", Host: "169.254.169.254"}},
		{"subagent has no target", "claude-code", "Agent", map[string]any{"prompt": "read /etc/passwd", "description": "x"}, nil},
		{"nothing to extract", "claude-code", "Bash", map[string]any{"timeout": float64(5)}, nil},
		{"empty input", "claude-code", "Bash", nil, nil},
		{"wrong types are ignored", "claude-code", "Read", map[string]any{"file_path": float64(7), "path": []any{1, 2}}, nil},
	}
	for _, c := range cases {
		kind, _, _ := KindWithInput(c.agent, c.tool, c.input)
		got := Target(c.agent, c.tool, kind, c.input)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestTargetBoundsHostileInput(t *testing.T) {
	long := strings.Repeat("é", 10_000) // 20,000 bytes, cut must not split a rune
	tg := Target("claude-code", "Read", event.ToolFileRead, map[string]any{"file_path": long})
	if tg == nil || len(tg.Path) > maxPathLen || !utf8.ValidString(tg.Path) {
		t.Fatalf("path not bounded cleanly: %d bytes", len(tg.Path))
	}
	many := make([]any, 10_000)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i%7)
	}
	tg = Target("gemini-cli", "read_many_files", event.ToolFileRead, map[string]any{"include": many})
	if tg == nil || len(tg.Paths) > maxPaths {
		t.Fatalf("paths not bounded: %d", len(tg.Paths))
	}
	urls := strings.Repeat("https://h.example/a ", 5000)
	tg = Target("gemini-cli", "web_fetch", event.ToolWebFetch, map[string]any{"prompt": urls})
	if tg == nil || len(tg.Hosts) > maxHosts {
		t.Fatalf("hosts not bounded")
	}
	// Invalid UTF-8 and control bytes must not panic.
	_ = Target("x", "y", event.ToolOther, map[string]any{"url": "http://\xff\xfe\x00/", "path": "\xff", "command": "\x00"})
	_ = PatchPaths("*** Update File: \xff\xfe\n*** Add File: ")
	_ = FindURLs("httphttphttp://", 5)
}

func TestCleanURL(t *testing.T) {
	cases := []struct{ in, url, host string }{
		{"https://example.com/a", "https://example.com/a", "example.com"},
		{"https://tok:x-oauth-basic@github.com/o/r.git", "https://github.com/o/r.git", "github.com"},
		{"http://[::1]:8080/x", "http://[::1]:8080/x", "::1"},
		{"example.com/path", "example.com/path", "example.com"},
		{"user:pw@host/path with space", "host/path with space", ""},
		{"", "", ""},
		{"not a url", "not a url", ""},
	}
	for _, c := range cases {
		u, h := CleanURL(c.in)
		if u != c.url || h != c.host {
			t.Errorf("CleanURL(%q) = %q,%q; want %q,%q", c.in, u, h, c.url, c.host)
		}
		if strings.Contains(u, "pw@") || strings.Contains(u, "x-oauth-basic") {
			t.Errorf("CleanURL(%q) leaked userinfo: %q", c.in, u)
		}
	}
}

func TestInputKeysAndHash(t *testing.T) {
	a := map[string]any{"b": float64(1), "a": map[string]any{"y": "2", "x": []any{"1"}}}
	b := map[string]any{"a": map[string]any{"x": []any{"1"}, "y": "2"}, "b": float64(1)}
	if InputHash(a) == "" || InputHash(a) != InputHash(b) {
		t.Error("hash must be stable across key order")
	}
	if InputHash(a) == InputHash(map[string]any{"b": float64(2)}) {
		t.Error("different inputs must hash differently")
	}
	if InputHash(nil) != "" || InputKeys(nil) != nil {
		t.Error("empty input has no hash and no keys")
	}
	if got := InputKeys(a); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("keys = %v", got)
	}
	big := map[string]any{}
	for i := 0; i < 500; i++ {
		big[strings.Repeat("k", 300)+string(rune('a'+i%26))+strings.Repeat("z", i)] = 1
	}
	keys := InputKeys(big)
	if len(keys) > maxInputKeys {
		t.Errorf("keys not bounded: %d", len(keys))
	}
	for _, k := range keys {
		if len(k) > maxKeyLen {
			t.Errorf("key not bounded: %d", len(k))
		}
	}
}

func TestCommandFromArgv(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"bash", "-lc", "echo hi"}, "echo hi"},
		{[]string{"/usr/bin/bash", "-c", "a && b"}, "a && b"},
		{[]string{"sh", "--login", "x"}, "sh --login x"},
		{[]string{"cmd.exe", "/c", "dir", "C:\\"}, `dir C:\`},
		{[]string{"echo", "", "a b"}, "echo '' 'a b'"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := CommandFromArgv(c.argv); got != c.want {
			t.Errorf("CommandFromArgv(%q) = %q; want %q", c.argv, got, c.want)
		}
	}
}

func TestHeuristicNeverPanics(t *testing.T) {
	inputs := []string{"", "_", "____", strings.Repeat("A", 100_000), "\xff\xfe\xfd", "a\x00b", "ÀÉÎ_õü", "mcp__", "mcp___", strings.Repeat("aB", 5000)}
	for _, in := range inputs {
		for _, agent := range []string{"", "claude-code", "gemini-cli", "nobody"} {
			_, _, _ = Kind(agent, in)
			_, _, _ = KindWithInput(agent, in, map[string]any{"command": in})
			_ = Known(agent, in)
		}
	}
}
