package hookio

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// The fixtures under testdata/claude named after an event are the JSON
// examples of the Claude Code hooks reference, copied verbatim.
func TestClaudeGolden(t *testing.T) {
	d := dialect(t, "claude")
	cases := []struct {
		file     string
		typ      string
		blocking bool
		check    func(t *testing.T, e *event.Event)
	}{
		{"PreToolUse.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "abc123")
			eq(t, "session.turn_id", e.Session.TurnID, "550e8400-e29b-41d4-a716-446655440000")
			eq(t, "session.cwd", e.Session.CWD, "/home/user/my-project")
			eq(t, "session.transcript", e.Session.Transcript, "/home/user/.claude/projects/.../transcript.jsonl")
			eq(t, "session.permission_mode", e.Session.PermissionMode, "default")
			eq(t, "tool.name", e.Tool.Name, "Bash")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "tool.use_id", e.Tool.UseID, "toolu_01ABC123...")
			eq(t, "tool.input_keys", e.Tool.InputKeys, []string{"command", "description", "run_in_background", "timeout"})
			eq(t, "target.command", target(e).Command, "npm test")
			eq(t, "content.tool_input.command", e.Content.ToolInput["command"], "npm test")
			if len(e.Tool.InputSHA256) != 64 {
				t.Errorf("input hash = %q", e.Tool.InputSHA256)
			}
			if len(e.Content.Raw) == 0 {
				t.Error("raw payload not kept")
			}
		}},
		{"PermissionRequest.json", event.TypePermissionDecision, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "tool.use_id", e.Tool.UseID, "") // the event has no tool_use_id
			eq(t, "target.command", target(e).Command, "rm -rf node_modules")
			eq(t, "outcome", outcome(e), event.Outcome{Decision: "ask", DecisionSource: "policy"})
		}},
		{"PermissionDenied.json", event.TypePermissionDecision, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.permission_mode", e.Session.PermissionMode, "auto")
			eq(t, "target.command", target(e).Command, "rm -rf /tmp/build")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "denied", Decision: "deny", DecisionSource: "policy", Error: "Irreversible Local Destruction"})
		}},
		{"PostToolUse.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileWrite)
			eq(t, "target.path", target(e).Path, "/path/to/file.txt")
			eq(t, "content.file_content", e.Content.FileContent, "file content")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok", DurationMS: 12})
			if e.Content.ToolOutput == "" || e.Tool.OutputLen != len(e.Content.ToolOutput) || len(e.Tool.OutputSHA256) != 64 {
				t.Errorf("output not recorded: %q len=%d", e.Content.ToolOutput, e.Tool.OutputLen)
			}
		}},
		{"PostToolUse_bash.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.permission_mode", e.Session.PermissionMode, "bypass")
			eq(t, "content.tool_output", e.Content.ToolOutput, "installed\n\nwarn: x\n")
			eq(t, "label sandbox_bypass", e.Labels["sandbox_bypass"], "1")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok", DurationMS: 812})
		}},
		{"PostToolUseFailure.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "exit code 1", DurationMS: 4187})
			eq(t, "exit code", exitCodeOf(e), 1)
			// The raw error text is for local detection only.
			eq(t, "content.tool_output", e.Content.ToolOutput, "Exit code 1\nError: Cannot find module 'express'")
		}},
		{"PreToolUse_mcp.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "tool.mcp_server", e.Tool.MCPServer, "db") // harness-reported name wins
			eq(t, "tool.mcp_tool", e.Tool.MCPTool, "query")
			eq(t, "label mcp_source", e.Labels["mcp_source"], "plugin")
			eq(t, "label mcp_tool_prefix", e.Labels["mcp_tool_prefix"], "plugin_my-plugin_db")
			eq(t, "session.permission_mode", e.Session.PermissionMode, "accept_edits")
			eq(t, "session.subagent_id", e.Session.SubagentID, "agent-7")
			eq(t, "session.subagent_type", e.Session.SubagentType, "Explore")
			eq(t, "target.host", target(e).Host, "db.internal.example")
		}},
		{"UserPromptSubmit.json", event.TypePromptSubmit, true, func(t *testing.T, e *event.Event) {
			const p = "Write a function to calculate the factorial of a number"
			eq(t, "content.prompt", e.Content.PromptText, p)
			eq(t, "prompt.len", e.Prompt.Len, len(p))
			eq(t, "prompt.text", e.Prompt.Text, "") // never serialized by the source
		}},
		{"UserPromptExpansion.json", event.TypePromptSubmit, true, func(t *testing.T, e *event.Event) {
			eq(t, "label prompt_kind", e.Labels["prompt_kind"], "expansion")
			eq(t, "label expansion_type", e.Labels["expansion_type"], "slash_command")
			eq(t, "label command_source", e.Labels["command_source"], "plugin")
		}},
		{"SessionStart.json", event.TypeSessionStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.model", e.Session.Model, "claude-opus-5")
			eq(t, "label session_source", e.Labels["session_source"], "resume")
		}},
		{"SessionEnd.json", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "other")
		}},
		{"Stop.json", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "I've completed the refactoring. Here's a summary...")
			if e.Outcome != nil {
				t.Errorf("Stop must not invent an outcome: %+v", e.Outcome)
			}
		}},
		{"StopFailure.json", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "rate_limit"})
		}},
		{"SubagentStart.json", event.TypeSubagentStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.subagent_id", e.Session.SubagentID, "agent-abc123")
			eq(t, "session.subagent_type", e.Session.SubagentType, "Explore")
		}},
		{"SubagentStop.json", event.TypeSubagentStop, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.subagent_id", e.Session.SubagentID, "def456")
			eq(t, "content.tool_output", e.Content.ToolOutput, "Analysis complete. Found 3 potential issues...")
		}},
		{"ConfigChange.json", event.TypeConfigChange, true, func(t *testing.T, e *event.Event) {
			eq(t, "label config_source", e.Labels["config_source"], "project_settings")
			eq(t, "target.path", target(e).Path, "/Users/.../my-project/.claude/settings.json")
		}},
		{"InstructionsLoaded.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "target.path", target(e).Path, "/Users/my-project/CLAUDE.md")
			eq(t, "label memory_type", e.Labels["memory_type"], "Project")
			eq(t, "label load_reason", e.Labels["load_reason"], "session_start")
		}},
		{"Notification.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "label notification_type", e.Labels["notification_type"], "permission_prompt")
		}},
		{"PreCompact.json", event.TypeCompact, false, func(t *testing.T, e *event.Event) {
			eq(t, "label compact_phase", e.Labels["compact_phase"], "pre")
			eq(t, "label compact_trigger", e.Labels["compact_trigger"], "manual")
		}},
		{"PostCompact.json", event.TypeCompact, false, func(t *testing.T, e *event.Event) {
			eq(t, "label compact_phase", e.Labels["compact_phase"], "post")
		}},
		{"Elicitation.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool", tool(e), event.Tool{Kind: event.ToolMCP, MCPServer: "my-mcp-server"})
			eq(t, "label elicitation_mode", e.Labels["elicitation_mode"], "form")
		}},
		{"Elicitation_2.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "label elicitation_mode", e.Labels["elicitation_mode"], "url")
			eq(t, "target.url", target(e).URL, "https://auth.example.com/login")
			eq(t, "target.host", target(e).Host, "auth.example.com")
		}},
		{"ElicitationResult.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "label elicitation_action", e.Labels["elicitation_action"], "accept")
		}},
		{"CwdChanged.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.cwd", e.Session.CWD, "/Users/my-project/src")
		}},
		{"FileChanged.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "target.path", target(e).Path, "/Users/my-project/.envrc")
			eq(t, "label file_event", e.Labels["file_event"], "change")
		}},
		{"DirectoryAdded.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "target.path", target(e).Path, "/Users/my-other-repo")
		}},
		{"PreModelSwitch.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.model", e.Session.Model, "claude-opus-5")
			eq(t, "label model_from", e.Labels["model_from"], "claude-sonnet-5")
		}},
		{"MessageDisplay.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.turn_id", e.Session.TurnID, "0c9e6a2f-7d41-4f4e-9a15-3f4f7c2b8d10")
		}},
		{"Setup.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "label setup_trigger", e.Labels["setup_trigger"], "init")
		}},
		{"TaskCreated.json", event.TypeNotification, false, nil},
		{"TaskCompleted.json", event.TypeNotification, false, nil},
		{"TeammateIdle.json", event.TypeNotification, false, nil},
		{"WorktreeCreate.json", event.TypeNotification, false, nil},
		{"WorktreeRemove.json", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "target.path", target(e).Path, "/Users/.../my-project/.claude/worktrees/feature-auth")
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.file] = true
		t.Run(tc.file, func(t *testing.T) {
			e, req := parseOne(t, d, fixture(t, "claude/"+tc.file), nil)
			eq(t, "type", e.Type, tc.typ)
			eq(t, "blocking", req.Blocking, tc.blocking)
			wantName := strings.TrimSuffix(strings.Split(tc.file, "_")[0], ".json")
			eq(t, "request event", req.EventName, wantName)
			eq(t, "label hook_event", e.Labels["hook_event"], wantName)
			if _, unmapped := e.Labels["hook_unmapped"]; unmapped {
				t.Error("documented event flagged as unmapped")
			}
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
	// Every fixture must be exercised, so a new doc example cannot be added
	// without an expectation.
	all, _ := filepath.Glob("testdata/claude/*.json")
	for _, f := range all {
		if base := filepath.Base(f); !seen[base] && base != "PostToolBatch.json" {
			t.Errorf("fixture %s has no test case", base)
		}
	}
}

// The example quoted verbatim in research/agent-surfaces-a.md (section 2).
func TestClaudeReportExample(t *testing.T) {
	const in = `{"session_id":"abc123","prompt_id":"550e8400-...","transcript_path":"/home/user/.claude/projects/.../transcript.jsonl",
 "cwd":"/home/user/my-project","permission_mode":"default","hook_event_name":"PreToolUse",
 "tool_name":"Bash","tool_input":{"command":"npm test","description":"Run test suite","timeout":120000,"run_in_background":false},
 "tool_use_id":"toolu_01ABC123..."}`
	e, req := parseOne(t, dialect(t, "claude"), []byte(in), nil)
	eq(t, "type", e.Type, event.TypeToolPre)
	eq(t, "session", *e.Session, event.Session{
		ID: "abc123", TurnID: "550e8400-...", CWD: "/home/user/my-project",
		PermissionMode: "default", Transcript: "/home/user/.claude/projects/.../transcript.jsonl",
	})
	eq(t, "tool.name", e.Tool.Name, "Bash")
	eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
	eq(t, "tool.use_id", e.Tool.UseID, "toolu_01ABC123...")
	eq(t, "target", target(e), event.Target{Command: "npm test"})
	eq(t, "request", *req, Request{AgentID: "claude-code", EventName: "PreToolUse", Blocking: true, Raw: req.Raw})
	// What would be written to the wire before redaction: no content
	// fields, no prompt text, one line.
	line, _ := e.MarshalLine()
	for _, banned := range []string{`"input":`, `"output":`, `"text":`, "Run test suite"} {
		if strings.Contains(string(line), banned) {
			t.Errorf("serialized event contains %s: %s", banned, line)
		}
	}
}

func TestClaudePostToolBatchExpands(t *testing.T) {
	d := dialect(t, "claude")
	evs, req, err := d.Parse(fixture(t, "claude/PostToolBatch.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events, want one per tool call (2)", len(evs))
	}
	wantPaths := []string{"/.../ledger/accounts.py", "/.../ledger/transactions.py"}
	wantIDs := []string{"toolu_01...", "toolu_02..."}
	for i, e := range evs {
		checkInvariants(t, d, e, req)
		eq(t, "type", e.Type, event.TypeToolPost)
		eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
		eq(t, "tool.use_id", e.Tool.UseID, wantIDs[i])
		eq(t, "target.path", target(e).Path, wantPaths[i])
		eq(t, "outcome.status", outcome(e).Status, "unknown")
		eq(t, "session.id", e.Session.ID, "abc123")
		if !strings.HasPrefix(e.Content.ToolOutput, "1\tfrom __future__") {
			t.Errorf("output = %q", e.Content.ToolOutput)
		}
	}
	if evs[0].ID == evs[1].ID {
		t.Error("batch events share an id")
	}
	if len(evs[0].Content.Raw) == 0 || len(evs[1].Content.Raw) != 0 {
		t.Error("raw payload must be kept once, on the first event")
	}
	if req.Blocking {
		t.Error("PostToolBatch must not be blocking")
	}
}

func TestClaudeBatchIsBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"hook_event_name":"PostToolBatch","session_id":"s","tool_calls":[`)
	for i := 0; i < maxBatch+50; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"tool_name":"Read","tool_input":{"file_path":"/a"},"tool_use_id":"t"}`)
	}
	sb.WriteString(`]}`)
	evs, _, err := dialect(t, "claude").Parse([]byte(sb.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != maxBatch {
		t.Fatalf("got %d events, want cap %d", len(evs), maxBatch)
	}
	eq(t, "truncated", evs[0].Truncated, []string{"tool_calls"})
}

func TestClaudeToolKinds(t *testing.T) {
	d := dialect(t, "claude")
	cases := []struct {
		tool, input string
		kind        event.ToolKind
		want        event.Target
	}{
		{"Bash", `{"command":"ls -la"}`, event.ToolShell, event.Target{Command: "ls -la"}},
		{"PowerShell", `{"command":"Get-ChildItem -Recurse"}`, event.ToolShell, event.Target{Command: "Get-ChildItem -Recurse"}},
		{"Read", `{"file_path":"/etc/passwd","offset":10}`, event.ToolFileRead, event.Target{Path: "/etc/passwd"}},
		{"Write", `{"file_path":"C:\\project\\src\\index.ts","content":"x"}`, event.ToolFileWrite, event.Target{Path: `C:\project\src\index.ts`}},
		{"Edit", `{"file_path":"/a/b","old_string":"a","new_string":"b"}`, event.ToolFileEdit, event.Target{Path: "/a/b"}},
		{"Glob", `{"pattern":"**/*.ts","path":"/src"}`, event.ToolFileList, event.Target{Path: "/src"}},
		{"Grep", `{"pattern":"TODO","path":"/src","glob":"*.ts"}`, event.ToolFileList, event.Target{Path: "/src"}},
		// Userinfo is dropped at the source; query and fragment are the
		// redaction stage's call.
		{"WebFetch", `{"url":"https://user:pw@Example.COM:8443/api?k=v#f","prompt":"x"}`, event.ToolWebFetch,
			event.Target{URL: "https://Example.COM:8443/api?k=v#f", Host: "example.com"}},
		{"WebSearch", `{"query":"react hooks best practices"}`, event.ToolWebSearch, event.Target{Query: "react hooks best practices"}},
		{"Agent", `{"prompt":"Find all API endpoints","subagent_type":"Explore"}`, event.ToolSubagent, event.Target{}},
		{"mcp__github__search_repositories", `{"query":"spoor"}`, event.ToolMCP, event.Target{}},
		{"mcp__fetch__fetch", `{"url":"https://example.org/x"}`, event.ToolMCP, event.Target{URL: "https://example.org/x", Host: "example.org"}},
		{"mcp__shell__run", `{"command":"id"}`, event.ToolMCP, event.Target{Command: "id"}},
		{"mcp__filesystem__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, event.ToolMCP, event.Target{Path: "/home/u/.ssh/id_rsa"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			in := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"` + tc.tool + `","tool_input":` + tc.input + `}`
			e, _ := parseOne(t, d, []byte(in), nil)
			eq(t, "kind", e.Tool.Kind, tc.kind)
			eq(t, "target", target(e), tc.want)
		})
	}
	// Edit content is exposed for local scanning.
	e, _ := parseOne(t, d, []byte(`{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/a","old_string":"a","new_string":"AKIA..."}}`), nil)
	eq(t, "file content", e.Content.FileContent, "AKIA...")
}

func TestClaudeEnvFallbacks(t *testing.T) {
	d := dialect(t, "claude")
	env := map[string]string{
		"CLAUDE_CODE_SESSION_ID": "env-session",
		"CLAUDE_PROJECT_DIR":     "/home/u/proj",
		"CLAUDE_CODE_REMOTE":     "true",
	}
	// No session_id or cwd in the payload: both come from the environment.
	e, _ := parseOne(t, d, []byte(`{"hook_event_name":"Stop"}`), env)
	eq(t, "session.id", e.Session.ID, "env-session")
	eq(t, "session.cwd", e.Session.CWD, "/home/u/proj")
	eq(t, "agent.surface", e.Agent.Surface, "cloud")
	if _, has := e.Labels["project_dir"]; has {
		t.Error("project_dir label is redundant when it became the cwd")
	}
	// The payload wins; the differing project dir is kept as a label.
	e, _ = parseOne(t, d, []byte(`{"hook_event_name":"Stop","session_id":"p","cwd":"/home/u/proj/sub"}`), env)
	eq(t, "session.id", e.Session.ID, "p")
	eq(t, "session.cwd", e.Session.CWD, "/home/u/proj/sub")
	eq(t, "label project_dir", e.Labels["project_dir"], "/home/u/proj")
	// The event name can come from the environment too.
	e, req := parseOne(t, d, []byte(`{"session_id":"p","tool_name":"Bash","tool_input":{"command":"id"}}`),
		map[string]string{EnvHookEvent: "PreToolUse"})
	eq(t, "type", e.Type, event.TypeToolPre)
	eq(t, "blocking", req.Blocking, true)

	for entry, want := range map[string]string{"cli": "cli", "sdk-ts": "sdk", "claude-vscode": "ide", "claude-desktop": "desktop", "weird": ""} {
		e, _ := parseOne(t, d, []byte(`{"hook_event_name":"Stop"}`), map[string]string{"CLAUDE_CODE_ENTRYPOINT": entry})
		eq(t, "surface for "+entry, e.Agent.Surface, want)
	}
}

func TestClaudeConfigChangePolicyNotBlocking(t *testing.T) {
	// Claude Code ignores a block for managed policy files.
	_, req := parseOne(t, dialect(t, "claude"),
		[]byte(`{"hook_event_name":"ConfigChange","source":"policy_settings","file_path":"/etc/claude-code/managed-settings.json"}`), nil)
	if req.Blocking {
		t.Error("policy_settings change must not be blocking")
	}
}

func TestPermissionModeVocabulary(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"default":           "default",
		"manual":            "default",
		"plan":              "plan",
		"acceptEdits":       "accept_edits",
		"auto":              "auto",
		"dontAsk":           "dont_ask",
		"bypassPermissions": "bypass",
		"someNewMode":       "some_new_mode",
		"weird mode\n":      "weird_mode_",
	} {
		eq(t, "permMode("+in+")", permMode(in), want)
	}
}

func TestUnknownEventIsKeptAsNotification(t *testing.T) {
	for _, id := range []string{"claude", "codex", "copilot", "gemini", "cursor"} {
		e, req := parseOne(t, dialect(t, id), []byte(`{"hook_event_name":"BrandNewEvent2027","session_id":"s","sessionId":"s"}`), nil)
		eq(t, id+" type", e.Type, event.TypeNotification)
		eq(t, id+" unmapped", e.Labels["hook_unmapped"], "1")
		eq(t, id+" hook_event", e.Labels["hook_event"], "BrandNewEvent2027")
		eq(t, id+" blocking", req.Blocking, false)
	}
}

func TestNoEventName(t *testing.T) {
	for _, id := range []string{"claude", "codex", "gemini", "cursor"} {
		evs, req, err := dialect(t, id).Parse([]byte(`{"session_id":"s"}`), nil)
		if err != ErrNoEvent || evs != nil {
			t.Errorf("%s: got %v events, err %v; want ErrNoEvent", id, len(evs), err)
		}
		if req == nil || req.Blocking {
			t.Errorf("%s: request must be returned and not blocking: %+v", id, req)
		}
	}
}
