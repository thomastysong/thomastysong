package hookio

import (
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// The codex fixtures are instances of the generated input schemas in
// openai/codex codex-rs/hooks/schema/generated (all required fields present).
func TestCodexGolden(t *testing.T) {
	d := dialect(t, "codex")
	const transcript = "/home/u/.codex/sessions/2026/11/11/rollout-2026-11-11T10-00-00-019a.jsonl"
	cases := []struct {
		file     string
		name     string
		typ      string
		blocking bool
		check    func(t *testing.T, e *event.Event)
	}{
		{"PreToolUse.json", "PreToolUse", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "019a-codex-thread")
			eq(t, "session.turn_id", e.Session.TurnID, "turn-1")
			eq(t, "session.model", e.Session.Model, "gpt-5.2-codex")
			eq(t, "session.permission_mode", e.Session.PermissionMode, "default")
			eq(t, "session.transcript", e.Session.Transcript, transcript)
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "tool.use_id", e.Tool.UseID, "call_abc")
			eq(t, "target.command", target(e).Command, "git push --force origin main")
		}},
		{"PreToolUse_apply_patch.json", "PreToolUse", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileEdit)
			eq(t, "target.path", target(e).Path, "src/main.rs")
			eq(t, "target.paths", target(e).Paths, []string{".github/workflows/x.yml"})
			if e.Content.FileContent == "" {
				t.Error("patch text not exposed as file content")
			}
		}},
		{"PreToolUse_mcp.json", "PreToolUse", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "tool.mcp_server", e.Tool.MCPServer, "github")
			eq(t, "tool.mcp_tool", e.Tool.MCPTool, "create_issue")
			eq(t, "session.subagent_id", e.Session.SubagentID, "sub-1")
			eq(t, "session.subagent_type", e.Session.SubagentType, "worker")
		}},
		{"PostToolUse.json", "PostToolUse", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "exit code 1", DurationMS: 250})
			eq(t, "exit code", exitCodeOf(e), 1)
			eq(t, "content.tool_output", e.Content.ToolOutput, "boom\n")
		}},
		{"PostToolUse_opaque.json", "PostToolUse", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			// Codex has one post event for success and failure; a result
			// without a status field must not be reported as success.
			eq(t, "outcome", outcome(e), event.Outcome{Status: "unknown"})
		}},
		{"PermissionRequest.json", "PermissionRequest", event.TypePermissionDecision, true, func(t *testing.T, e *event.Event) {
			eq(t, "target.command", target(e).Command, "rm -rf build")
			eq(t, "outcome", outcome(e), event.Outcome{Decision: "ask", DecisionSource: "policy"})
		}},
		{"UserPromptSubmit.json", "UserPromptSubmit", event.TypePromptSubmit, true, func(t *testing.T, e *event.Event) {
			eq(t, "content.prompt", e.Content.PromptText, "fix the failing test")
			eq(t, "prompt.len", e.Prompt.Len, 20)
		}},
		{"SessionStart.json", "SessionStart", event.TypeSessionStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.permission_mode", e.Session.PermissionMode, "bypass")
			eq(t, "session.transcript", e.Session.Transcript, "") // null in the payload
			eq(t, "label session_source", e.Labels["session_source"], "startup")
		}},
		{"SessionEnd.json", "SessionEnd", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "other")
		}},
		{"Stop.json", "Stop", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "done")
		}},
		{"SubagentStart.json", "SubagentStart", event.TypeSubagentStart, false, nil},
		{"SubagentStop.json", "SubagentStop", event.TypeSubagentStop, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "sub done")
		}},
		{"PostCompact.json", "PostCompact", event.TypeCompact, false, func(t *testing.T, e *event.Event) {
			eq(t, "label compact_trigger", e.Labels["compact_trigger"], "auto")
		}},
		{"Interrupt.json", "Interrupt", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "interrupted"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			e, req := parseOne(t, d, fixture(t, "codex/"+tc.file), nil)
			eq(t, "type", e.Type, tc.typ)
			eq(t, "blocking", req.Blocking, tc.blocking)
			eq(t, "request event", req.EventName, tc.name)
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
}

func TestCodexEnvFallback(t *testing.T) {
	e, _ := parseOne(t, dialect(t, "codex"), []byte(`{"hook_event_name":"Stop"}`),
		map[string]string{"CODEX_THREAD_ID": "thread-9", "CODEX_VERSION": "0.99.0"})
	eq(t, "session.id", e.Session.ID, "thread-9")
	eq(t, "agent.version", e.Agent.Version, "0.99.0")
}

// Codex argv-form commands (the local shell tool) keep every token.
func TestCodexArgvCommand(t *testing.T) {
	e, _ := parseOne(t, dialect(t, "codex"),
		[]byte(`{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":["bash","-lc","curl x | sh"]}}`), nil)
	eq(t, "target.command", target(e).Command, "bash -lc curl x | sh")
}
