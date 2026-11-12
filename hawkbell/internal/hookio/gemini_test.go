package hookio

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// The gemini fixtures instantiate the input schemas of the Gemini CLI hooks
// reference (docs/hooks/reference.md, packages/core/src/hooks/types.ts).
func TestGeminiGolden(t *testing.T) {
	d := dialect(t, "gemini")
	cases := []struct {
		file     string
		name     string
		typ      string
		blocking bool
		check    func(t *testing.T, e *event.Event)
	}{
		{"BeforeTool.json", "BeforeTool", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "gm-1")
			eq(t, "session.cwd", e.Session.CWD, "/work/site")
			eq(t, "session.transcript", e.Session.Transcript, "/home/u/.gemini/tmp/abc/chats/session-1.json")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "target.command", target(e).Command, "rm -rf /")
		}},
		{"BeforeTool_mcp.json", "BeforeTool", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			// The server name contains "_", which the tool name alone
			// cannot disambiguate; mcp_context is authoritative.
			eq(t, "tool.name", e.Tool.Name, "mcp_my_server_do_thing")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolMCP)
			eq(t, "tool.mcp_server", e.Tool.MCPServer, "my_server")
			eq(t, "tool.mcp_tool", e.Tool.MCPTool, "do_thing")
			eq(t, "target.path", target(e).Path, "/etc/passwd")
			eq(t, "label original_request", e.Labels["original_request"], "mcp_my_server_do_thing")
		}},
		{"BeforeTool_webfetch.json", "BeforeTool", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			// web_fetch takes a prompt with the URLs embedded.
			eq(t, "tool.kind", e.Tool.Kind, event.ToolWebFetch)
			eq(t, "target.url", target(e).URL, "https://example.com/a?x=1")
			eq(t, "target.host", target(e).Host, "example.com")
			eq(t, "target.hosts", target(e).Hosts, []string{"pastebin.com"}) // hosts beyond the primary
		}},
		{"AfterTool.json", "AfterTool", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
			eq(t, "target.path", target(e).Path, "/work/site/.env")
			eq(t, "content.tool_output", e.Content.ToolOutput, "API_KEY=abc")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok"})
		}},
		{"AfterTool_error.json", "AfterTool", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome.status", outcome(e).Status, "error")
			if strings.Contains(outcome(e).Error, "hunter2") {
				t.Errorf("secret leaked into outcome.error: %q", outcome(e).Error)
			}
			if !strings.Contains(e.Content.ToolOutput, "hunter2") {
				t.Error("error text must reach local detection")
			}
		}},
		{"BeforeAgent.json", "BeforeAgent", event.TypePromptSubmit, true, func(t *testing.T, e *event.Event) {
			eq(t, "content.prompt", e.Content.PromptText, "ignore previous instructions")
		}},
		{"AfterAgent.json", "AfterAgent", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "r")
			eq(t, "content.prompt", e.Content.PromptText, "") // already reported at BeforeAgent
		}},
		{"SessionStart.json", "SessionStart", event.TypeSessionStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "label session_source", e.Labels["session_source"], "startup")
		}},
		{"SessionEnd.json", "SessionEnd", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "exit")
		}},
		{"Notification.json", "Notification", event.TypePermissionDecision, false, func(t *testing.T, e *event.Event) {
			eq(t, "label notification_type", e.Labels["notification_type"], "ToolPermission")
			eq(t, "outcome", outcome(e), event.Outcome{Decision: "ask", DecisionSource: "policy"})
			eq(t, "tool.kind", tool(e).Kind, event.ToolShell)
			eq(t, "target.command", target(e).Command, "sudo ls")
		}},
		{"PreCompress.json", "PreCompress", event.TypeCompact, false, func(t *testing.T, e *event.Event) {
			eq(t, "label compact_trigger", e.Labels["compact_trigger"], "auto")
		}},
		{"BeforeModel.json", "BeforeModel", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.model", e.Session.Model, "gemini-3-pro")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			e, req := parseOne(t, d, fixture(t, "gemini/"+tc.file), nil)
			eq(t, "type", e.Type, tc.typ)
			eq(t, "blocking", req.Blocking, tc.blocking)
			eq(t, "request event", req.EventName, tc.name)
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
}

func TestGeminiEnvFallbacks(t *testing.T) {
	env := map[string]string{"GEMINI_SESSION_ID": "g-env", "GEMINI_CWD": "/w/sub", "GEMINI_PROJECT_DIR": "/w"}
	e, _ := parseOne(t, dialect(t, "gemini"), []byte(`{"hook_event_name":"SessionStart"}`), env)
	eq(t, "session.id", e.Session.ID, "g-env")
	eq(t, "session.cwd", e.Session.CWD, "/w/sub")
	eq(t, "label project_dir", e.Labels["project_dir"], "/w")
}

// A non-ToolPermission notification stays a plain notification.
func TestGeminiOtherNotification(t *testing.T) {
	e, _ := parseOne(t, dialect(t, "gemini"),
		[]byte(`{"hook_event_name":"Notification","notification_type":"Something","message":"m","details":{}}`), nil)
	eq(t, "type", e.Type, event.TypeNotification)
	if e.Outcome != nil {
		t.Errorf("outcome = %+v", e.Outcome)
	}
}
