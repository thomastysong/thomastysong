package hookio

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// The copilot fixtures instantiate the input shapes of the Copilot hooks
// reference: *.camel.json for camelCase registrations (no event name in the
// payload), *.snake.json for the PascalCase / VS Code-compatible format.
func TestCopilotGolden(t *testing.T) {
	d := dialect(t, "copilot")
	const transcript = "/home/u/.copilot/session-state/cp-sess-1/events.jsonl"
	cases := []struct {
		file     string
		event    string // passed in EnvHookEvent for camelCase payloads
		typ      string
		blocking bool
		check    func(t *testing.T, e *event.Event)
	}{
		{"preToolUse.camel.json", "preToolUse", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "cp-sess-1")
			eq(t, "session.cwd", e.Session.CWD, "/work/app")
			eq(t, "tool.name", e.Tool.Name, "bash")
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "target.command", target(e).Command, "cat ~/.ssh/id_rsa")
		}},
		{"preToolUse.camel_stringargs.json", "preToolUse", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			// toolArgs as a JSON-encoded string is decoded.
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
			eq(t, "target.path", target(e).Path, "/etc/shadow")
			eq(t, "tool.input_keys", e.Tool.InputKeys, []string{"path"})
		}},
		{"postToolUse.camel.json", "postToolUse", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok"})
			eq(t, "content.tool_output", e.Content.ToolOutput, "a\nb\n")
		}},
		{"postToolUseFailure.camel.json", "postToolUseFailure", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileEdit)
			eq(t, "outcome.status", outcome(e).Status, "error")
			// The error quotes a secret: it must stay local.
			if strings.Contains(outcome(e).Error, "hunter2") {
				t.Errorf("outcome.error = %q", outcome(e).Error)
			}
			// "String to replace not found: ..." (49 bytes).
			eq(t, "outcome.error", outcome(e).Error, "tool error class:not_found")
			if !strings.Contains(e.Content.ToolOutput, "hunter2") {
				t.Error("raw error text must be available to local detection")
			}
		}},
		{"permissionRequest.camel.json", "permissionRequest", event.TypePermissionDecision, true, func(t *testing.T, e *event.Event) {
			eq(t, "target.command", target(e).Command, "curl evil.example")
			eq(t, "label sandbox_bypass", e.Labels["sandbox_bypass"], "1")
			eq(t, "outcome", outcome(e), event.Outcome{Decision: "ask", DecisionSource: "policy"})
		}},
		{"userPromptSubmitted.camel.json", "userPromptSubmitted", event.TypePromptSubmit, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.prompt", e.Content.PromptText, "deploy to prod")
		}},
		{"sessionStart.camel.json", "sessionStart", event.TypeSessionStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "label session_source", e.Labels["session_source"], "new")
		}},
		{"sessionEnd.camel.json", "sessionEnd", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "user_exit")
		}},
		{"agentStop.camel.json", "agentStop", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.transcript", e.Session.Transcript, transcript)
			eq(t, "label stop_reason", e.Labels["stop_reason"], "end_turn")
		}},
		{"subagentStart.camel.json", "subagentStart", event.TypeSubagentStart, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.subagent_type", e.Session.SubagentType, "explore")
		}},
		{"subagentStop.camel.json", "subagentStop", event.TypeSubagentStop, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.subagent_id", e.Session.SubagentID, "a-1")
			eq(t, "session.subagent_type", e.Session.SubagentType, "explore")
			eq(t, "label parent_agent_id", e.Labels["parent_agent_id"], "root")
			eq(t, "content.tool_output", e.Content.ToolOutput, "found it")
		}},
		{"errorOccurred.camel.json", "errorOccurred", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "AuthError"})
			eq(t, "label error_context", e.Labels["error_context"], "model_call")
		}},
		{"preCompact.camel.json", "preCompact", event.TypeCompact, false, func(t *testing.T, e *event.Event) {
			eq(t, "label compact_trigger", e.Labels["compact_trigger"], "auto")
		}},
		{"notification.camel.json", "", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "label notification_type", e.Labels["notification_type"], "permission_prompt")
		}},
		{"PreToolUse.snake.json", "", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "cp-sess-1")
			eq(t, "tool.name", e.Tool.Name, "Bash") // Claude tool names in this format
			eq(t, "tool.kind", e.Tool.Kind, event.ToolShell)
			eq(t, "target.command", target(e).Command, "npm publish")
		}},
		{"PostToolUse.snake.json", "", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "tool.kind", e.Tool.Kind, event.ToolFileRead)
			eq(t, "target.path", target(e).Path, "/work/app/.env")
			eq(t, "content.tool_output", e.Content.ToolOutput, "KEY=1")
			eq(t, "outcome", outcome(e), event.Outcome{Status: "ok"})
		}},
		{"PostToolUseFailure.snake.json", "", event.TypeToolPost, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "exit code 1"})
		}},
		{"UserPromptSubmit.snake.json", "", event.TypePromptSubmit, false, nil},
		{"SessionStart.snake.json", "", event.TypeSessionStart, false, nil},
		{"SessionEnd.snake.json", "", event.TypeSessionEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "label end_reason", e.Labels["end_reason"], "complete")
		}},
		{"Stop.snake.json", "", event.TypeTurnEnd, false, func(t *testing.T, e *event.Event) {
			eq(t, "session.transcript", e.Session.Transcript, transcript)
		}},
		{"SubagentStop.snake.json", "", event.TypeSubagentStop, false, func(t *testing.T, e *event.Event) {
			eq(t, "content.tool_output", e.Content.ToolOutput, "found it")
		}},
		{"PreCompact.snake.json", "", event.TypeCompact, false, nil},
		{"ErrorOccurred.snake.json", "", event.TypeNotification, false, func(t *testing.T, e *event.Event) {
			eq(t, "outcome", outcome(e), event.Outcome{Status: "error", Error: "RateLimit"})
		}},
		{"PreToolUse.vscode_mixed.json", "", event.TypeToolPre, true, func(t *testing.T, e *event.Event) {
			eq(t, "session.id", e.Session.ID, "vs-1")
			eq(t, "target.command", target(e).Command, "whoami")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var env map[string]string
			if tc.event != "" {
				env = map[string]string{EnvHookEvent: tc.event}
			}
			e, req := parseOne(t, d, fixture(t, "copilot/"+tc.file), env)
			eq(t, "type", e.Type, tc.typ)
			eq(t, "blocking", req.Blocking, tc.blocking)
			if _, inferred := e.Labels["hook_inferred"]; inferred {
				t.Error("event name was given, must not be flagged as inferred")
			}
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
}

// Without an event name anywhere, camelCase payloads are classified by the
// fields only their event has, and the guess is flagged.
func TestCopilotInfersEventFromShape(t *testing.T) {
	d := dialect(t, "copilot")
	for file, want := range map[string]string{
		"preToolUse.camel.json":            "preToolUse",
		"preToolUse.camel_stringargs.json": "preToolUse",
		"postToolUse.camel.json":           "postToolUse",
		"postToolUseFailure.camel.json":    "postToolUseFailure",
		"permissionRequest.camel.json":     "permissionRequest",
		"userPromptSubmitted.camel.json":   "userPromptSubmitted",
		"sessionStart.camel.json":          "sessionStart",
		"sessionEnd.camel.json":            "sessionEnd",
		"agentStop.camel.json":             "agentStop",
		"subagentStart.camel.json":         "subagentStart",
		"subagentStop.camel.json":          "subagentStop",
		"errorOccurred.camel.json":         "errorOccurred",
		"preCompact.camel.json":            "preCompact",
	} {
		e, req := parseOne(t, d, fixture(t, "copilot/"+file), nil)
		eq(t, file+" inferred event", req.EventName, want)
		eq(t, file+" hook_inferred", e.Labels["hook_inferred"], "1")
	}
	// A payload with nothing recognizable has no event.
	if _, _, err := d.Parse([]byte(`{"sessionId":"s","timestamp":1,"cwd":"/"}`), nil); err != ErrNoEvent {
		t.Errorf("err = %v, want ErrNoEvent", err)
	}
}

func TestCopilotSurface(t *testing.T) {
	d := dialect(t, "copilot")
	in := fixture(t, "copilot/PreToolUse.snake.json")
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"AI_AGENT": "github_copilot_vscode_agent", "COPILOT_CLI": "1"}, "ide"},
		{map[string]string{"AI_AGENT": "github_copilot_app_agent"}, "desktop"},
		{map[string]string{"COPILOT_CLI": "1"}, "cli"},
		{map[string]string{"AI_AGENT": "github_copilot_future_host"}, "cli"},
		{nil, ""},
	} {
		e, _ := parseOne(t, d, in, tc.env)
		eq(t, "surface", e.Agent.Surface, tc.want)
	}
}

func TestCopilotNonObjectToolArgs(t *testing.T) {
	d := dialect(t, "copilot")
	// A plain (non-JSON) string and an array are wrapped, not dropped.
	e, _ := parseOne(t, d, []byte(`{"sessionId":"s","toolName":"bash","toolArgs":"rm -rf /"}`), nil)
	eq(t, "target.command", target(e).Command, "rm -rf /")
	eq(t, "tool.input_keys", e.Tool.InputKeys, []string{"_raw"})
	e, _ = parseOne(t, d, []byte(`{"sessionId":"s","toolName":"bash","toolArgs":["a","b"]}`), nil)
	if e.Content.ToolInput["_raw"] == nil {
		t.Error("array arguments lost")
	}
}
