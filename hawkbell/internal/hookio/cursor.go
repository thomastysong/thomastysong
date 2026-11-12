package hookio

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// cursor implements Cursor's hooks.json wire.
//
// Cursor's vendor documentation was unreachable when this was written, so
// the facts below come from code that talks to Cursor in production and from
// a typed mirror of the documented schema:
//
//   - event names: snyk/agent-scan guard.py (Apache-2.0);
//   - common fields conversation_id, generation_id, hook_event_name,
//     workspace_roots and the before*/afterFileEdit/stop payloads and replies:
//     johnlindquist/cursor-hooks src/types.ts;
//   - cursor_version in every payload, CURSOR_VERSION in the hook
//     environment, and the reply {"permission":"deny","agent_message":...} on
//     exit 0: 1Password/agent-hooks adapters/{_lib,cursor}.sh;
//   - session key conversation_id, project key workspace_roots:
//     snyk/agent-scan hook_events.py.
//
// Everything else (the generic preToolUse/postToolUse payloads, subagent and
// session payloads, user_message) is marked UNVERIFIED where it is used and
// is parsed defensively: unknown or missing fields only lose detail.
type cursor struct{}

func (cursor) id() string      { return "cursor" }
func (cursor) agentID() string { return AgentCursor }

var cursorTypes = map[string]string{
	"sessionStart":         event.TypeSessionStart,
	"sessionEnd":           event.TypeSessionEnd,
	"beforeSubmitPrompt":   event.TypePromptSubmit,
	"preToolUse":           event.TypeToolPre,
	"postToolUse":          event.TypeToolPost,
	"postToolUseFailure":   event.TypeToolPost,
	"beforeShellExecution": event.TypeToolPre,
	"afterShellExecution":  event.TypeToolPost,
	"beforeMCPExecution":   event.TypeToolPre,
	"afterMCPExecution":    event.TypeToolPost,
	"beforeReadFile":       event.TypeToolPre,
	"afterFileEdit":        event.TypeToolPost,
	"subagentStart":        event.TypeSubagentStart,
	"subagentStop":         event.TypeSubagentStop,
	"stop":                 event.TypeTurnEnd,
	"afterAgentResponse":   event.TypeNotification,
	"afterAgentThought":    event.TypeNotification,
	// UNVERIFIED: later additions recalled from the vendor docs.
	"preCompact":        event.TypeCompact,
	"beforeTabFileRead": event.TypeToolPre,
	"afterTabFileEdit":  event.TypeToolPost,
}

func (c cursor) build(p obj, env map[string]string, raw []byte) ([]*event.Event, *Request, error) {
	name := p.str("hook_event_name")
	if name == "" {
		name = envGet(env, EnvHookEvent)
	}
	name, _ = cleanID(name, 64)
	req := &Request{AgentID: AgentCursor, EventName: name, Raw: p}
	if name == "" {
		return nil, req, ErrNoEvent
	}
	typ, known := cursorTypes[name]
	ev := newEvent(AgentCursor, typ, name, raw)
	if !known {
		unknownEvent(ev)
	}

	s := sessionFields{
		id:           p.str("conversation_id", "session_id"),
		turnID:       p.str("generation_id"),
		cwd:          p.str("cwd"),
		transcript:   p.str("transcript_path"),
		model:        p.str("model"),
		agentVersion: p.str("cursor_version"),
		// UNVERIFIED: CURSOR_PROJECT_DIR in the hook environment (from
		// search results only). CLAUDE_PROJECT_DIR is also set, as a
		// compatibility alias (1Password/agent-hooks adapters/_lib.sh), but
		// is not read here because it is ambiguous inside nested agents.
		projectDir: envGet(env, "CURSOR_PROJECT_DIR"),
	}
	if s.agentVersion == "" {
		s.agentVersion = envGet(env, "CURSOR_VERSION")
	}
	if s.cwd == "" {
		// Most Cursor hooks have no cwd; the first workspace root is the
		// project the conversation belongs to.
		if roots := p.arr("workspace_roots"); len(roots) > 0 {
			if r, ok := roots[0].(string); ok {
				s.cwd = r
			}
		}
	}
	applySession(ev, s)

	switch name {
	case "sessionEnd":
		enumLabel(ev, "end_reason", p.str("reason"))
	case "beforeSubmitPrompt":
		setPrompt(ev, p.str("prompt"))
		req.Blocking = true

	case "preToolUse":
		// UNVERIFIED: tool_name, tool_input, tool_use_id.
		c.genericTool(ev, p)
		req.Blocking = true
	case "postToolUse":
		c.genericTool(ev, p)
		if resp, has := p.raw("tool_output", "tool_response", "output"); has {
			setOutput(ev, resp)
		}
		ev.Outcome = &event.Outcome{Status: "ok", DurationMS: durationMS(p, "duration", "duration_ms")}
	case "postToolUseFailure":
		c.genericTool(ev, p)
		interrupted, _ := p.boolean("is_interrupt")
		ev.Outcome = failure(ev, p.str("error_message", "error"), interrupted)
		ev.Outcome.DurationMS = durationMS(p, "duration", "duration_ms")
		// UNVERIFIED: failure_type is timeout | error | permission_denied.
		ft := p.str("failure_type")
		enumLabel(ev, "failure_type", ft)
		if ft == "permission_denied" {
			ev.Outcome.Status = "denied"
		}

	case "beforeShellExecution", "afterShellExecution":
		// The hook names the action, so the tool is a shell whatever the
		// payload calls it. These hooks carry the arguments as flat
		// top-level fields; they are gathered into a tool input object.
		c.specificTool(ev, "Shell", event.ToolShell, pick(p, "command", "cwd"))
		if name == "beforeShellExecution" {
			req.Blocking = true
			break
		}
		setOutput(ev, p["output"])
		// The payload reports no exit status.
		ev.Outcome = &event.Outcome{Status: "unknown", DurationMS: durationMS(p, "duration", "duration_ms")}

	case "beforeMCPExecution", "afterMCPExecution":
		c.mcpTool(ev, p)
		if name == "beforeMCPExecution" {
			req.Blocking = true
			break
		}
		setOutput(ev, p["result_json"])
		ev.Outcome = &event.Outcome{Status: "unknown", DurationMS: durationMS(p, "duration", "duration_ms")}

	case "beforeReadFile", "beforeTabFileRead":
		c.specificTool(ev, "Read", event.ToolFileRead, pick(p, "file_path"))
		// Cursor hands the hook the content it is about to send to the
		// model, so local detection can scan what is being read.
		ev.Content.FileContent = p.str("content")
		req.Blocking = true

	case "afterFileEdit", "afterTabFileEdit":
		c.specificTool(ev, "Edit", event.ToolFileEdit, pick(p, "file_path", "edits"))
		ev.Outcome = &event.Outcome{Status: "ok"}

	case "subagentStart":
		// UNVERIFIED: subagent_type.
		if st := p.str("subagent_type"); st != "" {
			ev.Session.SubagentType = field(ev, "session.subagent_type", st, maxName)
		}
	case "subagentStop":
		if st := p.str("subagent_type"); st != "" {
			ev.Session.SubagentType = field(ev, "session.subagent_type", st, maxName)
		}
		ev.Content.ToolOutput = p.str("result")
	case "stop":
		// status: completed | aborted | error.
		st := p.str("status")
		enumLabel(ev, "stop_status", st)
		switch st {
		case "completed":
			ev.Outcome = &event.Outcome{Status: "ok"}
		case "aborted":
			ev.Outcome = &event.Outcome{Status: "interrupted"}
		case "error":
			ev.Outcome = &event.Outcome{Status: "error"}
		}
	case "afterAgentResponse", "afterAgentThought":
		ev.Content.ToolOutput = p.str("text")
	case "preCompact":
		label(ev, "compact_phase", "pre")
		enumLabel(ev, "compact_trigger", p.str("trigger"))
	}
	return []*event.Event{ev}, req, nil
}

// pick copies the named top-level fields into a fresh argument object.
func pick(p obj, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := p[k]; ok && v != nil {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// genericTool handles preToolUse / postToolUse / postToolUseFailure, which
// fire for every tool. Cursor also fires the tool-specific hooks
// (beforeShellExecution ...) for the same call, so events are tagged with
// hook_scope to let a consumer keep one of the two.
func (cursor) genericTool(ev *event.Event, p obj) {
	args, _ := p.raw("tool_input")
	name := p.str("tool_name")
	setTool(ev, AgentCursor, name, args, p.str("tool_use_id"))
	// UNVERIFIED: MCP tools are reported as "MCP:<tool>" by the generic
	// hooks; recognized here because the shared table cannot know it.
	if rest, ok := cutPrefixFold(name, "mcp:"); ok && rest != "" {
		forceKind(ev, event.ToolMCP)
		ev.Tool.MCPTool, _ = cleanID(rest, maxName)
	}
	label(ev, "hook_scope", "generic")
}

// specificTool builds the tool for a hook whose name fixes the kind.
func (cursor) specificTool(ev *event.Event, name string, kind event.ToolKind, args map[string]any) {
	setTool(ev, AgentCursor, name, args, "")
	forceKind(ev, kind)
	label(ev, "hook_scope", "specific")
}

// mcpTool handles before/afterMCPExecution: tool_name, tool_input (an object
// or a JSON string) and the server's url or launch command.
func (c cursor) mcpTool(ev *event.Event, p obj) {
	args, _ := p.raw("tool_input")
	setTool(ev, AgentCursor, p.str("tool_name"), args, p.str("tool_use_id"))
	forceKind(ev, event.ToolMCP)
	if ev.Tool.MCPTool == "" {
		ev.Tool.MCPTool = ev.Tool.Name
	}
	// The payload identifies the server by where it runs, not by its config
	// name. A remote server's host is what a hunt needs. Only the host is
	// taken: the URL's query and a stdio server's launch command can embed
	// tokens, so those stay in Content.Raw.
	if h := hostOf(p.str("url")); h != "" && (ev.Target == nil || ev.Target.Host == "") {
		if ev.Target == nil {
			ev.Target = &event.Target{}
		}
		ev.Target.Host = h
	}
	label(ev, "hook_scope", "specific")
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// cursorReply covers Cursor's reply shapes. The permission hooks take
// permission + messages; beforeSubmitPrompt takes continue.
type cursorReply struct {
	Permission   string `json:"permission,omitempty"`
	Continue     *bool  `json:"continue,omitempty"`
	Decision     string `json:"decision,omitempty"`
	Reason       string `json:"reason,omitempty"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

func (cursor) respond(req *Request, d Decision) ([]byte, []byte, int) {
	if !req.Blocking {
		return proceed()
	}
	msg := reason(d)
	var out cursorReply
	switch req.EventName {
	case "beforeShellExecution", "beforeMCPExecution":
		// permission: allow | deny | ask.
		out.Permission = d.Action
		if d.Action != ActionAllow {
			out.UserMessage, out.AgentMessage = msg, msg
		}
	case "beforeReadFile", "beforeTabFileRead":
		// permission: allow | deny only; an ask has nowhere to go.
		if d.Action == ActionAsk {
			return proceed()
		}
		out.Permission = d.Action
		if d.Action == ActionDeny {
			out.UserMessage, out.AgentMessage = msg, msg
		}
	case "preToolUse":
		// UNVERIFIED: whether the generic hook reads "permission" (like the
		// before* hooks) or "decision"/"reason". For deny and allow both are
		// sent, so the verdict holds under either reading; "ask" is not a
		// documented decision value, so only "permission" carries it.
		out.Permission = d.Action
		if d.Action != ActionAsk {
			out.Decision = d.Action
		}
		if d.Action != ActionAllow {
			out.UserMessage, out.AgentMessage = msg, msg
			if d.Action == ActionDeny {
				out.Reason = msg
			}
		}
	case "beforeSubmitPrompt":
		// {"continue": false} stops the prompt. There is no ask.
		switch d.Action {
		case ActionDeny:
			stop := false
			out.Continue = &stop
			out.UserMessage = msg
		default:
			return proceed()
		}
	default:
		return proceed()
	}
	// Exit 0 with JSON, as the 1Password adapter does for a deny. Cursor
	// allows the action when a hook prints nothing, which is what "none"
	// relies on.
	return jsonLine(out), nil, 0
}

func (cursor) events() []HookEvent {
	// Cursor has no background-hook option. Both hook generations are
	// listed: the generic tool hooks cover every tool on current versions,
	// the specific ones are all that older versions have and add detail
	// (MCP server location, file content being read, the edits made).
	return []HookEvent{
		{Name: "sessionStart"},
		{Name: "beforeSubmitPrompt", Blocking: true},
		{Name: "preToolUse", Blocking: true},
		{Name: "postToolUse"},
		{Name: "postToolUseFailure"},
		{Name: "beforeShellExecution", Blocking: true},
		{Name: "afterShellExecution"},
		{Name: "beforeMCPExecution", Blocking: true},
		{Name: "afterMCPExecution"},
		{Name: "beforeReadFile", Blocking: true},
		{Name: "afterFileEdit"},
		{Name: "subagentStart"},
		{Name: "subagentStop"},
		{Name: "stop"},
		{Name: "sessionEnd"},
	}
}
