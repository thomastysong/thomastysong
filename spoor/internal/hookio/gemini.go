package hookio

import (
	"github.com/thomastysong/spoor/internal/event"
)

// gemini implements the Gemini CLI hook wire
// (google-gemini/gemini-cli docs/hooks/reference.md and
// packages/core/src/hooks/types.ts): every payload carries session_id,
// transcript_path, cwd, hook_event_name and an ISO 8601 timestamp; tool
// events add tool_name, tool_input and, for MCP tools, mcp_context.
type gemini struct{}

func (gemini) id() string      { return "gemini" }
func (gemini) agentID() string { return AgentGemini }

var geminiTypes = map[string]string{
	"SessionStart":        event.TypeSessionStart,
	"SessionEnd":          event.TypeSessionEnd,
	"BeforeAgent":         event.TypePromptSubmit,
	"AfterAgent":          event.TypeTurnEnd,
	"BeforeTool":          event.TypeToolPre,
	"AfterTool":           event.TypeToolPost,
	"PreCompress":         event.TypeCompact,
	"Notification":        event.TypeNotification,
	"BeforeModel":         event.TypeNotification,
	"AfterModel":          event.TypeNotification,
	"BeforeToolSelection": event.TypeNotification,
}

func (g gemini) build(p obj, env map[string]string, raw []byte) ([]*event.Event, *Request, error) {
	name := p.str("hook_event_name")
	if name == "" {
		name = envGet(env, EnvHookEvent)
	}
	name, _ = cleanID(name, 64)
	req := &Request{AgentID: AgentGemini, EventName: name, Raw: p}
	if name == "" {
		return nil, req, ErrNoEvent
	}
	typ, known := geminiTypes[name]
	ev := newEvent(AgentGemini, typ, name, raw)
	if !known {
		unknownEvent(ev)
	}
	// Hooks run with GEMINI_SESSION_ID, GEMINI_CWD and GEMINI_PROJECT_DIR
	// set (docs/hooks/index.md, Environment variables).
	s := sessionFields{
		id:         p.str("session_id"),
		cwd:        p.str("cwd"),
		transcript: p.str("transcript_path"),
		projectDir: envGet(env, "GEMINI_PROJECT_DIR"),
	}
	if s.id == "" {
		s.id = envGet(env, "GEMINI_SESSION_ID")
	}
	if s.cwd == "" {
		s.cwd = envGet(env, "GEMINI_CWD")
	}
	switch name {
	case "BeforeModel", "AfterModel", "BeforeToolSelection":
		s.model = p.sub("llm_request").str("model")
	}
	applySession(ev, s)

	switch name {
	case "SessionStart":
		enumLabel(ev, "session_source", p.str("source"))
	case "SessionEnd":
		enumLabel(ev, "end_reason", p.str("reason"))
	case "BeforeAgent":
		setPrompt(ev, p.str("prompt"))
		req.Blocking = true
	case "AfterAgent":
		// The prompt is repeated here; it was already reported (and
		// scanned) at BeforeAgent, so only the response is taken.
		ev.Content.ToolOutput = p.str("prompt_response")
	case "BeforeTool":
		g.tool(ev, p)
		req.Blocking = true
	case "AfterTool":
		g.tool(ev, p)
		resp := p.sub("tool_response")
		if len(resp) > 0 {
			setOutput(ev, map[string]any(resp))
		}
		// tool_response is {llmContent, returnDisplay, error?}; a present,
		// non-empty error marks the failure.
		if errv, has := resp.raw("error"); has && leafText(errv) != "" {
			ev.Outcome = failure(ev, leafText(errv), false)
		} else {
			ev.Outcome = &event.Outcome{Status: "ok"}
		}
	case "PreCompress":
		label(ev, "compact_phase", "pre")
		enumLabel(ev, "compact_trigger", p.str("trigger"))
	case "Notification":
		nt := p.str("notification_type")
		enumLabel(ev, "notification_type", nt)
		if nt == "ToolPermission" {
			// The CLI is asking the user to approve a tool: the same moment
			// as Claude Code's PermissionRequest, though a hook cannot
			// answer it here ("cannot block alerts or grant permissions").
			ev.Type = event.TypePermissionDecision
			ev.Outcome = &event.Outcome{Decision: "ask", DecisionSource: "policy"}
			// UNVERIFIED: the keys inside details; the reference only
			// says it holds alert metadata such as tool name and file path.
			d := p.sub("details")
			if tn := d.str("tool_name", "toolName", "name"); tn != "" {
				args, _ := d.raw("tool_input", "args", "toolInput")
				setTool(ev, AgentGemini, tn, args, "")
			}
		}
	}
	return []*event.Event{ev}, req, nil
}

func (gemini) tool(ev *event.Event, p obj) {
	args, _ := p.raw("tool_input")
	setTool(ev, AgentGemini, p.str("tool_name"), args, "")
	// mcp_context is present only for MCP tools and names the server and
	// the server's own tool name. It is authoritative: the mcp_<server>_<tool>
	// tool name cannot be split reliably when a server name contains "_".
	mc := p.sub("mcp_context")
	if len(mc) > 0 {
		forceKind(ev, event.ToolMCP)
		if s, _ := cleanID(mc.str("server_name"), maxName); s != "" {
			ev.Tool.MCPServer = s
		}
		if t, _ := cleanID(mc.str("tool_name"), maxName); t != "" {
			ev.Tool.MCPTool = t
		}
	}
	// A tail call replaces the tool the model asked for; keep the original.
	label(ev, "original_request", p.str("original_request_name"))
}

// geminiReply is Gemini's flat decision object.
type geminiReply struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

func (gemini) respond(req *Request, d Decision) ([]byte, []byte, int) {
	if !req.Blocking {
		return proceed()
	}
	msg := reason(d)
	switch req.EventName {
	case "BeforeTool", "BeforeAgent":
		switch d.Action {
		case ActionDeny:
			// Exit 0 with decision "deny" is the documented preferred form
			// ("Preferred code for all logic, including intentional
			// blocks"); the reason goes to the agent as a tool error.
			return jsonLine(geminiReply{Decision: "deny", Reason: msg}), nil, 0
		case ActionAsk:
			// Gemini has no ask decision.
			return warn(msg)
		case ActionAllow:
			if req.EventName == "BeforeTool" {
				return jsonLine(geminiReply{Decision: "allow"}), nil, 0
			}
		}
	}
	return proceed()
}

func (gemini) events() []HookEvent {
	// Gemini runs hooks synchronously (no background option). The model
	// hooks (BeforeModel, AfterModel, BeforeToolSelection) are left out:
	// AfterModel fires per streamed chunk and all three carry whole LLM
	// requests, which is cost without detection value here.
	return []HookEvent{
		{Name: "SessionStart"},
		{Name: "BeforeAgent", Blocking: true},
		{Name: "BeforeTool", Blocking: true},
		{Name: "AfterTool"},
		{Name: "AfterAgent"},
		{Name: "Notification"},
		{Name: "PreCompress"},
		{Name: "SessionEnd"},
	}
}
