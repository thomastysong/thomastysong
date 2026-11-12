package hookio

import (
	"github.com/thomastysong/spoor/internal/event"
)

// claudeWire implements the snake_case hook wire that Claude Code defined and
// Codex adopted: hook_event_name, session_id, cwd, tool_name, tool_input,
// tool_use_id, permission_mode. The two differ in which events exist, in a few
// fields (Codex adds turn_id and model everywhere) and, importantly, in what
// replies they honour, so the flag selects per-agent behaviour.
//
// Sources: Claude Code hooks reference (code.claude.com/docs/en/hooks.md),
// Codex hook schemas (openai/codex codex-rs/hooks/schema/generated/*.json)
// and reply parsing (codex-rs/hooks/src/engine/output_parser.rs,
// events/{pre_tool_use,user_prompt_submit,permission_request}.rs).
type claudeWire struct{ codex bool }

func (c claudeWire) id() string {
	if c.codex {
		return "codex"
	}
	return "claude"
}

func (c claudeWire) agentID() string {
	if c.codex {
		return AgentCodex
	}
	return AgentClaude
}

// claudeTypes maps every documented Claude Code hook event (33) to an event
// type. Events with no closer type are notifications.
var claudeTypes = map[string]string{
	"SessionStart":        event.TypeSessionStart,
	"SessionEnd":          event.TypeSessionEnd,
	"UserPromptSubmit":    event.TypePromptSubmit,
	"UserPromptExpansion": event.TypePromptSubmit,
	"PreToolUse":          event.TypeToolPre,
	"PostToolUse":         event.TypeToolPost,
	"PostToolUseFailure":  event.TypeToolPost,
	"PostToolBatch":       event.TypeToolPost,
	"PermissionRequest":   event.TypePermissionDecision,
	"PermissionDenied":    event.TypePermissionDecision,
	"Stop":                event.TypeTurnEnd,
	"StopFailure":         event.TypeTurnEnd,
	"SubagentStart":       event.TypeSubagentStart,
	"SubagentStop":        event.TypeSubagentStop,
	"ConfigChange":        event.TypeConfigChange,
	"PreCompact":          event.TypeCompact,
	"PostCompact":         event.TypeCompact,
	"Notification":        event.TypeNotification,
	"Setup":               event.TypeNotification,
	"InstructionsLoaded":  event.TypeNotification,
	"MessageDisplay":      event.TypeNotification,
	"TaskCreated":         event.TypeNotification,
	"TaskCompleted":       event.TypeNotification,
	"TeammateIdle":        event.TypeNotification,
	"CwdChanged":          event.TypeNotification,
	"DirectoryAdded":      event.TypeNotification,
	"FileChanged":         event.TypeNotification,
	"WorktreeCreate":      event.TypeNotification,
	"WorktreeRemove":      event.TypeNotification,
	"PreModelSwitch":      event.TypeNotification,
	"PostModelSwitch":     event.TypeNotification,
	"Elicitation":         event.TypeNotification,
	"ElicitationResult":   event.TypeNotification,
}

// codexTypes maps the 14 Codex hook events (HooksToml keys in
// codex-rs/core/config.schema.json).
var codexTypes = map[string]string{
	"SessionStart":      event.TypeSessionStart,
	"SessionEnd":        event.TypeSessionEnd,
	"UserPromptSubmit":  event.TypePromptSubmit,
	"PreToolUse":        event.TypeToolPre,
	"PostToolUse":       event.TypeToolPost,
	"PermissionRequest": event.TypePermissionDecision,
	"Stop":              event.TypeTurnEnd,
	"Interrupt":         event.TypeTurnEnd,
	"SubagentStart":     event.TypeSubagentStart,
	"SubagentStop":      event.TypeSubagentStop,
	"PreCompact":        event.TypeCompact,
	"PostCompact":       event.TypeCompact,
	"PreModelRequest":   event.TypeNotification,
	"PostModelRequest":  event.TypeNotification,
}

// maxBatch bounds how many tool.post events one PostToolBatch may expand to.
const maxBatch = 256

func (c claudeWire) build(p obj, env map[string]string, raw []byte) ([]*event.Event, *Request, error) {
	agent := c.agentID()
	name := p.str("hook_event_name")
	if name == "" {
		name = envGet(env, EnvHookEvent)
	}
	name, _ = cleanID(name, 64)
	req := &Request{AgentID: agent, EventName: name, Raw: p}
	if name == "" {
		return nil, req, ErrNoEvent
	}
	types := claudeTypes
	if c.codex {
		types = codexTypes
	}
	typ, known := types[name]
	if !known {
		// Codex tracks Claude's wire, so a Claude event name arriving from
		// Codex is more likely a newly adopted event than garbage.
		typ, known = claudeTypes[name]
	}
	ev := newEvent(agent, typ, name, raw)
	if !known {
		unknownEvent(ev)
	}
	applySession(ev, c.session(p, env, name))

	switch name {
	case "SessionStart":
		enumLabel(ev, "session_source", p.str("source"))
	case "SessionEnd":
		enumLabel(ev, "end_reason", p.str("reason"))
	case "Setup":
		enumLabel(ev, "setup_trigger", p.str("trigger"))
	case "UserPromptSubmit":
		setPrompt(ev, p.str("prompt"))
		req.Blocking = true
	case "UserPromptExpansion":
		setPrompt(ev, p.str("prompt"))
		label(ev, "prompt_kind", "expansion")
		enumLabel(ev, "expansion_type", p.str("expansion_type"))
		enumLabel(ev, "command_source", p.str("command_source"))
		req.Blocking = true
	case "PreToolUse":
		c.tool(ev, p)
		req.Blocking = true
	case "PermissionRequest":
		// The agent's own rules decided to ask the user; a hook may answer
		// in the user's place.
		c.tool(ev, p)
		ev.Outcome = &event.Outcome{Decision: "ask", DecisionSource: "policy"}
		req.Blocking = true
	case "PermissionDenied":
		// Fires only when auto mode's classifier denies a call. The reason
		// is the classifier's rule label (e.g. "[Data Exfiltration]").
		c.tool(ev, p)
		ev.Outcome = &event.Outcome{
			Status: "denied", Decision: "deny", DecisionSource: "policy",
			Error: denialReason(p.str("reason")),
		}
	case "PostToolUse":
		c.tool(ev, p)
		resp, _ := p.raw("tool_response")
		setOutput(ev, resp)
		// Claude Code fires PostToolUse only for calls that succeeded
		// (failures go to PostToolUseFailure). Codex has one event for
		// both, so without a recognizable result field its outcome is
		// unknown rather than assumed good.
		def := "ok"
		if c.codex {
			def = "unknown"
		}
		ev.Outcome = responseOutcome(resp, def)
		if ms := durationMS(p, "duration_ms"); ms > 0 {
			ev.Outcome.DurationMS = ms
		}
	case "PostToolUseFailure":
		c.tool(ev, p)
		interrupted, _ := p.boolean("is_interrupt")
		ev.Outcome = failure(ev, p.str("error"), interrupted)
		ev.Outcome.DurationMS = durationMS(p, "duration_ms")
	case "PostToolBatch":
		return c.batch(ev, p, env, name), req, nil
	case "Notification":
		enumLabel(ev, "notification_type", p.str("notification_type"))
	case "SubagentStop", "Stop":
		ev.Content.ToolOutput = p.str("last_assistant_message")
	case "StopFailure":
		ev.Content.ToolOutput = p.str("last_assistant_message")
		ev.Outcome = &event.Outcome{Status: "error", Error: token(p.str("error"))}
	case "Interrupt":
		ev.Outcome = &event.Outcome{Status: "interrupted"}
	case "ConfigChange":
		src := p.str("source")
		enumLabel(ev, "config_source", src)
		if fp := p.str("file_path"); fp != "" {
			ev.Target = &event.Target{Path: pathField(ev, "target.path", fp)}
		}
		// Claude Code ignores a block for managed policy files so that
		// enterprise settings always apply (hooks reference, ConfigChange).
		req.Blocking = src != "policy_settings"
	case "InstructionsLoaded":
		enumLabel(ev, "memory_type", p.str("memory_type"))
		enumLabel(ev, "load_reason", p.str("load_reason"))
		if fp := p.str("file_path"); fp != "" {
			ev.Target = &event.Target{Path: pathField(ev, "target.path", fp)}
		}
	case "FileChanged":
		enumLabel(ev, "file_event", p.str("event"))
		if fp := p.str("file_path"); fp != "" {
			ev.Target = &event.Target{Path: pathField(ev, "target.path", fp)}
		}
	case "DirectoryAdded":
		enumLabel(ev, "directory_source", p.str("source"))
		if dir := p.str("directory"); dir != "" {
			ev.Target = &event.Target{Path: pathField(ev, "target.path", dir)}
		}
	case "WorktreeRemove":
		if wp := p.str("worktree_path"); wp != "" {
			ev.Target = &event.Target{Path: pathField(ev, "target.path", wp)}
		}
	case "PreCompact":
		label(ev, "compact_phase", "pre")
		enumLabel(ev, "compact_trigger", p.str("trigger"))
	case "PostCompact":
		label(ev, "compact_phase", "post")
		enumLabel(ev, "compact_trigger", p.str("trigger"))
	case "PreModelSwitch", "PostModelSwitch":
		label(ev, "model_from", p.str("from_model"))
		if to := p.str("to_model"); to != "" {
			ev.Session.Model = field(ev, "session.model", to, maxName)
		}
	case "Elicitation", "ElicitationResult":
		// An MCP server is asking the user for input; URL mode sends the
		// user to a page the server chose, which is a phishing vector. The
		// server is recorded the way tool calls record it, so one query
		// over tool.mcp_server finds both.
		if name, _ := cleanID(p.str("mcp_server_name"), maxName); name != "" {
			ev.Tool = &event.Tool{Kind: event.ToolMCP, MCPServer: name}
		}
		enumLabel(ev, "elicitation_mode", p.str("mode"))
		enumLabel(ev, "elicitation_action", p.str("action"))
		ev.Target = urlTarget(p.str("url"))
	}
	return []*event.Event{ev}, req, nil
}

func (c claudeWire) session(p obj, env map[string]string, name string) sessionFields {
	s := sessionFields{
		id:             p.str("session_id"),
		cwd:            p.str("cwd"),
		transcript:     p.str("transcript_path"),
		model:          p.str("model"),
		permissionMode: p.str("permission_mode"),
		subagentID:     p.str("agent_id"),
		subagentType:   p.str("agent_type"),
	}
	if c.codex {
		s.turnID = p.str("turn_id")
		if s.id == "" {
			// UNVERIFIED: Codex sets these for tool child processes
			// (codex-rs/core/src/exec_env.rs); whether hook processes
			// inherit them was not confirmed. Used only as a fallback.
			s.id = envGet(env, "CODEX_SESSION_ID", "CODEX_THREAD_ID")
		}
		s.agentVersion = envGet(env, "CODEX_VERSION")
		return s
	}
	// prompt_id identifies the user prompt being processed and equals the
	// prompt.id attribute on Claude Code's OpenTelemetry events, which makes
	// it the turn join key across surfaces. MessageDisplay carries turn_id.
	s.turnID = p.str("prompt_id", "turn_id")
	if s.id == "" {
		// Hook commands receive CLAUDE_CODE_SESSION_ID matching session_id
		// (Claude Code env-vars reference).
		s.id = envGet(env, "CLAUDE_CODE_SESSION_ID")
	}
	// CLAUDE_PROJECT_DIR is the project root where the session started and
	// stays put when the agent changes directory or enters a worktree.
	s.projectDir = envGet(env, "CLAUDE_PROJECT_DIR")
	if name == "CwdChanged" {
		if nc := p.str("new_cwd"); nc != "" {
			s.cwd = nc
		}
	}
	s.agentSurface = claudeSurface(env)
	return s
}

// claudeSurface derives how Claude Code was launched.
func claudeSurface(env map[string]string) string {
	// CLAUDE_CODE_REMOTE is "true" in cloud sessions (env-vars reference).
	if envGet(env, "CLAUDE_CODE_REMOTE") == "true" {
		return "cloud"
	}
	// UNVERIFIED: the variable name. The values are the documented
	// app.entrypoint telemetry attribute (monitoring-usage reference).
	switch envGet(env, "CLAUDE_CODE_ENTRYPOINT") {
	case "cli":
		return "cli"
	case "sdk-cli", "sdk-ts", "sdk-py":
		return "sdk"
	case "claude-vscode":
		return "ide"
	case "claude-desktop":
		return "desktop"
	case "remote":
		return "cloud"
	}
	return ""
}

// tool fills the tool fields common to every tool-bearing event.
func (c claudeWire) tool(ev *event.Event, p obj) {
	args, _ := p.raw("tool_input")
	setTool(ev, c.agentID(), p.str("tool_name"), args, p.str("tool_use_id"))
	c.mcpServer(ev, p)
	// Claude Code's Bash tool can ask to run outside the sandbox.
	if off, _ := obj(ev.Content.ToolInput).boolean("dangerouslyDisableSandbox"); off {
		label(ev, "sandbox_bypass", "1")
	}
}

// mcpServer applies Claude Code's mcp_server object {name, source}
// (v2.1.274+). The docs say to base trust on source, not on the name or the
// mcp__<server>__ prefix, so both are surfaced; the harness-reported name
// wins over the one split from the tool name and the split one is kept as a
// label when they differ (plugin servers are prefixed plugin_<plugin>_).
func (c claudeWire) mcpServer(ev *event.Event, p obj) {
	ms := p.sub("mcp_server")
	if len(ms) == 0 || ev.Tool == nil {
		return
	}
	enumLabel(ev, "mcp_source", ms.str("source"))
	name, _ := cleanID(ms.str("name"), maxName)
	if name == "" {
		return
	}
	if ev.Tool.MCPServer != "" && ev.Tool.MCPServer != name {
		label(ev, "mcp_tool_prefix", ev.Tool.MCPServer)
	}
	ev.Tool.MCPServer = name
	if ev.Tool.Kind != event.ToolMCP {
		forceKind(ev, event.ToolMCP)
	}
}

// batch expands PostToolBatch, which reports every call of a parallel batch
// at once, into one tool.post per call. Their outcome is unknown: the batch
// payload carries the model-facing result but not success or failure.
func (c claudeWire) batch(first *event.Event, p obj, env map[string]string, name string) []*event.Event {
	calls := p.arr("tool_calls")
	if len(calls) > maxBatch {
		calls = calls[:maxBatch]
		first.Truncated = appendUnique(first.Truncated, "tool_calls")
	}
	var out []*event.Event
	for _, it := range calls {
		call, ok := it.(map[string]any)
		if !ok {
			continue
		}
		ev := first
		if len(out) > 0 {
			// Only the first event keeps the raw payload; copying it into
			// every sibling would multiply memory by the batch size.
			ev = newEvent(c.agentID(), event.TypeToolPost, name, nil)
			applySession(ev, c.session(p, env, name))
		}
		cp := obj(call)
		c.tool(ev, cp)
		resp, _ := cp.raw("tool_response")
		setOutput(ev, resp)
		ev.Outcome = &event.Outcome{Status: "unknown"}
		out = append(out, ev)
	}
	if len(out) == 0 {
		first.Outcome = &event.Outcome{Status: "unknown"}
		out = append(out, first)
	}
	return out
}

func (c claudeWire) respond(req *Request, d Decision) ([]byte, []byte, int) {
	if !req.Blocking {
		return proceed()
	}
	if c.codex {
		return c.respondCodex(req, d)
	}
	msg := reason(d)
	switch req.EventName {
	case "PreToolUse":
		// PreToolUse decides through hookSpecificOutput.permissionDecision
		// (allow | deny | ask) on exit 0; top-level decision is deprecated
		// for this event.
		return jsonLine(preToolReply{hookSpecific{
			HookEventName:            "PreToolUse",
			PermissionDecision:       d.Action,
			PermissionDecisionReason: msg,
		}}), nil, 0
	case "PermissionRequest":
		// Exit 2 is not honoured for this event; the decision object is.
		switch d.Action {
		case ActionDeny:
			return jsonLine(preToolReply{hookSpecific{
				HookEventName: "PermissionRequest",
				Decision:      &permBehavior{Behavior: "deny", Message: msg},
			}}), nil, 0
		case ActionAllow:
			return jsonLine(preToolReply{hookSpecific{
				HookEventName: "PermissionRequest",
				Decision:      &permBehavior{Behavior: "allow"},
			}}), nil, 0
		}
		// ask: the user is about to be asked anyway.
		return proceed()
	case "UserPromptSubmit", "UserPromptExpansion", "ConfigChange":
		switch d.Action {
		case ActionDeny:
			return jsonLine(blockReply{Decision: "block", Reason: msg}), nil, 0
		case ActionAsk:
			if req.EventName == "ConfigChange" {
				// ConfigChange discards systemMessage; nothing to show.
				return proceed()
			}
			return warn(msg)
		}
	}
	return proceed()
}

// respondCodex renders for Codex, whose reply parser is stricter than its
// Claude-shaped schema suggests: permissionDecision "ask", a bare "allow"
// and legacy decision "approve" are rejected as invalid and the hook then
// fails open. Exit code 2 with a non-empty stderr is the block signal every
// gateable Codex event honours.
func (c claudeWire) respondCodex(req *Request, d Decision) ([]byte, []byte, int) {
	msg := reason(d)
	switch req.EventName {
	case "PreToolUse", "UserPromptSubmit":
		switch d.Action {
		case ActionDeny:
			return exitBlock(msg)
		case ActionAsk:
			return warn(msg)
		}
	case "PermissionRequest":
		switch d.Action {
		case ActionDeny:
			return exitBlock(msg)
		case ActionAllow:
			return jsonLine(preToolReply{hookSpecific{
				HookEventName: "PermissionRequest",
				Decision:      &permBehavior{Behavior: "allow"},
			}}), nil, 0
		}
	}
	return proceed()
}

func (c claudeWire) events() []HookEvent {
	if c.codex {
		return []HookEvent{
			{Name: "SessionStart", Async: true},
			{Name: "UserPromptSubmit", Blocking: true},
			{Name: "PreToolUse", Blocking: true},
			{Name: "PermissionRequest", Blocking: true},
			{Name: "PostToolUse", Async: true},
			{Name: "SubagentStart", Async: true},
			{Name: "SubagentStop", Async: true},
			{Name: "Stop", Async: true},
			{Name: "PostCompact", Async: true},
			// Synchronous: the process is exiting and a background hook
			// may not get to run.
			{Name: "SessionEnd"},
		}
	}
	return []HookEvent{
		{Name: "SessionStart", Async: true},
		{Name: "UserPromptSubmit", Blocking: true},
		{Name: "PreToolUse", Blocking: true},
		{Name: "PermissionRequest", Blocking: true},
		{Name: "PermissionDenied", Async: true},
		{Name: "PostToolUse", Async: true},
		{Name: "PostToolUseFailure", Async: true},
		{Name: "SubagentStart", Async: true},
		{Name: "SubagentStop", Async: true},
		{Name: "Stop", Async: true},
		// Synchronous so a rule can stop a session from loading settings
		// that switch hooks off or widen permissions.
		{Name: "ConfigChange", Blocking: true},
		{Name: "InstructionsLoaded", Async: true},
		{Name: "Elicitation", Async: true},
		{Name: "PostCompact", Async: true},
		// Synchronous: SessionEnd hooks share a 1.5 s budget and async
		// hooks are killed at teardown in -p runs.
		{Name: "SessionEnd"},
	}
}
