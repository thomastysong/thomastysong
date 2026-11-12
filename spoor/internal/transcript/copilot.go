package transcript

import (
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// copilotParser reads GitHub Copilot CLI session event logs.
//
// Layout (github/docs cli-config-dir-reference):
// $COPILOT_HOME/session-state/<session-id>/events.jsonl. Each line is an
// envelope {id, parentId, timestamp, type, agentId?, data}; the data shapes
// are the published session-events schema (github/copilot-sdk,
// nodejs/src/generated/session-events.ts). Subagent events share the file
// and are tagged with agentId.
type copilotParser struct{}

func (copilotParser) AgentID() string { return toolmap.AgentCopilot }
func (copilotParser) Format() string  { return FormatCopilot }

func (copilotParser) Match(path string) bool {
	p := slashPath(path)
	return strings.HasSuffix(p, "/events.jsonl") && strings.Contains(p, "/session-state/")
}

func (p copilotParser) ParseLine(line []byte, st *FileState) ([]*event.Event, error) {
	return parseGuard(p.AgentID(), line, st, parseCopilot)
}

// copilotEnvelope is decoded in one pass, data included: copilotData is the
// union of the fields read from any handled event, with polymorphic values
// left generic.
type copilotEnvelope struct {
	ID        string       `json:"id"`
	Type      string       `json:"type"`
	Timestamp string       `json:"timestamp"`
	AgentID   string       `json:"agentId"`
	Data      *copilotData `json:"data"`
}

type copilotContext struct {
	CWD string `json:"cwd"`
}

type copilotData struct {
	// session.start, session.resume, session.context_changed
	SessionID      string          `json:"sessionId"`
	CopilotVersion string          `json:"copilotVersion"`
	SelectedModel  string          `json:"selectedModel"`
	Context        *copilotContext `json:"context"`
	CWD            string          `json:"cwd"`
	// session.model_change, session.mode_changed, session.shutdown
	NewModel     string `json:"newModel"`
	NewMode      string `json:"newMode"`
	PreviousMode string `json:"previousMode"`
	ShutdownType string `json:"shutdownType"`
	// user.message
	Content                 any    `json:"content"`
	Source                  string `json:"source"`
	IsAutopilotContinuation bool   `json:"isAutopilotContinuation"`
	// tool.execution_start / tool.execution_complete
	ToolCallID    string `json:"toolCallId"`
	ToolName      string `json:"toolName"`
	MCPServerName string `json:"mcpServerName"`
	MCPToolName   string `json:"mcpToolName"`
	Arguments     any    `json:"arguments"`
	Model         string `json:"model"`
	TurnID        string `json:"turnId"`
	Success       *bool  `json:"success"`
	Result        any    `json:"result"`
	Error         any    `json:"error"`
	// shellExecution.exitCode is set on shell tools even when success is true.
	ShellExecution *struct {
		ExitCode *int `json:"exitCode"`
	} `json:"shellExecution"`
	// permission.requested / permission.completed
	RequestID         string `json:"requestId"`
	PermissionMode    string `json:"permissionMode"`
	DecisionSource    string `json:"decisionSource"`
	PermissionRequest *struct {
		Kind       string `json:"kind"`
		ToolCallID string `json:"toolCallId"`
	} `json:"permissionRequest"`
	// subagent.*
	AgentName  string  `json:"agentName"`
	AgentType  string  `json:"agentType"`
	Cancelled  bool    `json:"cancelled"`
	DurationMs float64 `json:"durationMs"`
}

// copilotKnown is every envelope type in the session-events schema
// (generated from session-events.ts). Types outside it count as unknown.
var copilotKnown = toSet(`abort assistant.fusion_phase_activity assistant.fusion_phase_completed
assistant.fusion_phase_failed assistant.fusion_phase_started assistant.idle assistant.intent assistant.message
assistant.message_delta assistant.message_start assistant.reasoning assistant.reasoning_delta
assistant.server_tool_progress assistant.streaming_delta assistant.tool_call_delta assistant.turn_end
assistant.turn_start assistant.usage auto_mode_recovery.outcome auto_mode_recovery_consent.completed
auto_mode_recovery_consent.requested auto_mode_switch.completed auto_mode_switch.requested capabilities.changed
command.completed command.execute command.queued commands.changed elicitation.completed elicitation.requested
exit_plan_mode.completed exit_plan_mode.requested external_tool.completed external_tool.requested hook.end
hook.progress hook.start human_response.recorded instruction.update mcp.headers_refresh_completed
mcp.headers_refresh_required mcp.oauth_completed mcp.oauth_recovery_completed mcp.oauth_required
mcp.prompts.list_changed mcp.resources.list_changed mcp.tools.list_changed mcp_app.tool_call_complete
model.call_failure model.call_finished pending_messages.modified permission.assentDetected
permission.carriedForward permission.completed permission.contextualAuthorization permission.messageAuthorization
permission.messageAuthorizationDegraded permission.messageAuthorizationRead permission.requested
sampling.completed sampling.requested session.auto_mode_resolved session.auto_tier_recommendation
session.auto_tier_switch_failed session.autopilot_objective_changed session.autopilot_stopped
session.background_tasks_changed session.binary_asset session.canvas.closed session.canvas.opened
session.canvas.recorded session.canvas.registry_changed session.canvas.removed session.canvas.unavailable
session.compaction_complete session.compaction_start session.compaction_summarized session.completion_receipt
session.context_changed session.context_cleared session.custom_agents_updated session.custom_notification
session.error session.extensions.attachments_pushed session.extensions_loaded session.fusion_completed
session.fusion_resolved session.fusion_route_failed session.fusion_route_started session.handoff session.idle
session.indexed_search session.info session.journal_link session.managed_plugin_progress
session.managed_settings_enforced session.managed_settings_resolved session.mcp_server_needs_reconnect
session.mcp_server_removed session.mcp_server_status_changed session.mcp_server_tools_loaded
session.mcp_servers_loaded session.mode_changed session.mode_notice_delivered session.model_change
session.model_deselected session.permission_recovery session.permissions_changed session.plan_changed
session.quota_observation session.remote_steerable_changed session.resume session.schedule_cancelled
session.schedule_created session.schedule_rearmed session.session_limits_changed session.shutdown
session.skills_loaded session.snapshot_rewind session.start session.task_complete session.title_changed
session.todos_changed session.tools_updated session.truncation session.usage_checkpoint session.usage_info
session.warning session.workspace_file_changed session_limits_exhausted.completed
session_limits_exhausted.requested skill.invoked subagent.completed subagent.configured subagent.deselected
subagent.failed subagent.selected subagent.started system.message system.notification tool.execution_complete
tool.execution_partial_result tool.execution_progress tool.execution_start tool.shell_output tool.user_requested
tool_search.activated ui.ephemeral_query user.message user_input.completed user_input.requested
workflow.run_settled workflow.run_started workflow.run_updated`)

func parseCopilot(c *lineCtx) error {
	var env copilotEnvelope
	if err := decode(c.line, &env); err != nil {
		return err
	}
	st := c.st
	ts := parseTime(env.Timestamp)
	c.record("e:", env.ID) // every event carries its own id (eventIDs)
	if st.SessionID == "" {
		st.SessionID = copilotSessionFromPath(st.Path)
	}
	if !copilotHandled[env.Type] {
		if !copilotKnown[env.Type] {
			st.Unknown++
		}
		return nil
	}
	d := env.Data
	if d == nil {
		d = &copilotData{}
	}
	if env.Type == "user.message" && env.AgentID != "" {
		// Inside a subagent the "user" is the parent agent.
		return nil
	}
	n0 := len(c.out)
	c.copilotEvent(env.Type, d, ts)
	if env.AgentID != "" {
		for _, e := range c.out[n0:] {
			if e.Session != nil && e.Session.SubagentID == "" {
				e.Session.SubagentID = clip(env.AgentID, maxIDLen)
			}
		}
	}
	return nil
}

var copilotHandled = toSet(`session.start session.resume session.shutdown session.context_changed
session.model_change session.mode_changed session.compaction_complete user.message assistant.turn_end abort
tool.execution_start tool.execution_complete permission.requested permission.completed subagent.started
subagent.completed subagent.failed`)

// copilotSessionFromPath takes the session id from the directory name, the
// one place it is always present: .../session-state/<id>/events.jsonl.
func copilotSessionFromPath(path string) string {
	p := slashPath(path)
	p = strings.TrimSuffix(p, "/events.jsonl")
	if i := strings.LastIndexByte(p, '/'); i >= 0 && strings.HasSuffix(p[:i], "/session-state") {
		return clip(p[i+1:], maxIDLen)
	}
	return ""
}

func (c *lineCtx) copilotEvent(typ string, d *copilotData, ts time.Time) {
	st := c.st
	switch typ {
	case "session.start", "session.resume":
		if d.SessionID != "" {
			st.SessionID = clip(d.SessionID, maxIDLen)
		}
		if d.CopilotVersion != "" {
			st.Version = clip(d.CopilotVersion, maxVersionLen)
		}
		if d.SelectedModel != "" {
			st.Model = clip(d.SelectedModel, maxModelLen)
		}
		if d.Context != nil && d.Context.CWD != "" {
			st.CWD = clip(d.Context.CWD, maxCWDLen)
		}
		// No surface is claimed: the VS Code Copilot harness shares this
		// runtime and log format, and the record does not say which it is.
		e := c.newEvent(event.TypeSessionStart, ts)
		if typ == "session.resume" {
			c.label(e, "start", "resume")
		}
	case "session.shutdown":
		e := c.newEvent(event.TypeSessionEnd, ts)
		switch d.ShutdownType {
		case "error":
			e.Outcome = &event.Outcome{Status: statusError, Error: "shutdown_error"}
		default:
			e.Outcome = &event.Outcome{Status: statusOK}
		}
	case "session.context_changed":
		// The data is the working directory context itself; some builds
		// nest it under "context".
		switch {
		case d.Context != nil && d.Context.CWD != "":
			st.CWD = clip(d.Context.CWD, maxCWDLen)
		case d.CWD != "":
			st.CWD = clip(d.CWD, maxCWDLen)
		}
	case "session.model_change":
		if d.NewModel != "" {
			st.Model = clip(d.NewModel, maxModelLen)
		}
	case "session.mode_changed":
		switch d.NewMode {
		case "interactive", "plan", "autopilot":
			st.setExtra("copilot_mode", d.NewMode)
			c.copilotMode(ts)
		}
	case "session.compaction_complete":
		c.newEvent(event.TypeCompact, ts)
	case "user.message":
		// Skill text, agent hand-offs and autopilot nudges arrive as user
		// messages nobody typed (Fleet ai_agent_sessions).
		if strings.HasPrefix(d.Source, "skill-") || strings.HasPrefix(d.Source, "agent-") || d.IsAutopilotContinuation {
			return
		}
		if text := anyText(d.Content); text != "" {
			c.prompt(ts, text)
		}
	case "assistant.turn_end":
		e := c.newEvent(event.TypeTurnEnd, ts)
		if d.TurnID != "" {
			e.Session.TurnID = clip(d.TurnID, maxIDLen)
		}
		e.Outcome = &event.Outcome{Status: statusOK}
	case "abort":
		e := c.newEvent(event.TypeTurnEnd, ts)
		e.Outcome = &event.Outcome{Status: statusInterrupted}
	case "tool.execution_start":
		c.copilotToolStart(d, ts)
	case "tool.execution_complete":
		c.copilotToolComplete(d, ts)
	case "permission.requested":
		switch d.PermissionMode {
		case "manual", "assisted", "allow-all":
			st.setExtra("copilot_perm", d.PermissionMode)
			c.copilotMode(ts)
		}
		if d.RequestID != "" && d.PermissionRequest != nil {
			h := st.hint("req:" + d.RequestID)
			h.tool = clip(d.PermissionRequest.ToolCallID, maxIDLen)
			switch k := d.PermissionRequest.Kind; k {
			case "shell", "write", "read", "mcp", "url", "memory", "custom-tool", "hook",
				"extension-management", "workflow", "extension-permission-access", "extension-env-access":
				h.request = k
			}
		}
	case "permission.completed":
		c.copilotPermission(d, ts)
	case "subagent.started":
		e := c.newEvent(event.TypeSubagentStart, ts)
		e.Session.SubagentType = clip(firstNonEmpty(d.AgentName, d.AgentType), maxNameLen)
		e.Session.SubagentID = clip(d.ToolCallID, maxIDLen)
		e.Tool = &event.Tool{Kind: event.ToolSubagent, UseID: clip(d.ToolCallID, maxIDLen)}
	case "subagent.completed", "subagent.failed":
		e := c.newEvent(event.TypeSubagentStop, ts)
		e.Session.SubagentType = clip(d.AgentName, maxNameLen)
		e.Session.SubagentID = clip(d.ToolCallID, maxIDLen)
		e.Tool = &event.Tool{Kind: event.ToolSubagent, UseID: clip(d.ToolCallID, maxIDLen)}
		oc := &event.Outcome{Status: statusOK}
		switch {
		case typ == "subagent.failed":
			oc.Status, oc.Error = statusError, "subagent_failed"
		case d.Cancelled:
			oc.Status = statusInterrupted
		}
		if d.DurationMs > 0 && d.DurationMs < 1e12 {
			oc.DurationMS = int64(d.DurationMs)
		}
		e.Outcome = oc
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// copilotMode folds Copilot's two axes, the agent mode (interactive | plan |
// autopilot) and the permission mode (manual | assisted | allow-all), into
// the event vocabulary and reports a change. allow-all dominates: it is the
// state in which nothing asks.
func (c *lineCtx) copilotMode(ts time.Time) {
	st := c.st
	mode := "default"
	switch {
	case st.extra("copilot_perm") == "allow-all":
		mode = "bypass"
	case st.extra("copilot_mode") == "plan":
		mode = "plan"
	case st.extra("copilot_mode") == "autopilot", st.extra("copilot_perm") == "assisted":
		mode = "auto"
	}
	prev := st.PermissionMode
	st.PermissionMode = mode
	if prev == mode || (prev == "" && mode == "default") {
		return
	}
	e := c.newEvent(event.TypeConfigChange, ts)
	c.label(e, "change", "permission_mode")
	c.label(e, "from", prev)
	c.label(e, "to", mode)
}

func (c *lineCtx) copilotToolStart(d *copilotData, ts time.Time) {
	input := anyObject(d.Arguments)
	if input == nil {
		if s := anyString(d.Arguments); s != "" {
			input = map[string]any{"input": s}
		}
	}
	var kind event.ToolKind
	var server, tool string
	if d.MCPServerName != "" {
		// The envelope names the server outright; the tool name alone
		// ("server-tool") cannot be split reliably.
		kind, server, tool = event.ToolMCP, d.MCPServerName, firstNonEmpty(d.MCPToolName, d.ToolName)
	} else {
		kind, server, tool = toolmap.KindWithInput(c.agent, d.ToolName, input)
	}
	e := c.toolPre(ts, d.ToolName, d.ToolCallID, kind, server, tool, input)
	if d.TurnID != "" {
		e.Session.TurnID = clip(d.TurnID, maxIDLen)
	}
	if d.Model != "" {
		e.Session.Model = clip(d.Model, maxModelLen)
	}
}

func (c *lineCtx) copilotToolComplete(d *copilotData, ts time.Time) {
	res := anyObject(d.Result)
	text := anyText(res["content"])
	if text == "" {
		text = anyText(res["detailedContent"])
	}
	var exit *int
	if d.ShellExecution != nil {
		exit = d.ShellExecution.ExitCode
	}
	contents, _ := res["contents"].([]any)
	for _, raw := range contents {
		it := anyObject(raw)
		if text == "" {
			text = anyString(it["text"])
		}
		if exit == nil && anyString(it["type"]) == "shell_exit" {
			if n, ok := anyInt(it["exitCode"]); ok {
				exit = &n
			}
		}
	}
	if text == "" {
		text = anyString(anyObject(d.Error)["message"])
	}
	oc := &event.Outcome{Status: statusOK, ExitCode: exit}
	switch {
	case d.Success != nil && !*d.Success:
		oc.Status, oc.Error = statusError, "tool_error"
	case exit != nil && *exit != 0:
		// Copilot records a failed command as a successful tool call.
		oc.Status, oc.Error = statusError, "exit_code"
	case d.Success == nil:
		oc.Status = statusUnknown
	}
	if h := c.st.takeHint(d.ToolCallID); h != nil && h.denied {
		oc.Status, oc.Decision, oc.DecisionSource, oc.Error = statusDenied, "deny", h.source, "permission_denied"
	}
	e := c.toolPost(ts, d.ToolCallID, text, oc)
	if d.TurnID != "" {
		e.Session.TurnID = clip(d.TurnID, maxIDLen)
	}
}

// copilotPermission turns permission.completed into permission.decision.
// Result kinds are the PermissionResult union of the schema.
func (c *lineCtx) copilotPermission(d *copilotData, ts time.Time) {
	kind := anyString(anyObject(d.Result)["kind"])
	req := c.st.takeHint("req:" + d.RequestID)
	callID := clip(d.ToolCallID, maxIDLen)
	if callID == "" && req != nil {
		callID = req.tool
	}
	oc := &event.Outcome{}
	switch kind {
	case "approved", "approved-for-session", "approved-for-location", "approved-read-only-for-session":
		oc.Decision = "allow"
	case "denied-interactively-by-user":
		oc.Decision, oc.DecisionSource = "deny", "user"
	case "denied-by-permission-request-hook":
		oc.Decision, oc.DecisionSource = "deny", "hook"
	case "denied-by-rules", "denied-by-content-exclusion-policy",
		"denied-no-approval-rule-and-could-not-request-from-user":
		oc.Decision, oc.DecisionSource = "deny", "policy"
	case "cancelled":
		oc.Status = statusInterrupted
	default:
		if strings.HasPrefix(kind, "denied-") {
			oc.Decision, oc.DecisionSource = "deny", "policy"
		} else {
			c.st.Unknown++
			return
		}
	}
	if oc.DecisionSource == "" {
		switch d.DecisionSource {
		case "human_response":
			oc.DecisionSource = "user"
		case "assisted_approval", "host_policy", "unattended_fallback", "authorization_carry_forward":
			oc.DecisionSource = "policy"
		}
	}
	e := c.newEvent(event.TypePermissionDecision, ts)
	e.Outcome = oc
	e.Tool = &event.Tool{UseID: callID}
	if pre := c.st.Pending[callID]; pre != nil && pre.Tool != nil {
		t := *pre.Tool
		t.InputKeys = append([]string(nil), pre.Tool.InputKeys...)
		e.Tool = &t
		if pre.Content != nil {
			e.Content = &event.Content{ToolInput: pre.Content.ToolInput}
		}
		if pre.Target != nil {
			tg := *pre.Target
			e.Target = &tg
		}
	}
	// Result kinds are a closed set, safe to emit as a label.
	if copilotResultKinds[kind] {
		c.label(e, "result", kind)
	}
	if req != nil {
		c.label(e, "request", req.request)
	}
	if oc.Decision == "deny" && callID != "" {
		h := c.st.hint(callID)
		h.denied, h.source = true, oc.DecisionSource
	}
}

var copilotResultKinds = toSet(`approved approved-for-session approved-for-location approved-read-only-for-session
cancelled denied-by-rules denied-no-approval-rule-and-could-not-request-from-user denied-interactively-by-user
denied-by-content-exclusion-policy denied-by-permission-request-hook`)
