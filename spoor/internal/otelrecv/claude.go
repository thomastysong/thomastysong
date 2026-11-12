package otelrecv

import (
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// Claude Code events. Event and attribute names are from
// https://code.claude.com/docs/en/monitoring-usage.md (read 2026-11-11).

// claudeIgnored lists documented events that are deliberately not converted:
// API accounting, model output, UI surveys and internals. safety_event is
// here too: Claude Code stopped sending it in v2.1.312 and the same refusals
// are visible on tool_decision.
var claudeIgnored = map[string]bool{
	"assistant_response": true, "api_request": true, "api_error": true, "api_refusal": true,
	"api_request_body": true, "api_response_body": true, "api_retries_exhausted": true,
	"safety_event": true, "internal_error": true, "at_mention": true,
	"hook_plugin_metrics": true, "feedback_survey": true, "retention_sweep": true,
}

func (r *rec) claude() ([]*event.Event, bool) {
	var ev *event.Event
	switch r.name {
	case "tool_result":
		ev = r.claudeToolResult()
	case "tool_decision":
		ev = r.claudeToolDecision()
	case "user_prompt":
		ev = r.claudeEvent(event.TypePromptSubmit)
		// prompt_text duplicates prompt for backends that nest dotted names
		// and lose "prompt" next to "prompt.id" (v2.1.287+).
		setPrompt(ev, r.a, "prompt", "prompt_text")
		if id, _ := cleanID(r.a.str("message.uuid"), maxLabel); id != "" {
			setLabel(ev, "message_uuid", id) // joins to the transcript entry
		}
		setLabel(ev, "command", r.a.str("command_name"))
		setLabel(ev, "command_source", r.a.str("command_source"))
	case "permission_mode_changed":
		ev = r.claudeEvent(event.TypeConfigChange)
		setLabel(ev, "config_key", "permission_mode")
		setLabel(ev, "from_mode", permMode(r.a.str("from_mode")))
		setLabel(ev, "to_mode", permMode(r.a.str("to_mode")))
		// Absent for some changes, such as an SDK setPermissionMode() call.
		setLabel(ev, "trigger", r.a.str("trigger"))
		ev.Session.PermissionMode = permMode(r.a.str("to_mode"))
	case "mcp_server_connection":
		ev = r.claudeMCPConnection()
	case "plugin_installed":
		ev = r.claudeEvent(event.TypeConfigChange)
		setLabel(ev, "config_key", "plugin")
		r.pluginLabels(ev)
		setLabel(ev, "marketplace_official", r.a.str("marketplace.is_official"))
		setLabel(ev, "install_trigger", r.a.str("install.trigger"))
	case "plugin_loaded":
		ev = r.claudeEvent(event.TypeNotification)
		r.pluginLabels(ev)
		setLabel(ev, "plugin_scope", r.a.str("plugin.scope"))
		setLabel(ev, "enabled_via", r.a.str("enabled_via"))
		setLabel(ev, "has_hooks", r.a.str("has_hooks"))
		setLabel(ev, "has_mcp", r.a.str("has_mcp"))
		setLabel(ev, "safe_mode", r.a.str("safe_mode"))
	case "skill_activated":
		ev = r.claudeEvent(event.TypeNotification)
		// "custom_skill" unless OTEL_LOG_TOOL_DETAILS=1 for user and
		// third-party skills.
		setLabel(ev, "skill", r.a.str("skill.name"))
		setLabel(ev, "skill_trigger", r.a.str("invocation_trigger"))
		setLabel(ev, "skill_source", r.a.str("skill.source"))
		setLabel(ev, "skill_kind", r.a.str("skill.kind"))
		r.pluginLabels(ev)
	case "hook_registered":
		ev = r.claudeEvent(event.TypeNotification)
		setLabel(ev, LabelHookEvent, r.a.str("hook_event"))
		setLabel(ev, "hook_type", r.a.str("hook_type"))
		setLabel(ev, "hook_source", r.a.str("hook_source"))
		setLabel(ev, "safe_mode", r.a.str("safe_mode"))
		r.pluginLabels(ev)
	case "hook_execution_start":
		ev = r.claudeEvent(event.TypeNotification)
		r.claudeHookLabels(ev)
	case "hook_execution_complete":
		ev = r.claudeHookComplete()
	case "managed_settings_resolved":
		ev = r.claudeManagedSettings()
	case "subagent_completed":
		ev = r.claudeEvent(event.TypeSubagentStop)
		// "custom" unless OTEL_LOG_TOOL_DETAILS=1 for user-defined agents.
		ev.Session.SubagentType = field(ev, "session.subagent_type", r.a.str("agent_type"), maxName)
		setLabel(ev, "agent_source", r.a.str("agent.source"))
		setLabel(ev, "is_async", r.a.str("is_async"))
		setLabel(ev, "tool_uses", r.a.str("total_tool_uses"))
		ev.Outcome = &event.Outcome{Status: "ok"}
		if d, ok := r.a.integer("duration_ms"); ok && d >= 0 {
			ev.Outcome.DurationMS = d
		}
		if m := r.a.str("final_model", "model"); m != "" {
			ev.Session.Model = field(ev, "session.model", m, maxName)
		}
	case "compaction":
		ev = r.claudeEvent(event.TypeCompact)
		setLabel(ev, "compact_trigger", r.a.str("trigger"))
		o := &event.Outcome{}
		setOutcomeStatus(o, r.a)
		if d, ok := r.a.integer("duration_ms"); ok && d >= 0 {
			o.DurationMS = d
		}
		ev.Outcome = o
	case "auth":
		ev = r.claudeEvent(event.TypeNotification)
		setLabel(ev, "auth_action", r.a.str("action"))
		setLabel(ev, "auth_method", r.a.str("auth_method"))
		o := &event.Outcome{}
		setOutcomeStatus(o, r.a)
		if o.Status == "error" {
			o.Error = labelValue(r.a.str("error_category"), maxLabel)
		}
		ev.Outcome = o
	default:
		return nil, claudeIgnored[r.name]
	}
	return []*event.Event{ev}, true
}

// std reads a standard attribute. Claude Code puts them on every record;
// operators add their own through OTEL_RESOURCE_ATTRIBUTES, which arrive on
// the resource, so both are consulted, the record first.
func (r *rec) std(key string) string {
	if v := r.a.str(key); v != "" {
		return v
	}
	return r.res.str(key)
}

// claudeEvent starts an event with the attributes every Claude Code record
// carries ("Standard attributes" and "Event correlation attributes").
func (r *rec) claudeEvent(typ string) *event.Event {
	ev := r.newEvent(typ)
	a := r.a
	// prompt.id links every event produced while one prompt is processed;
	// the hook surface reports the same value as prompt_id.
	ev.Session.TurnID = field(ev, "session.turn_id", a.str("prompt.id"), maxID)
	ev.Session.SubagentID = field(ev, "session.subagent_id", a.str("agent_id"), maxID)
	if p, _ := cleanID(a.str("parent_agent_id"), maxLabel); p != "" {
		setLabel(ev, "parent_agent_id", p)
	}
	entry := r.std("app.entrypoint")
	ev.Agent.Surface = claudeSurface(entry)
	if ev.Agent.Surface == "" && strings.EqualFold(r.res.str("service.name"), "claude-code-desktop") {
		ev.Agent.Surface = "desktop"
	}
	setLabel(ev, "entrypoint", entry)
	// The organization the session is signed in to: an account outside the
	// company's organization on a managed machine is a posture finding.
	setLabel(ev, "org_id", r.std("organization.id"))
	// Per-process counter, the tie-breaker for records sharing a timestamp.
	setLabel(ev, "otel_seq", a.str("event.sequence"))
	if u := r.std("vcs.repository.url.full"); u != "" {
		// Claude Code already strips credentials, query and fragment; an
		// operator-declared value may not have been cleaned.
		if clean, _ := toolmap.CleanURL(u); clean != "" {
			ev.Repo = &event.Repo{Remote: field(ev, "repo.remote", clean, 512)}
		}
	}
	return ev
}

// claudeSurface maps app.entrypoint to the event surface vocabulary
// (cli | ide | desktop | sdk | cloud). Unlisted values stay in the
// "entrypoint" label only.
func claudeSurface(entry string) string {
	switch entry {
	case "cli":
		return "cli"
	case "sdk-cli", "sdk-ts", "sdk-py":
		return "sdk"
	case "claude-vscode":
		return "ide"
	case "claude-desktop", "claude-desktop-3p", "local-agent":
		return "desktop"
	case "remote", "remote_desktop", "remote_mobile", "claude-in-slack":
		return "cloud"
	}
	return ""
}

// permMode maps a Claude Code permission mode to the event vocabulary:
// default | plan | accept_edits | auto | dont_ask | bypass. An unknown value
// passes through as a snake_case token so a new mode is visible downstream.
func permMode(s string) string {
	switch s {
	case "":
		return ""
	case "default", "manual":
		return "default"
	case "plan":
		return "plan"
	case "acceptEdits":
		return "accept_edits"
	case "auto":
		return "auto"
	case "dontAsk":
		return "dont_ask"
	case "bypassPermissions":
		return "bypass"
	}
	var sb strings.Builder
	for i, c := range s {
		if i >= 64 {
			break
		}
		switch {
		case c >= 'A' && c <= 'Z':
			if sb.Len() > 0 {
				sb.WriteByte('_')
			}
			sb.WriteRune(c + ('a' - 'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
			sb.WriteRune(c)
		default:
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

// Placeholder tool names Claude Code writes instead of the real one.
const (
	claudeMCPPlaceholder = "mcp_tool" // every user-configured MCP tool unless OTEL_LOG_TOOL_DETAILS=1
)

var claudeOpaqueTools = map[string]bool{"skill_tool": true, "dynamic_tool": true, "other_tool": true}

// claudeTool fills Tool, Target and Content.ToolInput from tool_name,
// tool_use_id, tool_parameters and tool_input, and returns the decoded
// tool_parameters.
//
// What is available depends on OTEL_LOG_TOOL_DETAILS. Without it there is no
// command, no MCP server or tool name and no arguments: the event still
// proves that a call with this tool_use_id happened, which is what the
// coverage correlator needs. With it, tool_parameters carries a per-tool
// summary and (tool_result only) tool_input carries the arguments with each
// value cut at 512 characters and the whole at about 4 K characters.
func (r *rec) claudeTool(ev *event.Event) map[string]any {
	a := r.a
	name := a.str("tool_name")
	params, _ := embeddedObject(a.str("tool_parameters"))
	t := &event.Tool{UseID: field(ev, "tool.use_id", a.str("tool_use_id"), maxID)}

	server, mcpTool := strOf(params, "mcp_server_name"), strOf(params, "mcp_tool_name")
	placeholder := name == claudeMCPPlaceholder
	if placeholder && server != "" && mcpTool != "" {
		// Rebuild the name the hook and transcript surfaces report.
		name = "mcp__" + server + "__" + mcpTool
	}
	t.Name = field(ev, "tool.name", name, maxName)

	input := toolInputFromText(ev, a.str("tool_input"), "_raw")
	fromArgs := input != nil
	if input == nil && len(params) > 0 {
		input = claudeInputFromParams(params)
	}

	if t.Name != "" {
		kind, s, tl := toolmap.KindWithInput(r.agent, t.Name, input)
		switch src := a.str("tool_source"); {
		case placeholder, src == "mcp", src == "sdk_host_builtin_mcp":
			kind = event.ToolMCP
		case claudeOpaqueTools[name]:
			kind = event.ToolOther
		}
		t.Kind = kind
		t.MCPServer, _ = cleanID(firstNonEmpty(server, s), maxName)
		t.MCPTool, _ = cleanID(firstNonEmpty(mcpTool, tl), maxName)
	}
	if input != nil {
		content(ev).ToolInput = input
		if fromArgs {
			// No InputSHA256: the arguments were cut by the agent, so their
			// hash would disagree with the hook's hash of the full input.
			// The surfaces join on tool_use_id instead.
			t.InputKeys = toolmap.InputKeys(input)
		}
		ev.Target = toolmap.Target(r.agent, t.Name, t.Kind, input)
	}
	if truthy(params, "dangerouslyDisableSandbox") || truthy(input, "dangerouslyDisableSandbox") {
		setLabel(ev, "sandbox_bypass", "1") // same label as the hook surface
	}
	ev.Tool = t
	return params
}

// claudeInputFromParams rebuilds a tool input from tool_parameters when the
// arguments themselves were not exported. Keys are the tool's own argument
// names so toolmap.Target and the detection features read them unchanged.
func claudeInputFromParams(p map[string]any) map[string]any {
	in := map[string]any{}
	// full_command is the command line; bash_command is only its first word.
	if cmd := strOf(p, "full_command"); cmd != "" {
		in["command"] = cmd
	}
	if truthy(p, "dangerouslyDisableSandbox") {
		in["dangerouslyDisableSandbox"] = true
	}
	if s := strOf(p, "skill_name"); s != "" {
		in["skill"] = s
	}
	if s := strOf(p, "subagent_type"); s != "" {
		in["subagent_type"] = s
	}
	if len(in) == 0 {
		return nil
	}
	return in
}

// claudeDecisionSource maps the documented decision sources onto
// user | policy | hook and keeps the original value as a label, because
// "config" covers eight different mechanisms and user_abort differs from
// user_reject.
func claudeDecisionSource(ev *event.Event, o *event.Outcome, src string) {
	switch src {
	case "":
		return
	case "config":
		o.DecisionSource = "policy"
	case "hook":
		o.DecisionSource = "hook"
	case "user_permanent", "user_temporary", "user_abort", "user_reject":
		o.DecisionSource = "user"
	}
	setLabel(ev, "decision_source", src)
}

func (r *rec) claudeToolResult() *event.Event {
	ev := r.claudeEvent(event.TypeToolPost)
	a := r.a
	params := r.claudeTool(ev)
	o := &event.Outcome{}
	setOutcomeStatus(o, a)
	if d, ok := a.integer("duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	// error_type is a category ("ShellError", "Error:ENOENT"); error is the
	// full message and only present with OTEL_LOG_TOOL_DETAILS=1.
	setError(ev, o, a.str("error_type"), a.str("error"))
	// tool_result is emitted only after the tool ran, so decision_type is
	// always "accept"; rejected calls appear on tool_decision.
	if a.str("decision_type") == "accept" {
		o.Decision = "allow"
	}
	claudeDecisionSource(ev, o, a.str("decision_source"))
	ev.Outcome = o
	if n, ok := a.count("tool_result_size_bytes"); ok {
		ev.Tool.OutputLen = n
	}
	setLabel(ev, "tool_input_bytes", a.str("tool_input_size_bytes"))
	setLabel(ev, "mcp_server_scope", a.str("mcp_server_scope"))
	// A successful `git commit` is reported with its identity.
	setLabel(ev, "git_commit", firstNonEmpty(a.str("vcs.ref.head.revision"), strOf(params, "git_commit_id")))
	if b := firstNonEmpty(a.str("vcs.ref.head.name"), strOf(params, "git_branch")); b != "" {
		if ev.Repo == nil {
			ev.Repo = &event.Repo{}
		}
		ev.Repo.Branch = field(ev, "repo.branch", b, maxName)
	}
	return ev
}

func (r *rec) claudeToolDecision() *event.Event {
	ev := r.claudeEvent(event.TypePermissionDecision)
	a := r.a
	r.claudeTool(ev)
	o := &event.Outcome{}
	switch d := a.str("decision"); d {
	case "accept":
		o.Decision = "allow"
	case "reject":
		o.Decision, o.Status = "deny", "denied"
	default:
		o.Status = "unknown"
		setLabel(ev, "decision_raw", d)
	}
	claudeDecisionSource(ev, o, a.str("source"))
	ev.Outcome = o
	// The mode the call was checked in; a subagent call reports the
	// subagent's mode (v2.1.301+).
	ev.Session.PermissionMode = permMode(a.str("permission_mode"))
	setLabel(ev, "classifier_verdict", a.str("classifier_verdict"))
	setLabel(ev, "classifier_category", a.str("classifier_category"))
	setLabel(ev, "tool_source", a.str("tool_source"))
	return ev
}

// claudeMCPConnection reports an MCP server connecting, failing or
// disconnecting. It is a notification, not an inventory record: discovery
// owns MCP inventory and its asset ids, and this event only says what the
// running agent did with a server.
func (r *rec) claudeMCPConnection() *event.Event {
	ev := r.claudeEvent(event.TypeNotification)
	a := r.a
	status := a.str("status")
	setLabel(ev, "mcp_status", status)
	setLabel(ev, "mcp_transport", a.str("transport_type"))
	setLabel(ev, "mcp_scope", a.str("server_scope"))
	// Present only with OTEL_LOG_TOOL_DETAILS=1.
	setLabel(ev, "mcp_server", a.str("server_name"))
	setLabel(ev, "is_plugin", a.str("is_plugin"))
	r.pluginLabels(ev)
	o := &event.Outcome{Status: "ok"}
	if status == "failed" {
		o.Status = "error"
		setError(ev, o, a.str("error_code"), a.str("error"))
	}
	if d, ok := a.integer("duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	ev.Outcome = o
	return ev
}

// pluginLabels copies the plugin identity attributes shared by several
// events. Third-party names arrive as the literal "third-party" unless
// OTEL_LOG_TOOL_DETAILS=1; plugin_id_hash still tells such plugins apart.
func (r *rec) pluginLabels(ev *event.Event) {
	setLabel(ev, "plugin", r.a.str("plugin.name"))
	setLabel(ev, "plugin_version", r.a.str("plugin.version"))
	setLabel(ev, "plugin_id_hash", r.a.str("plugin_id_hash"))
	setLabel(ev, "marketplace", r.a.str("marketplace.name"))
}

func (r *rec) claudeHookLabels(ev *event.Event) {
	a := r.a
	setLabel(ev, LabelHookEvent, a.str("hook_event"))
	// "PreToolUse:Write": event type plus matcher, not a command line.
	setLabel(ev, "hook_name", a.str("hook_name"))
	setLabel(ev, LabelHookRuns, a.str("num_hooks"))
	setLabel(ev, "managed_only", a.str("managed_only"))
	setLabel(ev, "hook_source", a.str("hook_source"))
	setLabel(ev, "safe_mode", a.str("safe_mode"))
}

// claudeHookComplete is the record the coverage correlator counts: Claude
// Code logs it once per hook event after every matching hook finished. It is
// not tied to a tool call (there is no tool_use_id on it).
func (r *rec) claudeHookComplete() *event.Event {
	ev := r.claudeEvent(event.TypeNotification)
	a := r.a
	r.claudeHookLabels(ev)
	for label, key := range map[string]string{
		"hooks_ok":        "num_success",
		"hooks_blocking":  "num_blocking",
		"hooks_failed":    "num_non_blocking_error",
		"hooks_cancelled": "num_cancelled",
	} {
		setLabel(ev, label, a.str(key))
	}
	o := &event.Outcome{Status: "ok"}
	blocking, _ := a.integer("num_blocking")
	failed, _ := a.integer("num_non_blocking_error")
	cancelled, _ := a.integer("num_cancelled")
	switch {
	case blocking > 0:
		o.Status, o.Decision, o.DecisionSource = "denied", "deny", "hook"
	case failed > 0:
		o.Status = "error"
	case cancelled > 0:
		o.Status = "interrupted"
	}
	if d, ok := a.integer("total_duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	ev.Outcome = o
	return ev
}

// claudeManagedSettings reports which managed sources a session resolved.
// The settings document itself (managed_settings.settings, values redacted
// by Claude Code) is not copied: posture checks read policy from disk with
// root integrity, and this event is the agent's own account of it.
func (r *rec) claudeManagedSettings() *event.Event {
	ev := r.claudeEvent(event.TypeConfigChange)
	a := r.a
	setLabel(ev, "config_key", "managed_settings")
	trigger := a.str("managed_settings.trigger")
	setLabel(ev, "managed_trigger", trigger)
	// Highest priority first: remote | plist | hklm | file | parent | hkcu.
	setListLabel(ev, "managed_sources", a.names("managed_settings.sources"))
	setLabel(ev, "managed_source_behavior", a.str("managed_settings.source_behavior"))
	setLabel(ev, "helper_state", a.str("managed_settings.helper.state"))
	setLabel(ev, "helper_applied", a.str("managed_settings.helper.applied"))
	setLabel(ev, "helper_entry", a.str("managed_settings.helper.entry"))
	// Only with OTEL_LOG_MANAGED_SETTINGS=1. Machines with the same digest
	// run the same policy.
	setLabel(ev, "managed_settings_sha256", a.str("managed_settings.resolved_sha256"))
	if trigger == "refused" {
		o := &event.Outcome{Status: "denied", Decision: "deny", DecisionSource: "policy"}
		o.Error = labelValue(a.str("error.type"), maxLabel)
		ev.Outcome = o
	}
	return ev
}
