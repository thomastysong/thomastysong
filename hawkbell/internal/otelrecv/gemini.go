package otelrecv

import (
	"path"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/toolmap"
)

// Gemini CLI events. Names and attributes are from google-gemini/gemini-cli
// main (read 2026-11-11): docs/cli/telemetry.md and
// packages/core/src/telemetry/{types.ts,telemetryAttributes.ts,sdk.ts}.
// Every record carries session.id, installation.id, interactive and, when
// signed in, user.email. Gemini sends real booleans and numbers.
//
// Unlike the other two agents, Gemini CLI logs prompts and tool arguments by
// default (telemetry.logPrompts defaults to true).

var geminiIgnored = map[string]bool{
	"api_request": true, "api_response": true, "api_error": true, "malformed_json_response": true,
	"tool_output_truncated": true, "tool_output_masking": true, "edit_strategy": true, "edit_correction": true,
	"file_operation": true, "slash_command": true, "slash_command.model": true, "model_routing": true,
	"chat_compression": true, "chat.invalid_chunk": true, "chat.content_retry": true,
	"chat.content_retry_failure": true, "conversation_finished": true, "flash_fallback": true,
	"ripgrep_fallback": true, "web_fetch_fallback_attempt": true, "agent.recovery_attempt": true,
	"extension_install": true, "extension_uninstall": true, "extension_enable": true,
	"extension_disable": true, "extension_update": true, "ide_connection": true, "rewind": true,
	"conseca.verdict": true, "conseca.policy_generation": true, "keychain.availability": true,
	"startup_stats": true, "plan.approval_mode_duration": true, "approval_mode_duration": true,
	"plan.execution": true, "plan_execution": true, "llm_loop_check": true, "next_speaker_check": true,
	"network_retry_attempt": true, "onboarding.start": true, "onboarding.success": true,
	"token_storage.initialization": true, "kitty_sequence_overflow": true,
	"gen_ai.client.inference.operation.details": true,
}

func (r *rec) gemini() ([]*event.Event, bool) {
	a := r.a
	switch r.name {
	case "config":
		// Emitted once at startup with the effective configuration.
		ev := r.geminiEvent(event.TypeSessionStart)
		ev.Session.Model = field(ev, "session.model", a.str("model"), maxName)
		mode := a.str("approval_mode")
		setLabel(ev, "approval_mode", mode)
		if m := geminiMode(mode); m != "" {
			ev.Session.PermissionMode = m
		}
		setLabel(ev, "sandbox_enabled", a.str("sandbox_enabled"))
		setListLabel(ev, "mcp_servers", a.names("mcp_servers"))
		setLabel(ev, "mcp_servers_count", a.str("mcp_servers_count"))
		setListLabel(ev, "extensions", a.names("extensions"))
		setLabel(ev, "output_format", a.str("output_format"))
		setLabel(ev, "debug_mode", a.str("debug_mode"))
		// True means prompts and tool arguments are being exported.
		setLabel(ev, "log_prompts", a.str("log_user_prompts_enabled"))
		return []*event.Event{ev}, true
	case "user_prompt":
		ev := r.geminiEvent(event.TypePromptSubmit)
		setPrompt(ev, a, "prompt")
		return []*event.Event{ev}, true
	case "tool_call":
		return r.geminiToolCall(), true
	// The wire name is gemini_cli.plan.approval_mode_switch; telemetry.md
	// documents it as approval_mode_switch.
	case "plan.approval_mode_switch", "approval_mode_switch":
		ev := r.geminiEvent(event.TypeConfigChange)
		setLabel(ev, "config_key", "permission_mode")
		setLabel(ev, "from_mode", geminiMode(a.str("from_mode")))
		setLabel(ev, "to_mode", geminiMode(a.str("to_mode")))
		if m := geminiMode(a.str("to_mode")); m != "" {
			ev.Session.PermissionMode = m
		}
		return []*event.Event{ev}, true
	case "hook_call":
		return []*event.Event{r.geminiHookCall()}, true
	case "agent.start":
		ev := r.geminiEvent(event.TypeSubagentStart)
		r.geminiSubagent(ev)
		return []*event.Event{ev}, true
	case "agent.finish":
		ev := r.geminiEvent(event.TypeSubagentStop)
		r.geminiSubagent(ev)
		ev.Outcome = &event.Outcome{Status: "ok"}
		if d, ok := a.integer("duration_ms"); ok && d >= 0 {
			ev.Outcome.DurationMS = d
		}
		setLabel(ev, "terminate_reason", a.str("terminate_reason"))
		return []*event.Event{ev}, true
	}
	return nil, geminiIgnored[r.name]
}

func (r *rec) geminiEvent(typ string) *event.Event {
	ev := r.newEvent(typ)
	a := r.a
	// prompt_id ties a prompt to the tool calls made while answering it.
	ev.Session.TurnID = field(ev, "session.turn_id", a.str("prompt_id"), maxID)
	// UNVERIFIED: telemetry.md lists active_approval_mode as a common
	// attribute; getCommonAttributes on main does not set it. Used if present.
	ev.Session.PermissionMode = geminiMode(a.str("active_approval_mode"))
	if inter, ok := a.boolean("interactive"); ok && !inter {
		setLabel(ev, "interactive", "false") // headless run
	}
	setLabel(ev, "auth_type", a.str("auth_type"))
	return ev
}

// geminiMode maps ApprovalMode (packages/core/src/policy/types.ts:
// default | autoEdit | yolo | plan) to the event permission vocabulary.
func geminiMode(s string) string {
	switch s {
	case "":
		return ""
	case "default":
		return "default"
	case "autoEdit", "auto_edit":
		return "accept_edits"
	case "yolo":
		return "bypass"
	case "plan":
		return "plan"
	}
	return permMode(s)
}

func (r *rec) geminiSubagent(ev *event.Event) {
	ev.Session.SubagentID = field(ev, "session.subagent_id", r.a.str("agent_id"), maxID)
	ev.Session.SubagentType = field(ev, "session.subagent_type", r.a.str("agent_name"), maxName)
}

// geminiToolCall converts gemini_cli.tool_call, which Gemini logs once per
// finished call with the user's decision folded in. That is two facts, so it
// can become two events: a permission.decision when a decision was recorded,
// and a tool.post unless the call was rejected and never ran.
//
// The record has no tool-call id, so these events cannot be joined to hook
// or transcript records by Tool.UseID; the engine falls back to its
// content-based key.
func (r *rec) geminiToolCall() []*event.Event {
	a := r.a
	decision := a.str("decision") // accept | reject | modify | auto_accept
	var out []*event.Event
	if decision != "" {
		ev := r.geminiEvent(event.TypePermissionDecision)
		r.geminiTool(ev)
		o := &event.Outcome{}
		switch decision {
		case "accept", "modify":
			o.Decision, o.DecisionSource = "allow", "user"
		case "auto_accept":
			o.Decision, o.DecisionSource = "allow", "policy"
		case "reject":
			o.Decision, o.DecisionSource, o.Status = "deny", "user", "denied"
		default:
			o.Status = "unknown"
		}
		setLabel(ev, "decision_raw", decision)
		ev.Outcome = o
		out = append(out, ev)
	}
	if decision == "reject" {
		return out
	}
	ev := r.geminiEvent(event.TypeToolPost)
	r.geminiTool(ev)
	o := &event.Outcome{}
	setOutcomeStatus(o, a)
	if d, ok := a.integer("duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	// error_type is a category; error and error.message carry the text.
	setError(ev, o, a.str("error_type", "error.type"), a.str("error", "error.message"))
	ev.Outcome = o
	if n, ok := a.count("content_length"); ok {
		ev.Tool.OutputLen = n
	}
	return append(out, ev)
}

func (r *rec) geminiTool(ev *event.Event) {
	a := r.a
	t := &event.Tool{}
	t.Name = field(ev, "tool.name", a.str("function_name"), maxName)
	// function_args is the arguments object pretty-printed into a string;
	// absent when telemetry.logPrompts is false.
	input := toolInputFromText(ev, a.str("function_args"), "_raw")
	if t.Name != "" {
		kind, server, tool := toolmap.KindWithInput(r.agent, t.Name, input)
		// tool_type and mcp_server_name come from the tool registry, which
		// knows the server even when its name contains "_" and the
		// "mcp_<server>_<tool>" form cannot be split unambiguously.
		if srv := a.str("mcp_server_name"); srv != "" || a.str("tool_type") == "mcp" {
			kind = event.ToolMCP
			if srv != "" {
				server = srv
				if rest, ok := strings.CutPrefix(t.Name, "mcp_"+srv+"_"); ok && rest != "" {
					tool = rest
				}
			}
		}
		t.Kind = kind
		t.MCPServer, _ = cleanID(server, maxName)
		t.MCPTool, _ = cleanID(tool, maxName)
	}
	if input != nil {
		content(ev).ToolInput = input
		t.InputKeys = toolmap.InputKeys(input)
		t.InputSHA256 = toolmap.InputHash(input)
		ev.Target = toolmap.Target(r.agent, t.Name, t.Kind, input)
	}
	setLabel(ev, "extension", a.str("extension_name"))
	ev.Tool = t
}

// geminiHookCall reports one hook execution. With prompt logging on,
// hook_name is the hook's full command line, which can hold credentials, so
// only the program name is kept; hook_input, hook_output, stdout and stderr
// are not copied at all.
func (r *rec) geminiHookCall() *event.Event {
	ev := r.geminiEvent(event.TypeNotification)
	a := r.a
	setLabel(ev, LabelHookEvent, a.str("hook_event_name"))
	setLabel(ev, "hook_type", a.str("hook_type"))
	setLabel(ev, "hook_name", programName(a.str("hook_name")))
	setLabel(ev, LabelHookRuns, "1")
	o := &event.Outcome{}
	setOutcomeStatus(o, a)
	if d, ok := a.integer("duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	if code, ok := a.integer("exit_code"); ok && code >= -1<<31 && code < 1<<31 {
		c := int(code)
		o.ExitCode = &c
	}
	ev.Outcome = o
	return ev
}

// programName reduces a command line to the base name of its first word.
func programName(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return path.Base(strings.ReplaceAll(f[0], `\`, "/"))
}
