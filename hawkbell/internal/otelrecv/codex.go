package otelrecv

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/toolmap"
)

// Codex events. Names and attributes are from openai/codex main (read
// 2026-11-11): codex-rs/otel/src/events/session_telemetry.rs,
// codex-rs/otel/src/events/shared.rs (the attributes every log event
// carries: conversation.id, app.version, auth_mode, originator,
// user.account_id, user.email, terminal.type, model, slug),
// codex-rs/otel/src/tool_result.rs and codex-rs/otel/README.md.
//
// Codex formats most fields through Display, so numbers and booleans arrive
// as strings; the attrs accessors accept both.

// codexIgnored lists events that are deliberately not converted: transport
// and timing internals, cost accounting and model output.
// UNVERIFIED: guardian_assessment is named in the research report but was not
// found in the files read; it is listed so it is not reported as drift.
var codexIgnored = map[string]bool{
	"api_request": true, "sse_event": true, "websocket_connect": true, "websocket_request": true,
	"auth_recovery": true, "startup_phase": true, "turn_ttft": true, "turn_cost": true,
	"agent_response": true, "guardian_assessment": true,
	"plugin_install_elicitation_sent": true, "plugin_install_suggestion": true,
}

func (r *rec) codex() ([]*event.Event, bool) {
	var ev *event.Event
	a := r.a
	switch r.name {
	case "conversation_starts":
		ev = r.codexEvent(event.TypeSessionStart)
		approval := a.str("approval_policy") // untrusted | on-request | granular | never
		sandbox := a.str("sandbox_policy")   // read-only | workspace-write | external-sandbox | danger-full-access
		// Same label names as the transcript surface uses for these knobs.
		setLabel(ev, "approval_policy", approval)
		setLabel(ev, "sandbox", sandbox)
		ev.Session.PermissionMode = codexMode(approval, sandbox)
		setLabel(ev, "model_provider", a.str("provider_name"))
		// Logged as one string, names joined with ", ".
		setListLabel(ev, "mcp_servers", a.names("mcp_servers"))
	case "user_prompt":
		ev = r.codexEvent(event.TypePromptSubmit)
		// "[REDACTED]" unless otel.log_user_prompt is set.
		setPrompt(ev, a, "prompt")
	case "tool_decision":
		ev = r.codexEvent(event.TypePermissionDecision)
		r.codexTool(ev, nil)
		ev.Outcome = codexDecision(ev, a.str("decision"), a.str("source"))
	case "tool_result":
		ev = r.codexToolResult()
	case "sandbox_outcome":
		ev = r.codexSandboxOutcome()
	case "skill_invocation":
		ev = r.codexEvent(event.TypeNotification)
		setLabel(ev, "skill", a.str("skill.name"))
		setLabel(ev, "skill_trigger", a.str("skill.invocation_type")) // explicit | implicit
		setLabel(ev, "skill_source", a.str("skill.scope"))
		setLabel(ev, "plugin", a.str("skill.plugin_id"))
	default:
		return nil, codexIgnored[r.name]
	}
	return []*event.Event{ev}, true
}

func (r *rec) codexEvent(typ string) *event.Event {
	ev := r.newEvent(typ)
	a := r.a
	ev.Session.Model = field(ev, "session.model", a.str("model"), maxName)
	ev.Session.TurnID = field(ev, "session.turn_id", a.str("turn.id"), maxID)
	// The client that embeds Codex (CLI, IDE extension, app server).
	// UNVERIFIED: the set of originator values, so no surface is derived.
	setLabel(ev, "originator", a.str("originator"))
	setLabel(ev, "auth_mode", a.str("auth_mode"))
	return ev
}

// codexMode maps Codex's two knobs onto the event permission vocabulary the
// same way the transcript surface does: never ask plus no sandbox is the
// documented bypass (--dangerously-bypass-approvals-and-sandbox); never ask
// alone is dont_ask.
func codexMode(approval, sandbox string) string {
	switch {
	case approval == "never" && sandbox == "danger-full-access":
		return "bypass"
	case approval == "never":
		return "dont_ask"
	case approval == "" && sandbox == "":
		return ""
	}
	return "default"
}

// codexDefaultNamespace is the namespace of top-level function tools
// (codex-rs/protocol/src/tool_name.rs, DEFAULT_FUNCTION_NAMESPACE).
const codexDefaultNamespace = "functions"

// codexTool fills Tool, Target and Content.ToolInput. Codex logs the tool
// as name plus namespace; an MCP tool has namespace "mcp__<server>__".
func (r *rec) codexTool(ev *event.Event, input map[string]any) {
	a := r.a
	name, ns := a.str("tool_name"), a.str("tool_namespace")
	t := &event.Tool{UseID: field(ev, "tool.use_id", a.str("call_id"), maxID)}
	flat := name
	if name != "" && ns != "" && ns != codexDefaultNamespace {
		flat = ns + name // ToolName's Display form, what hooks and rollouts show
	}
	t.Name = field(ev, "tool.name", flat, maxName)
	if t.Name != "" {
		kind, server, tool := toolmap.KindWithInput(r.agent, t.Name, input)
		if s, tl, ok := toolmap.SplitMCPNamespace(ns, name); ok {
			kind, server, tool = event.ToolMCP, s, tl
		}
		// tool_result names the server outright.
		if s := a.str("mcp_server"); s != "" {
			kind, server = event.ToolMCP, s
			if tool == "" {
				tool = name
			}
		}
		t.Kind = kind
		t.MCPServer, _ = cleanID(server, maxName)
		t.MCPTool, _ = cleanID(tool, maxName)
	}
	if input != nil {
		content(ev).ToolInput = input
		t.InputKeys = toolmap.InputKeys(input)
		// Codex logs the arguments whole, so the hash is comparable with
		// the hook and transcript surfaces.
		t.InputSHA256 = toolmap.InputHash(input)
		ev.Target = toolmap.Target(r.agent, t.Name, t.Kind, input)
	}
	ev.Tool = t
}

// codexDecision maps ReviewDecision::to_opaque_string
// (codex-rs/protocol/src/protocol.rs) and ToolDecisionSource. The source is
// logged through Display, which renders the variant name ("Config"), while
// its serde form is snake_case; both are accepted.
func codexDecision(ev *event.Event, decision, source string) *event.Outcome {
	o := &event.Outcome{}
	switch decision {
	case "approved", "approved_with_amendment", "approved_for_session",
		"approved_mcp_policy_amendment", "approved_with_network_policy_allow":
		o.Decision = "allow"
	case "denied", "denied_with_network_policy_deny":
		o.Decision, o.Status = "deny", "denied"
	case "timed_out":
		// Nobody answered: the call does not run.
		o.Decision, o.Status = "deny", "denied"
	case "abort":
		o.Decision, o.Status = "deny", "interrupted"
	default:
		o.Status = "unknown"
	}
	setLabel(ev, "decision_raw", decision)
	switch strings.ToLower(strings.ReplaceAll(source, "_", "")) {
	case "user":
		o.DecisionSource = "user"
	case "config", "automatedreviewer":
		o.DecisionSource = "policy"
	}
	setLabel(ev, "decision_source", source)
	return o
}

func (r *rec) codexToolResult() *event.Event {
	ev := r.codexEvent(event.TypeToolPost)
	a := r.a
	// arguments is the call's argument string: JSON for function tools,
	// plain text for freeform tools such as apply_patch.
	r.codexTool(ev, toolInputFromText(ev, a.str("arguments"), "input"))
	o := &event.Outcome{}
	setOutcomeStatus(o, a)
	if d, ok := a.integer("duration_ms"); ok && d >= 0 {
		o.DurationMS = d
	}
	ev.Outcome = o
	// output is a preview bounded by the operator's tool-result log limit;
	// output_truncated says whether that limit removed text.
	if out, ok := a.text("output"); ok && out != "" && !isRedacted(out) {
		content(ev).ToolOutput = out
		if cut, _ := a.boolean("output_truncated"); cut {
			ev.Truncated = appendUnique(ev.Truncated, "tool.output")
		} else {
			ev.Tool.OutputLen = len(out)
		}
	}
	setLabel(ev, "mcp_server_origin", a.str("mcp_server_origin"))
	return ev
}

// codexSandboxOutcome reports what the sandbox did with a tool call:
// denied | timed_out | signal | escalated (codex-rs/core/src/tools/
// orchestrator.rs). "escalated" means the command failed inside the sandbox
// and was then run again without it. It is a notification, not a second
// tool.post: codex.tool_result reports the call itself.
func (r *rec) codexSandboxOutcome() *event.Event {
	ev := r.codexEvent(event.TypeNotification)
	a := r.a
	r.codexTool(ev, nil)
	outcome := a.str("outcome")
	setLabel(ev, "sandbox_outcome", outcome)
	o := &event.Outcome{}
	switch outcome {
	case "denied":
		o.Status, o.Decision, o.DecisionSource = "denied", "deny", "policy"
	case "timed_out", "signal":
		o.Status = "error"
		o.Error = "sandbox_" + outcome
	case "escalated":
		o.Status = "ok"
		setLabel(ev, "sandbox_bypass", "1")
	default:
		o.Status = "unknown"
	}
	var total int64
	for _, k := range []string{"initial_duration_ms", "escalated_duration_ms"} {
		if d, ok := a.integer(k); ok && d > 0 {
			total += d
		}
	}
	o.DurationMS = total
	ev.Outcome = o
	return ev
}
