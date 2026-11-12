package hookio

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// copilot implements the GitHub Copilot CLI hook wire, which the Copilot
// harness in VS Code and the Copilot app share.
//
// Two payload formats exist, selected by how the event name is spelled in
// the hook config (github/docs content/copilot/reference/hooks-reference.md):
//
//   - camelCase name (preToolUse): camelCase fields sessionId, timestamp (ms),
//     cwd, toolName, toolArgs. The payload does NOT carry the event name.
//   - PascalCase name (PreToolUse): snake_case fields hook_event_name,
//     session_id, timestamp (ISO 8601), cwd, tool_name, tool_input, with tool
//     names translated to Claude's (bash -> Bash, view -> Read ...).
//
// Both are parsed, including the mixed form the older VS Code harness sends
// (hook_event_name next to sessionId). hawkbell registers the PascalCase names
// so payloads are self-describing; for camelCase payloads the name comes
// from EnvHookEvent or, failing that, from the payload's shape.
type copilot struct{}

func (copilot) id() string      { return "copilot" }
func (copilot) agentID() string { return AgentCopilot }

// copilotKind is the dialect's canonical event, independent of spelling.
type copilotKind int

const (
	cpUnknown copilotKind = iota
	cpSessionStart
	cpSessionEnd
	cpPrompt
	cpPromptTransformed
	cpPreTool
	cpPostTool
	cpPostToolFailure
	cpPermissionRequest
	cpAgentStop
	cpSubagentStart
	cpSubagentStop
	cpError
	cpPreCompact
	cpNotification
)

// copilotKinds is keyed by the lower-cased event name, which folds the
// camelCase and PascalCase spellings together; the two spellings that differ
// by more than case (userPromptSubmitted/UserPromptSubmit, agentStop/Stop)
// are both listed.
var copilotKinds = map[string]copilotKind{
	"sessionstart":          cpSessionStart,
	"sessionend":            cpSessionEnd,
	"userpromptsubmitted":   cpPrompt,
	"userpromptsubmit":      cpPrompt,
	"userprompttransformed": cpPromptTransformed,
	"pretooluse":            cpPreTool,
	"posttooluse":           cpPostTool,
	"posttoolusefailure":    cpPostToolFailure,
	"permissionrequest":     cpPermissionRequest,
	"agentstop":             cpAgentStop,
	"stop":                  cpAgentStop,
	"subagentstart":         cpSubagentStart,
	"subagentstop":          cpSubagentStop,
	"erroroccurred":         cpError,
	"precompact":            cpPreCompact,
	"notification":          cpNotification,
}

var copilotTypes = map[copilotKind]string{
	cpSessionStart:      event.TypeSessionStart,
	cpSessionEnd:        event.TypeSessionEnd,
	cpPrompt:            event.TypePromptSubmit,
	cpPromptTransformed: event.TypePromptSubmit,
	cpPreTool:           event.TypeToolPre,
	cpPostTool:          event.TypeToolPost,
	cpPostToolFailure:   event.TypeToolPost,
	cpPermissionRequest: event.TypePermissionDecision,
	cpAgentStop:         event.TypeTurnEnd,
	cpSubagentStart:     event.TypeSubagentStart,
	cpSubagentStop:      event.TypeSubagentStop,
	cpError:             event.TypeNotification,
	cpPreCompact:        event.TypeCompact,
	cpNotification:      event.TypeNotification,
}

func (c copilot) build(p obj, env map[string]string, raw []byte) ([]*event.Event, *Request, error) {
	name := p.str("hook_event_name", "hookEventName")
	inferred := false
	if name == "" {
		name = envGet(env, EnvHookEvent)
	}
	if name == "" {
		name = inferCopilotEvent(p)
		inferred = name != ""
	}
	name, _ = cleanID(name, 64)
	req := &Request{AgentID: AgentCopilot, EventName: name, Raw: p}
	if name == "" {
		return nil, req, ErrNoEvent
	}
	kind := copilotKinds[strings.ToLower(name)]
	ev := newEvent(AgentCopilot, copilotTypes[kind], name, raw)
	if kind == cpUnknown {
		unknownEvent(ev)
	}
	if inferred {
		label(ev, "hook_inferred", "1")
	}
	applySession(ev, sessionFields{
		id:            p.str("sessionId", "session_id"),
		cwd:           p.str("cwd"),
		transcript:    p.str("transcriptPath", "transcript_path"),
		subagentID:    p.str("agentId", "agent_id"),
		subagentType:  p.str("agentType", "agent_type", "agentName", "agent_name"),
		parentAgentID: p.str("parentAgentId", "parent_agent_id"),
		agentSurface:  copilotSurface(env),
	})

	switch kind {
	case cpSessionStart:
		enumLabel(ev, "session_source", p.str("source"))
	case cpSessionEnd:
		enumLabel(ev, "end_reason", p.str("reason"))
	case cpPrompt:
		// Command-hook output is dropped for this event, so a prompt cannot
		// be blocked from a hook (hooks reference, userPromptSubmitted).
		setPrompt(ev, p.str("prompt"))
	case cpPromptTransformed:
		setPrompt(ev, p.str("transformedPrompt", "transformed_prompt", "prompt"))
		label(ev, "prompt_kind", "transformed")
	case cpPreTool:
		c.tool(ev, p)
		req.Blocking = true
	case cpPermissionRequest:
		c.tool(ev, p)
		ev.Outcome = &event.Outcome{Decision: "ask", DecisionSource: "policy"}
		req.Blocking = true
	case cpPostTool:
		c.tool(ev, p)
		res := p.sub("toolResult", "tool_result")
		if len(res) > 0 {
			setOutput(ev, map[string]any(res))
		}
		ev.Outcome = &event.Outcome{Status: copilotStatus(res.str("resultType", "result_type"))}
	case cpPostToolFailure:
		c.tool(ev, p)
		ev.Outcome = failure(ev, p.str("error"), false)
	case cpAgentStop:
		enumLabel(ev, "stop_reason", p.str("stopReason", "stop_reason"))
	case cpSubagentStop:
		enumLabel(ev, "stop_reason", p.str("stopReason", "stop_reason"))
		ev.Content.ToolOutput = p.str("response", "last_assistant_message")
	case cpError:
		// error.message and error.stack are free text; only the error class
		// and where it happened are emitted.
		enumLabel(ev, "error_context", p.str("errorContext", "error_context"))
		ev.Outcome = &event.Outcome{Status: "error", Error: token(p.sub("error").str("name"))}
	case cpPreCompact:
		label(ev, "compact_phase", "pre")
		enumLabel(ev, "compact_trigger", p.str("trigger"))
	case cpNotification:
		enumLabel(ev, "notification_type", p.str("notification_type", "notificationType"))
	}
	return []*event.Event{ev}, req, nil
}

func (copilot) tool(ev *event.Event, p obj) {
	// The reference types toolArgs as unknown and describes the snake_case
	// tool_input as "parsed from JSON string when possible", so the
	// camelCase form can arrive as a JSON-encoded string; setTool decodes
	// either form. The permission request text refers to toolInput.
	args, _ := p.raw("toolArgs", "tool_input", "toolInput", "tool_args")
	// UNVERIFIED: Copilot documents no tool-call id in hook payloads; these
	// keys are read only so an id is not lost if one is added.
	useID := p.str("toolCallId", "tool_call_id", "tool_use_id")
	setTool(ev, AgentCopilot, p.str("toolName", "tool_name"), args, useID)
	// A request to leave the sandbox is a privilege escalation the user
	// must confirm (hooks reference, permissionRequest decision control).
	if bypass, _ := obj(ev.Content.ToolInput).boolean("requestSandboxBypass"); bypass {
		label(ev, "sandbox_bypass", "1")
	}
}

// copilotStatus maps toolResult.resultType. Only "success" is documented for
// postToolUse (and "failure" for a rewritten result).
// UNVERIFIED: "error", "denied" and "rejected" as result types.
func copilotStatus(resultType string) string {
	switch strings.ToLower(resultType) {
	case "success":
		return "ok"
	case "failure", "error":
		return "error"
	case "denied", "rejected":
		return "denied"
	case "":
		return "ok" // postToolUse fires only after a successful call
	}
	return "unknown"
}

// copilotSurface tells Copilot's hosts apart. They share one hook config
// and send identical payloads, so the inherited environment is the only
// signal: AI_AGENT=github_copilot_vscode_agent inside VS Code,
// github_copilot_app_agent for the desktop app, COPILOT_CLI for the CLI.
// (Signals as used by snyk/agent-scan's hook forwarder, Apache-2.0.)
func copilotSurface(env map[string]string) string {
	agent := envGet(env, "AI_AGENT")
	switch {
	case agent == "github_copilot_vscode_agent":
		return "ide"
	case agent == "github_copilot_app_agent":
		return "desktop"
	case strings.HasPrefix(agent, "github_copilot_"), envGet(env, "COPILOT_CLI") != "":
		return "cli"
	}
	return ""
}

// inferCopilotEvent names the event of a camelCase payload from the fields
// only that event has, following the documented input shapes. It is the last
// resort when neither the payload nor EnvHookEvent names the event.
func inferCopilotEvent(p obj) string {
	hasTool := p.has("toolName") || p.has("tool_name")
	switch {
	case p.has("notification_type"), p.has("notificationType"):
		return "notification"
	case hasTool && (p.has("toolResult") || p.has("tool_result")):
		return "postToolUse"
	case hasTool && p.isString("error"):
		return "postToolUseFailure"
	case hasTool && p.has("toolInput") && !p.has("toolArgs"):
		// UNVERIFIED: the permissionRequest input is not spelled out in the
		// reference, which only refers to its toolName and toolInput.
		return "permissionRequest"
	case hasTool:
		return "preToolUse"
	case p.has("transformedPrompt"):
		return "userPromptTransformed"
	case p.has("prompt"):
		return "userPromptSubmitted"
	case p.has("errorContext"), p.has("error_context"), p.isObject("error"):
		return "errorOccurred"
	case p.has("trigger"):
		return "preCompact"
	case p.has("stopReason") || p.has("stop_reason"):
		if p.has("agentName") || p.has("agentId") || p.has("response") {
			return "subagentStop"
		}
		return "agentStop"
	case p.has("agentName"):
		return "subagentStart"
	case p.has("source"):
		return "sessionStart"
	case p.has("reason"):
		return "sessionEnd"
	}
	return ""
}

// Copilot's decision objects are flat (no hookSpecificOutput wrapper).
type copilotReply struct {
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	Behavior                 string `json:"behavior,omitempty"`
	Message                  string `json:"message,omitempty"`
	// HookSpecificOutput repeats the decision in Claude's nested form for
	// PascalCase registrations. UNVERIFIED that Copilot reads it: the
	// PascalCase names exist for Claude Code plugin compatibility and those
	// plugins reply in this form; the flat fields are the documented ones.
	// Copilot ignores unsupported verdict fields, so the repeat is harmless.
	HookSpecificOutput *hookSpecific `json:"hookSpecificOutput,omitempty"`
}

func (copilot) respond(req *Request, d Decision) ([]byte, []byte, int) {
	if !req.Blocking {
		return proceed()
	}
	kind := copilotKinds[strings.ToLower(req.EventName)]
	pascal := req.EventName != "" && req.EventName[0] >= 'A' && req.EventName[0] <= 'Z'
	msg := reason(d)
	var out copilotReply
	switch kind {
	case cpPreTool:
		// Exit 0 with a flat decision object. A non-zero exit also denies,
		// but carries no reason for the agent.
		out.PermissionDecision = d.Action
		if d.Action != ActionAllow {
			out.PermissionDecisionReason = msg
		}
		if d.Action == ActionDeny && !pascal {
			// A camelCase payload names no event, so a permissionRequest can
			// be mistaken for preToolUse; adding its deny fields makes the
			// block hold either way. Only for deny: the block must not fail
			// open, whereas a lost ask or allow just falls back to the
			// normal permission flow.
			out.Behavior, out.Message = "deny", msg
		}
		if pascal {
			out.HookSpecificOutput = &hookSpecific{
				HookEventName:            "PreToolUse",
				PermissionDecision:       d.Action,
				PermissionDecisionReason: out.PermissionDecisionReason,
			}
		}
	case cpPermissionRequest:
		switch d.Action {
		case ActionDeny:
			out.Behavior, out.Message = "deny", msg
		case ActionAllow:
			out.Behavior = "allow"
		default:
			// ask: returning nothing falls through to the normal flow,
			// which prompts the user.
			return proceed()
		}
		if pascal {
			out.HookSpecificOutput = &hookSpecific{
				HookEventName: "PermissionRequest",
				Decision:      &permBehavior{Behavior: out.Behavior, Message: out.Message},
			}
		}
	default:
		return proceed()
	}
	return jsonLine(out), nil, 0
}

func (copilot) events() []HookEvent {
	// Copilot has no background-hook option, so nothing is Async. The
	// PascalCase spellings select the self-describing snake_case payload
	// (the spelling Endor Labs' and Snyk's managed policies use as well).
	return []HookEvent{
		{Name: "SessionStart"},
		{Name: "UserPromptSubmit"},
		{Name: "PreToolUse", Blocking: true},
		// UNVERIFIED: the PascalCase PermissionRequest payload; the name
		// itself is documented (Claude-format matchers).
		{Name: "PermissionRequest", Blocking: true},
		{Name: "PostToolUse"},
		{Name: "PostToolUseFailure"},
		// The reference documents subagentStart in camelCase only, so the
		// documented spelling is used. Its payload names no event; it is
		// recognized by agentName without stopReason, or by EnvHookEvent.
		{Name: "subagentStart"},
		{Name: "SubagentStop"},
		{Name: "Stop"},
		{Name: "PreCompact"},
		{Name: "ErrorOccurred"},
		{Name: "SessionEnd"},
	}
}
