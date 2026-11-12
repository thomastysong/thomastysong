package hookcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/thomastysong/spoor/internal/hookio"
)

// validReply reports whether out is something the supervisor may forward:
// empty (the agent proceeds unchanged), or exactly one complete JSON object
// of at most max bytes with nothing but whitespace around it. A worker that
// crashed mid-write leaves a prefix, and no proper prefix of a JSON object
// is itself a complete object, so a partial reply is always refused.
func validReply(out []byte, max int) (reply []byte, ok bool) {
	if len(out) > max {
		return nil, false
	}
	t := bytes.TrimSpace(out)
	if len(t) == 0 {
		return nil, true
	}
	if t[0] != '{' || !json.Valid(t) {
		return nil, false
	}
	// json.Valid accepts exactly one value, so a second object or trailing
	// bytes already fail above; this keeps the check explicit.
	dec := json.NewDecoder(bytes.NewReader(t))
	var raw json.RawMessage
	if dec.Decode(&raw) != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return append(append([]byte(nil), t...), '\n'), true
}

// eventNameOf is the hook event name for the supervisor's fallback reply:
// the payload's own field, else --event, else SPOOR_HOOK_EVENT. It is read
// with topLevelStrings, not with the dialect parser that may just have
// crashed the worker.
func eventNameOf(payload []byte, flagEvent string, getenv func(string) string) string {
	f := topLevelStrings(payload, "hook_event_name", "hookEventName")
	name := f["hook_event_name"]
	if name == "" {
		name = f["hookEventName"]
	}
	if name == "" {
		name = flagEvent
	}
	if name == "" && getenv != nil {
		name = getenv(hookio.EnvHookEvent)
	}
	if t := token(name, 64); t != "other" {
		return t
	}
	return ""
}

// fallbackRequest builds the Request a dialect needs to render a reply
// without parsing the payload. Blocking comes from the dialect's own list of
// events it gates; an event spoor does not register as blocking gets no
// reply, which every agent reads as "proceed".
func fallbackRequest(d hookio.Dialect, eventName string) *hookio.Request {
	if d == nil || eventName == "" {
		return nil
	}
	agentID, _ := hookio.AgentIDFor(d.ID())
	req := &hookio.Request{AgentID: agentID, EventName: eventName}
	for _, he := range d.Events() {
		// Case-insensitive: Copilot sends camelCase names (preToolUse) for
		// the PascalCase events spoor registers, and no dialect has two
		// events differing only in case.
		if strings.EqualFold(he.Name, eventName) && he.Blocking {
			req.Blocking = true
			break
		}
	}
	return req
}

// render produces the reply for a decision. It differs from Dialect.Respond
// in one place: a Codex block. hookio renders that as exit 2 with the
// reason on stderr, but exit 2 is also what the Go runtime exits with on a
// fatal error, so the hook never uses it. Codex accepts a JSON block on
// exit 0 for every event it gates (openai/codex main,
// codex-rs/hooks/src/events/pre_tool_use.rs, user_prompt_submit.rs and
// permission_request.rs, read 2026-11-12):
//
//	PreToolUse        hookSpecificOutput.permissionDecision "deny" + permissionDecisionReason
//	UserPromptSubmit  decision "block" + reason
//	PermissionRequest hookSpecificOutput.decision.behavior "deny" + message
//
// Any other non-zero exit from a dialect (hookio's own panic fallback) is
// reported as not renderable, so the supervisor answers instead.
func render(d hookio.Dialect, req *hookio.Request, dec hookio.Decision) (reply []byte, ok bool) {
	defer func() {
		if recover() != nil {
			reply, ok = nil, false
		}
	}()
	if d == nil || req == nil || dec.Action == hookio.ActionNone || dec.Action == "" {
		return nil, true
	}
	stdout, stderr, code := d.Respond(req, dec)
	if code == 0 {
		return stdout, true
	}
	if d.ID() != "codex" || dec.Action != hookio.ActionDeny {
		return nil, false
	}
	msg := string(bytes.TrimSpace(stderr))
	if msg == "" {
		msg = "spoor: blocked by policy"
	}
	switch req.EventName {
	case "PreToolUse":
		return jsonLine(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": msg,
		}}), true
	case "UserPromptSubmit":
		return jsonLine(map[string]any{"decision": "block", "reason": msg}), true
	case "PermissionRequest":
		return jsonLine(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PermissionRequest", "decision": map[string]any{"behavior": "deny", "message": msg},
		}}), true
	}
	return nil, false
}

func jsonLine(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil
	}
	return buf.Bytes()
}

// replyCarries reports whether a rendered reply actually hands the agent
// the decision (deny or ask) rather than a degraded form of it. Codex and
// Gemini cannot ask, and several events cannot be gated at all: there the
// reply is a warning or nothing, and the detection must not claim it was
// enforced.
func replyCarries(reply []byte, action string) bool {
	if len(bytes.TrimSpace(reply)) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(reply, &m) != nil {
		return false
	}
	want := func(v any) bool {
		s, _ := v.(string)
		switch action {
		case hookio.ActionDeny:
			return s == "deny" || s == "block"
		case hookio.ActionAsk:
			return s == "ask"
		}
		return false
	}
	if want(m["decision"]) || want(m["permission"]) || want(m["permissionDecision"]) {
		return true
	}
	if action == hookio.ActionDeny {
		if c, ok := m["continue"].(bool); ok && !c {
			return true
		}
		if b, ok := m["behavior"].(string); ok && b == "deny" {
			return true
		}
	}
	if hs, ok := m["hookSpecificOutput"].(map[string]any); ok {
		if want(hs["permissionDecision"]) {
			return true
		}
		if d, ok := hs["decision"].(map[string]any); ok && action == hookio.ActionDeny && d["behavior"] == "deny" {
			return true
		}
	}
	return false
}
