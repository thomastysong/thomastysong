package hookcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

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
	// encoding/json tolerates invalid UTF-8 inside strings; JSON text
	// exchanged between programs must be UTF-8 (RFC 8259), and a healthy
	// worker's encoder never produces anything else.
	if t[0] != '{' || !utf8.Valid(t) || !json.Valid(t) {
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

// render produces the reply for a decision: Dialect.Respond's stdout,
// passed through. Every dialect, Codex included, renders a decision as JSON
// on exit 0 (hookio's reply table; for Codex the forms checked against
// openai/codex main on 2026-11-12, see the package doc). A non-zero exit
// from a dialect comes only from hookio's own panic fallback (exit 2 with a
// fixed reason on stderr); exit 2 is also what the Go runtime exits with
// on a fatal error, so it is never forwarded: the reply is reported as not
// renderable and the supervisor answers instead.
func render(d hookio.Dialect, req *hookio.Request, dec hookio.Decision) (reply []byte, ok bool) {
	defer func() {
		if recover() != nil {
			reply, ok = nil, false
		}
	}()
	if d == nil || req == nil || dec.Action == hookio.ActionNone || dec.Action == "" {
		return nil, true
	}
	stdout, _, code := d.Respond(req, dec)
	if code != 0 {
		return nil, false
	}
	return stdout, true
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
