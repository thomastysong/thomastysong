package hookio

import (
	"bytes"
	"encoding/json"
	"strings"
)

// maxReason bounds the text spoor hands to an agent. Claude Code caps hook
// strings at 10,000 characters and spills longer ones to a file; staying far
// below keeps the reason inline in every agent.
const maxReason = 1024

// reason builds the single-line message shown to the user or the model. It
// is never empty: Codex treats exit 2 without stderr, and a JSON block
// without a reason, as a failed hook and lets the action through
// (codex-rs/hooks/src/events/pre_tool_use.rs, engine/output_parser.rs).
func reason(d Decision) string {
	r := oneLine(d.Reason, maxReason)
	if r == "" {
		switch d.Action {
		case ActionDeny:
			r = "blocked by policy"
		case ActionAsk:
			r = "confirmation required by policy"
		default:
			r = "allowed by policy"
		}
	}
	if !strings.HasPrefix(strings.ToLower(r), "spoor") {
		r = "spoor: " + r
	}
	if id, _ := cleanID(d.RuleID, maxLabel); id != "" {
		r += " [" + oneLine(id, maxLabel) + "]"
	}
	return r
}

// jsonLine serializes a reply as one line of JSON. HTML escaping is off so
// the reason reads naturally in a terminal; the output is still valid JSON.
func jsonLine(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return buf.Bytes()
}

// proceed is the reply that leaves the agent's own flow untouched.
func proceed() ([]byte, []byte, int) { return nil, nil, 0 }

// exitBlock is the exit-code form of a block: code 2 with the reason on
// stderr. Claude Code, Codex, Copilot (preToolUse, permissionRequest) and
// Gemini document it; it carries no stdout so nothing can be misparsed.
func exitBlock(msg string) ([]byte, []byte, int) {
	return nil, []byte(msg + "\n"), 2
}

// warn is the non-blocking degrade for "ask" where an agent cannot ask: the
// universal systemMessage field, which Claude Code, Codex and Gemini show to
// the user without affecting the action.
func warn(msg string) ([]byte, []byte, int) {
	return jsonLine(struct {
		SystemMessage string `json:"systemMessage"`
	}{msg}), nil, 0
}

// Reply shapes shared by the Claude-compatible wire (Claude Code, Codex, and
// Copilot's PascalCase aliases).

type hookSpecific struct {
	HookEventName            string        `json:"hookEventName"`
	PermissionDecision       string        `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string        `json:"permissionDecisionReason,omitempty"`
	Decision                 *permBehavior `json:"decision,omitempty"`
}

type permBehavior struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

type preToolReply struct {
	HookSpecificOutput hookSpecific `json:"hookSpecificOutput"`
}

type blockReply struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}
