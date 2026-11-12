package hookio

import (
	"strings"
	"testing"
)

// reply runs the full round trip: parse a recorded payload, then render a
// decision for it.
func reply(t *testing.T, id, file string, env map[string]string, d Decision) (map[string]any, string, int) {
	t.Helper()
	dl := dialect(t, id)
	_, req, err := dl.Parse(fixture(t, file), env)
	if err != nil {
		t.Fatalf("Parse %s: %v", file, err)
	}
	stdout, stderr, code := dl.Respond(req, d)
	if len(stdout) == 0 {
		return nil, string(stderr), code
	}
	return decodeReply(t, stdout), string(stderr), code
}

func hso(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	h, ok := m["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("no hookSpecificOutput in %v", m)
	}
	return h
}

var (
	deny  = Decision{Action: ActionDeny, Reason: "reads an SSH private key", RuleID: "SP-0042"}
	ask   = Decision{Action: ActionAsk, Reason: "network egress to a paste site", RuleID: "SP-0100"}
	allow = Decision{Action: ActionAllow}
	none  = Decision{Action: ActionNone}
)

const (
	denyMsg = "spoor: reads an SSH private key [SP-0042]"
	askMsg  = "spoor: network egress to a paste site [SP-0100]"
)

func TestRespondClaude(t *testing.T) {
	// PreToolUse: hookSpecificOutput.permissionDecision on exit 0.
	m, stderr, code := reply(t, "claude", "claude/PreToolUse.json", nil, deny)
	h := hso(t, m)
	eq(t, "exit", code, 0)
	eq(t, "stderr", stderr, "")
	eq(t, "hookEventName", h["hookEventName"], "PreToolUse")
	eq(t, "permissionDecision", h["permissionDecision"], "deny")
	eq(t, "permissionDecisionReason", h["permissionDecisionReason"], denyMsg)
	if _, legacy := m["decision"]; legacy {
		t.Error("PreToolUse must not use the deprecated top-level decision")
	}

	m, _, code = reply(t, "claude", "claude/PreToolUse.json", nil, ask)
	eq(t, "ask exit", code, 0)
	eq(t, "ask decision", hso(t, m)["permissionDecision"], "ask")
	eq(t, "ask reason", hso(t, m)["permissionDecisionReason"], askMsg)

	m, _, _ = reply(t, "claude", "claude/PreToolUse.json", nil, allow)
	eq(t, "allow decision", hso(t, m)["permissionDecision"], "allow")

	// UserPromptSubmit: top-level decision "block".
	m, _, code = reply(t, "claude", "claude/UserPromptSubmit.json", nil, deny)
	eq(t, "prompt exit", code, 0)
	eq(t, "prompt decision", m["decision"], "block")
	eq(t, "prompt reason", m["reason"], denyMsg)
	// A prompt cannot be "asked": warn the user, do not block.
	m, _, code = reply(t, "claude", "claude/UserPromptSubmit.json", nil, ask)
	eq(t, "prompt ask exit", code, 0)
	eq(t, "prompt ask warns", m["systemMessage"], askMsg)
	if _, blocked := m["decision"]; blocked {
		t.Error("ask on a prompt must not block")
	}
	m, _, _ = reply(t, "claude", "claude/UserPromptSubmit.json", nil, allow)
	if m != nil {
		t.Errorf("allow on a prompt must print nothing, got %v", m)
	}

	// PermissionRequest: decision.behavior; exit 2 is not honoured there.
	m, _, code = reply(t, "claude", "claude/PermissionRequest.json", nil, deny)
	dec := hso(t, m)["decision"].(map[string]any)
	eq(t, "permission exit", code, 0)
	eq(t, "permission behavior", dec["behavior"], "deny")
	eq(t, "permission message", dec["message"], denyMsg)
	m, _, _ = reply(t, "claude", "claude/PermissionRequest.json", nil, allow)
	eq(t, "permission allow", hso(t, m)["decision"].(map[string]any)["behavior"], "allow")
	m, _, _ = reply(t, "claude", "claude/PermissionRequest.json", nil, ask)
	if m != nil {
		t.Errorf("ask on a permission request must print nothing, got %v", m)
	}

	// ConfigChange can be blocked.
	m, _, _ = reply(t, "claude", "claude/ConfigChange.json", nil, deny)
	eq(t, "config decision", m["decision"], "block")
}

func TestRespondCodex(t *testing.T) {
	// Exit 2 with the reason on stderr is the block; nothing on stdout.
	for _, f := range []string{"codex/PreToolUse.json", "codex/UserPromptSubmit.json", "codex/PermissionRequest.json"} {
		m, stderr, code := reply(t, "codex", f, nil, deny)
		eq(t, f+" exit", code, 2)
		eq(t, f+" stderr", stderr, denyMsg+"\n")
		if m != nil {
			t.Errorf("%s: stdout must be empty on a Codex block, got %v", f, m)
		}
	}
	// Codex rejects permissionDecision "ask": degrade to a warning.
	m, stderr, code := reply(t, "codex", "codex/PreToolUse.json", nil, ask)
	eq(t, "ask exit", code, 0)
	eq(t, "ask stderr", stderr, "")
	eq(t, "ask warns", m["systemMessage"], askMsg)
	if len(m) != 1 {
		t.Errorf("ask reply must carry only systemMessage (anything else is invalid for Codex): %v", m)
	}
	// A bare allow is invalid for PreToolUse: print nothing.
	m, _, code = reply(t, "codex", "codex/PreToolUse.json", nil, allow)
	if m != nil || code != 0 {
		t.Errorf("allow on Codex PreToolUse must be silent, got %v exit %d", m, code)
	}
	// PermissionRequest allow is supported.
	m, _, _ = reply(t, "codex", "codex/PermissionRequest.json", nil, allow)
	eq(t, "permission allow", hso(t, m)["decision"].(map[string]any)["behavior"], "allow")
}

// Codex treats exit 2 with empty stderr as a failed hook and lets the call
// through, so a block must always carry text.
func TestRespondCodexBlockAlwaysHasReason(t *testing.T) {
	_, stderr, code := reply(t, "codex", "codex/PreToolUse.json", nil, Decision{Action: ActionDeny})
	eq(t, "exit", code, 2)
	if strings.TrimSpace(stderr) == "" {
		t.Fatal("empty stderr on a Codex block fails open")
	}
	eq(t, "default reason", stderr, "spoor: blocked by policy\n")
}

func TestRespondCopilot(t *testing.T) {
	camel := map[string]string{EnvHookEvent: "preToolUse"}
	m, stderr, code := reply(t, "copilot", "copilot/preToolUse.camel.json", camel, deny)
	eq(t, "exit", code, 0) // any non-zero exit would also deny, but without a reason
	eq(t, "stderr", stderr, "")
	eq(t, "permissionDecision", m["permissionDecision"], "deny")
	eq(t, "permissionDecisionReason", m["permissionDecisionReason"], denyMsg)
	// camelCase payloads name no event; the permissionRequest deny fields
	// ride along so the block holds if the event was misjudged.
	eq(t, "behavior", m["behavior"], "deny")
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Error("camelCase reply must be flat")
	}

	m, _, _ = reply(t, "copilot", "copilot/preToolUse.camel.json", camel, ask)
	eq(t, "ask", m["permissionDecision"], "ask")
	eq(t, "ask reason", m["permissionDecisionReason"], askMsg)
	if _, has := m["behavior"]; has {
		t.Error("ask must not carry a permissionRequest verdict")
	}
	m, _, _ = reply(t, "copilot", "copilot/preToolUse.camel.json", camel, allow)
	eq(t, "allow", m, map[string]any{"permissionDecision": "allow"})

	// PascalCase registration: flat fields plus Claude's nested form.
	m, _, code = reply(t, "copilot", "copilot/PreToolUse.snake.json", nil, deny)
	eq(t, "snake exit", code, 0)
	eq(t, "snake flat", m["permissionDecision"], "deny")
	eq(t, "snake nested", hso(t, m)["permissionDecision"], "deny")
	eq(t, "snake nested reason", hso(t, m)["permissionDecisionReason"], denyMsg)

	// permissionRequest: behavior / message.
	pr := map[string]string{EnvHookEvent: "permissionRequest"}
	m, _, _ = reply(t, "copilot", "copilot/permissionRequest.camel.json", pr, deny)
	eq(t, "pr deny", m, map[string]any{"behavior": "deny", "message": denyMsg})
	m, _, _ = reply(t, "copilot", "copilot/permissionRequest.camel.json", pr, allow)
	eq(t, "pr allow", m, map[string]any{"behavior": "allow"})
	m, _, _ = reply(t, "copilot", "copilot/permissionRequest.camel.json", pr, ask)
	if m != nil {
		t.Errorf("ask on permissionRequest must fall through, got %v", m)
	}

	// Prompt hooks cannot block in Copilot: always silent.
	m, _, code = reply(t, "copilot", "copilot/UserPromptSubmit.snake.json", nil, deny)
	if m != nil || code != 0 {
		t.Errorf("Copilot prompt deny must be silent, got %v exit %d", m, code)
	}
}

func TestRespondGemini(t *testing.T) {
	for _, f := range []string{"gemini/BeforeTool.json", "gemini/BeforeAgent.json"} {
		m, stderr, code := reply(t, "gemini", f, nil, deny)
		eq(t, f+" exit", code, 0)
		eq(t, f+" stderr", stderr, "")
		eq(t, f+" reply", m, map[string]any{"decision": "deny", "reason": denyMsg})
		// No ask in Gemini: warn only.
		m, _, _ = reply(t, "gemini", f, nil, ask)
		eq(t, f+" ask", m, map[string]any{"systemMessage": askMsg})
	}
	m, _, _ := reply(t, "gemini", "gemini/BeforeTool.json", nil, allow)
	eq(t, "allow", m, map[string]any{"decision": "allow"})
	m, _, _ = reply(t, "gemini", "gemini/AfterTool.json", nil, deny)
	if m != nil {
		t.Errorf("AfterTool is not gated, got %v", m)
	}
}

func TestRespondCursor(t *testing.T) {
	for _, f := range []string{"cursor/beforeShellExecution.json", "cursor/beforeMCPExecution.json"} {
		m, stderr, code := reply(t, "cursor", f, nil, deny)
		eq(t, f+" exit", code, 0)
		eq(t, f+" stderr", stderr, "")
		eq(t, f+" reply", m, map[string]any{"permission": "deny", "user_message": denyMsg, "agent_message": denyMsg})
		m, _, _ = reply(t, "cursor", f, nil, ask)
		eq(t, f+" ask", m, map[string]any{"permission": "ask", "user_message": askMsg, "agent_message": askMsg})
		m, _, _ = reply(t, "cursor", f, nil, allow)
		eq(t, f+" allow", m, map[string]any{"permission": "allow"})
	}
	// beforeReadFile: allow | deny only.
	m, _, _ := reply(t, "cursor", "cursor/beforeReadFile.json", nil, deny)
	eq(t, "read deny", m["permission"], "deny")
	m, _, _ = reply(t, "cursor", "cursor/beforeReadFile.json", nil, ask)
	if m != nil {
		t.Errorf("beforeReadFile has no ask, got %v", m)
	}
	// Generic preToolUse: the verdict is sent under both field names.
	m, _, code := reply(t, "cursor", "cursor/preToolUse.json", nil, deny)
	eq(t, "generic exit", code, 0)
	eq(t, "generic permission", m["permission"], "deny")
	eq(t, "generic decision", m["decision"], "deny")
	eq(t, "generic reason", m["reason"], denyMsg)
	m, _, _ = reply(t, "cursor", "cursor/preToolUse.json", nil, ask)
	eq(t, "generic ask permission", m["permission"], "ask")
	if _, has := m["decision"]; has {
		t.Error(`"ask" is not a decision value`)
	}
	// beforeSubmitPrompt: continue false.
	m, _, _ = reply(t, "cursor", "cursor/beforeSubmitPrompt.json", nil, deny)
	eq(t, "prompt reply", m, map[string]any{"continue": false, "user_message": denyMsg})
	m, _, _ = reply(t, "cursor", "cursor/beforeSubmitPrompt.json", nil, ask)
	if m != nil {
		t.Errorf("prompt ask must be silent, got %v", m)
	}
}

// "none" (and an unknown action) must leave the agent untouched on every
// event of every dialect: empty stdout, empty stderr, exit 0.
func TestRespondNoneIsSilentEverywhere(t *testing.T) {
	for _, tc := range allFixtures(t) {
		d := dialect(t, tc.dialect)
		_, req, err := d.Parse(fixture(t, tc.file), tc.env)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for _, dec := range []Decision{none, {}, {Action: "explode", Reason: "x"}} {
			stdout, stderr, code := d.Respond(req, dec)
			if len(stdout) != 0 || len(stderr) != 0 || code != 0 {
				t.Errorf("%s action %q: stdout=%q stderr=%q exit=%d", tc.file, dec.Action, stdout, stderr, code)
			}
		}
	}
}

// A decision on an event the agent does not gate must never produce output:
// on Claude Code a "block" on Stop would force the agent to keep working,
// and on PreCompact stdout becomes compaction instructions.
func TestRespondNonBlockingEventsStaySilent(t *testing.T) {
	for _, tc := range allFixtures(t) {
		d := dialect(t, tc.dialect)
		_, req, err := d.Parse(fixture(t, tc.file), tc.env)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if req.Blocking {
			continue
		}
		for _, dec := range []Decision{deny, ask, allow} {
			stdout, stderr, code := d.Respond(req, dec)
			if len(stdout) != 0 || len(stderr) != 0 || code != 0 {
				t.Errorf("%s (%s) action %s: stdout=%q stderr=%q exit=%d", tc.file, req.EventName, dec.Action, stdout, stderr, code)
			}
		}
	}
}

// A deny on a gateable event must always produce a block signal the agent
// reads: either a non-zero exit with stderr, or a JSON reply.
func TestRespondDenyAlwaysSignalsOnBlockingEvents(t *testing.T) {
	n := 0
	for _, tc := range allFixtures(t) {
		d := dialect(t, tc.dialect)
		_, req, err := d.Parse(fixture(t, tc.file), tc.env)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if !req.Blocking {
			continue
		}
		n++
		stdout, stderr, code := d.Respond(req, deny)
		switch {
		case code == 2 && strings.TrimSpace(string(stderr)) != "":
		case code == 0 && len(stdout) > 0:
			decodeReply(t, stdout)
			if !strings.Contains(string(stdout), "SP-0042") {
				t.Errorf("%s: deny reply lost the rule id: %s", tc.file, stdout)
			}
		default:
			t.Errorf("%s (%s): deny produced no block signal: stdout=%q stderr=%q exit=%d", tc.file, req.EventName, stdout, stderr, code)
		}
	}
	if n < 20 {
		t.Fatalf("only %d blocking fixtures exercised", n)
	}
}

func TestRespondNilAndDegenerateRequests(t *testing.T) {
	for _, d := range All() {
		stdout, stderr, code := d.Respond(nil, deny)
		if len(stdout) != 0 || len(stderr) != 0 || code != 0 {
			t.Errorf("%s: nil request must be silent", d.ID())
		}
		// A blocking request with an event the dialect has no reply for.
		stdout, stderr, code = d.Respond(&Request{Blocking: true, EventName: "NoSuchEvent"}, deny)
		if len(stdout) != 0 || len(stderr) != 0 || code != 0 {
			t.Errorf("%s: unknown event must be silent, got %q %q %d", d.ID(), stdout, stderr, code)
		}
		d.Respond(&Request{Blocking: true}, deny) // empty event name: must not panic
	}
}

// Reason text comes from rule metadata, but it is rendered into a protocol
// stream; it must stay one bounded line.
func TestReasonIsSanitized(t *testing.T) {
	d := Decision{Action: ActionDeny, Reason: "line one\nline two\t\x1b[31mred\x00 ‮", RuleID: "R\n1"}
	got := reason(d)
	eq(t, "reason", got, "spoor: line one line two [31mred [R1]")
	long := Decision{Action: ActionDeny, Reason: strings.Repeat("é", 5000)}
	if r := reason(long); len(r) > maxReason+16 || !strings.HasPrefix(r, "spoor: ééé") {
		t.Errorf("long reason not bounded: %d bytes", len(r))
	}
	eq(t, "no double prefix", reason(Decision{Action: ActionDeny, Reason: "spoor: already tagged"}), "spoor: already tagged")
	eq(t, "ask default", reason(Decision{Action: ActionAsk}), "spoor: confirmation required by policy")

	// Through a real reply: still one line, still valid JSON.
	dl := dialect(t, "claude")
	_, req, _ := dl.Parse(fixture(t, "claude/PreToolUse.json"), nil)
	stdout, _, _ := dl.Respond(req, d)
	m := decodeReply(t, stdout)
	eq(t, "rendered", hso(t, m)["permissionDecisionReason"], "spoor: line one line two [31mred [R1]")
	// HTML-ish characters are not mangled into < escapes.
	stdout, _, _ = dl.Respond(req, Decision{Action: ActionDeny, Reason: "a <b> & c"})
	if !strings.Contains(string(stdout), "a <b> & c") {
		t.Errorf("reason was HTML-escaped: %s", stdout)
	}
}
