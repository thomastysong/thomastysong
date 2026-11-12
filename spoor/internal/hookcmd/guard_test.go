package hookcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

func lastActivity(t *testing.T, s *sandbox) *event.Event {
	t.Helper()
	acts := s.ofKind(t, event.KindActivity)
	if len(acts) == 0 {
		t.Fatal("no activity record")
	}
	return acts[len(acts)-1]
}

// Guard deny and ask rendering per dialect, through the supervisor and a
// real worker: what each agent is told, and what the activity says it was
// told.
func TestGuardRepliesPerDialect(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.agent, func(t *testing.T) {
			s := newSandbox(t, cfgGuard)

			r := s.supervised(t, d.agent, d.payload("spoor-test-block --now"), "")
			if r.code != 0 || len(r.stderr) != 0 {
				t.Fatalf("block: exit %d stderr %q", r.code, r.stderr)
			}
			if !replyCarries(r.stdout, hookio.ActionDeny) {
				t.Fatalf("block: reply does not deny: %s", r.stdout)
			}
			if !bytes.Contains(r.stdout, []byte("SPR-TEST-001")) {
				t.Fatalf("block: reason lacks the rule id: %s", r.stdout)
			}
			a := lastActivity(t, s)
			if a.Labels["guard_reply"] != "deny" || a.Labels["guard_rule"] != "SPR-TEST-001" ||
				a.Outcome == nil || a.Outcome.Decision != "deny" || a.Outcome.DecisionSource != "spoor" {
				t.Fatalf("block: activity does not record the decision: labels %v outcome %+v", a.Labels, a.Outcome)
			}

			r = s.supervised(t, d.agent, d.payload("spoor-test-ask --now"), "")
			if r.code != 0 {
				t.Fatalf("ask: exit %d", r.code)
			}
			a = lastActivity(t, s)
			if d.canAsk {
				if !replyCarries(r.stdout, hookio.ActionAsk) || a.Labels["guard_reply"] != "ask" || a.Outcome == nil || a.Outcome.Decision != "ask" {
					t.Fatalf("ask: reply %s labels %v", r.stdout, a.Labels)
				}
			} else {
				// Codex and Gemini cannot ask: a warning, and the action
				// proceeds. The record must not claim an ask was enforced.
				if !bytes.Contains(r.stdout, []byte(`"systemMessage"`)) || replyCarries(r.stdout, hookio.ActionAsk) ||
					a.Labels["guard_reply"] != "warn" || a.Outcome != nil {
					t.Fatalf("ask on %s: reply %s labels %v outcome %+v", d.agent, r.stdout, a.Labels, a.Outcome)
				}
			}

			r = s.supervised(t, d.agent, d.payload("ls -la"), "")
			if r.code != 0 || len(r.stdout) != 0 {
				t.Fatalf("benign: exit %d reply %s", r.code, r.stdout)
			}
			if a = lastActivity(t, s); a.Labels["guard_reply"] != "" {
				t.Fatalf("benign: guard label %v", a.Labels)
			}
			if hs := s.ofKind(t, event.KindHealth); len(hs) != 0 {
				t.Fatalf("healthy runs wrote health errors: %v", healthReasons(hs))
			}
			if dets := s.ofKind(t, event.KindDetection); len(dets) != 0 {
				t.Fatalf("guard-only mode spooled %d findings", len(dets))
			}
		})
	}
}

// Codex blocks are rendered as JSON on exit 0 for every event Codex gates
// (hookio itself still answers exit 2, which this package never uses).
func TestCodexBlockIsJSON(t *testing.T) {
	d, _ := hookio.Get("codex")
	dec := hookio.Decision{Action: hookio.ActionDeny, Reason: "reads a key", RuleID: "SPR-X-001"}
	cases := map[string]func(map[string]any) bool{
		"PreToolUse": func(m map[string]any) bool {
			hs, _ := m["hookSpecificOutput"].(map[string]any)
			return hs["hookEventName"] == "PreToolUse" && hs["permissionDecision"] == "deny" && strings.Contains(fmt.Sprint(hs["permissionDecisionReason"]), "reads a key")
		},
		"UserPromptSubmit": func(m map[string]any) bool {
			return m["decision"] == "block" && strings.Contains(fmt.Sprint(m["reason"]), "reads a key")
		},
		"PermissionRequest": func(m map[string]any) bool {
			hs, _ := m["hookSpecificOutput"].(map[string]any)
			dd, _ := hs["decision"].(map[string]any)
			return hs["hookEventName"] == "PermissionRequest" && dd["behavior"] == "deny" && dd["message"] != ""
		},
	}
	for name, ok := range cases {
		req := &hookio.Request{AgentID: "codex", EventName: name, Blocking: true}
		reply, rendered := render(d, req, dec)
		if !rendered {
			t.Fatalf("%s: not rendered", name)
		}
		var m map[string]any
		if err := json.Unmarshal(reply, &m); err != nil || !ok(m) {
			t.Fatalf("%s: %s", name, reply)
		}
		if !replyCarries(reply, hookio.ActionDeny) {
			t.Fatalf("%s: replyCarries misses the deny: %s", name, reply)
		}
	}
	// An event Codex does not gate is a no-op, never an exit code.
	reply, ok := render(d, &hookio.Request{EventName: "PostToolUse"}, dec)
	if !ok || len(reply) != 0 {
		t.Fatalf("PostToolUse: %q %v", reply, ok)
	}
}

// guard.max_response: ask (the default) turns a block rule into an ask,
// and the record says what was actually returned.
func TestGuardMaxResponseCapsBlock(t *testing.T) {
	s := newSandbox(t, strings.Replace(cfgGuard, "max_response: block", "max_response: ask", 1))
	r := s.supervised(t, "claude-code", dialects[0].payload("spoor-test-block now"), "")
	if r.code != 0 || !replyCarries(r.stdout, hookio.ActionAsk) || replyCarries(r.stdout, hookio.ActionDeny) {
		t.Fatalf("reply %s", r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["guard_reply"] != "ask" {
		t.Fatalf("labels %v", a.Labels)
	}
}

// Session state carried between one-shot hook processes: a flag
// maintainer (SPR-TEST-010) in one invocation arms a guard rule
// (SPR-TEST-011) in a later one, through the spool's state files.
func TestGuardSessionStateAcrossInvocations(t *testing.T) {
	d := dialects[0]
	withSession := func(cmd, session string) []byte {
		return bytes.Replace(d.payload(cmd), []byte(`"s-claude"`), []byte(`"`+session+`"`), 1)
	}
	s := newSandbox(t, cfgGuard)
	if r := s.supervised(t, d.agent, withSession("spoor-test-armed", "s1"), ""); len(r.stdout) != 0 {
		t.Fatalf("unarmed session should pass: %s", r.stdout)
	}
	if r := s.supervised(t, d.agent, withSession("spoor-test-arm", "s1"), ""); r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("arm: %d %s", r.code, r.stdout)
	}
	r := s.supervised(t, d.agent, withSession("spoor-test-armed", "s1"), "")
	if !replyCarries(r.stdout, hookio.ActionAsk) || !bytes.Contains(r.stdout, []byte("SPR-TEST-011")) {
		t.Fatalf("flag from an earlier invocation did not arm the guard rule: %s", r.stdout)
	}
	// Another session of the same user does not inherit the flag.
	if r := s.supervised(t, d.agent, withSession("spoor-test-armed", "s2"), ""); len(r.stdout) != 0 {
		t.Fatalf("flag leaked across sessions: %s", r.stdout)
	}
	// Tampered state is rejected and labelled, never trusted.
	states, _ := filepath.Glob(filepath.Join(s.spool, "state", "*.json"))
	for _, p := range states {
		if err := os.WriteFile(p, []byte(`{"v":1,"k":"forged","flags":"x"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r = s.supervised(t, d.agent, withSession("spoor-test-armed", "s1"), "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("forged state: %d %s", r.code, r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["hook_state"] != "rejected" {
		t.Fatalf("forged state not labelled: %v", a.Labels)
	}
}

// With in-hook detection on as well, findings are spooled, and Enforced is
// set only when the reply carried the rule's decision.
func TestGuardAndDetectEnforced(t *testing.T) {
	cfg := cfgGuard + "sources:\n  hooks:\n    detect_in_hook: true\n"
	for _, c := range []struct {
		agent, cmd, rule string
		enforced         bool
	}{
		{"claude-code", "spoor-test-block x", "SPR-TEST-001", true},
		{"claude-code", "spoor-test-ask x", "SPR-TEST-002", true},
		{"codex", "spoor-test-block x", "SPR-TEST-001", true},
		{"codex", "spoor-test-ask x", "SPR-TEST-002", false},      // a warning, not an ask
		{"gemini-cli", "spoor-test-ask x", "SPR-TEST-002", false}, // likewise
	} {
		t.Run(c.agent+"/"+c.rule, func(t *testing.T) {
			s := newSandbox(t, cfg)
			var d dialectCase
			for _, x := range dialects {
				if x.agent == c.agent {
					d = x
				}
			}
			r := s.supervised(t, c.agent, d.payload(c.cmd), "")
			if r.code != 0 {
				t.Fatalf("exit %d", r.code)
			}
			var found bool
			for _, det := range s.ofKind(t, event.KindDetection) {
				if det.Type != event.TypeDetectionFinding || det.Detection == nil || det.Detection.RuleID != c.rule {
					continue
				}
				found = true
				if det.Detection.Enforced != c.enforced {
					t.Fatalf("Enforced=%v want %v (reply %s)", det.Detection.Enforced, c.enforced, r.stdout)
				}
			}
			if !found {
				t.Fatalf("no finding for %s", c.rule)
			}
		})
	}
}

// A payload the guard cannot inspect (over the input cap, or nested too
// deep) on a gated event answers ask, never an implicit allow.
func TestGuardUninspectablePayloadAsks(t *testing.T) {
	cfg := cfgGuard + "limits:\n  max_hook_input_bytes: 65536\n"
	big := dialects[0].payload("echo " + strings.Repeat("A", 70000))
	deep := []byte(`{"session_id":"s","cwd":"/w","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"t","tool_input":{"command":"ls","x":` +
		strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}}`)
	for name, c := range map[string]struct {
		payload []byte
		code    string
	}{"oversize": {big, anomalyTooLarge}, "too deep": {deep, anomalyTooDeep}} {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, cfg)
			r := s.supervised(t, "claude-code", c.payload, "")
			if r.code != 0 || !replyCarries(r.stdout, hookio.ActionAsk) {
				t.Fatalf("exit %d reply %s", r.code, r.stdout)
			}
			var anomaly *event.Event
			for _, a := range s.ofKind(t, event.KindActivity) {
				if a.Type == TypePayloadAnomaly {
					anomaly = a
				}
			}
			if anomaly == nil || anomaly.Labels["hook_error"] != c.code || anomaly.Session.ID != "s" && name == "too deep" {
				t.Fatalf("anomaly record: %+v", anomaly)
			}
		})
	}
}

// Without usable rule content the guard asks on gated events rather than
// allowing silently.
func TestGuardWithoutRulesAsks(t *testing.T) {
	s := newSandbox(t, cfgGuard)
	saved := loadRuleSet
	t.Cleanup(func() { loadRuleSet = saved })
	loadRuleSet = func(*configT, bool) (*rulesSet, bool, error) { return nil, true, errTest }
	r := s.worker(t, OSEnv(), "claude-code", dialects[0].payload("ls"))
	if r.code != 0 || !replyCarries(r.stdout, hookio.ActionAsk) {
		t.Fatalf("exit %d reply %s", r.code, r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["hook_rules"] != "unavailable" {
		t.Fatalf("labels %v", a.Labels)
	}
}
