package hookcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// The agent has not closed stdin by half the hard deadline: the
// supervisor passes on the prefix it has and tells the worker it was cut
// (--stdin-cut). A prefix that does not parse is answered "ask" on a gated
// event, never an implicit allow; a complete payload from an agent that
// merely kept stdin open is judged normally.
func TestGuardTruncatedStdinAsks(t *testing.T) {
	full := dialects[0].payload("spoor-test-block now")
	cut := bytes.Index(full, []byte("spoor-test-block"))
	for _, c := range []struct {
		name    string
		payload []byte
		want    func([]byte) bool
		anomaly string
	}{
		{"prefix of a block", full[:cut+5], func(b []byte) bool { return replyCarries(b, hookio.ActionAsk) }, anomalyStdin},
		{"complete benign payload", dialects[0].payload("ls -la"), func(b []byte) bool { return len(b) == 0 }, ""},
		{"complete block payload", full, func(b []byte) bool { return replyCarries(b, hookio.ActionDeny) }, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Half the deadline goes to the stdin wait; a race-instrumented
			// worker needs more than the other half of one second.
			cfg := cfgGuardCrash
			if raceSlowdown > 1 {
				cfg = strings.Replace(cfg, "deadline: 1s", "deadline: 4s", 1)
			}
			s := newSandbox(t, cfg)
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pw.Close() })
			go func() { _, _ = pw.Write(c.payload) }() // never closed while the hook waits
			r := s.supervisedFrom(t, "claude-code", pr, "")
			if r.code != 0 || !c.want(r.stdout) {
				t.Fatalf("exit %d reply %q", r.code, r.stdout)
			}
			if got := healthReasons(s.ofKind(t, event.KindHealth)); !slices.Equal(got, []string{ReasonStdin}) {
				t.Fatalf("health %v", got)
			}
			var anomaly string
			for _, a := range s.ofKind(t, event.KindActivity) {
				if a.Type == TypePayloadAnomaly {
					anomaly = a.Labels["hook_error"]
				}
			}
			if anomaly != c.anomaly {
				t.Fatalf("anomaly %q, want %q", anomaly, c.anomaly)
			}
		})
	}
}

// A worker that starts with less time left than its reply margin still
// reads the whole payload its supervisor wrote: an empty read would decide
// "allow". Run directly with a deadline already almost spent, the answer is
// the rule's deny or, when the evaluation runs out of time, "ask".
func TestWorkerNearDeadlineReadsWholePayload(t *testing.T) {
	saved := exitFunc
	t.Cleanup(func() { exitFunc = saved })
	exitFunc = func(int) {} // the worker's watchdog must not end the test binary
	for i := 0; i < 3; i++ {
		s := newSandbox(t, cfgGuard)
		d := dialects[0]
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pw.Write(d.payload("spoor-test-block now")); err != nil {
			t.Fatal(err)
		}
		pw.Close()
		deadline := time.Now().Add(10 * time.Millisecond)
		var out, errb bytes.Buffer
		code := Run(pr, &out, &errb, []string{"--worker", "--agent", d.agent, "--config", s.cfg,
			"--deadline", strconv.FormatInt(deadline.UnixNano(), 10)}, OSEnv())
		pr.Close()
		if !replyCarries(out.Bytes(), hookio.ActionDeny) && !replyCarries(out.Bytes(), hookio.ActionAsk) {
			var labels []string
			for _, a := range s.ofKind(t, event.KindActivity) {
				labels = append(labels, a.Type+":"+a.Labels["hook_error"])
			}
			t.Fatalf("worker with the full block payload in its pipe answered %q (allow) with exit %d; records %v", out.Bytes(), code, labels)
		}
	}
}

// Hooks of parallel tool calls in one session overlap. A hook that loaded
// the session state before a parallel hook saved a new flag must not write
// its stale copy over it: the commit sees the newer state and evaluates
// again on top of it. Ordering is forced with the eval fault seam: the
// "ls" hook is paused after its first evaluation while the "arm" hook
// runs to completion.
func TestConcurrentHooksKeepSessionFlag(t *testing.T) {
	d := dialects[0]
	s := newSandbox(t, cfgGuard)
	saved := faultHook
	t.Cleanup(func() { faultHook = saved })
	var (
		mu      sync.Mutex
		first   = true
		reached = make(chan struct{})
		release = make(chan struct{})
	)
	faultHook = func(stage string) {
		if stage != "eval" {
			return
		}
		mu.Lock()
		hold := first
		first = false
		mu.Unlock()
		if hold { // the "ls" hook: state loaded and evaluated, not yet saved
			close(reached)
			<-release
		}
	}
	bDone := make(chan hookResult, 1)
	go func() { bDone <- s.worker(t, OSEnv(), d.agent, d.payload("ls -la")) }()
	<-reached
	if r := s.worker(t, OSEnv(), d.agent, d.payload("spoor-test-arm")); r.code != 0 {
		t.Fatalf("arm: exit %d", r.code)
	}
	close(release)
	if r := <-bDone; r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("ls: exit %d reply %q", r.code, r.stdout)
	}
	faultHook = saved
	for _, a := range s.ofKind(t, event.KindActivity) {
		if v := a.Labels["hook_state"]; v != "" {
			t.Fatalf("hook_state=%s on %s", v, a.Type)
		}
	}

	r := s.worker(t, OSEnv(), d.agent, d.payload("spoor-test-armed"))
	if !replyCarries(r.stdout, hookio.ActionAsk) {
		t.Fatalf("flag set by a concurrent hook was overwritten by a stale state save; guard rule SPR-TEST-011 did not fire (reply %q)", r.stdout)
	}
}

// Many guard hooks of one session at once, half of them arming: the flag
// survives every interleaving.
func TestParallelGuardHooksKeepFlag(t *testing.T) {
	d := dialects[0]
	s := newSandbox(t, cfgGuard)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		cmd := "ls -la"
		if i == 7 {
			cmd = "spoor-test-arm"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(t, OSEnv(), d.agent, d.payload(cmd))
		}()
	}
	wg.Wait()
	if r := s.worker(t, OSEnv(), d.agent, d.payload("spoor-test-armed")); !replyCarries(r.stdout, hookio.ActionAsk) {
		t.Fatalf("flag lost among parallel hooks: reply %q", r.stdout)
	}
}

// A guard that decided "proceed" and then could not append its records
// (here: no space) still proceeds. The spool failure is a health record,
// not a prompt on every tool call.
func TestGuardSpoolFailureKeepsAllow(t *testing.T) {
	s := newSandbox(t, cfgGuard)
	d := dialects[0]
	r := s.supervised(t, d.agent, d.payload("ls -la"), "nospace")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if len(r.stdout) != 0 {
		t.Fatalf("benign command, guard rules matched nothing, but the agent was told %s because the spool append failed", r.stdout)
	}
	// The supervisor (whose spool is fine in this test) reports why.
	if got := healthReasons(s.ofKind(t, event.KindHealth)); !slices.Equal(got, []string{ReasonSpool}) {
		t.Fatalf("health %v, want [%s]", got, ReasonSpool)
	}
	if acts := s.ofKind(t, event.KindActivity); len(acts) != 0 {
		t.Fatalf("activity appended despite no space: %d", len(acts))
	}
}

// One invalid value the hook never reads (heartbeat is a daemon setting)
// must not drop guard mode: the hook keeps the decoded configuration and
// labels its records.
func TestGuardSurvivesUnrelatedConfigError(t *testing.T) {
	s := newSandbox(t, cfgGuard+"heartbeat: 1s\n")
	d := dialects[0]
	r := s.supervised(t, d.agent, d.payload("spoor-test-block now"), "")
	if r.code != 0 || !replyCarries(r.stdout, hookio.ActionDeny) {
		t.Fatalf("guard.mode advisory with a block rule, but an invalid daemon-only field (heartbeat) changed the answer: reply %q", r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["hook_config"] != "invalid" || a.Labels["hook_mode"] != "guard" {
		t.Fatalf("labels %v", a.Labels)
	}
}

// A suppression whose bare-date expiry is today is still in force, as it
// is in the daemon ("through the end of that day").
func TestSuppressionExpiryMatchesDaemon(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	cfg := cfgGuard + "  suppressions:\n    - rule: SPR-TEST-001\n      reason: approved through " + today + "\n      expires: \"" + today + "\"\n"
	s := newSandbox(t, cfg)
	d := dialects[0]
	r := s.supervised(t, d.agent, d.payload("spoor-test-block now"), "")
	if r.code != 0 || replyCarries(r.stdout, hookio.ActionDeny) {
		t.Fatalf("suppression expiring today (%s) is in force for the daemon, but the hook answered: exit %d %s", today, r.code, r.stdout)
	}
	// Yesterday's has expired in both.
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	s = newSandbox(t, strings.ReplaceAll(cfg, today, yesterday))
	if r := s.supervised(t, d.agent, d.payload("spoor-test-block now"), ""); !replyCarries(r.stdout, hookio.ActionDeny) {
		t.Fatalf("expired suppression still honoured: %s", r.stdout)
	}
}
