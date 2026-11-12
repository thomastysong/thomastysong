package hookcmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

// crashFaults are the ways a worker can fail. Each must end with exit 0
// and the allow-shaped (observe) or timeout (guard) reply. reasons lists
// the acceptable health reasons: a goroutine stuck on a lock or racing on
// a map either dies (exit 2) or hangs until the deadline, depending on
// what the runtime notices first.
var crashFaults = []struct {
	fault   string
	reasons []string
}{
	{"kill@parsed", []string{ReasonWorkerCrash}},
	{"goroutine-panic@parsed", []string{ReasonWorkerCrash}},
	{"stack-overflow@parsed", []string{ReasonWorkerCrash}},
	{"map-race@parsed", []string{ReasonWorkerCrash, ReasonWorkerTimeout}},
	{"deadlock@parsed", []string{ReasonWorkerTimeout, ReasonWorkerCrash}},
	{"partial-json@parsed", []string{ReasonBadReply}},
	{"hang@parsed", []string{ReasonWorkerTimeout}},
	{"flood@parsed", []string{ReasonBadReply}},
	{"two-objects@parsed", []string{ReasonBadReply}},
	{"exit2@parsed", []string{ReasonWorkerCrash}},
	{"panic@parsed", []string{ReasonWorkerCrash}},
}

// assertFallback checks the reply a supervisor gives for a failed worker.
func assertFallback(t *testing.T, d dialectCase, guard bool, out []byte) {
	t.Helper()
	if !guard {
		if len(out) != 0 {
			t.Fatalf("observe fallback must be empty (allow-shaped), got %s", out)
		}
		return
	}
	if _, ok := validReply(out, MaxReply); !ok || len(out) == 0 {
		t.Fatalf("guard fallback is not one JSON object: %q", out)
	}
	if replyCarries(out, hookio.ActionDeny) {
		t.Fatalf("guard fallback must never deny: %s", out)
	}
	if d.canAsk {
		if !replyCarries(out, hookio.ActionAsk) {
			t.Fatalf("%s: guard fallback should ask: %s", d.agent, out)
		}
	} else if !bytes.Contains(out, []byte(`"systemMessage"`)) {
		t.Fatalf("%s: guard fallback should be a warning (no ask on this agent): %s", d.agent, out)
	}
}

func TestCrashSafetyPerDialect(t *testing.T) {
	modes := []struct {
		name  string
		cfg   string
		guard bool
		limit time.Duration
	}{
		{"observe", cfgObserve, false, 400 * time.Millisecond},
		{"guard", cfgGuard, true, time.Second},
	}
	for _, m := range modes {
		for _, d := range dialects {
			faults := crashFaults
			if m.guard {
				// Mid-evaluation exists only when rules run.
				faults = append(slices.Clone(faults), struct {
					fault   string
					reasons []string
				}{"kill@eval", []string{ReasonWorkerCrash}})
			}
			for _, f := range faults {
				t.Run(m.name+"/"+d.agent+"/"+f.fault, func(t *testing.T) {
					s := newSandbox(t, m.cfg)
					r := s.supervised(t, d.agent, d.payload("ls -la"), f.fault)
					if r.code != 0 {
						t.Fatalf("exit %d, want 0", r.code)
					}
					if len(r.stderr) != 0 {
						t.Fatalf("stderr written: %q", r.stderr)
					}
					assertFallback(t, d, m.guard, r.stdout)
					if r.dur > m.limit+1500*time.Millisecond {
						t.Fatalf("took %v, deadline %v", r.dur, m.limit)
					}
					// On a loaded machine any crash can lose the race with
					// the deadline; the reply is the same either way.
					got := healthReasons(s.ofKind(t, event.KindHealth))
					if len(got) != 1 || !(slices.Contains(f.reasons, got[0]) || got[0] == ReasonWorkerTimeout) {
						t.Fatalf("health reasons %v, want one of %v", got, f.reasons)
					}
					if got[0] != f.reasons[0] {
						t.Logf("health reason %s (expected %s unless the machine is loaded)", got[0], f.reasons[0])
					}
				})
			}
		}
	}
}

// A missing worker binary (a half-finished upgrade) is a start failure,
// answered like any other.
func TestWorkerBinaryMissing(t *testing.T) {
	for _, guard := range []bool{false, true} {
		for _, d := range dialects {
			cfg := cfgObserve
			if guard {
				cfg = cfgGuard
			}
			s := newSandbox(t, cfg)
			env := OSEnv()
			env.Exe = filepath.Join(s.dir, "no-such-spoor")
			var out, errb bytes.Buffer
			code := Run(bytes.NewReader(d.payload("ls")), &out, &errb, []string{"--agent", d.agent, "--config", s.cfg}, env)
			if code != 0 || errb.Len() != 0 {
				t.Fatalf("%s guard=%v: exit %d stderr %q", d.agent, guard, code, errb.Bytes())
			}
			assertFallback(t, d, guard, out.Bytes())
			if got := healthReasons(s.ofKind(t, event.KindHealth)); !slices.Equal(got, []string{ReasonWorkerStart}) {
				t.Fatalf("%s: health %v", d.agent, got)
			}
		}
	}
}

// A worker that wrote a complete reply and then failed (here: every spool
// append refused for lack of space) still gets its decision forwarded.
func TestReplyForwardedWhenAppendFails(t *testing.T) {
	s := newSandbox(t, cfgGuard)
	d := dialects[0]
	r := s.supervised(t, d.agent, d.payload("spoor-test-block now"), "nospace")
	if r.code != 0 || !replyCarries(r.stdout, hookio.ActionDeny) {
		t.Fatalf("exit %d reply %s", r.code, r.stdout)
	}
	if got := healthReasons(s.ofKind(t, event.KindHealth)); !slices.Equal(got, []string{ReasonSpool}) {
		t.Fatalf("health %v, want [%s]", got, ReasonSpool)
	}
	if acts := s.ofKind(t, event.KindActivity); len(acts) != 0 {
		t.Fatalf("activity appended despite no space: %d", len(acts))
	}
}

// The whole binary, as an agent sees it: the OS-level exit status is 0 for
// crashes and for a Codex block (no exit 2 anywhere).
func TestProcessExitStatus(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, agent, cfg, cmd, fault string
		check                        func([]byte) bool
	}{
		{"guard claude stack overflow", "claude-code", cfgGuard, "ls", "stack-overflow@parsed", func(b []byte) bool { return replyCarries(b, hookio.ActionAsk) }},
		{"guard codex block is JSON", "codex", cfgGuard, "spoor-test-block now", "", func(b []byte) bool { return replyCarries(b, hookio.ActionDeny) }},
		{"guard copilot goroutine panic", "copilot-cli", cfgGuard, "ls", "goroutine-panic@parsed", func(b []byte) bool { return replyCarries(b, hookio.ActionAsk) }},
		{"observe gemini kill", "gemini-cli", cfgObserve, "ls", "kill@parsed", func(b []byte) bool { return len(b) == 0 }},
		{"observe cursor exit 2", "cursor", cfgObserve, "ls", "exit2@parsed", func(b []byte) bool { return len(b) == 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, c.cfg)
			var d dialectCase
			for _, x := range dialects {
				if x.agent == c.agent {
					d = x
				}
			}
			cmd := exec.Command(exe, "hook", "--agent", c.agent, "--config", s.cfg)
			cmd.Env = append(os.Environ(), envRole+"=hook", envFault+"="+c.fault, "SPOOR_SPOOL="+s.spool)
			cmd.Stdin = bytes.NewReader(d.payload(c.cmd))
			var out, errb bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errb
			err := cmd.Run()
			if err != nil {
				t.Fatalf("exit: %v (stderr %q)", err, errb.String())
			}
			if cmd.ProcessState.ExitCode() != 0 || errb.Len() != 0 {
				t.Fatalf("exit %d stderr %q", cmd.ProcessState.ExitCode(), errb.String())
			}
			if !c.check(out.Bytes()) {
				t.Fatalf("reply %q", out.String())
			}
			if strings.Contains(out.String(), "goroutine") {
				t.Fatalf("a crash trace leaked into the reply: %q", out.String())
			}
		})
	}
}
