package hookcmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
	"github.com/thomastysong/spoor/internal/rules"
	"github.com/thomastysong/spoor/internal/spool"
)

// The test binary doubles as the spoor binary: with envRole=hook it runs
// Run on its own arguments, which is how the supervisor's re-exec reaches a
// worker in tests. envFault injects a crash into that worker only; the
// production binary has no such switch (faultHook is set here, in a test
// file, and nowhere else).
const (
	envRole  = "SPOOR_HOOKCMD_TEST_ROLE"
	envFault = "SPOOR_HOOKCMD_TEST_FAULT"
)

func TestMain(m *testing.M) {
	if os.Getenv(envRole) == "hook" {
		if f := os.Getenv(envFault); f != "" {
			installFault(f)
		}
		args := os.Args[1:]
		if len(args) > 0 && args[0] == "hook" {
			args = args[1:]
		}
		os.Exit(Run(os.Stdin, os.Stdout, os.Stderr, args, OSEnv()))
	}
	// Workers started by in-process supervisors inherit a short observe
	// deadline through their --deadline flag.
	observeDeadline = 400 * time.Millisecond
	os.Exit(m.Run())
}

// installFault arms one crash class at one worker stage ("kind@stage").
func installFault(spec string) {
	kind, stage, _ := strings.Cut(spec, "@")
	if kind == "nospace" {
		appendRecord = func(*spool.Writer, *event.Event) error { return spool.ErrNoSpace }
		return
	}
	if kind == "norender" {
		renderReply = func(hookio.Dialect, *hookio.Request, hookio.Decision) ([]byte, bool) { return nil, false }
		return
	}
	faultHook = func(s string) {
		if s == stage {
			doFault(kind)
		}
	}
}

func doFault(kind string) {
	switch kind {
	case "kill": // SIGKILL mid-evaluation
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Kill()
		time.Sleep(time.Hour)
	case "goroutine-panic": // not recoverable by the main goroutine
		go func() { panic("injected panic in a goroutine") }()
		time.Sleep(time.Hour)
	case "stack-overflow":
		debug.SetMaxStack(4 << 20)
		var f func(int) int
		f = func(n int) int {
			var pad [256]byte
			pad[n%256] = byte(n)
			return f(n+1) + int(pad[(n+1)%256])
		}
		f(0)
	case "map-race": // fatal error: concurrent map writes
		m := map[int]int{}
		for i := 0; i < 8; i++ {
			go func() {
				for j := 0; ; j++ {
					m[j%1024] = j
				}
			}()
		}
		time.Sleep(time.Hour)
	case "deadlock":
		var mu sync.Mutex
		mu.Lock()
		mu.Lock()
	case "partial-json":
		os.Stdout.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"de`))
		os.Exit(2)
	case "hang":
		time.Sleep(time.Hour)
	case "flood":
		os.Stdout.Write(bytes.Repeat([]byte(`{"a":1}`), 150000))
		os.Exit(0)
	case "two-objects":
		os.Stdout.Write([]byte(`{"a":1}{"b":2}`))
		os.Exit(0)
	case "exit2":
		os.Stderr.Write([]byte("spoor: blocked\n"))
		os.Exit(2)
	case "panic": // recoverable: the worker's own recover turns it into exitInternal
		panic("injected panic")
	}
}

// dialectCase is one agent's blocking pre-tool shell payload.
type dialectCase struct {
	agent    string
	canAsk   bool // the agent has a real "ask"; Codex and Gemini get a warning
	template string
}

var dialects = []dialectCase{
	{"claude-code", true, `{"session_id":"s-claude","transcript_path":"/home/u/.claude/projects/p/s.jsonl","cwd":"/work/p","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s,"description":"run"},"tool_use_id":"toolu_01"}`},
	{"codex", false, `{"cwd":"/work/p","model":"gpt-5.2-codex","permission_mode":"default","session_id":"s-codex","turn_id":"turn-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s},"tool_use_id":"call_1","transcript_path":null}`},
	{"copilot-cli", true, `{"session_id":"s-copilot","timestamp":"2026-11-11T10:00:00.000Z","cwd":"/work/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%s}}`},
	{"gemini-cli", false, `{"session_id":"s-gemini","transcript_path":"/home/u/.gemini/tmp/abc/chats/session-1.json","cwd":"/work/p","timestamp":"2026-11-11T10:00:00.000Z","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":%s}}`},
	{"cursor", true, `{"conversation_id":"s-cursor","generation_id":"gen-1","workspace_roots":["/work/p"],"cursor_version":"2.4.1","model":"m","transcript_path":null,"hook_event_name":"beforeShellExecution","command":%s,"cwd":"/work/p"}`},
}

func (d dialectCase) payload(cmd string) []byte {
	q, _ := json.Marshal(cmd)
	return []byte(fmt.Sprintf(d.template, q))
}

// testPack is a rule directory with one block rule and one ask rule keyed
// on marker commands.
const testPack = `pack: hooktest
version: "2026.11.0"
rules:
  - id: SPR-TEST-001
    title: Marker command that guard blocks
    description: Exercises the hook's block path.
    kind: activity
    class: finding
    severity: high
    confidence: high
    maturity: experimental
    category: execution
    when:
      type: tool.pre
      tool.kind: shell
    match:
      shell.commands: spoor-test-block
    response: block
    tests:
      - name: marker
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "spoor-test-block now" } }
        expect: match
      - name: other
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "ls" } }
        expect: no_match
  - id: SPR-TEST-002
    title: Marker command that guard asks about
    description: Exercises the hook's ask path.
    kind: activity
    class: finding
    severity: medium
    confidence: high
    maturity: experimental
    category: execution
    when:
      type: tool.pre
      tool.kind: shell
    match:
      shell.commands: spoor-test-ask
    response: ask
    tests:
      - name: marker
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "spoor-test-ask now" } }
        expect: match
      - name: other
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "ls" } }
        expect: no_match
  - id: SPR-TEST-010
    title: Marker command that arms a session flag
    description: Flag maintainer for the hook's session state test.
    kind: activity
    class: signal
    severity: info
    confidence: high
    maturity: experimental
    category: execution
    when:
      type: tool.pre
      tool.kind: shell
    match:
      shell.commands: spoor-test-arm
    flags:
      set: [spoor_test_armed]
      ttl: 30m
    emit: false
    tests:
      - name: arm
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "spoor-test-arm" } }
        expect: match
      - name: other
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "ls" } }
        expect: no_match
  - id: SPR-TEST-011
    title: Marker command guarded once the session is armed
    description: Guard rule that depends on state from an earlier hook process.
    kind: activity
    class: finding
    severity: medium
    confidence: high
    maturity: experimental
    category: execution
    when:
      type: tool.pre
      tool.kind: shell
    match:
      shell.commands: spoor-test-armed
    flags:
      require: [spoor_test_armed]
    response: ask
    tests:
      - name: armed
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "spoor-test-armed" } }
        flags: [spoor_test_armed]
        expect: match
      - name: not armed
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "spoor-test-armed" } }
        expect: no_match
`

// sandbox is a config file, a rules directory and a spool in one temp dir.
type sandbox struct {
	dir, cfg, rules, spool string
}

func newSandbox(t *testing.T, cfgBody string) *sandbox {
	t.Helper()
	d := t.TempDir()
	s := &sandbox{dir: d, cfg: filepath.Join(d, "spoor.yaml"), rules: filepath.Join(d, "rules"), spool: filepath.Join(d, "spool")}
	if err := os.Mkdir(s.rules, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.rules, "hooktest.yaml"), []byte(testPack), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(cfgBody, "$RULES", s.rules)
	if err := os.WriteFile(s.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(spool.EnvSpool, s.spool)
	return s
}

const (
	cfgObserve = "privacy:\n  profile: standard\n"
	// Functional guard tests get a long deadline so a slow (or race-
	// instrumented) worker is never mistaken for a timeout; the crash
	// matrix uses cfgGuardCrash, whose deadline it waits out on hangs.
	cfgGuard      = "guard:\n  mode: advisory\n  max_response: block\n  deadline: 5s\nrules:\n  dirs: [$RULES]\n"
	cfgGuardCrash = "guard:\n  mode: advisory\n  max_response: block\n  deadline: 1s\nrules:\n  dirs: [$RULES]\n"
	cfgDetect     = "sources:\n  hooks:\n    detect_in_hook: true\nrules:\n  dirs: [$RULES]\nprivacy:\n  context_events: 2\n"
)

// hookResult is one supervised invocation.
type hookResult struct {
	stdout []byte
	stderr []byte
	code   int
	dur    time.Duration
}

// supervised runs Run in this process as the supervisor; the worker is
// this test binary in a child process, with fault injected.
func (s *sandbox) supervised(t *testing.T, agent string, payload []byte, fault string, extra ...string) hookResult {
	t.Helper()
	return s.supervisedFrom(t, agent, bytes.NewReader(payload), fault, extra...)
}

// supervisedFrom is supervised with an arbitrary stdin. It returns once the
// supervisor's health appends are done, so the spool can be read at once.
func (s *sandbox) supervisedFrom(t *testing.T, agent string, stdin io.Reader, fault string, extra ...string) hookResult {
	t.Helper()
	t.Setenv(envRole, "hook")
	t.Setenv(envFault, fault)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := OSEnv()
	env.Exe = exe
	var out, errb bytes.Buffer
	args := append([]string{"--agent", agent, "--config", s.cfg}, extra...)
	start := time.Now()
	code := Run(stdin, &out, &errb, args, env)
	dur := time.Since(start)
	healthPending.Wait()
	return hookResult{stdout: out.Bytes(), stderr: errb.Bytes(), code: code, dur: dur}
}

// worker runs the worker in this process (no subprocess, no watchdog).
func (s *sandbox) worker(t *testing.T, env Env, agent string, payload []byte, extra ...string) hookResult {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"--worker", "--agent", agent, "--config", s.cfg}, extra...)
	start := time.Now()
	code := Run(bytes.NewReader(payload), &out, &errb, args, env)
	return hookResult{stdout: out.Bytes(), stderr: errb.Bytes(), code: code, dur: time.Since(start)}
}

// spoolLine is one line of a spool file.
type spoolLine struct {
	file    string
	raw     map[string]json.RawMessage
	ev      *event.Event
	content json.RawMessage
}

func (s *sandbox) lines(t *testing.T) []spoolLine {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(s.spool, "*.ndjson"))
	sort.Strings(files)
	var out []spoolLine
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
		for sc.Scan() {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
				t.Fatalf("%s: unparseable spool line: %v", f, err)
			}
			var ev event.Event
			if err := json.Unmarshal(raw["event"], &ev); err != nil {
				t.Fatalf("%s: bad event: %v", f, err)
			}
			out = append(out, spoolLine{file: filepath.Base(f), raw: raw, ev: &ev, content: raw["content"]})
		}
		fh.Close()
	}
	return out
}

func (s *sandbox) ofKind(t *testing.T, k event.Kind) []*event.Event {
	var out []*event.Event
	for _, l := range s.lines(t) {
		if l.ev.Kind == k {
			out = append(out, l.ev)
		}
	}
	return out
}

func healthReasons(evs []*event.Event) []string {
	var r []string
	for _, e := range evs {
		if e.Health != nil {
			r = append(r, e.Health.Reason)
		}
	}
	return r
}

func expectedIntegrity() event.Integrity {
	if os.Geteuid() == 0 {
		return event.IntegrityRoot
	}
	return event.IntegrityUser
}

// Short names for swapping loadRuleSet in tests.
type (
	configT  = config.Config
	rulesSet = rules.Set
)

var errTest = errors.New("injected test error")
