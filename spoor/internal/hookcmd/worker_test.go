package hookcmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/rules"
)

// countRuleLoads swaps loadRuleSet for a counting wrapper.
func countRuleLoads(t *testing.T) *int {
	t.Helper()
	saved := loadRuleSet
	t.Cleanup(func() { loadRuleSet = saved })
	n := new(int)
	loadRuleSet = func(c *config.Config, g bool) (*rules.Set, bool, error) {
		*n++
		return saved(c, g)
	}
	return n
}

// Observe mode is normalize, stamp, append, exit: no rule is loaded.
func TestObserveLoadsNoRules(t *testing.T) {
	for _, c := range []struct {
		cfg  string
		want int
	}{{cfgObserve, 0}, {cfgGuard, 1}, {cfgDetect, 1}} {
		s := newSandbox(t, c.cfg)
		n := countRuleLoads(t)
		r := s.worker(t, OSEnv(), "claude-code", dialects[0].payload("spoor-test-block x"))
		if r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
		if *n != c.want {
			t.Fatalf("config %q: rule set loaded %d times, want %d", c.cfg, *n, c.want)
		}
		if c.cfg == cfgObserve && len(r.stdout) != 0 {
			t.Fatalf("observe replied %s", r.stdout)
		}
	}
}

// In-hook detection appends findings (and their context) next to the
// activity: privacy-processed, without local content, integrity from the
// OS. The reply stays empty without guard.
func TestDetectInHook(t *testing.T) {
	s := newSandbox(t, cfgDetect)
	r := s.supervised(t, "claude-code", dialects[0].payload("spoor-test-block --token=hunter2hunter2"), "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("exit %d reply %s", r.code, r.stdout)
	}
	var finding, context int
	for _, l := range s.lines(t) {
		if l.ev.Kind != event.KindDetection {
			continue
		}
		if l.content != nil {
			t.Fatalf("%s line carries local content: %s", l.ev.Type, l.content)
		}
		if l.ev.Integrity != expectedIntegrity() || l.ev.Privacy == "" || l.ev.Writer == "" || l.ev.Seq == 0 {
			t.Fatalf("%s: integrity %q privacy %q writer %q seq %d", l.ev.Type, l.ev.Integrity, l.ev.Privacy, l.ev.Writer, l.ev.Seq)
		}
		switch l.ev.Type {
		case event.TypeDetectionFinding:
			finding++
			if l.ev.Detection.RuleID != "SPR-TEST-001" || l.ev.Detection.Enforced {
				t.Fatalf("finding %+v", l.ev.Detection)
			}
		case "detection.context":
			context++
		}
		raw, _ := l.raw["event"].MarshalJSON()
		if bytes.Contains(raw, []byte("hunter2hunter2")) {
			t.Fatalf("secret in a shippable record: %s", raw)
		}
	}
	if finding != 1 || context == 0 {
		t.Fatalf("findings %d context %d", finding, context)
	}
	if acts := s.ofKind(t, event.KindActivity); len(acts) != 1 || acts[0].Labels["hook_mode"] != "detect" {
		t.Fatalf("activity: %d", len(acts))
	}
}

// Identity comes from the OS, never from the payload; ids are
// deterministic; the caller chain is captured.
func TestStampingFromOS(t *testing.T) {
	s := newSandbox(t, cfgObserve)
	env := OSEnv()
	env.User = "os-account"
	env.PPID = os.Getpid() // the "agent" is this test process
	t0 := time.Date(2026, 11, 12, 8, 0, 0, 123456000, time.UTC)
	payload := []byte(`{"session_id":"s-id","cwd":"/work/p","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"id"},"tool_use_id":"toolu_x","user":"mallory","uid":"0","host":{"id":"forged"},"integrity":"root"}`)
	for i := 0; i < 2; i++ {
		r := s.worker(t, env, "claude-code", payload, "--t0", strconv.FormatInt(t0.UnixNano(), 10))
		if r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
	}
	acts := s.ofKind(t, event.KindActivity)
	if len(acts) != 2 {
		t.Fatalf("%d records", len(acts))
	}
	a := acts[0]
	host := platform.HostInfo()
	if a.User == nil || a.User.Name != "os-account" || a.User.ID != env.UID {
		t.Fatalf("user %+v", a.User)
	}
	if a.Host == nil || a.Host.ID != host.ID || a.Integrity != expectedIntegrity() {
		t.Fatalf("host %+v integrity %s", a.Host, a.Integrity)
	}
	if !a.TS.Equal(t0) {
		t.Fatalf("ts %v want %v", a.TS, t0)
	}
	exe, _ := os.Executable()
	p := a.Process
	if p == nil || p.PID != os.Getpid() || p.PPID != os.Getppid() || p.Exe != exe || p.StartTime.IsZero() || len(p.Ancestors) == 0 || len(p.Ancestors) > maxAncestors {
		t.Fatalf("process %+v (exe %s)", p, exe)
	}
	wantDedupe := event.DedupeKey(host.ID, "claude-code", "s-id", "tool:toolu_x", event.TypeToolPre)
	if a.Dedupe != wantDedupe || a.ID != event.StableID(t0, host.ID, "claude-code", "s-id", "tool:toolu_x", event.TypeToolPre) {
		t.Fatalf("dedupe %s id %s", a.Dedupe, a.ID)
	}
	if acts[1].ID != a.ID || acts[1].Dedupe != a.Dedupe || acts[1].Seq != a.Seq+1 {
		t.Fatalf("replay not deterministic or seq not consecutive: %s/%s seq %d,%d", acts[1].ID, a.ID, a.Seq, acts[1].Seq)
	}
	if a.Labels["hook_mode"] != "observe" || a.Writer != "hook-"+env.UID {
		t.Fatalf("labels %v writer %s", a.Labels, a.Writer)
	}
}

// Without a tool use id the natural key is a keyed digest of the payload:
// stable for one user (duplicate registrations collapse) but not the
// unkeyed hash a log reader could recompute from a guessed prompt.
func TestPayloadKeyIsKeyed(t *testing.T) {
	s := newSandbox(t, cfgObserve)
	prompt := []byte(`{"session_id":"s-p","transcript_path":"/x","cwd":"/w","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"deploy to prod"}`)
	other := bytes.Replace(prompt, []byte("prod"), []byte("staging"), 1)
	for _, p := range [][]byte{prompt, prompt, other} {
		if r := s.worker(t, OSEnv(), "claude-code", p); r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
	}
	acts := s.ofKind(t, event.KindActivity)
	if len(acts) != 3 || acts[0].Type != event.TypePromptSubmit {
		t.Fatalf("records %d", len(acts))
	}
	if acts[0].Dedupe != acts[1].Dedupe || acts[0].Dedupe == acts[2].Dedupe {
		t.Fatalf("payload keys: %s %s %s", acts[0].Dedupe, acts[1].Dedupe, acts[2].Dedupe)
	}
	sum := sha256.Sum256(prompt)
	h := acts[0].Host.ID
	for _, unkeyed := range []string{"p:" + hex.EncodeToString(sum[:]), "p:" + hex.EncodeToString(sum[:16]), hex.EncodeToString(sum[:])} {
		if acts[0].Dedupe == event.DedupeKey(h, "claude-code", "s-p", unkeyed, event.TypePromptSubmit) {
			t.Fatal("dedupe is an unkeyed digest of the payload")
		}
	}
	// Without a usable secret there is no payload key at all.
	st := &stamper{payload: prompt}
	if st.payloadKey() != "" {
		t.Fatal("payload key without a secret")
	}
}

// Undecodable payloads produce an anomaly record instead of nothing.
func TestPayloadAnomalies(t *testing.T) {
	deep := `{"hook_event_name":"PreToolUse","session_id":"s-deep","tool_name":"Bash","tool_input":` + strings.Repeat(`{"a":`, 80) + `1` + strings.Repeat("}", 80) + `}`
	cases := []struct {
		name, agent, payload, code string
		salvage                    bool
	}{
		{"empty", "claude-code", "", anomalyEmpty, false},
		{"whitespace", "claude-code", " \n\t ", anomalyEmpty, false},
		{"not json", "claude-code", "rm -rf / # not json", anomalyMalformed, false},
		{"array", "codex", `[{"hook_event_name":"PreToolUse"}]`, anomalyMalformed, false},
		{"two objects", "claude-code", `{"hook_event_name":"Stop","session_id":"a"}{"hook_event_name":"Stop"}`, anomalyMalformed, false},
		{"truncated", "gemini-cli", `{"hook_event_name":"BeforeTool","session_id":"s-trunc","tool_input":{"command":"ls`, anomalyMalformed, false},
		{"no event", "claude-code", `{"session_id":"s-x","cwd":"/w"}`, anomalyNoEvent, false},
		{"too deep", "claude-code", deep, anomalyTooDeep, true},
		{"unknown agent", "not-an-agent", `{"foo":"bar"}`, anomalyUnknownAgent, false},
		{"invalid utf8", "claude-code", "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"\xff\xfe\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo \xc3\x28\"}}", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, cfgObserve)
			// A clean environment: this test may itself run inside an
			// agent, whose markers would let detection guess the dialect.
			env := OSEnv()
			env.Getenv = func(string) string { return "" }
			r := s.worker(t, env, c.agent, []byte(c.payload))
			if r.code != 0 || len(r.stdout) != 0 || len(r.stderr) != 0 {
				t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
			}
			acts := s.ofKind(t, event.KindActivity)
			var anomaly *event.Event
			others := 0
			for _, a := range acts {
				if a.Type == TypePayloadAnomaly {
					anomaly = a
				} else {
					others++
				}
			}
			if c.code == "" {
				if anomaly != nil || others != 1 {
					t.Fatalf("valid payload: anomaly %v, %d events", anomaly != nil, others)
				}
				return
			}
			if anomaly == nil {
				t.Fatalf("no anomaly record (%d others)", others)
			}
			sum := sha256.Sum256([]byte(c.payload))
			if anomaly.Labels["hook_error"] != c.code || anomaly.Labels["payload_bytes"] != strconv.Itoa(len(c.payload)) ||
				anomaly.Tool == nil || anomaly.Tool.InputSHA256 != hex.EncodeToString(sum[:]) || anomaly.User == nil || anomaly.Host == nil {
				t.Fatalf("anomaly %+v labels %v", anomaly, anomaly.Labels)
			}
			if c.salvage != (others > 0) {
				t.Fatalf("salvage events: %d", others)
			}
		})
	}
}

// Over an operator cap below hookio's: an anomaly, nothing decoded.
func TestInputCap(t *testing.T) {
	s := newSandbox(t, cfgObserve+"limits:\n  max_hook_input_bytes: 65536\n")
	big := dialects[0].payload("echo " + strings.Repeat("x", 100000))
	r := s.worker(t, OSEnv(), "claude-code", big)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	// Size and digest describe the whole payload, not the kept prefix.
	acts := s.ofKind(t, event.KindActivity)
	sum := sha256.Sum256(big)
	if len(acts) != 1 || acts[0].Type != TypePayloadAnomaly || acts[0].Labels["hook_error"] != anomalyTooLarge ||
		acts[0].Labels["payload_bytes"] != strconv.Itoa(len(big)) || acts[0].Tool.InputSHA256 != hex.EncodeToString(sum[:]) ||
		acts[0].Session.ID != "s-claude" {
		t.Fatalf("%+v", acts)
	}
	if inputCap(&config.Config{Limits: config.Limits{MaxHookInput: 10}}) != minInputCap ||
		inputCap(&config.Config{Limits: config.Limits{MaxHookInput: 1 << 30}}) != 8<<20 {
		t.Fatal("cap clamping")
	}
}

// Excluded sessions leave no record and get no decision.
func TestExclusions(t *testing.T) {
	s := newSandbox(t, cfgGuard+"privacy:\n  exclude:\n    paths: [\"/work/secret*\"]\n")
	p := bytes.Replace(dialects[0].payload("spoor-test-block x"), []byte(`"/work/p"`), []byte(`"/work/secret-project"`), 1)
	r := s.supervised(t, "claude-code", p, "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("exit %d reply %s", r.code, r.stdout)
	}
	if l := s.lines(t); len(l) != 0 {
		t.Fatalf("%d records for an excluded session", len(l))
	}
}

// The kill switch and hooks.enabled: false answer at once, start no worker
// and write nothing.
func TestKillSwitchAndDisabled(t *testing.T) {
	for name, setup := range map[string]func(s *sandbox){
		"kill switch": func(s *sandbox) { os.WriteFile(filepath.Join(s.dir, platform.KillSwitchName), nil, 0o600) },
		"disabled":    func(s *sandbox) { os.WriteFile(s.cfg, []byte("sources:\n  hooks:\n    enabled: false\n"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, cfgGuard)
			setup(s)
			env := OSEnv()
			env.Exe = filepath.Join(s.dir, "would-fail-if-started")
			var out, errb bytes.Buffer
			start := time.Now()
			code := Run(strings.NewReader(string(dialects[0].payload("spoor-test-block x"))), &out, &errb, []string{"--agent", "claude-code", "--config", s.cfg}, env)
			if code != 0 || out.Len() != 0 || errb.Len() != 0 {
				t.Fatalf("exit %d out %q err %q", code, out.String(), errb.String())
			}
			if d := time.Since(start); d > 200*time.Millisecond*raceSlowdown {
				t.Fatalf("took %v", d)
			}
			if l := s.lines(t); len(l) != 0 {
				t.Fatalf("%d records written", len(l))
			}
		})
	}
	if killSwitch("") != platform.Disabled() {
		t.Fatal("empty config path must defer to the platform kill switch")
	}
}

// A broken config falls back to observe defaults and says so on the
// records; it never breaks the hook.
func TestBrokenConfig(t *testing.T) {
	s := newSandbox(t, "guard: [this is not valid\n")
	r := s.supervised(t, "claude-code", dialects[0].payload("spoor-test-block x"), "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("exit %d reply %s", r.code, r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["hook_config"] != "invalid" || a.Labels["hook_mode"] != "observe" {
		t.Fatalf("labels %v", a.Labels)
	}
}

func TestWatchdog(t *testing.T) {
	saved := exitFunc
	defer func() { exitFunc = saved }()
	got := make(chan int, 1)
	exitFunc = func(c int) { got <- c }
	armWatchdog(time.Now())
	select {
	case c := <-got:
		if c != exitWatchdog {
			t.Fatalf("code %d", c)
		}
	case <-time.After(watchdogSlack + time.Second):
		t.Fatal("watchdog did not fire")
	}
}

type blockingReader struct{ ch chan struct{} }

func (b blockingReader) Read([]byte) (int, error) { <-b.ch; return 0, os.ErrClosed }

type slowReader struct {
	data []byte
	done bool
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.done {
		select {} // a writer that never closes stdin
	}
	s.done = true
	return copy(p, s.data), nil
}

func TestReadBounded(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	start := time.Now()
	r := readBounded(blockingReader{stop}, 1024, 50*time.Millisecond)
	if !r.timedOut || r.eof || len(r.b) != 0 || time.Since(start) > time.Second {
		t.Fatalf("blocking reader: %+v", r)
	}
	// Data then silence: the bytes read so far are kept.
	r = readBounded(&slowReader{data: []byte(`{"a":1}`)}, 1024, 50*time.Millisecond)
	if !r.timedOut || string(r.b) != `{"a":1}` {
		t.Fatalf("slow reader: %+v", r)
	}
	// Over the cap: max+1 bytes kept, the rest drained to EOF.
	r = readBounded(bytes.NewReader(bytes.Repeat([]byte("x"), 300000)), 1000, time.Second)
	if !r.eof || len(r.b) != 1001 {
		t.Fatalf("cap: eof %v len %d", r.eof, len(r.b))
	}
}

// Many hooks at once: every line parses and sequence numbers are unique
// and gapless per stream.
func TestConcurrentHooks(t *testing.T) {
	// Nothing here should hang, so a long deadline only keeps a loaded
	// (or race-instrumented) machine from turning slow workers into
	// timeouts.
	saved := observeDeadline
	observeDeadline = 10 * time.Second
	defer func() { observeDeadline = saved }()
	s := newSandbox(t, cfgObserve)
	t.Setenv(envRole, "hook")
	t.Setenv(envFault, "")
	exe, _ := os.Executable()
	env := OSEnv()
	env.Exe = exe
	const workers, each = 8, 6
	var wg sync.WaitGroup
	errs := make(chan string, workers*each)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				var out, errb bytes.Buffer
				p := dialects[g%len(dialects)].payload("echo " + strconv.Itoa(g*100+i))
				if c := Run(bytes.NewReader(p), &out, &errb, []string{"--agent", dialects[g%len(dialects)].agent, "--config", s.cfg}, env); c != 0 || out.Len() != 0 {
					errs <- "exit " + strconv.Itoa(c) + " " + out.String()
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	acts := s.ofKind(t, event.KindActivity)
	if len(acts) != workers*each {
		t.Fatalf("%d records, want %d (health: %v)", len(acts), workers*each, healthReasons(s.ofKind(t, event.KindHealth)))
	}
	seen := map[uint64]bool{}
	for _, a := range acts {
		if seen[a.Seq] {
			t.Fatalf("duplicate seq %d", a.Seq)
		}
		seen[a.Seq] = true
	}
	for i := uint64(1); i <= uint64(len(acts)); i++ {
		if !seen[i] {
			t.Fatalf("seq gap at %d", i)
		}
	}
}
