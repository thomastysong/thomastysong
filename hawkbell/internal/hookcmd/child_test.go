package hookcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// envArgvDump makes a test-binary worker record the argument vector and the
// hand-off digest it was started with, so a test can check what crossed
// argv and what crossed the environment in a real supervisor run.
const envArgvDump = "HAWKBELL_HOOKCMD_TEST_ARGV_DUMP"

type argvDump struct {
	Args   []string
	Digest string
}

// init runs in every copy of the test binary, before TestMain; it acts only
// in a worker (envRole=hook) of a test that asked for the dump.
func init() {
	path := os.Getenv(envArgvDump)
	if path == "" || os.Getenv(envRole) != "hook" {
		return
	}
	for _, a := range os.Args {
		if a == "--worker" {
			b, _ := json.Marshal(argvDump{Args: os.Args, Digest: os.Getenv(envStdinSHA256)})
			_ = os.WriteFile(path, b, 0o600)
			return
		}
	}
}

func overCapInput(t *testing.T) (inputResult, string) {
	t.Helper()
	full := []byte(strings.Repeat("A", 5000))
	sum := sha256.Sum256(full)
	h := hex.EncodeToString(sum[:])
	return inputResult{b: full[:1001], eof: true, total: int64(len(full)), sum: h}, h
}

// The digest of an over-cap payload never appears on the worker's command
// line, which every local user can read; its size still does.
func TestWorkerArgsCarryNoDigest(t *testing.T) {
	in, h := overCapInput(t)
	t0 := time.Unix(1_700_000_000, 0)
	a := workerArgs(opts{agent: "claude-code", event: "PreToolUse"}, "/etc/hawkbell/hawkbell.yaml", 42, t0, t0.Add(time.Second), in)
	joined := strings.Join(a, " ")
	if strings.Contains(joined, h[:8]) || strings.Contains(joined, "sha256") {
		t.Fatalf("argv carries the payload digest: %q", a)
	}
	if !strings.Contains(joined, "--stdin-bytes 5000") {
		t.Fatalf("argv lost the drained size: %q", a)
	}
	// Under the cap there is nothing to hand off at all.
	small := inputResult{b: []byte("{}"), eof: true, total: 2}
	if j := strings.Join(workerArgs(opts{}, "c", 1, t0, t0, small), " "); strings.Contains(j, "--stdin-bytes") {
		t.Fatalf("argv for an ordinary payload: %q", j)
	}
}

func TestWorkerEnv(t *testing.T) {
	in, h := overCapInput(t)
	base := []string{"PATH=/usr/bin", envStdinSHA256 + "=" + strings.Repeat("0", 64), "HOME=/home/u", strings.ToLower(envStdinSHA256) + "=planted", "EMPTY="}
	got := workerEnv(base, in)
	var digests []string
	for _, kv := range got {
		if name, v, _ := strings.Cut(kv, "="); strings.EqualFold(name, envStdinSHA256) {
			digests = append(digests, v)
		}
	}
	if len(digests) != 1 || digests[0] != h {
		t.Fatalf("hand-off entries %q, want exactly the supervisor's digest", digests)
	}
	want := []string{"PATH=/usr/bin", "HOME=/home/u", "EMPTY="}
	if strings.Join(got[:len(got)-1], "\n") != strings.Join(want, "\n") {
		t.Fatalf("other variables changed: %q", got)
	}
	// Under the cap a planted digest is removed and none is added.
	small := inputResult{b: []byte("{}"), eof: true, total: 2}
	for _, kv := range workerEnv(base, small) {
		if name, _, _ := strings.Cut(kv, "="); strings.EqualFold(name, envStdinSHA256) {
			t.Fatalf("a hand-off digest reached a worker with an ordinary payload: %q", kv)
		}
	}
	if len(base) != 5 || base[1] != envStdinSHA256+"="+strings.Repeat("0", 64) {
		t.Fatal("workerEnv modified its input")
	}
	if handoffDigest(nil) != "" {
		t.Fatal("nil getenv")
	}
}

// A real supervisor run: the worker gets the digest through its
// environment, not argv, and the anomaly record still describes the whole
// payload. A digest the agent planted in the hook's environment is
// replaced, so it cannot be passed off as the supervisor's.
func TestDigestHandOffEndToEnd(t *testing.T) {
	s := newSandbox(t, cfgObserve+"limits:\n  max_hook_input_bytes: 65536\n")
	d := dialects[0]
	dump := filepath.Join(t.TempDir(), "argv.json")
	t.Setenv(envArgvDump, dump)
	planted := strings.Repeat("e", 64)
	t.Setenv(envStdinSHA256, planted)

	read := func() argvDump {
		t.Helper()
		b, err := os.ReadFile(dump)
		if err != nil {
			t.Fatalf("worker left no dump: %v", err)
		}
		var a argvDump
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(dump)
		return a
	}

	p := d.payload("echo " + strings.Repeat("A", 200000))
	sum := sha256.Sum256(p)
	h := hex.EncodeToString(sum[:])
	if r := s.supervised(t, d.agent, p, ""); r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	a := read()
	if strings.Contains(strings.Join(a.Args, " "), h[:8]) {
		t.Fatalf("the payload digest was on the worker's argv: %q", a.Args)
	}
	if !strings.Contains(strings.Join(a.Args, " "), "--stdin-bytes "+strconv.Itoa(len(p))) {
		t.Fatalf("the size was not passed: %q", a.Args)
	}
	if a.Digest != h {
		t.Fatalf("worker environment digest %q, want the supervisor's %q (planted %q)", a.Digest, h, planted)
	}
	var found bool
	for _, e := range s.ofKind(t, event.KindActivity) {
		if e.Type == event.TypePayloadAnomaly {
			found = true
			if e.Tool == nil || e.Tool.InputSHA256 != h || e.Labels["payload_bytes"] != strconv.Itoa(len(p)) {
				t.Fatalf("anomaly %+v %v", e.Tool, e.Labels)
			}
		}
	}
	if !found {
		t.Fatal("no anomaly record")
	}

	// An ordinary payload: no hand-off, and the planted value is gone.
	if r := s.supervised(t, d.agent, d.payload("ls"), ""); r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if a := read(); a.Digest != "" || strings.Contains(strings.Join(a.Args, " "), "--stdin-bytes") {
		t.Fatalf("ordinary payload: digest %q, args %q", a.Digest, a.Args)
	}
}
