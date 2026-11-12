package sink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

var testTime = time.Date(2026, 11, 11, 10, 20, 30, 123456789, time.UTC)

// testEvent builds an activity event with a deterministic identity and a
// command of the requested size, so a torn or merged line is detectable:
// the command must be exactly n copies of fill and Labels["n"] must say n.
func testEvent(id string, n int) *event.Event {
	fill := byte('a' + len(id)%26)
	return &event.Event{
		V: event.SchemaVersion, ID: id, TS: event.At(testTime), Kind: event.KindActivity, Type: event.TypeToolPre,
		Source: event.SourceHook,
		Host:   &event.Host{ID: "host-1", Name: "h1", OS: "linux", Arch: "amd64"},
		Agent:  &event.Agent{ID: "claude-code"},
		Tool:   &event.Tool{Name: "Bash", Kind: event.ToolShell, UseID: "use-" + id},
		Target: &event.Target{Command: strings.Repeat(string(fill), n)},
		Labels: map[string]string{"n": fmt.Sprint(n), "fill": string(fill)},
	}
}

// checkTestEvent verifies the self-describing payload of testEvent.
func checkTestEvent(e *event.Event) error {
	if e.Target == nil || e.Labels == nil {
		return fmt.Errorf("event %s lost its payload", e.ID)
	}
	want := strings.Repeat(e.Labels["fill"], atoi(e.Labels["n"]))
	if e.Target.Command != want {
		return fmt.Errorf("event %s: command has %d bytes, label says %s", e.ID, len(e.Target.Command), e.Labels["n"])
	}
	return nil
}

func atoi(s string) int {
	n := 0
	fmt.Sscan(s, &n)
	return n
}

func kindEvent(kind event.Kind, id string) *event.Event {
	e := testEvent(id, 16)
	e.Kind = kind
	switch kind {
	case event.KindDetection:
		e.Type = event.TypeDetectionFinding
		e.Detection = &event.Detection{RuleID: "HB-1", Title: "t", Severity: event.SevHigh}
	case event.KindInventory:
		e.Type = event.TypeInventoryAsset
		e.Asset = &event.Asset{ID: "a-" + id, Kind: event.AssetAgent, Name: "x"}
	case event.KindPosture:
		e.Type = event.TypePostureCheck
		e.Check = &event.Check{ID: "c-" + id, Status: "pass"}
	case event.KindHealth:
		e.Type = event.TypeHealthHeartbeat
		e.Health = &event.Health{SensorVersion: "0", Mode: "daemon"}
	}
	return e
}

// segmentFiles lists segment file names in dir, oldest first.
func segmentFiles(t testing.TB, dir string) []string {
	t.Helper()
	segs, err := listSegments(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	sortSegments(segs)
	names := make([]string, len(segs))
	for i, g := range segs {
		names[i] = g.name
	}
	return names
}

// readLines returns every line of every segment in dir. It fails the test
// if a file does not end with a newline.
func readLines(t testing.TB, dir string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, name := range segmentFiles(t, dir) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			t.Fatalf("%s does not end with a newline", name)
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// readEvents parses every line in dir as a native event.
func readEvents(t testing.TB, dir string) []*event.Event {
	t.Helper()
	var out []*event.Event
	for _, line := range readLines(t, dir) {
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unparsable line (%v): %.120q", err, line)
		}
		out = append(out, &e)
	}
	return out
}

// memSink is a destination that records what it was given and can be told
// to fail.
type memSink struct {
	mu      sync.Mutex
	name    string
	got     []*event.Event
	batches [][]string
	fail    func(batch []*event.Event) error // called before recording
	flushes int
}

func (m *memSink) Name() string {
	if m.name == "" {
		return "mem"
	}
	return m.name
}

func (m *memSink) Write(batch []*event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		if err := m.fail(batch); err != nil {
			return err
		}
	}
	ids := make([]string, len(batch))
	for i, e := range batch {
		ids[i] = e.ID
	}
	m.got = append(m.got, batch...)
	m.batches = append(m.batches, ids)
	return nil
}

func (m *memSink) Flush() error {
	m.mu.Lock()
	m.flushes++
	m.mu.Unlock()
	return nil
}

func (m *memSink) Close() error { return nil }

func (m *memSink) ids() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.got))
	for i, e := range m.got {
		out[i] = e.ID
	}
	return out
}

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.got)
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

// permErr is a delivery error the destination will never accept.
type permErr struct{ msg string }

func (e permErr) Error() string   { return e.msg }
func (e permErr) Permanent() bool { return true }
