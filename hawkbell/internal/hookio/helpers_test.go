package hookio

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// sha256Hex is the plain SHA-256 a test compares toolmap.InputHash
// against; the package itself no longer hashes free text.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fixture reads a recorded hook payload from testdata.
func fixture(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("fixture %s: %v", rel, err)
	}
	return b
}

func dialect(t testing.TB, id string) Dialect {
	t.Helper()
	d, ok := Get(id)
	if !ok {
		t.Fatalf("no dialect %q", id)
	}
	return d
}

// parseOne parses a payload that must yield exactly one event.
func parseOne(t testing.TB, d Dialect, stdin []byte, env map[string]string) (*event.Event, *Request) {
	t.Helper()
	evs, req, err := d.Parse(stdin, env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("Parse returned %d events, want 1", len(evs))
	}
	if req == nil {
		t.Fatal("Parse returned nil request")
	}
	checkInvariants(t, d, evs[0], req)
	return evs[0], req
}

// checkInvariants asserts what every event from every dialect must satisfy.
func checkInvariants(t testing.TB, d Dialect, e *event.Event, req *Request) {
	t.Helper()
	if e.V != event.SchemaVersion || e.ID == "" || e.TS.IsZero() {
		t.Errorf("event not initialized: v=%d id=%q ts=%v", e.V, e.ID, e.TS)
	}
	if e.Kind != event.KindActivity || e.Source != event.SourceHook || e.Fidelity != event.FidelityObserved {
		t.Errorf("kind/source/fidelity = %q/%q/%q", e.Kind, e.Source, e.Fidelity)
	}
	if e.Type == "" {
		t.Error("empty event type")
	}
	wantAgent, _ := AgentIDFor(d.ID())
	if e.Agent == nil || e.Agent.ID != wantAgent {
		t.Errorf("agent = %+v, want id %q", e.Agent, wantAgent)
	}
	if req.AgentID != wantAgent {
		t.Errorf("request agent = %q, want %q", req.AgentID, wantAgent)
	}
	if e.Session == nil || e.Content == nil {
		t.Fatal("session/content must always be set")
	}
	if e.Labels["hook_event"] == "" {
		t.Error("hook_event label missing")
	}
	// Every label value is a token over the label alphabet, except the
	// project_dir path label.
	for k, v := range e.Labels {
		if k == "project_dir" {
			continue
		}
		if v != labelValue(v) || len(v) > maxLabel {
			t.Errorf("label %s=%q is not a sanitized token", k, v)
		}
	}
	// The event must serialize to exactly one line.
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	if strings.Count(string(line), "\n") != 1 || !json.Valid(line) {
		t.Errorf("event does not serialize to one JSON line: %q", line)
	}
}

func eq(t testing.TB, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

// decodeReply parses a hook reply and fails if it is not one JSON object on
// one line (Claude Code, Copilot and Gemini all reject anything else).
func decodeReply(t testing.TB, stdout []byte) map[string]any {
	t.Helper()
	if len(stdout) == 0 {
		t.Fatal("empty stdout, want a JSON reply")
	}
	if !strings.HasSuffix(string(stdout), "\n") || strings.Count(string(stdout), "\n") != 1 {
		t.Errorf("reply is not exactly one line: %q", stdout)
	}
	var m map[string]any
	if err := json.Unmarshal(stdout, &m); err != nil {
		t.Fatalf("reply is not a JSON object: %v: %q", err, stdout)
	}
	return m
}

func outcome(e *event.Event) event.Outcome {
	if e.Outcome == nil {
		return event.Outcome{}
	}
	o := *e.Outcome
	o.ExitCode = nil
	return o
}

func exitCodeOf(e *event.Event) int {
	if e.Outcome == nil || e.Outcome.ExitCode == nil {
		return -1
	}
	return *e.Outcome.ExitCode
}

func tool(e *event.Event) event.Tool {
	if e.Tool == nil {
		return event.Tool{}
	}
	return *e.Tool
}

func target(e *event.Event) event.Target {
	if e.Target == nil {
		return event.Target{}
	}
	return *e.Target
}
