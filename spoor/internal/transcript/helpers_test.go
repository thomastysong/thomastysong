package transcript

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// parseLines feeds lines to a parser with a fresh state for path.
func parseLines(t *testing.T, p Parser, path string, lines ...string) ([]*event.Event, *FileState) {
	t.Helper()
	st := &FileState{Path: path}
	return parseInto(t, p, st, lines...), st
}

func parseInto(t *testing.T, p Parser, st *FileState, lines ...string) []*event.Event {
	t.Helper()
	var out []*event.Event
	for _, l := range lines {
		evs, _ := p.ParseLine([]byte(l), st)
		out = append(out, evs...)
	}
	return out
}

// brief renders an event as "type", "type name status" etc. for sequence
// assertions.
func brief(e *event.Event) string {
	s := e.Type
	if e.Tool != nil && e.Tool.Name != "" {
		s += " " + e.Tool.Name
	}
	if e.Outcome != nil {
		if e.Outcome.Status != "" {
			s += " " + e.Outcome.Status
		}
		if e.Outcome.Decision != "" {
			s += " " + e.Outcome.Decision
		}
	}
	return s
}

func briefs(evs []*event.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = brief(e)
	}
	return out
}

func wantSeq(t *testing.T, evs []*event.Event, want ...string) {
	t.Helper()
	got := briefs(evs)
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d:\n got: %s\nwant: %s", len(got), len(want), strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// find returns the first event of a type whose tool use id matches (any when
// useID is "").
func find(t *testing.T, evs []*event.Event, typ, useID string) *event.Event {
	t.Helper()
	for _, e := range evs {
		if e.Type != typ {
			continue
		}
		if useID == "" || (e.Tool != nil && e.Tool.UseID == useID) {
			return e
		}
	}
	t.Fatalf("no %s event with use id %q", typ, useID)
	return nil
}

// checkCommon asserts the invariants every transcript event must hold.
func checkCommon(t *testing.T, evs []*event.Event, agent, path string) {
	t.Helper()
	ids := map[string]bool{}
	for i, e := range evs {
		if e.V != event.SchemaVersion || e.Kind != event.KindActivity {
			t.Errorf("event %d: v=%d kind=%q", i, e.V, e.Kind)
		}
		if e.Source != event.SourceTranscript || e.Fidelity != event.FidelityObserved {
			t.Errorf("event %d: source=%q fidelity=%q", i, e.Source, e.Fidelity)
		}
		if e.Agent == nil || e.Agent.ID != agent {
			t.Errorf("event %d: agent=%+v", i, e.Agent)
		}
		if e.Session == nil || e.Session.Transcript != path {
			t.Errorf("event %d: session=%+v", i, e.Session)
		}
		if e.TS.IsZero() {
			t.Errorf("event %d: zero timestamp", i)
		}
		if len(e.ID) != 36 || e.ID[14] != '7' {
			t.Errorf("event %d: id %q is not UUIDv7-shaped", i, e.ID)
		}
		if ids[e.ID] {
			t.Errorf("event %d: duplicate id %s", i, e.ID)
		}
		ids[e.ID] = true
		if (e.Type == event.TypeToolPre || e.Type == event.TypeToolPost) && (e.Tool == nil || e.Tool.UseID == "") {
			t.Errorf("event %d (%s): no tool use id", i, e.Type)
		}
		if _, err := e.MarshalLine(); err != nil {
			t.Errorf("event %d: marshal: %v", i, err)
		}
	}
}

// wire is the NDJSON every event would serialize to, for leak checks.
func wire(t *testing.T, evs []*event.Event) string {
	t.Helper()
	var sb strings.Builder
	for _, e := range evs {
		b, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
	}
	return sb.String()
}

func sameIDs(a, b []*event.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func lines(ls ...string) string { return strings.Join(ls, "\n") + "\n" }

func probKinds(ps []Problem) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Kind
	}
	return out
}

func hasProblem(ps []Problem, kind, path string) bool {
	for _, p := range ps {
		if p.Kind == kind && (path == "" || p.Path == path) {
			return true
		}
	}
	return false
}

func mustPoll(t *testing.T, tl *Tailer) ([]*event.Event, []Problem) {
	t.Helper()
	evs, probs, err := tl.Poll(t.Context())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return evs, probs
}

func claudePrompt(session string, i int, text string) string {
	return fmt.Sprintf(`{"type":"user","sessionId":%q,"timestamp":"2026-11-01T10:%02d:%02d.000Z","cwd":"/work/repo","version":"2.1.300","message":{"role":"user","content":%q}}`,
		session, (i/60)%60, i%60, text)
}

// mustAny decodes a JSON value the way a parser sees it; "" is an absent field.
func mustAny(t *testing.T, raw string) any {
	t.Helper()
	if raw == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("bad test JSON %q: %v", raw, err)
	}
	return v
}
