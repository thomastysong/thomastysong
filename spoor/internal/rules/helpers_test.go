package rules

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/internal/event"
)

// dummyTest satisfies the loader's "at least one test" rule in packs built
// by Go tests.
const dummyTest = `
    tests:
      - {name: t, event: {type: tool.pre}, expect: no_match}`

// mustPack compiles a pack from the YAML of its rules list (each rule
// indented by two spaces, as under "rules:").
func mustPack(t *testing.T, rules string) *Set {
	t.Helper()
	s, err := Load(map[string][]byte{"p.yaml": []byte("pack: p\nversion: \"1\"\nrules:\n" + rules)})
	if err != nil {
		t.Fatalf("load: %v\n%s", err, rules)
	}
	return s
}

func mustPackWithLists(t *testing.T, rules, lists string) *Set {
	t.Helper()
	s, err := Load(map[string][]byte{
		"p.yaml":     []byte("pack: p\nversion: \"1\"\nrules:\n" + rules),
		"lists.yaml": []byte(lists),
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return s
}

func pred(t *testing.T, src string) *node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	n, err := compilePred(doc.Content[0], scopeEvent)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return n
}

// fakeClock is a settable time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)} }
func engine(s *Set, c *fakeClock) *Engine {
	return NewEngine(s, Options{Now: c.now, Home: "/home/u", OS: "linux"})
}
func withOpts(s *Set, o Options) *Engine     { return NewEngine(s, o) }
func ids(dets []*event.Event) (out []string) { return detIDs(dets) }

func detIDs(dets []*event.Event) []string {
	var out []string
	for _, d := range dets {
		switch {
		case d.Detection != nil:
			out = append(out, d.Detection.RuleID)
		case d.Check != nil:
			out = append(out, "posture:"+d.Check.ID)
		}
	}
	return out
}

// evSeq numbers test events; atomic because TestConcurrentEval builds
// events from several goroutines.
var evSeq atomic.Int64

// ev builds an activity event in session sid of user 1000 / agent a.
func ev(typ string, mods ...func(*event.Event)) *event.Event {
	n := evSeq.Add(1)
	e := &event.Event{
		V: 1, ID: fmt.Sprintf("ev-%d", n), Kind: event.KindActivity, Type: typ, Source: event.SourceHook,
		Host:    &event.Host{ID: "host-1", OS: "linux"},
		User:    &event.User{ID: "1000", Name: "u"},
		Agent:   &event.Agent{ID: "claude-code"},
		Session: &event.Session{ID: "s1", CWD: "/home/u/proj"},
	}
	for _, m := range mods {
		m(e)
	}
	return e
}

func shell(cmd string) func(*event.Event) {
	return func(e *event.Event) {
		e.Tool = &event.Tool{Kind: event.ToolShell, Name: "Bash"}
		e.Target = &event.Target{Command: cmd}
	}
}

func file(kind event.ToolKind, path string) func(*event.Event) {
	return func(e *event.Event) {
		e.Tool = &event.Tool{Kind: kind, Name: "Tool"}
		e.Target = &event.Target{Path: path}
	}
}

func web(url string) func(*event.Event) {
	return func(e *event.Event) {
		e.Tool = &event.Tool{Kind: event.ToolWebFetch, Name: "WebFetch"}
		e.Target = &event.Target{URL: url}
	}
}

func session(id string) func(*event.Event) {
	return func(e *event.Event) { e.Session.ID = id }
}

func subagent(id string) func(*event.Event) {
	return func(e *event.Event) { e.Session.SubagentID = id }
}

func user(id string) func(*event.Event) {
	return func(e *event.Event) { e.User = &event.User{ID: id, Name: "same-name"} }
}

func output(s string) func(*event.Event) {
	return func(e *event.Event) {
		if e.Content == nil {
			e.Content = &event.Content{}
		}
		e.Content.ToolOutput = s
	}
}

func contains2(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n")
}
