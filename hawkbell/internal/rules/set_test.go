package rules

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestMergeDisableCount(t *testing.T) {
	base := mustPackWithLists(t, goodRule+strings.Replace(goodRule, "HB-T-001", "HB-T-002", 1), "lists:\n  a: [x]\n  b: [y]\n")
	over, err := Load(map[string][]byte{
		"o.yaml":     []byte("pack: o\nversion: \"9\"\nrules:\n" + strings.Replace(goodRule, "title: t", "title: overridden", 1) + strings.Replace(goodRule, "HB-T-001", "HB-T-003", 1)),
		"lists.yaml": []byte("lists:\n  a: [z]\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	over.Disable("HB-T-002")
	base.Merge(over)
	info := base.Rules()
	if len(info) != 3 || info[0].ID != "HB-T-001" || info[0].Title != "overridden" || info[0].Pack != "o" || info[2].ID != "HB-T-003" {
		t.Fatalf("merged rules %+v", info)
	}
	if base.Count() != 2 || info[1].Enabled {
		t.Errorf("disable did not carry over: count %d", base.Count())
	}
	if !base.lists["a"].match("z") || base.lists["a"].match("x") || !base.lists["b"].match("y") {
		t.Error("lists must be replaced by name and kept otherwise")
	}
	if base.Version() != "o@9,p@1" {
		t.Errorf("version %q", base.Version())
	}
	base.Merge(nil)
	// Disabling an id before the pack that defines it arrives works.
	s := newSet()
	s.Disable("HB-T-001", "")
	s.Merge(mustPack(t, goodRule))
	if s.Count() != 0 {
		t.Error("pre-disabled rule enabled by merge")
	}
	if NewEngine(s, Options{}).Eval(ev(event.TypeToolPre, func(e *event.Event) { e.Feat = map[string]any{"b": true} })).Detections != nil {
		t.Error("disabled rule evaluated")
	}
}

func TestHashStableAndSensitive(t *testing.T) {
	a := mustPack(t, goodRule)
	// Same content, different formatting, comments and key order.
	b := mustPack(t, `  # comment
  - title: t
    id: HB-T-001
    match:
      b: true
    severity: low
    tests: [{expect: no_match, name: t, event: {type: tool.pre}}]
`)
	if a.Hash() != b.Hash() {
		t.Error("formatting changed the hash")
	}
	if len(a.Hash()) != 64 {
		t.Error("hash is not hex sha256")
	}
	c := mustPack(t, strings.Replace(goodRule, "b: true", "b: false", 1))
	if a.Hash() == c.Hash() {
		t.Error("content change kept the hash")
	}
	d := mustPackWithLists(t, goodRule, "lists:\n  x: [a]\n")
	if a.Hash() == d.Hash() {
		t.Error("lists not hashed")
	}
	e := a.clone()
	e.Disable("HB-T-001")
	if a.Hash() == e.Hash() {
		t.Error("enabled state not hashed")
	}
}

func TestGuardSubset(t *testing.T) {
	s := mustPack(t, flagRules+`  - id: HB-G-001
    title: guard
    severity: high
    when: {type: tool.pre}
    match: {path.sensitive_read: true}
    flags: {require: [untrusted]}
    response: ask`+dummyTest+`
  - id: HB-G-002
    title: block
    severity: high
    when: {type: tool.pre}
    match: {shell.destructive|exists: true}
    response: block`+dummyTest+`
  - id: HB-G-003
    title: disabled guard
    severity: high
    when: {type: tool.pre}
    match: {tool.kind: shell}
    response: block`+dummyTest+"\n")
	s.Disable("HB-G-003")
	g := s.GuardSubset()
	got := map[string]bool{}
	for _, i := range g.Rules() {
		got[i.ID] = true
		if i.ID == "HB-F-001" && i.Emit {
			t.Error("flag maintainer must not emit in the guard subset")
		}
	}
	for _, want := range []string{"HB-G-001", "HB-G-002", "HB-F-001"} {
		if !got[want] {
			t.Errorf("guard subset lacks %s: %v", want, got)
		}
	}
	for _, not := range []string{"HB-F-002", "HB-F-003", "HB-F-004", "HB-G-003"} {
		if got[not] {
			t.Errorf("guard subset has %s", not)
		}
	}
	// The dependency works inside a hook-mode engine.
	e := engine(g, newClock())
	e.Eval(ev(event.TypeToolPost, web("https://x.example")))
	r := e.Eval(ev(event.TypeToolPre, file(event.ToolFileRead, "/home/u/.ssh/id_rsa")))
	if r.Response != ResponseAsk || r.Rule != "HB-G-001" {
		t.Fatalf("guard response %+v", r)
	}
	if !equalStrings(ids(r.Detections), []string{"HB-G-001"}) {
		t.Errorf("guard detections %v", ids(r.Detections))
	}
	if g.Hash() == s.Hash() {
		t.Error("subset hash equals the full set's")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRulesInfo(t *testing.T) {
	s, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range s.Rules() {
		if i.ID == "" || i.Title == "" || i.Severity == "" || i.Kind == "" || i.Class == "" || i.Maturity == "" || i.Response == "" || i.Tests == 0 || i.PackVersion == "" {
			t.Errorf("incomplete info %+v", i)
		}
	}
}
