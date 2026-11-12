package hookinstall

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// removeSpoorOneAtATime is the reference removeSpoor is checked against:
// one entry per parse, removed with drop, the container chosen the way the
// single pass chooses it.
func removeSpoorOneAtATime(src []byte, kind fileKind) ([]byte, int, error) {
	removed := 0
	for i := 0; i < 100000; i++ {
		d, err := parseJSON(src)
		if err != nil {
			return nil, removed, err
		}
		sc := scanHooks(d, kind)
		mine := sc.spoorAll()
		if len(mine) == 0 {
			return src, removed, nil
		}
		h := mine[0]
		switch {
		case h.inner != nil && (len(h.inner.elems) > 1 || d.holdsComment(h.inner) || d.holdsComment(h.group)):
			src = d.drop(h.inner, h.hIdx)
		case len(h.evArr.elems) > 1 || d.holdsComment(h.evArr):
			src = d.drop(h.evArr, h.grpIdx)
		case len(sc.hooks.members) > 1 || d.holdsComment(sc.hooks):
			src = d.drop(sc.hooks, h.evIdx)
		default:
			src = d.drop(d.root, sc.hooksIdx)
		}
		removed++
	}
	return nil, removed, errors.New("did not converge")
}

// genHookDoc builds a random hook document: random separators (blanks,
// line and block comments), trailing commas, repeated event keys, spoor
// and foreign handlers mixed in any order.
func genHookDoc(r *rand.Rand, kind fileKind) string {
	seps := []string{"", " ", "\n  ", "\n", " /* c */ ", "\n  // c\n  ", "/*x*/", "\n\n    "}
	sep := func() string { return seps[r.Intn(len(seps))] }
	container := func(open, close string, items []string) string {
		var b strings.Builder
		b.WriteString(open)
		for i, it := range items {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(sep())
			b.WriteString(it)
			b.WriteString(sep())
		}
		if len(items) > 0 && r.Intn(6) == 0 {
			b.WriteString("," + sep())
		}
		if len(items) == 0 {
			b.WriteString(sep())
		}
		b.WriteString(close)
		return b.String()
	}
	handler := func() string {
		if r.Intn(3) > 0 {
			return `{"type": "command", "command": "/x/spoor hook --agent a"}`
		}
		return `{"command": "/opt/other"}`
	}
	handlers := func() []string {
		n := r.Intn(4)
		out := make([]string, n)
		for i := range out {
			out[i] = handler()
		}
		return out
	}
	element := func() string {
		if kind == kindFlat {
			return handler()
		}
		items := []string{`"hooks": ` + container("[", "]", handlers())}
		if r.Intn(2) == 0 {
			items = append([]string{`"matcher": "Bash"`}, items...)
		}
		return container("{", "}", items)
	}
	var events []string
	for i, n := 0, r.Intn(4); i < n; i++ {
		var elems []string
		for j, m := 0, r.Intn(4); j < m; j++ {
			elems = append(elems, element())
		}
		name := []string{"A", "B", "A", "C"}[r.Intn(4)]
		events = append(events, `"`+name+`": `+container("[", "]", elems))
	}
	var root []string
	if r.Intn(2) == 0 {
		root = append(root, `"pre": 1`)
	}
	root = append(root, `"hooks": `+container("{", "}", events))
	if r.Intn(2) == 0 {
		root = append(root, `"post": {"x": [1, 2]}`)
	}
	return container("{", "}", root) + "\n"
}

// TestRemoveSpoorMatchesOneAtATime: the single pass gives exactly the bytes
// of removing the entries one at a time, comments, trailing commas and
// repeated keys included.
func TestRemoveSpoorMatchesOneAtATime(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	checked := 0
	for i := 0; i < 4000; i++ {
		kind := kindGroups
		if i%3 == 0 {
			kind = kindFlat
		}
		doc := []byte(genHookDoc(r, kind))
		if _, err := parseJSON(doc); err != nil {
			t.Fatalf("generator produced invalid JSONC: %v\n%s", err, doc)
		}
		want, nWant, errWant := removeSpoorOneAtATime(doc, kind)
		got, nGot, errGot := removeSpoor(doc, kind)
		if (errWant == nil) != (errGot == nil) || nWant != nGot || !bytes.Equal(want, got) {
			t.Fatalf("doc %d (kind %d):\n%s\none at a time (%d, %v):\n%s\nsingle pass (%d, %v):\n%s", i, kind, doc, nWant, errWant, want, nGot, errGot, got)
		}
		if _, err := parseJSON(got); err != nil {
			t.Fatalf("doc %d: result does not parse: %v\n%s", i, err, got)
		}
		if nGot > 0 {
			checked++
		}
	}
	if checked < 1000 {
		t.Errorf("only %d documents held spoor entries", checked)
	}
}

// TestRemoveSpoorIsLinear: a user-controlled file with thousands of
// spoor-marked entries used to be re-parsed once per entry (a 76 KB file
// allocated 2.9 GiB; 0.65 MB took 28 s), which let a user stall a root
// installer. Planning such a file now costs a few passes over it.
func TestRemoveSpoorIsLinear(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	var b bytes.Buffer
	b.WriteString(`{"pad": "`)
	b.Write(bytes.Repeat([]byte("a"), 16<<10))
	b.WriteString(`", "hooks": {"Stop": [{"hooks": [`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"command":"x hook --agent y"}`)
	}
	b.WriteString("]}]}}\n")
	writeFile(t, path, b.Bytes(), 0o644)
	var p Plan
	alloc := allocDuring(func() { p = only(t, mustPlan(t, c, o), "claude-code") })
	if alloc > 256<<20 {
		t.Errorf("planning one %d-byte file allocated %d MiB", b.Len(), alloc>>20)
	}
	if p.Action != ActionMerge || bytes.Contains(p.After, []byte("x hook --agent y")) || !bytes.Contains(p.After, []byte(`"pad"`)) {
		t.Errorf("stale entries not replaced: %s", p.Action)
	}
}

// TestForceKeepsCommentInEmptyContainer: with Force, comments survive
// ("with Force the same splice keeps the comments"), also when the only
// content of the object being extended is a comment, and uninstall gives
// the original bytes back.
func TestForceKeepsCommentInEmptyContainer(t *testing.T) {
	c := testCatalog(t)
	for _, orig := range []string{
		"{\n  // \"model\": \"opus\"\n}\n",
		"{\n  \"hooks\": {\n    /* team hooks go here */\n  },\n  \"model\": \"opus\"\n}\n",
		"{/* tight */}",
		"{\"hooks\": {\"Stop\": [ /* none yet */ ]}}\n",
	} {
		o := opts(t, "linux", event.ScopeUser, "claude-code")
		o.Force = true
		path := targetPath(t, c, o, "claude-code")
		writeFile(t, path, []byte(orig), 0o644)
		plans := mustPlan(t, c, o)
		p := only(t, plans, "claude-code")
		if p.Action != ActionMerge {
			t.Fatalf("%q: action %s: %s", orig, p.Action, p.Note)
		}
		for _, cm := range []string{`// "model": "opus"`, "team hooks go here", "tight", "none yet"} {
			if strings.Contains(orig, cm) && !bytes.Contains(p.After, []byte(cm)) {
				t.Errorf("Force install destroyed the comment %q:\n%s", cm, p.After)
			}
		}
		if s, diff := scanHooks(mustParse(t, p.After), kindGroups).compare(mustWant(t), kindGroups); s != contentOK {
			t.Errorf("%q: registration not found after edit (%s):\n%s", orig, diff, p.After)
		}
		mustApply(t, plans)
		mustApply(t, mustUnplan(t, c, o))
		if got := readBytes(t, path); string(got) != orig {
			t.Errorf("round trip\n got %q\nwant %q", got, orig)
		}
	}
}

func mustParse(t *testing.T, b []byte) *jsonDoc {
	t.Helper()
	d, err := parseJSON(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return d
}

func mustWant(t *testing.T) []entry {
	t.Helper()
	w, ok := dialects["claude"].entries(params{binary: unixBin, agentID: "claude-code", goos: "linux", timeout: 10})
	if !ok {
		t.Fatal("no entries")
	}
	return w
}

// TestDuplicateEventKeyLastWins: agents keep the last of repeated keys
// (JSON.parse, serde maps). A user who appends "PreToolUse": [] after
// spoor's entry switches the gate off; Status must say so, and a
// reinstall must repair it and then be stable.
func TestDuplicateEventKeyLastWins(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	path := only(t, plans, "claude-code").Path
	data := readBytes(t, path)
	_, hooks := mustParse(t, data).root.member("hooks")
	tampered := append([]byte{}, data[:hooks.end-1]...)
	tampered = append(tampered, []byte(`, "PreToolUse": [], "UserPromptSubmit": []`)...)
	tampered = append(tampered, data[hooks.end-1:]...)
	writeFile(t, path, tampered, 0o644)
	s := stateOf(t, c, o, "claude-code")
	if s.Status != StatusModified || !strings.Contains(s.Detail, "PreToolUse") {
		t.Errorf("PreToolUse is overridden by a later duplicate key, but Status = %q (%s)", s.Status, s.Detail)
	}
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionMerge {
		t.Fatalf("reinstall does not repair it: %s %s", p.Action, p.Note)
	}
	mustApply(t, []Plan{p})
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusUser {
		t.Errorf("after reinstall: %s (%s)", s.Status, s.Detail)
	}
	if again := only(t, mustPlan(t, c, o), "claude-code"); again.Action != ActionUnchanged {
		t.Errorf("reinstall is not stable: %s", again.Action)
	}
	d := mustParse(t, readBytes(t, path))
	_, hooks = d.root.member("hooks")
	seen := map[string]int{}
	for _, m := range hooks.members {
		seen[m.key]++
	}
	if seen["PreToolUse"] != 1 {
		t.Errorf("PreToolUse appears %d times after repair:\n%s", seen["PreToolUse"], readBytes(t, path))
	}

	// A spoor entry hidden under an earlier duplicate is not counted as
	// installed, and uninstall removes it too.
	writeFile(t, path, []byte(`{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "/usr/local/bin/spoor", "args": ["hook", "--agent", "claude-code"]}]}], "Stop": []}}`), 0o644)
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusModified {
		t.Errorf("a shadowed spoor entry: Status %s (%s)", s.Status, s.Detail)
	}
	u := only(t, mustUnplan(t, c, o), "claude-code")
	if u.Action != ActionMerge || bytes.Contains(u.After, []byte("spoor")) {
		t.Errorf("uninstall left the shadowed entry: %s\n%s", u.Action, u.After)
	}
}
