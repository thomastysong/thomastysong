package hookinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestParseJSONHostile(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", false},
		{"blank", "  \n", false},
		{"object", `{"a": 1}`, true},
		{"bom", "\ufeff{}", true},
		{"array root", `[]`, false},
		{"string root", `"x"`, false},
		{"depth at limit", strings.Repeat(`{"a":`, maxJSONDepth) + "1" + strings.Repeat("}", maxJSONDepth), true},
		{"depth over limit", strings.Repeat(`{"a":`, maxJSONDepth+2) + "1" + strings.Repeat("}", maxJSONDepth+2), false},
		{"array bomb", "{\"a\":" + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + "}", false},
		{"too many values", "{\"a\":[" + strings.Repeat("1,", maxJSONNodes) + "1]}", false},
		{"unterminated string", `{"a": "b`, false},
		{"unterminated object", `{"a": 1`, false},
		{"unterminated comment", `{"a": 1 /* x`, false},
		{"bad escape", `{"a": "\x"}`, false},
		{"lone surrogate", `{"a": "\ud800"}`, true},
		{"raw newline in string", "{\"a\": \"b\nc\"}", false},
		{"leading zero", `{"a": 01}`, false},
		{"trailing dot", `{"a": 1.}`, false},
		{"huge exponent", `{"a": 1e999999}`, true},
		{"missing colon", `{"a" 1}`, false},
		{"missing comma", `{"a": 1 "b": 2}`, false},
		{"double comma", `{"a": 1,, "b": 2}`, false},
		{"literal typo", `{"a": tru}`, false},
		{"garbage after", `{} x`, false},
		{"comments", "// c\n{/* d */\"a\": 1 // e\n}", true},
		{"trailing commas", `{"a": [1, 2,], }`, true},
		{"invalid utf8 in string", "{\"a\": \"\xff\"}", true},
		{"nul in string", "{\"a\": \"\x00\"}", false},
		{"duplicate keys", `{"a": 1, "a": 2}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := parseJSON([]byte(tc.in))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && strings.Contains(err.Error(), tc.in) && len(tc.in) > 4 {
				t.Errorf("error quotes the input: %v", err)
			}
			if d != nil && tc.name == "duplicate keys" {
				if _, v := d.root.member("a"); v.num != 2 {
					t.Error("last duplicate must win")
				}
			}
		})
	}
}

// docsForEdit are files in the layouts people and tools actually produce.
var docsForEdit = []string{
	"{}",
	"{}\n",
	"{\n}\n",
	`{"a":1}`,
	`{"a": 1, "b": [1, 2]}`,
	"{\n  \"a\": 1\n}\n",
	"{\n    \"a\": 1,\n    \"hooks\": {\n        \"Other\": [\n            {\"hooks\": [{\"type\": \"command\", \"command\": \"x\"}]}\n        ]\n    }\n}\n",
	"{\n\t\"a\": 1,\n\t\"hooks\": {}\n}",
	"{\r\n  \"a\": 1,\r\n  \"hooks\": {\r\n    \"PreToolUse\": []\r\n  }\r\n}\r\n",
	`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/x"}]}]},"z":null}`,
	"{\n  \"a\": 1 // trailing comment\n}\n",
	"{\n  // leading comment\n  \"a\": [1, 2,],\n}\n",
	"{ \"a\": 1, /* c */ \"hooks\": { \"Stop\": [ ] } }",
	"\ufeff{\n  \"a\": true\n}\n",
}

// emptyContainers marks the documents of docsForEdit that hold an empty
// object or array where hawkbell's entries go.
var emptyContainers = map[int]bool{2: true, 7: true, 8: true, 12: true}

// sameMeaning compares two documents with empty hook containers dropped.
func sameMeaning(t *testing.T, a, b []byte) bool {
	t.Helper()
	norm := func(src []byte) string {
		d, err := parseJSON(src)
		if err != nil {
			t.Fatalf("does not parse: %v", err)
		}
		v := d.root.value().(map[string]any)
		if h, ok := v["hooks"].(map[string]any); ok {
			for k, e := range h {
				if l, ok := e.([]any); ok && len(l) == 0 {
					delete(h, k)
				}
			}
			if len(h) == 0 {
				delete(v, "hooks")
			}
		}
		out, _ := json.Marshal(v)
		return string(out)
	}
	return norm(a) == norm(b)
}

// TestEditRoundTrip: adding the registration and removing it again gives
// the original bytes back, in every layout, and the edited file is valid.
func TestEditRoundTrip(t *testing.T) {
	want, _ := dialects["claude"].entries(params{binary: unixBin, agentID: "claude-code", goos: "linux", timeout: 10})
	flat, _ := dialects["copilot"].entries(params{binary: unixBin, agentID: "copilot-cli", goos: "linux", timeout: 10})
	for i, doc := range docsForEdit {
		for _, k := range []struct {
			kind fileKind
			want []entry
		}{{kindGroups, want}, {kindFlat, flat}} {
			added, err := addEntries([]byte(doc), k.want, k.kind)
			if err != nil {
				// An existing "hooks" member of another shape is refused.
				t.Logf("doc %d kind %d: %v", i, k.kind, err)
				continue
			}
			d, err := parseJSON(added)
			if err != nil {
				t.Fatalf("doc %d: edit produced invalid JSON: %v\n%s", i, err, added)
			}
			if !d.comments && !d.trailingCommas {
				if !json.Valid(bytes.TrimPrefix(added, []byte("\ufeff"))) {
					t.Fatalf("doc %d: encoding/json rejects the edit:\n%s", i, added)
				}
			}
			if st, diff := scanHooks(d, k.kind).compare(k.want, k.kind); st != contentOK {
				t.Fatalf("doc %d: registration not found after edit (%s):\n%s", i, diff, added)
			}
			back, n, err := removeHawkbell(added, k.kind)
			if err != nil || n != len(k.want) {
				t.Fatalf("doc %d: removed %d of %d: %v", i, n, len(k.want), err)
			}
			if emptyContainers[i] {
				// Known limit: an empty container that existed before is
				// indistinguishable from one hawkbell created and goes too.
				// The result must still mean the same to the agent.
				if !sameMeaning(t, back, []byte(doc)) {
					t.Errorf("doc %d kind %d: meaning changed\n got %q\nwant %q", i, k.kind, back, doc)
				}
				continue
			}
			if !bytes.Equal(back, []byte(doc)) {
				t.Errorf("doc %d kind %d: round trip\n got %q\nwant %q", i, k.kind, back, doc)
			}
		}
	}
}

func TestDropKeepsComments(t *testing.T) {
	cases := []struct{ in, key, want string }{
		{
			"{\"a\": 1, // keep a\n  \"x\": 2,\n  // keep b\n  \"b\": 3}",
			"x",
			"{\"a\": 1, // keep a\n  // keep b\n  \"b\": 3}",
		},
		{
			"{\n  \"x\": 2,\n  // keep b\n  \"b\": 3\n}",
			"x",
			"{\n  // keep b\n  \"b\": 3\n}",
		},
		{
			"{\n  \"a\": 1, // keep a\n  \"x\": 2\n}",
			"x",
			"{\n  \"a\": 1 // keep a\n}",
		},
	}
	for _, tc := range cases {
		d, err := parseJSON([]byte(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		i, _ := d.root.member(tc.key)
		got := d.drop(d.root, i)
		if string(got) != tc.want {
			t.Errorf("drop %s from %q\n got %q\nwant %q", tc.key, tc.in, got, tc.want)
		}
		if _, err := parseJSON(got); err != nil {
			t.Errorf("result does not parse: %v", err)
		}
	}
}

func TestScanFindsEveryCommandSpelling(t *testing.T) {
	doc := `{"hooks": {
	  "A": [{"hooks": [{"command": "/x/hawkbell", "args": ["hook", "--agent", "claude-code"]}]}],
	  "B": [{"hooks": [{"command": "'/x/hawkbell' hook --agent codex"}]}],
	  "C": [{"bash": "x", "powershell": "& 'C:\\x\\hawkbell.exe' hook --agent copilot-cli"}],
	  "D": [{"hooks": [{"command": "numbat hook pre --agent claude"}]}],
	  "E": [{"hooks": "not an array"}],
	  "F": "not an array",
	  "G": [1, "x", null]
	}}`
	d, err := parseJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g := scanHooks(d, kindGroups)
	if len(g.hawkbellHandlers()) != 2 {
		t.Errorf("grouped hawkbell handlers: %d", len(g.hawkbellHandlers()))
	}
	if n, sensors := g.foreign(); n != 1 || len(sensors) != 1 || sensors[0] != "numbat" {
		t.Errorf("foreign %d %v", n, sensors)
	}
	if g.binary() != "/x/hawkbell" {
		t.Errorf("binary %q", g.binary())
	}
	f := scanHooks(d, kindFlat)
	if len(f.hawkbellHandlers()) != 1 {
		t.Errorf("flat hawkbell handlers: %d", len(f.hawkbellHandlers()))
	}
}

func FuzzEditRoundTrip(f *testing.F) {
	for _, d := range docsForEdit {
		f.Add([]byte(d))
	}
	f.Add([]byte(`{"hooks":{"x":[{"hooks":[{"command":"a hook --agent b"}]}]}}`))
	want, _ := dialects["gemini"].entries(params{binary: unixBin, agentID: "gemini-cli", goos: "linux", timeout: 10})
	f.Fuzz(func(t *testing.T, in []byte) {
		d, err := parseJSON(in)
		if err != nil {
			return
		}
		sc := scanHooks(d, kindGroups)
		if len(sc.hawkbellHandlers()) > 0 || sc.malformed != "" || emptyTarget(d, want) {
			return
		}
		added, err := addEntries(in, want, kindGroups)
		if err != nil {
			return
		}
		if _, err := parseJSON(added); err != nil {
			t.Fatalf("invalid after add: %v\n%q", err, added)
		}
		back, _, err := removeHawkbell(added, kindGroups)
		if err != nil || !bytes.Equal(back, in) {
			t.Fatalf("round trip failed (%v):\n in %q\nout %q", err, in, back)
		}
	})
}

// emptyTarget reports the documented limit: an empty object or array
// where hawkbell's entries go (the root, "hooks", or a wanted event array).
func emptyTarget(d *jsonDoc, want []entry) bool {
	if len(d.root.members) == 0 && d.root.end-d.root.start > 2 {
		return true
	}
	_, h := d.root.member("hooks")
	if h == nil {
		return false
	}
	if h.kind == kindObject && len(h.members) == 0 {
		return true
	}
	for _, w := range want {
		if _, a := h.member(w.event); a != nil && a.kind == kindArray && len(a.elems) == 0 {
			return true
		}
	}
	return false
}

// removeHawkbellOneAtATime is the reference removeHawkbell is checked against:
// one entry per parse, removed with drop, the container chosen the way the
// single pass chooses it.
func removeHawkbellOneAtATime(src []byte, kind fileKind) ([]byte, int, error) {
	removed := 0
	for i := 0; i < 100000; i++ {
		d, err := parseJSON(src)
		if err != nil {
			return nil, removed, err
		}
		sc := scanHooks(d, kind)
		mine := sc.hawkbellAll()
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
// line and block comments), trailing commas, repeated event keys, hawkbell
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
			return `{"type": "command", "command": "/x/hawkbell hook --agent a"}`
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

// TestRemoveHawkbellMatchesOneAtATime: the single pass gives exactly the bytes
// of removing the entries one at a time, comments, trailing commas and
// repeated keys included.
func TestRemoveHawkbellMatchesOneAtATime(t *testing.T) {
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
		want, nWant, errWant := removeHawkbellOneAtATime(doc, kind)
		got, nGot, errGot := removeHawkbell(doc, kind)
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
		t.Errorf("only %d documents held hawkbell entries", checked)
	}
}

// TestRemoveHawkbellIsLinear: a user-controlled file with thousands of
// hawkbell-marked entries used to be re-parsed once per entry (a 76 KB file
// allocated 2.9 GiB; 0.65 MB took 28 s), which let a user stall a root
// installer. Planning such a file now costs a few passes over it.
func TestRemoveHawkbellIsLinear(t *testing.T) {
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
// hawkbell's entry switches the gate off; Status must say so, and a
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

	// A hawkbell entry hidden under an earlier duplicate is not counted as
	// installed, and uninstall removes it too.
	writeFile(t, path, []byte(`{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "/usr/local/bin/hawkbell", "args": ["hook", "--agent", "claude-code"]}]}], "Stop": []}}`), 0o644)
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusModified {
		t.Errorf("a shadowed hawkbell entry: Status %s (%s)", s.Status, s.Detail)
	}
	u := only(t, mustUnplan(t, c, o), "claude-code")
	if u.Action != ActionMerge || bytes.Contains(u.After, []byte("hawkbell")) {
		t.Errorf("uninstall left the shadowed entry: %s\n%s", u.Action, u.After)
	}
}

// FuzzRemoveHawkbell: on any document, the single pass equals removing the
// entries one at a time and leaves a document that parses.
func FuzzRemoveHawkbell(f *testing.F) {
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 32; i++ {
		f.Add([]byte(genHookDoc(r, kindGroups)), false)
		f.Add([]byte(genHookDoc(r, kindFlat)), true)
	}
	f.Fuzz(func(t *testing.T, in []byte, flat bool) {
		kind := kindGroups
		if flat {
			kind = kindFlat
		}
		if _, err := parseJSON(in); err != nil {
			return
		}
		want, nWant, errWant := removeHawkbellOneAtATime(in, kind)
		got, nGot, errGot := removeHawkbell(in, kind)
		if errGot != nil {
			t.Fatalf("single pass failed: %v", errGot)
		}
		if errWant == nil && (nWant != nGot || !bytes.Equal(want, got)) {
			t.Fatalf("differs from one at a time:\n in %q\nwant %q\n got %q", in, want, got)
		}
		if _, err := parseJSON(got); err != nil {
			t.Fatalf("result does not parse (%v):\n in %q\n got %q", err, in, got)
		}
	})
}
