package hookinstall

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
// object or array where spoor's entries go.
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
			back, n, err := removeSpoor(added, k.kind)
			if err != nil || n != len(k.want) {
				t.Fatalf("doc %d: removed %d of %d: %v", i, n, len(k.want), err)
			}
			if emptyContainers[i] {
				// Known limit: an empty container that existed before is
				// indistinguishable from one spoor created and goes too.
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
	  "A": [{"hooks": [{"command": "/x/spoor", "args": ["hook", "--agent", "claude-code"]}]}],
	  "B": [{"hooks": [{"command": "'/x/spoor' hook --agent codex"}]}],
	  "C": [{"bash": "x", "powershell": "& 'C:\\x\\spoor.exe' hook --agent copilot-cli"}],
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
	if len(g.spoorHandlers()) != 2 {
		t.Errorf("grouped spoor handlers: %d", len(g.spoorHandlers()))
	}
	if n, sensors := g.foreign(); n != 1 || len(sensors) != 1 || sensors[0] != "numbat" {
		t.Errorf("foreign %d %v", n, sensors)
	}
	if g.binary() != "/x/spoor" {
		t.Errorf("binary %q", g.binary())
	}
	f := scanHooks(d, kindFlat)
	if len(f.spoorHandlers()) != 1 {
		t.Errorf("flat spoor handlers: %d", len(f.spoorHandlers()))
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
		if len(sc.spoorHandlers()) > 0 || sc.malformed != "" || emptyTarget(d, want) {
			return
		}
		added, err := addEntries(in, want, kindGroups)
		if err != nil {
			return
		}
		if _, err := parseJSON(added); err != nil {
			t.Fatalf("invalid after add: %v\n%q", err, added)
		}
		back, _, err := removeSpoor(added, kindGroups)
		if err != nil || !bytes.Equal(back, in) {
			t.Fatalf("round trip failed (%v):\n in %q\nout %q", err, in, back)
		}
	})
}

// emptyTarget reports the documented limit: an empty object or array
// where spoor's entries go (the root, "hooks", or a wanted event array).
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
