package rules

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

// canonicalCorpus is YAML exercising every scalar spelling the fast path
// renders itself or hands to the reference.
var canonicalCorpus = []string{
	`{a: 1, b: -7, c: 0, d: -0, e: 007, f: 0x1F, g: 1_000, h: 123456789012345678, i: 1234567890123456789012}`,
	`{a: true, b: false, c: True, d: FALSE, e: yes, f: "true", g: !!bool true}`,
	`{a: null, b: ~, c: , d: Null, e: NULL, f: "null"}`,
	`{a: 1.5, b: -0.0, c: .inf, d: -.Inf, e: .nan, f: 1e3, g: 6.02e23, h: !!float 3}`,
	`{a: 2026-11-11, b: 2026-11-11T12:00:00Z, c: "2026-11-11", d: !!timestamp 2026-01-02}`,
	`{"quoted key": 1, 'single': 2, "<html> & \"esc\"": "a<b>&c", tab: "a\tb", nl: "x\ny", uni: "é ✓ \u2028 \u2029", ctl: "\x01\x7f"}`,
	`{z: 1, a: {y: [1, {b: 2, a: 1}], x: []}, m: {}, e: ""}`,
	`[1, "two", [3, [4]], {k: v}]`,
	`{1: a, 2: b}`,
	"a: !!str 12\nb: !!int \"12\"\nc: !!str true\nd: |\n  literal\n  block\ne: >\n  folded\n  text\n",
	`{a: 0b101, b: 0o17, c: +12, d: 12.0, e: 1__2}`,
	`{zz: [a, b], aa: "\ufeffbom", mm: "\U0001F600"}`,
}

func parseForCanon(t testing.TB, src string) *yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("%q: %v", src, err)
	}
	return doc.Content[0]
}

// The fast renderer produces exactly the reference bytes: for every rule
// of the shipped packs and the bench corpus, and for scalar spellings the
// packs do not use yet.
func TestCanonicalFastPath(t *testing.T) {
	check := func(name string, n *yaml.Node) {
		t.Helper()
		got, want := canonical(n), canonicalRef(n)
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\nfast %s\nref  %s", name, got, want)
		}
	}
	for _, src := range canonicalCorpus {
		check(src, parseForCanon(t, src))
	}
	fast := 0
	for name, data := range cacheCorpus(t) {
		src, ok, err := parseSource(name, data)
		if err != nil || !ok {
			continue
		}
		check(name, src.root)
		if rules := mapValue(src.root, "rules"); rules != nil {
			for _, rn := range rules.Content {
				check(name+"/"+mapValue(rn, "id").Value, rn)
				if _, ok := appendCanonical(nil, rn, 0); ok {
					fast++
				}
			}
		}
	}
	if fast == 0 {
		t.Error("the fast path rendered no rule")
	}
}

func FuzzCanonical(f *testing.F) {
	for _, s := range canonicalCorpus {
		f.Add(s)
	}
	f.Add("pack: p\nversion: \"1\"\nrules:\n" + benchRules(2))
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 1<<14 {
			return
		}
		root, err := parseStrict([]byte(src))
		if err != nil {
			return
		}
		if got, want := canonical(root), canonicalRef(root); !bytes.Equal(got, want) {
			t.Errorf("%q:\nfast %s\nref  %s", src, got, want)
		}
	})
}

func TestPlainDecimal(t *testing.T) {
	for s, want := range map[string]bool{
		"0": true, "7": true, "-7": true, "123456789012345678": true,
		"": false, "-": false, "-0": false, "007": false, "1_0": false, "+1": false, "1234567890123456789": false, "0x1": false,
	} {
		if plainDecimal(s) != want {
			t.Errorf("plainDecimal(%q) = %v", s, !want)
		}
	}
}
