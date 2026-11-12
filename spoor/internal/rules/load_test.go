package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const goodRule = `  - id: SPR-T-001
    title: t
    severity: low
    match: {b: true}` + dummyTest + "\n"

func TestStrictLoaderRejections(t *testing.T) {
	head := "pack: p\nversion: \"1\"\nrules:\n"
	many := &strings.Builder{}
	for i := 0; i <= MaxPackRules; i++ {
		fmt.Fprintf(many, "  - {id: R-%d, title: t, severity: low, match: {b: true}, tests: [{name: t, event: {type: x}, expect: match}]}\n", i)
	}
	cases := []struct {
		name, doc, want string
	}{
		{"unknown top key", "pack: p\nversion: \"1\"\nextra: 1\nrules: []\n", `unknown key "extra"`},
		{"unknown rule key", head + strings.Replace(goodRule, "title: t", "title: t\n    titel: typo", 1), `unknown key "titel"`},
		{"unknown flags key", head + strings.Replace(goodRule, "title: t", "title: t\n    flags: {sett: [x]}", 1), `unknown key "sett"`},
		{"unknown test key", head + strings.Replace(goodRule, "expect: no_match", "expect: no_match, extra: 1", 1), `unknown key "extra"`},
		{"anchor", head + strings.Replace(goodRule, "match: {b: true}", "match: &m {b: true}", 1), "anchors are not allowed"},
		{"alias", head + strings.Replace(goodRule, "title: t", "title: &t x", 1) + strings.Replace(strings.Replace(goodRule, "SPR-T-001", "SPR-T-002", 1), "title: t", "title: *t", 1), "are not allowed"},
		{"alias bomb", "a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n", "are not allowed"},
		{"merge key", "base: &b {x: 1}\n" + head, "anchors are not allowed"},
		{"custom tag", head + strings.Replace(goodRule, "title: t", "title: !evil t", 1), "custom tag"},
		{"binary tag", head + strings.Replace(goodRule, "title: t", "title: !!binary aGk=", 1), "not allowed"},
		{"duplicate key", head + strings.Replace(goodRule, "title: t", "title: t\n    title: u", 1), "already defined"},
		{"two documents", head + goodRule + "---\npack: q\n", "more than one YAML document"},
		{"empty", "", "empty document"},
		{"no pack name", "version: \"1\"\nrules: []\n", "pack name"},
		{"no version", "pack: p\nrules: []\n", "version is required"},
		{"oversized", head + goodRule + "# " + strings.Repeat("x", MaxPackBytes), "larger than"},
		{"too many rules", head + many.String(), "more than 500 rules"},
		{"no tests", head + "  - {id: R-1, title: t, severity: low, match: {b: true}}\n", "at least one test"},
		{"no match", head + "  - {id: R-1, title: t, severity: low, tests: [{name: t, event: {type: x}, expect: match}]}\n", "match is required"},
		{"bad severity", head + strings.Replace(goodRule, "severity: low", "severity: urgent", 1), "severity"},
		{"no severity", head + strings.Replace(goodRule, "    severity: low\n", "", 1), "severity is required"},
		{"bad class", head + strings.Replace(goodRule, "title: t", "title: t\n    class: page", 1), "class"},
		{"bad kind", head + strings.Replace(goodRule, "title: t", "title: t\n    kind: posture", 1), "kind"},
		{"bad response", head + strings.Replace(goodRule, "title: t", "title: t\n    response: deny", 1), "response"},
		{"bad id", head + strings.Replace(goodRule, "SPR-T-001", "bad id!", 1), "rule id"},
		{"bad flag name", head + strings.Replace(goodRule, "title: t", "title: t\n    flags: {set: [Bad Flag]}", 1), "flag name"},
		{"bad ttl", head + strings.Replace(goodRule, "title: t", "title: t\n    flags: {set: [x], ttl: forever}", 1), "ttl"},
		{"ttl too long", head + strings.Replace(goodRule, "title: t", "title: t\n    flags: {set: [x], ttl: 400d}", 1), "ttl"},
		{"bad scope", head + strings.Replace(goodRule, "title: t", "title: t\n    flags: {set: [x], scope: global}", 1), "scope"},
		{"threshold zero", head + strings.Replace(goodRule, "title: t", "title: t\n    threshold: {count: 0}", 1), "threshold.count"},
		{"threshold huge", head + strings.Replace(goodRule, "title: t", "title: t\n    threshold: {count: 100000}", 1), "threshold.count"},
		{"threshold by", head + strings.Replace(goodRule, "title: t", "title: t\n    threshold: {count: 2, by: planet}", 1), "threshold.by"},
		{"regex too long", head + strings.Replace(goodRule, "match: {b: true}", "match: {s|re: '"+strings.Repeat("a", MaxRegexLen+1)+"'}", 1), "longer than"},
		{"bad regex", head + strings.Replace(goodRule, "match: {b: true}", "match: {s|re: '(?<x>'}", 1), "match"},
		{"bad expect", head + strings.Replace(goodRule, "expect: no_match", "expect: maybe", 1), "expect"},
		{"event and events", head + strings.Replace(goodRule, "event: {type: tool.pre}", "event: {type: tool.pre}, events: [{type: x}]", 1), "exactly one"},
		{"neither event", head + strings.Replace(goodRule, "event: {type: tool.pre}, ", "", 1), "exactly one"},
		{"unnamed test", head + strings.Replace(goodRule, "name: t, ", "", 1), "no name"},
		{"novelty without fields", head + strings.Replace(goodRule, "title: t", "title: t\n    novelty: {raise: true}", 1), "novelty.fields"},
		{"bad dedup field", head + strings.Replace(goodRule, "title: t", "title: t\n    dedup: [\"a b\"]", 1), "field name"},
		{"deep nesting", head + "  - {id: R-1, title: t, severity: low, match: " + strings.Repeat("{not: ", 70) + "{b: true}" + strings.Repeat("}", 70) + ", tests: [{name: t, event: {type: x}, expect: match}]}\n", "nesting"},
		{"wrong type", head + strings.Replace(goodRule, "title: t", "title: [a, b]", 1), "invalid YAML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(map[string][]byte{"p.yaml": []byte(c.doc)})
			if err == nil {
				t.Fatalf("accepted:\n%s", c.doc)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestLoadDuplicatesAndPacks(t *testing.T) {
	a := "pack: a\nversion: \"1\"\nrules:\n" + goodRule
	b := "pack: b\nversion: \"2\"\nrules:\n" + strings.Replace(goodRule, "title: t", "title: second", 1)
	s, err := Load(map[string][]byte{"rules/a.yaml": []byte(a), "rules/b.yaml": []byte(b), "README.md": []byte("ignored")})
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 1 || s.Rules()[0].Title != "second" || s.Rules()[0].Pack != "b" {
		t.Fatalf("later definition should win: %+v", s.Rules())
	}
	found := false
	for _, is := range Lint(s) {
		found = found || (is.Code == "duplicate_id" && is.Level == LevelError)
	}
	if !found {
		t.Error("duplicate id not reported by Lint")
	}
	if s.Version() != "a@1,b@2" {
		t.Errorf("version %q", s.Version())
	}
	if _, err := Load(map[string][]byte{"x.yaml": []byte(a), "y.yaml": []byte(a)}); err == nil {
		t.Error("the same pack loaded twice")
	}
}

func TestListsAndSuppressionsFiles(t *testing.T) {
	_, err := Load(map[string][]byte{"lists.yaml": []byte("lists:\n  x: [a]\nother: 1\n")})
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("lists.yaml unknown key: %v", err)
	}
	_, err = Load(map[string][]byte{"lists.yaml": []byte("lists:\n  Bad: [a]\n")})
	if err == nil {
		t.Error("bad list name accepted")
	}
	s, err := Load(map[string][]byte{"suppressions.yaml": []byte(`suppressions:
  - rule: SPR-NET-*
    match: {net.host: "*.corp.example"}
    expires: 2027-01-01
    reason: corp egress
    tags: [offsec]
`)})
	if err != nil {
		t.Fatal(err)
	}
	sups := s.Suppressions()
	if len(sups) != 1 || sups[0].RuleID != "SPR-NET-*" || sups[0].Expires.Year() != 2027 || sups[0].Tags[0] != "offsec" {
		t.Errorf("suppressions %+v", sups)
	}
	for _, bad := range []string{
		"suppressions:\n  - {match: {a: b}, reason: x}\n",
		"suppressions:\n  - {rule: x}\n",
		"suppressions:\n  - {rule: x, reason: y, expires: tomorrow}\n",
		"suppressions:\n  - {rule: x, reason: y, colour: red}\n",
	} {
		if _, err := Load(map[string][]byte{"suppressions.yaml": []byte(bad)}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// LoadEmbedded returns an independent Set on every call. The check holds
// whatever packs ship: it uses the first embedded rule, not a fixed id.
func TestLoadEmbeddedReturnsCopies(t *testing.T) {
	a, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := LoadEmbedded()
	n := b.Count()
	if n == 0 {
		t.Fatal("no embedded rules")
	}
	id := b.Rules()[0].ID
	a.Disable(id)
	if b.Count() != n || a.Count() != n-1 {
		t.Fatalf("copies share state: a=%d b=%d", a.Count(), b.Count())
	}
	if a.Hash() == b.Hash() {
		t.Error("disabling a rule must change the hash")
	}
	c, _ := LoadEmbedded()
	if c.Count() != n || c.Hash() != b.Hash() {
		t.Error("a later load sees an earlier copy's change")
	}
}

func TestACLProblem(t *testing.T) {
	self := "S-1-5-21-1-2-3-1001"
	cases := []struct {
		name  string
		owner string
		nil   bool
		aces  []aceInfo
		bad   bool
	}{
		{"admins only", sidAdministrators, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x1f01ff, sid: sidSystem}, {allow: true, inheritOnly: false, mask: 0x1f01ff, sid: sidAdministrators}, {allow: true, inheritOnly: false, mask: 0x1200a9, sid: "S-1-5-32-545"}}, false},
		{"self owned", self, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x1f01ff, sid: self}}, false},
		{"users can write", sidAdministrators, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x1301bf, sid: "S-1-5-32-545"}}, true},
		{"everyone generic write", sidSystem, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x40000000, sid: "S-1-1-0"}}, true},
		{"inherit-only users write", sidAdministrators, false, []aceInfo{{allow: true, inheritOnly: true, mask: 0x1f01ff, sid: "S-1-5-32-545"}}, false},
		{"deny ace ignored", sidAdministrators, false, []aceInfo{{allow: false, inheritOnly: false, mask: 0x1f01ff, sid: "S-1-1-0"}}, false},
		{"creator owner", sidAdministrators, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x1f01ff, sid: sidCreatorOwner}}, false},
		{"foreign owner", "S-1-5-21-9-9-9-1234", false, nil, true},
		{"null dacl", sidAdministrators, true, nil, true},
		{"trustedinstaller", sidTrustedInst, false, []aceInfo{{allow: true, inheritOnly: false, mask: 0x1f01ff, sid: sidTrustedInst}}, false},
		// Conditional (callback) and object allow entries grant like the
		// basic one; an entry type the check does not know fails closed.
		{"callback allow users write", sidAdministrators, false, []aceInfo{{allow: true, mask: 0x2, sid: "S-1-5-32-545", typ: aceAllowedCallback}}, true},
		{"object allow users write", sidAdministrators, false, []aceInfo{{allow: true, mask: 0x2, sid: "S-1-5-32-545", typ: aceAllowedObject}}, true},
		{"unreadable trustee", sidAdministrators, false, []aceInfo{{allow: true, mask: 0x2, sid: "", typ: aceAllowedCallbackObject}}, true},
		{"unknown ace type", sidAdministrators, false, []aceInfo{{unknown: true, mask: 0x1, typ: aceAllowedCompound}}, true},
		{"unknown inherit-only ace", sidAdministrators, false, []aceInfo{{unknown: true, inheritOnly: true, mask: 0x1, typ: 0x42}}, false},
	}
	for _, c := range cases {
		got := aclProblem(c.owner, c.nil, c.aces, self) != ""
		if got != c.bad {
			t.Errorf("%s: problem=%v want %v (%q)", c.name, got, c.bad, aclProblem(c.owner, c.nil, c.aces, self))
		}
	}
}

func TestClassifyACE(t *testing.T) {
	for typ, want := range map[uint8]int{
		aceAllowed: aceGrant, aceAllowedObject: aceGrant, aceAllowedCallback: aceGrant, aceAllowedCallbackObject: aceGrant,
		aceDenied: aceNoGrant, aceDeniedCallback: aceNoGrant, aceDeniedObject: aceNoGrant, aceDeniedCallbackObject: aceNoGrant,
		aceSystemAudit: aceNoGrant, aceSystemMandatoryLabel: aceNoGrant,
		aceAllowedCompound: aceUnknown, 0x16: aceUnknown, 0xff: aceUnknown,
	} {
		if got := classifyACE(typ); got != want {
			t.Errorf("classifyACE(%#x) = %d, want %d", typ, got, want)
		}
	}
	if !objectACE(aceAllowedObject) || !objectACE(aceAllowedCallbackObject) || objectACE(aceAllowedCallback) {
		t.Error("objectACE")
	}
	for flags, want := range map[uint32]int{0: 12, 1: 28, 2: 28, 3: 44} {
		if got := objectSIDOffset(flags); got != want {
			t.Errorf("objectSIDOffset(%d) = %d, want %d", flags, got, want)
		}
	}
}

func TestErrInsecureDirIsMatchable(t *testing.T) {
	err := fmt.Errorf("%w: x", ErrInsecureDir)
	if !errors.Is(err, ErrInsecureDir) {
		t.Fatal("ErrInsecureDir must be matchable with errors.Is")
	}
}
