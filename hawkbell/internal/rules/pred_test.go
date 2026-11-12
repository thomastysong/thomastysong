package rules

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testFields() map[string]any {
	return map[string]any{
		"s":     "Hello World",
		"l":     []string{"alpha", "beta.example.com", "/etc/passwd"},
		"b":     true,
		"f":     false,
		"n":     42.0,
		"ip":    "10.1.2.3",
		"ips":   []string{"192.168.0.1", "8.8.8.8", "[fe80::1%eth0]"},
		"empty": "",
		"el":    []string{},
		"hosts": []string{"a.trusted.example", "evil.example"},
		"host":  "a.trusted.example",
	}
}

func TestLeafModifiers(t *testing.T) {
	cases := []struct {
		pred string
		want bool
	}{
		// equality
		{`s: Hello World`, true},
		{`s: hello world`, false},
		{`s: [x, Hello World]`, true},
		{`l: beta.example.com`, true},
		{`l: [x, y]`, false},
		{`b: true`, true},
		{`f: false`, true},
		{`b: "true"`, false}, // a string never equals a bool
		{`n: 42`, true},
		{`n: 42.0`, true},
		{`n: "42"`, false},
		{`missing: x`, false},
		{`empty: ""`, false}, // empty counts as missing
		// string modifiers, any element of a list
		{`s|contains: lo Wo`, true},
		{`s|contains: [zz, "o W"]`, true},
		{`s|icontains: HELLO`, true},
		{`l|contains: example`, true},
		{`l|icontains: ETC`, true},
		{`s|startswith: Hell`, true},
		{`s|endswith: World`, true},
		{`l|startswith: /etc`, true},
		{`l|endswith: [.com, .net]`, true},
		{`l|endswith: .org`, false},
		{`b|contains: t`, false},
		{`s|re: '^H.*d$'`, true},
		{`l|re: '^/etc/(passwd|shadow)$'`, true},
		{`l|re: ['^zz', '^al']`, true},
		{`s|re: '^world'`, false},
		// list membership
		{`s|in: [a, Hello World]`, true},
		{`l|in: [gamma, alpha]`, true},
		{`n|in: [1, 42]`, true},
		{`l|contains_any: [x, alpha]`, true},
		{`l|contains_any: [x, y]`, false},
		{`l|contains_all: [alpha, /etc/passwd]`, true},
		{`l|contains_all: [alpha, nope]`, false},
		{`s|contains_any: [Hello World]`, true},
		// numbers
		{`n|gt: 41`, true},
		{`n|gt: 42`, false},
		{`n|gte: 42`, true},
		{`n|lt: 43`, true},
		{`n|lte: 41`, false},
		{`s|gt: 1`, false},
		// exists
		{`s|exists: true`, true},
		{`missing|exists: true`, false},
		{`missing|exists: false`, true},
		{`empty|exists: false`, true},
		{`el|exists: false`, true},
		{`f|exists: true`, true}, // false is a value
		// len_gt
		{`s|len_gt: 10`, true},
		{`s|len_gt: 11`, false},
		{`l|len_gt: 2`, true},
		{`missing|len_gt: 0`, false},
		// cidr
		{`ip|cidr: 10.0.0.0/8`, true},
		{`ip|cidr: [192.168.0.0/16]`, false},
		{`ips|cidr: 8.8.0.0/16`, true},
		{`ips|cidr: fe80::/10`, true},
		{`s|cidr: 0.0.0.0/0`, false},
		// any_* list forms
		{`l|any_startswith: [/usr, /etc]`, true},
		{`l|any_endswith: [.com]`, true},
		{`l|any_contains: [ph]`, true},
		{`l|any_re: ['^b.*com$']`, true},
		{`l|any_re: ['^zzz']`, false},
	}
	f := testFields()
	ctx := &evalCtx{}
	for _, c := range cases {
		n := pred(t, c.pred)
		if got := n.eval(f, ctx); got != c.want {
			t.Errorf("%s = %v, want %v", c.pred, got, c.want)
		}
	}
}

func TestBooleanStructure(t *testing.T) {
	f := testFields()
	ctx := &evalCtx{}
	cases := []struct {
		pred string
		want bool
	}{
		{"all: [{b: true}, {n: 42}]", true},
		{"all: [{b: true}, {n: 1}]", false},
		{"any: [{b: false}, {n: 42}]", true},
		{"any: [{b: false}, {n: 1}]", false},
		{"not: {b: false}", true},
		{"not: {missing: x}", true},
		{"{b: true, n: 42}", true}, // several keys: conjunction
		{"{b: true, n: 1}", false},
		{"any: [{all: [{b: true}, {not: {f: true}}]}, {missing: 1}]", true},
	}
	for _, c := range cases {
		if got := pred(t, c.pred).eval(f, ctx); got != c.want {
			t.Errorf("%s = %v, want %v", c.pred, got, c.want)
		}
	}
}

// The red team measured flat predicates over arrays over-matching 3.3x to
// 3.6x because they cannot say "the same command" (redteam/detection-quality.md
// section 6). any_command binds.
func TestAnyCommandBindsToOneCommand(t *testing.T) {
	cmds := func(cs ...map[string]any) map[string]any { return map[string]any{"shell.cmds": cs} }
	rmBuild := map[string]any{"name": "rm", "path": "rm", "args": []string{"-rf", "build"}, "origin": "top", "dynamic": false}
	cpEtc := map[string]any{"name": "cp", "path": "cp", "args": []string{"/etc/x", "."}, "origin": "top", "dynamic": false}
	rmRoot := map[string]any{"name": "rm", "path": "rm", "args": []string{"-rf", "/"}, "origin": "substitution", "dynamic": false}
	bound := pred(t, `any_command: {name|in: [rm], args|contains_any: ["-rf", "-fr"], args|any_startswith: ["/", "~"]}`)
	flat := pred(t, `all: [{shell.argv|contains_any: ["-rf"]}, {shell.argv|any_startswith: ["/"]}]`)
	ctx := &evalCtx{}
	split := cmds(rmBuild, cpEtc)
	split["shell.argv"] = []string{"-rf", "build", "/etc/x", "."}
	if bound.eval(split, ctx) {
		t.Error("any_command matched across two commands")
	}
	if !flat.eval(split, ctx) {
		t.Error("control: the flat predicate should over-match here")
	}
	if !bound.eval(cmds(cpEtc, rmRoot), ctx) {
		t.Error("any_command missed rm -rf /")
	}
	if pred(t, `any_command: {name: rm, origin: top, not: {args|contains: build}}`).eval(cmds(rmBuild, rmRoot), ctx) {
		t.Error("nested not inside any_command")
	}
	if !pred(t, `any_command: {dynamic: false, path|endswith: cp}`).eval(cmds(cpEtc), ctx) {
		t.Error("bool and path keys")
	}
	if pred(t, `any_command: {name: rm}`).eval(map[string]any{}, ctx) {
		t.Error("no commands must not match")
	}
}

func TestAnyInstall(t *testing.T) {
	f := map[string]any{"shell.install_entries": []map[string]any{
		{"manager": "npm", "packages": []string{"left-pad"}, "global": false, "exec": false, "flags": []string{}},
		{"manager": "npx", "packages": []string{"@evil/pkg@1.0.0"}, "global": false, "exec": true, "flags": []string{"-y"}},
	}}
	ctx := &evalCtx{}
	if !pred(t, `any_install: {manager: npx, exec: true, packages|any_re: "^@evil/"}`).eval(f, ctx) {
		t.Error("any_install missed")
	}
	if pred(t, `any_install: {manager: npm, exec: true}`).eval(f, ctx) {
		t.Error("any_install bound across entries")
	}
}

func TestInListSemantics(t *testing.T) {
	l, err := newList("hosts", []string{"*.trusted.example", "exact.example", "pre*"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &evalCtx{lists: map[string]*namedList{"hosts": l}}
	cases := []struct {
		pred   string
		fields map[string]any
		want   bool
	}{
		{"host|in_list: hosts", map[string]any{"host": "a.trusted.example"}, true},
		{"host|in_list: hosts", map[string]any{"host": "A.TRUSTED.EXAMPLE"}, true},
		{"host|in_list: hosts", map[string]any{"host": "trusted.example"}, false}, // *.x is subdomains only
		{"host|in_list: hosts", map[string]any{"host": "eviltrusted.example"}, false},
		{"host|in_list: hosts", map[string]any{"host": "exact.example"}, true},
		{"host|in_list: hosts", map[string]any{"host": "prefix-anything"}, true},
		{"hosts|in_list: hosts", map[string]any{"hosts": []string{"a.trusted.example", "exact.example"}}, true},
		{"hosts|in_list: hosts", map[string]any{"hosts": []string{"a.trusted.example", "evil.example"}}, false},
		{"hosts|any_in_list: hosts", map[string]any{"hosts": []string{"a.trusted.example", "evil.example"}}, true},
		{"hosts|any_in_list: hosts", map[string]any{"hosts": []string{"evil.example"}}, false},
		{"hosts|in_list: hosts", map[string]any{"hosts": []string{}}, false},
		{"host|in_list: nolist", map[string]any{"host": "exact.example"}, false},
	}
	missing := 0
	ctx.missingList = func(string) { missing++ }
	for _, c := range cases {
		if got := pred(t, c.pred).eval(c.fields, ctx); got != c.want {
			t.Errorf("%s over %v = %v, want %v", c.pred, c.fields, got, c.want)
		}
	}
	if missing != 1 {
		t.Errorf("missing list counted %d times", missing)
	}
	for _, bad := range [][]string{{"a*b"}, {"*"}, {""}, {"**.x"}} {
		if _, err := newList("x", bad); err == nil {
			t.Errorf("entry %v should be rejected", bad)
		}
	}
	if _, err := newList("Bad Name", nil); err == nil {
		t.Error("list name with spaces accepted")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []string{
		`s|nope: x`,
		`s|contains|re: x`,
		`all: []`,
		`any: {s: x}`,
		`not: []`,
		`s|re: "` + strings.Repeat("a", MaxRegexLen+1) + `"`,
		`s|re: "(unclosed"`,
		`s|re: '\C'`,
		`s|cidr: 300.0.0.0/8`,
		`n|gt: big`,
		`n|gt: [1, 2]`,
		`s|exists: maybe`,
		`s|in_list: [a, b]`,
		`s|in_list: "Bad Name"`,
		`s: null`,
		`s: {nested: map}`,
		`s: [[1]]`,
		`s|contains: 3`,
		`"bad field!": x`,
		`any_command: {any_command: {name: x}}`,
		`any_command: {}`,
		`s: []`,
	}
	for _, c := range cases {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(c), &doc); err != nil {
			continue // not even YAML: fine
		}
		if _, err := compilePred(doc.Content[0], scopeEvent); err == nil {
			t.Errorf("%s compiled", c)
		}
	}
}

func TestLazyRegexCompilesOnce(t *testing.T) {
	n := pred(t, `s|re: "^a+$"`)
	r := n.leaf.res[0]
	if r.re != nil {
		t.Fatal("compiled before use")
	}
	f := map[string]any{"s": "aaa"}
	if !n.eval(f, &evalCtx{}) || r.re == nil {
		t.Fatal("not compiled on use")
	}
}
