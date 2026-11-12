package hookinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestQuoting(t *testing.T) {
	if got := posixQuote("/a b/it's"); got != `'/a b/it'\''s'` {
		t.Errorf("posixQuote %s", got)
	}
	if got := pwshQuote(`C:\O'Brien’s\x.exe`); got != `'C:\O''Brien’’s\x.exe'` {
		t.Errorf("pwshQuote %s", got)
	}
	// binaryOf reads back every form, current and legacy, for paths that
	// stress both quoting rules.
	for _, bin := range []string{
		"/usr/bin/spoor", "/a b/it's/spoor", `C:\Program Files\O'Brien‘x’\spoor.exe`,
		"/x/''/'''/spoor", "/a/[b]*/spoor", "/a/exec '/b/spoor", `C:\a\’’’\spoor.exe`,
		"/opt/] || exit 0; exec /spoor",
	} {
		lines := []string{bin + " hook --agent codex"}
		for _, m := range []guardMode{guarded, strict, legacy} {
			lines = append(lines, posixCommand(bin, "codex", m), pwshCommand(bin, "codex", m), windowsCommand(bin, "codex", m))
		}
		for _, line := range lines {
			if got := binaryOf(line); got != bin {
				t.Errorf("binaryOf(%q) = %q, want %q", line, got, bin)
			}
		}
	}
	for _, bad := range []string{
		"no marker here",
		"& 'unterminated hook --agent x",
		"'unterminated hook --agent x",
		"'/a' '/b' hook --agent x",
		"exec '/a hook --agent x",
		"& 'C:\\a.exe' 'x' hook --agent x",
		// A guard must check the path it runs; anything else is not a line
		// this package wrote.
		"[ -x '/a/spoor' ] || exit 0; exec '/b/spoor' hook --agent x",
		"[ -x '/a/spoor' ] || exit 0; '/a/spoor' hook --agent x",
		"[ -x '/a/spoor' ] && exit 0; exec '/a/spoor' hook --agent x",
		"[ -x '/a/spoor' ] || exit 0; exec '/a/spoor' '/a/spoor' hook --agent x",
		"if (Test-Path -LiteralPath 'C:\\a.exe' -PathType Leaf) { & 'C:\\b.exe' hook --agent x; exit $LASTEXITCODE } else { exit 0 }",
		"if (Test-Path -LiteralPath 'C:\\a.exe' -PathType Leaf) { & 'C:\\a.exe' 'x' hook --agent x",
		"if (Test-Path -LiteralPath 'C:\\a.exe hook --agent x",
	} {
		if got := binaryOf(bad); got != "" {
			t.Errorf("binaryOf(%q) = %q, want none", bad, got)
		}
	}
	for p, ok := range map[string]bool{
		`C:\spoor\spoor.exe`:         true,
		`C:\Program Files\spoor.exe`: false,
		`C:\a&b\spoor.exe`:           false,
		`C:\%TEMP%\spoor.exe`:        false,
		`C:\a'b\spoor.exe`:           false,
		``:                           false,
	} {
		if plainWindowsPath(p) != ok {
			t.Errorf("plainWindowsPath(%q) != %v", p, ok)
		}
	}
	forms := []struct{ got, want string }{
		{posixCommand("/opt/O'Brien/spoor", "codex", guarded), `[ -x '/opt/O'\''Brien/spoor' ] || exit 0; exec '/opt/O'\''Brien/spoor' hook --agent codex`},
		{posixCommand("/opt/spoor", "cursor", strict), `exec '/opt/spoor' hook --agent cursor`},
		{posixCommand("/opt/spoor", "codex", legacy), `'/opt/spoor' hook --agent codex`},
		{pwshCommand(`C:\O'Brien\spoor.exe`, "copilot-cli", guarded), `if (Test-Path -LiteralPath 'C:\O''Brien\spoor.exe' -PathType Leaf) { & 'C:\O''Brien\spoor.exe' hook --agent copilot-cli; exit $LASTEXITCODE } else { exit 0 }`},
		{pwshCommand(`C:\x\spoor.exe`, "cursor", strict), `& 'C:\x\spoor.exe' hook --agent cursor`},
		{pwshCommand(`C:\x\spoor.exe`, "codex", legacy), `& 'C:\x\spoor.exe' hook --agent codex`},
		// A path that cmd.exe and PowerShell both read unquoted stays bare
		// in every mode (the documented gap); any other gets PowerShell's.
		{windowsCommand(`C:\spoor\spoor.exe`, "x", guarded), `C:\spoor\spoor.exe hook --agent x`},
		{windowsCommand(`C:\spoor\spoor.exe`, "x", legacy), `C:\spoor\spoor.exe hook --agent x`},
		{windowsCommand(`C:\Program Files\s.exe`, "x", guarded), `if (Test-Path -LiteralPath 'C:\Program Files\s.exe' -PathType Leaf) { & 'C:\Program Files\s.exe' hook --agent x; exit $LASTEXITCODE } else { exit 0 }`},
		{windowsCommand(`C:\Program Files\s.exe`, "x", legacy), `& 'C:\Program Files\s.exe' hook --agent x`},
	}
	for _, f := range forms {
		if f.got != f.want {
			t.Errorf("command form\n got %s\nwant %s", f.got, f.want)
		}
	}
	for id, ok := range map[string]bool{
		"claude-code": true, "cursor": true, "a.b_c-1": true,
		"": false, "-x": false, "A": false, "a b": false, "a;b": false, "a/b": false,
		strings.Repeat("a", 65): false,
	} {
		if validAgentID(id) != ok {
			t.Errorf("validAgentID(%q) != %v", id, ok)
		}
	}
}

func TestForeignSensorRecognition(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/numbat hook pre-tool-use --agent claude": "numbat",
		`"C:\Program Files\numbat\numbat.exe" hook stop`:         "numbat",
		"snyk-agent-guard hook --client claude":                  "snyk-agent-guard",
		"/opt/beacon/beacon-hooks claude pre":                    "agent-beacon",
		"/home/numbat/bin/spoor hook --agent claude-code":        "",
		"/usr/local/bin/spoor hook --agent claude-code":          "",
		"python3 /opt/hooks/check.py":                            "",
	}
	for line, want := range cases {
		if got := sensorIn(line); got != want {
			t.Errorf("sensorIn(%q) = %q, want %q", line, got, want)
		}
	}
	if spoor, s := classify([]string{"/x/numbat hook --agent x"}); spoor || s != "numbat" {
		t.Error("numbat with the spoor marker must stay numbat")
	}
	if spoor, _ := classify([]string{"/x/spoor hook --agent x"}); !spoor {
		t.Error("spoor not recognised")
	}
	if spoor, _ := classify([]string{strings.Repeat("a", maxCommandLen*2) + " hook --agent x"}); !spoor {
		t.Error("long line")
	}
}

func TestTOMLBlocks(t *testing.T) {
	blk := hooksBegin + "\nx = 1\n" + hooksEnd + "\n"
	cases := []struct {
		name  string
		src   string
		found bool
		err   bool
	}{
		{"none", "a = 1\n", false, false},
		{"block", "a = 1\n\n" + blk, true, false},
		{"crlf and trailing blanks", "a = 1\r\n" + hooksBegin + " \r\n" + hooksEnd + "\t\r\n", true, false},
		{"no final newline", hooksBegin + "\n" + hooksEnd, true, false},
		{"end first", hooksEnd + "\n" + hooksBegin + "\n", false, true},
		{"open", hooksBegin + "\n", false, true},
		{"twice", blk + blk, false, true},
		{"nested", hooksBegin + "\n" + hooksBegin + "\n" + hooksEnd + "\n", false, true},
		{"indented markers are not markers", "  " + hooksBegin + "\n", false, false},
	}
	for _, tc := range cases {
		b, err := findBlock([]byte(tc.src), hooksBegin, hooksEnd)
		if (err != nil) != tc.err || b.found != tc.found {
			t.Errorf("%s: found=%v err=%v", tc.name, b.found, err)
		}
	}
	// put then cut restores the original for every trailing shape.
	for _, src := range []string{"", "a = 1", "a = 1\n", "a = 1\n\n", "a = 1\r\n", "# only a comment\n"} {
		nl := newline([]byte(src))
		out := putBlock([]byte(src), block{}, blk, nl)
		b, err := findBlock(out, hooksBegin, hooksEnd)
		if err != nil || !b.found {
			t.Fatalf("%q: block not found after put", src)
		}
		if back := cutBlock(out, b); string(back) != src {
			t.Errorf("%q: put/cut gave %q", src, back)
		}
	}
	// Replacing keeps the surroundings.
	src := "a = 1\n\n" + hooksBegin + "\nold = 1\n" + hooksEnd + "\n[t]\nb = 2\n"
	b, _ := findBlock([]byte(src), hooksBegin, hooksEnd)
	out := putBlock([]byte(src), b, blk, "\n")
	if string(out) != "a = 1\n\n"+blk+"[t]\nb = 2\n" {
		t.Errorf("replace: %q", out)
	}
	if keysAfter([]byte(src), b) {
		t.Error("a table header after the block is fine")
	}
	if !keysAfter([]byte(hooksBegin+"\n"+hooksEnd+"\n# c\n\nstray = 1\n"), block{found: true, start: 0, end: len(hooksBegin + "\n" + hooksEnd + "\n")}) {
		t.Error("stray key not detected")
	}
}

func TestTOMLStringRoundTrip(t *testing.T) {
	for _, s := range []string{
		`plain`, `with "quotes"`, `back\slash`, `C:\Program Files\O'Brien\spoor.exe`,
		"ctl\x01\x7f", "tab\there", "unicode ‘’ é",
	} {
		var v struct{ X string }
		if _, err := toml.Decode("X = "+tomlString(s), &v); err != nil || v.X != s {
			t.Errorf("tomlString(%q): %q %v", s, v.X, err)
		}
	}
}

func TestSDDLProblem(t *testing.T) {
	cases := []struct {
		sddl string
		ok   bool
	}{
		{"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", true},
		{"O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", true},
		{"O:S-1-5-21-1-2-3-1001D:PAI(A;;FA;;;SY)", false}, // owned by a user
		{"O:BAD:(A;;FA;;;SY)(A;;FW;;;BU)", false},         // users can write
		{"O:BAD:(A;;0x2;;;AU)", false},                    // add file for authenticated users
		{"O:BAD:(A;;GA;;;WD)", false},                     // everyone generic all
		{"O:BAD:(A;OICIIO;GA;;;CO)(A;;FA;;;BA)", true},    // inherit-only creator owner
		{"O:BAD:(D;;FA;;;BU)(A;;FA;;;BA)", true},          // deny grants nothing
		{"O:BAD:(A;;WDWO;;;BU)", false},                   // change the DACL
		{"O:BA", false},                                   // no DACL
		{"O:BAD:P", true},                                 // empty DACL
		{"O:BAD:(A;;ZZ;;;BU)", false},                     // unknown right
		{"O:BAD:(A;;FA)", false},                          // short ACE
		{"garbage", false},
		{"O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)S:AI(AU;SA;FA;;;WD)", true}, // group and SACL sections
		// A NULL DACL grants everyone full control; Windows writes it as
		// NO_ACCESS_CONTROL, without parentheses.
		{"O:BAD:NO_ACCESS_CONTROL", false},
		{"O:SYG:SYD:NO_ACCESS_CONTROL", false},
		{"O:BAD:PNO_ACCESS_CONTROL", false},
		{"O:BAD:NO_ACCESS_CONTROLS:AI(AU;SA;FA;;;WD)", false},
		{"O:BAD:", true},                              // empty DACL, no flags
		{"O:BAD:PAIAR(A;;FA;;;SY)", true},             // every known flag
		{"O:BAD:QQ(A;;FA;;;SY)", false},               // unknown flag
		{"O:BAD:(A;;FA;;;SY)junk(A;;FA;;;BA)", false}, // text between entries
		{"O:BAD:(A;;FA;;;SY", false},                  // unterminated entry
		{"O:BAD:(ZA;;FW;;;BU)(A;;FA;;;BA)", false},    // callback object entry
	}
	for _, tc := range cases {
		if got := sddlProblem(tc.sddl); (got == "") != tc.ok {
			t.Errorf("sddlProblem(%q) = %q", tc.sddl, got)
		}
	}
	if sddlProblem(managedFileSDDLForTest) != "" || sddlProblem(managedDirSDDLForTest) != "" {
		t.Error("the descriptors this package sets must pass its own check")
	}
}

// Copies of the Windows descriptors (perm_windows.go is windows-only).
const (
	managedFileSDDLForTest = "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	managedDirSDDLForTest  = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

func TestManagedChain(t *testing.T) {
	sep := string(filepath.Separator)
	j := func(parts ...string) string { return sep + filepath.Join(parts...) }
	cases := []struct {
		path string
		want []string
	}{
		{j("etc", "claude-code", "managed-settings.d", "50-spoor.json"),
			[]string{j("etc", "claude-code", "managed-settings.d"), j("etc", "claude-code")}},
		{j("Library", "Application Support", "ClaudeCode", "managed-settings.d", "50-spoor.json"),
			[]string{j("Library", "Application Support", "ClaudeCode", "managed-settings.d"), j("Library", "Application Support", "ClaudeCode")}},
		{j("root", "C", "ProgramData", "Cursor", "hooks.json"), []string{j("root", "C", "ProgramData", "Cursor")}},
		{j("etc", "hooks.json"), []string{j("etc")}},
		{j("opt", "x", "hooks.json"), []string{j("opt", "x")}},
	}
	for _, tc := range cases {
		got := managedChain(tc.path)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("managedChain(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestPathHelpers(t *testing.T) {
	if pathKey(`C:\Program Files\X. \a.json`, "windows") != pathKey(`c:/program files/x/A.JSON`, "windows") {
		t.Error("windows path folding")
	}
	if pathKey("/Library/X", "darwin") != pathKey("/library/x", "darwin") || pathKey("/a/B", "linux") == pathKey("/a/b", "linux") {
		t.Error("case folding by OS")
	}
	if d, b := splitPath(`C:\a\b.json`, "windows"); d != `C:\a` || b != "b.json" {
		t.Errorf("split %s %s", d, b)
	}
	if d, b := splitPath("/x", "linux"); d != "/" || b != "x" {
		t.Errorf("split root %s %s", d, b)
	}
	if joinPath(`C:\`, "x", "windows") != `C:\x` || joinPath("/a", "x", "linux") != "/a/x" {
		t.Error("join")
	}
	root := filepath.FromSlash("/r")
	if got := hostPath(root, `C:\ProgramData\x.json`, "windows"); got != filepath.Join(root, "C", "ProgramData", "x.json") {
		t.Errorf("hostPath drive: %s", got)
	}
	if got := hostPath(root, `\\srv\share\x.json`, "windows"); got != filepath.Join(root, "UNC", "srv", "share", "x.json") {
		t.Errorf("hostPath UNC: %s", got)
	}
	if got := hostPath(root, "/etc/x", "linux"); got != filepath.Join(root, "etc", "x") {
		t.Errorf("hostPath unix: %s", got)
	}
}

func TestChainWalk(t *testing.T) {
	root := t.TempDir()
	if why := checkChain(filepath.Join(root, "a", "b"), ""); why != "" {
		t.Errorf("missing dirs: %s", why)
	}
	file := filepath.Join(root, "file")
	writeFile(t, file, []byte("x"), 0o644)
	if why := checkChain(filepath.Join(file, "sub"), ""); !strings.Contains(why, "not a directory") {
		t.Errorf("file in the way: %q", why)
	}
	if _, err := openDirChain(filepath.Join(file, "sub"), "", dirPolicy{create: true}); err == nil {
		t.Error("created below a file")
	}
	if why := checkChain("relative/dir", ""); why == "" {
		t.Error("relative path accepted")
	}
	if why := checkChain(filepath.Join(root, "..", "x"), filepath.Join(root, "in")); why == "" {
		t.Error("path outside the confining root accepted")
	}
	r, err := openDirChain(filepath.Join(root, "new", "deep"), root, dirPolicy{create: true})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if fi, err := os.Stat(filepath.Join(root, "new", "deep")); err != nil || !fi.IsDir() {
		t.Error("directories not created")
	}
	// Without create, a missing directory is an error for Apply.
	if _, err := openDirChain(filepath.Join(root, "absent"), root, dirPolicy{}); err == nil {
		t.Error("opened a missing directory")
	}

	// A loop of links made by this user (trusted when unprivileged; made by
	// root when running as root) ends with an error, not a hang.
	a, b := filepath.Join(root, "la"), filepath.Join(root, "lb")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_ = os.Symlink(a, b)
	if _, err := openDirChain(filepath.Join(a, "x"), "", dirPolicy{create: true}); err == nil {
		t.Error("link loop accepted")
	}
	if why := checkChain(filepath.Join(a, "x"), ""); why == "" {
		t.Error("link loop accepted by checkChain")
	}
	if _, err := openDirChain(filepath.Join(a, "x"), root, dirPolicy{create: true}); !errors.Is(err, ErrSymlink) {
		t.Errorf("link under a confining root: %v", err)
	}
}

func TestTOMLBounds(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("{b=", n) + "1" + strings.Repeat("}", n) }
	ok := []string{
		requirementsTOML,
		"[otel]\nexporter = { otlp-http = { endpoint = \"http://x/v1/logs\", protocol = \"json\" } }\n",
		"a = " + deep(maxTOMLDepth-1) + "\n",
		"[a.b.c]\nd = " + deep(maxTOMLDepth-4) + "\n",
		// Brackets inside strings and comments do not nest anything.
		"s = \"" + strings.Repeat("[{", 50) + "\"\n# " + strings.Repeat("[", 50) + "\nl = '" + strings.Repeat("{", 50) + "'\n",
		"m = \"\"\"\n" + strings.Repeat("[", 50) + "\"\"\n\"\"\"\nn = '''" + strings.Repeat("{", 50) + "'''\n",
		"o = \"\"\"\"x\"\"\"\"\np = [" + strings.Repeat("1,", 10) + "]\n",
		"q = \"a\\\"[[[[[[[[[[[[[[[[[[[[\"\n",
		"[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n[[hooks.PreToolUse.hooks]]\ncommand = \"x\"\n",
		"[projects.\"/a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r\"]\ntrust_level = \"trusted\"\n",
		"v = [1.5, 2.5, 3.5]\nw = 1979-05-27T07:32:00.999\n",
	}
	for _, src := range ok {
		var m map[string]any
		if _, err := toml.Decode(src, &m); err != nil {
			t.Errorf("test input is not valid TOML: %q: %v", src, err)
		}
		if err := tomlBounds([]byte(src)); err != nil {
			t.Errorf("refused %q: %v", src, err)
		}
	}
	bad := map[string]string{
		"inline tables":        "a = " + deep(maxTOMLDepth+1) + "\n",
		"arrays":               "a = " + strings.Repeat("[", maxTOMLDepth+1) + strings.Repeat("]", maxTOMLDepth+1) + "\n",
		"dotted key":           "a" + strings.Repeat(".b", maxTOMLDepth+1) + " = 1\n",
		"header":               "[a" + strings.Repeat(".b", maxTOMLDepth) + "]\n",
		"header then value":    "[a" + strings.Repeat(".b", 9) + "]\nc = " + deep(8) + "\n",
		"dotted key in inline": "a = {b" + strings.Repeat(".c", 10) + " = " + deep(7) + "}\n",
		"after a string":       "s = \"}}}]]]\"\na = " + deep(maxTOMLDepth+1) + "\n",
		"after a comment":      "# }}}]]]\na = " + deep(maxTOMLDepth+1) + "\n",
		"after a ml string":    "s = '''\n}}}]]]\n'''\na = " + deep(maxTOMLDepth+1) + "\n",
		"size":                 strings.Repeat("k = 1\n", maxTOMLSize/6+1),
	}
	for name, src := range bad {
		if err := tomlBounds([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := parseTOML([]byte(src)); err == nil {
			t.Errorf("%s: parseTOML accepted", name)
		}
	}
}
