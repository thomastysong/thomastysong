package fleetgen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Behaviour tests for the Fleet scripts that run without a container: the
// exact blocks of the shell scripts that touch extensions.load, run by sh;
// the PowerShell native calls, through a model of Windows PowerShell 5.1's
// argument passing; verify.sh's polling, sourced by bash. The full scripts
// run in a Debian container in test/e2e (TestFleetInstallScripts).

func needSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

// shBlock returns the text of script from the line that starts with start
// up to and including the first line after it that equals end.
func shBlock(t *testing.T, script, start, end string) string {
	t.Helper()
	i := strings.Index(script, start)
	if i < 0 {
		t.Fatalf("block %q not found", start)
	}
	j := strings.Index(script[i:], "\n"+end+"\n")
	if j < 0 {
		t.Fatalf("block %q has no end %q", start, end)
	}
	return script[i : i+j+len(end)+2]
}

func runSh(t *testing.T, code string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "set -eu\ndie() { echo \"$*\" >&2; exit 1; }\n"+code)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestAutoloadRegistrationKeepsOtherLines: registering hawkbell in osquery's
// extensions.load must keep every other entry intact. An existing last
// line without a newline used to be glued to hawkbell's path, so neither
// extension loaded and uninstall could not repair it.
func TestAutoloadRegistrationKeepsOtherLines(t *testing.T) {
	needSh(t)
	const ext = "/usr/lib/hawkbell/hawkbell.ext"
	blocks := map[string]string{
		"install-hawkbell.sh": shBlock(t, readDeploy(t, "scripts/install-hawkbell.sh"),
			"\tif ! grep -qxF \"$EXT\" \"$LOAD\" 2>/dev/null; then", "\tfi"),
		"register-extension.sh": shBlock(t, readDeploy(t, "scripts/register-extension.sh"),
			"if ! grep -qxF \"$EXT\" \"$LOAD\" 2>/dev/null; then", "fi"),
	}
	if _, err := exec.LookPath("bash"); err == nil {
		blocks["verify.sh"] = "append_line() {\n" + shBlock(t, readDeploy(t, "verify.sh"),
			"\tif grep -qxF \"$2\" \"$1\" 2>/dev/null; then return 0; fi", "}") + "\nappend_line \"$LOAD\" \"$EXT\"\n"
	}
	for name, block := range blocks {
		for _, tc := range []struct {
			name    string
			initial *string
			want    string
		}{
			{"missing file", nil, ext + "\n"},
			{"empty file", ptr(""), ext + "\n"},
			{"last line ends in newline", ptr("/usr/lib/santa/santa.ext\n"), "/usr/lib/santa/santa.ext\n" + ext + "\n"},
			{"last line without newline", ptr("/usr/lib/santa/santa.ext"), "/usr/lib/santa/santa.ext\n" + ext + "\n"},
			{"two lines, no final newline", ptr("/a.ext\n/b.ext"), "/a.ext\n/b.ext\n" + ext + "\n"},
			{"already registered", ptr("/a.ext\n" + ext + "\n"), "/a.ext\n" + ext + "\n"},
			{"already registered, no final newline", ptr(ext), ext},
		} {
			load := filepath.Join(t.TempDir(), "extensions.load")
			if tc.initial != nil {
				if err := os.WriteFile(load, []byte(*tc.initial), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := runSh(t, block, "EXT="+ext, "LOAD="+load, "load_changed=0", "restart=0"); err != nil {
				t.Fatalf("%s/%s: %v\n%s", name, tc.name, err, out)
			}
			b, _ := os.ReadFile(load)
			if string(b) != tc.want {
				t.Errorf("%s/%s: extensions.load = %q, want %q", name, tc.name, b, tc.want)
			}
		}
	}
}

func ptr(s string) *string { return &s }

// TestScriptsRefuseOrbitManagedAutoload: when orbit's own extensions.load
// is not empty (Fleet's `extensions` agent option), orbit starts osquery
// with --extensions_autoload pointing at it (orbit/cmd/orbit/orbit.go) and
// osquery ignores its default file. The extension tier must then fail with
// a reason instead of reporting a registration that never loads; the atc
// tier, and orbit with an empty file, are fine.
func TestScriptsRefuseOrbitManagedAutoload(t *testing.T) {
	needSh(t)
	install := shBlock(t, readDeploy(t, "scripts/install-hawkbell.sh"), "if [ \"$TIER\" = extension ]; then\n\tfor f in", "fi")
	register := shBlock(t, readDeploy(t, "scripts/register-extension.sh"), "for f in \"$ROOT/opt/orbit/extensions.load\"", "done")
	for _, tc := range []struct {
		name   string
		orbit  map[string]string // path under ROOT -> content
		tier   string
		refuse bool
	}{
		{"no orbit", nil, "extension", false},
		{"orbit, no managed extensions", map[string]string{"opt/orbit/extensions.load": ""}, "extension", false},
		{"orbit manages an extension", map[string]string{"opt/orbit/extensions.load": "/opt/orbit/bin/extensions/x.ext\n"}, "extension", true},
		{"old orbit root", map[string]string{"var/lib/orbit/extensions.load": "/var/lib/orbit/x.ext\n"}, "extension", true},
		{"atc tier ignores orbit", map[string]string{"opt/orbit/extensions.load": "/opt/orbit/x.ext\n"}, "atc", false},
	} {
		root := t.TempDir()
		for p, c := range tc.orbit {
			f := filepath.Join(root, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f, []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		env := []string{"ROOT=" + root, "TIER=" + tc.tier, "LOAD=/etc/osquery/extensions.load"}
		for name, block := range map[string]string{"install-hawkbell.sh": install, "register-extension.sh": register} {
			if name == "register-extension.sh" && tc.tier != "extension" {
				continue // the post-install script is the extension tier only
			}
			out, err := runSh(t, block, env...)
			if refused := err != nil; refused != tc.refuse {
				t.Errorf("%s/%s: refused = %v, want %v\n%s", name, tc.name, refused, tc.refuse, out)
			}
			if tc.refuse && !strings.Contains(out, "osquery ignores /etc/osquery/extensions.load") {
				t.Errorf("%s/%s: refusal does not say why: %s", name, tc.name, out)
			}
		}
	}
}

// ---- Windows PowerShell 5.1 native argument passing ----

// ps51CommandLine models how Windows PowerShell 5.1 (Fleet runs Windows
// scripts with powershell.exe) builds a native command line: an argument
// that has whitespace outside its own embedded quotes is wrapped in quotes,
// and embedded quotes are not escaped
// (NativeCommandParameterBinder.NeedQuotes).
func ps51CommandLine(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		need, bs, q := false, false, 0
		for _, r := range a {
			if r == '"' && !bs {
				q++
			} else if (r == ' ' || r == '\t') && q%2 == 0 {
				need = true
			}
			bs = r == '\\'
		}
		if need {
			a = `"` + a + `"`
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

// msvcArgv splits a command line the way the Microsoft C runtime does for
// sc.exe and icacls.exe: 2n backslashes and a quote give n backslashes and
// toggle quoting, 2n+1 give n and a literal quote, "" inside quotes is a
// literal quote.
func msvcArgv(cmd string) []string {
	var args []string
	for len(cmd) > 0 {
		if cmd[0] == ' ' || cmd[0] == '\t' {
			cmd = cmd[1:]
			continue
		}
		var b []byte
		inq, ns := false, 0
		flush := func() {
			for ; ns > 0; ns-- {
				b = append(b, '\\')
			}
		}
	arg:
		for ; len(cmd) > 0; cmd = cmd[1:] {
			c := cmd[0]
			switch {
			case (c == ' ' || c == '\t') && !inq:
				break arg
			case c == '\\':
				ns++
				continue
			case c == '"':
				for ; ns > 1; ns -= 2 {
					b = append(b, '\\')
				}
				if ns == 1 {
					ns = 0
					b = append(b, '"')
					continue
				}
				if inq && len(cmd) > 1 && cmd[1] == '"' {
					b = append(b, '"')
					cmd = cmd[1:]
					continue
				}
				inq = !inq
				continue
			}
			flush()
			b = append(b, c)
		}
		flush()
		args = append(args, string(b))
	}
	return args
}

// The defaults the PowerShell scripts compute on a standard Windows install.
var psVars = map[string][]string{
	"Name": {"hawkbell"},
	"Dir":  {`C:\Program Files\hawkbell`},
	"Data": {`C:\ProgramData\hawkbell`},
	"d":    {`C:\Program Files\hawkbell`, `C:\ProgramData\hawkbell`}, // foreach ($d in @($Dir, $Data))
	"bin":  {psServiceCommand},
}

// psServiceCommand is the service command line install-hawkbell.ps1 builds.
const psServiceCommand = `"C:\Program Files\hawkbell\hawkbell.exe" run --config "C:\ProgramData\hawkbell\hawkbell.yaml"`

// psArgSets expands a PowerShell argument list written as quoted literals
// and $variables into every concrete argument vector it can produce.
func psArgSets(t *testing.T, file string, elems []string) [][]string {
	t.Helper()
	sets := [][]string{nil}
	for _, el := range elems {
		var vals []string
		switch {
		case strings.HasPrefix(el, "'") && strings.HasSuffix(el, "'") && len(el) >= 2:
			vals = []string{strings.ReplaceAll(el[1:len(el)-1], "''", "'")}
		case strings.HasPrefix(el, "$"):
			v, ok := psVars[el[1:]]
			if !ok {
				t.Fatalf("%s: native argument %s: add its value to psVars", file, el)
			}
			vals = v
		case psBareWord.MatchString(el):
			vals = []string{el}
		default:
			t.Fatalf("%s: native argument %q is not a literal or a plain variable", file, el)
		}
		var next [][]string
		for _, s := range sets {
			for _, v := range vals {
				next = append(next, append(append([]string(nil), s...), v))
			}
		}
		sets = next
	}
	return sets
}

// splitPSWords splits "a $b 'c d'" at whitespace outside single quotes.
func splitPSWords(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for _, r := range s {
		switch {
		case r == '\'':
			inq = !inq
		case (r == ' ' || r == '\t') && !inq:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// splitPSList splits "'a', $b, 'c, d'" at top-level commas.
func splitPSList(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for _, r := range s {
		switch {
		case r == '\'':
			inq = !inq
		case r == ',' && !inq:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

var (
	psBareWord     = regexp.MustCompile(`^[A-Za-z0-9=/_.:-]+$`)
	psInvokeNative = regexp.MustCompile(`(?m)^\s*Invoke-Native\s+(\S+)\s+@\((.*)\)\s*$`)
	psDirectNative = regexp.MustCompile(`(?m)^.*&\s+(sc\.exe|icacls\.exe)\s+([^|]*?)\s*(\|.*)?$`)
)

// TestPowerShellNativeArguments: every argument the PowerShell scripts pass
// to sc.exe and icacls.exe must reach the program unchanged under Windows
// PowerShell 5.1. The service command line has embedded quotes, which 5.1
// does not escape: passed to `sc.exe create ... binPath= $bin` it arrived
// as binPath "C:\Program" plus a stray token, so the service was never
// created. It now goes to New-Service and Win32_Service.Change as one
// string. Every native call must also check its exit code.
func TestPowerShellNativeArguments(t *testing.T) {
	// The model reproduces the failure it guards against.
	old := []string{"create", "hawkbell", "binPath=", psServiceCommand, "start=", "delayed-auto"}
	if got := msvcArgv(ps51CommandLine(old)); strings.Join(got, "\x00") == strings.Join(old, "\x00") {
		t.Fatalf("the PowerShell 5.1 model passes %q through intact; it cannot catch the binPath defect", psServiceCommand)
	}
	if got := msvcArgv(`a "b c" "d \"e\" f" g\\h "i\\" ""`); strings.Join(got, "|") != `a|b c|d "e" f|g\\h|i\|` {
		t.Fatalf("msvcArgv model broken: %q", got)
	}

	ents, err := filepath.Glob(filepath.Join(deployDir(t), "scripts", "*.ps1"))
	if err != nil || len(ents) < 3 {
		t.Fatalf("ps1 scripts: %v (%d)", err, len(ents))
	}
	calls := 0
	for _, f := range ents {
		name := filepath.Base(f)
		code := stripComments(readDeploy(t, "scripts/"+name))
		if strings.Contains(strings.ToLower(code), "binpath=") {
			t.Errorf("%s: passes binPath= to sc.exe; PowerShell 5.1 mangles its quotes", name)
		}
		check := func(where string, args []string) {
			calls++
			for _, a := range args {
				if a == "" || strings.HasSuffix(a, `\`) || strings.ContainsRune(a, '"') {
					t.Errorf("%s: %s: argument %q is dropped or mangled by PowerShell 5.1", name, where, a)
				}
			}
			if got := msvcArgv(ps51CommandLine(args)); strings.Join(got, "\x00") != strings.Join(args, "\x00") {
				t.Errorf("%s: %s: %q arrives as %q", name, where, args, got)
			}
		}
		for _, m := range psInvokeNative.FindAllStringSubmatch(code, -1) {
			for _, args := range psArgSets(t, name, splitPSList(m[2])) {
				check("Invoke-Native "+m[1], args)
			}
		}
		lines := strings.Split(code, "\n")
		for i, l := range lines {
			m := psDirectNative.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			for _, args := range psArgSets(t, name, splitPSWords(m[2])) {
				check(m[1], args)
			}
			next := ""
			if i+1 < len(lines) {
				next = lines[i+1]
			}
			if !strings.Contains(l+next, "$LASTEXITCODE") {
				t.Errorf("%s: %s exit code not checked: %s", name, m[1], strings.TrimSpace(l))
			}
		}
		if strings.Contains(code, "Invoke-Native ") {
			def := regexp.MustCompile(`(?s)function Invoke-Native\(.*?\n\}`).FindString(code)
			if !strings.Contains(def, "$LASTEXITCODE -ne 0") || !strings.Contains(def, "throw") {
				t.Errorf("%s: Invoke-Native does not fail on a non-zero exit code:\n%s", name, def)
			}
		}
	}
	if calls < 5 {
		t.Errorf("found only %d native calls to check", calls)
	}
	ps := stripComments(readDeploy(t, "scripts/install-hawkbell.ps1"))
	for _, w := range []string{"New-Service -Name $Name -BinaryPathName $bin", "-MethodName Change -Arguments @{ PathName = $bin }", "$r.ReturnValue -ne 0"} {
		if !strings.Contains(ps, w) {
			t.Errorf("install-hawkbell.ps1 lacks %q", w)
		}
	}
}

// ---- verify.sh ----

// TestVerifyShSurvivesEmptyPolls: with set -euo pipefail, a live query that
// returned nothing (the host not answering yet) used to end verify.sh at
// its first poll. live must turn that into an error result and the waits
// must keep polling.
func TestVerifyShSurvivesEmptyPolls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "fleetctl")
	// `report` answers nothing twice, then 9 tables.
	if err := os.WriteFile(fake, []byte(`#!/bin/sh
n=$(cat "$COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$COUNT"
case "$1" in
report) [ "$n" -gt 2 ] || exit 1; echo 'noise'; echo '{"host":"vm","rows":[{"n":"9"}]}' ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `HAWKBELL_VERIFY_LIB=1 source "$VERIFY"
r=$(live "SELECT 1"); echo "first: $r"
wait_tables 9
echo "waited: $(cat "$COUNT") polls"
r=$(live "SELECT 1"); echo "later: $r"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "VERIFY="+filepath.Join(deployDir(t), "verify.sh"), "FLEETCTL="+fake,
		"COUNT="+filepath.Join(dir, "count"), "WORK="+dir, "POLL=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh functions failed: %v\n%s", err, out)
	}
	for _, w := range []string{`first: {"rows":[],"error":"no result from the host"}`, "waited: 3 polls", `later: {"host":"vm","rows":[{"n":"9"}]}`} {
		if !strings.Contains(string(out), w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// TestVerifyShWaitTablesGivesUp: osquery 5.19 kept ATC tables registered
// after the agent options stopped naming them, and tier 3's wait for 0
// tables ended the run. With a poll count wait_tables gives up softly
// (returning 1 and the last count) so the caller can restart osqueryd, and
// a poll the host did not answer is never taken for 0 tables.
func TestVerifyShWaitTablesGivesUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "fleetctl")
	// The host does not answer the first poll, then reports 9 tables.
	if err := os.WriteFile(fake, []byte(`#!/bin/sh
n=$(cat "$COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" >"$COUNT"
case "$1" in
report) [ "$n" -gt 1 ] || exit 1; echo '{"host":"vm","rows":[{"n":"9"}]}' ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `HAWKBELL_VERIFY_LIB=1 source "$VERIFY"
if left=$(wait_tables 0 3); then echo "waited for 0: ok"; else echo "gave up, last count $left"; fi
echo "polls: $(cat "$COUNT")"
rm -f "$COUNT"
if left=$(wait_tables 0 1); then echo "unanswered poll: 0"; else echo "unanswered poll: [$left]"; fi
echo "still running"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "VERIFY="+filepath.Join(deployDir(t), "verify.sh"), "FLEETCTL="+fake,
		"COUNT="+filepath.Join(dir, "count"), "WORK="+dir, "POLL=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh functions failed: %v\n%s", err, out)
	}
	for _, w := range []string{"gave up, last count 9", "polls: 3", "unanswered poll: [?]", "still running"} {
		if !strings.Contains(string(out), w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// TestVerifyShBinaryScenarios: with HAWKBELL_BIN, verify.sh signs and installs a
// rules bundle with the binary (once), and builds the "healthy" and "hook"
// databases with it: a fresh database, `scan --state`, then `run` (stopped
// by SIGTERM); for "hook" a Claude Code PreToolUse payload that pipes a
// downloaded script into sh goes through `hawkbell hook` while `run` is up.
// Without these the binary's healthy database could never pass the bundle
// policy (no bundle, no trusted key) and no scenario had a real detection.
func TestVerifyShBinaryScenarios(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "hawkbell")
	// A fake hawkbell: logs every call, writes what bundle keygen/create/pull
	// would, and for run stays up (marker file) until SIGTERM.
	if err := os.WriteFile(fake, []byte(`#!/bin/sh
log="$FAKE_DIR/calls"
echo "$*" >>"$log"
out= prev=
for a in "$@"; do [ "$prev" = --out ] && out=$a; prev=$a; done
case "$1 $2" in
"bundle keygen") echo key >"$out.key"; echo FAKEPUB >"$out.pub" ;;
"bundle create") echo tgz >"$out" ;;
"bundle pull") mkdir -p "$WORK/data/bundle" && echo '{"version":1}' >"$WORK/data/bundle/current" ;;
esac
case "$1" in
run)
	touch "$FAKE_DIR/running"
	trap 'rm -f "$FAKE_DIR/running"; echo "run stopped by TERM" >>"$log"; exit 0' TERM
	i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
	rm -f "$FAKE_DIR/running"; echo "run ended without TERM" >>"$log" ;;
hook)
	if [ -f "$FAKE_DIR/running" ]; then echo "hook while run is up" >>"$log"; fi
	cat >"$FAKE_DIR/payload" ;;
scan)
	if [ -e "$WORK/data/state.db" ]; then echo "scan found the old database" >>"$log"; fi ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	// sleep waits for the fake daemon instead of fixed seconds; timeout
	// stops it after a moment instead of 20 s.
	script := `HAWKBELL_VERIFY_LIB=1 source "$VERIFY"
sleep() { for _ in $(seq 1 100); do [ -f "$FAKE_DIR/running" ] && return 0; command sleep 0.05; done; }
timeout() { shift; "$@" & local p=$!; command sleep 0.3; kill -TERM "$p"; wait "$p"; }
bin_bundle
bin_bundle
for sc in healthy hook; do
	echo old >"$DB"; echo old >"$DB-wal"
	build_db "$sc"
done
echo "daemon pid after: [$DAEMON_PID]"
for sc in healthy hook planted stale removed; do
	echo "source $sc: $(db_source "$sc")"
	if table_scenario "$sc"; then echo "tables listed: $sc"; fi
done
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "VERIFY="+filepath.Join(deployDir(t), "verify.sh"), "HAWKBELL_BIN="+fake,
		"FAKE_DIR="+dir, "WORK="+dir, "POLL=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh functions failed: %v\n%s", err, out)
	}
	for _, w := range []string{"daemon pid after: []",
		"source healthy: the hawkbell binary", "source hook: the hawkbell binary", "source planted: the harness",
		"source stale: the harness", "source removed: nowhere, removed",
		"tables listed: healthy", "tables listed: hook"} {
		if !strings.Contains(string(out), w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	for _, w := range []string{"tables listed: planted", "tables listed: stale", "tables listed: removed"} {
		if strings.Contains(string(out), w) {
			t.Errorf("output has %q:\n%s", w, out)
		}
	}
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "hawkbell.yaml")
	want := []string{
		"bundle keygen --out " + filepath.Join(dir, "bundle", "key"),
		"bundle create --src " + filepath.Join(dir, "bundle", "src") + " --version 1 --key " +
			filepath.Join(dir, "bundle", "key.key") + " --out " + filepath.Join(dir, "bundle", "rules-1.tar.gz") +
			" --note deploy/fleet/verify.sh",
		"bundle pull --file " + filepath.Join(dir, "bundle", "rules-1.tar.gz") + " --config " + cfg,
		// healthy
		"scan --state --config " + cfg,
		"run --config " + cfg,
		"run stopped by TERM",
		// hook
		"scan --state --config " + cfg,
		"run --config " + cfg,
		"hook --agent claude-code --config " + cfg,
		"hook while run is up",
		"run stopped by TERM",
	}
	if got := strings.Split(strings.TrimSpace(string(calls)), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls of the binary:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if b, _ := os.ReadFile(cfg); string(b) != "data_dir: "+filepath.Join(dir, "data")+"\nbundle:\n  public_keys:\n    - FAKEPUB\n" {
		t.Errorf("hawkbell.yaml:\n%s", b)
	}
	packs, _ := filepath.Glob(filepath.Join(dir, "bundle", "src", "rules", "*.yaml"))
	if _, err := os.Stat(filepath.Join(dir, "bundle", "src", "lists.yaml")); err != nil || len(packs) == 0 {
		t.Errorf("bundle source: %d rule packs, lists.yaml: %v", len(packs), err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Session   string `json:"session_id"`
		Event     string `json:"hook_event_name"`
		Tool      string `json:"tool_name"`
		ToolUseID string `json:"tool_use_id"`
		Input     struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("hook payload is not JSON: %v\n%s", err, b)
	}
	if p.Event != "PreToolUse" || p.Tool != "Bash" || p.Session == "" || p.ToolUseID == "" ||
		!regexp.MustCompile(`^curl .*https://\S+ \| sh$`).MatchString(p.Input.Command) {
		t.Errorf("hook payload %+v", p)
	}
}
