//go:build unix

package hookinstall

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// hookShell is one way an agent hands a command line to a POSIX shell.
type hookShell struct {
	name string
	argv []string // the shell and its flags; the command line is appended
}

// hookShells returns `sh -c` (Codex's last resort, Cursor) and `bash -lc`
// (Codex's $SHELL fallback), which must exist, plus every other shell
// installed here as `<shell> -c` (bash -c is what Copilot CLI and Gemini CLI
// use).
func hookShells(t *testing.T) []hookShell {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Fatal("no /bin/sh")
	}
	out := []hookShell{{"sh -c", []string{"/bin/sh", "-c"}}}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("bash is required for the login-shell case")
	}
	out = append(out, hookShell{"bash -lc", []string{bash, "-lc"}}, hookShell{"bash -c", []string{bash, "-c"}})
	for _, s := range []string{"dash", "zsh", "ksh", "mksh", "fish"} {
		if p, err := exec.LookPath(s); err == nil {
			out = append(out, hookShell{s + " -c", []string{p, "-c"}})
		}
	}
	return out
}

// shellRun is the outcome of one hook invocation.
type shellRun struct {
	stdout, stderr []byte
	code           int
	pid            int
}

// runHook runs line the way an agent does: payload on stdin, a clean HOME
// so a login shell reads no personal profile, and env added.
func runHook(t *testing.T, sh hookShell, line string, stdin []byte, env ...string) shellRun {
	t.Helper()
	cmd := exec.Command(sh.argv[0], append(sh.argv[1:], line)...)
	cmd.Env = append(os.Environ(), append([]string{"HOME=" + t.TempDir(), "ENV=", "BASH_ENV="}, env...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("%s: %v", sh.name, err)
	}
	return shellRun{stdout: stdout.Bytes(), stderr: stderr.Bytes(), code: cmd.ProcessState.ExitCode(), pid: cmd.Process.Pid}
}

// renderedPOSIX returns every distinct POSIX command line PlanInstall
// writes for bin on linux, split into guarded lines and the unguarded
// (fail-closed) ones.
func renderedPOSIX(t *testing.T, bin string) (guardedLines, strictLines []string) {
	t.Helper()
	c := testCatalog(t)
	cases := []struct {
		agent string
		scope event.Scope
		fc    bool
	}{
		{"codex", event.ScopeUser, false},
		{"codex", event.ScopeManaged, false},
		{"codex", event.ScopeSystem, false},
		{"copilot-cli", event.ScopeUser, false},
		{"copilot-cli", event.ScopeManaged, false},
		{"gemini-cli", event.ScopeUser, false},
		{"gemini-cli", event.ScopeManaged, false},
		{"cursor", event.ScopeUser, false},
		{"cursor", event.ScopeManaged, false},
		{"cursor-agent", event.ScopeUser, false},
		{"cursor", event.ScopeManaged, true},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		o := opts(t, "linux", tc.scope, tc.agent)
		o.Binary = bin
		o.Guard, o.FailClosed = tc.fc, tc.fc
		p := only(t, mustPlan(t, c, o), tc.agent)
		cmds := collectCommands(t, p.Path, p.After)
		if len(cmds) == 0 {
			t.Fatalf("%s/%s: no shell commands", tc.agent, tc.scope)
		}
		for _, l := range cmds {
			if seen[l] {
				continue
			}
			seen[l] = true
			switch {
			case strings.HasPrefix(l, posixGuardHead):
				guardedLines = append(guardedLines, l)
			case strings.HasPrefix(l, posixExec) && tc.fc:
				strictLines = append(strictLines, l)
			default:
				t.Fatalf("%s/%s: unexpected command form %q", tc.agent, tc.scope, l)
			}
		}
	}
	if len(guardedLines) == 0 || len(strictLines) == 0 {
		t.Fatalf("%d guarded, %d strict lines", len(guardedLines), len(strictLines))
	}
	return guardedLines, strictLines
}

const hookPayload = `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`

// TestGuardMissingBinary runs every rendered POSIX command with a spoor
// binary that is not there, not executable or a dangling link: the hook
// must exit 0 and print nothing, which every agent reads as "no decision".
// Unguarded fail-closed lines must keep failing instead.
func TestGuardMissingBinary(t *testing.T) {
	shells := hookShells(t)
	dir := filepath.Join(t.TempDir(), "O'Brien Tools & co")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	noExec := filepath.Join(dir, "spoor-quarantined")
	writeFile(t, noExec, []byte("#!/bin/sh\necho ran\n"), 0o644)
	dangling := filepath.Join(dir, "spoor-link")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	// Root passes -x for a file with any execute bit, but not for one with
	// none, so "not executable" holds for root too.
	bins := map[string]string{
		"absent":         filepath.Join(dir, "missing", "spoor"),
		"not executable": noExec,
		"dangling link":  dangling,
	}
	for what, bin := range bins {
		guardedLines, strictLines := renderedPOSIX(t, bin)
		for _, sh := range shells {
			for _, line := range guardedLines {
				r := runHook(t, sh, line, []byte(hookPayload))
				if r.code != 0 || len(r.stdout) != 0 {
					t.Errorf("%s binary via %s: exit %d, stdout %q, stderr %q\n  %s", what, sh.name, r.code, r.stdout, r.stderr, line)
				}
				if len(r.stderr) != 0 {
					t.Errorf("%s binary via %s: the guard printed %q", what, sh.name, r.stderr)
				}
			}
			for _, line := range strictLines {
				if r := runHook(t, sh, line, []byte(hookPayload)); r.code == 0 {
					t.Errorf("fail-closed line exited 0 with a %s binary via %s: %s", what, sh.name, line)
				}
			}
		}
	}
}

// stubSpoor is a stand-in for the spoor binary: it records its pid and its
// stdin, then prints $STUB_OUT, writes $STUB_ERR to stderr and exits with
// $STUB_EXIT.
const stubSpoor = `#!/bin/sh
printf '%s' "$$" > "$STUB_DIR/pid"
cat > "$STUB_DIR/stdin"
printf '%s' "$STUB_OUT"
printf '%s' "$STUB_ERR" >&2
exit "$STUB_EXIT"
`

// TestGuardPassesThroughSpoor checks that the guard is invisible when the
// binary is there: spoor's stdout (its JSON decision), stderr and exit
// status reach the agent unchanged, including a deliberate 2 (Codex's
// block) and a deliberate 127, and the stdin payload reaches spoor. The
// shell's own pid becomes spoor's, which shows exec replaced the shell, so
// the agent's signals and timeout kill land on spoor itself.
func TestGuardPassesThroughSpoor(t *testing.T) {
	shells := hookShells(t)
	dir := filepath.Join(t.TempDir(), "O'Brien Tools & co")
	bin := filepath.Join(dir, "spoor")
	writeFile(t, bin, []byte(stubSpoor), 0o755)
	guardedLines, strictLines := renderedPOSIX(t, bin)
	lines := append(guardedLines, strictLines...)

	decision := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spoor: blocked by policy [R01] é 'quoted' \"double\" $HOME ` + "`x`" + `"}}` + "\n"
	cases := []struct {
		name, out, errText string
		exit               int
	}{
		{"json decision", decision, "", 0},
		{"exit 2 block", "", "spoor: blocked by policy\n", 2},
		{"exit 1", "", "spoor: internal error\n", 1},
		{"deliberate 127", "", "", 127},
	}
	for _, sh := range shells {
		for _, line := range lines {
			for _, tc := range cases {
				stubDir := t.TempDir()
				r := runHook(t, sh, line, []byte(hookPayload),
					"STUB_DIR="+stubDir, "STUB_OUT="+tc.out, "STUB_ERR="+tc.errText, "STUB_EXIT="+strconv.Itoa(tc.exit))
				if r.code != tc.exit {
					t.Errorf("%s via %s: exit %d, want %d (stderr %q)\n  %s", tc.name, sh.name, r.code, tc.exit, r.stderr, line)
				}
				if string(r.stdout) != tc.out {
					t.Errorf("%s via %s: stdout %q, want %q", tc.name, sh.name, r.stdout, tc.out)
				}
				if string(r.stderr) != tc.errText {
					t.Errorf("%s via %s: stderr %q, want %q", tc.name, sh.name, r.stderr, tc.errText)
				}
				if got := string(readBytes(t, filepath.Join(stubDir, "stdin"))); got != hookPayload {
					t.Errorf("%s via %s: spoor read %q from stdin", tc.name, sh.name, got)
				}
				if got := string(readBytes(t, filepath.Join(stubDir, "pid"))); got != strconv.Itoa(r.pid) {
					t.Errorf("%s via %s: spoor ran as pid %s, the shell was %d (no exec)", tc.name, sh.name, got, r.pid)
				}
			}
		}
	}
}

// TestGuardCost measures what the guard adds to a hook invocation: the
// guarded line against the line the previous release wrote, both running
// a binary that exits at once, interleaved, 300 runs each per shell.
func TestGuardCost(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement")
	}
	trueBin := ""
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			trueBin = p
			break
		}
	}
	if trueBin == "" {
		t.Skip("no true binary")
	}
	shells := []hookShell{{"sh -c", []string{"/bin/sh", "-c"}}}
	if bash, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, hookShell{"bash -c", []string{bash, "-c"}})
	}
	const runs = 300
	for _, sh := range shells {
		forms := []struct {
			name string
			line string
			d    []time.Duration
		}{
			{"previous", posixCommand(trueBin, "codex", legacy), nil},
			{"exec only", posixCommand(trueBin, "codex", strict), nil},
			{"guarded", posixCommand(trueBin, "codex", guarded), nil},
		}
		run := func(line string) time.Duration {
			cmd := exec.Command(sh.argv[0], append(sh.argv[1:], line)...)
			start := time.Now()
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			return time.Since(start)
		}
		for i := 0; i < 30; i++ { // warm the page cache and the exec path
			run(forms[i%len(forms)].line)
		}
		for i := 0; i < runs; i++ {
			// Alternate the order so drift affects both forms alike.
			for j := range forms {
				k := (i + j) % len(forms)
				forms[k].d = append(forms[k].d, run(forms[k].line))
			}
		}
		pct := func(d []time.Duration, p float64) time.Duration {
			s := append([]time.Duration(nil), d...)
			sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
			return s[int(p*float64(len(s)-1)+0.5)]
		}
		prev50, prev99 := pct(forms[0].d, 0.50), pct(forms[0].d, 0.99)
		ex50, ex99 := pct(forms[1].d, 0.50), pct(forms[1].d, 0.99)
		g50, g99 := pct(forms[2].d, 0.50), pct(forms[2].d, 0.99)
		t.Logf("%s, %d runs each: previous p50 %v p99 %v | exec only p50 %v p99 %v | guarded p50 %v p99 %v | check alone (guarded - exec only) p50 %+v p99 %+v | vs previous p50 %+v p99 %+v",
			sh.name, runs, prev50, prev99, ex50, ex99, g50, g99, g50-ex50, g99-ex99, g50-prev50, g99-prev99)
		// `[` is a builtin: the check adds no process. A bound far above
		// the expected microseconds still catches a guard that forks.
		if g50-ex50 > 2*time.Millisecond || g50-prev50 > 2*time.Millisecond {
			t.Errorf("%s: the guard adds %v at p50 (%v against the previous form)", sh.name, g50-ex50, g50-prev50)
		}
	}
}
