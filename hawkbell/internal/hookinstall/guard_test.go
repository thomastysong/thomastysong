package hookinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// renderedField is one command-carrying string of a rendered hook file.
type renderedField struct {
	key, value string
	args       []string // exec form only
	failClosed bool     // the handler carries "failClosed": true (Cursor)
}

// renderedFields decodes a rendered file with the standard decoders and
// returns every command field of every handler.
func renderedFields(t *testing.T, path string, data []byte) []renderedField {
	t.Helper()
	var root map[string]any
	if strings.HasSuffix(path, ".toml") {
		if _, err := toml.Decode(string(data), &root); err != nil {
			t.Fatalf("TOML: %v", err)
		}
	} else if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out []renderedField
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			var args []string
			if a, ok := x["args"].([]any); ok {
				for _, e := range a {
					s, _ := e.(string)
					args = append(args, s)
				}
			}
			failClosed, _ := x["failClosed"].(bool)
			for _, k := range []string{"command", "bash", "powershell", "commandWindows"} {
				if s, ok := x[k].(string); ok {
					out = append(out, renderedField{key: k, value: s, args: args, failClosed: failClosed})
				}
			}
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(root["hooks"])
	return out
}

// pwshShape checks a guarded PowerShell line without a PowerShell to run
// it: verbatim strings are closed, braces and parentheses balance outside
// them, no double-quoted (expanding) string is used, and the only variable
// is $LASTEXITCODE.
func pwshShape(line string) error {
	var depth []rune
	outside := strings.Builder{}
	for i := 0; i < len(line); {
		if line[i] == '\'' {
			_, rest, ok := cutPwshQuoted(line[i:])
			if !ok {
				return errors.New("unterminated string")
			}
			i = len(line) - len(rest)
			outside.WriteString("''")
			continue
		}
		c := rune(line[i])
		switch c {
		case '(', '{':
			depth = append(depth, c)
		case ')', '}':
			want := map[rune]rune{')': '(', '}': '{'}[c]
			if len(depth) == 0 || depth[len(depth)-1] != want {
				return fmt.Errorf("unbalanced %q at %d", c, i)
			}
			depth = depth[:len(depth)-1]
		case '"', '`':
			return fmt.Errorf("%q outside a verbatim string", c)
		}
		outside.WriteRune(c)
		i++
	}
	if len(depth) != 0 {
		return errors.New("unclosed bracket")
	}
	if rest := strings.ReplaceAll(outside.String(), "$LASTEXITCODE", ""); strings.Contains(rest, "$") {
		return errors.New("a variable other than $LASTEXITCODE")
	}
	return nil
}

// TestRenderedCommands renders every agent on every OS and scope, plain,
// with guard and fail-closed, and with native telemetry, and checks each
// command field: it runs `<binary> hook --agent <id>` and nothing more
// (none of the hook's internal flags --worker, --ppid, --t0, --deadline),
// is recognised as hawkbell's and names the binary, and has the form its
// shell needs. A handler marked failClosed (Cursor, guard and fail-closed)
// must have no missing-binary check on any OS, and every other handler
// must have it wherever its shell allows one.
func TestRenderedCommands(t *testing.T) {
	c := testCatalog(t)
	internal := []string{"--worker", "--ppid", "--t0", "--deadline"}
	variants := map[string]func(*Options){
		"plain":       func(*Options) {},
		"fail-closed": func(o *Options) { o.Guard, o.FailClosed = true, true },
		"otel":        func(o *Options) { o.OTel = "http://127.0.0.1:4319" },
	}
	bins := map[string][]string{
		"linux":   {unixBin, "/opt/O'Brien Tools & co/hawkbell"},
		"darwin":  {"/Applications/Hawkbell.app/Contents/MacOS/hawkbell"},
		"windows": {winBin, `C:\hawkbell\hawkbell.exe`, `C:\Users\O'Brien‘s Tools\hawkbell.exe`},
	}
	var nPosix, nPwsh, nBare, nExec, nStrictPosix, nStrictPwsh, nStrictBare int
	for goos, list := range bins {
		for _, bin := range list {
			for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser, event.ScopeSystem} {
				for vname, mutate := range variants {
					agents := allAgents
					if sc == event.ScopeSystem {
						agents = []string{"codex"}
					}
					o := opts(t, goos, sc, agents...)
					o.Binary = bin
					mutate(&o)
					for _, p := range mustPlan(t, c, o) {
						if p.Action == ActionUnsupported || len(p.After) == 0 || strings.HasSuffix(p.Path, "config.toml") {
							continue
						}
						where := fmt.Sprintf("%s/%s/%s/%s %s", goos, sc, vname, p.AgentID, bin)
						for _, f := range internal {
							if contains(p.After, f) {
								t.Errorf("%s: renders %s", where, f)
							}
						}
						fields := renderedFields(t, p.Path, p.After)
						if len(fields) == 0 {
							t.Fatalf("%s: no command fields", where)
						}
						for _, f := range fields {
							line := f.value
							if len(f.args) > 0 {
								// Claude Code exec form: no shell, no guard.
								nExec++
								if f.value != bin || strings.Join(f.args, " ") != "hook --agent "+p.AgentID {
									t.Errorf("%s: exec form %q %q", where, f.value, f.args)
								}
								line += " " + strings.Join(f.args, " ")
							}
							if strings.Count(line, hookMarker) != 1 {
								t.Errorf("%s: %s has %d markers: %s", where, f.key, strings.Count(line, hookMarker), line)
							}
							if hawkbell, sensor := classify([]string{line}); !hawkbell || sensor != "" {
								t.Errorf("%s: %s not recognised as hawkbell's: %s", where, f.key, line)
							}
							if got := binaryOf(line); got != bin {
								t.Errorf("%s: %s names binary %q: %s", where, f.key, got, line)
							}
							if len(f.args) > 0 {
								continue
							}
							pwsh := f.key == "powershell" || f.key == "commandWindows" ||
								(goos == "windows" && f.key == "command" && (p.AgentID == "gemini-cli" || p.AgentID == "cursor"))
							if f.failClosed && (vname != "fail-closed" || p.AgentID != "cursor") {
								t.Errorf("%s: %s: failClosed outside Cursor with guard and fail-closed", where, f.key)
							}
							// The strict forms are spelled out here rather than
							// rendered, so a change to the renderer cannot
							// move the expectation with it.
							strictPwsh := "& " + pwshQuote(bin) + " hook --agent " + p.AgentID
							strictPosix := "exec " + posixQuote(bin) + " hook --agent " + p.AgentID
							switch {
							case pwsh && plainWindowsPath(bin) && f.key != "powershell" && p.AgentID != "gemini-cli":
								// Run by PowerShell or cmd.exe: bare, the
								// documented gap, whether failClosed or not.
								nBare++
								if f.failClosed {
									nStrictBare++
								}
								if line != bin+" hook --agent "+p.AgentID {
									t.Errorf("%s: %s should be bare: %s", where, f.key, line)
								}
							case pwsh && f.failClosed:
								// Cursor failClosed on Windows: a missing
								// binary must fail and so block.
								nStrictPwsh++
								if line != strictPwsh {
									t.Errorf("%s: failClosed %s\n got %s\nwant %s", where, f.key, line, strictPwsh)
								}
								if err := pwshShape(line); err != nil {
									t.Errorf("%s: %s: %v: %s", where, f.key, err, line)
								}
							case pwsh:
								nPwsh++
								want := pwshCommand(bin, p.AgentID, guarded)
								if !strings.HasPrefix(line, pwshGuardHead) || line != want {
									t.Errorf("%s: %s\n got %s\nwant %s", where, f.key, line, want)
								}
								if err := pwshShape(line); err != nil {
									t.Errorf("%s: %s: %v: %s", where, f.key, err, line)
								}
							case f.failClosed:
								nStrictPosix++
								if line != strictPosix {
									t.Errorf("%s: failClosed %s\n got %s\nwant %s", where, f.key, line, strictPosix)
								}
							default:
								nPosix++
								if line != posixCommand(bin, p.AgentID, guarded) {
									t.Errorf("%s: %s\n got %s\nwant %s", where, f.key, line, posixCommand(bin, p.AgentID, guarded))
								}
							}
						}
					}
				}
			}
		}
	}
	if nPosix == 0 || nPwsh == 0 || nBare == 0 || nExec == 0 || nStrictPosix == 0 || nStrictPwsh == 0 || nStrictBare == 0 {
		t.Errorf("coverage: %d posix, %d pwsh, %d bare, %d exec, failClosed: %d posix, %d pwsh, %d bare",
			nPosix, nPwsh, nBare, nExec, nStrictPosix, nStrictPwsh, nStrictBare)
	}
}

func TestPwshShapeRejects(t *testing.T) {
	good := pwshCommand(`C:\a b\O'Brien’s [x]\hawkbell.exe`, "codex", guarded)
	if err := pwshShape(good); err != nil {
		t.Fatalf("%v: %s", err, good)
	}
	for _, bad := range []string{
		"if (Test-Path -LiteralPath 'C:\\a.exe' -PathType Leaf) { & 'C:\\a.exe' hook --agent x; exit $LASTEXITCODE } else { exit 0 ",
		"if (Test-Path -LiteralPath 'C:\\a.exe -PathType Leaf) { & 'C:\\a.exe' hook --agent x }",
		"if (Test-Path -LiteralPath \"C:\\a.exe\") { & 'C:\\a.exe' hook --agent x }",
		"if (Test-Path -LiteralPath $p) { & 'C:\\a.exe' hook --agent x }",
	} {
		if pwshShape(bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestGuardNotes checks that a plan states the trade-offs the command form
// makes where one exists.
func TestGuardNotes(t *testing.T) {
	c := testCatalog(t)
	note := func(goos, agent, bin string) string {
		o := opts(t, goos, event.ScopeUser, agent)
		o.Binary = bin
		return only(t, mustPlan(t, c, o), agent).Note
	}
	if n := note("linux", "copilot-cli", unixBin); !strings.Contains(n, "checks for the hawkbell binary first") {
		t.Errorf("copilot: %s", n)
	}
	// The bare line costs only the missing-binary check: hawkbell hook exits 0
	// in every case and sends a Codex block as JSON (internal/hookcmd), so
	// the note must not claim that PowerShell's exit-code handling loses a
	// block.
	plain := note("windows", "codex", `C:\hawkbell\hawkbell.exe`)
	if !strings.Contains(plain, "commandWindows is written bare") || !strings.Contains(plain, "no missing-binary check") || !strings.Contains(plain, "does not block") {
		t.Errorf("codex, plain path: %s", plain)
	}
	for _, bad := range []string{"exits 2", "exit 2", "exits 1", "does not take effect"} {
		if strings.Contains(plain, bad) {
			t.Errorf("codex, plain path: the note says %q, but hawkbell hook never exits 2:\n%s", bad, plain)
		}
	}
	if n := note("windows", "codex", winBin); !strings.Contains(n, "commandWindows is written for PowerShell") {
		t.Errorf("codex, quoted path: %s", n)
	}
	if n := note("linux", "codex", unixBin); strings.Contains(n, "commandWindows") {
		t.Errorf("codex on linux: %s", n)
	}
}

// FuzzCommandRoundTrip: every form renders a binary path that binaryOf
// reads back exactly, and binaryOf, classify and pwshShape never panic on
// arbitrary text (hook files are written by whoever controls them).
func FuzzCommandRoundTrip(f *testing.F) {
	for _, s := range []string{
		"/usr/local/bin/hawkbell", "/a b/it's/hawkbell", `C:\Program Files\O'Brien‘x’\hawkbell.exe`,
		"/x/''/'''/hawkbell", "'", "’’", "] || exit 0; exec '", "-PathType Leaf) { & '",
		"[ -x '/a' ] || exit 0; exec '/a' hook --agent x", "\xff\xfe'", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, line := range []string{s, s + hookMarker + "x", posixGuardHead + s + hookMarker + "x", pwshGuardHead + s + hookMarker + "x", "& " + s + hookMarker + "x"} {
			_ = binaryOf(line)
			_, _ = classify([]string{line})
			_ = pwshShape(line)
		}
		// The paths validBinary accepts: valid UTF-8 (pwshQuote would carry
		// an invalid byte as U+FFFD), no control characters.
		if s == "" || !utf8.ValidString(s) || strings.Contains(s, hookMarker) || hasControl(s) || strings.TrimSpace(s) != s {
			return
		}
		for _, m := range []guardMode{guarded, strict, legacy} {
			for _, line := range []string{posixCommand(s, "codex", m), pwshCommand(s, "codex", m)} {
				if got := binaryOf(line); got != s {
					t.Fatalf("binaryOf(%q) = %q, want %q", line, got, s)
				}
			}
		}
		// Outside its verbatim strings the guarded line is fixed text, so
		// its shape cannot depend on the path.
		if err := pwshShape(pwshCommand(s, "codex", guarded)); err != nil {
			t.Fatalf("%v: %s", err, pwshCommand(s, "codex", guarded))
		}
	})
}
