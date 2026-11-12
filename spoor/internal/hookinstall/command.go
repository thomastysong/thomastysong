package hookinstall

import (
	"strings"
	"unicode/utf8"
)

// posixQuote wraps s in single quotes. Inside single quotes sh, bash, zsh and
// fish expand nothing, so one rule covers every login shell Codex, Copilot,
// Gemini and Cursor may hand the string to. The path is always quoted, even
// when it would not need it, so the generated text does not change shape
// when a path gains a space.
func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// pwshQuote wraps s in a PowerShell single-quoted (verbatim) string.
// PowerShell also treats the typographic quotes U+2018..U+201B as string
// delimiters, so they are doubled like the ASCII apostrophe.
func pwshQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, r := range s {
		if isPwshQuote(r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// guardMode selects how a shell command line treats a spoor binary that is
// not there.
type guardMode uint8

const (
	// guarded checks for the binary first and exits 0 without output when
	// it is missing (POSIX: or not executable; PowerShell: or not a file).
	// A shell that cannot find
	// a program exits 126/127, and Copilot CLI denies a preToolUse call on
	// any non-zero exit while Gemini CLI reads a non-JSON exit 127 as a
	// deny: a removed, half-replaced or quarantined binary would otherwise
	// block every tool call. The check never changes a status spoor itself
	// returns (exec hands over the process; PowerShell exits with
	// $LASTEXITCODE).
	guarded guardMode = iota
	// strict has no check: the handler asks the agent to block when the
	// hook fails (Cursor failClosed), and a missing binary is exactly the
	// failure the operator asked to be blocked on.
	strict
	// legacy is what releases before the guard wrote. It is rendered only
	// to recognise such entries in Status.
	legacy
)

// modeFor picks the form for one handler.
func (p params) modeFor(failClosed bool) guardMode {
	switch {
	case p.legacy:
		return legacy
	case failClosed:
		return strict
	}
	return guarded
}

// Shell fragments of the guarded forms. binaryOf parses exactly these.
const (
	posixGuardHead = "[ -x "
	posixGuardTail = " ] || exit 0; "
	posixExec      = "exec "
	pwshGuardHead  = "if (Test-Path -LiteralPath "
	pwshGuardMid   = " -PathType Leaf) { & "
	pwshGuardTail  = "; exit $LASTEXITCODE } else { exit 0 }"
)

// posixCommand is the hook command line for a POSIX shell:
//
//	[ -x '<bin>' ] || exit 0; exec '<bin>' hook --agent <id>
//
// `[` is a builtin in sh, dash, bash, zsh and ksh (and fish, which needs
// 3.0 for ||; UNVERIFIED, fish is not installed in the build
// environment), so the check starts no process. exec replaces the shell with spoor, so stdin, stdout,
// signals and the exit status are spoor's own; nothing follows the call
// that could rewrite its status (no `|| true`).
func posixCommand(bin, agent string, m guardMode) string {
	q := posixQuote(bin)
	switch m {
	case legacy:
		return q + hookMarker + agent
	case strict:
		return posixExec + q + hookMarker + agent
	}
	return posixGuardHead + q + posixGuardTail + posixExec + q + hookMarker + agent
}

// pwshCommand is the hook command line for PowerShell:
//
//	if (Test-Path -LiteralPath '<bin>' -PathType Leaf) { & '<bin>' hook --agent <id>; exit $LASTEXITCODE } else { exit 0 }
//
// A quoted path is a string expression there, not a command, so it needs
// the call operator; -LiteralPath takes the path verbatim (no wildcard
// expansion of [ ] in it). exit $LASTEXITCODE is also what keeps spoor's
// status: with -Command, PowerShell turns any native exit code other than
// 0 or 1 into 1 unless the script exits with it explicitly
// (about_Pwsh.md, "-Command", re-read 2026-11-12), which loses Codex's
// exit-2 block. A call that fails without running anything (a file that
// is not a program) leaves $LASTEXITCODE unset, so the guarded line then
// exits 0 too (UNVERIFIED: no PowerShell in the build environment). The
// strict and legacy forms are the bare call, which exits 1 when the binary
// is missing.
func pwshCommand(bin, agent string, m guardMode) string {
	q := pwshQuote(bin)
	if m != guarded {
		return "& " + q + hookMarker + agent
	}
	return pwshGuardHead + q + pwshGuardMid + q + hookMarker + agent + pwshGuardTail
}

// bareCommand is the unquoted form, valid in cmd.exe and PowerShell alike.
// Only usable when plainWindowsPath(bin) holds.
func bareCommand(bin, agent string) string {
	return bin + hookMarker + agent
}

// windowsCommand is the command line for a Windows field whose shell is
// PowerShell by default but may be cmd.exe (Codex commandWindows, Cursor).
// A path that needs no quoting is written bare, which both shells run.
// That form has no missing-binary guard: the guard needs `if`, and no
// single line found here is valid in cmd.exe, Windows PowerShell 5.1 and
// PowerShell 7 alike (5.1 has no && or ||, and both parsers reject the
// other's `if`). Run by PowerShell it also exits 1 where spoor exited 2
// (see pwshCommand), which only matters for Codex, the one agent whose
// block is an exit code. Any other path gets the PowerShell form (a path
// with spaces cannot be written so that both shells accept it).
func windowsCommand(bin, agent string, m guardMode) string {
	if plainWindowsPath(bin) {
		return bareCommand(bin, agent)
	}
	return pwshCommand(bin, agent, m)
}

// plainWindowsPath reports whether a Windows path can be written without
// quotes in both cmd.exe and PowerShell: letters, digits and the few
// punctuation characters neither shell gives a meaning to.
func plainWindowsPath(p string) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '\\' || c == ':' || c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// validAgentID keeps the agent id safe to place unquoted in a command line.
// Catalog ids already match this; an overlay could carry anything.
func validAgentID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// foreignSensors are other endpoint sensors that install their own hook
// handler. Two handlers on the same event double the latency a developer
// pays per tool call and, in guard mode, give two answers to one question.
//
// Sources: numbat generates "<binary> hook <event> --agent <agent> ..." and
// drop-ins named numbat.json (perplexityai/numbat internal/hook/install.go,
// read 2026-11-11); Snyk Agent Guard is recognised the way its own installer
// does, by "snyk-agent-guard" in the command (snyk/agent-scan guard.py);
// Agent Beacon ships a hook binary called beacon-hooks
// (asymptote-labs/agent-beacon cli/beacon-hooks).
// UNVERIFIED: the exact command line Agent Beacon registers.
var foreignSensors = []struct {
	name  string
	match func(base string) bool
}{
	{"numbat", func(b string) bool { return b == "numbat" }},
	{"agent-beacon", func(b string) bool { return b == "beacon-hooks" || b == "beacon" || b == "agent-beacon" }},
	{"snyk-agent-guard", func(b string) bool { return strings.HasPrefix(b, "snyk-agent-guard") }},
}

// sensorIn names the foreign sensor a command line launches, or "". It looks
// at the file name of every word (the program and any script it is given),
// not at the whole text: a spoor binary under /home/numbat/ is still spoor.
func sensorIn(line string) string {
	if len(line) > maxCommandLen {
		line = line[:maxCommandLen]
	}
	for _, w := range strings.Fields(line) {
		w = strings.Trim(w, `'"`)
		if i := strings.LastIndexAny(w, `/\`); i >= 0 {
			w = w[i+1:]
		}
		w = strings.ToLower(w)
		if i := strings.IndexByte(w, '.'); i > 0 {
			w = w[:i]
		}
		if w == "" {
			continue
		}
		for _, s := range foreignSensors {
			if s.match(w) {
				return s.name
			}
		}
	}
	return ""
}

// maxCommandLen bounds how much of a hook command from somebody else's file
// is examined.
const maxCommandLen = 8 << 10

// classify decides whose handler a set of command lines belongs to. numbat's
// own command also has "hook" and "--agent" in it (with the event name in
// between), so a sensor match wins over the spoor marker.
func classify(lines []string) (spoor bool, sensor string) {
	for _, l := range lines {
		if s := sensorIn(l); s != "" {
			return false, s
		}
	}
	for _, l := range lines {
		if strings.Contains(l, hookMarker) {
			return true, ""
		}
	}
	return false, ""
}

// binaryOf extracts the executable path from a spoor command line in any of
// the forms this package writes or wrote before: exec form (path, then
// arguments), POSIX single quotes with or without the guard and exec,
// PowerShell call operator with or without the Test-Path guard, or bare.
// In the guarded forms the checked path and the run path must be the same.
// It returns "" when the line has another shape.
func binaryOf(line string) string {
	i := strings.Index(line, hookMarker)
	if i < 0 {
		return ""
	}
	exe := strings.TrimSpace(line[:i])
	switch {
	case strings.HasPrefix(exe, posixGuardHead):
		checked, rest, ok := cutPosixQuoted(exe[len(posixGuardHead):])
		if !ok || !strings.HasPrefix(rest, posixGuardTail+posixExec) {
			return ""
		}
		run, rest, ok := cutPosixQuoted(rest[len(posixGuardTail+posixExec):])
		if !ok || rest != "" || run != checked {
			return ""
		}
		return run
	case strings.HasPrefix(exe, pwshGuardHead):
		checked, rest, ok := cutPwshQuoted(exe[len(pwshGuardHead):])
		if !ok || !strings.HasPrefix(rest, pwshGuardMid) {
			return ""
		}
		run, rest, ok := cutPwshQuoted(rest[len(pwshGuardMid):])
		if !ok || rest != "" || run != checked {
			return ""
		}
		return run
	case strings.HasPrefix(exe, "& "):
		run, rest, ok := cutPwshQuoted(strings.TrimSpace(exe[2:]))
		if !ok || rest != "" {
			return ""
		}
		return run
	case strings.HasPrefix(exe, posixExec+"'"):
		run, rest, ok := cutPosixQuoted(exe[len(posixExec):])
		if !ok || rest != "" {
			return ""
		}
		return run
	case strings.HasPrefix(exe, "'"):
		run, rest, ok := cutPosixQuoted(exe)
		if !ok || rest != "" {
			return ""
		}
		return run
	}
	return exe
}

// cutPosixQuoted reads one word written by posixQuote at the start of s:
// single-quoted runs, where an apostrophe in the value is written as a
// closing quote, a backslash-escaped apostrophe and an opening quote.
func cutPosixQuoted(s string) (val, rest string, ok bool) {
	if !strings.HasPrefix(s, "'") {
		return "", s, false
	}
	var b strings.Builder
	for {
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return "", s, false
		}
		b.WriteString(s[1 : 1+end])
		s = s[end+2:]
		if !strings.HasPrefix(s, `\''`) {
			return b.String(), s, true
		}
		b.WriteByte('\'')
		s = s[2:]
	}
}

// cutPwshQuoted reads one PowerShell verbatim string written by pwshQuote
// at the start of s: any single-quote character doubled stands for itself,
// any other one ends the string.
func cutPwshQuoted(s string) (val, rest string, ok bool) {
	if !strings.HasPrefix(s, "'") {
		return "", s, false
	}
	var b strings.Builder
	for i := 1; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if !isPwshQuote(r) {
			// Copy bytes, not runes: an invalid byte must not turn into
			// U+FFFD and name another file.
			b.WriteString(s[i : i+n])
			i += n
			continue
		}
		if r2, n2 := utf8.DecodeRuneInString(s[i+n:]); r2 == r && n2 > 0 {
			b.WriteString(s[i : i+n])
			i += n + n2
			continue
		}
		return b.String(), s[i+n:], true
	}
	return "", s, false
}

func isPwshQuote(r rune) bool {
	switch r {
	case '\'', '‘', '’', '‚', '‛':
		return true
	}
	return false
}
