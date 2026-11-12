package hookinstall

import (
	"strings"
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
		switch r {
		case '\'', '‘', '’', '‚', '‛':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// posixCommand is the hook command line for a POSIX shell.
func posixCommand(bin, agent string) string {
	return posixQuote(bin) + hookMarker + agent
}

// pwshCommand is the hook command line for PowerShell. A quoted path is a
// string expression there, not a command: it needs the call operator.
func pwshCommand(bin, agent string) string {
	return "& " + pwshQuote(bin) + hookMarker + agent
}

// bareCommand is the unquoted form, valid in cmd.exe and PowerShell alike.
// Only usable when plainWindowsPath(bin) holds.
func bareCommand(bin, agent string) string {
	return bin + hookMarker + agent
}

// windowsCommand is the command line for a Windows field whose shell is
// PowerShell by default but may be cmd.exe: bare when the path allows it,
// else the PowerShell call form (a path with spaces cannot be written so
// that both shells accept it; the package doc recommends a path without
// spaces for that reason).
func windowsCommand(bin, agent string) string {
	if plainWindowsPath(bin) {
		return bareCommand(bin, agent)
	}
	return pwshCommand(bin, agent)
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
// the forms this package writes: exec form (path, then arguments), POSIX
// single quotes, PowerShell call operator, or bare. It returns "" when the
// line has another shape.
func binaryOf(line string) string {
	i := strings.Index(line, hookMarker)
	if i < 0 {
		return ""
	}
	exe := strings.TrimSpace(line[:i])
	if strings.HasPrefix(exe, "& ") {
		q := strings.TrimSpace(exe[2:])
		if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
			return ""
		}
		return unquoteDoubled(q[1 : len(q)-1])
	}
	if len(exe) >= 2 && exe[0] == '\'' && exe[len(exe)-1] == '\'' {
		return strings.ReplaceAll(exe[1:len(exe)-1], `'\''`, "'")
	}
	return exe
}

func unquoteDoubled(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		b.WriteRune(rs[i])
		switch rs[i] {
		case '\'', '‘', '’', '‚', '‛':
			if i+1 < len(rs) && rs[i+1] == rs[i] {
				i++
			}
		}
	}
	return b.String()
}
