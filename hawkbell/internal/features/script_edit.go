package features

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Patches and edits. An edit tool sends the text it inserts, not the file:
// "| cat" replaced by "| sh" is harmless on its own and a download piped
// into a shell in the line it lands in. When the caller holds the file's
// text from an earlier write (WrittenScript.Keep), the edit is applied to
// it the way the tool applies it and the whole result is analysed. When it
// does not (the text was too long or held a credential, or was written in
// another session), or the edit does not apply to the held text (the file
// changed outside the agent's file tools), the new text is analysed on its
// own and the facts are marked as a fragment.

// patchKeys are the tool-input fields an apply_patch envelope travels in:
// the tool's own "input" (and "patch" / "diff" in other clients), and
// {"command": <patch>} as Codex hands it to hooks ("_raw" when the
// arguments arrived as a plain string).
var patchKeys = []string{"input", "patch", "diff", "command", "_raw"}

// patchText returns the apply_patch envelope a file-edit event carries,
// or "". Only a patch tool's input fields count, and only text that starts
// with the envelope's first line: the content of a write or the new text
// of an edit that merely mentions the marker is that file's content, not
// a patch.
func patchText(e *event.Event) string {
	if e.Content == nil {
		return ""
	}
	for _, k := range patchKeys {
		if s, ok := e.Content.ToolInput[k].(string); ok && isPatch(s) {
			return s
		}
	}
	if e.Tool != nil && strings.EqualFold(e.Tool.Name, "apply_patch") && isPatch(e.Content.FileContent) {
		return e.Content.FileContent
	}
	return ""
}

// isPatch reports text whose first line is "*** Begin Patch", which the
// apply_patch tool requires.
func isPatch(s string) bool {
	return strings.HasPrefix(strings.TrimLeft(cutHead(s, 4096), " \t\r\n"), "*** Begin Patch")
}

// patchFile is one file of an apply_patch envelope.
type patchFile struct {
	path, from  string
	add, remove bool
	text        string // added lines without their "+"
	hunks       []patchHunk
	bad         bool // a hunk line could not be read: the hunks do not apply
}

// patchHunk is one change of an Update File section: the lines it expects
// (context and removed lines), the lines it leaves (context and added
// lines), the @@ line it is anchored after, and whether it is anchored at
// the end of the file.
type patchHunk struct {
	header   string
	old, new []string
	eof      bool
}

// parsePatch splits an apply_patch envelope ("*** Add File: p" followed
// by "+" lines, "*** Update File: p" with an optional "*** Move to: q" and
// hunks, "*** Delete File: p") into the content each file gains and, for
// an update, its hunks.
func parsePatch(patch string) []patchFile {
	if len(patch) > maxPatchText {
		patch = cutHead(patch, maxPatchText)
	}
	var out []patchFile
	var cur *patchFile
	var hunk *patchHunk
	var b strings.Builder
	flush := func() {
		if cur != nil {
			cur.text = b.String()
			out = append(out, *cur)
		}
		cur, hunk = nil, nil
		b.Reset()
	}
	newHunk := func(header string) {
		if len(cur.hunks) >= maxPatchHunks {
			cur.bad = true
			hunk = nil
			return
		}
		cur.hunks = append(cur.hunks, patchHunk{header: header})
		hunk = &cur.hunks[len(cur.hunks)-1]
	}
	for len(patch) > 0 {
		line := patch
		if i := strings.IndexByte(patch, '\n'); i >= 0 {
			line, patch = patch[:i], patch[i+1:]
		} else {
			patch = ""
		}
		line = strings.TrimSuffix(line, "\r")
		if rest, ok := strings.CutPrefix(line, "*** "); ok {
			switch {
			case strings.HasPrefix(rest, "Add File: "), strings.HasPrefix(rest, "Update File: "), strings.HasPrefix(rest, "Delete File: "):
				flush()
				if len(out) >= maxPatchFiles {
					return out
				}
				verb, p, _ := strings.Cut(rest, ": ")
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				cur = &patchFile{path: p, add: verb == "Add File", remove: verb == "Delete File"}
				continue
			case strings.HasPrefix(rest, "Move to: "):
				if cur != nil && !cur.remove {
					to := strings.TrimSpace(strings.TrimPrefix(rest, "Move to: "))
					if to != "" {
						cur.from, cur.path = cur.path, to
					}
				}
				continue
			case rest == "End of File":
				if hunk != nil {
					hunk.eof = true
				}
				continue
			case rest == "Begin Patch", rest == "End Patch":
				continue
			}
		}
		if cur == nil || cur.remove {
			continue
		}
		if cur.add {
			if added, ok := strings.CutPrefix(line, "+"); ok && b.Len() < maxPatchText {
				b.WriteString(added)
				b.WriteByte('\n')
			}
			continue
		}
		if h, ok := strings.CutPrefix(line, "@@"); ok {
			newHunk(strings.TrimSpace(h))
			continue
		}
		if hunk == nil && !cur.bad {
			newHunk("") // the first hunk may come without an @@ line
		}
		var op byte
		body := ""
		if line != "" {
			op, body = line[0], line[1:]
		} else {
			op = ' ' // an empty line in a hunk is an empty context line
		}
		switch op {
		case '+':
			if b.Len() < maxPatchText {
				b.WriteString(body)
				b.WriteByte('\n')
			}
			if hunk != nil {
				hunk.new = append(hunk.new, body)
			}
		case '-':
			if hunk != nil {
				hunk.old = append(hunk.old, body)
			}
		case ' ':
			if hunk != nil {
				hunk.old = append(hunk.old, body)
				hunk.new = append(hunk.new, body)
			}
		default:
			cur.bad = true
		}
	}
	flush()
	return out
}

// applyHunks applies an update's hunks to text as apply_patch does: each
// hunk's expected lines are found after the previous hunk (after its @@
// line when it names one; at the end for an end-of-file hunk), compared
// exactly, then ignoring trailing and then surrounding white space, and
// replaced; a hunk that expects nothing appends. It reports false when a
// hunk does not apply.
func applyHunks(text string, hunks []patchHunk, b *budget) (string, bool) {
	lines := strings.Split(text, "\n")
	// The final newline leaves an empty last element; the result ends
	// with one again.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	pos := 0
	for _, h := range hunks {
		if h.header != "" {
			i := seekLines(lines, []string{h.header}, pos, false, b)
			if i < 0 {
				return "", false
			}
			pos = i + 1
		}
		if len(h.old) == 0 {
			lines = append(lines, h.new...)
			pos = len(lines)
			continue
		}
		i := seekLines(lines, h.old, pos, h.eof, b)
		if i < 0 {
			return "", false
		}
		rest := append(append([]string(nil), h.new...), lines[i+len(h.old):]...)
		lines = append(lines[:i], rest...)
		pos = i + len(h.new)
	}
	out := strings.Join(lines, "\n")
	if len(lines) > 0 {
		out += "\n"
	}
	return out, true
}

// seekLines returns the first index at or after from where want occurs in
// lines (for eof, only at the end), trying exact, right-trimmed and trimmed
// comparison in that order, or -1. Comparisons are charged to b.
func seekLines(lines, want []string, from int, eof bool, b *budget) int {
	if len(want) > len(lines) {
		return -1
	}
	for _, cmp := range []func(a, b string) bool{
		func(a, b string) bool { return a == b },
		func(a, b string) bool { return strings.TrimRight(a, " \t") == strings.TrimRight(b, " \t") },
		func(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) },
	} {
		start, end := from, len(lines)-len(want)
		if eof {
			start = end
		}
		for i := start; i <= end; i++ {
			ok := true
			for j := range want {
				b.work--
				if b.work < 0 {
					return -1
				}
				if !cmp(lines[i+j], want[j]) {
					ok = false
					break
				}
			}
			if ok {
				return i
			}
		}
	}
	return -1
}

// applyEdits applies the replacements of an edit tool's input to text the
// way the tools do (Claude Code Edit and MultiEdit, Gemini replace,
// Copilot str_replace and insert): the old text must occur exactly once,
// or as often as expected_replacements says, or at least once with
// replace_all. It reports false when the input is not such an edit or one
// of its replacements does not apply.
func applyEdits(text string, in map[string]any) (string, bool) {
	if len(in) == 0 {
		return "", false
	}
	if edits, ok := in["edits"].([]any); ok {
		if len(edits) == 0 || len(edits) > 256 {
			return "", false
		}
		for _, ed := range edits {
			m, ok := ed.(map[string]any)
			if !ok {
				return "", false
			}
			if text, ok = replaceOnce(text, m); !ok {
				return "", false
			}
		}
		return text, true
	}
	if cmd, _ := in["command"].(string); cmd == "insert" {
		ins, ok1 := in["new_str"].(string)
		at, ok2 := in["insert_line"].(float64)
		if !ok1 || !ok2 || at < 0 || at != float64(int(at)) {
			return "", false
		}
		lines := strings.SplitAfter(text, "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		n := int(at)
		if n > len(lines) {
			return "", false
		}
		if !strings.HasSuffix(ins, "\n") {
			ins += "\n"
		}
		if n > 0 && !strings.HasSuffix(lines[n-1], "\n") {
			lines[n-1] += "\n"
		}
		return strings.Join(lines[:n], "") + ins + strings.Join(lines[n:], ""), true
	}
	return replaceOnce(text, in)
}

// replaceOnce applies one old/new replacement.
func replaceOnce(text string, m map[string]any) (string, bool) {
	var old, repl string
	found := false
	for _, k := range [][2]string{{"old_string", "new_string"}, {"old_str", "new_str"}, {"oldText", "newText"}} {
		o, ok1 := m[k[0]].(string)
		n, ok2 := m[k[1]].(string)
		if ok1 && ok2 {
			old, repl, found = o, n, true
			break
		}
	}
	if !found || old == "" {
		return "", false
	}
	count := strings.Count(text, old)
	all, _ := m["replace_all"].(bool)
	want, hasWant := m["expected_replacements"].(float64)
	switch {
	case count == 0:
		return "", false
	case all:
		return strings.ReplaceAll(text, old, repl), true
	case hasWant && want >= 1:
		if float64(count) != want {
			return "", false
		}
		return strings.ReplaceAll(text, old, repl), true
	case count != 1:
		return "", false
	}
	return strings.Replace(text, old, repl, 1), true
}

// Redaction of script facts. Credentials are replaced by
// "[REDACTED:<kind>]": the marker form without a fingerprint, so nothing
// held can be compared against a guessed value. Rules need only the kinds
// (shell.secret_kinds).

// redactArgs returns a command's arguments with credentials replaced, the
// way the evidence stage redacts a command line (structural rules for
// secret-named flags, headers, NAME=value and URL credentials, then every
// pattern classify knows); name is the program, which program-specific
// rules key on.
func redactArgs(name string, args []string) []string {
	red := classify.RedactArgs(append([]string{name}, args...))
	if len(red) != len(args)+1 {
		out := make([]string, len(args))
		for i := range out {
			out[i] = "[REDACTED:" + markerFailure + "]"
		}
		return out
	}
	red = red[1:]
	for i := range red {
		red[i] = unkeyMarkers(red[i])
	}
	return red
}

// markerFailure is the marker kind classify writes when redaction itself
// failed.
const markerFailure = "error"

// redactValue redacts one list value like a lone argument.
func redactValue(v string) string {
	red := classify.RedactArgs([]string{v})
	if len(red) != 1 {
		return "[REDACTED:" + markerFailure + "]"
	}
	return unkeyMarkers(red[0])
}

const markerOpen = "[REDACTED:"

// unkeyMarkers rewrites "[REDACTED:<kind>:<fp>]" and
// "[REDACTED:<kind>:hmac=<fp>]" to "[REDACTED:<kind>]".
func unkeyMarkers(s string) string {
	if !strings.Contains(s, markerOpen) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, markerOpen)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i+len(markerOpen)])
		s = s[i+len(markerOpen):]
		k := 0
		for k < len(s) && k < 64 && (s[k] >= 'a' && s[k] <= 'z' || s[k] >= '0' && s[k] <= '9' || s[k] == '_') {
			k++
		}
		rest := s[k:]
		if k == 0 || !strings.HasPrefix(rest, ":") {
			continue
		}
		fp := strings.TrimPrefix(rest[1:], "hmac=")
		if len(fp) >= 9 && isLowerHex(fp[:8]) && fp[8] == ']' {
			b.WriteString(s[:k])
			b.WriteByte(']')
			s = fp[9:]
		}
	}
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
