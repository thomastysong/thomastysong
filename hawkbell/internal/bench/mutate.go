package bench

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Operator is a semantics-preserving rewrite of an attack's shell
// commands. Robust recall asks whether a rule still fires after each one;
// it is the question a static rule set has to answer, because every
// operator here is a documented approval-parser bypass or an obvious
// variation an agent produces unprompted (research/threats.md rows 9, 23,
// 24; redteam/detection-quality.md section 7).
type Operator struct {
	Name string
	Doc  string
	// rewrite returns the rewritten command, or ok=false when the operator
	// does not apply to it (it would change what the command does).
	rewrite func(cmd string, n int) (string, bool)
	// split replaces the event pair carrying the command instead of
	// rewriting it in place.
	split bool
}

var operators = []*Operator{
	{Name: "quoting", Doc: "empty quotes inside every command name (c''url)", rewrite: mutQuote},
	{Name: "ifs", Doc: "argument separators replaced by ${IFS}", rewrite: mutIFS},
	{Name: "wrapper", Doc: "the whole command run through sh -c", rewrite: mutWrapper},
	{Name: "var_assembly", Doc: "command names assembled from shell variables", rewrite: mutVars},
	{Name: "interpreter", Doc: "the command run from a Python one-liner (subprocess, shell=True)", rewrite: mutInterpreter},
	{Name: "split", Doc: "the command written to a script by a file tool, then run in a second event", split: true},
}

// Operators returns the mutation operators in report order.
func Operators() []*Operator { return append([]*Operator(nil), operators...) }

// OperatorNames lists the operator names.
func OperatorNames() []string {
	out := make([]string, 0, len(operators))
	for _, o := range operators {
		out = append(out, o.Name)
	}
	return out
}

func operatorByName(name string) *Operator {
	for _, o := range operators {
		if o.Name == name {
			return o
		}
	}
	return nil
}

// selectedOperators resolves a scenario's mutations list.
func selectedOperators(names []string) []*Operator {
	if len(names) == 0 {
		return Operators()
	}
	var out []*Operator
	for _, n := range names {
		switch n {
		case "none":
			return nil
		case "all":
			return Operators()
		}
		if o := operatorByName(n); o != nil {
			out = append(out, o)
		}
	}
	return out
}

// mutateSequence applies op to every shell command of evs. It reports
// false when no event carried a command the operator applies to, so the
// mutation is excluded from robust recall instead of counted as a pass.
func mutateSequence(op *Operator, evs []built) ([]built, bool) {
	applied := false
	if op.split {
		var out []built
		n := 0
		// Tool pre/post pairs share a use id; both are replaced by the
		// script write and its execution.
		done := map[string]string{}
		for _, b := range evs {
			cmd := shellCommand(b.ev)
			if cmd == "" {
				out = append(out, b)
				continue
			}
			key := cmd
			if b.ev.Tool != nil && b.ev.Tool.UseID != "" {
				key = b.ev.Tool.UseID
			}
			script, seen := done[key]
			if !seen {
				n++
				script = fmt.Sprintf("/tmp/.agent-work/step%d.sh", n)
				done[key] = script
			}
			if b.ev.Type == event.TypeToolPre || !seen {
				out = append(out, writeEvent(b, script, cmd, n))
			}
			out = append(out, runEvent(b, script))
			applied = true
		}
		return renumber(out), applied
	}
	out := make([]built, 0, len(evs))
	for i, b := range evs {
		cmd := shellCommand(b.ev)
		if cmd == "" {
			out = append(out, b)
			continue
		}
		nc, ok := op.rewrite(cmd, i)
		if !ok || nc == cmd {
			out = append(out, b)
			continue
		}
		out = append(out, withCommand(b, nc))
		applied = true
	}
	return out, applied
}

// shellCommand returns the POSIX command line a shell tool event carries.
// The operators are POSIX shell rewrites: on a PowerShell or cmd.exe
// command (or any command on a Windows host) they would change what runs,
// so those commands count as not applicable.
func shellCommand(ev *event.Event) string {
	if ev == nil || ev.Tool == nil || ev.Tool.Kind != event.ToolShell || ev.Target == nil {
		return ""
	}
	if ev.Host != nil && strings.EqualFold(ev.Host.OS, "windows") {
		return ""
	}
	switch strings.ToLower(ev.Tool.Name) {
	case "powershell", "pwsh", "cmd":
		return ""
	}
	return ev.Target.Command
}

func withCommand(b built, cmd string) built {
	ev := b.ev.Clone()
	t := *ev.Target
	t.Command = cmd
	ev.Target = &t
	if b.ev.Content != nil {
		c := *b.ev.Content
		if c.ToolInput != nil {
			in := make(map[string]any, len(c.ToolInput))
			for k, v := range c.ToolInput {
				in[k] = v
			}
			if _, ok := in["command"]; ok {
				in["command"] = cmd
			}
			c.ToolInput = in
		}
		ev.Content = &c
	}
	ev.Feat = nil
	return built{ev: ev, feat: b.feat, surfaces: b.surfaces}
}

func writeEvent(b built, script, cmd string, n int) built {
	ev := b.ev.Clone()
	ev.Type = event.TypeToolPre
	ev.Tool = &event.Tool{Name: "Write", Kind: event.ToolFileWrite, UseID: "bench-split-write-" + strconv.Itoa(n)}
	ev.Target = &event.Target{Path: script}
	ev.Content = &event.Content{
		ToolInput:   map[string]any{"file_path": script, "content": "#!/bin/sh\n" + cmd + "\n"},
		FileContent: "#!/bin/sh\n" + cmd + "\n",
	}
	ev.Outcome = nil
	ev.Feat = nil
	return built{ev: ev, surfaces: b.surfaces}
}

func runEvent(b built, script string) built {
	return withCommand(b, "sh "+script)
}

// renumber gives a rewritten sequence fresh ids and one-second spacing.
func renumber(evs []built) []built {
	for i := range evs {
		evs[i].ev.ID = fmt.Sprintf("bench-event-%d", i+1)
		evs[i].ev.TS = event.At(scenarioEpoch.Add(secondsDur(i)))
	}
	return evs
}

// --- operators on POSIX command lines ---

// tok is a lexical token of a command line: a word (with its quoting
// intact) or an operator, with the whitespace that preceded it.
type tok struct {
	text   string
	pre    string
	op     bool // control operator: | || & && ; ;; ( ) and newlines
	redir  bool // redirection operator: < > >> <& >& <> >| 2> &>
	assign bool // NAME=value word
}

// lexPOSIX splits a command line into tokens. It understands quotes,
// backslash escapes and $(...) / `...` nesting well enough to find
// command-name positions; it refuses heredocs and anything it cannot
// close, because rewriting those risks changing what the command does.
func lexPOSIX(s string) ([]tok, bool) {
	if strings.Contains(s, "<<") {
		return nil, false
	}
	var out []tok
	i := 0
	pre := ""
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' {
			pre += string(c)
			i++
			continue
		}
		if c == '\n' {
			out = append(out, tok{text: "\n", pre: pre, op: true})
			pre = ""
			i++
			continue
		}
		if c == '#' {
			return nil, false
		}
		if op := ctlOp(s[i:]); op != "" {
			out = append(out, tok{text: op, pre: pre, op: true})
			pre = ""
			i += len(op)
			continue
		}
		if r := redirOp(s[i:]); r != "" {
			out = append(out, tok{text: r, pre: pre, redir: true})
			pre = ""
			i += len(r)
			continue
		}
		j, ok := wordEnd(s, i)
		if !ok {
			return nil, false
		}
		w := s[i:j]
		out = append(out, tok{text: w, pre: pre, assign: isAssign(w)})
		pre = ""
		i = j
	}
	return out, len(out) > 0
}

func ctlOp(s string) string {
	for _, op := range []string{"&&", "||", ";;", "|&", "|", ";", "&", "(", ")"} {
		if strings.HasPrefix(s, op) {
			if op == "&" && strings.HasPrefix(s, "&>") {
				return ""
			}
			return op
		}
	}
	return ""
}

func redirOp(s string) string {
	// Optional fd number before the operator.
	k := 0
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		k++
	}
	rest := s[k:]
	for _, op := range []string{"&>>", "&>", ">>", ">&", "<&", "<>", ">|", ">", "<"} {
		if strings.HasPrefix(rest, op) {
			if k > 0 || op[0] == '&' || op[0] == '>' || op[0] == '<' {
				return s[:k+len(op)]
			}
		}
	}
	return ""
}

// wordEnd returns the end of the word starting at i.
func wordEnd(s string, i int) (int, bool) {
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			return i, true
		case c == '\\':
			i += 2
		case c == '\'':
			k := strings.IndexByte(s[i+1:], '\'')
			if k < 0 {
				return 0, false
			}
			i += k + 2
		case c == '"':
			j, ok := closeDouble(s, i+1)
			if !ok {
				return 0, false
			}
			i = j
		case c == '`':
			k := strings.IndexByte(s[i+1:], '`')
			if k < 0 {
				return 0, false
			}
			i += k + 2
		case c == '$' && i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{'):
			j, ok := closeParen(s, i+1)
			if !ok {
				return 0, false
			}
			i = j
		case c == '<' || c == '>':
			if i+1 < len(s) && s[i+1] == '(' {
				j, ok := closeParen(s, i+1)
				if !ok {
					return 0, false
				}
				i = j
				continue
			}
			return i, true
		case ctlOp(s[i:]) != "":
			return i, true
		default:
			i++
		}
	}
	if i > len(s) {
		return 0, false
	}
	return i, true
}

func closeDouble(s string, i int) (int, bool) {
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, true
		case '$':
			if i+1 < len(s) && (s[i+1] == '(' || s[i+1] == '{') {
				j, ok := closeParen(s, i+1)
				if !ok {
					return 0, false
				}
				i = j
				continue
			}
			i++
		default:
			i++
		}
	}
	return 0, false
}

// closeParen returns the index after the bracket matching s[i] ('(' or '{').
func closeParen(s string, i int) (int, bool) {
	open := s[i]
	closeCh := byte(')')
	if open == '{' {
		closeCh = '}'
	}
	depth := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\'' && open == '(':
			k := strings.IndexByte(s[i+1:], '\'')
			if k < 0 {
				return 0, false
			}
			i += k + 2
			continue
		case c == '"':
			j, ok := closeDouble(s, i+1)
			if !ok {
				return 0, false
			}
			i = j
			continue
		case c == open:
			depth++
		case c == closeCh:
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
		i++
	}
	return 0, false
}

func isAssign(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// plainName reports whether a word is an unquoted command name that can be
// rewritten without changing its meaning.
func plainName(w string) bool {
	if len(w) < 2 || len(w) > 64 {
		return false
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/') {
			return false
		}
	}
	switch w {
	case "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "function", "select", "time", "!":
		return false
	}
	return true
}

// commandNames returns the indexes of tokens in command-name position.
func commandNames(toks []tok) []int {
	var out []int
	start := true
	skipNext := false
	for i, t := range toks {
		switch {
		case t.op:
			start = t.text != ")"
		case t.redir:
			skipNext = true
		case skipNext:
			skipNext = false
		case start && t.assign:
		case start:
			if plainName(t.text) {
				out = append(out, i)
			}
			start = false
		}
	}
	return out
}

func join(toks []tok) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(t.pre)
		b.WriteString(t.text)
	}
	return b.String()
}

func mutQuote(cmd string, _ int) (string, bool) {
	toks, ok := lexPOSIX(cmd)
	if !ok {
		return "", false
	}
	idx := commandNames(toks)
	if len(idx) == 0 {
		return "", false
	}
	for _, i := range idx {
		w := toks[i].text
		cut := 1
		if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "./") {
			cut = strings.LastIndexByte(w, '/') + 2
			if cut >= len(w) {
				continue
			}
		}
		toks[i].text = w[:cut] + "''" + w[cut:]
	}
	return join(toks), true
}

func mutIFS(cmd string, _ int) (string, bool) {
	toks, ok := lexPOSIX(cmd)
	if !ok {
		return "", false
	}
	kw, ok := ifsKeywords(toks)
	if !ok {
		return "", false
	}
	changed := false
	for i := 1; i < len(toks); i++ {
		prev, cur := toks[i-1], toks[i]
		// Only separators between two words of one command, never after
		// an assignment (it would swallow the command into the value) or
		// around a redirection (an expansion that splits there is an
		// "ambiguous redirect").
		if prev.op || prev.redir || prev.assign || cur.op || cur.redir || cur.pre != " " {
			continue
		}
		if i >= 2 && toks[i-2].redir {
			continue
		}
		if kw[i-1] || kw[i] {
			continue
		}
		toks[i].pre = "${IFS}"
		changed = true
	}
	if !changed {
		return "", false
	}
	return join(toks), true
}

// ifsKeywords marks the tokens a ${IFS} must not touch. A reserved word is
// recognised only as a whole unquoted word in command position, so
// "for${IFS}b" is a call to a command named "for b" and the loop around
// it no longer parses; the header of a for or select loop is kept intact
// for the same reason. It refuses (ok=false) constructs whose words are
// never field-split, so ${IFS} cannot stand in for a blank there: [[ ]],
// arithmetic (( )), case patterns and function definitions.
func ifsKeywords(toks []tok) ([]bool, bool) {
	kw := make([]bool, len(toks))
	start := true     // the next word is in command position
	header := false   // inside "for NAME in WORDS" or "select ..."
	skipNext := false // the word after a redirection operator
	for i, t := range toks {
		next := ""
		if i+1 < len(toks) && toks[i+1].op {
			next = toks[i+1].text
		}
		switch {
		case t.op:
			if t.text == "(" && (next == "(" || next == ")") {
				return nil, false
			}
			start = t.text != ")"
			header = false
			continue
		case t.redir:
			skipNext = true
			continue
		case skipNext:
			skipNext = false
			continue
		case header:
			kw[i] = true
			continue
		case !start, t.assign:
			continue
		}
		switch t.text {
		case "[[", "]]", "((", "case", "esac", "function", "coproc":
			return nil, false
		case "for", "select":
			kw[i], header, start = true, true, false
		case "if", "then", "else", "elif", "while", "until", "do", "!", "time", "{":
			kw[i] = true // a command follows
		case "fi", "done", "}":
			kw[i], start = true, false
		default:
			start = false
		}
	}
	return kw, true
}

func mutWrapper(cmd string, _ int) (string, bool) {
	if strings.TrimSpace(cmd) == "" {
		return "", false
	}
	return "sh -c " + shQuote(cmd), true
}

func mutVars(cmd string, _ int) (string, bool) {
	toks, ok := lexPOSIX(cmd)
	if !ok {
		return "", false
	}
	idx := commandNames(toks)
	if len(idx) == 0 {
		return "", false
	}
	var assigns []string
	for n, i := range idx {
		w := toks[i].text
		if strings.Contains(w, "/") {
			continue
		}
		h := len(w) / 2
		a, b := fmt.Sprintf("p%d", n), fmt.Sprintf("q%d", n)
		assigns = append(assigns, a+"="+w[:h], b+"="+w[h:])
		toks[i].text = `"$` + a + `$` + b + `"`
	}
	if len(assigns) == 0 {
		return "", false
	}
	return strings.Join(assigns, " ") + "; " + join(toks), true
}

func mutInterpreter(cmd string, _ int) (string, bool) {
	if strings.TrimSpace(cmd) == "" {
		return "", false
	}
	py := "import subprocess; subprocess.run(" + strconv.Quote(cmd) + ", shell=True)"
	return "python3 -c " + shQuote(py), true
}

// shQuote single-quotes s for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
