package shellx

import (
	"strings"
)

// The tokenizer front ends (POSIX fallback, PowerShell, cmd.exe) lex a
// command line into pipelines of lexCmd and hand them to runPipes, which
// lowers each command to a simple so the semantic layer is shared with the
// bash AST walker. Every front end is iterative: nesting is handled by
// re-analysing captured text one level down through analyzer.sub, which is
// capped by MaxDepth and maxSubAnalyses, so hostile input cannot grow the
// Go stack.

type lexRedir struct {
	op     string // ">", ">>", "<", "2>", "2>>"
	target arg
}

type lexCmd struct {
	words  []arg
	env    []envKV
	redirs []lexRedir
	bg     bool
	stdin  *string
	stdinT taint
	// expr is set for a PowerShell expression statement such as
	// (New-Object Net.WebClient).DownloadString('u'): it is not a command,
	// but its value flows on to the next pipeline stage.
	expr  bool
	exprT taint
}

func (c *lexCmd) empty() bool {
	return len(c.words) == 0 && len(c.env) == 0 && len(c.redirs) == 0 && !c.expr && c.stdin == nil
}

type lexPipe struct {
	cmds []*lexCmd
}

// runPipes analyses lexed statements. It mirrors walker.stmts and
// walker.pipeline.
func (a *analyzer) runPipes(pipes []lexPipe, origin string, depth int, d Dialect, in flow) flow {
	out := noFlow()
	for pi, p := range pipes {
		fl := in
		first := -1
		var reps []int
		for _, c := range p.cmds {
			before := len(a.f.Commands)
			o := a.runLex(c, fl, origin, depth, d)
			rep := o.rep
			if rep < 0 && len(a.f.Commands) > before {
				rep = before
			}
			if rep >= 0 {
				reps = append(reps, rep)
				if first < 0 {
					first = rep
				}
			}
			o.piped = true
			fl = o
			if a.work < 0 {
				break
			}
		}
		if len(reps) >= 2 && len(a.f.Pipelines) < maxList {
			a.f.Pipelines = append(a.f.Pipelines, reps)
		}
		fl.piped = false
		fl.rep = first
		if pi == 0 {
			out.rep = fl.rep
		}
		out.t |= fl.t
		if fl.static != nil && fl.t&tPayload != 0 {
			a.sinkDecoded(*fl.static, depth)
		}
		if a.work < 0 {
			break
		}
	}
	return out
}

// varKey namespaces variables per dialect: bash is case-sensitive, PowerShell
// and cmd are not, and the three must not see each other's assignments.
func varKey(d Dialect, name string) string {
	switch d {
	case PowerShell:
		return "ps$" + strings.ToLower(name)
	case Cmd:
		return "cmd%" + strings.ToUpper(name)
	}
	return name
}

func (a *analyzer) runLex(c *lexCmd, in flow, origin string, depth int, d Dialect) flow {
	if !a.tick() {
		return noFlow()
	}
	if c.bg {
		a.f.Background = true
	}
	if c.expr {
		for i := range c.redirs {
			a.lexRedirect(c.redirs[i], nil)
		}
		return flow{rep: -1, t: c.exprT}
	}
	if len(c.words) == 0 {
		for _, e := range c.env {
			a.setVar(varKey(d, e.name), value{s: e.val.s, static: !e.val.dyn, t: e.val.t})
			a.envAssign(e.name)
			a.assignFacts(e.name, e.val)
		}
		for i := range c.redirs {
			r := c.redirs[i]
			if r.op == ">" && !r.target.dyn {
				// "> file" on its own truncates the file.
				a.write(r.target.s)
				if !pseudoPath(r.target.s) {
					a.destructive("truncate_file")
				}
				continue
			}
			a.lexRedirect(r, nil)
		}
		return noFlow()
	}
	sc := &simple{
		args: c.words, raw: c.words[0].s, env: c.env, origin: origin, depth: depth, dialect: d,
		bg: c.bg, idx: -1, stdin: c.stdin, stdinT: c.stdinT,
	}
	for i := range c.redirs {
		a.lexRedirect(c.redirs[i], sc)
	}
	return a.runSimple(sc, in)
}

// lexRedirect applies one redirection. With sc nil the redirection stands
// alone and only records the path use.
func (a *analyzer) lexRedirect(r lexRedir, sc *simple) {
	switch r.op {
	case ">", ">>":
		if sc != nil {
			sc.hasOut, sc.outFile, sc.outAppend = true, r.target, r.op == ">>"
			return
		}
		if r.op == ">>" {
			a.appendTo(r.target.s)
		} else {
			a.write(r.target.s)
		}
	case "2>", "2>>":
		if r.op == "2>>" {
			a.appendTo(r.target.s)
		} else {
			a.write(r.target.s)
		}
	case "<":
		a.read(r.target.s)
		if sc != nil {
			sc.hasIn, sc.inFile = true, r.target
		}
	}
}

// pipeBuilder accumulates lexed commands into pipelines.
type pipeBuilder struct {
	pipes []lexPipe
	pipe  lexPipe
	cur   *lexCmd
}

func newPipeBuilder() *pipeBuilder { return &pipeBuilder{cur: &lexCmd{}} }

// endCmd closes the current command (a pipe boundary).
func (b *pipeBuilder) endCmd() {
	if !b.cur.empty() {
		b.pipe.cmds = append(b.pipe.cmds, b.cur)
	}
	b.cur = &lexCmd{}
}

// endPipe closes the current pipeline (a statement boundary).
func (b *pipeBuilder) endPipe() {
	b.endCmd()
	if len(b.pipe.cmds) > 0 {
		b.pipes = append(b.pipes, b.pipe)
	}
	b.pipe = lexPipe{}
}

func (b *pipeBuilder) finish() []lexPipe {
	b.endPipe()
	return b.pipes
}

// matchClose returns the index just past the bracket that closes the one at
// s[i], honouring quotes the way all three dialects roughly agree on. It is
// iterative and O(n); -1 means unbalanced.
func matchClose(s string, i int, open, close byte) int {
	depth := 0
	for j := i; j < len(s); j++ {
		switch c := s[j]; c {
		case '\\':
			j++
		case '\'':
			if k := strings.IndexByte(s[j+1:], '\''); k >= 0 {
				j += k + 1
			} else {
				return -1
			}
		case '"':
			k := j + 1
			for k < len(s) && s[k] != '"' {
				if s[k] == '\\' || s[k] == '`' {
					k++
				}
				k++
			}
			if k >= len(s) {
				return -1
			}
			j = k
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// POSIX fallback lexer: used when the bash parser rejects the input or the
// input is shaped to make a recursive-descent parser blow its stack.

type heredocReq struct {
	delim  string
	quoted bool
	strip  bool
	cmd    *lexCmd
}

type shLexer struct {
	a        *analyzer
	s        string
	i        int
	origin   string
	depth    int
	b        *pipeBuilder
	pending  []heredocReq
	skipHead bool // inside a for/case/select header: words are not a command
}

func (a *analyzer) posixFallback(src, origin string, depth int, in flow) flow {
	lx := &shLexer{a: a, s: src, origin: origin, depth: depth, b: newPipeBuilder()}
	lx.lex()
	return a.runPipes(lx.b.finish(), origin, depth, Posix, in)
}

func (lx *shLexer) lex() {
	s := lx.s
	for lx.i < len(s) {
		if !lx.a.tick() {
			return
		}
		c := s[lx.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			lx.i++
		case c == '\\' && lx.i+1 < len(s) && s[lx.i+1] == '\n':
			lx.i += 2
		case c == '\n':
			lx.i++
			lx.b.endPipe()
			lx.skipHead = false
			lx.heredocBodies()
		case c == '#':
			for lx.i < len(s) && s[lx.i] != '\n' {
				lx.i++
			}
		case c == ';':
			lx.i++
			if lx.i < len(s) && s[lx.i] == ';' {
				lx.i++
			}
			lx.b.endPipe()
			lx.skipHead = false
		case c == '&':
			switch {
			case lx.peek(1) == '&':
				lx.i += 2
				lx.b.endPipe()
			case lx.peek(1) == '>':
				lx.redirect()
			default:
				lx.i++
				lx.b.cur.bg = true
				lx.b.endPipe()
			}
			lx.skipHead = false
		case c == '|':
			switch lx.peek(1) {
			case '|':
				lx.i += 2
				lx.b.endPipe()
			case '&':
				lx.i += 2
				lx.b.endCmd()
			default:
				lx.i++
				lx.b.endCmd()
			}
			lx.skipHead = false
		case c == '(' || c == ')':
			lx.i++
			lx.b.endPipe()
		case (c == '{' || c == '}') && (lx.i+1 >= len(s) || isSpace(s[lx.i+1]) || s[lx.i+1] == ';'):
			lx.i++
			lx.b.endPipe()
		case c == '<' && lx.peek(1) == '(' || c == '>' && lx.peek(1) == '(':
			lx.addWord(lx.word())
		case c == '<' || c == '>':
			lx.redirect()
		case c >= '0' && c <= '9' && lx.fdRedirect():
			lx.redirect()
		default:
			if lx.b.cur.empty() && lx.assignment() {
				continue
			}
			lx.addWord(lx.word())
		}
	}
	lx.heredocBodies()
}

func (lx *shLexer) peek(n int) byte {
	if lx.i+n < len(lx.s) {
		return lx.s[lx.i+n]
	}
	return 0
}

// fdRedirect reports "2>" style input at the cursor.
func (lx *shLexer) fdRedirect() bool {
	j := lx.i
	for j < len(lx.s) && lx.s[j] >= '0' && lx.s[j] <= '9' {
		j++
	}
	return j < len(lx.s) && j-lx.i <= 2 && (lx.s[j] == '>' || lx.s[j] == '<')
}

var shReserved map[string]int

func buildShReserved() {
	shReserved = map[string]int{
		// 0: drop the word and keep going; 1: drop the rest of the header.
		"if": 0, "then": 0, "else": 0, "elif": 0, "do": 0, "while": 0, "until": 0, "!": 0, "time": 0,
		"fi": 0, "done": 0, "esac": 0, "coproc": 0, "{": 0, "}": 0, "in": 0,
		"for": 1, "case": 1, "select": 1, "function": 1,
	}
}

func (lx *shLexer) addWord(w arg) {
	if lx.skipHead {
		return
	}
	cur := lx.b.cur
	if len(cur.words) == 0 && !w.quoted && !w.dyn {
		if k, ok := shReserved[w.s]; ok {
			if k == 1 {
				lx.skipHead = true
			}
			return
		}
	}
	cur.words = append(cur.words, w)
	if len(cur.words) > 8*maxList {
		lx.a.f.Truncated = true
		lx.b.endCmd()
	}
}

// assignment consumes NAME=value / NAME+=value at command start.
func (lx *shLexer) assignment() bool {
	s := lx.s
	j := lx.i
	if j >= len(s) || !(s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
		return false
	}
	for j < len(s) && isIdentByte(s[j]) {
		j++
	}
	plus := false
	if j < len(s) && s[j] == '+' {
		plus = true
		j++
	}
	if j >= len(s) || s[j] != '=' {
		return false
	}
	name := s[lx.i : j-boolInt(plus)]
	lx.i = j + 1
	var v arg
	if lx.i < len(s) && !isSpace(s[lx.i]) && strings.IndexByte(";&|()<>", s[lx.i]) < 0 {
		v = lx.word()
	}
	if plus {
		if old, ok := lx.a.getVar(name); ok && old.static && !v.dyn {
			v.s = old.s + v.s
		} else {
			v.dyn = true
		}
	}
	lx.b.cur.env = append(lx.b.cur.env, envKV{name: name, val: v})
	return true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (lx *shLexer) redirect() {
	s := lx.s
	fd := ""
	for lx.i < len(s) && s[lx.i] >= '0' && s[lx.i] <= '9' {
		fd += string(s[lx.i])
		lx.i++
	}
	ops := []string{"<<<", "<<-", "<<", "<>", "<&", "&>>", "&>", ">>", ">|", ">&", "<", ">"}
	op := ""
	for _, o := range ops {
		if strings.HasPrefix(s[lx.i:], o) {
			op = o
			break
		}
	}
	if op == "" {
		lx.i++
		return
	}
	lx.i += len(op)
	lx.skipSpace()
	switch op {
	case "<<", "<<-":
		lx.a.f.HereDoc = true
		w := lx.word()
		lx.pending = append(lx.pending, heredocReq{delim: w.s, quoted: w.quoted, strip: op == "<<-", cmd: lx.b.cur})
		return
	case "<<<":
		w := lx.word()
		text := w.s + "\n"
		lx.b.cur.stdin, lx.b.cur.stdinT = &text, w.t
		return
	case ">&", "<&":
		// fd duplication: >&2, >&-, and the bash spelling ">& file".
		if lx.i < len(s) && (s[lx.i] >= '0' && s[lx.i] <= '9' || s[lx.i] == '-') {
			for lx.i < len(s) && !isSpace(s[lx.i]) && strings.IndexByte(";&|()<>", s[lx.i]) < 0 {
				lx.i++
			}
			return
		}
		op = ">"
	case "&>", ">|":
		op = ">"
	case "&>>":
		op = ">>"
	case "<>":
		op = "<"
	}
	if fd == "2" {
		op = "2" + op
	}
	if lx.i >= len(s) || strings.IndexByte(";&|()\n", s[lx.i]) >= 0 {
		return
	}
	t := lx.word()
	if fd != "" && fd != "1" && fd != "2" && fd != "0" {
		return
	}
	lx.b.cur.redirs = append(lx.b.cur.redirs, lexRedir{op: op, target: t})
}

func (lx *shLexer) skipSpace() {
	for lx.i < len(lx.s) && (lx.s[lx.i] == ' ' || lx.s[lx.i] == '\t') {
		lx.i++
	}
}

// heredocBodies reads the bodies of heredocs opened on the line just ended.
func (lx *shLexer) heredocBodies() {
	for len(lx.pending) > 0 {
		req := lx.pending[0]
		lx.pending = lx.pending[1:]
		var body strings.Builder
		found := false
		for lx.i < len(lx.s) {
			end := strings.IndexByte(lx.s[lx.i:], '\n')
			line := ""
			if end < 0 {
				line = lx.s[lx.i:]
				lx.i = len(lx.s)
			} else {
				line = lx.s[lx.i : lx.i+end]
				lx.i += end + 1
			}
			cmp := line
			if req.strip {
				cmp = strings.TrimLeft(cmp, "\t")
			}
			if cmp == req.delim {
				found = true
				break
			}
			if body.Len() < maxStatic {
				body.WriteString(line)
				body.WriteByte('\n')
			}
		}
		if !found {
			lx.a.f.ParseOK = false
		}
		text := body.String()
		if req.cmd != nil {
			req.cmd.stdin = &text
		}
	}
}

// word reads one word up to an unquoted metacharacter.
func (lx *shLexer) word() arg {
	s := lx.s
	var b strings.Builder
	var w arg
	start := lx.i
	lastIdent := false // previous output byte was an identifier byte
	split := false     // a quote or escape began mid-identifier
	// Process substitution.
	if lx.i+1 < len(s) && (s[lx.i] == '<' || s[lx.i] == '>') && s[lx.i+1] == '(' {
		end := matchClose(s, lx.i+1, '(', ')')
		if end < 0 {
			end = len(s)
		}
		inner := s[lx.i+2 : max(lx.i+2, end-1)]
		lx.i = end
		fl := lx.a.sub(inner, Posix, OriginSubstitution, lx.depth+1, noFlow())
		return arg{s: "<(...)", dyn: true, proc: true, exp: true, t: fl.t}
	}
	for lx.i < len(s) {
		c := s[lx.i]
		if isSpace(c) || strings.IndexByte(";&|()<>", c) >= 0 {
			break
		}
		if b.Len() > maxWord {
			lx.a.f.Truncated = true
			lx.i++
			continue
		}
		switch c {
		case '\'':
			w.quoted = true
			end := strings.IndexByte(s[lx.i+1:], '\'')
			var lit string
			if end < 0 {
				lit = s[lx.i+1:]
				lx.i = len(s)
				lx.a.f.ParseOK = false
			} else {
				lit = s[lx.i+1 : lx.i+1+end]
				lx.i += end + 2
			}
			if lastIdent && lit != "" && isIdentByte(lit[0]) {
				split = true
			}
			b.WriteString(lit)
			lastIdent = lit != "" && isIdentByte(lit[len(lit)-1])
		case '"':
			w.quoted = true
			lx.i++
			first := true
			for lx.i < len(s) && s[lx.i] != '"' {
				d := s[lx.i]
				switch {
				case d == '\\' && lx.i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[lx.i+1]) >= 0:
					if s[lx.i+1] != '\n' {
						b.WriteByte(s[lx.i+1])
					}
					lx.i += 2
				case d == '$':
					lx.dollar(&b, &w)
				case d == '`':
					lx.backtick(&b, &w)
				default:
					if first && lastIdent && isIdentByte(d) {
						split = true
					}
					b.WriteByte(d)
					lx.i++
				}
				first = false
			}
			if lx.i < len(s) {
				lx.i++
			} else {
				lx.a.f.ParseOK = false
			}
			out := b.String()
			lastIdent = out != "" && isIdentByte(out[len(out)-1])
		case '\\':
			if lx.i+1 < len(s) {
				if s[lx.i+1] == '\n' {
					lx.i += 2
					continue
				}
				if lastIdent && isIdentByte(s[lx.i+1]) {
					split = true
				}
				b.WriteByte(s[lx.i+1])
				lastIdent = isIdentByte(s[lx.i+1])
				lx.i += 2
			} else {
				lx.i++
			}
		case '$':
			if lx.i+1 < len(s) && s[lx.i+1] == '\'' {
				// ANSI-C quoting.
				w.quoted = true
				j := lx.i + 2
				for j < len(s) && s[j] != '\'' {
					if s[j] == '\\' {
						j++
					}
					j++
				}
				if j > len(s) {
					j = len(s)
				}
				lit, coded := unescapeC(s[lx.i+2 : j])
				if coded {
					w.t |= tEsc
				}
				b.WriteString(lit)
				lx.i = j + 1
				lastIdent = lit != "" && isIdentByte(lit[len(lit)-1])
				continue
			}
			if lx.dollar(&b, &w) {
				// $IFS outside quotes splits the word.
				lx.a.obf("ifs_abuse")
				w.s = b.String()
				if w.s != "" || w.quoted {
					lx.addWord(lx.finishWord(w, split))
				}
				b.Reset()
				w = arg{}
				split, lastIdent = false, false
				continue
			}
			lastIdent = false
		case '`':
			lx.backtick(&b, &w)
			lastIdent = false
		default:
			if (c == '*' || c == '?' || c == '[') && !w.quoted {
				w.glob = true
			}
			b.WriteByte(c)
			lastIdent = isIdentByte(c)
			lx.i++
		}
	}
	if lx.i == start {
		// Never loop on a byte the caller did not expect.
		lx.i++
	}
	w.s = b.String()
	return lx.finishWord(w, split)
}

func (lx *shLexer) finishWord(w arg, split bool) arg {
	if split && w.s != "" && isIdentByte(w.s[0]) {
		w.concat = true
	}
	return w
}

// dollar expands a $ form at the cursor into b. It reports true for an
// unquoted $IFS, which the caller treats as a word separator.
func (lx *shLexer) dollar(b *strings.Builder, w *arg) bool {
	s := lx.s
	i := lx.i
	if i+1 >= len(s) {
		b.WriteByte('$')
		lx.i++
		return false
	}
	switch n := s[i+1]; {
	case n == '(' && i+2 < len(s) && s[i+2] == '(':
		end := matchClose(s, i+1, '(', ')')
		if end < 0 {
			end = len(s)
		}
		b.WriteString("$((...))")
		w.dyn, w.exp = true, true
		lx.i = end
	case n == '(':
		end := matchClose(s, i+1, '(', ')')
		if end < 0 {
			end = len(s)
			lx.a.f.ParseOK = false
		}
		inner := s[i+2 : max(i+2, end-1)]
		lx.i = end
		fl := lx.a.sub(inner, Posix, OriginSubstitution, lx.depth+1, noFlow())
		b.WriteString("$(...)")
		w.dyn, w.exp = true, true
		w.t |= fl.t
	case n == '{':
		end := matchClose(s, i+1, '{', '}')
		if end < 0 {
			end = len(s)
		}
		inner := s[i+2 : max(i+2, end-1)]
		lx.i = end
		w.exp = true
		if inner == "IFS" {
			return true
		}
		if strings.Contains(inner, ":?") {
			w.guard = true
		}
		if isName(inner) {
			if v, ok := lx.a.getVar(inner); ok && v.static {
				b.WriteString(v.s)
				w.t |= v.t
				return false
			}
		}
		b.WriteString("${" + clip(inner, 64) + "}")
		w.dyn = true
	case isIdentByte(n) && !(n >= '0' && n <= '9'):
		j := i + 1
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		name := s[i+1 : j]
		lx.i = j
		w.exp = true
		if name == "IFS" {
			return true
		}
		if v, ok := lx.a.getVar(name); ok && v.static {
			b.WriteString(v.s)
			w.t |= v.t
			return false
		}
		b.WriteString("$" + name)
		w.dyn = true
	case strings.IndexByte("0123456789@*#?$!-", n) >= 0:
		b.WriteString(s[i : i+2])
		w.dyn, w.exp = true, true
		lx.i = i + 2
	default:
		b.WriteByte('$')
		lx.i++
	}
	return false
}

// backtick handles `...` command substitution.
func (lx *shLexer) backtick(b *strings.Builder, w *arg) {
	s := lx.s
	j := lx.i + 1
	for j < len(s) && s[j] != '`' {
		if s[j] == '\\' {
			j++
		}
		j++
	}
	if j > len(s) {
		j = len(s)
	}
	inner := s[lx.i+1 : min(j, len(s))]
	lx.i = min(j+1, len(s))
	fl := lx.a.sub(inner, Posix, OriginSubstitution, lx.depth+1, noFlow())
	b.WriteString("$(...)")
	w.dyn, w.exp = true, true
	w.t |= fl.t
}

func isName(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}
