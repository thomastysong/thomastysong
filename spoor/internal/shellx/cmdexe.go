package shellx

import "strings"

// cmd.exe front end: ^ escapes, "..." quoting, %VAR% and !VAR! expansion,
// & && || | separators, redirections, and the control words (if, for, call,
// start, set, rem) that change which word is the command.

type cmdLexer struct {
	a      *analyzer
	s      string
	i      int
	origin string
	depth  int
	b      *pipeBuilder
}

func (a *analyzer) cmdexe(src, origin string, depth int, in flow) flow {
	lx := &cmdLexer{a: a, s: src, origin: origin, depth: depth, b: newPipeBuilder()}
	lx.lex()
	pipes := lx.b.finish()
	for pi := range pipes {
		for _, c := range pipes[pi].cmds {
			lx.normalize(c)
		}
	}
	return a.runPipes(pipes, origin, depth, Cmd, in)
}

func (lx *cmdLexer) peek(n int) byte {
	if lx.i+n < len(lx.s) {
		return lx.s[lx.i+n]
	}
	return 0
}

func (lx *cmdLexer) lex() {
	s := lx.s
	lineStart := true
	for lx.i < len(s) {
		if !lx.a.tick() {
			return
		}
		c := s[lx.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == ',' && lx.b.cur.empty():
			lx.i++
			continue
		case c == '^' && lx.peek(1) == '\n':
			lx.i += 2
			continue
		case c == '\n':
			lx.i++
			lx.b.endPipe()
			lineStart = true
			continue
		case lineStart && c == ':' && lx.peek(1) == ':', lineStart && c == ':' && lx.b.cur.empty():
			// ":: comment" and ":label".
			for lx.i < len(s) && s[lx.i] != '\n' {
				lx.i++
			}
			continue
		case c == '@' && lx.b.cur.empty():
			lx.i++
			continue
		case c == '&' && lx.peek(1) == '&', c == '|' && lx.peek(1) == '|':
			lx.i += 2
			lx.b.endPipe()
		case c == '&':
			lx.i++
			lx.b.endPipe()
		case c == '|':
			lx.i++
			lx.b.endCmd()
		case c == '(' && lx.b.cur.empty(), c == ')':
			lx.i++
			lx.b.endPipe()
		case c == '>' || c == '<' || (c >= '0' && c <= '9') && (lx.peek(1) == '>' || lx.peek(1) == '<'):
			lx.redirect()
		default:
			w := lx.word()
			cur := lx.b.cur
			if len(cur.words) == 0 && !w.quoted && strings.EqualFold(w.s, "rem") {
				for lx.i < len(s) && s[lx.i] != '\n' {
					lx.i++
				}
				continue
			}
			cur.words = append(cur.words, w)
			if len(cur.words) > 8*maxList {
				lx.a.f.Truncated = true
				lx.b.endCmd()
			}
		}
		lineStart = false
	}
}

func (lx *cmdLexer) redirect() {
	s := lx.s
	fd := byte('1')
	if s[lx.i] >= '0' && s[lx.i] <= '9' {
		fd = s[lx.i]
		lx.i++
	}
	op := string(s[lx.i])
	lx.i++
	if op == ">" && lx.i < len(s) && s[lx.i] == '>' {
		op = ">>"
		lx.i++
	}
	if lx.i < len(s) && s[lx.i] == '&' {
		lx.i++
		for lx.i < len(s) && s[lx.i] >= '0' && s[lx.i] <= '9' {
			lx.i++
		}
		return
	}
	for lx.i < len(s) && (s[lx.i] == ' ' || s[lx.i] == '\t') {
		lx.i++
	}
	if lx.i >= len(s) || strings.IndexByte("&|\n", s[lx.i]) >= 0 {
		return
	}
	t := lx.word()
	switch {
	case op == "<":
	case fd == '2':
		op = "2" + op
	case fd != '1':
		return
	}
	lx.b.cur.redirs = append(lx.b.cur.redirs, lexRedir{op: op, target: t})
}

// word reads one cmd.exe word. Quotes group but are not part of the value.
func (lx *cmdLexer) word() arg {
	s := lx.s
	var b strings.Builder
	var w arg
	start := lx.i
	inQ := false
	for lx.i < len(s) {
		c := s[lx.i]
		if !inQ && (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '&' || c == '|' || c == '<' || c == '>' || c == ')') {
			break
		}
		if c == '\n' {
			break
		}
		if b.Len() > maxWord {
			lx.a.f.Truncated = true
			lx.i++
			continue
		}
		switch {
		case c == '"':
			inQ = !inQ
			w.quoted = true
			lx.i++
		case c == '^' && !inQ && lx.i+1 < len(s):
			if isAlnum(s[lx.i+1]) && b.Len() > 0 {
				// c^u^r^l: caret escapes splitting an identifier.
				w.concat = true
			}
			b.WriteByte(s[lx.i+1])
			lx.i += 2
		case c == '%':
			lx.percent(&b, &w)
		case c == '!' && lx.i+1 < len(s) && isIdentByte(s[lx.i+1]):
			j := lx.i + 1
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '!' {
				name := s[lx.i+1 : j]
				lx.i = j + 1
				w.exp = true
				if v, ok := lx.a.getVar(varKey(Cmd, name)); ok && v.static {
					b.WriteString(v.s)
					w.t |= v.t
				} else {
					b.WriteString("!" + name + "!")
					w.dyn = true
				}
				continue
			}
			b.WriteByte(c)
			lx.i++
		default:
			b.WriteByte(c)
			lx.i++
		}
	}
	if inQ {
		lx.a.f.ParseOK = false
	}
	if lx.i == start {
		lx.i++
	}
	w.s = b.String()
	return w
}

// percent expands %VAR%, %VAR:~a,b%, %VAR:x=y%, %1, %~dp0 and %%i.
func (lx *cmdLexer) percent(b *strings.Builder, w *arg) {
	s := lx.s
	i := lx.i
	if i+1 < len(s) && s[i+1] == '%' {
		// %%i loop variable.
		j := i + 2
		if j < len(s) {
			j++
		}
		b.WriteString(s[i:min(j, len(s))])
		w.dyn, w.exp = true, true
		lx.i = min(j, len(s))
		return
	}
	if i+1 < len(s) && (s[i+1] >= '0' && s[i+1] <= '9' || s[i+1] == '~' || s[i+1] == '*') {
		j := i + 2
		for j < len(s) && (isAlnum(s[j]) || s[j] == '~') && j-i < 12 {
			j++
		}
		b.WriteString(s[i:j])
		w.dyn, w.exp = true, true
		lx.i = j
		return
	}
	end := strings.IndexByte(s[i+1:], '%')
	if end < 0 || end > 256 || strings.ContainsAny(s[i+1:i+1+end], " \n\"") && !strings.Contains(s[i+1:i+1+end], ":") {
		b.WriteByte('%')
		lx.i++
		return
	}
	ref := s[i+1 : i+1+end]
	lx.i = i + end + 2
	w.exp = true
	name, modifier := ref, ""
	if k := strings.IndexByte(ref, ':'); k >= 0 {
		name, modifier = ref[:k], ref[k+1:]
	}
	if modifier != "" {
		// Substring and replacement syntax is the cmd.exe way to spell a
		// command out of other variables' characters.
		lx.a.obf("var_indirection")
		b.WriteString("%" + ref + "%")
		w.dyn = true
		return
	}
	if v, ok := lx.a.getVar(varKey(Cmd, name)); ok && v.static {
		b.WriteString(v.s)
		w.t |= v.t
		return
	}
	b.WriteString("%" + name + "%")
	w.dyn = true
}

// normalize strips control words so words[0] is the command that runs, and
// handles "set".
func (lx *cmdLexer) normalize(c *lexCmd) {
	for n := 0; n < 8 && len(c.words) > 0; n++ {
		w := c.words
		head := strings.ToLower(w[0].s)
		if w[0].quoted {
			head = ""
		}
		switch head {
		case "if":
			c.words = stripIfCond(w[1:])
		case "else":
			c.words = w[1:]
		case "for":
			c.words = nil
			for i := 1; i < len(w); i++ {
				if strings.EqualFold(w[i].s, "do") && !w[i].quoted {
					c.words = w[i+1:]
					break
				}
			}
		case "do":
			c.words = w[1:]
		case "call":
			if len(w) > 1 && strings.HasPrefix(w[1].s, ":") {
				c.words = nil
			} else {
				c.words = w[1:]
			}
		case "start":
			rest := w[1:]
			if len(rest) > 0 && rest[0].quoted {
				rest = rest[1:] // window title
			}
			for len(rest) > 0 && strings.HasPrefix(rest[0].s, "/") && !rest[0].quoted {
				opt := strings.ToLower(rest[0].s)
				rest = rest[1:]
				switch opt {
				case "/b", "/min":
					c.bg = true
				case "/d":
					if len(rest) > 0 {
						rest = rest[1:]
					}
				}
			}
			c.words = rest
		case "set":
			if len(w) > 1 {
				lx.cmdSet(w[1:])
			}
			return
		default:
			if len(w) == 1 && strings.HasPrefix(w[0].s, "'") && strings.HasSuffix(w[0].s, "'") && len(w[0].s) > 2 {
				// for /f ... in ('command') do ...
				inner := w[0].s[1 : len(w[0].s)-1]
				c.words = nil
				lx.a.sub(inner, Cmd, OriginSubstitution, lx.depth+1, noFlow())
			}
			return
		}
	}
}

// stripIfCond removes an if condition: [/i] [not] exist X | defined X |
// errorlevel N | cmdextversion N | A==B | A op B.
func stripIfCond(w []arg) []arg {
	i := 0
	if i < len(w) && strings.EqualFold(w[i].s, "/i") {
		i++
	}
	if i < len(w) && strings.EqualFold(w[i].s, "not") {
		i++
	}
	if i >= len(w) {
		return nil
	}
	switch strings.ToLower(w[i].s) {
	case "exist", "defined", "errorlevel", "cmdextversion":
		i += 2
	default:
		if strings.Contains(w[i].s, "==") {
			i++
		} else if i+1 < len(w) && (w[i+1].s == "==" || isCmpOp(w[i+1].s)) {
			i += 3
		} else {
			i++
		}
	}
	if i >= len(w) {
		return nil
	}
	return w[i:]
}

func isCmpOp(s string) bool {
	switch strings.ToLower(s) {
	case "equ", "neq", "lss", "leq", "gtr", "geq":
		return true
	}
	return false
}

// cmdSet handles set NAME=value, set /a NAME=expr and set /p NAME=prompt.
func (lx *cmdLexer) cmdSet(args []arg) {
	if len(args) == 0 {
		return
	}
	opt := strings.ToLower(args[0].s)
	if opt == "/a" || opt == "/p" {
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}
	joined := joinArgs(args)
	k := strings.IndexByte(joined, '=')
	if k <= 0 {
		return
	}
	name := strings.TrimSpace(joined[:k])
	val := joined[k+1:]
	lx.a.envAssign(name)
	v := value{s: val, static: !anyDyn(args) && opt != "/a" && opt != "/p", t: anyTaint(args)}
	lx.a.setVar(varKey(Cmd, name), v)
	lx.a.assignFacts(name, arg{s: val, dyn: !v.static, t: v.t})
	if setsDisableAllHooks(joined) {
		lx.a.evasion("agent_hook_tamper")
	}
}
