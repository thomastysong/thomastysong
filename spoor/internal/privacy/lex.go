package privacy

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/shellx"
)

// This file is a small, linear-time lexer for command lines. shellx.Analyze
// already parses commands into argument vectors (and that is what decides
// which values are secrets), but its facts carry no byte offsets. Redaction
// has to edit the original text in place, keeping pipes, redirections and
// quoting readable, so it needs the span of every word. The lexer only
// splits; it never decides meaning beyond what the edit step needs (which
// words are arguments, which feed a pipe, what a here-string or heredoc
// holds).

type tokKind uint8

const (
	tWord tokKind = iota
	tOp
	tHeredoc // body of a here-document, owned by a "<<" operator token
	tComment
)

// token is one lexical unit. For words, val is the value with quotes and
// escapes removed; for operators it is the operator text; for heredoc
// bodies and comments it is the raw text.
type token struct {
	kind       tokKind
	start, end int
	val        string
	// quote is the quoting style when the whole word is a single quoted
	// string ('\'' or '"'), 'm' for a word that mixes quoted and unquoted
	// parts, 0 when the word is unquoted.
	quote byte
	owner int // tHeredoc: index of the "<<" operator token
}

// maxTokens bounds the lexer's output. Every token but an empty heredoc
// body spans at least one byte, so a command capped at maxCommandScan fits;
// should the cap be reached anyway, the lexer reports where it stopped and
// redactCommand cuts the line there, because text no token covers is text
// no structural view has seen.
const maxTokens = 1 << 16

// maxNestScan bounds how deep $( ... ) and ${ ... } nesting is followed
// inside one word.
const maxNestScan = 256

type lexer struct {
	src  string
	d    shellx.Dialect
	toks []token
	// pending heredocs, read after the next newline
	pending []pendingDoc
	full    bool // token cap reached
	stop    int  // byte offset of the first token that was not emitted, -1 when complete
}

type pendingDoc struct {
	op    int // index of the "<<" operator token
	delim string
	strip bool // "<<-": leading tabs are stripped from body lines
}

// lex splits src into tokens for dialect d. It never panics on any input
// (callers still recover) and runs in linear time apart from bounded
// nesting scans.
func lex(src string, d shellx.Dialect) []token {
	toks, _ := lexStop(src, d)
	return toks
}

// lexStop is lex that also returns the byte offset where the token cap
// stopped it (-1 when all of src was tokenised).
func lexStop(src string, d shellx.Dialect) ([]token, int) {
	l := &lexer{src: src, d: d, stop: -1}
	switch d {
	case shellx.PowerShell:
		l.run(l.psWord, psOps)
	case shellx.Cmd:
		l.run(l.cmdWord, cmdOps)
	default:
		l.run(l.posixWord, posixOps)
	}
	return l.toks, l.stop
}

var (
	posixOps = []string{"&>>", "<<<", "<<-", "&&", "||", "|&", ";;", "<<", ">>", "<&", ">&", "<>", ">|", "&>", "|", "&", ";", "(", ")", "<", ">"}
	psOps    = []string{"&&", "||", ">>", "2>&1", "*>", "|", ";", "(", ")", "{", "}", ">", "<"}
	cmdOps   = []string{"&&", "||", ">>", "2>&1", "|", "&", "(", ")", ">", "<"}
)

func (l *lexer) emit(t token) {
	if l.full {
		return
	}
	if len(l.toks) >= maxTokens {
		l.full = true
		l.stop = t.start
		return
	}
	l.toks = append(l.toks, t)
}

// run is the dialect-independent main loop: whitespace, newlines,
// comments and operators are handled here; words by the dialect's reader.
func (l *lexer) run(word func(i int) (token, int), ops []string) {
	src := l.src
	i := 0
	atWordStart := true
	for i < len(src) && !l.full {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			i++
			atWordStart = true
			continue
		case c == '\n':
			l.emit(token{kind: tOp, start: i, end: i + 1, val: "\n"})
			i++
			if len(l.pending) > 0 {
				i = l.readHeredocs(i)
			}
			atWordStart = true
			continue
		case c == '\\' && l.d == shellx.Posix && i+1 < len(src) && src[i+1] == '\n':
			i += 2 // line continuation
			continue
		case c == '#' && atWordStart && l.d != shellx.Cmd:
			if l.d == shellx.PowerShell && i > 0 && src[i-1] == '<' {
				break
			}
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src)
			} else {
				end += i
			}
			l.emit(token{kind: tComment, start: i, end: end, val: src[i:end]})
			i = end
			continue
		case c == '<' && l.d == shellx.PowerShell && i+1 < len(src) && src[i+1] == '#':
			end := strings.Index(src[i+2:], "#>")
			if end < 0 {
				end = len(src)
			} else {
				end += i + 4
			}
			l.emit(token{kind: tComment, start: i, end: end, val: src[i:end]})
			i = end
			continue
		}
		if op := matchOp(src[i:], ops); op != "" {
			op = src[i:extendDup(src, i+len(op))]
			l.emit(token{kind: tOp, start: i, end: i + len(op), val: op})
			i += len(op)
			if op == "<<" || op == "<<-" {
				i = l.heredocDelim(i, op == "<<-")
			}
			atWordStart = true
			continue
		}
		t, next := word(i)
		if next <= i {
			next = i + 1 // defensive: always make progress
			t = token{kind: tWord, start: i, end: next, val: src[i:next]}
		}
		if fd := fdPrefix(t, src, next); fd {
			// The word was "2" in "2>file": a file-descriptor number glued
			// to a redirection belongs to the operator, not to argv.
			if op := matchOp(src[next:], ops); op != "" {
				end := extendDup(src, next+len(op))
				l.emit(token{kind: tOp, start: t.start, end: end, val: t.val + src[next:end]})
				i = end
				atWordStart = true
				continue
			}
		}
		l.emit(t)
		i = next
		atWordStart = false
	}
	if len(l.pending) > 0 {
		// Heredoc operators with no newline after them: nothing to read.
		l.pending = nil
	}
}

// extendDup extends a redirection operator ending at end over a following
// "&1" / "&-" (descriptor duplication), which takes no target word.
func extendDup(src string, end int) int {
	if end < 2 || end+1 >= len(src) || src[end] != '&' {
		return end
	}
	if p := src[end-1]; p != '>' && p != '<' {
		return end
	}
	if c := src[end+1]; c == '-' || c >= '0' && c <= '9' {
		return end + 2
	}
	return end
}

func matchOp(s string, ops []string) string {
	for _, op := range ops {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

// fdPrefix reports a word made only of digits (or "*" in PowerShell) that
// is immediately followed by a redirection.
func fdPrefix(t token, src string, next int) bool {
	if t.quote != 0 || next >= len(src) || (src[next] != '>' && src[next] != '<') {
		return false
	}
	if t.val == "" || len(t.val) > 3 {
		return false
	}
	for i := 0; i < len(t.val); i++ {
		if (t.val[i] < '0' || t.val[i] > '9') && t.val[i] != '*' {
			return false
		}
	}
	return true
}

// heredocDelim reads the delimiter word after "<<" / "<<-" and queues the
// body for reading after the next newline.
func (l *lexer) heredocDelim(i int, strip bool) int {
	src := l.src
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	if i >= len(src) || src[i] == '\n' {
		return i
	}
	t, next := l.posixWord(i)
	if next <= i {
		return i
	}
	l.emit(t)
	l.pending = append(l.pending, pendingDoc{op: len(l.toks) - 2, delim: t.val, strip: strip})
	if len(l.pending) > 64 {
		l.pending = l.pending[len(l.pending)-64:]
	}
	return next
}

// readHeredocs consumes the bodies of every pending heredoc starting at i
// (the first byte after a newline) and returns the position after the last
// delimiter line.
func (l *lexer) readHeredocs(i int) int {
	src := l.src
	for _, p := range l.pending {
		start := i
		end := len(src)
		next := len(src)
		for j := i; j < len(src); {
			k := strings.IndexByte(src[j:], '\n')
			lineEnd := len(src)
			if k >= 0 {
				lineEnd = j + k
			}
			line := src[j:lineEnd]
			if p.strip {
				line = strings.TrimLeft(line, "\t")
			}
			if strings.TrimRight(line, "\r") == p.delim {
				end = j
				next = lineEnd
				if next < len(src) {
					next++
				}
				break
			}
			if k < 0 {
				break
			}
			j = lineEnd + 1
		}
		if p.op >= 0 && p.op < len(l.toks) {
			l.emit(token{kind: tHeredoc, start: start, end: end, val: src[start:end], owner: p.op})
		}
		i = next
		if i >= len(src) {
			break
		}
	}
	l.pending = l.pending[:0]
	return i
}

// wordBuilder accumulates a word's value and tracks its quoting style.
type wordBuilder struct {
	b      strings.Builder
	quoted bool
	bare   bool // some part was unquoted
	style  byte
	mixed  bool
}

func (w *wordBuilder) quotedPart(q byte) {
	if w.style != 0 && w.style != q {
		w.mixed = true
	}
	w.style = q
	w.quoted = true
}

func (w *wordBuilder) token(start, end int) token {
	t := token{kind: tWord, start: start, end: end, val: w.b.String()}
	switch {
	case !w.quoted:
		t.quote = 0
	case w.bare || w.mixed:
		t.quote = 'm'
	default:
		t.quote = w.style
	}
	return t
}

func isPosixBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '|', '&', ';', '<', '>', '(', ')':
		return true
	}
	return false
}

// posixWord reads one POSIX/bash word starting at i.
func (l *lexer) posixWord(i int) (token, int) {
	src := l.src
	start := i
	var w wordBuilder
	for i < len(src) {
		c := src[i]
		if isPosixBreak(c) {
			// "<(" and ">(" are process substitutions, but they start a new
			// token; "$(" inside a word is handled below.
			break
		}
		switch c {
		case '\'':
			w.quotedPart('\'')
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				w.b.WriteString(src[i+1:])
				i = len(src)
				continue
			}
			w.b.WriteString(src[i+1 : i+1+end])
			i += end + 2
		case '"':
			w.quotedPart('"')
			i = l.posixDouble(i+1, &w.b)
		case '\\':
			w.bare = true
			if i+1 < len(src) {
				if src[i+1] != '\n' {
					_, n := utf8.DecodeRuneInString(src[i+1:])
					w.b.WriteString(src[i+1 : i+1+n])
					i += 1 + n
				} else {
					i += 2
				}
			} else {
				i++
			}
		case '$':
			w.bare = true
			if i+1 < len(src) && src[i+1] == '\'' {
				w.quotedPart('\'')
				v, n := ansiC(src[i+2:])
				w.b.WriteString(v)
				i += 2 + n
				continue
			}
			if i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{') {
				end := skipBalanced(src, i+1)
				w.b.WriteString(src[i:end])
				i = end
				continue
			}
			w.b.WriteByte(c)
			i++
		case '`':
			w.bare = true
			end := skipBacktick(src, i)
			w.b.WriteString(src[i:end])
			i = end
		default:
			w.bare = true
			w.b.WriteByte(c)
			i++
		}
	}
	return w.token(start, i), i
}

// posixDouble reads the inside of a double-quoted string starting after the
// opening quote and returns the position after the closing quote.
func (l *lexer) posixDouble(i int, b *strings.Builder) int {
	src := l.src
	for i < len(src) {
		c := src[i]
		switch c {
		case '"':
			return i + 1
		case '\\':
			if i+1 < len(src) {
				switch src[i+1] {
				case '"', '\\', '$', '`':
					b.WriteByte(src[i+1])
					i += 2
					continue
				case '\n':
					i += 2
					continue
				}
			}
			b.WriteByte(c)
			i++
		case '$':
			if i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{') {
				end := skipBalanced(src, i+1)
				b.WriteString(src[i:end])
				i = end
				continue
			}
			b.WriteByte(c)
			i++
		case '`':
			end := skipBacktick(src, i)
			b.WriteString(src[i:end])
			i = end
		default:
			b.WriteByte(c)
			i++
		}
	}
	return i
}

// skipBalanced returns the position after the bracket group that opens at
// src[i] ("(" or "{"), honouring quotes. Unbalanced input ends at len(src);
// nesting deeper than maxNestScan ends the scan there too.
func skipBalanced(src string, i int) int {
	open := src[i]
	closeCh := byte(')')
	if open == '{' {
		closeCh = '}'
	}
	depth := 0
	for i < len(src) {
		switch c := src[i]; c {
		case open:
			depth++
			if depth > maxNestScan {
				return len(src)
			}
		case closeCh:
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'':
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				return len(src)
			}
			i += end + 1
		case '"':
			for i++; i < len(src) && src[i] != '"'; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case '\\':
			i++
		}
		i++
	}
	return len(src)
}

func skipBacktick(src string, i int) int {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '`':
			return j + 1
		}
	}
	return len(src)
}

// ansiC decodes a bash $'...' body (s starts after the opening quote) and
// returns the decoded value and the number of bytes consumed including the
// closing quote.
func ansiC(s string) (string, int) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			return b.String(), i + 1
		}
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		e := s[i+1]
		i += 2
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		case 'x':
			n := hexRun(s[i:], 2)
			if n == 0 {
				b.WriteString(`\x`)
				continue
			}
			v, _ := strconv.ParseUint(s[i:i+n], 16, 8)
			b.WriteByte(byte(v))
			i += n
		case 'u', 'U':
			max := 4
			if e == 'U' {
				max = 8
			}
			n := hexRun(s[i:], max)
			if n == 0 {
				b.WriteByte('\\')
				b.WriteByte(e)
				continue
			}
			v, _ := strconv.ParseUint(s[i:i+n], 16, 32)
			if v > utf8.MaxRune {
				v = utf8.RuneError
			}
			b.WriteRune(rune(v))
			i += n
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i - 1
			k := j
			for k < len(s) && k < j+3 && s[k] >= '0' && s[k] <= '7' {
				k++
			}
			v, _ := strconv.ParseUint(s[j:k], 8, 16)
			b.WriteByte(byte(v))
			i = k
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String(), len(s)
}

func hexRun(s string, max int) int {
	n := 0
	for n < len(s) && n < max && isHex(s[n]) {
		n++
	}
	return n
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isPSBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '|', ';', '(', ')', '{', '}', '>', '<':
		return true
	}
	return false
}

// psWord reads one PowerShell word starting at i.
func (l *lexer) psWord(i int) (token, int) {
	src := l.src
	start := i
	var w wordBuilder
	// Here-strings: @' ... '@ and @" ... "@ on their own lines.
	if strings.HasPrefix(src[i:], "@'") || strings.HasPrefix(src[i:], `@"`) {
		q := src[i+1]
		term := "\n" + string(q) + "@"
		if end := strings.Index(src[i+2:], term); end >= 0 {
			body := src[i+2 : i+2+end]
			body = strings.TrimPrefix(strings.TrimPrefix(body, "\r"), "\n")
			w.quotedPart(q)
			w.b.WriteString(body)
			next := i + 2 + end + len(term)
			return w.token(start, next), next
		}
	}
	for i < len(src) {
		c := src[i]
		if isPSBreak(c) {
			break
		}
		if c == '&' && i+1 < len(src) && src[i+1] == '&' {
			break
		}
		switch c {
		case '\'':
			w.quotedPart('\'')
			i++
			for i < len(src) {
				if src[i] == '\'' {
					if i+1 < len(src) && src[i+1] == '\'' {
						w.b.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				w.b.WriteByte(src[i])
				i++
			}
		case '"':
			w.quotedPart('"')
			i++
			for i < len(src) {
				ch := src[i]
				if ch == '"' {
					if i+1 < len(src) && src[i+1] == '"' {
						w.b.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				if ch == '`' && i+1 < len(src) {
					w.b.WriteByte(psEscape(src[i+1]))
					i += 2
					continue
				}
				if ch == '$' && i+1 < len(src) && src[i+1] == '(' {
					end := skipBalanced(src, i+1)
					w.b.WriteString(src[i:end])
					i = end
					continue
				}
				w.b.WriteByte(ch)
				i++
			}
		case '`':
			w.bare = true
			if i+1 < len(src) {
				w.b.WriteByte(psEscape(src[i+1]))
				i += 2
			} else {
				i++
			}
		case '$', '@':
			w.bare = true
			if i+1 < len(src) && (src[i+1] == '(' || src[i+1] == '{') {
				end := skipBalanced(src, i+1)
				w.b.WriteString(src[i:end])
				i = end
				continue
			}
			w.b.WriteByte(c)
			i++
		default:
			w.bare = true
			w.b.WriteByte(c)
			i++
		}
	}
	return w.token(start, i), i
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
	}
	return c
}

func isCmdBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '|', '&', '(', ')', '>', '<':
		return true
	}
	return false
}

// cmdWord reads one cmd.exe word starting at i.
func (l *lexer) cmdWord(i int) (token, int) {
	src := l.src
	start := i
	var w wordBuilder
	for i < len(src) {
		c := src[i]
		if isCmdBreak(c) {
			break
		}
		switch c {
		case '"':
			w.quotedPart('"')
			i++
			for i < len(src) && src[i] != '"' && src[i] != '\n' {
				w.b.WriteByte(src[i])
				i++
			}
			if i < len(src) && src[i] == '"' {
				i++
			}
		case '^':
			w.bare = true
			if i+1 < len(src) {
				w.b.WriteByte(src[i+1])
				i += 2
			} else {
				i++
			}
		default:
			w.bare = true
			w.b.WriteByte(c)
			i++
		}
	}
	return w.token(start, i), i
}

// segment is one simple command: the argument words between separators,
// with what it redirects and what feeds it.
type segment struct {
	words    []int // token indexes of argv words
	herestr  []int // token indexes of here-string words (bash "<<<")
	heredocs []int // token indexes of heredoc bodies
	outs     []int // token indexes of output redirection targets (">", ">>", "&>", ...)
	pipeFrom int   // index of the segment piping into this one, or -1
}

// segments groups tokens into simple commands. Redirection targets are not
// argv: "cmd > out.txt" must not shift a flag-value pairing.
func segments(toks []token) []segment {
	var segs []segment
	cur := segment{pipeFrom: -1}
	opSeg := map[int]int{}
	nextPipe := -1
	expectTarget := ""
	flush := func(op string) {
		if len(cur.words) > 0 || len(cur.herestr) > 0 || len(cur.heredocs) > 0 || len(cur.outs) > 0 || cur.pipeFrom >= 0 {
			segs = append(segs, cur)
		}
		idx := len(segs) - 1
		cur = segment{pipeFrom: -1}
		if (op == "|" || op == "|&") && idx >= 0 {
			nextPipe = idx
		} else {
			nextPipe = -1
		}
		cur.pipeFrom = nextPipe
	}
	for i, t := range toks {
		switch t.kind {
		case tComment:
			continue
		case tHeredoc:
			if s, ok := opSeg[t.owner]; ok {
				if s == len(segs) {
					cur.heredocs = append(cur.heredocs, i)
				} else if s >= 0 && s < len(segs) {
					segs[s].heredocs = append(segs[s].heredocs, i)
				}
			}
			continue
		case tOp:
			switch redir, target := redirection(t.val); {
			case redir:
				if target {
					expectTarget = strings.TrimLeft(t.val, "0123456789*")
				}
				opSeg[i] = len(segs)
			default:
				expectTarget = ""
				flush(t.val)
			}
			continue
		}
		if expectTarget != "" {
			op := expectTarget
			expectTarget = ""
			switch {
			case op == "<<<":
				cur.herestr = append(cur.herestr, i)
			case strings.HasPrefix(op, ">") || strings.HasPrefix(op, "&>") || op == "<>":
				cur.outs = append(cur.outs, i)
			}
			continue // a redirection target or heredoc delimiter
		}
		cur.words = append(cur.words, i)
	}
	flush("")
	return segs
}

// redirection reports whether op redirects, and whether a target word
// follows it ("2>&1" duplicates a descriptor and takes none).
func redirection(op string) (redir, target bool) {
	op = strings.TrimLeft(op, "0123456789*")
	switch op {
	case "<", ">", ">>", "<<", "<<-", "<<<", "<&", ">&", "<>", ">|", "&>", "&>>":
		return true, true
	}
	if n := len(op); n >= 3 && op[n-2] == '&' && (op[0] == '<' || op[0] == '>') {
		return true, false
	}
	return false, false
}
