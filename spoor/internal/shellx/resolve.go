package shellx

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// fieldBuilder assembles the fields one shell word expands to. It mirrors the
// shell's own order of operations closely enough for analysis: quote removal,
// parameter and command substitution with values known from the same command
// line, then field splitting of unquoted expansion results.
type fieldBuilder struct {
	a        *analyzer
	out      []arg
	cur      arg
	open     bool // cur is a field in progress (possibly empty but quoted)
	boundary bool // a quoting boundary sits right before the next text
	lastExp  bool // the last appended text came from an expansion
	nosplit  bool // the word is not field-split (assignment value, redirect target, heredoc)
}

func (b *fieldBuilder) appendStr(s string) {
	if len(b.cur.s)+len(s) > maxWord {
		room := maxWord - len(b.cur.s)
		if room < 0 {
			room = 0
		}
		s = clip(s, room)
		b.cur.dyn = true
		b.a.f.Truncated = true
	}
	b.cur.s += s
}

// text appends literal text; quoted text never splits or globs.
func (b *fieldBuilder) text(s string, quoted bool) {
	if quoted {
		b.cur.quoted = true
		b.open = true
	}
	if s == "" {
		return
	}
	if b.boundary && !b.lastExp && b.cur.s != "" && isAlnum(b.cur.s[len(b.cur.s)-1]) && isAlnum(s[0]) {
		// A quote boundary in the middle of a word: c'u'rl.
		b.cur.concat = true
	}
	b.boundary = false
	b.lastExp = false
	b.appendStr(s)
	b.open = true
}

// mark notes a quoting boundary between word parts.
func (b *fieldBuilder) mark() { b.boundary = true }

// expand appends the statically known result of an expansion. Unquoted
// results are field-split, which is how "c='curl -s x'; $c" becomes a command
// with arguments.
func (b *fieldBuilder) expand(s string, quoted bool, t taint) {
	b.boundary = false
	if quoted || b.nosplit {
		b.cur.exp = true
		b.cur.t |= t
		if quoted {
			b.cur.quoted = true
		}
		b.appendStr(s)
		b.open = true
		b.lastExp = true
		return
	}
	if s == "" {
		b.cur.exp = true
		b.cur.t |= t
		return
	}
	startWS, endWS := isSpace(s[0]), isSpace(s[len(s)-1])
	fields := strings.Fields(s)
	if len(fields) == 0 {
		b.brk()
		return
	}
	if startWS {
		b.brk()
	}
	for i, f := range fields {
		if i > 0 {
			b.brk()
		}
		b.cur.exp = true
		b.cur.t |= t
		b.appendStr(f)
		b.open = true
	}
	b.lastExp = true
	if endWS {
		b.brk()
	}
}

// dynamic appends the rendering of an expansion that could not be resolved.
func (b *fieldBuilder) dynamic(render string, t taint) {
	b.boundary = false
	b.cur.dyn = true
	b.cur.exp = true
	b.cur.t |= t
	b.appendStr(render)
	b.open = true
	b.lastExp = true
}

// brk ends the current field.
func (b *fieldBuilder) brk() {
	if b.open {
		if len(b.out) < maxList*4 {
			b.out = append(b.out, b.cur)
		} else {
			b.a.f.Truncated = true
		}
	}
	b.cur = arg{}
	b.open = false
	b.boundary = false
	b.lastExp = false
}

// fields resolves one word to the arguments it expands to.
func (w *walker) fields(word *syntax.Word) []arg {
	if word == nil {
		return nil
	}
	b := fieldBuilder{a: w.a}
	alts := w.braces(word)
	w.braced = len(alts) > 1
	if alts == nil {
		w.parts(&b, word.Parts, false)
		b.brk()
		return b.out
	}
	for _, parts := range alts {
		w.parts(&b, parts, false)
		b.brk()
	}
	return b.out
}

// single resolves a word that the shell does not field-split (assignment
// values, redirect targets, heredoc bodies, here-strings).
func (w *walker) single(word *syntax.Word) arg {
	if word == nil {
		return arg{}
	}
	b := fieldBuilder{a: w.a, nosplit: true}
	w.parts(&b, word.Parts, false)
	return b.cur
}

func (w *walker) parts(b *fieldBuilder, parts []syntax.WordPart, quoted bool) {
	for _, p := range parts {
		if !w.a.tick() {
			return
		}
		switch x := p.(type) {
		case *syntax.Lit:
			if quoted {
				b.text(unescapeDQ(x.Value), true)
				continue
			}
			s, glob, split := unescapeLit(x.Value)
			if glob {
				b.cur.glob = true
			}
			if split {
				b.cur.concat = true
			}
			b.text(s, false)
		case *syntax.SglQuoted:
			b.mark()
			v := x.Value
			if x.Dollar {
				var coded bool
				v, coded = unescapeC(v)
				if coded {
					b.cur.t |= tEsc
				}
			}
			b.text(v, true)
			b.mark()
		case *syntax.DblQuoted:
			b.mark()
			b.cur.quoted = true
			b.open = true
			w.parts(b, x.Parts, true)
			b.mark()
		case *syntax.ParamExp:
			w.param(b, x, quoted)
		case *syntax.CmdSubst:
			w.cmdSubst(b, x, quoted)
		case *syntax.ArithmExp:
			b.dynamic("$((...))", 0)
		case *syntax.ProcSubst:
			w.procSubst(b, x)
		case *syntax.ExtGlob:
			b.cur.glob = true
			pat := ""
			if x.Pattern != nil {
				pat = x.Pattern.Value
			}
			b.text(x.Op.String()+pat+")", false)
		case *syntax.BraceExp:
			// Only reached when expansion was refused for size.
			b.text(renderBrace(x), false)
		}
	}
}

// unescapeLit removes backslash escapes from an unquoted literal. glob
// reports an unescaped glob metacharacter; split reports a backslash between
// two alphanumerics (c\url), which only ever serves to break up a word.
func unescapeLit(s string) (out string, glob, split bool) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, strings.ContainsAny(s, "*?["), false
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '\n' {
				i++
				continue
			}
			if i > 0 && isAlnum(s[i-1]) && isAlnum(n) {
				split = true
			}
			sb.WriteByte(n)
			i++
			continue
		}
		if c == '*' || c == '?' || c == '[' {
			glob = true
		}
		sb.WriteByte(c)
	}
	return sb.String(), glob, split
}

// unescapeDQ removes the escapes that are live inside double quotes.
func unescapeDQ(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch n := s[i+1]; n {
			case '$', '`', '"', '\\':
				sb.WriteByte(n)
				i++
				continue
			case '\n':
				i++
				continue
			}
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func renderBrace(x *syntax.BraceExp) string {
	sep := ","
	if x.Sequence {
		sep = ".."
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, e := range x.Elems {
		if i > 0 {
			sb.WriteString(sep)
		}
		if e != nil {
			sb.WriteString(e.Lit())
		}
	}
	sb.WriteByte('}')
	return sb.String()
}

// braces expands brace expressions ({a,b}, {1..3}) into alternative part
// lists. It returns nil when the word has none. Brace expansion matters for
// analysis because {cat,/etc/passwd} is a way to write a command and its
// argument without a space.
func (w *walker) braces(word *syntax.Word) [][]syntax.WordPart {
	has := false
	for _, p := range word.Parts {
		if l, ok := p.(*syntax.Lit); ok && strings.IndexByte(l.Value, '{') >= 0 {
			has = true
			break
		}
	}
	if !has {
		return nil
	}
	cp := &syntax.Word{Parts: append([]syntax.WordPart(nil), word.Parts...)}
	if !syntax.SplitBraces(cp) {
		return nil
	}
	alts, ok := expandBraceParts(cp.Parts, maxBraceFields, 0)
	if !ok || len(alts) < 2 {
		return [][]syntax.WordPart{cp.Parts}
	}
	return alts
}

func expandBraceParts(parts []syntax.WordPart, limit, depth int) ([][]syntax.WordPart, bool) {
	if depth > 8 {
		return nil, false
	}
	res := [][]syntax.WordPart{nil}
	for _, p := range parts {
		be, isBrace := p.(*syntax.BraceExp)
		if !isBrace {
			for i := range res {
				res[i] = append(res[i], p)
			}
			continue
		}
		var alts [][]syntax.WordPart
		if be.Sequence {
			alts = braceSequence(be, limit)
			if alts == nil {
				return nil, false
			}
		} else {
			for _, e := range be.Elems {
				var sub [][]syntax.WordPart
				if e == nil || len(e.Parts) == 0 {
					sub = [][]syntax.WordPart{nil}
				} else {
					var ok bool
					sub, ok = expandBraceParts(e.Parts, limit, depth+1)
					if !ok {
						return nil, false
					}
				}
				alts = append(alts, sub...)
				if len(alts) > limit {
					return nil, false
				}
			}
		}
		if len(res)*len(alts) > limit {
			return nil, false
		}
		next := make([][]syntax.WordPart, 0, len(res)*len(alts))
		for _, r := range res {
			for _, al := range alts {
				n := make([]syntax.WordPart, 0, len(r)+len(al))
				n = append(n, r...)
				n = append(n, al...)
				next = append(next, n)
			}
		}
		res = next
	}
	return res, true
}

func braceSequence(be *syntax.BraceExp, limit int) [][]syntax.WordPart {
	if len(be.Elems) < 2 {
		return nil
	}
	from, to := be.Elems[0].Lit(), be.Elems[1].Lit()
	step := 1
	if len(be.Elems) > 2 {
		n, err := strconv.Atoi(be.Elems[2].Lit())
		if err != nil || n == 0 {
			return nil
		}
		if n < 0 {
			n = -n
		}
		step = n
	}
	var vals []string
	if x, err1 := strconv.Atoi(from); err1 == nil {
		y, err2 := strconv.Atoi(to)
		if err2 != nil {
			return nil
		}
		if x <= y {
			for v := x; v <= y && len(vals) <= limit; v += step {
				vals = append(vals, strconv.Itoa(v))
			}
		} else {
			for v := x; v >= y && len(vals) <= limit; v -= step {
				vals = append(vals, strconv.Itoa(v))
			}
		}
	} else if len(from) == 1 && len(to) == 1 {
		x, y := int(from[0]), int(to[0])
		if x <= y {
			for v := x; v <= y && len(vals) <= limit; v += step {
				vals = append(vals, string(rune(v)))
			}
		} else {
			for v := x; v >= y && len(vals) <= limit; v -= step {
				vals = append(vals, string(rune(v)))
			}
		}
	} else {
		return nil
	}
	if len(vals) == 0 || len(vals) > limit {
		return nil
	}
	out := make([][]syntax.WordPart, len(vals))
	for i, v := range vals {
		out[i] = []syntax.WordPart{&syntax.Lit{Value: v}}
	}
	return out
}

// param resolves a parameter expansion.
func (w *walker) param(b *fieldBuilder, p *syntax.ParamExp, quoted bool) {
	name := ""
	if p.Param != nil {
		name = p.Param.Value
	}
	if name == "" {
		b.dynamic("$", 0)
		return
	}
	plain := p.Flags == nil && !p.Excl && !p.Length && !p.Width && !p.IsSet &&
		p.NestedParam == nil && p.Index == nil && len(p.Modifiers) == 0 && p.Repl == nil && p.Names == 0

	// $IFS is whitespace unless the line reassigned it. Any use of it inside
	// a command is the classic way to avoid typing a space.
	if name == "IFS" && plain {
		if _, set := w.a.getVar("IFS"); !set {
			w.a.obf("ifs_abuse")
			if quoted || b.nosplit {
				b.text(" ", quoted)
			} else {
				b.brk()
			}
			return
		}
	}
	if p.Excl {
		// ${!name} is indirection by definition.
		w.a.obf("var_indirection")
		b.dynamic("$"+name, 0)
		return
	}
	if !plain {
		b.dynamic("$"+name, 0)
		return
	}
	v, known := w.a.getVar(name)
	if p.Slice != nil {
		if known && v.static {
			if s, ok := sliceValue(v.s, p.Slice); ok {
				b.expand(s, quoted, v.t)
				return
			}
		}
		b.dynamic("$"+name, v.t)
		return
	}
	if p.Exp == nil {
		if known && v.static {
			b.expand(v.s, quoted, v.t)
			return
		}
		b.dynamic("$"+name, v.t)
		return
	}
	// Operators with a word: resolve the word for its side effects (it may
	// hold a command substitution) and use it when the outcome is certain.
	var alt arg
	if p.Exp.Word != nil {
		alt = w.single(p.Exp.Word)
	}
	switch p.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
		if known && v.static && v.s != "" {
			b.expand(v.s, quoted, v.t)
			return
		}
		if known && v.static && v.s == "" && !alt.dyn {
			b.expand(alt.s, quoted, alt.t)
			return
		}
		b.dynamic("$"+name, v.t|alt.t)
	case syntax.AlternateUnset, syntax.AlternateUnsetOrNull:
		if known && v.static && v.s != "" && !alt.dyn {
			b.expand(alt.s, quoted, alt.t)
			return
		}
		b.dynamic("$"+name, v.t|alt.t)
	case syntax.ErrorUnset, syntax.ErrorUnsetOrNull:
		if known && v.static && v.s != "" {
			b.expand(v.s, quoted, v.t)
			return
		}
		b.cur.guard = true
		b.dynamic("$"+name, v.t)
	default:
		b.dynamic("$"+name, v.t)
	}
}

// sliceValue applies ${v:off:len} when both are plain integers. Substring
// tricks such as ${PATH:0:1} are used to produce "/" without typing it.
func sliceValue(s string, sl *syntax.Slice) (string, bool) {
	num := func(e syntax.ArithmExpr) (int, bool) {
		if e == nil {
			return 0, false
		}
		wd, ok := e.(*syntax.Word)
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(wd.Lit())
		return n, err == nil
	}
	off, ok := num(sl.Offset)
	if !ok || off < 0 || off > len(s) {
		return "", false
	}
	if sl.Length == nil {
		return s[off:], true
	}
	n, ok := num(sl.Length)
	if !ok || n < 0 {
		return "", false
	}
	if off+n > len(s) {
		n = len(s) - off
	}
	return s[off : off+n], true
}

// cmdSubst analyses $(...) and substitutes its output when it is static.
func (w *walker) cmdSubst(b *fieldBuilder, cs *syntax.CmdSubst, quoted bool) {
	sub, ok := w.child(OriginSubstitution)
	if !ok {
		b.dynamic("$(...)", 0)
		return
	}
	out := sub.stmts(cs.Stmts, noFlow(), true)
	if out.static != nil {
		s := strings.TrimRight(*out.static, "\n")
		if out.t&tPayload != 0 {
			w.a.sinkDecoded(s, w.depth)
		}
		b.expand(s, quoted, out.t)
		return
	}
	b.dynamic("$(...)", out.t)
}

// procSubst analyses <(...) and >(...). The argument is a file name chosen by
// the shell, so it is rendered symbolically; what matters is the taint of
// what the inner commands produce.
func (w *walker) procSubst(b *fieldBuilder, ps *syntax.ProcSubst) {
	render := "<(...)"
	if ps.Op == syntax.CmdOut {
		render = ">(...)"
	}
	sub, ok := w.child(OriginSubstitution)
	if !ok {
		b.dynamic(render, 0)
		b.cur.proc = true
		return
	}
	out := sub.stmts(ps.Stmts, noFlow(), true)
	if out.static != nil && out.t&tPayload != 0 {
		w.a.sinkDecoded(*out.static, w.depth)
	}
	b.dynamic(render, out.t)
	b.cur.proc = true
}
