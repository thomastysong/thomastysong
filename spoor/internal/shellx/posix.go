package shellx

import (
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// Parsers are reused because allocation dominates short inputs; a Parser is
// safe to reuse sequentially, which the pool guarantees.
var parserPool = sync.Pool{New: func() any {
	return syntax.NewParser(syntax.Variant(syntax.LangBash))
}}

// walker walks a bash AST and lowers it to simple commands.
type walker struct {
	a      *analyzer
	src    string
	origin string
	depth  int
	braced bool // the last word resolved by fields() was brace-expanded
}

func (w *walker) child(origin string) (*walker, bool) {
	if w.depth+1 > MaxDepth {
		w.a.f.Truncated = true
		return nil, false
	}
	return &walker{a: w.a, src: w.src, origin: origin, depth: w.depth + 1}, true
}

// posix analyses src as POSIX/bash code.
func (a *analyzer) posix(src string, origin string, depth int, in flow) flow {
	if parserHostile(src) {
		// Pathological nesting makes the recursive-descent parser spend
		// seconds growing its stack. No real command line looks like this,
		// so do not hand it over.
		a.f.ParseOK = false
		a.obf("deep_nesting")
		return a.posixFallback(src, origin, depth, in)
	}
	p := parserPool.Get().(*syntax.Parser)
	file, err := p.Parse(strings.NewReader(src), "")
	// Not deferred: a parser that panicked must not go back into the pool.
	parserPool.Put(p)
	if err != nil || file == nil {
		a.f.ParseOK = false
		return a.posixFallback(src, origin, depth, in)
	}
	w := &walker{a: a, src: src, origin: origin, depth: depth}
	return w.stmts(file.Stmts, in, false)
}

// parserHostile is a cheap lexical pre-check for inputs built to make the
// parser recurse deeply. It ignores quoting, so it over-counts; that only
// costs precision on inputs nobody writes by hand.
func parserHostile(s string) bool {
	depth, maxDepth, kw := 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')', '}':
			if depth > 0 {
				depth--
			}
		case 'i':
			if strings.HasPrefix(s[i:], "if ") {
				kw++
			}
		case 'w':
			if strings.HasPrefix(s[i:], "while ") {
				kw++
			}
		case 'u':
			if strings.HasPrefix(s[i:], "until ") {
				kw++
			}
		case 't':
			if strings.HasPrefix(s[i:], "time ") {
				kw++
			}
		case '`':
			kw++
		}
		if maxDepth > maxParserNest || kw > maxParserKw {
			return true
		}
	}
	return false
}

// stmts walks a statement list. With capture set and exactly one statement,
// the statement's output stream is returned for the caller to substitute;
// otherwise decoded payloads that nothing consumed are analysed here.
func (w *walker) stmts(list []*syntax.Stmt, in flow, capture bool) flow {
	out := noFlow()
	for i, s := range list {
		fl := w.stmt(s, in)
		if i == 0 {
			out.rep = fl.rep
		}
		if capture && len(list) == 1 {
			return fl
		}
		out.t |= fl.t
		if fl.static != nil && fl.t&tPayload != 0 {
			w.a.sinkDecoded(*fl.static, w.depth)
		}
		if w.a.work < 0 {
			break
		}
	}
	return out
}

func (w *walker) stmt(s *syntax.Stmt, in flow) flow {
	a := w.a
	if s == nil || !a.tick() {
		return noFlow()
	}
	a.nest++
	defer func() { a.nest-- }()
	if a.nest > maxNest {
		a.f.Truncated = true
		return noFlow()
	}
	if s.Background || s.Coprocess || s.Disown {
		a.f.Background = true
	}
	out := noFlow()
	switch x := s.Cmd.(type) {
	case nil:
		w.redirs(s.Redirs, nil, true)
		return out
	case *syntax.CallExpr:
		return w.call(x, s, in)
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			out = w.pipeline(s, in)
		} else {
			out = w.andOr(s, in)
		}
	case *syntax.Subshell:
		if sub, ok := w.child(OriginSubshell); ok {
			out = sub.stmts(x.Stmts, in, false)
		}
	case *syntax.Block:
		out = w.stmts(x.Stmts, in, false)
	case *syntax.IfClause:
		for c := x; c != nil; c = c.Else {
			w.stmts(c.Cond, in, false)
			fl := w.stmts(c.Then, in, false)
			out.t |= fl.t
			if !a.tick() {
				break
			}
		}
	case *syntax.WhileClause:
		w.stmts(x.Cond, in, false)
		out = w.stmts(x.Do, in, false)
	case *syntax.ForClause:
		w.loopVars(x.Loop)
		out = w.stmts(x.Do, in, false)
	case *syntax.CaseClause:
		if x.Word != nil {
			w.single(x.Word)
		}
		for _, it := range x.Items {
			fl := w.stmts(it.Stmts, in, false)
			out.t |= fl.t
		}
	case *syntax.FuncDecl:
		w.stmt(x.Body, noFlow())
	case *syntax.TimeClause:
		out = w.stmt(x.Stmt, in)
	case *syntax.CoprocClause:
		a.f.Background = true
		out = w.stmt(x.Stmt, in)
	case *syntax.DeclClause:
		out = w.decl(x, s, in)
	case *syntax.TestClause:
		w.testExpr(x.X, 0)
	case *syntax.TestDecl:
		w.stmt(x.Body, noFlow())
	}
	if len(s.Redirs) > 0 {
		if _, isDecl := s.Cmd.(*syntax.DeclClause); !isDecl {
			w.redirs(s.Redirs, nil, false)
		}
	}
	return out
}

// pipeline walks "a | b | c". The AST nests pipelines to the left, so the
// stages are collected iteratively to keep the Go stack flat on inputs with
// thousands of stages.
func (w *walker) pipeline(s *syntax.Stmt, in flow) flow {
	a := w.a
	var stages []*syntax.Stmt
	cur := s
	for {
		b, ok := cur.Cmd.(*syntax.BinaryCmd)
		if !ok || (b.Op != syntax.Pipe && b.Op != syntax.PipeAll) {
			stages = append(stages, cur)
			break
		}
		stages = append(stages, b.Y)
		cur = b.X
		if len(stages) > maxCommands {
			a.f.Truncated = true
			break
		}
	}
	fl := in
	first := -1
	var reps []int
	for i := len(stages) - 1; i >= 0; i-- {
		before := len(a.f.Commands)
		out := w.stmtKeep(stages[i], fl)
		rep := out.rep
		if rep < 0 && len(a.f.Commands) > before {
			rep = before
		}
		if rep >= 0 {
			reps = append(reps, rep)
			if first < 0 {
				first = rep
			}
		}
		out.piped = true
		fl = out
		if a.work < 0 {
			break
		}
	}
	if len(reps) >= 2 && len(a.f.Pipelines) < maxList {
		a.f.Pipelines = append(a.f.Pipelines, reps)
	}
	fl.piped = false
	fl.rep = first
	return fl
}

// stmtKeep is stmt for pipeline stages: a simple command's static output must
// survive to the next stage, which stmt drops for compound commands.
func (w *walker) stmtKeep(s *syntax.Stmt, in flow) flow {
	if s == nil {
		return noFlow()
	}
	if c, ok := s.Cmd.(*syntax.CallExpr); ok {
		if !w.a.tick() {
			return noFlow()
		}
		if s.Background {
			w.a.f.Background = true
		}
		return w.call(c, s, in)
	}
	return w.stmt(s, in)
}

// andOr walks "a && b || c" left to right without recursion on the chain.
func (w *walker) andOr(s *syntax.Stmt, in flow) flow {
	a := w.a
	var chain []*syntax.Stmt
	cur := s
	for {
		b, ok := cur.Cmd.(*syntax.BinaryCmd)
		if !ok || b.Op == syntax.Pipe || b.Op == syntax.PipeAll {
			chain = append(chain, cur)
			break
		}
		chain = append(chain, b.Y)
		cur = b.X
		if len(chain) > maxCommands {
			a.f.Truncated = true
			break
		}
	}
	out := noFlow()
	for i := len(chain) - 1; i >= 0; i-- {
		fl := w.stmtKeep(chain[i], in)
		if i == len(chain)-1 {
			out.rep = fl.rep
		}
		out.t |= fl.t
		if fl.static != nil && fl.t&tPayload != 0 {
			a.sinkDecoded(*fl.static, w.depth)
		}
		if a.work < 0 {
			break
		}
	}
	return out
}

func (w *walker) loopVars(l syntax.Loop) {
	switch x := l.(type) {
	case *syntax.WordIter:
		if x.Name != nil {
			// The loop variable takes several values; treat it as unknown.
			w.a.setVar(x.Name.Value, value{})
		}
		for _, it := range x.Items {
			w.fields(it)
		}
	}
}

func (w *walker) testExpr(e syntax.TestExpr, depth int) {
	if e == nil || depth > 64 || !w.a.tick() {
		return
	}
	switch x := e.(type) {
	case *syntax.Word:
		w.single(x)
	case *syntax.BinaryTest:
		w.testExpr(x.X, depth+1)
		w.testExpr(x.Y, depth+1)
	case *syntax.UnaryTest:
		w.testExpr(x.X, depth+1)
	case *syntax.ParenTest:
		w.testExpr(x.X, depth+1)
	}
}

func (w *walker) rawWord(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	s, e := int(word.Pos().Offset()), int(word.End().Offset())
	if s < 0 || e > len(w.src) || s >= e {
		return ""
	}
	return clip(w.src[s:e], 1024)
}

// assign records "name=value" and returns the resolved value.
func (w *walker) assign(as *syntax.Assign) (string, arg) {
	a := w.a
	if as == nil || as.Name == nil {
		if as != nil && as.Value != nil {
			w.fields(as.Value)
		}
		return "", arg{}
	}
	name := as.Name.Value
	var r arg
	v := value{static: true}
	switch {
	case as.Array != nil:
		for _, e := range as.Array.Elems {
			if e != nil && e.Value != nil {
				w.fields(e.Value)
			}
		}
		v.static = false
		r.dyn = true
	case as.Value != nil:
		r = w.single(as.Value)
		v = value{s: r.s, static: !r.dyn, t: r.t}
	}
	if as.Append {
		if old, ok := a.getVar(name); ok && old.static && v.static {
			v.s = old.s + v.s
			v.t |= old.t
		} else {
			v.static = false
		}
	}
	if as.Index != nil {
		v.static = false
	}
	a.setVar(name, v)
	return name, r
}

func (w *walker) call(c *syntax.CallExpr, s *syntax.Stmt, in flow) flow {
	a := w.a
	if len(c.Args) == 0 {
		for _, as := range c.Assigns {
			if name, v := w.assign(as); name != "" {
				a.envAssign(name)
				a.assignFacts(name, v)
			}
		}
		w.redirs(s.Redirs, nil, len(c.Assigns) == 0)
		return noFlow()
	}
	sc := &simple{origin: w.origin, depth: w.depth, dialect: Posix, bg: s.Background, idx: -1}
	for _, as := range c.Assigns {
		if as == nil || as.Name == nil {
			continue
		}
		// A prefix assignment only reaches the command's environment, not
		// later expansions on the line, so it is not stored as a variable.
		var v arg
		if as.Value != nil {
			v = w.single(as.Value)
		}
		sc.env = append(sc.env, envKV{name: as.Name.Value, val: v})
	}
	for i, wd := range c.Args {
		fs := w.fields(wd)
		if i == 0 && w.braced && len(fs) > 1 {
			// {cat,/etc/passwd}: a command and its arguments with no space.
			a.obf("ifs_abuse")
		}
		sc.args = append(sc.args, fs...)
		if len(sc.args) > 8*maxList {
			a.f.Truncated = true
			break
		}
	}
	if len(sc.args) == 0 {
		w.redirs(s.Redirs, nil, false)
		return noFlow()
	}
	sc.raw = w.rawWord(c.Args[0])
	w.redirs(s.Redirs, sc, false)
	return a.runSimple(sc, in)
}

// decl handles export/declare/local/readonly/typeset as a command plus its
// assignments.
func (w *walker) decl(d *syntax.DeclClause, s *syntax.Stmt, in flow) flow {
	a := w.a
	if d.Variant == nil {
		return noFlow()
	}
	sc := &simple{origin: w.origin, depth: w.depth, dialect: Posix, idx: -1, raw: d.Variant.Value}
	sc.args = append(sc.args, arg{s: d.Variant.Value})
	for _, as := range d.Args {
		if as == nil {
			continue
		}
		if as.Name == nil {
			if as.Value != nil {
				sc.args = append(sc.args, w.fields(as.Value)...)
			}
			continue
		}
		if as.Naked {
			sc.args = append(sc.args, arg{s: as.Name.Value})
			continue
		}
		name, v := w.assign(as)
		a.envAssign(name)
		a.assignFacts(name, v)
		v.s = name + "=" + v.s
		sc.args = append(sc.args, v)
	}
	w.redirs(s.Redirs, sc, false)
	return a.runSimple(sc, in)
}

// redirs records redirections. With sc set, stdin/stdout redirections are
// attached to the command so its handler can use them; bare means the
// statement is nothing but redirections ("> file").
func (w *walker) redirs(list []*syntax.Redirect, sc *simple, bare bool) {
	a := w.a
	for _, r := range list {
		if r == nil || !a.tick() {
			return
		}
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			a.f.HereDoc = true
			if r.Hdoc != nil && sc != nil {
				body := w.single(r.Hdoc)
				s := body.s
				sc.stdin, sc.stdinT = &s, body.t
			} else if r.Hdoc != nil {
				w.single(r.Hdoc)
			}
		case syntax.WordHdoc:
			if r.Word == nil {
				continue
			}
			v := w.single(r.Word)
			if sc != nil {
				s := v.s + "\n"
				sc.stdin, sc.stdinT = &s, v.t
			}
		case syntax.RdrIn, syntax.RdrInOut:
			if r.Word == nil {
				continue
			}
			t := w.single(r.Word)
			if !t.proc {
				a.read(t.s)
			}
			if sc != nil && (r.N == nil || r.N.Value == "0") {
				sc.inFile, sc.hasIn = t, true
			}
		case syntax.DplIn:
			// <&N duplicates a descriptor; nothing to record.
		case syntax.DplOut:
			if r.Word == nil {
				continue
			}
			t := w.single(r.Word)
			if isDigits(t.s) || t.s == "-" || t.proc {
				continue
			}
			// ">& file" is bash for "both streams to file".
			w.outRedir(t, false, true, sc, bare)
		default:
			if r.Word == nil {
				continue
			}
			t := w.single(r.Word)
			if t.proc {
				continue
			}
			app := r.Op == syntax.AppOut || r.Op == syntax.AppAll || r.Op == syntax.AppClob || r.Op == syntax.AppAllClob
			all := r.Op == syntax.RdrAll || r.Op == syntax.AppAll || r.Op == syntax.RdrAllClob || r.Op == syntax.AppAllClob
			stdout := all || r.N == nil || r.N.Value == "1"
			w.outRedir(t, app, stdout, sc, bare)
		}
	}
}

func (w *walker) outRedir(t arg, app, stdout bool, sc *simple, bare bool) {
	a := w.a
	if sc != nil && stdout {
		// Recorded by runSimple's tail once the handler knows the content.
		sc.outFile, sc.hasOut, sc.outAppend = t, true, app
		return
	}
	mode := mWrite
	if app {
		mode = mAppend
	}
	a.use(t.s, mode)
	if h, ok := devTCPHost(t.s); ok && !isLoopback(cleanHost(h)) {
		a.exfil("netcat_out")
	}
	if bare && !app && !pseudoPath(t.s) {
		a.destructive("truncate_file")
	}
}
