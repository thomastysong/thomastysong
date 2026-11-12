package shellx

import "strings"

// handler derives facts from one simple command. out is the stream the
// command writes to its stdout; handlers that know the content set it.
type handler func(a *analyzer, c *simple, in flow, out *flow)

// Wrapper outcomes.
const (
	wrapNone      = iota // not acting as a wrapper this time; run the normal handlers
	wrapDelegated        // an inner simple command ran in place of the wrapper
	wrapReparsed         // a command string was re-analysed; the wrapper's own redirects still apply
)

// wrapper unwraps commands that take another command (sudo, env, xargs ...).
type wrapper func(a *analyzer, c *simple, in flow) (flow, int)

// handlers and wrappers map a command name to what it implies. They are
// filled by the register* functions that buildTables (tables.go) runs on the
// first Analyze.
var (
	handlers map[string]handler
	wrappers map[string]wrapper
)

func register(h handler, names ...string) {
	for _, n := range names {
		handlers[n] = h
	}
}

func registerWrap(w wrapper, names ...string) {
	for _, n := range names {
		wrappers[n] = w
	}
}

func (a *analyzer) addCommand(c *simple) int {
	if len(a.f.Commands) >= maxCommands {
		a.f.Truncated = true
		return -1
	}
	cmd := Command{Name: c.name, Path: c.raw, Origin: c.origin, Dynamic: c.args[0].dyn || c.tail}
	if cmd.Path == "" {
		cmd.Path = c.args[0].s
	}
	rest := c.args[1:]
	if len(rest) > maxList*2 {
		rest = rest[:maxList*2]
		a.f.Truncated = true
	}
	if len(rest) > 0 {
		cmd.Args = make([]string, len(rest))
		for i := range rest {
			cmd.Args[i] = rest[i].s
			if rest[i].dyn {
				cmd.Dynamic = true
			}
		}
	}
	a.f.Commands = append(a.f.Commands, cmd)
	return len(a.f.Commands) - 1
}

// runSimple records one simple command and everything it implies. in is the
// stream on its stdin when it is a pipeline stage.
func (a *analyzer) runSimple(c *simple, in flow) flow {
	if len(c.args) == 0 || !a.tick() {
		return noFlow()
	}
	head := c.args[0]
	c.name = commandName(head)
	prevDial, prevCur := a.dial, a.cur
	a.dial, a.cur = c.dialect, c
	defer func() { a.dial, a.cur = prevDial, prevCur }()
	c.idx = a.addCommand(c)
	if c.idx < 0 {
		return noFlow()
	}
	// A stage downstream of a download or decoder stays tainted unless a
	// handler knows better: "curl x | tr -d '\r' | sh" is still download
	// and execute.
	out := flow{rep: c.idx, t: in.t}

	// A command name taken from a variable is ordinary scripting when the
	// variable holds a path ("OSQ=/opt/osquery/bin/osqueryd; $OSQ -S").
	// It hides the tool when the value is unknown, assembled, or a bare
	// tool name ("x=curl; $x http://... | sh").
	if head.dyn || (head.exp && (head.concat || !strings.ContainsAny(head.s, "/\\"))) {
		a.obf("var_indirection")
	}
	if head.concat {
		a.obf("char_concat")
	}
	a.obfTaint(head.t & tCoded)
	if head.t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	for i := range c.env {
		a.envAssign(c.env[i].name)
		a.assignFacts(c.env[i].name, c.env[i].val)
	}
	if c.bg {
		a.f.Background = true
	}
	if strings.ContainsAny(head.s, "/\\") {
		a.ranFile(head.s)
	}
	a.scanArgs(c)

	if w, ok := wrappers[c.name]; ok {
		if c.wraps >= maxWrapChain {
			a.f.Truncated = true
		} else {
			res, mode := w(a, c, in)
			switch mode {
			case wrapDelegated:
				if res.rep < 0 {
					res.rep = c.idx
				}
				return res
			case wrapReparsed:
				res.rep = c.idx
				a.tail(c, &res)
				return res
			}
		}
	}
	if d := interpFor(c.name); d != nil {
		if res, delegated := a.interp(c, d, in, &out); delegated {
			if res.rep < 0 {
				res.rep = c.idx
			}
			return res
		}
	}
	if h := pick(c); h != nil {
		h(a, c, in, &out)
	}
	a.tail(c, &out)
	return out
}

// tail applies the command's stdout redirect to what the handlers decided
// the command writes.
func (a *analyzer) tail(c *simple, out *flow) {
	if !c.hasOut {
		return
	}
	target := c.outFile.s
	text := ""
	if out.static != nil {
		text = *out.static
	}
	mode := mWrite
	if c.outAppend {
		mode = mAppend
	}
	a.useText(target, mode, text)
	if h, ok := devTCPHost(target); ok {
		if !isLoopback(cleanHost(h)) {
			a.exfil("netcat_out")
		}
	}
	if out.t&(tDownload|tCoded) != 0 {
		a.drop(target, out.t)
	}
	if out.static != nil {
		if out.t&tPayload != 0 {
			a.sinkDecoded(*out.static, c.depth)
		}
		if *out.static == "" && !c.outAppend && !pseudoPath(target) {
			// ": > file", "cat /dev/null > file", "echo -n > file".
			a.destructive("truncate_file")
		}
	}
	// Nothing flows on to the next pipeline stage.
	out.static = nil
	out.t = 0
}

// runInner runs args as the command a wrapper executes.
func (a *analyzer) runInner(c *simple, args []arg, in flow, keepIn, tail bool) flow {
	if len(args) == 0 {
		return noFlow()
	}
	if c.wraps >= maxWrapChain {
		a.f.Truncated = true
		return noFlow()
	}
	inner := &simple{
		args: args, raw: args[0].s, origin: OriginWrapper, depth: c.depth, wraps: c.wraps + 1,
		dialect: c.dialect, bg: c.bg, idx: -1, tail: tail,
		hasOut: c.hasOut, outFile: c.outFile, outAppend: c.outAppend,
	}
	in2 := noFlow()
	if keepIn {
		in2 = in
		inner.stdin, inner.stdinT, inner.inFile, inner.hasIn = c.stdin, c.stdinT, c.inFile, c.hasIn
	}
	return a.runSimple(inner, in2)
}

// sub analyses src as code of dialect d one nesting level down.
func (a *analyzer) sub(src string, d Dialect, origin string, depth int, in flow) flow {
	if depth > MaxDepth || a.subs >= maxSubAnalyses {
		a.f.Truncated = true
		return noFlow()
	}
	a.subs++
	if len(src) > maxAnalyzeText {
		src = clip(src, maxAnalyzeText)
		a.f.Truncated = true
	}
	if strings.TrimSpace(src) == "" {
		return noFlow()
	}
	// Code run by another process (sh -c, a substitution, a decoded
	// payload) starts in this directory and cannot change it.
	saved := a.saveCwd()
	defer a.restoreCwd(saved)
	switch d {
	case PowerShell:
		return a.powershell(src, origin, depth, in)
	case Cmd:
		return a.cmdexe(src, origin, depth, in)
	default:
		return a.posix(src, origin, depth, in)
	}
}

// addDecoded records recovered text. It reports false when the text is not
// worth keeping (binary, oversized) or was already recorded.
func (a *analyzer) addDecoded(s string) bool {
	if len(s) > MaxDecoded {
		a.f.Truncated = true
		return false
	}
	if !textual(s) {
		return false
	}
	if _, seen := a.decoded[s]; seen {
		return false
	}
	if a.decoded == nil {
		a.decoded = make(map[string]struct{})
	}
	if len(a.decoded) >= maxInline {
		return false
	}
	a.decoded[s] = struct{}{}
	a.f.Decoded = append(a.f.Decoded, s)
	return true
}

// sinkDecoded handles a decoded payload that no interpreter consumed on this
// command line: it is still analysed, because decoding a script and running
// it later is the same attack in two steps.
func (a *analyzer) sinkDecoded(s string, depth int) {
	s = strings.TrimRight(s, "\n")
	if !a.addDecoded(s) {
		return
	}
	a.sub(s, detectDialect(s), OriginDecoded, depth+1, noFlow())
}

// input returns what the command reads on stdin: a heredoc or here-string
// first, then the pipe, then a redirected file.
func (c *simple) input(a *analyzer, in flow) (static *string, t taint, has bool) {
	if c.stdin != nil {
		return c.stdin, c.stdinT, true
	}
	if in.piped {
		return in.static, in.t, true
	}
	if c.hasIn {
		t := c.inFile.t
		if dt, ok := a.droppedTaint(c.inFile.s); ok {
			t |= dt
		}
		return nil, t, true
	}
	return nil, 0, false
}

// scanArgs collects the facts that do not depend on which command it is.
func (a *analyzer) scanArgs(c *simple) {
	for i := range c.args {
		s := c.args[i].s
		if len(s) < 6 {
			continue
		}
		if strings.Contains(s, "://") {
			a.scanURLs(s)
		}
		if len(s) >= longTokenBytes && !strings.ContainsAny(s, " \t\n") {
			a.obf("long_single_token")
		}
		if strings.Contains(s, "/dev/tcp/") || strings.Contains(s, "/dev/udp/") {
			a.scanDevTCP(s)
		}
		if setsDisableAllHooks(s) {
			a.evasion("agent_hook_tamper")
		}
	}
}

func (a *analyzer) scanDevTCP(s string) {
	for _, pre := range []string{"/dev/tcp/", "/dev/udp/"} {
		rest := s
		for n := 0; n < 4; n++ {
			i := strings.Index(rest, pre)
			if i < 0 {
				break
			}
			end := i
			for end < len(rest) && !isSpace(rest[end]) && rest[end] != '\'' && rest[end] != '"' && rest[end] != ';' {
				end++
			}
			if h, ok := devTCPHost(rest[i:end]); ok {
				a.host(h)
			}
			rest = rest[end:]
		}
	}
}

// setsDisableAllHooks reports text that turns agent hooks off:
// "disableAllHooks": true, disableAllHooks=true, .disableAllHooks = true.
func setsDisableAllHooks(s string) bool {
	rest := s
	for n := 0; n < 4; n++ {
		i := indexFold(rest, "disableallhooks")
		if i < 0 {
			return false
		}
		j := i + len("disableallhooks")
		for j < len(rest) && strings.IndexByte("\"' :=\\\t", rest[j]) >= 0 {
			j++
		}
		if hasPrefixFold(rest[j:], "true") || hasPrefixFold(rest[j:], "1") || hasPrefixFold(rest[j:], "$true") {
			return true
		}
		rest = rest[j:]
	}
	return false
}

// assignFacts derives facts from a variable assignment.
func (a *analyzer) assignFacts(name string, v arg) {
	switch name {
	case "HISTFILE":
		if !v.dyn && (v.s == "" || v.s == "/dev/null") {
			a.evasion("history_clear")
		}
	case "HISTSIZE", "HISTFILESIZE", "SAVEHIST":
		if v.s == "0" {
			a.evasion("history_clear")
		}
	}
}
