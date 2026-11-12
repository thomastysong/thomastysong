package shellx

import "strings"

// interpDef describes how an interpreter is handed code on its command line.
type interpDef struct {
	lang    string
	kind    int
	code    []string            // flags followed by code
	cluster bool                // perl/ruby style: -pe 'code', -e'code', several -e
	short   string              // short flags that take a value
	long    map[string]struct{} // long flags that take a value
	module  string              // flag that runs a module as a program (python -m)
}

const (
	kindScript = iota // python, node, perl, ruby, php, lua, osascript
	kindShell         // sh, bash, zsh ...
	kindPwsh          // powershell, pwsh
	kindCmd           // cmd.exe
	kindAwk           // program text is the first positional
	kindDeno          // deno/bun: subcommands, URL scripts
	kindMshta         // mshta: URL or script-protocol argument
	kindWSH           // wscript/cscript: script file
)

var interpDefs = map[string]*interpDef{
	"sh": {lang: "sh", kind: kindShell}, "bash": {lang: "sh", kind: kindShell}, "zsh": {lang: "sh", kind: kindShell},
	"dash": {lang: "sh", kind: kindShell}, "ksh": {lang: "sh", kind: kindShell}, "mksh": {lang: "sh", kind: kindShell},
	"ash": {lang: "sh", kind: kindShell}, "fish": {lang: "sh", kind: kindShell}, "csh": {lang: "sh", kind: kindShell},
	"tcsh": {lang: "sh", kind: kindShell}, "rbash": {lang: "sh", kind: kindShell},

	"python": pyDef, "python2": pyDef, "python3": pyDef, "pypy": pyDef, "pypy3": pyDef, "py": pyDef,
	"node": nodeDef, "nodejs": nodeDef,
	"deno": {lang: "javascript", kind: kindDeno}, "bun": {lang: "javascript", kind: kindDeno},
	"perl": {lang: "perl", code: []string{"-e", "-E"}, cluster: true, short: "IMmFCD"},
	"ruby": {lang: "ruby", code: []string{"-e"}, cluster: true, short: "IrCFEKTW"},
	"php":  {lang: "php", code: []string{"-r", "--run", "-B", "-R", "-E"}, short: "dcfzFtS", long: longSet("--define", "--php-ini", "--file", "--server", "--docroot")},
	"lua":  {lang: "lua", code: []string{"-e"}, short: "l"}, "luajit": {lang: "lua", code: []string{"-e"}, short: "l"},
	"osascript": {lang: "applescript", code: []string{"-e"}, cluster: true, short: "ls"},
	"awk":       {lang: "awk", kind: kindAwk}, "gawk": {lang: "awk", kind: kindAwk}, "mawk": {lang: "awk", kind: kindAwk}, "nawk": {lang: "awk", kind: kindAwk},

	"powershell": {lang: "powershell", kind: kindPwsh}, "pwsh": {lang: "powershell", kind: kindPwsh},
	"powershell_ise": {lang: "powershell", kind: kindPwsh}, "pwsh-preview": {lang: "powershell", kind: kindPwsh},
	"cmd":   {lang: "cmd", kind: kindCmd},
	"mshta": {lang: "vbscript", kind: kindMshta},
	"wscript": {lang: "vbscript", kind: kindWSH}, "cscript": {lang: "vbscript", kind: kindWSH},
}

var pyDef = &interpDef{lang: "python", code: []string{"-c"}, short: "WXQ", long: longSet("--check-hash-based-pycs"), module: "-m"}

var nodeDef = &interpDef{
	lang: "javascript", code: []string{"-e", "--eval", "-p", "--print"}, short: "rC",
	long: longSet("--require", "--loader", "--import", "--experimental-loader", "--conditions", "--inspect-port",
		"--max-old-space-size", "--env-file", "--title", "--input-type", "--cpu-prof-dir", "--redirect-warnings"),
}

func interpFor(name string) *interpDef {
	if d, ok := interpDefs[name]; ok {
		return d
	}
	// Versioned binaries: python3.12, pypy3.10, php8.3, ruby3.2, lua5.4, node20.
	for _, p := range [...]struct {
		prefix string
		def    string
	}{{"python", "python"}, {"pypy", "python"}, {"php", "php"}, {"ruby", "ruby"}, {"lua", "lua"}, {"perl5", "perl"}} {
		if strings.HasPrefix(name, p.prefix) && len(name) > len(p.prefix) {
			rest := name[len(p.prefix):]
			ok := true
			for i := 0; i < len(rest); i++ {
				if !(rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
					ok = false
					break
				}
			}
			if ok {
				return interpDefs[p.def]
			}
		}
	}
	return nil
}

// inline records code handed to an interpreter.
func (a *analyzer) inline(lang, code string) {
	if code == "" || len(a.f.Inline) >= maxInline {
		return
	}
	if len(code) > maxInlineBytes {
		code = clip(code, maxInlineBytes)
		a.f.Truncated = true
	}
	for i := range a.f.Inline {
		if a.f.Inline[i].Lang == lang && a.f.Inline[i].Code == code {
			return
		}
	}
	a.f.Inline = append(a.f.Inline, InlineCode{Lang: lang, Code: code})
}

// runCode analyses code handed to interpreter name. t says how the code text
// was produced (downloaded, decoded ...).
func (a *analyzer) runCode(c *simple, d *interpDef, code string, t taint, dyn bool, in flow) {
	a.interpreter(c.name)
	if t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	a.obfTaint(t)
	origin := OriginInlinePrefix + c.name
	if t&tCoded != 0 {
		origin = OriginDecoded
		if !a.addDecoded(strings.TrimRight(code, "\n")) {
			// Not text, too large, or this payload was already analysed.
			return
		}
	} else {
		a.inline(d.lang, code)
	}
	switch d.kind {
	case kindShell:
		a.sub(code, Posix, origin, c.depth+1, in)
	case kindPwsh:
		a.sub(code, PowerShell, origin, c.depth+1, in)
	case kindCmd:
		a.sub(code, Cmd, origin, c.depth+1, in)
	default:
		a.foreign(d.lang, code, origin, c.depth+1)
	}
	_ = dyn
}

// interp handles a command that is an interpreter. delegated is true when an
// inner command ran instead (python -m pip ...).
func (a *analyzer) interp(c *simple, d *interpDef, in flow, out *flow) (flow, bool) {
	switch d.kind {
	case kindShell:
		a.shellInterp(c, d, in)
	case kindPwsh:
		a.pwshLaunch(c, d, in)
	case kindCmd:
		a.cmdLaunch(c, d, in)
	case kindAwk:
		a.awkInterp(c, d)
	case kindDeno:
		a.denoInterp(c, d, in)
	case kindMshta:
		a.mshta(c, d)
	case kindWSH:
		for _, p := range c.rest() {
			if strings.HasPrefix(p.s, "//") || strings.HasPrefix(p.s, "/") && len(p.s) < 12 {
				continue
			}
			a.ranFile(p.s)
			if strings.Contains(p.s, "://") {
				a.f.Downloads, a.f.DownloadAndExecute = true, true
			}
			break
		}
	default:
		return a.scriptInterp(c, d, in)
	}
	_ = out
	return noFlow(), false
}

// stdinCode handles an interpreter that reads its program from stdin.
func (a *analyzer) stdinCode(c *simple, d *interpDef, in flow) {
	static, t, has := c.input(a, in)
	if !has {
		return
	}
	if c.stdin == nil && in.piped {
		a.f.PipeToInterpreter = true
	}
	if c.stdin == nil && !in.piped && c.hasIn && c.inFile.proc {
		// sh < <(curl ...)
		a.f.PipeToInterpreter = true
	}
	a.interpreter(c.name)
	if t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	a.obfTaint(t)
	if static != nil {
		a.runCode(c, d, *static, t, false, noFlow())
	}
}

// scriptArg handles an interpreter given a script path.
func (a *analyzer) scriptArg(c *simple, script arg) {
	if script.proc {
		// bash <(curl ...): the "file" is a pipe from the inner commands.
		a.f.PipeToInterpreter = true
		a.interpreter(c.name)
		if script.t&tDownload != 0 {
			a.f.DownloadAndExecute = true
		}
		a.obfTaint(script.t)
		return
	}
	if script.s == "/dev/stdin" {
		return
	}
	a.ranFile(script.s)
}

func (a *analyzer) shellInterp(c *simple, d *interpDef, in flow) {
	args := c.rest()
	var code *arg
	stdinFlag := false
	i := 0
	for i < len(args) {
		s := args[i].s
		if s == "--" {
			i++
			break
		}
		if s == "-" {
			stdinFlag = true
			i++
			break
		}
		if args[i].proc || len(s) < 2 || (s[0] != '-' && s[0] != '+') {
			break
		}
		if strings.HasPrefix(s, "--") {
			if s == "--rcfile" || s == "--init-file" {
				i++
				if i < len(args) {
					a.scriptArg(c, args[i])
				}
			}
			i++
			continue
		}
		hasC := false
		takes := 0
		for j := 1; j < len(s); j++ {
			switch s[j] {
			case 'c':
				hasC = true
			case 's':
				stdinFlag = true
			case 'o', 'O':
				takes++
			}
		}
		i += 1 + takes
		if hasC {
			if i < len(args) {
				code = &args[i]
				i++
			}
			break
		}
	}
	if i > len(args) {
		i = len(args)
	}
	switch {
	case code != nil:
		// bash -c 'code' name arg1 ...: remaining words are $0, $1, ...
		restore := a.pushPositional(args[i:])
		a.pushEnv(c.env)
		a.runCode(c, d, code.s, code.t, code.dyn, in)
		restore()
	case !stdinFlag && i < len(args):
		a.scriptArg(c, args[i])
		if args[i].s == "/dev/stdin" {
			a.stdinCode(c, d, in)
		}
	default:
		a.stdinCode(c, d, in)
	}
}

// pushPositional makes $0, $1 ... resolvable inside inline code and returns a
// function that restores the previous values.
func (a *analyzer) pushPositional(args []arg) func() {
	type saved struct {
		name string
		v    value
		had  bool
	}
	var old []saved
	n := len(args)
	if n > 10 {
		n = 10
	}
	for i := 0; i < 10; i++ {
		name := string(rune('0' + i))
		v, had := a.vars[name]
		if had || i < n {
			old = append(old, saved{name, v, had})
		}
		if i < n {
			a.setVar(name, value{s: args[i].s, static: !args[i].dyn, t: args[i].t})
		} else if had {
			delete(a.vars, name)
		}
	}
	return func() {
		for _, s := range old {
			if s.had {
				a.vars[s.name] = s.v
			} else {
				delete(a.vars, s.name)
			}
		}
	}
}

// pushEnv exposes prefix assignments (FOO=bar bash -c '... $FOO') to the
// inline code. They stay visible afterwards, which over-approximates but
// never hides a resolvable value.
func (a *analyzer) pushEnv(env []envKV) {
	for _, kv := range env {
		a.setVar(kv.name, value{s: kv.val.s, static: !kv.val.dyn, t: kv.val.t})
	}
}

func (a *analyzer) scriptInterp(c *simple, d *interpDef, in flow) (flow, bool) {
	args := c.rest()
	var codes []arg
	isCode := func(s string) bool {
		for _, f := range d.code {
			if s == f {
				return true
			}
		}
		return false
	}
	i := 0
	script := -1
loop:
	for i < len(args) {
		s := args[i].s
		switch {
		case s == "--":
			i++
			if i < len(args) && len(codes) == 0 {
				script = i
			}
			break loop
		case s == "-":
			break loop
		case args[i].proc || len(s) < 2 || s[0] != '-':
			if len(codes) == 0 {
				script = i
			}
			break loop
		case d.module != "" && s == d.module:
			// python -m pip install x: the module is the program.
			if i+1 < len(args) {
				mod := args[i+1:]
				return a.runInner(c, mod, in, true, false), true
			}
			break loop
		case isCode(s):
			if i+1 < len(args) {
				codes = append(codes, args[i+1])
			}
			i += 2
			if !d.cluster {
				break loop
			}
		case strings.HasPrefix(s, "--"):
			if j := strings.IndexByte(s, '='); j > 0 {
				if isCode(s[:j]) {
					codes = append(codes, arg{s: s[j+1:], dyn: args[i].dyn, t: args[i].t})
				}
				i++
				continue
			}
			if _, ok := d.long[s]; ok {
				i++
			}
			i++
		default:
			// Short cluster. A value-taking letter ends it; an "e" hands
			// over code, attached or as the next word.
			consumed := false
			for j := 1; j < len(s); j++ {
				ch := s[j]
				if d.cluster && (ch == 'e' || (ch == 'E' && d.lang == "perl")) {
					if j+1 < len(s) {
						codes = append(codes, arg{s: s[j+1:], dyn: args[i].dyn, t: args[i].t})
					} else if i+1 < len(args) {
						codes = append(codes, args[i+1])
						i++
					}
					consumed = true
					break
				}
				if strings.IndexByte(d.short, ch) >= 0 {
					if j+1 >= len(s) {
						i++
					}
					consumed = true
					break
				}
				if !d.cluster && isCode("-"+string(ch)) && j+1 == len(s) {
					if i+1 < len(args) {
						codes = append(codes, args[i+1])
						i++
					}
					consumed = true
					break
				}
			}
			_ = consumed
			i++
		}
	}
	if len(codes) > 0 {
		lang := d.lang
		if d.lang == "applescript" && c.hasFold("javascript") {
			lang = "javascript"
		}
		var sb strings.Builder
		var t taint
		dyn := false
		for k, cd := range codes {
			if k > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(cd.s)
			t |= cd.t
			dyn = dyn || cd.dyn
		}
		dd := *d
		dd.lang = lang
		a.runCode(c, &dd, sb.String(), t, dyn, in)
		return noFlow(), false
	}
	if script >= 0 && script < len(args) {
		a.scriptArg(c, args[script])
		return noFlow(), false
	}
	a.stdinCode(c, d, in)
	return noFlow(), false
}

func (a *analyzer) awkInterp(c *simple, d *interpDef) {
	o := parseOpts(c.rest(), &optSpec{short: "Fvfi", long: longSet("--field-separator", "--assign", "--file", "--include"), posStop: true})
	for _, f := range o.all("-f", "--file") {
		a.read(f.s)
	}
	pos := o.pos
	if !o.has("-f", "--file") && len(pos) > 0 {
		prog := pos[0].s
		pos = pos[1:]
		if strings.Contains(prog, "system(") || strings.Contains(prog, "| getline") || strings.Contains(prog, "|getline") ||
			strings.Contains(prog, "| \"") || strings.Contains(prog, "|\"") {
			// Only awk programs that shell out are worth keeping as code.
			a.inline(d.lang, prog)
			a.foreign(d.lang, prog, OriginInlinePrefix+c.name, c.depth+1)
		}
	}
	for _, p := range pos {
		if !strings.Contains(p.s, "=") {
			a.read(p.s)
		}
	}
}

func (a *analyzer) denoInterp(c *simple, d *interpDef, in flow) {
	args := c.rest()
	for i := 0; i < len(args); i++ {
		s := args[i].s
		switch {
		case s == "eval" && c.name == "deno" || s == "-e" || s == "--eval" || s == "-p" || s == "--print":
			if i+1 < len(args) {
				a.runCode(c, d, args[i+1].s, args[i+1].t, args[i+1].dyn, in)
			}
			return
		case s == "run" || s == "x" && c.name == "bun":
			continue
		case s == "install" || s == "add" || s == "i" || s == "create" || s == "pm" || s == "remove" || s == "update" || s == "test" || s == "build" || s == "task" || s == "fmt" || s == "lint":
			return
		case s == "-":
			a.stdinCode(c, d, in)
			return
		case strings.HasPrefix(s, "-"):
			continue
		default:
			if strings.Contains(s, "://") {
				// deno run https://...: fetch and execute in one step.
				a.f.Downloads, a.f.DownloadAndExecute = true, true
				a.interpreter(c.name)
				return
			}
			a.scriptArg(c, args[i])
			return
		}
	}
	if in.piped || c.stdin != nil {
		a.stdinCode(c, d, in)
	}
}

func (a *analyzer) mshta(c *simple, d *interpDef) {
	rest := joinArgs(c.rest())
	l := strings.ToLower(rest)
	switch {
	case strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "ftp://") || strings.HasPrefix(l, "\\\\"):
		// mshta http://x/a.hta runs remote script.
		a.f.Downloads, a.f.DownloadAndExecute = true, true
		a.interpreter(c.name)
	}
	if i := strings.Index(l, "vbscript:"); i >= 0 {
		a.interpreter(c.name)
		a.inline("vbscript", rest[i+len("vbscript:"):])
		a.foreign("vbscript", rest[i+len("vbscript:"):], OriginInlinePrefix+c.name, c.depth+1)
	} else if i := strings.Index(l, "javascript:"); i >= 0 {
		a.interpreter(c.name)
		a.inline("javascript", rest[i+len("javascript:"):])
		a.foreign("javascript", rest[i+len("javascript:"):], OriginInlinePrefix+c.name, c.depth+1)
	}
	for _, p := range c.rest() {
		a.ranFile(p.s)
	}
}

// pwshLaunch handles "powershell [-opts] -Command ... | -EncodedCommand b64 |
// -File script" from any dialect. PowerShell accepts any unambiguous prefix
// of a parameter name and "/" as the dash.
func (a *analyzer) pwshLaunch(c *simple, d *interpDef, in flow) {
	args := c.rest()
	for i := 0; i < len(args); i++ {
		s := args[i].s
		if len(s) < 2 || (s[0] != '-' && s[0] != '/') {
			// First bare word: implicit -Command (Windows PowerShell) with
			// the rest of the line, or a script file.
			rest := args[i:]
			l := strings.ToLower(s)
			if len(rest) == 1 && (strings.HasSuffix(l, ".ps1") || strings.HasSuffix(l, ".psm1")) {
				a.scriptArg(c, rest[0])
				return
			}
			a.runCode(c, d, joinArgs(rest), anyTaint(rest), anyDyn(rest), in)
			return
		}
		if s == "-" {
			a.stdinCode(c, d, in)
			return
		}
		p := strings.ToLower(s[1:])
		val := ""
		if j := strings.IndexByte(p, ':'); j > 0 {
			p, val = p[:j], s[j+2:]
		}
		switch {
		case psPrefix(p, "encodedcommand", 1) || p == "ec":
			enc := val
			var t taint
			if enc == "" && i+1 < len(args) {
				enc, t = args[i+1].s, args[i+1].t
			}
			a.obf("encoded_command")
			a.interpreter(c.name)
			if raw, ok := decodeBase64(enc); ok {
				text, ok := decodeUTF16LE(raw)
				if !ok && textual(string(raw)) {
					text, ok = string(raw), true
				}
				if ok {
					if a.addDecoded(text) {
						a.sub(text, PowerShell, OriginDecoded, c.depth+1, in)
					}
				}
			}
			if t&tDownload != 0 {
				a.f.DownloadAndExecute = true
			}
			return
		case psPrefix(p, "command", 1):
			rest := args[i+1:]
			if val != "" {
				rest = append([]arg{{s: val}}, rest...)
			}
			if len(rest) == 1 && rest[0].s == "-" {
				a.stdinCode(c, d, in)
				return
			}
			if len(rest) > 0 {
				a.runCode(c, d, joinArgs(rest), anyTaint(rest), anyDyn(rest), in)
			}
			return
		case psPrefix(p, "file", 1):
			if i+1 < len(args) {
				a.scriptArg(c, args[i+1])
			}
			return
		case psPrefix(p, "windowstyle", 1):
			v := val
			if v == "" && i+1 < len(args) {
				v = args[i+1].s
				i++
			}
			if hasPrefixFold(v, "h") || v == "1" {
				a.f.Background = true
			}
		case psPrefix(p, "executionpolicy", 2) || p == "ep" || psPrefix(p, "inputformat", 2) || psPrefix(p, "outputformat", 1) ||
			psPrefix(p, "configurationname", 4) || psPrefix(p, "workingdirectory", 2) || p == "wd" || psPrefix(p, "version", 1) ||
			psPrefix(p, "settingsfile", 3) || psPrefix(p, "custompipename", 3) || psPrefix(p, "psconsolefile", 2) || psPrefix(p, "encodedarguments", 8):
			if val == "" {
				i++
			}
		}
	}
	if in.piped || c.stdin != nil {
		a.stdinCode(c, d, in)
	}
}

// psPrefix reports whether p is an abbreviation of full at least min long.
func psPrefix(p, full string, min int) bool {
	return len(p) >= min && len(p) <= len(full) && full[:len(p)] == p
}

// cmdLaunch handles "cmd /c ..." and "cmd /k ...".
func (a *analyzer) cmdLaunch(c *simple, d *interpDef, in flow) {
	args := c.rest()
	for i := 0; i < len(args); i++ {
		l := strings.ToLower(args[i].s)
		if l == "/c" || l == "/k" || l == "/r" || l == "-c" {
			rest := args[i+1:]
			if len(rest) > 0 {
				a.runCode(c, d, joinArgs(rest), anyTaint(rest), anyDyn(rest), in)
			}
			return
		}
		if strings.HasPrefix(l, "/c") && len(l) > 2 || strings.HasPrefix(l, "/k") && len(l) > 2 {
			// cmd /c"command": no space after the switch.
			rest := append([]arg{{s: args[i].s[2:], dyn: args[i].dyn, t: args[i].t}}, args[i+1:]...)
			a.runCode(c, d, joinArgs(rest), anyTaint(rest), anyDyn(rest), in)
			return
		}
		if !strings.HasPrefix(l, "/") {
			return
		}
	}
	if in.piped || c.stdin != nil {
		a.stdinCode(c, d, in)
	}
}

func init() {
	register(hEval, "eval")
	register(hSource, "source", ".")
	register(hTrapAlias, "trap", "alias")
}

func hEval(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix {
		return
	}
	a.f.Eval = true
	a.obf("eval")
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	t := anyTaint(rest)
	if t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	a.obfTaint(t)
	code := joinArgs(rest)
	origin := OriginEval
	if t&tCoded != 0 {
		origin = OriginDecoded
		if !a.addDecoded(code) {
			return
		}
	}
	a.sub(code, Posix, origin, c.depth+1, in)
}

func hSource(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix && c.name == "." {
		return
	}
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	f := rest[0]
	switch {
	case f.proc:
		a.f.PipeToInterpreter = true
		a.interpreter("source")
		if f.t&tDownload != 0 {
			a.f.DownloadAndExecute = true
		}
		a.obfTaint(f.t)
	case f.s == "/dev/stdin":
		if static, t, has := c.input(a, in); has {
			a.f.PipeToInterpreter = a.f.PipeToInterpreter || in.piped
			a.interpreter("source")
			if t&tDownload != 0 {
				a.f.DownloadAndExecute = true
			}
			a.obfTaint(t)
			if static != nil {
				a.runCode(c, interpDefs["sh"], *static, t, false, noFlow())
			}
		}
	default:
		a.ranFile(f.s)
	}
}

// hTrapAlias analyses code stored for later: trap handlers and alias bodies.
func hTrapAlias(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix {
		return
	}
	rest := c.rest()
	if c.name == "trap" {
		if len(rest) >= 2 && !strings.HasPrefix(rest[0].s, "-") && rest[0].s != "" {
			a.sub(rest[0].s, Posix, OriginEval, c.depth+1, noFlow())
		}
		return
	}
	for _, r := range rest {
		if _, body, ok := splitAssign(r.s); ok && body != "" {
			a.sub(body, Posix, OriginEval, c.depth+1, noFlow())
		}
	}
}
