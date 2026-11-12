package mcpconf

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// maxUnwrap bounds how many wrappers (env, sudo, sh -c, cmd /c, op run ...)
// are looked through before the launch is taken as it stands.
const maxUnwrap = 6

// launch is what a stdio declaration does when the client starts it, read
// from the words alone.
type launch struct {
	declCmd  string   // executable as declared, after splitting a one-string command line
	declArgs []string // its arguments as declared

	cmd  string   // effective executable after looking through wrappers
	args []string // its arguments
	dir  string   // working directory the launch line itself selects (uv --directory, cd X &&)

	runner string  // event.MCP.Runner vocabulary
	eco    string  // npm | pypi | oci | ""
	spec   pkgSpec // primary package or image
	has    bool    // spec is set

	fetch    bool // code is resolved from a registry or the network at launch
	unpinned bool // at least one fetched spec can change under the same declaration
	latest   bool // container image is re-resolved at launch (untagged, :latest, --pull=always)

	script string   // local file or directory whose code is executed, when the launch names one
	rest   []string // the server's own arguments
	shell  bool     // a shell interprets the launch line
	inline []string // shell text seen on the way (sh -c scripts, cmd /c lines)

	container  bool
	privileged bool
	socket     bool
	mounts     []string // host side of bind mounts
	ctrEnv     []string // K=V pairs passed with -e/--env

	bridgeURL string // remote endpoint a stdio bridge forwards to
}

// pinned reports whether everything the launch fetches is immutable.
func (l *launch) pinned() bool {
	return l.has && !l.spec.local && !l.unpinned
}

// analyze reads the launch of a declared server.
func analyze(s Server) launch {
	cmd := strings.TrimSpace(s.Command)
	args := s.Args
	if cmd != "" && len(args) == 0 && strings.ContainsAny(cmd, " \t") {
		cmd, args = splitCommandLine(cmd)
	}
	return analyzeArgv(cmd, args)
}

// analyzeArgv reads the launch of an executable and its arguments.
func analyzeArgv(cmd string, args []string) launch {
	var l launch
	if strings.TrimSpace(cmd) == "" {
		return l
	}
	l.declCmd, l.declArgs = cmd, args
	l.resolve(cmd, args, 0)
	if l.runner == "" {
		l.runner = "binary"
	}
	l.findBridge()
	return l
}

// splitCommandLine separates the executable from its arguments when a client
// wrote the whole line into "command". An executable path may itself contain
// spaces (C:\Program Files\nodejs\npx.cmd), so a prefix that ends in a known
// launcher is preferred over the first word.
func splitCommandLine(line string) (string, []string) {
	words := splitWords(line)
	if len(words) <= 1 {
		if len(words) == 1 {
			return words[0], nil
		}
		return line, nil
	}
	if knownLauncher(cmdBase(words[0])) {
		return words[0], words[1:]
	}
	if isAbsPath(words[0]) || homeRelative(words[0]) {
		for i := 2; i <= len(words) && i <= 8; i++ {
			cand := strings.Join(words[:i], " ")
			if knownLauncher(cmdBase(cand)) {
				return cand, words[i:]
			}
		}
		flagSeen := false
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") {
				flagSeen = true
				break
			}
		}
		if !flagSeen {
			return line, nil // read as one path with spaces
		}
	}
	return words[0], words[1:]
}

func knownLauncher(base string) bool {
	if _, ok := wrappers[base]; ok {
		return true
	}
	return shells[base] || interpreters[base] || runners[base] || isPython(base)
}

var (
	shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
		"ash": true, "fish": true}
	runners = map[string]bool{"npx": true, "pnpx": true, "bunx": true, "npm": true, "pnpm": true,
		"yarn": true, "bun": true, "uvx": true, "uv": true, "pipx": true, "pip": true, "pip3": true,
		"node": true, "nodejs": true, "tsx": true, "ts-node": true, "deno": true, "docker": true,
		"podman": true, "go": true, "cmd": true, "powershell": true, "pwsh": true}
	interpreters = map[string]bool{"ruby": true, "perl": true, "php": true, "lua": true,
		"rscript": true, "osascript": true, "java": true, "dotnet": true}
	rePython = regexp.MustCompile(`^(?:python|pypy)[0-9.]*$`)
)

func isPython(base string) bool { return base == "py" || rePython.MatchString(base) }

func isFlag(a string) bool { return len(a) > 1 && a[0] == '-' }

// resolve classifies the launch of cmd with args, looking through wrappers.
func (l *launch) resolve(cmd string, args []string, depth int) {
	l.cmd, l.args = cmd, args
	if depth > maxUnwrap {
		l.runner = "binary"
		return
	}
	base := cmdBase(cmd)
	if w, ok := wrappers[base]; ok {
		if next := w.unwrap(args); len(next) > 0 {
			l.resolve(next[0], next[1:], depth+1)
			return
		}
		l.binary(cmd, args)
		return
	}
	switch {
	case base == "cmd":
		l.cmdExe(args, depth)
	case shells[base]:
		l.posixShell(args, depth)
	case base == "powershell" || base == "pwsh":
		l.powerShell(args, depth)
	case base == "npx" || base == "pnpx":
		l.nodePackage("npx", args)
	case base == "bunx":
		l.nodePackage("bunx", args)
	case base == "npm" && len(args) > 0 && (args[0] == "exec" || args[0] == "x"):
		l.nodePackage("npx", args[1:])
	case (base == "pnpm" || base == "yarn") && len(args) > 0 && args[0] == "dlx":
		l.nodePackage("npx", args[1:])
	case base == "bun" && len(args) > 0 && args[0] == "x":
		l.nodePackage("bunx", args[1:])
	case base == "bun":
		if len(args) > 0 && args[0] == "run" {
			args = args[1:]
		}
		l.nodeScript(args, bunValueFlags)
	case base == "node" || base == "nodejs" || base == "tsx" || base == "ts-node":
		l.nodeScript(args, nodeValueFlags)
	case base == "uvx":
		l.uvTool(args)
	case base == "uv":
		l.uv(args, depth)
	case base == "pipx":
		l.pipx(args)
	case base == "pip" || base == "pip3":
		l.pip(args)
	case isPython(base):
		l.python(args)
	case base == "deno":
		l.deno(args)
	case base == "docker" || base == "podman":
		l.containerRun(base, args)
	case base == "go":
		l.goRun(args)
	case interpreters[base]:
		l.interpreter(args)
	default:
		l.binary(cmd, args)
	}
}

func (l *launch) binary(cmd string, args []string) {
	l.runner = "binary"
	l.rest = args
	if isPathLike(cmd) {
		l.script = joinPath(l.dir, cmd)
	}
}

// ---- wrappers ----

// wrapSpec describes a program whose job is to run another program.
type wrapSpec struct {
	value    map[string]bool // flags that take a separate value
	sub      []string        // subcommand words that precede the wrapped command (op run)
	operands int             // positional operands before the wrapped command (timeout 5s)
	assigns  bool            // NAME=value operands are settings, not the command (env)
	dashDash bool            // the wrapped command is only identifiable after "--"
	next     bool            // the very next word is the wrapped command (corepack, busybox)
}

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// wrappers is deliberately data: adding one is a table entry.
var wrappers = map[string]wrapSpec{
	"env":        {value: set("-u", "--unset", "-C", "--chdir", "-S", "--split-string"), assigns: true},
	"sudo":       {value: set("-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "-D", "--chdir", "-R", "-r", "-t", "-T"), assigns: true},
	"doas":       {value: set("-u", "-C")},
	"nohup":      {},
	"exec":       {value: set("-a")},
	"command":    {},
	"time":       {value: set("-o", "-f")},
	"setsid":     {},
	"winpty":     {},
	"unbuffer":   {},
	"nice":       {value: set("-n", "--adjustment")},
	"ionice":     {value: set("-c", "-n", "-p")},
	"stdbuf":     {},
	"timeout":    {value: set("-s", "--signal", "-k", "--kill-after"), operands: 1},
	"arch":       {value: set("-e", "-d")},
	"caffeinate": {value: set("-t", "-w")},
	"xvfb-run":   {value: set("-n", "--server-num", "-s", "--server-args", "-e", "--error-file", "-f", "--auth-file", "-p", "--xauth-protocol", "-w", "--wait")},
	"wsl":        {value: set("-d", "--distribution", "-u", "--user", "--cd", "--shell-type")},
	"busybox":    {next: true},
	"corepack":   {next: true},
	"dotenv":     {value: set("-e", "-v")},
	"direnv":     {sub: []string{"exec"}, operands: 1},
	"envchain":   {operands: 1},
	"volta":      {sub: []string{"run"}, value: set("--node", "--npm", "--yarn", "--pnpm", "--env")},
	// Secret injectors. Their own flags vary by version, so the wrapped
	// command is only trusted after an explicit "--".
	"op":        {dashDash: true},
	"doppler":   {dashDash: true},
	"infisical": {dashDash: true},
	"aws-vault": {dashDash: true},
	"dotenvx":   {dashDash: true},
	"chamber":   {dashDash: true},
	"mise":      {dashDash: true},
	"fnm":       {dashDash: true},
	"teller":    {dashDash: true},
}

var reEnvAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// unwrap returns the wrapped command line, or nil when there is none.
func (w wrapSpec) unwrap(args []string) []string {
	if w.dashDash {
		for i, a := range args {
			if a == "--" {
				return args[i+1:]
			}
		}
		return nil
	}
	if w.next {
		return args
	}
	sub, operands := w.sub, w.operands
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:]
		case isFlag(a):
			if w.value[a] {
				i++
			}
		case w.assigns && reEnvAssign.MatchString(a):
		case len(sub) > 0:
			if a != sub[0] {
				return nil
			}
			sub = sub[1:]
		case operands > 0:
			operands--
		default:
			return args[i:]
		}
	}
	return nil
}

// ---- shells ----

// cmdExe handles "cmd /c ...". On Windows this is the documented way to start
// npx (a .cmd shim), so the wrapped launch must stay readable.
func (l *launch) cmdExe(args []string, depth int) {
	for i, a := range args {
		la := strings.ToLower(a)
		if la == "/c" || la == "/k" {
			l.shell = true
			rest := args[i+1:]
			line := strings.Join(rest, " ")
			l.inline = append(l.inline, line)
			if len(rest) == 1 && strings.ContainsAny(rest[0], " \t") {
				l.fromScript(rest[0], depth)
			} else if len(rest) > 0 {
				inline := l.inline
				l.resolve(rest[0], rest[1:], depth+1)
				l.shell, l.inline = true, inline
			}
			if l.runner == "" {
				l.runner = "binary"
			}
			return
		}
		if !strings.HasPrefix(a, "/") {
			break
		}
	}
	l.binary(l.cmd, args)
}

// posixShell handles "sh -c script" and "sh file".
func (l *launch) posixShell(args []string, depth int) {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) && !strings.HasPrefix(a, "+") {
			break
		}
		if !strings.HasPrefix(a, "--") && strings.Contains(a, "s") && !strings.Contains(a, "c") {
			// -s: commands come from standard input, operands are its
			// parameters. There is no script file to point at.
			l.runner = "binary"
			l.rest = args[i+1:]
			return
		}
		if !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
			// -c, -lc, -ic ...: the next word is the script.
			l.shell = true
			if i+1 < len(args) {
				l.inline = append(l.inline, args[i+1])
				l.fromScript(args[i+1], depth)
			}
			if l.runner == "" {
				l.runner = "binary"
			}
			return
		}
		if a == "-o" || a == "-O" || a == "--rcfile" || a == "--init-file" {
			i++
		}
		i++
	}
	l.runner = "binary"
	if i < len(args) {
		l.script = joinPath(l.dir, args[i])
		l.rest = args[i+1:]
	}
}

// powerShell handles -Command, -EncodedCommand and -File. PowerShell accepts
// any unambiguous prefix of a parameter name.
func (l *launch) powerShell(args []string, depth int) {
	l.runner = "binary"
	for i := 0; i < len(args); i++ {
		a := args[i]
		la := strings.ToLower(a)
		switch {
		case la == "-c" || (len(la) >= 4 && strings.HasPrefix("-command", la)):
			l.inlineShell(strings.Join(args[i+1:], " "), depth)
			return
		case la == "-e" || la == "-ec" || (len(la) >= 3 && strings.HasPrefix("-encodedcommand", la)):
			script := ""
			if i+1 < len(args) {
				script = decodePSCommand(args[i+1])
			}
			l.inlineShell(script, depth)
			return
		case la == "-f" || (len(la) >= 3 && strings.HasPrefix("-file", la)):
			if i+1 < len(args) {
				l.script = joinPath(l.dir, args[i+1])
				l.rest = args[i+2:]
			}
			return
		case psValueFlags[la]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if strings.HasSuffix(la, ".ps1") {
				l.script = joinPath(l.dir, a)
				l.rest = args[i+1:]
				return
			}
			l.inlineShell(strings.Join(args[i:], " "), depth)
			return
		}
	}
}

var psValueFlags = set("-executionpolicy", "-ep", "-ex", "-exec", "-windowstyle", "-w",
	"-workingdirectory", "-wd", "-configurationname", "-inputformat", "-outputformat",
	"-version", "-psconsolefile", "-settingsfile", "-custompipename")

func (l *launch) inlineShell(script string, depth int) {
	l.shell = true
	l.inline = append(l.inline, script)
	l.fromScript(script, depth)
	if l.runner == "" {
		l.runner = "binary"
	}
}

// decodePSCommand decodes -EncodedCommand (base64 of UTF-16LE). Failure
// yields "", which simply means nothing can be said about the script.
func decodePSCommand(b64 string) string {
	if len(b64) > maxScript*3 {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return ""
	}
	return string(utf16ToUTF8(raw, false))
}

// fromScript finds the launch inside an inline script. The first simple
// command that fetches or runs a package or image is the launch; failing
// that, the last command is (the usual shape is "cd dir && node server.js").
func (l *launch) fromScript(script string, depth int) {
	if depth >= maxUnwrap {
		return
	}
	var (
		chosen *launch
		last   *launch
		dir    = l.dir
	)
	cmds := splitScript(script, true)
	if len(cmds) > 64 {
		cmds = cmds[:64]
	}
	for _, c := range cmds {
		c = cleanSimpleCommand(c)
		if len(c) == 0 {
			continue
		}
		if cmdBase(c[0]) == "cd" {
			if len(c) > 1 {
				dir = joinPath(dir, c[1])
			}
			continue
		}
		sub := &launch{dir: dir}
		sub.resolve(c[0], c[1:], depth+1)
		last = sub
		if sub.fetch || sub.container || sub.has {
			chosen = sub
			break
		}
	}
	if chosen == nil {
		chosen = last
	}
	if chosen == nil {
		return
	}
	declCmd, declArgs := l.declCmd, l.declArgs
	inline := append(l.inline, chosen.inline...)
	*l = *chosen
	l.declCmd, l.declArgs = declCmd, declArgs
	l.shell, l.inline = true, inline
}

// cleanSimpleCommand drops what precedes or follows the command words of a
// simple command: grouping punctuation, leading assignments and redirections.
func cleanSimpleCommand(c []string) []string {
	for len(c) > 0 {
		w := strings.TrimLeft(c[0], "({")
		switch {
		case w == "", w == "!":
			c = c[1:]
			continue
		case reEnvAssign.MatchString(w):
			c = c[1:]
			continue
		}
		if w != c[0] {
			c = append([]string{w}, c[1:]...)
		}
		break
	}
	for i, w := range c {
		t := strings.TrimLeft(w, "0123456789")
		if strings.HasPrefix(t, ">") || strings.HasPrefix(t, "<") {
			c = c[:i]
			break
		}
	}
	if n := len(c); n > 0 {
		if w := strings.TrimRight(c[n-1], ")}"); w == "" {
			c = c[:n-1]
		} else if w != c[n-1] {
			c = append(append([]string{}, c[:n-1]...), w)
		}
	}
	return c
}

// reFetchPipe recognises downloaded content reaching an interpreter:
// curl ... | sh, bash <(curl ...), sh -c "$(wget ...)", iex (iwr ...).
// It is a text heuristic on purpose; precise shell analysis is package
// shellx's job and this package must not depend on it.
var reFetchPipe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:[\w./\\-]*/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|perl|ruby|php|pwsh|powershell|iex|invoke-expression)\b`),
	regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|dash|ksh|eval|source|python[0-9.]*|node)\b[^|;&\n]*(?:<\(|\$\(|` + "`" + `)\s*(?:curl|wget)\b`),
	regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^;\n]*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b`),
	regexp.MustCompile(`(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^;\n]*\|\s*(?:iex|invoke-expression)\b`),
}

func fetchPipe(script string) bool {
	if len(script) > maxScript {
		script = script[:maxScript]
	}
	for _, re := range reFetchPipe {
		if re.MatchString(script) {
			return true
		}
	}
	return false
}

// bridges are stdio programs whose only job is to forward to a remote MCP
// endpoint given as a URL argument. Their endpoint is the fact worth
// inventorying.
// UNVERIFIED: names are from memory of the npm (mcp-remote, supergateway)
// and PyPI (mcp-proxy) registries, not re-checked against them today.
var bridges = set("mcp-remote", "supergateway", "mcp-proxy")

func (l *launch) findBridge() {
	name := cmdBase(l.cmd)
	if l.has {
		name = strings.ToLower(baseName(l.spec.name))
	}
	if !bridges[name] {
		return
	}
	for _, a := range l.rest {
		if isURLLike(a) {
			l.bridgeURL = a
			return
		}
	}
}
