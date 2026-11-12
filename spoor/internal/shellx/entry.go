package shellx

import (
	"regexp"
	"strings"
)

// Options carry what the caller knows about where the command line runs.
type Options struct {
	// OS is the host's operating system in runtime.GOOS spelling, or ""
	// when unknown. On a host known not to be Windows a POSIX shell's
	// paths are POSIX paths: "a:" is a name, not a drive.
	OS string
}

// Analyze derives Facts from one command line. hint selects the dialect; ""
// auto-detects it. Analyze never panics and always returns non-nil Facts:
// the input is attacker-controlled (it arrives on hook stdin), so every
// failure mode degrades to a heuristic, truncated result instead of an error.
func Analyze(cmdline string, hint Dialect) *Facts {
	return AnalyzeWith(cmdline, hint, Options{})
}

// AnalyzeWith is Analyze with what the caller knows about the host.
func AnalyzeWith(cmdline string, hint Dialect, o Options) *Facts {
	ensureTables()
	f := &Facts{ParseOK: true}
	src := cmdline
	if len(src) > MaxInput {
		src = clip(src, MaxInput)
		f.Truncated = true
	}
	d := hint
	switch d {
	case Posix, PowerShell, Cmd:
	default:
		d = detectDialect(src)
	}
	f.Dialect = d
	a := newAnalyzer(f)
	switch strings.ToLower(o.OS) {
	case "", "windows", "win", "win32":
	default:
		a.posixHost = true
	}
	func() {
		defer a.guard()
		if strings.TrimSpace(src) == "" {
			return
		}
		switch d {
		case PowerShell:
			a.powershell(src, OriginTop, 0, noFlow())
		case Cmd:
			a.cmdexe(src, OriginTop, 0, noFlow())
		default:
			a.posix(src, OriginTop, 0, noFlow())
		}
	}()
	func() {
		defer a.guard()
		a.finish()
	}()
	return f
}

// finish derives the summary facts that depend on everything else.
func (a *analyzer) finish() {
	f := a.f
	a.classifyUses()
	addOpaque := func(v string) { addUniq(&f.Opaque, v) }
	if f.Eval {
		addOpaque("eval")
	}
	for _, ic := range f.Inline {
		switch ic.Lang {
		case "sh", "powershell", "cmd":
			// Re-parsed by this package: not opaque.
		default:
			addOpaque("inline_code")
		}
	}
	if f.HereDoc && len(f.Interpreters) > 0 {
		addOpaque("heredoc_interpreter")
	}
	for _, o := range f.Obfuscation {
		switch o {
		case "var_indirection":
			for _, c := range f.Commands {
				if strings.HasPrefix(c.Name, "$") || strings.HasPrefix(c.Name, "%") || strings.HasPrefix(c.Name, "!") {
					addOpaque("dynamic_command")
					break
				}
			}
		case "base64_decode_exec", "encoded_command", "rev_exec", "hex_escape":
			if f.PipeToInterpreter || f.Eval || len(f.Interpreters) > 0 {
				addOpaque("decoded_exec")
			}
		case "deep_nesting":
			addOpaque("deep_nesting")
		}
	}
	for _, c := range f.Commands {
		if interpFor(c.Name) == nil {
			continue
		}
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "<(") {
				addOpaque("process_substitution_exec")
			}
		}
	}
}

// detectDialect guesses the syntax family of a command line. It runs before
// any parser because a PowerShell or cmd.exe line usually parses "fine" as
// bash and then yields cmdlet names no rule knows, with backslashes in
// Windows paths eaten as escapes. The decision is a weighted vote over cheap
// lexical signals; ties and weak evidence go to POSIX.
func detectDialect(s string) Dialect {
	ensureTables()
	if len(s) > 8<<10 {
		s = clip(s, 8<<10)
	}
	t := strings.TrimSpace(s)
	if t == "" {
		return Posix
	}
	l := strings.ToLower(t)
	first := firstWordLower(t)
	switch first {
	case "powershell", "pwsh", "powershell_ise", "pwsh-preview":
		return PowerShell
	case "cmd":
		return Cmd
	}
	// Neither PowerShell nor cmd.exe has a heredoc. A "<<WORD" whose
	// terminator line is present settles the dialect, and its body (data
	// for cat, code for an interpreter) must not vote: a Go or PowerShell
	// file written with cat contains plenty of foreign-looking text.
	if hasHeredoc(t) {
		return Posix
	}
	ps, cmd, sh := 0, 0, 0

	// POSIX signals.
	for _, sig := range []string{"$(", "${", "2>/dev/null", "/dev/null", "~/", "| sh", "|sh", "| bash", "|bash", "#!/", "$'", "sudo ", "export ", " || true", "set -e"} {
		if strings.Contains(l, sig) {
			sh += 2
		}
	}
	// Heredocs exist in POSIX shells (and PowerShell has no "<<"); cmd.exe
	// has neither. Unix absolute paths as arguments are POSIX evidence too.
	for _, sig := range []string{"<<'", "<<\"", "<<-", "<<eof", "<< 'eof'", "<<end"} {
		if strings.Contains(l, sig) {
			sh += 3
			break
		}
	}
	// "NAME=value cmd" or "NAME=value;" as the first word needs "set" in
	// cmd.exe and "$" in PowerShell; "name() {" is a POSIX function.
	if posixAssignFirst(t) {
		sh += 3
	}
	if posixFuncDef.MatchString(t) {
		sh += 3
	}
	for _, sig := range []string{" /tmp/", " /home/", " /etc/", " /usr/", " /var/", " /opt/", " /root/", " /users/", " /private/", " ./", " ../"} {
		if strings.Contains(l, sig) {
			sh += 2
			break
		}
	}

	// PowerShell signals.
	for _, sig := range []string{"$env:", "[convert]::", "[system.", "[io.", "[text.encoding]", "[net.", "]::"} {
		if strings.Contains(l, sig) {
			ps += 3
		}
	}
	for _, sig := range []string{"$_", "@{", "$null", "$true", "$false", "-erroraction", "-executionpolicy", "-noprofile", "-windowstyle", "-encodedcommand", "-usebasicparsing", "-outfile", "-recurse", "-force"} {
		if strings.Contains(l, sig) {
			ps += 2
		}
	}
	if strings.Contains(l, "| iex") || strings.Contains(l, "|iex") || strings.Contains(l, "| invoke-expression") {
		ps += 4
	}
	cmdWords := commandWords(t, 32)
	for _, w := range cmdWords {
		if isVerbNoun(w) {
			ps += 4
		}
		switch w {
		case "iex", "iwr", "irm", "saps", "gci", "icm", "gwmi", "sal", "ri", "gcim", "spsv", "sasv":
			ps += 3
		}
	}

	// cmd.exe signals.
	if strings.HasPrefix(l, "@echo off") || strings.HasPrefix(l, "@") {
		cmd += 3
	}
	for _, sig := range []string{">nul", "> nul", "2>nul", "2> nul", "if exist ", "if not exist ", "for /f", "for /l", "for /d", "setlocal", "goto :", "%errorlevel%", "%~dp0"} {
		if strings.Contains(l, sig) {
			cmd += 3
		}
	}
	cmd += cmdVarScore(t)
	if winOnlyCommand(first) {
		cmd += 3
	} else if winPathCommand(first) && windowsPathArg(t) {
		// "cd C:\x", "copy C:\a.txt D:\b": the first argument must look like
		// a Windows path. A backslash elsewhere ("\n" in a curl format, "\("
		// in a grep pattern) is ordinary in POSIX commands.
		cmd += 3
	}
	if strings.Contains(t, "^&") || strings.Contains(t, "^|") || strings.Contains(t, "^>") {
		cmd += 2
	}

	switch {
	case ps >= 3 && ps > cmd && ps > sh:
		return PowerShell
	case cmd >= 3 && cmd > ps && cmd > sh:
		return Cmd
	}
	return Posix
}

// firstWordLower returns the first word, lower-cased, with a leading "@",
// "&", "." call operator or quote removed and ".exe" stripped.
func firstWordLower(t string) string {
	t = strings.TrimLeft(t, "@& \t")
	if t == "" {
		return ""
	}
	end := len(t)
	if t[0] == '"' || t[0] == '\'' {
		q := t[0]
		if j := strings.IndexByte(t[1:], q); j >= 0 {
			t = t[1 : 1+j]
			end = len(t)
		}
	} else {
		for i := 0; i < len(t); i++ {
			if isSpace(t[i]) || t[i] == ';' || t[i] == '|' || t[i] == '&' {
				end = i
				break
			}
		}
	}
	w := strings.ToLower(t[:end])
	w = baseName(w)
	return strings.TrimSuffix(w, ".exe")
}

// commandWords returns lower-cased words in command position: the first word
// and words after a pipe, separator or opening bracket.
func commandWords(t string, max int) []string {
	var out []string
	start := true
	i := 0
	for i < len(t) && len(out) < max {
		c := t[i]
		switch {
		case isSpace(c):
			i++
			continue
		case c == '|' || c == ';' || c == '(' || c == '{' || c == '&' || c == '=':
			start = true
			i++
			continue
		}
		j := i
		for j < len(t) && !isSpace(t[j]) && strings.IndexByte("|;(){}&=", t[j]) < 0 {
			j++
		}
		if j == i {
			// A closing bracket: not a separator, not a word.
			i++
			continue
		}
		if start {
			out = append(out, strings.ToLower(t[i:j]))
		}
		start = false
		i = j
	}
	return out
}

// psVerbs are the approved PowerShell verbs most often seen on command lines.
var psVerbs map[string]struct{}

func buildPsVerbs() {
	psVerbs = map[string]struct{}{
		"get": {}, "set": {}, "new": {}, "remove": {}, "invoke": {}, "start": {}, "stop": {}, "add": {}, "out": {},
		"write": {}, "read": {}, "import": {}, "export": {}, "select": {}, "where": {}, "foreach": {}, "test": {},
		"convert": {}, "convertto": {}, "convertfrom": {}, "copy": {}, "move": {}, "rename": {}, "clear": {},
		"enable": {}, "disable": {}, "install": {}, "uninstall": {}, "register": {}, "unregister": {}, "expand": {},
		"compress": {}, "resolve": {}, "split": {}, "join": {}, "format": {}, "measure": {}, "sort": {}, "group": {},
		"wait": {}, "update": {}, "restart": {}, "suspend": {}, "resume": {}, "enter": {}, "exit": {}, "push": {},
		"pop": {}, "unblock": {}, "send": {}, "receive": {}, "connect": {}, "disconnect": {}, "find": {}, "save": {},
	}
}

// isVerbNoun recognises a cmdlet name such as Get-Content. A word with a dot
// or slash is a file (get-pip.py), not a cmdlet.
func isVerbNoun(w string) bool {
	if strings.ContainsAny(w, "./\\:$\"'") {
		return false
	}
	i := strings.IndexByte(w, '-')
	if i <= 0 || i == len(w)-1 {
		return false
	}
	if _, ok := psVerbs[w[:i]]; !ok {
		return false
	}
	noun := w[i+1:]
	if len(noun) < 2 {
		return false
	}
	for j := 0; j < len(noun); j++ {
		c := noun[j]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// winVars are environment variables that only exist on Windows.
var winVars map[string]struct{}

func buildWinVars() {
	winVars = map[string]struct{}{
		"PATH": {}, "TEMP": {}, "TMP": {}, "USERPROFILE": {}, "APPDATA": {}, "LOCALAPPDATA": {}, "COMSPEC": {},
		"PROGRAMDATA": {}, "SYSTEMROOT": {}, "WINDIR": {}, "USERNAME": {}, "COMPUTERNAME": {}, "HOMEDRIVE": {},
		"HOMEPATH": {}, "PROGRAMFILES": {}, "PUBLIC": {}, "CD": {}, "DATE": {}, "TIME": {}, "RANDOM": {},
		"ERRORLEVEL": {}, "USERDOMAIN": {}, "ALLUSERSPROFILE": {}, "SYSTEMDRIVE": {},
	}
}

// cmdVarScore scores %NAME% references. date +%Y%m%d also contains "%Y%",
// so a short or lower-case name only counts when it is a known Windows
// variable.
func cmdVarScore(t string) int {
	score := 0
	for i := 0; i < len(t) && score < 6; i++ {
		if t[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(t) && (isIdentByte(t[j]) || t[j] == '(' || t[j] == ')') && j-i < 40 {
			j++
		}
		if j >= len(t) || j == i+1 || (t[j] != '%' && t[j] != ':') {
			continue
		}
		name := strings.ToUpper(t[i+1 : j])
		if _, ok := winVars[name]; ok {
			score += 3
		} else if len(name) >= 4 && t[i+1:j] == name {
			score += 2
		}
		i = j
	}
	return score
}

// posixFuncDef matches a POSIX function definition ("name() {").
var posixFuncDef *regexp.Regexp

func buildPosixFuncDef() {
	posixFuncDef = regexp.MustCompile(`(^|[;&|\s{(])[A-Za-z_][A-Za-z0-9_-]*\s*\(\)\s*\{`)
}

// posixAssignFirst reports whether t starts with NAME=value.
func posixAssignFirst(t string) bool {
	i := 0
	for i < len(t) && isIdentByte(t[i]) && !(i == 0 && t[i] >= '0' && t[i] <= '9') {
		i++
	}
	return i > 0 && i < len(t) && t[i] == '='
}

// hasHeredoc reports whether s contains a POSIX heredoc: "<<WORD",
// "<<'WORD'", "<<\"WORD\"" or "<<-WORD", followed later by a line that is
// exactly WORD (leading tabs allowed for <<-).
func hasHeredoc(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '<' || s[i+1] != '<' || (i > 0 && s[i-1] == '<') || s[i+2] == '<' {
			continue
		}
		j := i + 2
		strip := false
		if j < len(s) && s[j] == '-' {
			strip = true
			j++
		}
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		q := byte(0)
		if j < len(s) && (s[j] == '\'' || s[j] == '"') {
			q = s[j]
			j++
		}
		k := j
		for k < len(s) && (isIdentByte(s[k]) || s[k] == '-' || s[k] == '.') {
			k++
		}
		if k == j || k-j > 64 {
			continue
		}
		word := s[j:k]
		if q != 0 && (k >= len(s) || s[k] != q) {
			continue
		}
		nl := strings.IndexByte(s[k:], '\n')
		if nl < 0 {
			continue
		}
		for _, ln := range strings.Split(s[k+nl+1:], "\n") {
			ln = strings.TrimRight(ln, "\r")
			if strip {
				ln = strings.TrimLeft(ln, "\t")
			}
			if ln == word {
				return true
			}
		}
	}
	return false
}

// windowsPathArg reports whether the first argument of the command line t
// looks like a Windows path: a drive letter, a UNC prefix, a %VAR%\ prefix,
// or backslash separators with no forward slash.
func windowsPathArg(t string) bool {
	_, rest, ok := strings.Cut(strings.TrimSpace(t), " ")
	if !ok {
		return false
	}
	arg := strings.TrimLeft(strings.TrimSpace(rest), "\"")
	if i := strings.IndexAny(arg, " \"&|<>"); i >= 0 {
		arg = arg[:i]
	}
	switch {
	case len(arg) >= 3 && isASCIILetter(arg[0]) && arg[1] == ':' && (arg[2] == '\\' || arg[2] == '/'):
		return true
	case strings.HasPrefix(arg, `\\`), strings.HasPrefix(arg, "%") && strings.Contains(arg, `%\`):
		return true
	}
	return strings.Contains(arg, `\`) && !strings.Contains(arg, "/")
}

func isASCIILetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func winOnlyCommand(w string) bool {
	switch w {
	case "reg", "schtasks", "sc", "netsh", "wevtutil", "vssadmin", "wbadmin", "bcdedit", "certutil", "bitsadmin",
		"rundll32", "regsvr32", "msiexec", "taskkill", "wmic", "icacls", "takeown", "attrib", "setx", "xcopy",
		"robocopy", "mklink", "findstr", "ipconfig", "systeminfo", "tasklist", "cmdkey", "vaultcmd", "mshta",
		"cscript", "wscript", "erase", "del":
		return true
	}
	return false
}

func winPathCommand(w string) bool {
	switch w {
	case "copy", "move", "type", "dir", "rd", "rmdir", "ren", "start", "call", "cd", "mkdir", "md":
		return true
	}
	return false
}

// classifyUses maps every recorded path use and host to the semantic
// categories. Handlers record what a command touches; what that means
// (credential read, persistence, tampering) is decided once, here, so every
// front end and every command gets the same answer.
func (a *analyzer) classifyUses() {
	for _, u := range a.uses {
		n := u.norm
		if n == "" {
			continue
		}
		switch u.mode {
		case mRead, mMove:
			if cls := readClassNorm(n); cls != "" {
				a.cred(cls)
			}
		}
		switch u.mode {
		case mWrite, mAppend, mLink, mAttr:
			cls := persistClass(n)
			if cls == "" && u.mode != mAttr {
				// A write whose target is a persistence directory itself
				// (cp x.service /etc/systemd/system/) puts a file in it; the
				// canonical form has dropped the trailing separator.
				cls = persistClass(n + "/")
			}
			if cls != "" {
				a.persist(cls)
			}
			if isSudoersPath(n) && u.mode != mAttr {
				a.priv("sudoers_edit")
			}
		}
		switch u.mode {
		case mWrite, mAppend, mLink, mDelete, mAttr, mMove:
			// Not mAlias: making a path reachable under another name changes
			// nothing. A write through the new name on this line is recorded
			// under the path it reaches (analyzer.reached).
			if isAgentHookPath(n) {
				a.evasion("agent_hook_tamper")
			}
			if isSensorPath(n) {
				a.evasion("sensor_tamper")
			}
		}
		if u.mode == mDelete || u.mode == mWrite || u.mode == mMove {
			// Overwriting or removing history and logs; appending is not.
			if isHistoryFile(n) {
				a.evasion("history_clear")
			}
			if isLogPath(n) {
				a.evasion("log_clear")
			}
		}
	}
	for _, h := range a.f.Hosts {
		if isMetadataHost(h) {
			a.cred("cloud_metadata")
		}
	}
}
