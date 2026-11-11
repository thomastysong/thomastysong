package shellx

import (
	"strings"
	"unicode/utf8"
)

// Internal budgets. The exported limits live in facts.go.
const (
	maxCommands    = 2048      // simple commands recorded per Analyze call
	maxWork        = 400_000   // AST nodes / tokens visited per Analyze call
	maxSubAnalyses = 256       // nested re-analyses (inline, eval, decoded, substitutions in fallback mode)
	maxList        = 512       // entries per string list in Facts
	maxWord        = 32 << 10  // bytes of one resolved word
	maxStatic      = 64 << 10  // bytes of a statically evaluated stream
	maxInline      = 64        // InlineCode entries
	maxInlineBytes = 64 << 10  // bytes of one InlineCode.Code
	maxWrapChain   = 16        // chained wrappers (sudo env nice ...) unwrapped
	maxNest        = 200       // recursion guard for control-flow nesting in the walker
	maxBraceFields = 64        // fields one brace-expanded word may produce
	maxParserNest  = 120       // bracket nesting accepted before the real parser is skipped
	maxParserKw    = 3000      // compound-command keywords accepted before the real parser is skipped
	longTokenBytes = 1024      // a single argument at least this long without whitespace is long_single_token
	maxEmbedded    = 16        // shell strings extracted from one piece of foreign-language inline code
	maxAnalyzeText = MaxInput  // sub-analysis inputs are capped like the top-level input
	maxDecodeInput = 128 << 10 // encoded text longer than this is not decoded at all
	maxDroppedFile = 64        // files tracked as written by a download or decoder
	maxVars        = 512       // tracked variable assignments
)

// taint describes where a piece of text came from. It rides on arguments,
// variables and pipeline streams so that "download output reaches an
// interpreter" is a data-flow fact and not a regex over the raw line.
type taint uint8

const (
	tDownload taint = 1 << iota // produced by a network fetch
	tB64                        // passed through a base64 decoder
	tHex                        // passed through a hex-dump decoder (xxd -r)
	tRev                        // passed through rev
	tEsc                        // built from hex/octal escape sequences (printf, echo -e, $'..')
)

// tPayload marks decoders whose static output is a recovered payload even
// when nothing executes it. tCoded is every way executed text can have been
// spelled indirectly.
const (
	tPayload = tB64 | tHex
	tCoded   = tB64 | tHex | tRev | tEsc
)

// arg is one resolved word of a simple command.
type arg struct {
	s      string
	dyn    bool  // contains an expansion that could not be resolved
	t      taint //
	exp    bool  // built at least partly from a parameter or command expansion
	concat bool  // quoting or escaping splits an identifier (c'u'r"l")
	glob   bool  // contains an unquoted glob metacharacter
	guard  bool  // contains ${VAR:?}: expansion aborts when unset, so "$VAR/" is safe
	proc   bool  // is a process substitution <(...)
	quoted bool  // contained quoting
}

// value is a tracked variable.
type value struct {
	s      string
	static bool
	t      taint
}

// flow describes the stream a pipeline stage receives or produces.
type flow struct {
	piped  bool    // a previous stage exists
	static *string // content when statically known
	t      taint
	rep    int // index of the command that represents the stage, -1 when none
}

func noFlow() flow { return flow{rep: -1} }

// useMode says how a command touches a path.
type useMode uint8

const (
	mRead useMode = iota
	mWrite
	mAppend
	mDelete
	mMove // source of a move: read and removed
	mAttr // permissions / ownership / attributes changed
	mLink // link created at this path
)

type pathUse struct {
	path string
	mode useMode
	text string // content being written, when statically known (bounded)
}

type dropFile struct {
	key string
	t   taint
}

// simple is a simple command in dialect-neutral form. Every front end (bash
// AST, fallback tokenizer, PowerShell and cmd tokenizers) lowers to it so the
// semantic layer is written once.
type simple struct {
	args    []arg
	raw     string // command word as written
	env     []envKV
	stdin   *string // heredoc / here-string content when resolvable
	stdinT  taint
	inFile  arg  // "< file"
	hasIn   bool // inFile is set
	outFile arg  // stdout redirected to this file
	hasOut  bool
	origin  string
	depth   int
	wraps   int
	dialect Dialect
	bg      bool
	tail    bool // more arguments are appended at run time (xargs, find -exec {} +)

	name string // normalised command name
	idx  int    // index in Facts.Commands, -1 when not recorded
}

type envKV struct {
	name string
	val  arg
}

type analyzer struct {
	f       *Facts
	vars    map[string]value
	uses    []pathUse
	dropped []dropFile
	work    int
	subs    int
	nest    int
	decoded map[string]struct{}

	gitRemotes []string // remote names added or re-pointed on this command line
}

func newAnalyzer(f *Facts) *analyzer {
	return &analyzer{f: f, work: maxWork}
}

// tick spends one unit of the work budget. It returns false once the budget
// is gone, which callers treat as "stop descending".
func (a *analyzer) tick() bool {
	a.work--
	if a.work < 0 {
		a.f.Truncated = true
		return false
	}
	return true
}

// guard converts a panic in analysis code into a truncated, heuristic result.
// The sensor must survive any input; a missed fact is better than a crash in
// the hook path.
func (a *analyzer) guard() {
	if r := recover(); r != nil {
		a.f.ParseOK = false
		a.f.Truncated = true
	}
}

func addUniq(list *[]string, s string) {
	if s == "" {
		return
	}
	l := *list
	for i := range l {
		if l[i] == s {
			return
		}
	}
	if len(l) >= maxList {
		return
	}
	*list = append(l, s)
}

func (a *analyzer) obf(v string)       { addUniq(&a.f.Obfuscation, v) }
func (a *analyzer) destructive(v string) { addUniq(&a.f.Destructive, v) }
func (a *analyzer) persist(v string)   { addUniq(&a.f.Persistence, v) }
func (a *analyzer) evasion(v string)   { addUniq(&a.f.DefenseEvasion, v) }
func (a *analyzer) cred(v string)      { addUniq(&a.f.CredAccess, v) }
func (a *analyzer) exfil(v string)     { addUniq(&a.f.Exfil, v) }
func (a *analyzer) nettool(v string)   { addUniq(&a.f.NetTools, v) }
func (a *analyzer) recon(v string)     { addUniq(&a.f.Recon, v) }
func (a *analyzer) priv(v string)      { addUniq(&a.f.Privilege, v) }
func (a *analyzer) gitop(v string)     { addUniq(&a.f.GitOps, v) }
func (a *analyzer) interpreter(v string) { addUniq(&a.f.Interpreters, v) }
func (a *analyzer) envAssign(v string) { addUniq(&a.f.EnvAssign, v) }

// obfTaint records the obfuscation implied by how executed text was built.
func (a *analyzer) obfTaint(t taint) {
	if t&tB64 != 0 {
		a.obf("base64_decode_exec")
	}
	if t&(tHex|tEsc) != 0 {
		a.obf("hex_escape")
	}
	if t&tRev != 0 {
		a.obf("rev_exec")
	}
}

func (a *analyzer) sudo() {
	a.f.Sudo = true
	a.priv("sudo")
}

// pseudoPath reports targets that are not files worth recording.
func pseudoPath(p string) bool {
	switch strings.ToLower(p) {
	case "", "-", "/dev/null", "nul", "nul:", "$null", "/dev/stdout", "/dev/stderr", "/dev/stdin",
		"/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom", "con", "&1", "&2":
		return true
	}
	return strings.HasPrefix(p, "/dev/fd/")
}

func (a *analyzer) use(path string, m useMode) { a.useText(path, m, "") }

func (a *analyzer) useText(path string, m useMode, text string) {
	path = strings.TrimSpace(path)
	if pseudoPath(path) {
		return
	}
	if h, ok := devTCPHost(path); ok {
		a.host(h)
		return
	}
	if len(path) > 4096 {
		path = path[:4096]
	}
	if len(text) > 4096 {
		text = text[:4096]
	}
	if len(a.uses) < 4*maxList {
		a.uses = append(a.uses, pathUse{path: path, mode: m, text: text})
	}
	switch m {
	case mRead, mMove:
		addUniq(&a.f.Reads, path)
	case mWrite, mAppend, mLink:
		addUniq(&a.f.Writes, path)
	case mDelete:
		addUniq(&a.f.Deletes, path)
	}
}

func (a *analyzer) read(path string)   { a.use(path, mRead) }
func (a *analyzer) write(path string)  { a.use(path, mWrite) }
func (a *analyzer) del(path string)    { a.use(path, mDelete) }
func (a *analyzer) attr(path string)   { a.use(path, mAttr) }
func (a *analyzer) appendTo(path string) { a.use(path, mAppend) }

// drop remembers a file written by a download or a decoder so a later
// execution of it in the same command line can be linked back.
func (a *analyzer) drop(path string, t taint) {
	k := dropKey(path)
	if k == "" || pseudoPath(path) || len(a.dropped) >= maxDroppedFile {
		return
	}
	for i := range a.dropped {
		if a.dropped[i].key == k {
			a.dropped[i].t |= t
			return
		}
	}
	a.dropped = append(a.dropped, dropFile{key: k, t: t})
}

func dropKey(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

// droppedTaint reports whether path names a file written earlier on this
// command line by a download or decoder. A bare file name matches a recorded
// path with the same base name because the working directory is unknown.
func (a *analyzer) droppedTaint(path string) (taint, bool) {
	if len(a.dropped) == 0 {
		return 0, false
	}
	k := dropKey(path)
	if k == "" {
		return 0, false
	}
	kb := baseName(k)
	kDir := strings.Contains(k, "/")
	for _, d := range a.dropped {
		if d.key == k {
			return d.t, true
		}
		if baseName(d.key) == kb && (!kDir || !strings.Contains(d.key, "/")) {
			return d.t, true
		}
	}
	return 0, false
}

// ranFile links the execution of path to how the file got there.
func (a *analyzer) ranFile(path string) {
	t, ok := a.droppedTaint(path)
	if !ok {
		return
	}
	if t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	a.obfTaint(t)
}

func baseName(p string) string {
	p = strings.TrimRight(p, "/\\")
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// commandName normalises a command word: basename, lower-case, ".exe"
// stripped. A name that is wholly an unresolved expansion is kept verbatim.
func commandName(w arg) string {
	s := w.s
	if w.dyn && (strings.HasPrefix(s, "$") || strings.HasPrefix(s, "%") || strings.HasPrefix(s, "<(")) && !strings.ContainsAny(s, "/\\") {
		return s
	}
	s = baseName(s)
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".exe")
	return s
}

func (a *analyzer) setVar(name string, v value) {
	if a.vars == nil {
		a.vars = make(map[string]value)
	}
	if _, ok := a.vars[name]; !ok && len(a.vars) >= maxVars {
		return
	}
	if len(v.s) > maxWord {
		v.s = v.s[:maxWord]
		v.static = false
	}
	a.vars[name] = v
}

func (a *analyzer) getVar(name string) (value, bool) {
	v, ok := a.vars[name]
	return v, ok
}

// clip cuts s to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func containsFold(s, sub string) bool {
	return indexFold(s, sub) >= 0
}

// indexFold is a case-insensitive strings.Index for ASCII needles. sub must
// already be lower-case.
func indexFold(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	first := sub[0]
	for i := 0; i+n <= len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != first {
			continue
		}
		j := 1
		for ; j < n; j++ {
			d := s[i+j]
			if d >= 'A' && d <= 'Z' {
				d += 'a' - 'A'
			}
			if d != sub[j] {
				break
			}
		}
		if j == n {
			return i
		}
	}
	return -1
}

func strs(args []arg) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i := range args {
		out[i] = args[i].s
	}
	return out
}

func joinArgs(args []arg) string {
	switch len(args) {
	case 0:
		return ""
	case 1:
		return args[0].s
	}
	n := len(args) - 1
	for i := range args {
		n += len(args[i].s)
	}
	var b strings.Builder
	b.Grow(n)
	for i := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(args[i].s)
	}
	return b.String()
}

func anyTaint(args []arg) taint {
	var t taint
	for i := range args {
		t |= args[i].t
	}
	return t
}

func anyDyn(args []arg) bool {
	for i := range args {
		if args[i].dyn {
			return true
		}
	}
	return false
}
