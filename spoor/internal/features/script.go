package features

import (
	"runtime"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/shellx"
)

// Write-then-run. An agent (or whoever steers it) can write a command into
// a script with a file tool and run the script in a second event: the
// shell event then reads "sh /tmp/x.sh" and every parsed-fact rule is
// blind. WrittenScripts analyses the content a file_write / file_edit
// event writes, when that content is a script, into the same shell
// features a shell event carrying it would get (ScriptFacts); the rule
// engine keeps them per normalized path in bounded session state and,
// when a later command executes the path, merges them into that command's
// features with Inherit. Nothing here opens a file: the content is what
// the tool call carried.

// Script languages: the values of ScriptFacts.Lang.
const (
	LangShell      = "sh"
	LangPowerShell = "powershell"
	LangCmd        = "cmd"
	LangPython     = "python"
	LangJavaScript = "javascript"
	LangRuby       = "ruby"
	LangPerl       = "perl"
	LangPHP        = "php"
	LangLua        = "lua"
)

// ScriptLangs is the vocabulary of ScriptFacts.Lang.
var ScriptLangs = []string{LangShell, LangPowerShell, LangCmd, LangPython, LangJavaScript, LangRuby, LangPerl, LangPHP, LangLua}

// Bounds of script analysis. A written file is attacker-authored and the
// analysis runs in the hook process, inside the event's time budget, so
// the text, the number of files one patch names and the bytes analysed are
// all capped.
const (
	// maxPatchFiles is how many files of one apply_patch envelope are
	// returned; the files after them are not analysed and not returned,
	// so nothing is remembered about them.
	maxPatchFiles = 32
	// maxPatchText is how much of a patch envelope is parsed.
	maxPatchText = 1 << 20
	// maxPatchHunks bounds the hunks kept per file of a patch.
	maxPatchHunks = 1024
	// foreignChunk is the largest piece of non-shell code handed to
	// shellx at once. shellx keeps at most 32 KiB of one resolved word,
	// which is what the code of a heredoc is; a larger piece would be
	// analysed only up to that point.
	foreignChunk = 30 << 10
	// MaxScriptText is the longest file text WrittenScript.Keep returns
	// for the caller to hold, so that a later edit can be applied to it.
	MaxScriptText = 8 << 10
	// maxEditWork bounds the line comparisons spent applying the hunks of
	// one event's patch to held texts.
	maxEditWork = 1 << 20
)

// ScriptKeep says which facts some rule can match. When a script's facts
// are over their bounds, the commands and list values it does not report
// are shed first, so padding a script with ordinary commands does not push
// the one a rule matches out of view.
type ScriptKeep interface {
	// Command reports a command some rule's command predicate matches.
	Command(c ScriptCommand) bool
	// Value reports a value of the list feature name that a rule matches.
	Value(name, v string) bool
}

// ScriptOptions are what the caller adds to script analysis. The zero
// value analyses without a time budget, sheds by position and holds no
// earlier text.
type ScriptOptions struct {
	// Stop reports that the event's time budget is spent. Analysis checks
	// it before each piece of text it hands to the analyzer (the first
	// piece is always analysed); once it holds, the rest is skipped, the
	// facts cover what was analysed and every list they hold is recorded
	// as incomplete (Cut, shell.truncated).
	Stop func() bool
	// Keep orders what the bounds shed; nil sheds by position.
	Keep ScriptKeep
	// Prior returns the text the caller holds for path (a Keep returned
	// earlier), so that an edit is applied to it and the whole result is
	// analysed instead of the edit's new text on its own.
	Prior func(path string) (text string, ok bool)
}

// budget is one WrittenScripts call's share of the event's time budget.
type budget struct {
	stop    func() bool
	ran     int
	stopped bool
	work    int // line comparisons left for applying patch hunks
}

func newBudget(stop func() bool) *budget { return &budget{stop: stop, work: maxEditWork} }

// spent reports that the budget is gone, without charging a piece.
func (b *budget) spent() bool {
	if !b.stopped && b.stop != nil && b.stop() {
		b.stopped = true
	}
	return b.stopped
}

// next reports whether another piece may be analysed.
func (b *budget) next() bool {
	if b.stopped {
		return false
	}
	if b.ran > 0 && b.stop != nil && b.stop() {
		b.stopped = true
		return false
	}
	b.ran++
	return true
}

// WrittenScript is one file a file-tool event writes, as the engine needs
// it for write-then-run.
type WrittenScript struct {
	// Path is the file as the event names it (target path, or the path
	// in a patch envelope); the caller normalizes it.
	Path string
	// Facts are the shell features of the content, or nil when the
	// content is not a script.
	Facts *ScriptFacts
	// Replace is true when Facts describe the whole file: a write, a
	// patch that adds the file, or an edit applied to the text the caller
	// held (InContext). It is false for a fragment (an edit of a file
	// whose text is not held), whose facts add to what is known about the
	// file and carry Fragment.
	Replace bool
	// InContext is true for an edit applied to the text ScriptOptions.Prior
	// returned. That text has its credentials redacted, so the caller
	// keeps what it knew about the credentials the file sent.
	InContext bool
	// Remove is true when the event deletes the file (a patch).
	Remove bool
	// From is the previous path of a file a patch moves.
	From string
	// Text is the analysed content (bounded: head and tail of a long
	// file). It lets the caller scan the script for remembered values;
	// it is never stored.
	Text string
	// Keep is the whole new text of the file for the caller to hold, with
	// credentials redacted, or "" when the whole text is not known or is
	// longer than MaxScriptText.
	Keep string
}

// WrittenScripts returns the files e writes with what is known about
// their content, for a file_write or file_edit tool event, and nil for any
// other event. Content is the tool input (Content.FileContent, or the
// write keys of Content.ToolInput); the apply_patch envelope of a patch
// tool is split per file. An edit is applied to the text o.Prior holds for
// the file when there is one, and the whole result is analysed; otherwise
// its new text is analysed as a fragment. A file whose content is not a
// script is returned with nil Facts, so the caller forgets what it knew
// about a file a write replaced. WrittenScripts never panics and never
// opens a file.
func WrittenScripts(e *event.Event, ctx Context, o ScriptOptions) (out []WrittenScript) {
	if e == nil || e.Tool == nil {
		return nil
	}
	kind := e.Tool.Kind
	if kind != event.ToolFileWrite && kind != event.ToolFileEdit {
		return nil
	}
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	ctx = scriptCtx(e, ctx)
	b := newBudget(o.Stop)
	// Compute scanned the event's written content for credentials
	// (write.*); the scan is the most expensive part of a large file, so
	// it is not run twice. A text derived from that content (one file of
	// a patch, an edit applied to a held text whose credentials are
	// redacted) has none when the content had none.
	known := computedSecrets(e)
	var none *knownSecrets
	if known != nil && len(known.kinds) == 0 {
		none = known
	}
	if kind == event.ToolFileEdit {
		if patch := patchText(e); patch != "" {
			if files := parsePatch(patch); len(files) > 0 {
				for _, pf := range files {
					out = append(out, patchScript(pf, ctx, o, b, none))
				}
				return out
			}
		}
	}
	path := ""
	if t := e.Target; t != nil {
		path = t.Path
		if path == "" && len(t.Paths) == 1 {
			path = t.Paths[0]
		}
	}
	if path == "" {
		return nil
	}
	var in map[string]any
	if e.Content != nil {
		in = e.Content.ToolInput
	}
	if kind == event.ToolFileWrite || isCreate(in) {
		ws := WrittenScript{Path: path, Replace: true}
		if text := writtenContent(e); text != "" {
			ws.Facts, ws.Text = analyzeScript(path, text, ctx, o.Keep, b, known)
			ws.Keep = keepText(text, ws.Facts)
		}
		return []WrittenScript{ws}
	}
	ws := WrittenScript{Path: path}
	if o.Prior != nil {
		if prior, ok := o.Prior(path); ok {
			if text, ok := applyEdits(prior, in); ok {
				return []WrittenScript{inContext(path, text, ctx, o, b, none)}
			}
		}
	}
	if text := writtenContent(e); text != "" {
		ws.Facts, ws.Text = analyzeScript(path, text, ctx, o.Keep, b, known)
		ws.Facts.markFragment(o.Keep)
	}
	return []WrittenScript{ws}
}

// knownSecrets are credential kinds already found in the text a script
// analysis gets.
type knownSecrets struct{ kinds []string }

// computedSecrets returns the write.secret_kinds Compute found in the
// event's written content, or nil when Compute did not scan it.
func computedSecrets(e *event.Event) *knownSecrets {
	if e.Feat == nil {
		return nil
	}
	if _, done := e.Feat[computedKey]; !done {
		return nil
	}
	if _, scanned := e.Feat["write.hidden_unicode"]; !scanned {
		return nil
	}
	k, _ := e.Feat["write.secret_kinds"].([]string)
	return &knownSecrets{kinds: k}
}

// inContext analyses the whole text of a file after an edit applied to
// the text the caller held. The held text has its credentials replaced by
// redaction markers; the kinds those markers name are what the file still
// carries, so they are counted as its secrets.
func inContext(path, text string, ctx Context, o ScriptOptions, b *budget, known *knownSecrets) WrittenScript {
	ws := WrittenScript{Path: path, Replace: true, InContext: true}
	ws.Facts, ws.Text = analyzeScript(path, text, ctx, o.Keep, b, known)
	ws.Keep = keepText(text, ws.Facts)
	ws.Facts.addSecretKinds(markerKinds(text), o.Keep)
	return ws
}

// patchScript is WrittenScripts for one file of a patch.
func patchScript(pf patchFile, ctx Context, o ScriptOptions, b *budget, known *knownSecrets) WrittenScript {
	ws := WrittenScript{Path: pf.path, Replace: pf.add, Remove: pf.remove, From: pf.from}
	switch {
	case pf.remove:
		return ws
	case pf.add:
		if pf.text != "" {
			ws.Facts, ws.Text = analyzeScript(pf.path, pf.text, ctx, o.Keep, b, known)
			ws.Keep = keepText(pf.text, ws.Facts)
		}
		return ws
	}
	if o.Prior != nil && !pf.bad {
		src := pf.path
		if pf.from != "" {
			src = pf.from
		}
		if prior, ok := o.Prior(src); ok {
			if text, ok := applyHunks(prior, pf.hunks, b); ok {
				in := inContext(pf.path, text, ctx, o, b, known)
				in.From = pf.from
				return in
			}
		}
	}
	if pf.text != "" {
		ws.Facts, ws.Text = analyzeScript(pf.path, pf.text, ctx, o.Keep, b, known)
		ws.Facts.markFragment(o.Keep)
	}
	return ws
}

// isCreate reports an edit tool told to create a file with the given text
// (Copilot's str_replace_editor command=create): a write of the whole file.
func isCreate(in map[string]any) bool {
	cmd, _ := in["command"].(string)
	_, ok := in["file_text"].(string)
	return ok && cmd == "create"
}

// keepText returns text for the caller to hold, or "" when it is not a
// script (nothing to apply a later edit to) or too long.
func keepText(text string, f *ScriptFacts) string {
	if f == nil || len(text) > MaxScriptText {
		return ""
	}
	k := redactText(text)
	if len(k) > MaxScriptText {
		return ""
	}
	return k
}

// scriptCtx fills ctx from the event like Compute does.
func scriptCtx(e *event.Event, ctx Context) Context {
	if ctx.CWD == "" && e.Session != nil {
		ctx.CWD = e.Session.CWD
	}
	if ctx.OS == "" && e.Host != nil {
		ctx.OS = e.Host.OS
	}
	ctx.OS = strings.ToLower(ctx.OS)
	return ctx
}

// AnalyzeScript returns the shell features of content written to name
// when it is a script, and the text it analysed. A script is content that
// starts with a #! line naming a known interpreter, a file whose extension
// is a script language's (.sh .bash .zsh .ksh .csh .tcsh .fish .command
// .ps1 .psm1 .bat .cmd .py .pyw .js .mjs .cjs .ts .mts .cts .rb .pl .pm
// .php .lua), or a file with no extension or an extension that is not a
// known document, data or compiled-language source format whose content
// parses as POSIX shell. Shell content (csh and fish included, read as
// POSIX shell), PowerShell and cmd content is analysed as a command line
// of its dialect; Python, JavaScript, Ruby, Perl, PHP and Lua content is
// analysed as the program an interpreter reads from a heredoc
// (python3 - <<'EOF'), which is what shellx sees through (shell commands
// handed to exec-style calls, URLs, decoded payloads, reads), in pieces of
// at most 30 KiB, and additionally as POSIX shell when it parses as such,
// so "bash x.py" is not a way around it. Facts is nil when the content is
// not a script. o.Stop bounds the time spent (see ScriptOptions).
func AnalyzeScript(name, content string, ctx Context, o ScriptOptions) (facts *ScriptFacts, text string) {
	return analyzeScript(name, content, ctx, o.Keep, newBudget(o.Stop), nil)
}

// analyzeScript is AnalyzeScript within the budget b. The first piece of
// text the budget pays for and, whenever anything was left out, the last
// 8 KiB of the content are always analysed: a payload sits at the start of
// a script or after the padding that pushed it out of view, so spending
// the event's budget elsewhere (a large content scan) does not hide both
// ends. The credential scan of the text is skipped once the budget is
// spent (and recorded as incomplete), unless known has its result.
func analyzeScript(name, content string, ctx Context, keep ScriptKeep, b *budget, known *knownSecrets) (facts *ScriptFacts, text string) {
	defer func() {
		if recover() != nil {
			facts, text = nil, ""
		}
	}()
	if content == "" {
		return nil, ""
	}
	lang, mustParse := scriptLang(name, content)
	if lang == "" {
		return nil, ""
	}
	if ctx.OS == "" {
		ctx.OS = runtime.GOOS
	}
	c := &computer{e: &event.Event{}, f: make(map[string]any, 32), ctx: ctx}
	a := &scriptAnalysis{c: c, lang: lang, b: b}
	// A long file is analysed as its head and its tail separately, like an
	// oversized command line: joining them would fuse two unrelated lines.
	parts := []string{content}
	if len(content) > maxScan {
		c.f["content.truncated_scan"] = true
		parts = []string{cutHead(content, scanHead), cutTail(content, scanTail)}
	}
	text = headTail(content)
	var fx *shellx.Facts
	for _, part := range parts {
		fx = mergeFacts(fx, a.analyze(part))
	}
	// As for a command line: when the analyzer stopped early, or the
	// budget did, the end of the text (where a payload appended after
	// padding sits) is analysed on its own.
	if (a.cut || fx != nil && fx.Truncated) && len(content) > tailRescan {
		a.forced = true
		fx = mergeFacts(fx, a.analyze(cutTail(content, tailRescan)))
		a.forced = false
	}
	if fx == nil {
		if a.cut {
			// Nothing was analysed before the budget ran out: the facts
			// are unknown, which is not the same as clean.
			return cutFacts(lang), text
		}
		return nil, ""
	}
	if mustParse && (!fx.ParseOK || len(fx.Commands) == 0) {
		return nil, ""
	}
	if a.cut {
		c.f["content.truncated_scan"] = true
		fx.Truncated = true
	}
	switch {
	case known != nil:
		c.secrets = &known.kinds
	case b.spent():
		c.secretsSkipped = true
	}
	c.shellFacts(fx, text, fx.Truncated || len(parts) > 1)
	c.network()
	c.finish()
	return scriptFromFeat(lang, c.f, keep), text
}

// scriptAnalysis is one AnalyzeScript call: the pieces it hands to shellx
// are charged to the budget.
type scriptAnalysis struct {
	c      *computer
	lang   string
	b      *budget
	cut    bool // a piece was skipped for the budget
	forced bool // analyse whatever the budget says
}

// analyze returns the facts of one part of a script.
func (a *scriptAnalysis) analyze(part string) *shellx.Facts {
	switch a.lang {
	case LangShell:
		return a.run(part, shellx.Posix)
	case LangPowerShell:
		return a.run(part, shellx.PowerShell)
	case LangCmd:
		return a.run(part, shellx.Cmd)
	}
	px := a.foreign(part)
	// The same text run by a shell ("bash x.py") is a shell script; real
	// Python or JavaScript does not parse as one.
	if sx := a.run(part, shellx.Posix); sx != nil && sx.ParseOK && len(sx.Commands) > 0 {
		px = mergeFacts(px, sx)
	}
	return px
}

// run analyses text in dialect d when the budget allows.
func (a *scriptAnalysis) run(text string, d shellx.Dialect) *shellx.Facts {
	if !a.forced && !a.b.next() {
		a.cut = true
		return nil
	}
	return a.c.analyzeParts(text, d)
}

// analyzeParts analyses text in dialect d behind a recover, like analyze.
func (c *computer) analyzeParts(text string, d shellx.Dialect) (fx *shellx.Facts) {
	defer func() {
		if recover() != nil {
			c.f["content.analyzer_error"] = true
			fx = nil
		}
	}()
	return shellx.Analyze(text, d)
}

// foreignInterp is the interpreter each non-shell language is analysed
// as: the program reads its code from standard input ("-").
func foreignInterp(lang string) string {
	switch lang {
	case LangPython:
		return "python3"
	case LangJavaScript:
		return "node"
	case LangRuby:
		return "ruby"
	case LangPerl:
		return "perl"
	case LangPHP:
		return "php"
	case LangLua:
		return "lua"
	}
	return ""
}

// foreign analyses code in a non-shell language as the program of an
// interpreter fed by a quoted heredoc, in pieces shellx keeps whole, and
// removes what the synthetic wrapper itself contributed (the interpreter
// command, the inline-code record, the heredoc and their opacity), so only
// what the code does remains. A quoted heredoc hands shellx the code byte
// for byte as one literal: the earlier one-liner form (python3 -c '<code>')
// had to splice every single quote of the code as '\'', and shellx's cost
// grew with the number of splices, to 80 ms for 32 KiB of an ordinary
// Python table.
func (a *scriptAnalysis) foreign(code string) *shellx.Facts {
	prog := foreignInterp(a.lang)
	if prog == "" {
		return nil
	}
	var out *shellx.Facts
	for _, chunk := range lineChunks(code, foreignChunk) {
		body := chunk
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		delim := heredocDelim(body)
		fx := a.run(prog+" - <<'"+delim+"'\n"+body+delim+"\n", shellx.Posix)
		if fx == nil {
			continue
		}
		stripWrapper(fx, prog, a.lang, body)
		out = mergeFacts(out, fx)
	}
	return out
}

// lineChunks splits s into pieces of at most n bytes, at a line end when
// one is in the last quarter of the piece, else at a rune boundary.
func lineChunks(s string, n int) []string {
	var out []string
	for len(s) > n {
		cut := len(cutHead(s, n))
		if i := strings.LastIndexByte(s[:cut], '\n'); i >= cut-n/4 && i > 0 {
			cut = i + 1
		}
		if cut == 0 {
			cut = n
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// heredocDelim returns a heredoc delimiter that is not a line of body.
func heredocDelim(body string) string {
	d := "SPOOR_EOF"
	for i := 0; strings.Contains(body, d) && i < 64; i++ {
		d += "_X"
	}
	return d
}

// stripWrapper removes the facts the synthetic "prog - <<'EOF'" wrapper
// contributed by itself. The heredoc fact goes with it: a heredoc inside
// a shell string the code hands to a shell is not distinguishable from the
// wrapper's own, and shell.heredoc is a weak fact.
func stripWrapper(fx *shellx.Facts, prog, lang, code string) {
	fx.Pipelines = nil // indexes into Commands, which changes below
	for i, cm := range fx.Commands {
		if cm.Origin == shellx.OriginTop && cm.Name == prog {
			fx.Commands = append(fx.Commands[:i:i], fx.Commands[i+1:]...)
			break
		}
	}
	inl := fx.Inline[:0:0]
	for _, ic := range fx.Inline {
		if ic.Lang == lang && (ic.Code == code || strings.HasPrefix(code, ic.Code)) {
			continue
		}
		inl = append(inl, ic)
	}
	fx.Inline = inl
	stillRuns := false
	for _, cm := range fx.Commands {
		if cm.Name == prog {
			stillRuns = true
			break
		}
	}
	if !stillRuns {
		fx.Interpreters = removeString(fx.Interpreters, prog)
	}
	fx.HereDoc = false
	fx.Opaque = removeString(fx.Opaque, "heredoc_interpreter")
	if len(fx.Inline) == 0 {
		fx.Opaque = removeString(fx.Opaque, "inline_code")
	}
}

func removeString(l []string, v string) []string {
	out := l[:0:0]
	for _, x := range l {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// scriptLang returns the language content written to name runs as, and
// whether the content must also parse as shell to count (no shebang, no
// script extension).
func scriptLang(name, content string) (lang string, mustParse bool) {
	if l := shebangLang(content); l != "" {
		return l, false
	}
	ext := pathExt(name)
	if l := extLang(ext); l != "" {
		return l, false
	}
	if strings.HasPrefix(content, "#!") || nonScriptExt(ext) || binaryText(content) {
		return "", false
	}
	return LangShell, true
}

// ScriptLang returns the language of content written to name as
// AnalyzeScript decides it ("" when it is not a script, or when only a
// parse could tell).
func ScriptLang(name, content string) string {
	l, must := scriptLang(name, content)
	if must {
		return ""
	}
	return l
}

func extLang(ext string) string {
	switch ext {
	case ".sh", ".bash", ".zsh", ".ksh", ".csh", ".tcsh", ".fish", ".command":
		return LangShell
	case ".ps1", ".psm1":
		return LangPowerShell
	case ".bat", ".cmd":
		return LangCmd
	case ".py", ".pyw":
		return LangPython
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return LangJavaScript
	case ".rb":
		return LangRuby
	case ".pl", ".pm":
		return LangPerl
	case ".php":
		return LangPHP
	case ".lua":
		return LangLua
	}
	return ""
}

// nonScriptExt reports extensions of documents, data and compiled-language
// sources. Prose and data often parse as shell (a Markdown line is a
// command with arguments), so files with these extensions are analysed
// only when their #! line says they are scripts: remembering them would
// spend the session's bounded script memory on files nobody runs.
func nonScriptExt(ext string) bool {
	switch ext {
	case ".md", ".markdown", ".rst", ".adoc", ".tex", ".html", ".htm", ".xml", ".svg", ".css", ".scss",
		".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv", ".tsv",
		".lock", ".sum", ".mod", ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".java", ".kt",
		".swift", ".cs", ".m", ".scala", ".sql", ".proto", ".tf", ".hcl", ".gradle", ".xsd",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".tgz",
		".jsx", ".tsx", ".vue", ".svelte", ".ipynb", ".log", ".diff", ".patch", ".pem", ".crt", ".key":
		return true
	}
	return false
}

// binaryText reports content that is not text: a NUL byte early on.
func binaryText(s string) bool {
	return strings.IndexByte(cutHead(s, 8<<10), 0) >= 0
}

// shebangLang returns the language a #! line names, or "".
func shebangLang(content string) string {
	if !strings.HasPrefix(content, "#!") {
		return ""
	}
	line := content[2:]
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = cutHead(line, 512)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	prog := baseName(fields[0])
	if prog == "env" {
		prog = ""
		for i := 1; i < len(fields); i++ {
			f := fields[i]
			switch {
			case f == "-u" || f == "--unset" || f == "-C" || f == "--chdir":
				i++ // takes a value
			case strings.HasPrefix(f, "-"), strings.Contains(f, "="):
			default:
				prog = baseName(f)
			}
			if prog != "" {
				break
			}
		}
	}
	return interpLang(prog)
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.ToLower(p)
	return strings.TrimSuffix(p, ".exe")
}

// interpLang maps an interpreter program name to its script language.
// csh, tcsh and fish scripts are read as POSIX shell: their syntax differs,
// but the commands, pipes and redirections an attack is made of read the
// same, and a line that does not parse falls back to shellx's tokenizer.
func interpLang(prog string) string {
	switch prog {
	case "":
		return ""
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "rbash", "busybox",
		"csh", "tcsh", "fish":
		return LangShell
	case "pwsh", "powershell", "pwsh-preview":
		return LangPowerShell
	case "node", "nodejs", "deno", "bun", "tsx", "ts-node":
		return LangJavaScript
	case "luajit":
		return LangLua
	}
	for _, p := range [...]struct{ prefix, lang string }{
		{"python", LangPython}, {"pypy", LangPython}, {"ruby", LangRuby}, {"perl", LangPerl},
		{"php", LangPHP}, {"lua", LangLua},
	} {
		if rest, ok := strings.CutPrefix(prog, p.prefix); ok && versionSuffix(rest) {
			return p.lang
		}
	}
	return ""
}

// versionSuffix reports "", "3", "3.12" and similar.
func versionSuffix(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			return false
		}
	}
	return true
}
