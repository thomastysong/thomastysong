package features

import (
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
// analysis runs in the hook process, so the text, the number of files one
// patch names and the bytes analysed are all capped.
const (
	// maxPatchFiles is how many files of one apply_patch envelope are
	// analysed; the rest are left out (WrittenScript.Partial is not set
	// for them: they are simply not remembered).
	maxPatchFiles = 32
	// maxPatchText is how much of a patch envelope is parsed.
	maxPatchText = 1 << 20
	// foreignChunk is the largest piece of non-shell code handed to
	// shellx in one interpreter one-liner: shellx keeps at most 64 KiB of
	// one inline code string.
	foreignChunk = 60 << 10
)

// WrittenScript is one file a file-tool event writes, as the engine needs
// it for write-then-run.
type WrittenScript struct {
	// Path is the file as the event names it (target path, or the path
	// in a patch envelope); the caller normalizes it.
	Path string
	// Facts are the shell features of the content, or nil when the
	// content is not a script.
	Facts *ScriptFacts
	// Replace is true when the content replaces the file (a write, a
	// patch that adds the file) and false for a fragment (an edit, a
	// patch hunk), whose facts add to what is known about the file.
	Replace bool
	// Remove is true when the event deletes the file (a patch).
	Remove bool
	// From is the previous path of a file a patch moves.
	From string
	// Text is the analysed content (bounded: head and tail of a long
	// file). It lets the caller scan the script for remembered values;
	// it is never stored.
	Text string
}

// WrittenScripts returns the files e writes with what is known about
// their content, for a file_write or file_edit tool event, and nil for any
// other event. Content is the tool input (Content.FileContent, or the
// write keys of Content.ToolInput); an apply_patch envelope is split per
// file. A file whose content is not a script is returned with nil Facts,
// so the caller forgets what it knew about a file a write replaced.
// WrittenScripts never panics and never opens a file.
func WrittenScripts(e *event.Event, ctx Context) (out []WrittenScript) {
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
	if patch := patchText(e); patch != "" {
		for _, pf := range parsePatch(patch) {
			ws := WrittenScript{Path: pf.path, Replace: pf.add, Remove: pf.remove, From: pf.from}
			if !pf.remove && pf.text != "" {
				ws.Facts, ws.Text = AnalyzeScript(pf.path, pf.text, ctx)
			}
			out = append(out, ws)
		}
		return out
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
	ws := WrittenScript{Path: path, Replace: kind == event.ToolFileWrite}
	if text := writtenContent(e); text != "" {
		ws.Facts, ws.Text = AnalyzeScript(path, text, ctx)
	}
	return []WrittenScript{ws}
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
// is a script language's (.sh .bash .zsh .ksh .command .ps1 .psm1 .bat
// .cmd .py .pyw .js .mjs .cjs .ts .mts .cts .rb .pl .pm .php .lua), or a
// file with no extension or an extension that is not a known document,
// data or compiled-language source format whose content parses as POSIX
// shell. Shell, PowerShell and cmd content is analysed as a command line
// of its dialect; Python, JavaScript, Ruby, Perl, PHP and Lua content is
// analysed as the code of an interpreter one-liner (python3 -c '<code>'),
// which is what shellx sees through (shell commands handed to exec-style
// calls, URLs, decoded payloads, reads), and additionally as POSIX shell
// when it parses as such, so "bash x.py" is not a way around it. Facts is
// nil when the content is not a script.
func AnalyzeScript(name, content string, ctx Context) (facts *ScriptFacts, text string) {
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
		ctx.OS = "linux"
	}
	c := &computer{e: &event.Event{}, f: make(map[string]any, 32), ctx: ctx}
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
		var px *shellx.Facts
		switch lang {
		case LangShell:
			px = c.analyzeParts(part, shellx.Posix)
		case LangPowerShell:
			px = c.analyzeParts(part, shellx.PowerShell)
		case LangCmd:
			px = c.analyzeParts(part, shellx.Cmd)
		default:
			px = c.analyzeForeign(lang, part)
			// The same text run by a shell ("bash x.py") is a shell
			// script; real Python or JavaScript does not parse as one.
			if sx := c.analyzeParts(part, shellx.Posix); sx != nil && sx.ParseOK && len(sx.Commands) > 0 {
				px = mergeFacts(px, sx)
			}
		}
		fx = mergeFacts(fx, px)
	}
	// As for a command line: when the analyzer stopped early, the end of
	// the text (where a payload appended after padding sits) is analysed
	// on its own.
	if fx != nil && fx.Truncated && len(content) > tailRescan {
		tail := cutTail(content, tailRescan)
		switch lang {
		case LangShell:
			fx = mergeFacts(fx, c.analyzeParts(tail, shellx.Posix))
		case LangPowerShell:
			fx = mergeFacts(fx, c.analyzeParts(tail, shellx.PowerShell))
		case LangCmd:
			fx = mergeFacts(fx, c.analyzeParts(tail, shellx.Cmd))
		default:
			fx = mergeFacts(fx, c.analyzeForeign(lang, tail))
		}
	}
	if fx == nil || (mustParse && (!fx.ParseOK || len(fx.Commands) == 0)) {
		return nil, ""
	}
	c.shellFacts(fx, text, fx.Truncated || len(parts) > 1)
	c.network()
	c.finish()
	return scriptFromFeat(lang, c.f), text
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

// foreignInterp is the interpreter one-liner each non-shell language is
// analysed as: the program name and its code flag.
func foreignInterp(lang string) (prog, flag string) {
	switch lang {
	case LangPython:
		return "python3", "-c"
	case LangJavaScript:
		return "node", "-e"
	case LangRuby:
		return "ruby", "-e"
	case LangPerl:
		return "perl", "-e"
	case LangPHP:
		return "php", "-r"
	case LangLua:
		return "lua", "-e"
	}
	return "", ""
}

// analyzeForeign analyses code in a non-shell language as the code of an
// interpreter one-liner, in chunks shellx keeps whole, and removes what
// the synthetic wrapper itself contributed (the interpreter command, the
// inline-code record and its opacity), so only what the code does
// remains.
func (c *computer) analyzeForeign(lang, code string) *shellx.Facts {
	prog, flag := foreignInterp(lang)
	if prog == "" {
		return nil
	}
	chunks := []string{code}
	if len(code) > foreignChunk {
		chunks = []string{cutHead(code, foreignChunk), cutTail(code, foreignChunk)}
		if len(code) > 2*foreignChunk {
			c.f["content.truncated_scan"] = true
		}
	}
	var out *shellx.Facts
	for _, chunk := range chunks {
		// Single quotes are the one POSIX quoting with no escapes inside,
		// so '\'' splicing hands shellx the code byte for byte whatever it
		// contains.
		wrapper := prog + " " + flag + " '" + strings.ReplaceAll(chunk, "'", `'\''`) + "'"
		fx := c.analyzeParts(wrapper, shellx.Posix)
		if fx == nil {
			continue
		}
		stripWrapper(fx, prog, lang, chunk)
		out = mergeFacts(out, fx)
	}
	return out
}

// stripWrapper removes the facts the synthetic "prog flag '<code>'"
// wrapper contributed by itself.
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
	case ".sh", ".bash", ".zsh", ".ksh", ".command":
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
func interpLang(prog string) string {
	switch prog {
	case "":
		return ""
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "rbash", "busybox":
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

// patchText returns the apply_patch envelope a file-edit event carries,
// or "".
func patchText(e *event.Event) string {
	if e.Content == nil || len(e.Content.ToolInput) == 0 {
		return ""
	}
	for _, k := range []string{"input", "patch", "content", "diff"} {
		if s, ok := e.Content.ToolInput[k].(string); ok && isPatch(s) {
			return s
		}
	}
	return ""
}

func isPatch(s string) bool {
	head := cutHead(s, 4096)
	return strings.Contains(head, "*** Begin Patch") ||
		strings.HasPrefix(head, "*** Add File: ") || strings.HasPrefix(head, "*** Update File: ") ||
		strings.Contains(head, "\n*** Add File: ") || strings.Contains(head, "\n*** Update File: ")
}

// patchFile is one file of an apply_patch envelope.
type patchFile struct {
	path, from  string
	add, remove bool
	text        string // added lines without their "+"
}

// parsePatch splits an apply_patch envelope ("*** Add File: p" followed
// by "+" lines, "*** Update File: p" with an optional "*** Move to: q" and
// hunks, "*** Delete File: p") into the content each file gains. Only
// added lines are kept: they are what the patch writes.
func parsePatch(patch string) []patchFile {
	if len(patch) > maxPatchText {
		patch = cutHead(patch, maxPatchText)
	}
	var out []patchFile
	var cur *patchFile
	var b strings.Builder
	flush := func() {
		if cur != nil {
			cur.text = b.String()
			out = append(out, *cur)
		}
		cur = nil
		b.Reset()
	}
	for len(patch) > 0 {
		line := patch
		if i := strings.IndexByte(patch, '\n'); i >= 0 {
			line, patch = patch[:i], patch[i+1:]
		} else {
			patch = ""
		}
		line = strings.TrimSuffix(line, "\r")
		if rest, ok := strings.CutPrefix(line, "*** "); ok {
			switch {
			case strings.HasPrefix(rest, "Add File: "), strings.HasPrefix(rest, "Update File: "), strings.HasPrefix(rest, "Delete File: "):
				flush()
				if len(out) >= maxPatchFiles {
					return out
				}
				verb, p, _ := strings.Cut(rest, ": ")
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				cur = &patchFile{path: p, add: verb == "Add File", remove: verb == "Delete File"}
				continue
			case strings.HasPrefix(rest, "Move to: "):
				if cur != nil && !cur.remove {
					to := strings.TrimSpace(strings.TrimPrefix(rest, "Move to: "))
					if to != "" {
						cur.from, cur.path = cur.path, to
					}
				}
				continue
			case rest == "Begin Patch", rest == "End Patch", rest == "End of File":
				continue
			}
		}
		if cur == nil || cur.remove {
			continue
		}
		if added, ok := strings.CutPrefix(line, "+"); ok && b.Len() < maxPatchText {
			b.WriteString(added)
			b.WriteByte('\n')
		}
	}
	flush()
	return out
}
