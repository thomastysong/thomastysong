package features

import (
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/mcpconf"
)

func (c *computer) content() {
	c.prompt()
	c.write()
	c.output()
}

// scan sets <prefix>.secret_kinds, .hidden_unicode and .markers for text.
func (c *computer) scan(prefix, text string) {
	if text == "" {
		return
	}
	text = c.bound(text)
	tf := classify.ScanText(text)
	c.f[prefix+".hidden_unicode"] = tf.HiddenUnicode()
	c.setList(prefix+".markers", sortedUniq(tf.Markers))
	c.setList(prefix+".secret_kinds", secretKinds(text))
}

func (c *computer) prompt() {
	text := ""
	if c.e.Content != nil {
		text = c.e.Content.PromptText
	}
	if text == "" && c.e.Prompt != nil {
		text = c.e.Prompt.Text
	}
	c.scan("prompt", text)
}

// writeKeys are the tool-input fields that carry content being written, by
// agent: Claude (content, new_string, edits[].new_string, new_source),
// Copilot (file_text, new_str), Codex (input/patch of apply_patch), Gemini
// (content, new_string), Cursor (contents).
var writeKeys = []string{"content", "contents", "new_string", "new_str", "file_text", "new_source", "patch", "input", "text"}

func writtenContent(e *event.Event) string {
	if e.Content == nil {
		return ""
	}
	if e.Content.FileContent != "" {
		return e.Content.FileContent
	}
	in := e.Content.ToolInput
	if len(in) == 0 {
		return ""
	}
	var parts []string
	size := 0
	add := func(s string) {
		if s == "" || size > 2*maxScan {
			return
		}
		parts = append(parts, s)
		size += len(s)
	}
	for _, k := range writeKeys {
		if s, ok := in[k].(string); ok {
			add(s)
		}
	}
	if edits, ok := in["edits"].([]any); ok {
		for i, ed := range edits {
			if i >= 256 {
				break
			}
			if m, ok := ed.(map[string]any); ok {
				for _, k := range []string{"new_string", "new_str", "content"} {
					if s, ok := m[k].(string); ok {
						add(s)
					}
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

func (c *computer) write() {
	switch c.toolKind() {
	case event.ToolFileWrite, event.ToolFileEdit:
	default:
		return
	}
	text := writtenContent(c.e)
	if text == "" {
		return
	}
	c.scan("write", text)
	// Autorun and GitExecKeys bound their own input (and Autorun decodes
	// a whole configuration file when it is small enough to).
	ctl, _ := c.f["path.control_file"].(bool)
	if ctl {
		name := ""
		if c.e.Target != nil {
			name = c.e.Target.Path
		}
		kinds := Autorun(name, text)
		c.f["write.autorun"] = len(kinds) > 0
		c.setList("write.autorun_kinds", kinds)
	}
	if c.isGitConfigTarget() {
		c.setList("write.exec_keys", GitExecKeys(text))
	}
}

func (c *computer) isGitConfigTarget() bool {
	t := c.e.Target
	if t == nil {
		return false
	}
	paths := append([]string{t.Path}, t.Paths...)
	for _, p := range paths {
		l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
		if strings.HasSuffix(l, ".gitconfig") || strings.HasSuffix(l, ".git/config") ||
			strings.HasSuffix(l, "/git/config") || strings.HasSuffix(l, ".git/config.worktree") ||
			strings.HasSuffix(l, ".gitmodules") {
			return true
		}
	}
	return false
}

func (c *computer) output() {
	out := ""
	if c.e.Content != nil {
		out = c.e.Content.ToolOutput
	}
	c.scan("output", out)
	if c.e.Type != event.TypeToolPost && out == "" {
		return
	}
	if c.e.Tool == nil {
		return
	}
	if src := c.untrustedSource(); src != "" {
		c.f["output.untrusted"] = true
		c.f["output.untrusted_source"] = src
	} else {
		c.f["output.untrusted"] = false
	}
}

// untrustedDir reports path components under which file content is
// authored by third parties: dependency trees, downloads and scratch space.
func untrustedDir(seg string) bool {
	switch seg {
	case "node_modules", "vendor", "downloads", "third_party", "site-packages",
		"tmp", "temp":
		return true
	}
	return false
}

// untrustedSource says why a tool result is attacker-authorable, or "".
// Every web fetch is: package registries and CDNs serve whatever their
// publishers upload (READMEs, skills, files from any GitHub repository), so
// no host class is exempt here. Rules that want to discount particular
// hosts do so visibly, with net.host or net.host_classes in an allow block
// or a list such as trusted_content_hosts.
func (c *computer) untrustedSource() string {
	switch c.toolKind() {
	case event.ToolWebFetch:
		return "web_fetch"
	case event.ToolWebSearch:
		return "web_search"
	case event.ToolMCP:
		return "mcp"
	case event.ToolBrowser:
		return "browser"
	case event.ToolFileRead, event.ToolFileList:
		sid := c.sessionID()
		own := false
		if t := c.e.Target; t != nil {
			for _, p := range append([]string{t.Path}, t.Paths...) {
				if p == "" {
					continue
				}
				if rest, ok := ownTempRest(p, sid); ok {
					own = true
					if underUntrusted(rest) {
						return "file"
					}
					continue
				}
				if underUntrusted(p) {
					return "file"
				}
			}
		}
		if cl, _ := c.f["path.classes"].([]string); contains(cl, "downloads") || contains(cl, "temp") && !own {
			return "file"
		}
	case event.ToolShell:
		if d, _ := c.f["shell.downloads"].(bool); d {
			return "shell"
		}
		if cmds, _ := c.f["shell.cmds"].([]map[string]any); ghReads(cmds) {
			return "shell"
		}
		if reads, _ := c.f["shell.reads"].([]string); len(reads) > 0 {
			sid := c.sessionID()
			for _, p := range reads {
				if rest, ok := ownTempRest(p, sid); ok {
					p = rest
				}
				if underUntrusted(p) {
					return "shell"
				}
			}
		}
		if cl, _ := c.f["shell.read_classes"].([]string); contains(cl, "downloads") {
			return "shell"
		}
	}
	return ""
}

func (c *computer) sessionID() string {
	if c.e.Session == nil {
		return ""
	}
	return c.e.Session.ID
}

// ownTempRest reports a path inside the session's own temporary directory
// and returns the part of it below that directory. That directory is a
// component equal to the session id below a temporary directory (Claude
// Code's scratchpad is /tmp/claude-<uid>/<project>/<session id>/scratchpad).
// The id is long and random, so only the session made the directory, and
// what is in it is the agent's own work; a dependency tree or a download
// inside it is still third-party, which the caller checks on the rest.
// Without this, an agent that works in its scratchpad (cd $S && sed ...)
// marks most of its own reads untrusted.
func ownTempRest(p, sid string) (string, bool) {
	if len(sid) < 16 || !strings.Contains(p, sid) {
		return "", false
	}
	segs := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	temp := false
	for i, seg := range segs {
		switch l := strings.ToLower(seg); {
		case l == "tmp" || l == "temp":
			temp = true
		case seg == sid && temp:
			return strings.Join(segs[i+1:], "/"), true
		case i == 0 && (l == "$tmpdir" || l == "${tmpdir}" || l == "%temp%" || l == "$env:temp"):
			temp = true
		}
	}
	return "", false
}

func underUntrusted(p string) bool {
	if p == "" {
		return false
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if untrustedDir(strings.ToLower(seg)) {
			return true
		}
	}
	return false
}

// ghReads reports `gh issue|pr view|list|diff` and `gh api`: content written
// by whoever can open an issue or a pull request.
func ghReads(cmds []map[string]any) bool {
	for _, cm := range cmds {
		if cm["name"] != "gh" {
			continue
		}
		args, _ := cm["args"].([]string)
		var pos []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				pos = append(pos, a)
			}
			if len(pos) == 2 {
				break
			}
		}
		if len(pos) >= 1 && pos[0] == "api" {
			return true
		}
		if len(pos) == 2 && (pos[0] == "issue" || pos[0] == "pr" || pos[0] == "run") {
			switch pos[1] {
			case "view", "list", "diff", "status", "checks":
				return true
			}
		}
	}
	return false
}

// autorunPattern is one key pattern of Autorun.
type autorunPattern struct {
	kind string
	re   *regexp.Regexp
}

// autorunRegexps are compiled on the first Autorun call, not at package
// init: they are nine large case-insensitive patterns that cost 1.3 to 2 ms
// per process to compile, and most processes that link features (the hook
// supervisor, an observe-mode hook worker) never call Autorun.
type autorunRegexps struct {
	// patterns detect content that makes an agent or IDE run something or
	// widen its own permissions. They are applied only to files whose path
	// classifies as a control file, so ordinary JSON that happens to
	// contain "command" is not considered.
	patterns []autorunPattern
	// mcpServersKey is VS Code's "servers" map, an MCP declaration only in
	// a file named mcp.json.
	mcpServersKey *regexp.Regexp
}

var (
	autorunOnce sync.Once
	autorunTab  *autorunRegexps
)

// autorunRE returns the compiled patterns, compiling them on first use.
// A plain sync.Once rather than sync.OnceValue: the latter is a call at
// package init and allocates there, and this file's point is that linking
// features costs no init work at all.
func autorunRE() *autorunRegexps {
	autorunOnce.Do(func() { autorunTab = compileAutorun() })
	return autorunTab
}

func compileAutorun() *autorunRegexps {
	return &autorunRegexps{
		patterns: []autorunPattern{
			{"hook_command", regexp.MustCompile(`(?ism)"hooks"\s*:.*"(command|bash|powershell)"\s*:|^\s*\[\[?hooks[\].\]]`)},
			{"always_apply", regexp.MustCompile(`(?i)alwaysApply\s*:\s*true`)},
			{"folder_open_task", regexp.MustCompile(`(?i)"runOn"\s*:\s*"folderOpen"`)},
			{"mcp_server", regexp.MustCompile(`(?i)"mcpServers"\s*:|\[mcp_servers[\].]|"mcp_servers"\s*:|"context_servers"\s*:`)},
			{"permission_escalation", regexp.MustCompile(`(?i)bypassPermissions|"defaultMode"\s*:\s*"dontAsk"|enableAllProjectMcpServers"\s*:\s*true|"Bash\(\*\)"|"Bash\(\s*\*?\s*:\s*\*\)"|approval_policy\s*=\s*"never"|chat\.tools\.(global\.)?autoApprove"\s*:\s*true|task\.allowAutomaticTasks"\s*:\s*"on"|security\.workspace\.trust\.enabled"\s*:\s*false|"alwaysAllow"\s*:\s*\[\s*"|"autoApprove"\s*:\s*(true|\[\s*")|"trust"\s*:\s*true|"approvalMode"\s*:\s*"yolo"|dangerously-skip-permissions`)},
			{"base_url_override", regexp.MustCompile(`(?i)"?[A-Z0-9_]*_(BASE_URL|API_BASE)"?\s*[:=]|"apiKeyHelper"\s*:|(?m)^\s*base_url\s*=`)},
			{"hooks_disabled", regexp.MustCompile(`(?is)"disableAllHooks"\s*:\s*true|"hooksConfig"\s*:\s*\{[^}]{0,512}"enabled"\s*:\s*false`)},
			{"sandbox_disabled", regexp.MustCompile(`(?is)"sandbox"\s*:\s*(false|\{[^}]{0,512}"enabled"\s*:\s*false)|dangerouslyDisableSandbox|sandbox_mode\s*=\s*"danger-full-access"`)},
		},
		mcpServersKey: regexp.MustCompile(`(?i)"servers"\s*:\s*\{`),
	}
}

// AutorunVocabulary is the vocabulary of Autorun results and of the
// write.autorun_kinds feature.
var AutorunVocabulary = []string{
	"hook_command", "always_apply", "folder_open_task", "mcp_server",
	"permission_escalation", "base_url_override", "hooks_disabled", "sandbox_disabled",
}

// maxAutorunParse is the largest content Autorun decodes as a whole
// configuration file. Larger content, and content that does not decode (an
// edit fragment, a truncated capture), is matched with key patterns over its
// head and tail instead.
const maxAutorunParse = 256 << 10

// Autorun returns what content, destined for the agent control file name,
// would make an agent or IDE run or allow: hook commands, always-applied
// rules, folder-open tasks, MCP server entries, permission escalation,
// model endpoint overrides, and hook or sandbox switches. Discovery uses the
// same function on files at rest.
//
// MCP server entries are found by decoding the content (JSON, JSONC, TOML
// or YAML) with internal/mcpconf, which knows the per-agent declaration
// keys (mcpServers in JSON and YAML, "amp.mcpServers", opencode/Crush/Kilo
// "mcp", Zed "context_servers", VS Code "servers", Codex and Hermes
// mcp_servers, goose extensions) and accepts an entry only when it declares
// something to launch or connect to (command, args, url). A file that
// decodes but declares no such entry (an empty server map) reports none.
// Only content that does not decode falls back to the key patterns.
func Autorun(name, content string) []string {
	if content == "" {
		return nil
	}
	declared, decoded := mcpDeclared(name, content)
	scan := headTail(content)
	re := autorunRE()
	var out []string
	for _, p := range re.patterns {
		hit := false
		if p.kind == "mcp_server" {
			switch {
			case decoded:
				hit = declared
			default:
				hit = p.re.MatchString(scan) || (isMCPJSON(name) && re.mcpServersKey.MatchString(scan))
			}
		} else {
			hit = p.re.MatchString(scan)
		}
		if hit {
			out = append(out, p.kind)
		}
	}
	return out
}

// mcpDeclared decodes content as an MCP configuration and reports whether it
// declares at least one server, and whether it could be decoded at all. The
// content is read in the syntax its file name implies and, unless that
// already found a server, once more in the syntax sniffed from the content
// alone: an edit fragment ("name": {"command": ...}) or TOML written to a
// .json name still declares what it declares.
func mcpDeclared(name, content string) (declared, decoded bool) {
	if len(content) > maxAutorunParse {
		return false, false
	}
	data := []byte(content)
	for _, n := range []string{name, ""} {
		servers, err := mcpconf.Parse(n, data, mcpconf.FormatAuto)
		if err != nil && !errors.Is(err, mcpconf.ErrTooManyServers) {
			continue
		}
		decoded = true
		if len(servers) > 0 {
			return true, true
		}
	}
	return false, decoded
}

func isMCPJSON(name string) bool {
	base := strings.ToLower(name)
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return base == "mcp.json"
}

// GitExecKeyVocabulary is the vocabulary of GitExecKeys results and of the
// write.exec_keys feature.
var GitExecKeyVocabulary = []string{
	"core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "core.hookspath",
	"core.gitproxy", "alias.shell", "diff.textconv", "diff.command", "filter.clean",
	"filter.smudge", "filter.process", "merge.driver", "credential.helper.shell",
	"include.path", "includeif.path", "sequence.editor", "gpg.program", "uploadpack.packobjectshook",
	"credential.helper", "core.askpass",
}

const maxGitLines = 20000

// GitExecKeys parses git-config syntax and returns the keys whose value git
// runs as a command (or that pull in more config): core.fsmonitor other
// than a boolean, core.sshCommand, core.askPass, aliases starting with "!",
// diff drivers, clean/smudge filters, merge drivers, credential helpers
// that are shell snippets ("!...": credential.helper.shell) or absolute
// program paths (git-credential(1) runs those as given:
// credential.helper), and includes. A repository-local .git/config with one of these runs code the
// moment an agent or IDE calls git (threat research R14).
func GitExecKeys(text string) []string {
	text = headTail(text)
	var out []string
	add := func(k string) {
		for _, x := range out {
			if x == k {
				return
			}
		}
		out = append(out, k)
	}
	section, sub := "", ""
	lines := strings.Split(text, "\n")
	if len(lines) > maxGitLines {
		lines = lines[:maxGitLines]
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			hdr := strings.TrimSpace(line[1:end])
			sub = ""
			if q := strings.IndexByte(hdr, '"'); q >= 0 {
				sub = strings.Trim(hdr[q:], `"`)
				hdr = strings.TrimSpace(hdr[:q])
			} else if d := strings.IndexByte(hdr, '.'); d >= 0 {
				sub = hdr[d+1:]
				hdr = hdr[:d]
			}
			section = strings.ToLower(hdr)
			rest := strings.TrimSpace(line[end+1:])
			if rest == "" {
				continue
			}
			line = rest // "[core] editor = x" on one line
		}
		key, val, hasVal := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.Trim(strings.TrimSpace(val), `"`)
		lval := strings.ToLower(val)
		switch section {
		case "core":
			switch key {
			case "fsmonitor":
				if hasVal && lval != "true" && lval != "false" && lval != "" && lval != "yes" && lval != "no" && lval != "on" && lval != "off" && lval != "0" && lval != "1" {
					add("core.fsmonitor")
				}
			case "sshcommand":
				add("core.sshcommand")
			case "pager":
				add("core.pager")
			case "editor":
				add("core.editor")
			case "hookspath":
				add("core.hookspath")
			case "gitproxy":
				add("core.gitproxy")
			case "askpass":
				add("core.askpass")
			}
		case "alias":
			if strings.HasPrefix(val, "!") {
				add("alias.shell")
			}
		case "diff":
			if sub != "" && key == "textconv" {
				add("diff.textconv")
			}
			if sub != "" && key == "command" {
				add("diff.command")
			}
		case "filter":
			switch key {
			case "clean", "smudge", "process":
				add("filter." + key)
			}
		case "merge":
			if sub != "" && key == "driver" {
				add("merge.driver")
			}
		case "credential":
			if key == "helper" {
				switch {
				case strings.HasPrefix(val, "!"):
					add("credential.helper.shell")
				case isAbsProgram(val):
					add("credential.helper")
				}
			}
		case "include":
			if key == "path" {
				add("include.path")
			}
		case "includeif":
			if key == "path" {
				add("includeif.path")
			}
		case "sequence":
			if key == "editor" {
				add("sequence.editor")
			}
		case "gpg":
			if key == "program" {
				add("gpg.program")
			}
		case "uploadpack":
			if key == "packobjectshook" {
				add("uploadpack.packobjectshook")
			}
		}
	}
	return out
}

// isAbsProgram reports a value git treats as an absolute program path: a
// path rooted at a slash or backslash, or a drive path (git's
// is_absolute_path on Windows).
func isAbsProgram(v string) bool {
	switch {
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, `\`):
		return true
	case len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/'):
		c := v[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}
