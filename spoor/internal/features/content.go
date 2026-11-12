package features

import (
	"regexp"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
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
	text = c.bound(text)
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

// untrustedDirs are path components under which file content is authored by
// third parties: dependency trees, downloads and scratch space.
var untrustedDirs = map[string]bool{
	"node_modules": true, "vendor": true, "downloads": true, "third_party": true, "site-packages": true,
	"tmp": true, "temp": true,
}

// untrustedSource says why a tool result is attacker-authorable, or "".
// Package registries do not taint: a registry page is not an instruction
// channel an agent is steered through in practice, and counting it made the
// flag near-constant in measured benign sessions.
func (c *computer) untrustedSource() string {
	switch c.toolKind() {
	case event.ToolWebFetch:
		hc, _ := c.f["net.host_classes"].([]string)
		if len(hc) > 0 && allIn(hc, "package_registry") {
			return ""
		}
		return "web_fetch"
	case event.ToolWebSearch:
		return "web_search"
	case event.ToolMCP:
		return "mcp"
	case event.ToolBrowser:
		return "browser"
	case event.ToolFileRead, event.ToolFileList:
		if t := c.e.Target; t != nil {
			if underUntrusted(t.Path) {
				return "file"
			}
			for _, p := range t.Paths {
				if underUntrusted(p) {
					return "file"
				}
			}
		}
		if cl, _ := c.f["path.classes"].([]string); contains(cl, "temp") || contains(cl, "downloads") {
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
			for _, p := range reads {
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

func allIn(list []string, v string) bool {
	for _, x := range list {
		if x != v {
			return false
		}
	}
	return true
}

func underUntrusted(p string) bool {
	if p == "" {
		return false
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if untrustedDirs[strings.ToLower(seg)] {
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

// autorunPatterns detect content that makes an agent or IDE run something or
// widen its own permissions. They are applied only to files whose path
// classifies as a control file, so ordinary JSON that happens to contain
// "command" is not considered.
var autorunPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"hook_command", regexp.MustCompile(`(?ism)"hooks"\s*:.*"(command|bash|powershell)"\s*:|^\s*\[\[?hooks[\].\]]`)},
	{"always_apply", regexp.MustCompile(`(?i)alwaysApply\s*:\s*true`)},
	{"folder_open_task", regexp.MustCompile(`(?i)"runOn"\s*:\s*"folderOpen"`)},
	{"mcp_server", regexp.MustCompile(`(?i)"mcpServers"\s*:|\[mcp_servers[\].]|"mcp_servers"\s*:|"context_servers"\s*:`)},
	{"permission_escalation", regexp.MustCompile(`(?i)bypassPermissions|"defaultMode"\s*:\s*"dontAsk"|enableAllProjectMcpServers"\s*:\s*true|"Bash\(\*\)"|"Bash\(\s*\*?\s*:\s*\*\)"|approval_policy\s*=\s*"never"|chat\.tools\.(global\.)?autoApprove"\s*:\s*true|task\.allowAutomaticTasks"\s*:\s*"on"|security\.workspace\.trust\.enabled"\s*:\s*false|"alwaysAllow"\s*:\s*\[\s*"|"autoApprove"\s*:\s*(true|\[\s*")|"trust"\s*:\s*true|"approvalMode"\s*:\s*"yolo"|dangerously-skip-permissions`)},
	{"base_url_override", regexp.MustCompile(`(?i)"?[A-Z0-9_]*_(BASE_URL|API_BASE)"?\s*[:=]|"apiKeyHelper"\s*:|(?m)^\s*base_url\s*=`)},
	{"hooks_disabled", regexp.MustCompile(`(?is)"disableAllHooks"\s*:\s*true|"hooksConfig"\s*:\s*\{[^}]{0,512}"enabled"\s*:\s*false`)},
	{"sandbox_disabled", regexp.MustCompile(`(?is)"sandbox"\s*:\s*(false|\{[^}]{0,512}"enabled"\s*:\s*false)|dangerouslyDisableSandbox|sandbox_mode\s*=\s*"danger-full-access"`)},
}

var mcpServersKey = regexp.MustCompile(`(?i)"servers"\s*:\s*\{`)

// AutorunVocabulary is the vocabulary of Autorun results and of the
// write.autorun_kinds feature.
var AutorunVocabulary = []string{
	"hook_command", "always_apply", "folder_open_task", "mcp_server",
	"permission_escalation", "base_url_override", "hooks_disabled", "sandbox_disabled",
}

// Autorun returns what content, destined for the agent control file name,
// would make an agent or IDE run or allow: hook commands, always-applied
// rules, folder-open tasks, MCP server entries, permission escalation,
// model endpoint overrides, and hook or sandbox switches. Discovery uses the
// same function on files at rest. The input is bounded to its head and
// tail like every other content scan.
func Autorun(name, content string) []string {
	if content == "" {
		return nil
	}
	content = headTail(content)
	var out []string
	for _, p := range autorunPatterns {
		if p.re.MatchString(content) {
			out = append(out, p.kind)
		}
	}
	base := strings.ToLower(name)
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if base == "mcp.json" && !contains(out, "mcp_server") && mcpServersKey.MatchString(content) {
		out = append(out, "mcp_server")
	}
	return out
}

// GitExecKeyVocabulary is the vocabulary of GitExecKeys results and of the
// write.exec_keys feature.
var GitExecKeyVocabulary = []string{
	"core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "core.hookspath",
	"core.gitproxy", "alias.shell", "diff.textconv", "diff.command", "filter.clean",
	"filter.smudge", "filter.process", "merge.driver", "credential.helper.shell",
	"include.path", "includeif.path", "sequence.editor", "gpg.program", "uploadpack.packobjectshook",
}

const maxGitLines = 20000

// GitExecKeys parses git-config syntax and returns the keys whose value git
// runs as a command (or that pull in more config): core.fsmonitor other
// than a boolean, core.sshCommand, aliases starting with "!", diff drivers,
// clean/smudge filters, merge drivers, shell credential helpers and
// includes. A repository-local .git/config with one of these runs code the
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
			if key == "helper" && strings.HasPrefix(val, "!") {
				add("credential.helper.shell")
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
