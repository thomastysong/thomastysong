package features

import (
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// controlClass reports the path classes of files that make an agent, an
// IDE or git run something or trust something: writing one is how a prompt
// injection becomes persistent code execution.
func controlClass(class string) bool {
	switch class {
	case "agent_config", "agent_managed_policy", "agent_hook", "agent_memory",
		"agent_skill", "mcp_config", "vcs_hook", "vcs_internal", "startup_item":
		return true
	}
	return false
}

// IsControlClass reports whether classes include an agent, IDE or VCS
// control-file class.
func IsControlClass(classes []string) bool {
	for _, c := range classes {
		if controlClass(c) {
			return true
		}
	}
	return false
}

func (c *computer) paths() {
	k := c.toolKind()
	switch k {
	case event.ToolFileRead, event.ToolFileWrite, event.ToolFileEdit, event.ToolFileList:
	default:
		return
	}
	t := c.e.Target
	if t == nil {
		return
	}
	var all uniqList
	all.add(t.Path)
	all.addAll(t.Paths)
	if len(all.list) == 0 {
		return
	}
	// A tool call naming thousands of paths is classified on its first and
	// last maxList; path.classes is then marked incomplete.
	paths, cut := headTailCut(all.list, maxList)
	pc := c.pathCtx()
	classes := pathClasses(paths, pc)
	c.setDerived("path.classes", classes, cut)
	read := k == event.ToolFileRead || k == event.ToolFileList
	c.f["path.sensitive_read"] = read && classify.IsSensitiveRead(classes)
	c.f["path.sensitive_write"] = !read && classify.IsSensitiveWrite(classes)
	c.f["path.outside_cwd"] = contains(classes, "outside_cwd")
	c.f["path.control_file"] = IsControlClass(classes)
	if ext := pathExt(t.Path); ext != "" {
		c.f["path.ext"] = ext
	}
	evasion := false
	for _, p := range paths {
		if NormalizationEvasion(p, pc) {
			evasion = true
			break
		}
	}
	c.f["path.normalization_evasion"] = evasion
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// pathExt returns the lower-case extension of the last path component,
// with its dot, or "" when there is none (".bashrc" has none).
func pathExt(p string) string {
	if p == "" || len(p) > 4096 {
		return ""
	}
	base := p
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	i := strings.LastIndexByte(base, '.')
	if i <= 0 || i == len(base)-1 || len(base)-i > 16 {
		return ""
	}
	return strings.ToLower(base[i:])
}

// controlNames are the canonical spellings of agent control files and the
// directories that hold them. A case-only variant of one of these on a
// case-insensitive filesystem opens the same file while slipping past a
// protection that compares names exactly (threat research rule R12,
// CVE-2025-59944 class).
var controlNames = []string{
	".claude", ".claude.json", "settings.json", "settings.local.json", ".mcp.json", "mcp.json",
	".cursor", "hooks.json", "rules", ".cursorrules", ".codex", "config.toml", "requirements.toml",
	".gemini", ".env", ".kiro", ".amazonq", ".roo", ".vscode", "tasks.json", "launch.json",
	"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".github", "copilot-instructions.md",
	".clinerules", ".windsurfrules", "skills", "agents", "commands", "hooks", ".git", "config",
	"managed-settings.json", "managed-settings.d", "policy.d", "system-defaults.json", ".copilot",
	".windsurf", ".continue", ".zed", "SKILL.md",
}

// NormalizationEvasion reports whether path names an agent control file
// only after the normalization the target filesystem applies: a case-only
// variant (Windows, macOS), a trailing dot or space or an NTFS alternate
// data stream (Windows), or an 8.3 short name (Windows). On Linux every one
// of those is a different file, so the answer there is always false. 8.3
// names are matched by their generated prefix (".claude" -> "CLAUDE~1"); a
// short name the filesystem generated differently is a known gap.
func NormalizationEvasion(path string, ctx classify.PathCtx) bool {
	if path == "" || len(path) > 4096 {
		return false
	}
	os := strings.ToLower(ctx.OS)
	win := os == "windows" || os == "win" || os == "win32"
	fold := win || os == "darwin" || os == "macos"
	if !fold {
		return false
	}
	segs := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	odd := false
	rewritten := make([]string, len(segs))
	for i, s := range segs {
		rewritten[i] = s
		if s == "" || s == "." || s == ".." {
			continue
		}
		if win {
			clean := s
			if j := strings.IndexByte(clean, ':'); j >= 0 && !(i == 0 && j == 1 && len(clean) == 2) {
				clean = clean[:j] // alternate data stream
				odd = true
			}
			if t := strings.TrimRight(clean, ". "); t != clean && t != "" {
				clean = t
				odd = true
			}
			if long, ok := expandShortName(clean); ok {
				clean = long
				odd = true
			}
			rewritten[i] = clean
			s = clean
		}
		// A case variant counts for dot-directories anywhere and for the
		// last two components otherwise, so "~/Config/.claude/x.json"
		// (an ordinary folder named Config above a control directory) is
		// not mistaken for one.
		near := i >= len(segs)-2
		for _, n := range controlNames {
			if s != n && strings.EqualFold(s, n) && (near || n[0] == '.') {
				odd = true
				break
			}
		}
	}
	if !odd {
		return false
	}
	return IsControlClass(classify.PathClasses(strings.Join(rewritten, "/"), ctx))
}

// expandShortName maps an 8.3 alias ("CLAUDE~1", "SETTIN~1.JSO") back to
// the control name it most likely stands for.
func expandShortName(seg string) (string, bool) {
	t := strings.IndexByte(seg, '~')
	if t <= 0 || t > 6 || t+1 >= len(seg) {
		return "", false
	}
	j := t + 1
	for j < len(seg) && seg[j] >= '0' && seg[j] <= '9' {
		j++
	}
	if j == t+1 {
		return "", false
	}
	ext := ""
	if j < len(seg) {
		if seg[j] != '.' || len(seg)-j-1 > 3 {
			return "", false
		}
		ext = seg[j+1:]
	}
	prefix := seg[:t]
	for _, n := range controlNames {
		b, e := shortForm(n)
		if strings.EqualFold(b, prefix) && strings.EqualFold(e, ext) {
			return n, true
		}
	}
	return "", false
}

// shortForm returns the base (at most six characters) and extension (at
// most three) that Windows uses to generate an 8.3 alias of name.
func shortForm(name string) (base, ext string) {
	n := strings.TrimLeft(name, ".")
	stem := n
	if i := strings.LastIndexByte(n, '.'); i > 0 {
		stem, ext = n[:i], n[i+1:]
	}
	var b strings.Builder
	for i := 0; i < len(stem) && b.Len() < 6; i++ {
		ch := stem[i]
		if ch == '.' || ch == ' ' {
			continue
		}
		b.WriteByte(ch)
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	return b.String(), ext
}
