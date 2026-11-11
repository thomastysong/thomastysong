package mcpconf

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Parse is tolerant: JSON with comments and trailing commas, BOM, CRLF; 20 MiB cap; unknown shapes return (nil, nil); a malformed entry is skipped, not fatal.
//
// Syntax (JSON, TOML, YAML) is chosen from content and file extension; f
// selects which keys are read. With FormatAuto every known shape is read.
// Servers come back sorted by (Project, Name) so output is stable across runs.
// path is recorded as SourcePath and used for hints only; nothing is opened.
//
// Errors: ErrTooLarge, *SyntaxError for a file that does not parse, an
// unknown-format error, and ErrTooManyServers (returned together with the
// first MaxServers servers).
func Parse(path string, data []byte, f Format) (servers []Server, err error) {
	defer func() {
		if r := recover(); r != nil {
			servers, err = nil, errInternal
		}
	}()
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	switch f {
	case FormatMCPServers, FormatClaudeJSON, FormatVSCode, FormatZed, FormatCodexTOML,
		FormatOpenCode, FormatContinue, FormatGoose, FormatAuto:
	default:
		return nil, fmt.Errorf("mcpconf: unknown format %q", capString(string(f), 64))
	}
	text := toUTF8(data)
	if len(bytes.TrimSpace(text)) == 0 {
		return nil, nil
	}
	root, err := decode(path, text, f)
	if err != nil {
		return nil, err
	}
	top, ok := asMap(root)
	if !ok {
		return nil, nil
	}
	b := &builder{path: path, fileProject: projectOf(path)}
	b.extract(top, f)
	return b.finish()
}

type builder struct {
	path        string
	fileProject string
	out         []Server
	over        bool
}

func (b *builder) add(s Server, ok bool) {
	if !ok {
		return
	}
	if len(b.out) >= MaxServers {
		b.over = true
		return
	}
	s.SourcePath = b.path
	if s.Project == "" {
		s.Project = b.fileProject
	}
	b.out = append(b.out, s)
}

// servers reads a name->entry map or a list of named entries and returns how
// many servers it added.
func (b *builder) servers(v any, project string, d dialect) int {
	before := len(b.out)
	if m, ok := asMap(v); ok {
		for _, name := range sortedKeys(m) {
			if b.over {
				break
			}
			s, ok := toServer(name, m[name], d)
			s.Project = project
			b.add(s, ok)
		}
	} else if l, ok := asList(v); ok {
		for i, item := range l {
			if b.over {
				break
			}
			s, ok := toServer(listEntryName(item, i), item, d)
			s.Project = project
			b.add(s, ok)
		}
	}
	return len(b.out) - before
}

func (b *builder) extract(top map[string]any, f Format) {
	switch f {
	case FormatMCPServers:
		if b.mcpServers(top) == 0 && !hasAny(top, "mcpServers", "amp.mcpServers") {
			b.flat(top)
		}
	case FormatClaudeJSON:
		b.mcpServers(top)
		b.claudeProjects(top)
	case FormatVSCode:
		b.servers(top["servers"], "", dGeneric)
		b.vscodeNested(top)
	case FormatZed:
		b.servers(top["context_servers"], "", dZed)
	case FormatCodexTOML:
		b.servers(top["mcp_servers"], "", dGeneric)
	case FormatOpenCode:
		b.servers(top["mcp"], "", dGeneric)
	case FormatContinue:
		b.servers(top["mcpServers"], "", dGeneric)
		b.continueLegacy(top)
	case FormatGoose:
		b.servers(top["extensions"], "", dGoose)
	case FormatAuto:
		b.auto(top)
	}
}

// auto reads every shape. Keys that are specific to MCP are read
// unconditionally; generic key names are read only when their values look
// like server declarations, so an unrelated settings file yields nothing.
func (b *builder) auto(top map[string]any) {
	n := b.mcpServers(top)
	n += b.servers(top["mcp_servers"], "", dGeneric) // Codex TOML, Hermes YAML
	n += b.claudeProjects(top)
	if anyEntry(top["servers"]) {
		n += b.servers(top["servers"], "", dGeneric)
	}
	n += b.vscodeNested(top)
	n += b.servers(top["context_servers"], "", dZed)
	n += b.servers(top["mcp"], "", dGeneric) // opencode, Crush, Kilo
	n += b.continueLegacy(top)
	if ext, ok := asMap(top["extensions"]); ok && looksLikeGoose(ext) {
		n += b.servers(ext, "", dGoose)
	}
	if n == 0 && !hasAny(top, "mcpServers", "amp.mcpServers", "mcp_servers", "servers",
		"context_servers", "mcp", "extensions", "projects") {
		b.flat(top)
	}
}

// mcpServers reads the shared "mcpServers" key and Amp's namespaced spelling
// of it ("amp.mcpServers" as a dotted settings key, or nested under "amp").
func (b *builder) mcpServers(top map[string]any) int {
	n := b.servers(top["mcpServers"], "", dGeneric)
	n += b.servers(top["amp.mcpServers"], "", dGeneric)
	if amp, ok := asMap(top["amp"]); ok {
		n += b.servers(amp["mcpServers"], "", dGeneric)
	}
	return n
}

// claudeProjects reads projects.<path>.mcpServers from ~/.claude.json (local
// scope). A project's disabledMcpServers list is Claude Code's per-project
// opt-out; it is applied to the servers declared in that same project block.
func (b *builder) claudeProjects(top map[string]any) int {
	projects, ok := asMap(top["projects"])
	if !ok {
		return 0
	}
	total := 0
	for _, p := range sortedKeys(projects) {
		pm, ok := asMap(projects[p])
		if !ok {
			continue
		}
		start := len(b.out)
		project := capString(p, maxProjectLen)
		if project == "" {
			// An empty key would be indistinguishable from user scope.
			project = "."
		}
		total += b.servers(pm["mcpServers"], project, dGeneric)
		l, ok := asList(pm["disabledMcpServers"])
		if !ok || len(b.out) == start {
			continue
		}
		disabled := make(map[string]bool, len(l))
		for _, name := range scalarStrings(l) {
			disabled[name] = true
		}
		for i := start; i < len(b.out); i++ {
			if disabled[b.out[i].Name] && b.out[i].Enabled == nil {
				off := false
				b.out[i].Enabled = &off
			}
		}
	}
	return total
}

// vscodeNested reads the places VS Code keeps a "servers" map other than the
// top level of mcp.json: settings.json ("mcp": {"servers"} or the dotted
// "mcp.servers" key), .code-workspace files (the same under "settings") and
// devcontainer.json ("customizations.vscode.mcp.servers").
func (b *builder) vscodeNested(top map[string]any) int {
	n := b.vscodeSettings(top)
	if st, ok := asMap(top["settings"]); ok {
		n += b.vscodeSettings(st)
	}
	if c, ok := asMap(top["customizations"]); ok {
		if vs, ok := asMap(c["vscode"]); ok {
			n += b.vscodeSettings(vs)
		}
	}
	return n
}

func (b *builder) vscodeSettings(m map[string]any) int {
	n := b.servers(m["mcp.servers"], "", dGeneric)
	if mcp, ok := asMap(m["mcp"]); ok {
		n += b.servers(mcp["servers"], "", dGeneric)
	}
	return n
}

// continueLegacy reads Continue's pre-YAML config.json list.
func (b *builder) continueLegacy(top map[string]any) int {
	exp, ok := asMap(top["experimental"])
	if !ok {
		return 0
	}
	return b.servers(exp["modelContextProtocolServers"], "", dGeneric)
}

// flat reads {name: {...}, ...} with no wrapper key, the form Claude Code
// plugins may use for .mcp.json. Every value must be a declaration: a file
// that merely contains one object with a "url" is not a server list.
func (b *builder) flat(top map[string]any) {
	if len(top) == 0 {
		return
	}
	for _, v := range top {
		if !looksLikeEntry(v) {
			return
		}
	}
	b.servers(top, "", dGeneric)
}

func (b *builder) finish() ([]Server, error) {
	if len(b.out) == 0 {
		return nil, nil
	}
	sort.SliceStable(b.out, func(i, j int) bool {
		if b.out[i].Project != b.out[j].Project {
			return b.out[i].Project < b.out[j].Project
		}
		return b.out[i].Name < b.out[j].Name
	})
	if b.over {
		return b.out, ErrTooManyServers
	}
	return b.out, nil
}

func hasAny(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// anyEntry reports whether v is a map or list holding at least one server
// declaration.
func anyEntry(v any) bool {
	if m, ok := asMap(v); ok {
		for _, e := range m {
			if looksLikeEntry(e) {
				return true
			}
		}
	}
	if l, ok := asList(v); ok {
		for _, e := range l {
			if looksLikeEntry(e) {
				return true
			}
		}
	}
	return false
}

// looksLikeGoose guards the very common key "extensions": at least one entry
// must use Goose's own vocabulary.
func looksLikeGoose(ext map[string]any) bool {
	for _, v := range ext {
		m, ok := asMap(v)
		if !ok {
			continue
		}
		if _, ok := m["cmd"].(string); ok {
			return true
		}
		if _, ok := m["uri"].(string); ok {
			return true
		}
		if t, ok := m["type"].(string); ok {
			switch strings.ToLower(t) {
			case "stdio", "sse", "streamable_http":
				if looksLikeEntry(v) {
					return true
				}
			}
		}
	}
	return false
}

// projectSuffixes are config locations that only exist relative to a project
// root. Layouts that also exist under a home directory (.cursor/mcp.json,
// .codex/config.toml, .gemini/settings.json ...) are left out on purpose:
// Parse cannot tell a home from a repository, the caller can.
var projectSuffixes = []string{
	"/.mcp.json",
	"/.vscode/mcp.json",
	"/.roo/mcp.json",
	"/.amp/settings.json",
	"/.github/mcp.json",
	"/.devcontainer/devcontainer.json",
	"/.devcontainer.json",
}

// projectOf derives the project root from the path alone, or "".
func projectOf(path string) string {
	p := strings.ReplaceAll(path, `\`, "/")
	if strings.Contains(p, "/.claude/plugins/") {
		return "" // a plugin's .mcp.json is plugin scope, not a project
	}
	for _, suf := range projectSuffixes {
		if strings.HasSuffix(p, suf) {
			root := path[:len(path)-len(suf)]
			if root == "" {
				root = path[:1] // the file sits in the filesystem root
			}
			return capString(root, maxProjectLen)
		}
	}
	return ""
}
