package features

import (
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// Bounds on the MCP argument walk. The input is model output shaped by
// whatever the agent read, so it can be arbitrarily wide or deep.
const (
	maxWalkDepth   = 8
	maxWalkStrings = 4096
	maxWalkBytes   = 1 << 20
	maxArgString   = 4096 // longer strings are not paths or hosts; they are still scanned for secrets
)

// pathKey and hostKey report argument names that say what a string is when
// its shape alone does not.
func pathKey(key string) bool {
	switch key {
	case "path", "paths", "file", "files", "filename", "file_path", "filepath",
		"dir", "directory", "cwd", "root", "target", "source", "destination",
		"dest", "src", "dst", "folder", "location", "workdir", "working_directory",
		"absolute_path", "relative_path", "notebook_path":
		return true
	}
	return false
}

func hostKey(key string) bool {
	switch key {
	case "host", "hostname", "domain", "url", "urls", "uri", "endpoint",
		"server", "base_url", "baseurl", "address", "href", "link", "webhook":
		return true
	}
	return false
}

type walker struct {
	strings, bytes int
	paths, hosts   uniqList
	urls           uniqList
	secrets        []string
	truncated      bool
}

func (c *computer) mcp() {
	if c.toolKind() != event.ToolMCP {
		return
	}
	t := c.e.Tool
	if t.MCPServer != "" {
		c.f["mcp.server"] = t.MCPServer
	}
	if t.MCPTool != "" {
		c.f["mcp.tool"] = t.MCPTool
	}
	if c.e.Content == nil || len(c.e.Content.ToolInput) == 0 {
		return
	}
	w := &walker{}
	w.walkMap(c.e.Content.ToolInput, 0)
	if w.truncated {
		c.f["content.truncated_scan"] = true
	}
	// A walk that stopped at a cap has not seen every argument: every
	// list it produced, and the network features fed from it, are
	// incomplete.
	pc := c.pathCtx()
	paths := c.setList("mcp.arg_paths", w.paths.list)
	hosts := c.setList("mcp.arg_hosts", w.hosts.list)
	pathsCut := w.truncated || c.cut["mcp.arg_paths"]
	hostsCut := w.truncated || c.cut["mcp.arg_hosts"]
	c.setDerived("mcp.arg_path_classes", pathClasses(paths, pc), pathsCut)
	c.setDerived("mcp.arg_host_classes", hostClasses(hosts), hostsCut)
	c.setDerived("mcp.arg_secret_kinds", sortedUniq(w.secrets), w.truncated)
	if w.truncated {
		for _, k := range []string{"mcp.arg_paths", "mcp.arg_hosts"} {
			if _, ok := c.f[k]; ok {
				c.markCut(k)
			}
		}
	}
	c.urls = append(c.urls, w.urls.list...)
	c.hosts = append(c.hosts, w.hosts.list...)
	c.netCut = c.netCut || hostsCut
}

func (w *walker) walkMap(m map[string]any, depth int) {
	if depth > maxWalkDepth {
		w.truncated = true
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order under the caps
	for _, k := range keys {
		w.walkValue(k, m[k], depth+1)
	}
}

func (w *walker) walkValue(key string, v any, depth int) {
	if w.strings >= maxWalkStrings || w.bytes >= maxWalkBytes {
		w.truncated = true
		return
	}
	switch t := v.(type) {
	case string:
		w.str(key, t)
	case map[string]any:
		w.walkMap(t, depth)
	case []any:
		if depth > maxWalkDepth {
			w.truncated = true
			return
		}
		for _, x := range t {
			w.walkValue(key, x, depth+1)
		}
	case []string:
		for _, x := range t {
			w.walkValue(key, x, depth+1)
		}
	}
}

func (w *walker) str(key, s string) {
	w.strings++
	if s == "" {
		return
	}
	if len(s) > maxScan {
		s = headTail(s)
		w.truncated = true
	}
	w.bytes += len(s)
	lk := strings.ToLower(key)
	// The key name lets the secret finder use its assignment heuristics
	// ("api_key": "...") on a value that has no recognisable format.
	for _, h := range classify.FindSecrets(key + "=" + s) {
		w.secrets = append(w.secrets, h.Kind)
	}
	if len(s) > maxArgString || strings.ContainsAny(s, "\n\r") {
		return
	}
	if strings.Contains(s, "://") {
		if isFileURL(s) {
			w.paths.add(s)
			return
		}
		if h := classify.URLHost(s); h != "" {
			w.hosts.add(h)
			w.urls.add(s)
		}
		return
	}
	if looksLikePath(s) || (pathKey(lk) && !strings.ContainsAny(s, " \t") && strings.ContainsAny(s, `/\.`)) {
		w.paths.add(s)
		return
	}
	if hostKey(lk) {
		if h := classify.URLHost(s); h != "" && strings.Contains(h, ".") {
			w.hosts.add(h)
		}
	}
}

func isFileURL(s string) bool {
	return len(s) >= 7 && strings.EqualFold(s[:7], "file://")
}

// looksLikePath accepts strings whose shape alone makes them a path:
// rooted, home-relative, explicitly relative, a drive or UNC path, or a
// home variable.
func looksLikePath(s string) bool {
	if s == "" || strings.ContainsAny(s, "\x00") {
		return false
	}
	switch {
	case strings.HasPrefix(s, "/") && len(s) > 1 && !strings.HasPrefix(s, "//"),
		strings.HasPrefix(s, "~/"), strings.HasPrefix(s, `~\`), s == "~",
		strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"), strings.HasPrefix(s, `.\`), strings.HasPrefix(s, `..\`),
		strings.HasPrefix(s, `\\`),
		strings.HasPrefix(s, "$HOME/"), strings.HasPrefix(s, "${HOME}/"),
		strings.HasPrefix(strings.ToUpper(s), "%USERPROFILE%"), strings.HasPrefix(strings.ToLower(s), "$env:userprofile"):
		return true
	}
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		c := s[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}
