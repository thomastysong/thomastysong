package hookio

import (
	"net/url"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Argument names agents use for the thing a tool acts on. The lists are
// ordered most-specific first. Sources: Claude Code hooks reference
// (PreToolUse input: command, file_path, path, url, query, notebook_path);
// Gemini CLI tools (file_path, dir_path, absolute_path, paths, prompt);
// Codex hooks ({"command": ...} for shell-like tools, apply_patch text);
// Copilot CLI tool arguments (command, path); Cursor (command, file_path,
// working_directory, target_file).
var (
	commandKeys = []string{"command", "cmd", "script", "commandLine", "command_line"}
	pathKeys    = []string{"file_path", "filePath", "path", "absolute_path", "notebook_path", "target_file", "filename", "file", "dir_path", "directory", "relative_workspace_path", "target_directory"}
	urlKeys     = []string{"url", "uri", "href", "link"}
	queryKeys   = []string{"query", "q", "search_term", "searchTerm", "search_query"}
	contentKeys = []string{"content", "new_string", "new_str", "contents", "file_text", "text", "code_edit", "new_source"}
	patchKeys   = []string{"patch", "input", "diff", "command", "_raw"}
)

// Bounds on derived lists so a hostile argument cannot inflate an event.
const (
	maxTargetPaths = 64
	maxTargetHosts = 32
)

// setTarget extracts what the tool call acts on. Values are copied verbatim:
// detection needs the exact command, path and URL, and redaction of the
// serialized copy is the next stage's job.
func setTarget(ev *event.Event, in map[string]any) {
	if in == nil || ev.Tool == nil {
		return
	}
	o := obj(in)
	t := &event.Target{}
	switch ev.Tool.Kind {
	case event.ToolShell:
		t.Command = commandLine(o)
	case event.ToolFileRead, event.ToolFileList:
		t.Path, t.Paths = filePaths(o)
	case event.ToolFileWrite, event.ToolFileEdit:
		t.Path, t.Paths = filePaths(o)
		if t.Path == "" {
			t.Path, t.Paths = patchPaths(o)
		}
		ev.Content.FileContent = writtenContent(o)
	case event.ToolWebFetch, event.ToolBrowser:
		setURLs(t, o)
	case event.ToolWebSearch:
		t.Query = o.str(queryKeys...)
	default:
		// MCP, subagent and unclassified tools: a filesystem or fetch MCP
		// server acts on paths and URLs exactly like the built-ins, so take
		// the obvious arguments when present rather than leaving the call
		// opaque to path and host rules.
		t.Command = o.str("command")
		t.Path = o.str("file_path", "path", "filePath")
		t.Query = o.str("query")
		if u := o.str("url", "uri"); u != "" {
			t.URL = u
			t.Host = hostOf(u)
		}
	}
	if targetEmpty(t) {
		return
	}
	ev.Target = t
}

// targetEmpty reports whether a Target carries nothing. (Target holds
// slices, so it is not comparable with ==.)
func targetEmpty(t *event.Target) bool {
	return t.Command == "" && t.Path == "" && len(t.Paths) == 0 && t.URL == "" &&
		t.Host == "" && len(t.Hosts) == 0 && t.Query == ""
}

// commandLine returns the shell command. Some tools pass argv as an array
// (Codex local shell: ["bash","-lc","..."]); it is joined with spaces, which
// preserves every token for matching even though quoting is lost.
func commandLine(o obj) string {
	for _, k := range commandKeys {
		switch v := o[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case []any:
			parts := make([]string, 0, len(v))
			for _, it := range v {
				if s, ok := it.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, " ")
			}
		}
	}
	return o.str("_raw")
}

// filePaths returns the primary path and any additional ones (Gemini's
// read_many_files takes a list).
func filePaths(o obj) (string, []string) {
	primary := o.str(pathKeys...)
	var more []string
	for _, k := range []string{"paths", "file_paths", "files"} {
		for _, it := range o.arr(k) {
			s, ok := it.(string)
			if !ok || s == "" || s == primary {
				continue
			}
			if primary == "" {
				primary = s
				continue
			}
			if len(more) < maxTargetPaths {
				more = append(more, s)
			}
		}
	}
	return primary, more
}

// patchPaths reads the file headers of an apply_patch envelope
// ("*** Update File: p", "*** Add File: p", "*** Delete File: p",
// "*** Move to: p"), the format Codex and Copilot use for multi-file edits.
func patchPaths(o obj) (string, []string) {
	var text string
	for _, k := range patchKeys {
		if s, ok := o[k].(string); ok && strings.Contains(s, "*** ") {
			text = s
			break
		}
	}
	if text == "" {
		return "", nil
	}
	var paths []string
	seen := map[string]bool{}
	for len(text) > 0 && len(paths) <= maxTargetPaths {
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		line = strings.TrimRight(line, "\r")
		for _, h := range []string{"*** Update File: ", "*** Add File: ", "*** Delete File: ", "*** Move to: "} {
			if p, ok := strings.CutPrefix(line, h); ok {
				p = strings.TrimSpace(p)
				if p != "" && !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
				break
			}
		}
	}
	if len(paths) == 0 {
		return "", nil
	}
	return paths[0], paths[1:]
}

// writtenContent returns the text a write or edit would put on disk, for
// local content scanning. Multi-edit tools carry it per edit.
func writtenContent(o obj) string {
	if s := o.str(contentKeys...); s != "" {
		return s
	}
	var parts []string
	for _, it := range o.arr("edits") {
		if m, ok := it.(map[string]any); ok {
			if s := obj(m).str("new_string", "new_str", "newText", "text"); s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n")
	}
	for _, k := range patchKeys {
		if s, ok := o[k].(string); ok && strings.Contains(s, "*** Begin Patch") {
			return s
		}
	}
	return ""
}

// setURLs fills URL, Host and Hosts for fetch-style tools. Gemini's
// web_fetch takes a free-text prompt with the URLs embedded, so when there
// is no URL argument the prompt is scanned.
func setURLs(t *event.Target, o obj) {
	var urls []string
	if u := o.str(urlKeys...); u != "" {
		urls = append(urls, u)
	}
	for _, it := range o.arr("urls") {
		if s, ok := it.(string); ok && s != "" && len(urls) < maxTargetHosts {
			urls = append(urls, s)
		}
	}
	if len(urls) == 0 {
		urls = urlsIn(o.str("prompt", "_raw"))
	}
	if len(urls) == 0 {
		return
	}
	t.URL = urls[0]
	t.Host = hostOf(urls[0])
	if len(urls) == 1 {
		return
	}
	seen := map[string]bool{}
	for _, u := range urls {
		h := hostOf(u)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		t.Hosts = append(t.Hosts, h)
	}
}

// urlsIn finds http(s) URLs in free text.
func urlsIn(s string) []string {
	var out []string
	for len(s) > 0 && len(out) < maxTargetHosts {
		i := strings.Index(s, "http")
		if i < 0 {
			break
		}
		s = s[i:]
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			s = s[4:]
			continue
		}
		end := strings.IndexAny(s, " \t\r\n\"'<>`)]}")
		if end < 0 {
			end = len(s)
		}
		u := strings.TrimRight(s[:end], ".,;:!?")
		if len(u) > len("https://") {
			out = append(out, u)
		}
		s = s[end:]
	}
	return out
}

// hostOf returns the lower-cased host of a URL, or "" when it has none. A
// bare "host/path" (no scheme) is accepted because agents and users write
// URLs that way and the fetch tools add the scheme themselves.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8192 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if strings.Contains(raw, "://") {
			return ""
		}
		u, err = url.Parse("//" + raw)
		if err != nil {
			return ""
		}
	}
	h := strings.ToLower(u.Hostname())
	h, _ = cleanID(strings.TrimSuffix(h, "."), 253)
	return h
}
