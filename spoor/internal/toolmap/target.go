package toolmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Sanity bounds on derived fields. Tool input is agent output, so a "path"
// can be a megabyte of padding; the full value stays available to local
// detection in event.Content, and only the derived field is cut.
const (
	maxPathLen   = 4096
	maxURLLen    = 8192
	maxQueryLen  = 4096
	maxPaths     = 64
	maxHosts     = 16
	maxInputKeys = 64
	maxKeyLen    = 128
	maxScanLen   = 256 << 10 // text scanned for patch headers and URLs
)

// KindWithInput is Kind refined by the tool input, for the few tools whose
// class depends on their arguments: Copilot's str_replace_editor reads when
// command is "view" and creates when it is "create", and the MCP resource
// tools name their server in the input rather than in the tool name.
func KindWithInput(agentID, toolName string, input map[string]any) (kind event.ToolKind, mcpServer, mcpTool string) {
	kind, mcpServer, mcpTool = Kind(agentID, toolName)
	if len(input) == 0 {
		return kind, mcpServer, mcpTool
	}
	switch strings.ToLower(toolName) {
	case "str_replace_editor":
		switch s, _ := input["command"].(string); s {
		case "view":
			kind = event.ToolFileRead
		case "create":
			kind = event.ToolFileWrite
		}
	}
	if kind == event.ToolMCP && mcpServer == "" {
		if s, _ := input["server"].(string); s != "" && len(s) <= maxKeyLen {
			mcpServer = s
		}
	}
	return kind, mcpServer, mcpTool
}

// InputKeys returns the sorted top-level argument names of a tool input,
// bounded in count and length. Names are safe to emit; values are not.
func InputKeys(input map[string]any) []string {
	if len(input) == 0 {
		return nil
	}
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, cut(k, maxKeyLen))
	}
	sort.Strings(keys)
	if len(keys) > maxInputKeys {
		keys = keys[:maxInputKeys]
	}
	return keys
}

// InputHash returns the SHA-256 of the canonical JSON of a tool input:
// encoding/json output of the decoded map, which sorts object keys at every
// level. Hook and transcript sources must both use this function (on a map
// decoded by encoding/json without UseNumber) so the same call hashes the
// same on both surfaces.
func InputHash(input map[string]any) string {
	if len(input) == 0 {
		return ""
	}
	b, err := json.Marshal(input)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var (
	shellKeys  = []string{"command", "cmd", "script", "commandLine", "command_line", "fullCommandText"}
	pathKeys   = []string{"file_path", "path", "notebook_path", "absolute_path", "filePath", "target_file", "file", "filename", "fileName", "dir_path", "directory", "target_directory"}
	pathsKeys  = []string{"paths", "include", "file_paths", "files"}
	urlKeys    = []string{"url", "uri", "href", "link"}
	queryKeys  = []string{"query", "q", "search_term", "search_query", "searchTerm"}
	patchKeys  = []string{"input", "patch", "content", "diff"}
	promptKeys = []string{"prompt"}
)

// Target extracts what a tool call acts on from its input: the command of a
// shell tool, the path of a file tool, the URL and host of a fetch, the query
// of a search. It returns nil when nothing was found.
//
// Values are copied as the agent wrote them, apart from URL userinfo, which
// is always dropped. Secret redaction and tier-dependent stripping (URL
// query, search text) belong to the redaction stage.
func Target(agentID, toolName string, kind event.ToolKind, input map[string]any) *event.Target {
	if len(input) == 0 {
		return nil
	}
	t := &event.Target{}
	switch kind {
	case event.ToolShell:
		// The working directory is deliberately not a Target.Path: path
		// classification would read it as a file the command touched.
		t.Command = commandOf(input)
	case event.ToolFileRead, event.ToolFileWrite, event.ToolFileEdit, event.ToolFileList:
		fillPaths(t, input)
		if t.Path == "" && kind == event.ToolFileEdit {
			// apply_patch carries its targets inside the patch text.
			if ps := PatchPaths(str(input, patchKeys...)); len(ps) > 0 {
				t.Path, t.Paths = ps[0], ps[1:]
			}
		}
	case event.ToolWebFetch:
		fillURLs(t, input, true)
	case event.ToolWebSearch:
		t.Query = cut(queryOf(input), maxQueryLen)
		fillURLs(t, input, false)
	case event.ToolSubagent:
		// The prompt handed to a subagent is content, not a target.
	default:
		// MCP, browser and unclassified tools take arbitrary arguments;
		// the conventional names still say what is being touched.
		if s, ok := input["command"].(string); ok {
			t.Command = s
		} else if s, ok := input["cmd"].(string); ok {
			t.Command = s
		}
		fillPaths(t, input)
		fillURLs(t, input, false)
	}
	if t.Command == "" && t.Path == "" && len(t.Paths) == 0 && t.URL == "" && t.Host == "" && len(t.Hosts) == 0 && t.Query == "" {
		return nil
	}
	return t
}

// str returns the first of keys whose value is a non-empty string.
func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func strs(v any, limit int) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// cut shortens s to at most n bytes without splitting a UTF-8 sequence.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func commandOf(input map[string]any) string {
	for _, k := range shellKeys {
		switch v := input[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case []any:
			if argv := strs(v, 4096); len(argv) > 0 {
				return CommandFromArgv(argv)
			}
		}
	}
	// Codex local_shell_call nests the argv under action.
	if act, ok := input["action"].(map[string]any); ok {
		if argv := strs(act["command"], 4096); len(argv) > 0 {
			return CommandFromArgv(argv)
		}
	}
	return ""
}

// CommandFromArgv renders an argv as one command line. Codex's shell tool
// passes ["bash","-lc","<script>"]; the script is what the agent ran, so the
// wrapper is unwrapped. Any other argv is joined with POSIX quoting so a
// shell parser reads back the same words.
func CommandFromArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	if len(argv) >= 3 {
		base := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(argv[0], `\`, "/"))), ".exe")
		flag := argv[1]
		switch base {
		case "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox":
			if len(flag) >= 2 && flag[0] == '-' && flag[1] != '-' && strings.HasSuffix(flag, "c") {
				return argv[2]
			}
		case "powershell", "pwsh":
			if lf := strings.ToLower(flag); lf == "-command" || lf == "-c" {
				return strings.Join(argv[2:], " ")
			}
		case "cmd":
			if lf := strings.ToLower(flag); lf == "/c" || lf == "/k" {
				return strings.Join(argv[2:], " ")
			}
		}
	}
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuote(a)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_-./:=@%+,", c) >= 0) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fillPaths(t *event.Target, input map[string]any) {
	if p := str(input, pathKeys...); p != "" {
		t.Path = cut(p, maxPathLen)
	}
	for _, k := range pathsKeys {
		for _, p := range strs(input[k], maxPaths) {
			p = cut(p, maxPathLen)
			if t.Path == "" {
				t.Path = p
			} else if p != t.Path && len(t.Paths) < maxPaths {
				t.Paths = append(t.Paths, p)
			}
		}
	}
}

func queryOf(input map[string]any) string {
	if q := str(input, queryKeys...); q != "" {
		return q
	}
	if qs := strs(input["queries"], 1); len(qs) > 0 {
		return qs[0]
	}
	// Codex web_search_call nests the query under action.
	if act, ok := input["action"].(map[string]any); ok {
		if q := str(act, queryKeys...); q != "" {
			return q
		}
		if qs := strs(act["queries"], 1); len(qs) > 0 {
			return qs[0]
		}
	}
	return ""
}

// fillURLs sets URL/Host from the conventional URL arguments. With
// scanPrompt it also pulls URLs out of a free-text prompt, which is how
// Gemini CLI's web_fetch receives them.
func fillURLs(t *event.Target, input map[string]any, scanPrompt bool) {
	var raws []string
	if u := str(input, urlKeys...); u != "" {
		raws = append(raws, u)
	}
	raws = append(raws, strs(input["urls"], maxHosts)...)
	if act, ok := input["action"].(map[string]any); ok {
		if u := str(act, urlKeys...); u != "" {
			raws = append(raws, u)
		}
	}
	if len(raws) == 0 && scanPrompt {
		raws = FindURLs(str(input, promptKeys...), maxHosts)
	}
	seen := map[string]bool{}
	for _, raw := range raws {
		clean, host := CleanURL(raw)
		if clean == "" {
			continue
		}
		if t.URL == "" {
			t.URL, t.Host = clean, host
		}
		if host != "" && !seen[host] {
			seen[host] = true
			if host != t.Host && len(t.Hosts) < maxHosts {
				t.Hosts = append(t.Hosts, host)
			}
		}
	}
}

// CleanURL returns the URL without userinfo and its lower-cased host. A
// value that does not parse as an absolute URL is returned bounded and
// without a host, so a malformed target is still visible.
func CleanURL(raw string) (clean, host string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	raw = cut(raw, maxURLLen)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Scheme-less "example.com/x" parses as a path; retry as https.
		if err == nil && u.Scheme == "" && !strings.HasPrefix(raw, "/") {
			if u2, err2 := url.Parse("https://" + raw); err2 == nil && u2.Host != "" && strings.Contains(u2.Hostname(), ".") {
				u2.User = nil
				return strings.TrimPrefix(u2.String(), "https://"), strings.ToLower(u2.Hostname())
			}
		}
		if i := strings.Index(raw, "@"); i >= 0 {
			// Unparseable and possibly carrying credentials: keep nothing
			// before the "@".
			return raw[i+1:], ""
		}
		return raw, ""
	}
	u.User = nil
	return u.String(), strings.ToLower(u.Hostname())
}

// FindURLs returns up to limit http(s) URLs found in free text.
func FindURLs(text string, limit int) []string {
	if len(text) > maxScanLen {
		text = text[:maxScanLen]
	}
	var out []string
	for len(text) > 0 && len(out) < limit {
		i := strings.Index(text, "http")
		if i < 0 {
			break
		}
		text = text[i:]
		var n int
		switch {
		case strings.HasPrefix(text, "https://"):
			n = len("https://")
		case strings.HasPrefix(text, "http://"):
			n = len("http://")
		default:
			text = text[4:]
			continue
		}
		end := n
		for end < len(text) {
			c := text[end]
			if c <= ' ' || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == '\\' || c == 0x7f {
				break
			}
			end++
		}
		u := strings.TrimRight(text[:end], ".,;:!?)]}")
		if len(u) > n {
			out = append(out, u)
		}
		text = text[end:]
	}
	return out
}

// PatchPaths lists the files named by an apply_patch envelope
// ("*** Add File: p", "*** Update File: p", "*** Delete File: p",
// "*** Move to: p"), in order and without duplicates.
func PatchPaths(patch string) []string {
	if patch == "" {
		return nil
	}
	if len(patch) > maxScanLen {
		patch = patch[:maxScanLen]
	}
	var out []string
	seen := map[string]bool{}
	for len(patch) > 0 && len(out) < maxPaths {
		line := patch
		if i := strings.IndexByte(patch, '\n'); i >= 0 {
			line, patch = patch[:i], patch[i+1:]
		} else {
			patch = ""
		}
		rest, ok := strings.CutPrefix(line, "*** ")
		if !ok {
			continue
		}
		for _, verb := range []string{"Add File: ", "Update File: ", "Delete File: ", "Move to: "} {
			if p, ok := strings.CutPrefix(rest, verb); ok {
				p = cut(strings.TrimSpace(p), maxPathLen)
				if p != "" && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				break
			}
		}
	}
	return out
}
