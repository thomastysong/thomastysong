package mcpconf

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// dialect selects alias priority where two clients disagree on a key name.
type dialect int

const (
	dGeneric dialect = iota
	dGoose           // cmd / uri / envs are the primary spellings
	dZed             // extension-provided servers carry "settings" instead of a command
)

const (
	maxNameLen    = 256
	maxProjectLen = 1024
)

var (
	cmdKeys      = []string{"command", "cmd"}
	cmdKeysGoose = []string{"cmd", "command"}
	// url: every client; serverUrl: Windsurf, Antigravity; httpUrl: Gemini
	// CLI streamable HTTP; uri: Goose.
	urlKeys      = []string{"url", "serverUrl", "httpUrl", "uri"}
	urlKeysGoose = []string{"uri", "url", "serverUrl", "httpUrl"}
	// env: most clients; environment: opencode; envs: Goose.
	envKeys      = []string{"env", "environment", "envs"}
	envKeysGoose = []string{"envs", "env", "environment"}
)

// toServer converts one declaration. ok is false when the value is not an
// object or declares nothing that could be launched or contacted: such
// entries are skipped so one malformed sibling never hides the rest.
func toServer(name string, v any, d dialect) (Server, bool) {
	m, ok := asMap(v)
	if !ok {
		return Server{}, false
	}
	// Continue's legacy config.json nests the launch under "transport":
	// {"transport": {"type": "stdio", "command": ..., "args": [...]}}.
	// UNVERIFIED: shape taken from memory of Continue's 2025 docs; the
	// current docs only describe the YAML list.
	nested, _ := asMap(m["transport"])
	get := func(keys ...string) any {
		for _, k := range keys {
			if x, ok := m[k]; ok && x != nil {
				return x
			}
		}
		for _, k := range keys {
			if x, ok := nested[k]; ok && x != nil {
				return x
			}
		}
		return nil
	}

	ck, uk, ek := cmdKeys, urlKeys, envKeys
	if d == dGoose {
		ck, uk, ek = cmdKeysGoose, urlKeysGoose, envKeysGoose
	}

	// The name is cut to maxNameLen by builder.finish, which sees every
	// name of the file and can keep the cut forms stable and distinct.
	s := Server{Name: name}

	var pre []string
	switch c := get(ck...).(type) {
	case string:
		s.Command = c
	default:
		if l, ok := asList(c); ok {
			// opencode: "command": ["npx", "-y", "pkg"]
			if parts := scalarStrings(l); len(parts) > 0 {
				s.Command, pre = parts[0], parts[1:]
			}
		} else if cm, ok := asMap(c); ok {
			// Zed before 2025: "command": {"path": ..., "args": [...], "env": {...}}
			s.Command, _ = cm["path"].(string)
			if s.Command == "" {
				s.Command, _ = cm["command"].(string)
			}
			if l, ok := asList(cm["args"]); ok {
				pre = scalarStrings(l)
			}
			s.addEnv(cm["env"])
		}
	}
	switch a := get("args").(type) {
	case string:
		if a != "" {
			pre = append(pre, a)
		}
	default:
		if l, ok := asList(a); ok {
			pre = append(pre, scalarStrings(l)...)
		}
	}
	if len(pre) > 0 {
		s.Args = pre
	}

	s.addEnv(get(ek...))
	s.addEnvNames(get("env_vars")) // Codex: variables forwarded from the parent environment
	s.addEnvNames(get("env_keys")) // Goose: variables resolved from the keyring at launch

	urlKey := ""
	for _, k := range uk {
		if str, ok := get(k).(string); ok && strings.TrimSpace(str) != "" {
			s.URL, urlKey = str, k
			break
		}
	}

	s.addHeaders(get("headers", "http_headers")) // http_headers: Codex
	if ro, ok := asMap(get("requestOptions")); ok {
		s.addHeaders(ro["headers"]) // Continue
	}
	// Codex names the environment variable a header is read from. The header
	// is recorded with a reference as its value: the name is inventory, and
	// the reference tells AuthMode the credential is not in the file.
	if eh, ok := asMap(get("env_http_headers")); ok {
		for _, h := range sortedKeys(eh) {
			if envName, ok := eh[h].(string); ok && envName != "" {
				s.setHeader(h, "${"+envName+"}")
				s.addEnvName(envName)
			}
		}
	}
	if envName, ok := get("bearer_token_env_var").(string); ok && envName != "" {
		if _, exists := lookupFold(s.Headers, "authorization"); !exists {
			s.setHeader("Authorization", "Bearer ${"+envName+"}")
		}
		s.addEnvName(envName)
	}

	switch o := get("oauth").(type) {
	case nil:
	case bool:
		s.oauth = o
	default:
		s.oauth = true
		if om, ok := asMap(o); ok {
			if en, ok := om["enabled"].(bool); ok && !en {
				s.oauth = false
			}
			// clientSecret: Gemini CLI; client_secret: Codex.
			for _, k := range []string{"clientSecret", "client_secret"} {
				if sec, ok := om[k].(string); ok && sec != "" {
					s.oauthSecret = sec
				}
			}
		}
	}
	for _, k := range []string{"auth", "authProviderType", "oauthClientId"} {
		// auth: Codex (oauth | chatgpt | ema_auth); authProviderType: Gemini
		// CLI; oauthClientId: Copilot CLI's flat spelling.
		if a, ok := get(k).(string); ok && a != "" {
			s.oauth = true
		}
	}
	if h, ok := get("headersHelper", "http_headers_helper").(string); ok {
		s.headersHelper = h
	}

	if b, ok := get("enabled").(bool); ok {
		s.Enabled = &b
	} else if b, ok := get("disabled").(bool); ok {
		nb := !b
		s.Enabled = &nb
	}

	launchable := strings.TrimSpace(s.Command) != "" || s.URL != ""
	if !launchable && d == dZed {
		// A Zed extension builds the launch itself from "settings", and
		// those settings are where its API tokens are written. They are
		// recorded as Env: that is where extensions put them, and it keeps
		// the names visible and the values scanned.
		if st, ok := asMap(m["settings"]); ok {
			for _, k := range sortedKeys(st) {
				if val, ok := scalarString(st[k]); ok {
					s.setEnv(k, val)
				}
			}
			launchable = len(s.Env) > 0
		}
	}
	if !launchable {
		return Server{}, false
	}

	typ, _ := get("type").(string)
	if typ == "" {
		typ, _ = m["transport"].(string)
	}
	if typ == "" {
		// UNVERIFIED: "transportType" was written by older Cline builds.
		typ, _ = get("transportType").(string)
	}
	s.Transport = transportOf(typ, strings.TrimSpace(s.Command) != "", urlKey, s.URL)
	return s, true
}

// transportOf maps a client's transport vocabulary onto stdio | http | sse | ws.
func transportOf(typ string, hasCmd bool, urlKey, rawURL string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	t = strings.NewReplacer("-", "", "_", "", " ", "").Replace(t)
	switch t {
	case "stdio", "local", "command", "process":
		return "stdio"
	case "sse":
		return "sse"
	case "ws", "wss", "websocket", "websockets":
		return "ws"
	case "http", "https", "streamablehttp", "streamablehttps", "httpstream", "streamable":
		return "http"
	}
	// "remote" (opencode), an unknown word or no type at all: go by what the
	// entry declares. A command wins because clients that default to stdio
	// ignore a stray url.
	if hasCmd && t != "remote" {
		return "stdio"
	}
	if rawURL == "" {
		return "stdio"
	}
	u := splitURL(rawURL)
	switch {
	case u.scheme == "ws" || u.scheme == "wss":
		return "ws"
	case urlKey == "httpUrl":
		return "http"
	case strings.HasSuffix(strings.TrimRight(u.path, "/"), "/sse"):
		// A bare url means SSE to Gemini CLI and streamable HTTP to most
		// others; the conventional /sse endpoint path settles it.
		return "sse"
	}
	return "http"
}

func (s *Server) setEnv(k, v string) {
	if k == "" {
		return
	}
	if s.Env == nil {
		s.Env = make(map[string]string)
	}
	s.Env[k] = v
}

// addEnvName records a variable the server consumes without a value in the file.
func (s *Server) addEnvName(k string) {
	if _, ok := s.Env[k]; !ok {
		s.setEnv(k, "")
	}
}

func (s *Server) setHeader(k, v string) {
	if k == "" {
		return
	}
	if s.Headers == nil {
		s.Headers = make(map[string]string)
	}
	s.Headers[k] = v
}

// addEnv accepts a map (every client) or a list of "K=V" / "K" strings
// (compose-style, seen in hand-written YAML).
func (s *Server) addEnv(v any) {
	if m, ok := asMap(v); ok {
		for k, val := range m {
			str, _ := scalarString(val) // a non-scalar value still declares the name
			s.setEnv(k, str)
		}
		return
	}
	if l, ok := asList(v); ok {
		for _, item := range scalarStrings(l) {
			k, val, _ := strings.Cut(item, "=")
			s.setEnv(strings.TrimSpace(k), val)
		}
	}
}

// addEnvNames accepts ["NAME", ...] or [{"name": "NAME"}, ...].
func (s *Server) addEnvNames(v any) {
	l, ok := asList(v)
	if !ok {
		return
	}
	for _, item := range l {
		switch t := item.(type) {
		case string:
			if t != "" {
				s.addEnvName(t)
			}
		default:
			if m, ok := asMap(t); ok {
				if n, ok := m["name"].(string); ok && n != "" {
					s.addEnvName(n)
				}
			}
		}
	}
}

func (s *Server) addHeaders(v any) {
	m, ok := asMap(v)
	if !ok {
		return
	}
	for k, val := range m {
		str, _ := scalarString(val)
		s.setHeader(k, str)
	}
}

// lookupFold finds a key case-insensitively (header names).
func lookupFold(m map[string]string, lowerKey string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, lowerKey) {
			return v, true
		}
	}
	return "", false
}

// capString cuts s to at most max bytes on a rune boundary, never inside a
// redaction marker. A cut value ends in "~" and a digest of the full value
// keyed per process (runFP8), so two different long values stay
// distinguishable within a run and the cut is visible, while nothing in
// the output lets a reader confirm a guess about the cut tail.
//
// The digest changes from one process to the next, so capString is for
// values that are reported, never for ones that identify an asset
// (Server.Name, Server.Project): builder.finish cuts those.
func capString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:cutPoint(s, max-12)] + "~" + runFP8(s)
}

// cutPoint returns where to cut s so that the head is at most n bytes: on a
// rune boundary, and moved back to the start of a "[REDACTED" marker the
// cut would otherwise split. The values cut here are already redacted, and
// a marker's fingerprint is an UNKEYED digest of the credential (fp8) that
// package privacy rewrites only inside a complete marker: a marker cut
// before its ']' would ship all or part of that fingerprint as written.
func cutPoint(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	if n < 0 {
		n = 0
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	// A marker holds no '[', so a cut inside one leaves its '[' last.
	if k := strings.LastIndexByte(s[:n], '['); k >= 0 && strings.HasPrefix(s[k:], "[REDACTED") &&
		strings.IndexByte(s[k:n], ']') < 0 {
		n = k
	}
	return n
}

// listEntryName names an entry of a list-shaped declaration.
func listEntryName(v any, index int) string {
	if m, ok := asMap(v); ok {
		if n, ok := m["name"].(string); ok && strings.TrimSpace(n) != "" {
			return n
		}
	}
	return "unnamed-" + strconv.Itoa(index+1)
}

// looksLikeEntry reports whether v has the minimum shape of a server
// declaration. It gates the sniffed shapes whose key names ("servers",
// "extensions", a flat map) are too common to trust on their own.
func looksLikeEntry(v any) bool {
	m, ok := asMap(v)
	if !ok {
		return false
	}
	for _, k := range []string{"command", "cmd", "url", "serverUrl", "httpUrl", "uri"} {
		switch t := m[k].(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return true
			}
		case nil:
		default:
			if k == "command" {
				if _, ok := asList(t); ok {
					return true
				}
				if _, ok := asMap(t); ok {
					return true
				}
			}
		}
	}
	return false
}
