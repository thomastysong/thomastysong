package discovery

import (
	"sort"
	"strconv"
	"strings"
)

// hookHandler is one hook entry found in an agent configuration.
type hookHandler struct {
	event, matcher, typ string
	command             string   // command text as the agent would run it (local only)
	argv                []string // exec-form arguments, when declared
	url                 string
	async               bool
	index               int // position within (event, matcher): part of the identity
	spoor               bool
	spoorAgent          string
}

const (
	maxHandlers   = 1024
	maxHookWalk   = 6
	maxCommandLen = 64 << 10
)

// extractHooks reads hook declarations in the shapes the hook-capable
// agents use:
//
//	claude, gemini, codex:  {"hooks": {Event: [{"matcher": m, "hooks": [handler...]}]}}
//	copilot, cursor:        {"version": 1, "hooks": {event: [handler...]}}
//	codex TOML:             [[hooks.Event]] matcher = ...  [[hooks.Event.hooks]] ...
//
// and, when fallback is set (dedicated hook files of agents without a
// dialect: Windsurf, Kiro, Antigravity), any object below the document that
// carries a command. Settings files never use the fallback: their MCP
// server entries also carry a "command".
func extractHooks(doc any, fallback bool) []hookHandler {
	var out []hookHandler
	if hooks, ok := getPath(doc, "hooks"); ok {
		if hm, ok := asMap(hooks); ok {
			for _, ev := range sortedKeys(hm) {
				counts := map[string]int{}
				for _, el := range asList(hm[ev]) {
					em, ok := asMap(el)
					if !ok {
						continue
					}
					matcher := scalarString(em["matcher"])
					if inner, ok := em["hooks"]; ok {
						for _, h := range asList(inner) {
							if hmap, ok := asMap(h); ok {
								if hh, ok := handlerOf(ev, matcher, hmap, counts); ok {
									out = append(out, hh)
								}
							}
						}
						continue
					}
					if hh, ok := handlerOf(ev, matcher, em, counts); ok {
						out = append(out, hh)
					}
				}
				if len(out) >= maxHandlers {
					return out[:maxHandlers]
				}
			}
			return out
		}
	}
	if !fallback {
		return out
	}
	// Fallback: walk for command-bearing objects.
	counts := map[string]int{}
	var walk func(v any, path []string, depth int)
	walk = func(v any, path []string, depth int) {
		if depth > maxHookWalk || len(out) >= maxHandlers {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if hasCommand(t) {
				ev := strings.Join(path, ".")
				if ev == "" {
					ev = "hook"
				}
				if w, ok := getPath(t, "when", "type"); ok {
					if s, ok := w.(string); ok {
						ev = s
					}
				}
				if hh, ok := handlerOf(ev, scalarString(t["matcher"]), t, counts); ok {
					out = append(out, hh)
				}
				return
			}
			for _, k := range sortedKeys(t) {
				walk(t[k], append(path, k), depth+1)
			}
		case []any:
			for _, x := range t {
				walk(x, path, depth+1)
			}
		}
	}
	walk(doc, nil, 0)
	return out
}

func hasCommand(m map[string]any) bool {
	for _, k := range []string{"command", "bash", "powershell", "commandWindows"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func handlerOf(ev, matcher string, h map[string]any, counts map[string]int) (hookHandler, bool) {
	out := hookHandler{event: safeText(ev, 128), matcher: matcher, typ: scalarString(h["type"])}
	if out.typ == "" {
		out.typ = "command"
	}
	// sp collects whether every way this handler can run is spoor's own
	// invocation (for one agent). A handler that also runs anything else is
	// not spoor's, whatever else it carries.
	sp := spoorCheck{}
	var parts []string
	var args []string
	argsOK := true
	argList, hasArgs := h["args"].([]any)
	for _, x := range argList {
		if s, ok := x.(string); ok {
			args = append(args, s)
		} else {
			argsOK = false
		}
	}
	// "command" (and Copilot's "exec") is a shell string, or with "args"
	// the executable of an exec form; opencode writes an argv list.
	for _, k := range []string{"command", "exec"} {
		switch c := h[k].(type) {
		case string:
			if hasArgs {
				out.argv = append(out.argv, args...)
				parts = append(parts, strings.TrimSpace(c+" "+joinArgv(args)))
				sp.add(spoorArgv(append([]string{c}, args...)))
				if !argsOK {
					sp.fail()
				}
			} else {
				parts = append(parts, c)
				sp.add(spoorHook(c))
			}
		case []any:
			var argv []string
			ok := true
			for _, x := range c {
				if s, isStr := x.(string); isStr {
					argv = append(argv, s)
				} else {
					ok = false
				}
			}
			argv = append(argv, args...)
			out.argv = append(out.argv, argv...)
			parts = append(parts, joinArgv(argv))
			sp.add(spoorArgv(argv))
			if !ok || !argsOK {
				sp.fail()
			}
		}
	}
	for _, k := range []string{"bash", "powershell", "commandWindows", "windows", "linux", "osx"} {
		if s, ok := h[k].(string); ok && s != "" {
			parts = append(parts, s)
			sp.add(spoorHook(s))
		}
	}
	if s, ok := h["url"].(string); ok {
		out.url = s
		sp.fail()
	}
	if b, ok := asBool(h["async"]); ok {
		out.async = b
	}
	if then, ok := asMap(h["then"]); ok { // Kiro: {"then": {"type": "runCommand", "command": ...}}
		if s, ok := then["command"].(string); ok {
			parts = append(parts, s)
			sp.add(spoorHook(s))
		}
	}
	out.command = strings.Join(parts, "\n")
	if len(out.command) > maxCommandLen {
		out.command = out.command[:maxCommandLen]
	}
	if out.command == "" && out.url == "" {
		if s, ok := h["prompt"].(string); ok && s != "" {
			out.typ = "prompt"
		} else {
			return out, false
		}
	}
	key := out.event + "\x00" + out.matcher
	out.index = counts[key]
	counts[key]++
	out.spoor, out.spoorAgent = sp.result()
	return out, true
}

// spoorCheck accumulates spoor recognition over a handler's commands.
type spoorCheck struct {
	seen, bad bool
	agent     string
}

// fail records a way to run the handler that is not spoor's.
func (c *spoorCheck) fail() { c.seen, c.bad = true, true }

func (c *spoorCheck) add(ok bool, agent string) {
	c.seen = true
	switch {
	case !ok:
		c.bad = true
	case c.agent == "":
		c.agent = agent
	case c.agent != agent:
		c.bad = true
	}
}

func (c *spoorCheck) result() (bool, string) {
	if !c.seen || c.bad || c.agent == "" {
		return false, ""
	}
	return true, c.agent
}

// spoorBinaries are the file names of the spoor executable. A hook is
// spoor's own only when it runs one of them, with exactly the arguments
// hookinstall registers.
var spoorBinaries = []string{"spoor", "spoor.exe"}

func isSpoorBinary(p string) bool {
	if p == "" || len(p) > 4096 || strings.ContainsAny(p, "\x00\n") {
		return false
	}
	base := p
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		base = p[i+1:]
	}
	for _, b := range spoorBinaries {
		if strings.EqualFold(base, b) {
			return true
		}
	}
	return false
}

// validAgentID is the shape of an agent id hookinstall puts in a command
// line: lower-case letters and digits, then also '.', '_' and '-'.
func validAgentID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// spoorArgv recognises the exec form: the spoor binary, then exactly
// "hook", "--agent", <id>.
func spoorArgv(argv []string) (bool, string) {
	if len(argv) != 4 || !isSpoorBinary(argv[0]) || argv[1] != "hook" || argv[2] != "--agent" || !validAgentID(argv[3]) {
		return false, ""
	}
	return true, argv[3]
}

// spoorHook recognises spoor's own registration in shell text. Every
// non-blank line must be one spoor invocation, "<spoor binary> hook
// --agent <id>", in one of the shapes hookinstall writes: a POSIX
// single-quoted path ('/opt/O'\”Brien/spoor'), a double-quoted path, the
// PowerShell call operator (& 'C:\x\spoor.exe'), or a bare path. Hook
// scripts (one file per event) may add a shebang, comments and a leading
// "exec". Words such as " hook --agent " elsewhere in a command prove
// nothing: anything can carry them.
func spoorHook(cmd string) (bool, string) {
	c := spoorCheck{}
	for _, line := range strings.Split(cmd, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c.add(spoorLine(line))
	}
	return c.result()
}

func spoorLine(line string) (bool, string) {
	line = strings.TrimSpace(line)
	if rest, ok := strings.CutPrefix(line, "exec "); ok {
		line = strings.TrimSpace(rest)
	}
	var exe, rest string
	var ok bool
	switch {
	case strings.HasPrefix(line, "& "):
		exe, rest, ok = pwshQuoted(strings.TrimSpace(line[2:]))
	case strings.HasPrefix(line, "'"), strings.HasPrefix(line, `"`):
		exe, rest, ok = posixWord(line)
	default:
		exe, rest, _ = strings.Cut(line, " ")
		ok = plainPath(exe)
	}
	if !ok {
		return false, ""
	}
	return spoorArgv(append([]string{exe}, strings.Fields(rest)...))
}

// plainPath accepts an unquoted path that no shell would expand or split.
func plainPath(p string) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '\\' || c == ':' || c == '.' || c == '_' || c == '-' || c == '+' || c == '@':
		default:
			return false
		}
	}
	return true
}

// posixWord reads one quoted shell word (single quotes, double quotes
// without expansions, backslash escapes between them) and returns it and
// the text after it. A word that would expand anything is refused.
func posixWord(s string) (word, rest string, ok bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			return b.String(), s[i:], b.Len() > 0
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case c == '"':
			i++
			for {
				if i >= len(s) {
					return "", "", false
				}
				d := s[i]
				if d == '"' {
					i++
					break
				}
				if d == '$' || d == '`' {
					return "", "", false
				}
				if d == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
					d = s[i]
				}
				b.WriteByte(d)
				i++
			}
		case c == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i += 2
		case plainPath(string(c)):
			b.WriteByte(c)
			i++
		default:
			return "", "", false
		}
	}
	return b.String(), "", b.Len() > 0
}

// pwshQuoted reads a PowerShell single-quoted string (a quote character is
// written twice to stand for itself; PowerShell treats the typographic
// single quotes as delimiters too) and returns it and the text after it.
func pwshQuoted(s string) (word, rest string, ok bool) {
	isQ := func(r rune) bool {
		return r == '\'' || r == '\u2018' || r == '\u2019' || r == '\u201a' || r == '\u201b'
	}
	rs := []rune(s)
	if len(rs) < 2 || !isQ(rs[0]) {
		return "", "", false
	}
	var b strings.Builder
	for i := 1; i < len(rs); i++ {
		if isQ(rs[i]) {
			if i+1 < len(rs) && isQ(rs[i+1]) {
				b.WriteRune(rs[i])
				i++
				continue
			}
			rest = string(rs[i+1:])
			if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
				return "", "", false
			}
			return b.String(), rest, true
		}
		b.WriteRune(rs[i])
	}
	return "", "", false
}

func joinArgv(a []string) string {
	q := make([]string, len(a))
	for i, s := range a {
		if s == "" || strings.ContainsAny(s, " \t\"'\\$`;&|<>()") {
			q[i] = strconv.Quote(s)
		} else {
			q[i] = s
		}
	}
	return strings.Join(q, " ")
}

// scalarString renders a scalar for identity purposes; non-scalars give "".
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return safeText(t, 256)
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	return ""
}

// definitionHash identifies a hook's behaviour: what runs, on which event
// and matcher, and whether the agent waits for it.
func (h hookHandler) definitionHash() string {
	return digestParts("hook/v1", h.event, h.matcher, h.typ, h.command, h.url, strconv.FormatBool(h.async))
}

func sortHandlers(hs []hookHandler) {
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].event != hs[j].event {
			return hs[i].event < hs[j].event
		}
		return hs[i].matcher < hs[j].matcher
	})
}
