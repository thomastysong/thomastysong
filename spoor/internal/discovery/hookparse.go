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
	var parts []string
	switch c := h["command"].(type) {
	case string:
		parts = append(parts, c)
	case []any:
		// opencode-style argv list
		for _, x := range c {
			if s, ok := x.(string); ok {
				out.argv = append(out.argv, s)
			}
		}
		parts = append(parts, joinArgv(out.argv))
	}
	if args, ok := h["args"].([]any); ok {
		for _, x := range args {
			if s, ok := x.(string); ok {
				out.argv = append(out.argv, s)
			}
		}
		if len(parts) > 0 {
			parts[0] = strings.TrimSpace(parts[0] + " " + joinArgv(out.argv))
		}
	}
	for _, k := range []string{"bash", "powershell", "commandWindows", "windows", "linux", "osx"} {
		if s, ok := h[k].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	if s, ok := h["url"].(string); ok {
		out.url = s
	}
	if b, ok := asBool(h["async"]); ok {
		out.async = b
	}
	if then, ok := asMap(h["then"]); ok { // Kiro: {"then": {"type": "runCommand", "command": ...}}
		if s, ok := then["command"].(string); ok {
			parts = append(parts, s)
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
	out.spoor, out.spoorAgent = spoorHook(out.command)
	return out, true
}

// spoorHook recognises spoor's own registration: every entry spoor
// installs runs "<binary> hook --agent <id>", as a command line or in the
// exec form (command plus args), so the joined text contains the marker.
func spoorHook(cmd string) (bool, string) {
	const marker = " hook --agent "
	for _, line := range strings.Split(cmd, "\n") {
		norm := strings.ReplaceAll(strings.ReplaceAll(line, `"`, " "), "'", " ")
		norm = " " + strings.Join(strings.Fields(norm), " ") + " "
		i := strings.Index(norm, marker)
		if i < 0 {
			continue
		}
		rest := strings.Fields(norm[i+len(marker):])
		if len(rest) == 0 {
			return true, ""
		}
		return true, safeText(rest[0], 64)
	}
	return false, ""
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
