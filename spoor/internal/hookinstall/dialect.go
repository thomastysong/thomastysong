package hookinstall

import (
	"github.com/thomastysong/spoor/internal/hookio"
)

// fileKind is how a hook file is edited.
type fileKind uint8

const (
	// kindGroups: {"hooks": {"<Event>": [{"matcher"?: "...", "hooks": [handler]}]}}
	// (Claude Code settings, Codex hooks.json, Gemini CLI settings).
	kindGroups fileKind = iota + 1
	// kindFlat: {"version": 1, "hooks": {"<event>": [handler]}} (Copilot CLI, Cursor).
	kindFlat
	// kindTOML: a marked block of [[hooks.<Event>]] tables (Codex requirements.toml).
	kindTOML
)

// params is everything a dialect needs to render one handler.
type params struct {
	binary     string
	agentID    string
	goos       string
	timeout    int
	guard      bool
	failClosed bool
}

// entry is the registration for one hook event.
type entry struct {
	event   string
	matcher string
	handler jobj // the command handler itself
}

// element is what goes into the event's array: the handler for flat formats,
// a matcher group around it for the grouped ones.
func (e entry) element(kind fileKind) any {
	if kind == kindFlat {
		return e.handler
	}
	g := jobj{}
	if e.matcher != "" {
		g = append(g, jfield{"matcher", e.matcher})
	}
	return append(g, jfield{"hooks", jarr{e.handler}})
}

// dialectSpec describes how one agent wants its hooks written.
type dialectSpec struct {
	id string
	// async is true when the agent can run a command hook in the background.
	// VERIFIED for Claude Code ("async", code.claude.com/docs/en/hooks.md)
	// and Codex ("async" in HookHandlerConfig, codex-rs/core/config.schema.json).
	// Copilot, Gemini and Cursor run every hook synchronously.
	async bool
	// failClosed is true when a failing or timed-out hook can be made to
	// block the action.
	failClosed bool
	handler    func(p params, ev hookio.HookEvent, async bool) jobj
	// notes are facts the operator must know about this agent's hook tier.
	notes func(p params, scope string) []string
}

var dialects = map[string]dialectSpec{
	"claude":  {id: "claude", async: true, failClosed: true, handler: claudeHandler},
	"codex":   {id: "codex", async: true, handler: codexHandler},
	"copilot": {id: "copilot", handler: copilotHandler},
	"gemini":  {id: "gemini", handler: geminiHandler},
	"cursor":  {id: "cursor", failClosed: true, handler: cursorHandler},
}

// entries renders the registration for every event the hookio dialect asks
// for.
func (d dialectSpec) entries(p params) ([]entry, bool) {
	hd, ok := hookio.Get(d.id)
	if !ok {
		return nil, false
	}
	var out []entry
	for _, ev := range hd.Events() {
		if ev.Name == "" {
			continue
		}
		// Without guard mode nothing waits for spoor's answer, so events
		// that could be gated go to the background as well. Events hookio
		// marks neither async nor blocking (session end) stay synchronous:
		// the agent is exiting and would kill a background hook.
		async := d.async && (ev.Async || (ev.Blocking && !p.guard))
		out = append(out, entry{event: ev.Name, matcher: ev.Matcher, handler: d.handler(p, ev, async)})
	}
	return out, len(out) > 0
}

// claudeHandler uses the exec form: "command" is the executable and "args"
// its argument vector, spawned with no shell on every OS, so a path with
// spaces needs no quoting. "timeout" is in seconds; "async": true runs in
// the background; "onFailure": "block" makes a crash or timeout block the
// action (needs Claude Code v2.1.295 or later and has no effect on
// background hooks).
// VERIFIED: code.claude.com/docs/en/hooks.md, sections "Command hook
// fields", "Exec form and shell form", "Block the action when a hook fails".
func claudeHandler(p params, ev hookio.HookEvent, async bool) jobj {
	h := jobj{
		{"type", "command"},
		{"command", p.binary},
		{"args", jarr{"hook", "--agent", p.agentID}},
		{"timeout", p.timeout},
	}
	if async {
		h = append(h, jfield{"async", true})
	}
	if p.failClosed && p.guard && ev.Blocking && !async {
		h = append(h, jfield{"onFailure", "block"})
	}
	return h
}

// codexSessionEndMax is the cap Codex puts on SessionEnd hook timeouts
// (SESSION_END_MAX_TIMEOUT_SEC in codex-rs/hooks/src/events/session_end.rs);
// asking for more only produces a startup warning.
const codexSessionEndMax = 3

// codexHandler writes one string per shell field. Codex runs "command"
// through the user's shell (<shell> -c on unix, pwsh/powershell
// -NoProfile -Command on Windows) and prefers "commandWindows" on Windows.
// "timeout" is in seconds.
// VERIFIED: codex-rs/core/config.schema.json (HookHandlerConfig),
// codex-rs/hooks/src/engine/discovery.rs, codex-rs/core/src/session/mod.rs
// (build_hooks_config), read 2026-11-11.
func codexHandler(p params, ev hookio.HookEvent, async bool) jobj {
	h := jobj{
		{"type", "command"},
		{"command", posixCommand(p.binary, p.agentID)},
	}
	if p.goos == "windows" {
		h = append(h, jfield{"commandWindows", pwshCommand(p.binary, p.agentID)})
	}
	t := p.timeout
	if ev.Name == "SessionEnd" && t > codexSessionEndMax {
		t = codexSessionEndMax
	}
	h = append(h, jfield{"timeout", t})
	if async {
		h = append(h, jfield{"async", true})
	}
	return h
}

// copilotHandler writes both shell fields: Copilot CLI runs "bash" on unix
// and "powershell" on Windows. "timeoutSec" is in seconds. Timeouts always
// fail open, including for policy hooks.
// VERIFIED: github/docs content/copilot/reference/hooks-reference.md,
// "Command hooks" and "Exit codes for command hooks", read 2026-11-11.
func copilotHandler(p params, ev hookio.HookEvent, async bool) jobj {
	return jobj{
		{"type", "command"},
		{"bash", posixCommand(p.binary, p.agentID)},
		{"powershell", pwshCommand(p.binary, p.agentID)},
		{"timeoutSec", p.timeout},
	}
}

// geminiHandler has a single "command" string, which Gemini CLI passes to
// bash -c on unix and to PowerShell (-NoProfile -NonInteractive -Command)
// on Windows. "timeout" is in milliseconds.
// VERIFIED: google-gemini/gemini-cli docs/hooks/index.md (configuration
// schema) and packages/core/src/utils/shell-utils.ts (getShellConfiguration),
// read 2026-11-11.
func geminiHandler(p params, ev hookio.HookEvent, async bool) jobj {
	cmd := posixCommand(p.binary, p.agentID)
	if p.goos == "windows" {
		cmd = pwshCommand(p.binary, p.agentID)
	}
	return jobj{
		{"name", sensorName},
		{"type", "command"},
		{"command", cmd},
		{"timeout", p.timeout * 1000},
	}
}

// cursorHandler follows the hooks.json shape used by two independent
// installers (snyk/agent-scan guard.py, numbat): {"command": "..."} entries
// under a top-level "version": 1.
// UNVERIFIED: cursor.com was unreachable, so "timeout" (seconds),
// "failClosed" and the shell Cursor uses on Windows are not confirmed
// against vendor documentation. On Windows the command is therefore written
// without quotes whenever the path allows it, which both cmd.exe and
// PowerShell accept.
func cursorHandler(p params, ev hookio.HookEvent, async bool) jobj {
	cmd := posixCommand(p.binary, p.agentID)
	if p.goos == "windows" {
		if plainWindowsPath(p.binary) {
			cmd = bareCommand(p.binary, p.agentID)
		} else {
			cmd = pwshCommand(p.binary, p.agentID)
		}
	}
	h := jobj{
		{"command", cmd},
		{"timeout", p.timeout},
	}
	if p.failClosed && p.guard && ev.Blocking {
		h = append(h, jfield{"failClosed", true})
	}
	return h
}
