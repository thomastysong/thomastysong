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
	binary string
	// agentID is the value of --agent. It is the id hookio stamps on the
	// events of the dialect (so "cursor" for the Cursor IDE and CLI alike),
	// which keeps the command line identical whichever product id the
	// caller named.
	agentID    string
	goos       string
	timeout    int
	guard      bool
	failClosed bool
	// legacy renders the command lines of releases before the
	// missing-binary guard (see guardMode); Status uses it to name such
	// entries. Install never writes it.
	legacy bool
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
}

var dialects = map[string]dialectSpec{
	"claude":  {id: "claude", async: true, failClosed: true, handler: claudeHandler},
	"codex":   {id: "codex", async: true, handler: codexHandler},
	"copilot": {id: "copilot", handler: copilotHandler},
	"gemini":  {id: "gemini", handler: geminiHandler},
	"cursor":  {id: "cursor", failClosed: true, handler: cursorHandler},
}

// notificationEvents are the only events that may run in the background.
// A background (async) hook is killed when the session ends right after the
// event, and the record is lost without an error (Claude Code finalises
// still-running async hooks as "cancelled" at -p teardown,
// code.claude.com/docs/en/hooks.md "Run hooks in the background"). Tool,
// prompt and session events are the record spoor exists to keep, so they
// are registered synchronously whatever hookio's Async hint says; only
// events that announce something without recording an action qualify.
var notificationEvents = map[string]bool{
	"Notification": true, "notification": true,
	"PostCompact": true, "PreCompact": true, "PreCompress": true,
}

// entries renders the registration for every event the hookio dialect asks
// for. Guard mode does not change which events are registered or how: the
// hook path decides between observing and gating from its own
// configuration. It only enables fail-closed handling where asked for.
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
		async := d.async && ev.Async && !ev.Blocking && notificationEvents[ev.Name]
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
//
// There is no shell, so there is no missing-binary guard either: a missing
// binary is a spawn failure, which Claude Code counts as a hook that
// "can't start" and treats as a non-blocking error (the action goes ahead
// with a "hook error" notice), except with "onFailure": "block", where
// blocking is what the operator asked for. VERIFIED: hooks.md "Other exit
// codes" ("a hook that can't start is a non-blocking error too") and
// "Block the action when a hook fails" ("Without onFailure set, the same
// missing script is a non-blocking error"), research/dl_hooks/hooks.md.
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
// through the user's login shell (<shell> -c on unix) and "commandWindows"
// through pwsh or powershell -NoProfile -Command on Windows; $SHELL -lc and
// %COMSPEC% /C are its fallbacks (the latter also whenever the session has
// no single local environment). "command" carries the POSIX guard. The
// Windows string is written bare when the path needs no quoting (valid in
// PowerShell and cmd.exe alike, but unguarded) and as the guarded
// PowerShell form otherwise; see windowsCommand. Codex reads a non-zero
// exit other than 2 as a failed, non-blocking run and exit 2 with stderr as
// a block (codex-rs/hooks/src/events/pre_tool_use.rs, read 2026-11-12), so
// for Codex an unguarded missing binary is noise rather than a denial.
// "timeout" is in seconds.
// VERIFIED: codex-rs/core/config.schema.json (HookHandlerConfig),
// codex-rs/hooks/src/engine/discovery.rs, codex-rs/core/src/session/mod.rs
// (build_hooks_config), read 2026-11-11.
func codexHandler(p params, ev hookio.HookEvent, async bool) jobj {
	h := jobj{
		{"type", "command"},
		{"command", posixCommand(p.binary, p.agentID, p.modeFor(false))},
	}
	if p.goos == "windows" {
		h = append(h, jfield{"commandWindows", windowsCommand(p.binary, p.agentID, p.modeFor(false))})
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
// fail open, including for policy hooks, but a preToolUse command hook
// that crashes or exits non-zero denies the tool call ("Exit codes for
// command hooks"), so both fields carry the missing-binary guard: without
// it a removed or quarantined binary would deny every tool call.
// VERIFIED: github/docs content/copilot/reference/hooks-reference.md,
// "Command hooks" and "Exit codes for command hooks", re-read 2026-11-12.
// The CLI now also accepts an exec form ("exec" plus "args"), but the page
// marks it CLI-only and the same files are loaded by the VS Code Copilot
// harness and by older CLI releases, where an entry without a shell field
// is dropped; the shell fields work everywhere.
func copilotHandler(p params, ev hookio.HookEvent, async bool) jobj {
	return jobj{
		{"type", "command"},
		{"bash", posixCommand(p.binary, p.agentID, p.modeFor(false))},
		{"powershell", pwshCommand(p.binary, p.agentID, p.modeFor(false))},
		{"timeoutSec", p.timeout},
	}
}

// geminiHandler has a single "command" string, which Gemini CLI passes to
// bash -c on unix and to PowerShell (-NoProfile -NonInteractive -Command)
// on Windows. "timeout" is in milliseconds.
// VERIFIED: google-gemini/gemini-cli docs/hooks/index.md (configuration
// schema) and packages/core/src/utils/shell-utils.ts (getShellConfiguration),
// read 2026-11-11.
//
// Gemini CLI turns output that is not JSON into a decision by exit code,
// and every code other than 0 and 1 is a deny, so the shell's exit 127 for
// a missing binary would deny the event: the command carries the guard. On
// PowerShell it appends "; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
// to the command, which the guarded form never reaches.
// VERIFIED: packages/core/src/hooks/hookRunner.ts (convertPlainTextToHookOutput
// and the PowerShell suffix), redteam/verify-platform-parity/dl/gemini-hookRunner.ts.
func geminiHandler(p params, ev hookio.HookEvent, async bool) jobj {
	cmd := posixCommand(p.binary, p.agentID, p.modeFor(false))
	if p.goos == "windows" {
		cmd = pwshCommand(p.binary, p.agentID, p.modeFor(false))
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
// PowerShell accept (unguarded, see windowsCommand).
//
// A handler marked failClosed gets no missing-binary guard: the operator
// asked for a failing hook to block, and the guard would turn the most
// likely failure, a removed binary, into a silent allow.
func cursorHandler(p params, ev hookio.HookEvent, async bool) jobj {
	failClosed := p.failClosed && p.guard && ev.Blocking
	m := p.modeFor(failClosed)
	cmd := posixCommand(p.binary, p.agentID, m)
	if p.goos == "windows" {
		cmd = windowsCommand(p.binary, p.agentID, m)
	}
	h := jobj{
		{"command", cmd},
		{"timeout", p.timeout},
	}
	if failClosed {
		h = append(h, jfield{"failClosed", true})
	}
	return h
}
