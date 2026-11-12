package hookinstall

import (
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// notes collects the facts an operator must know about one plan.
type notes struct{ list []string }

func (n *notes) add(s string) {
	for _, have := range n.list {
		if have == s {
			return
		}
	}
	n.list = append(n.list, s)
}

func (n *notes) first(s string) { n.list = append([]string{s}, n.list...) }

func (n *notes) String() string { return strings.Join(n.list, "; ") }

// coexistProblem refuses to put a second sensor's handler next to another
// one unless asked to: two handlers double the latency on every tool call
// and, in guard mode, give two answers to the same question.
func coexistProblem(t target, o Options, cur fileState, rel related, n *notes, noWrite bool) string {
	found := map[string]string{}
	for _, s := range rel.sensorList() {
		found[s] = rel.sensors[s]
	}
	if cur.exists {
		var sensors []string
		if t.kind == kindTOML {
			if td, err := parseTOML(cur.data); err == nil {
				_, _, sensors = td.counts()
			}
		} else if d, err := parseJSON(cur.data); err == nil {
			_, sensors = scanHooks(d, t.kind).foreign()
		}
		for _, s := range sensors {
			found[s] = t.path
		}
	}
	if len(found) == 0 {
		return ""
	}
	var parts []string
	for _, s := range sortedKeys(found) {
		parts = append(parts, s+" ("+found[s]+")")
	}
	if !o.Coexist && !noWrite {
		return "another sensor's hook is already registered for this agent: " + strings.Join(parts, ", ") + "; nothing written (set Coexist to install next to it)"
	}
	n.add("also registered: " + strings.Join(parts, ", ") + "; both handlers run on every event")
	return ""
}

// installNotes states the side effects and limits of the hook tier.
func installNotes(t target, o Options, rel related, n *notes) {
	for _, u := range rel.unread {
		n.add("not checked for other sensors, policy or telemetry: " + u)
	}
	if o.FailClosed {
		switch {
		case !o.Guard:
			n.add("FailClosed takes effect only with Guard; hooks fail open")
		case !dialects[t.dialect].failClosed:
			n.add("this agent cannot make a failing hook block the action; hooks fail open")
		}
	}
	if o.OTel != "" && t.dialect != "claude" && t.dialect != "gemini" && t.dialect != "codex" {
		n.add("native OpenTelemetry export is not configured for this agent")
	}
	managed := t.scope != event.ScopeUser
	switch t.dialect {
	case "claude":
		if managed {
			// code.claude.com/docs/en/managed-settings.md, "When an admin
			// document counts as present" and "Let an embedding host add
			// policy".
			n.add(`Claude Code treats this drop-in as an admin policy source: while it exists, the user-writable HKCU policy and settings passed by an embedding host are ignored unless parentSettingsBehavior is "merge"`)
			if sh := shadowOf(t, o, rel, nil); sh.shadowed {
				n.add("installed but shadowed: " + sh.why)
			} else {
				n.add(`not visible from disk: server-managed settings outrank this file under the default managedSourcesBehavior "first-wins"`)
			}
		} else if rel.managedOnly != "" {
			n.add("allowManagedHooksOnly in " + rel.managedOnly + " makes Claude Code ignore user hooks; install in the managed scope")
		}
	case "codex":
		// codex-rs/core/src/session/mod.rs build_hooks_config and
		// codex-rs/hooks/src/engine/command_runner.rs: pwsh/powershell -NoProfile
		// -Command normally, %COMSPEC% /C without a single local
		// environment.
		if o.GOOS == "windows" {
			if plainWindowsPath(o.Binary) {
				n.add("commandWindows is written bare so that cmd.exe, Codex's fallback shell, can run it too: it has no missing-binary check, and run by PowerShell, Codex's usual shell, it exits 1 where spoor exits 2, so a block by spoor does not take effect")
			} else {
				n.add("commandWindows is written for PowerShell, Codex's usual shell; cmd.exe, which Codex uses when a session has no single local environment, cannot run it")
			}
		}
		switch t.scope {
		case event.ScopeManaged:
			if o.GOOS == "darwin" {
				n.add("a cloud requirements source (not visible from disk) or the MDM profile com.openai.codex that defines hooks replaces these")
				if hits, _ := mdmProfiles(o, codexMDMDomain); len(hits) > 0 {
					n.add("an MDM profile for com.openai.codex is installed (" + hits[0] + "); its content was not parsed")
				}
			} else {
				n.add("a cloud requirements source that defines hooks replaces these (not visible from disk)")
			}
		case event.ScopeSystem:
			n.add("Codex loads hooks.json beside the system config.toml as a managed layer, without asking the user to trust it")
		default:
			// codex-rs/hooks/src/engine/discovery.rs: hook_trust_status.
			n.add("Codex runs user hooks only after the user trusts them in /hooks (or with --dangerously-bypass-hook-trust)")
			if rel.managedOnly != "" {
				n.add("allow_managed_hooks_only in " + rel.managedOnly + " makes Codex ignore user hooks; install in the managed scope")
			}
		}
	case "copilot":
		// github/docs hooks-reference.md, "Exit codes for command hooks".
		n.add("a preToolUse hook that crashes or exits non-zero denies the tool call (only timeouts fail open); the command checks for the spoor binary first and exits 0 when it is missing")
		if managed {
			n.add("Copilot CLI loads policy files only while they are root-owned and not group- or world-writable")
		}
	case "gemini":
		if managed {
			n.add("GEMINI_CLI_SYSTEM_SETTINGS_PATH can point Gemini CLI at another system file, and hooksConfig.enabled=false turns hooks off: this tier is advisory")
		} else {
			n.add("hooksConfig.enabled=false turns hooks off")
		}
	case "cursor":
		n.add("UNVERIFIED: the hooks.json fields timeout and failClosed could not be checked against Cursor documentation")
	}
}

// permNotes tells the operator about files beside a managed hook file that
// a non-admin could change. Install takes them back, but their content was
// written by somebody who was not meant to set policy for every user.
func permNotes(ps []permProblem, n *notes) {
	for _, p := range ps {
		switch {
		case !p.sibling:
		case p.fixable:
			n.add(p.String() + ": the agent loads it for every user; install makes it admin-only, review its content")
		default:
			n.add(p.String() + ": the agent loads it for every user and spoor cannot secure it; remove it")
		}
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
