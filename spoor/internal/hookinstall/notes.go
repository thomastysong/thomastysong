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
			if sh := shadowOf(t, o, rel); sh.shadowed {
				n.add("installed but shadowed: " + sh.why)
			} else {
				n.add(`not visible from disk: server-managed settings outrank this file under the default managedSourcesBehavior "first-wins"`)
			}
		} else if rel.managedOnly != "" {
			n.add("allowManagedHooksOnly in " + rel.managedOnly + " makes Claude Code ignore user hooks; install in the managed scope")
		}
	case "codex":
		switch t.scope {
		case event.ScopeManaged:
			n.add("a cloud or MDM requirements source that defines hooks replaces these (not visible from disk)")
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
		n.add("a preToolUse hook that cannot start or crashes denies the tool call (only timeouts fail open): uninstall before removing the spoor binary")
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

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
