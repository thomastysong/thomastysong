package hookinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// A managed hook file is only as good as the agent's willingness to read
// it. Claude Code ranks its managed sources (server-managed settings, then
// the MDM policy, then the files) and by default applies only the highest
// one that carries a policy key, without any warning for the ones it skips.
// A Fleet-deployed drop-in can therefore be present, correct and ignored.
// VERIFIED: code.claude.com/docs/en/managed-settings.md, "How Claude Code
// combines managed sources", read 2026-11-11.

// claudeMDMDomain is the macOS managed-preferences domain, and
// claudePolicyKey the Windows registry key (value "Settings"), that outrank
// the managed settings files.
const (
	claudeMDMDomain = "com.anthropic.claudecode"
	claudePolicyKey = `SOFTWARE\Policies\ClaudeCode`
)

// shadowReport says whether something outranks the file and, just as
// important, what could and could not be looked at.
type shadowReport struct {
	shadowed bool
	why      string
	checked  []string
	blind    []string
}

func (s shadowReport) detail() string {
	var parts []string
	if s.why != "" {
		parts = append(parts, s.why)
	}
	if len(s.checked) > 0 {
		parts = append(parts, "checked: "+strings.Join(s.checked, ", "))
	}
	if len(s.blind) > 0 {
		parts = append(parts, "not checked: "+strings.Join(s.blind, ", "))
	}
	return strings.Join(parts, "; ")
}

// shadowOf inspects the sources that outrank t.
func shadowOf(t target, o Options, rel related) shadowReport {
	var r shadowReport
	switch {
	case t.dialect == "claude" && t.scope == event.ScopeManaged:
		claudeShadow(&r, o)
	case t.dialect == "claude" && t.scope == event.ScopeUser:
		if rel.managedOnly != "" {
			r.shadowed = true
			r.why = "allowManagedHooksOnly in " + rel.managedOnly + " makes Claude Code ignore user hooks"
		}
		r.checked = append(r.checked, "allowManagedHooksOnly in the managed settings files")
		r.blind = append(r.blind, "server-managed settings and MDM policy (not visible from these files)")
	case t.dialect == "codex" && t.scope == event.ScopeUser:
		if rel.managedOnly != "" {
			r.shadowed = true
			r.why = "allow_managed_hooks_only in " + rel.managedOnly + " makes Codex ignore user hooks"
		}
		r.checked = append(r.checked, "allow_managed_hooks_only in requirements.toml")
		r.blind = append(r.blind, "cloud and MDM requirements (not visible from disk)", "whether the user trusted the hooks in /hooks")
	case t.dialect == "codex" && t.scope == event.ScopeManaged:
		// codex-rs/config/src/config_requirements.rs: a higher requirements
		// source that defines hooks replaces this one as a whole.
		r.blind = append(r.blind, "cloud and MDM requirements, which replace the [hooks] of requirements.toml when they define hooks")
	}
	return r
}

func claudeShadow(r *shadowReport, o Options) {
	// Server-managed settings outrank everything on every OS and live on
	// Anthropic's servers (or a gateway), so no file scan can rule them out.
	r.blind = append(r.blind, `server-managed settings (claude.ai admin console or gateway; not visible from disk, they outrank this file unless managedSourcesBehavior is "merge")`)
	switch o.GOOS {
	case "darwin":
		// Managed preferences are materialised as plists under
		// /Library/Managed Preferences, machine-wide or per user.
		// UNVERIFIED: the per-user location for this domain; the machine
		// one is where macOS puts any device-level configuration profile.
		base := hostPath(o.Root, "/Library/Managed Preferences", "darwin")
		name := claudeMDMDomain + ".plist"
		hits := []string{filepath.Join(base, name)}
		if m, err := filepath.Glob(filepath.Join(globEscape(base), "*", name)); err == nil {
			hits = append(hits, m...)
		}
		r.checked = append(r.checked, "/Library/Managed Preferences/"+name)
		for _, h := range hits {
			if fi, err := os.Lstat(h); err == nil && !fi.IsDir() {
				r.shadowed = true
				r.why = "an MDM policy (" + h + `) outranks the managed settings files; Claude Code ignores this file unless that policy sets managedSourcesBehavior to "merge"`
				break
			}
		}
	case "windows":
		if o.Root != "" || runtime.GOOS != "windows" {
			r.blind = append(r.blind, `HKLM\`+claudePolicyKey+" (the registry of the target machine is not reachable from here)")
			return
		}
		present, err := claudeRegistryPolicy()
		if err != nil {
			r.blind = append(r.blind, `HKLM\`+claudePolicyKey+" (could not be read)")
			return
		}
		r.checked = append(r.checked, `HKLM\`+claudePolicyKey)
		if present {
			r.shadowed = true
			r.why = `the registry policy HKLM\` + claudePolicyKey + ` outranks the managed settings files; Claude Code ignores this file unless that policy sets managedSourcesBehavior to "merge"`
		}
	default:
		r.checked = append(r.checked, "no MDM source exists on this OS")
	}
}

// globEscape neutralises glob metacharacters in a directory name that is
// used as the fixed part of a pattern.
func globEscape(s string) string {
	if runtime.GOOS == "windows" {
		// Backslash is the separator there and cannot escape; Windows file
		// names cannot contain * or ? anyway.
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(s)
}
