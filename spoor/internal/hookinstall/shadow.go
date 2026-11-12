package hookinstall

import (
	"io/fs"
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

// shadowOf inspects the sources that outrank t. selfOff is the file's own
// switch for every hook (Claude Code disableAllHooks, Gemini CLI
// hooksConfig.enabled negated), nil when the file does not set it.
func shadowOf(t target, o Options, rel related, selfOff *bool) shadowReport {
	var r shadowReport
	switch {
	case t.dialect == "claude" && t.scope == event.ScopeManaged:
		claudeShadow(&r, o)
		if !r.shadowed && rel.hooksOff != nil && *rel.hooksOff {
			r.shadowed = true
			r.why = "disableAllHooks in " + rel.hooksOffFile + " turns off every hook, managed ones included"
		}
		r.checked = append(r.checked, "disableAllHooks in the managed settings files")
	case t.dialect == "claude" && t.scope == event.ScopeUser:
		switch {
		case rel.managedOnly != "":
			r.shadowed = true
			r.why = "allowManagedHooksOnly in " + rel.managedOnly + " makes Claude Code ignore user hooks"
		case rel.hooksOff != nil && *rel.hooksOff:
			r.shadowed = true
			r.why = "disableAllHooks in " + rel.hooksOffFile + " turns off every hook"
		case rel.hooksOff == nil && selfOff != nil && *selfOff:
			r.shadowed = true
			r.why = "disableAllHooks in this file turns off user hooks (a project's own settings can set it back to false)"
		}
		r.checked = append(r.checked, "allowManagedHooksOnly and disableAllHooks in the managed settings files and this file")
		r.blind = append(r.blind, "server-managed settings and MDM policy (not visible from these files)", "project settings")
	case t.dialect == "gemini":
		// System settings outrank user and project settings.
		switch {
		case t.scope != event.ScopeUser && selfOff != nil && *selfOff:
			r.shadowed = true
			r.why = "hooksConfig.enabled is false in this file, which turns off every hook"
		case t.scope == event.ScopeUser && rel.hooksOff != nil && *rel.hooksOff:
			r.shadowed = true
			r.why = "hooksConfig.enabled is false in " + rel.hooksOffFile + ", which outranks user settings"
		case t.scope == event.ScopeUser && rel.hooksOff == nil && selfOff != nil && *selfOff:
			r.shadowed = true
			r.why = "hooksConfig.enabled is false in this file (a project's settings can turn hooks back on)"
		}
		r.checked = append(r.checked, "hooksConfig.enabled in the system settings")
		r.blind = append(r.blind, "GEMINI_CLI_SYSTEM_SETTINGS_PATH, which can point Gemini CLI at another system file")
	case t.dialect == "codex" && t.scope == event.ScopeUser:
		if rel.managedOnly != "" {
			r.shadowed = true
			r.why = "allow_managed_hooks_only in " + rel.managedOnly + " makes Codex ignore user hooks"
		}
		r.checked = append(r.checked, "allow_managed_hooks_only in requirements.toml")
		codexMDM(&r, o, "it can set allow_managed_hooks_only")
		r.blind = append(r.blind, "whether the user trusted the hooks in /hooks")
	case t.dialect == "codex":
		// codex-rs/config/src/config_requirements.rs: a higher requirements
		// source that defines hooks replaces this one as a whole.
		codexMDM(&r, o, "when its requirements define hooks, Codex uses them instead of these")
	}
	if len(rel.unread) > 0 {
		r.blind = append(r.blind, rel.unread...)
	}
	return r
}

// codexMDM reports the requirements sources that outrank requirements.toml:
// cloud requirements (never visible from disk) and, on macOS only, the MDM
// managed-preferences domain com.openai.codex (requirements_toml_base64).
// The profile's content is base64 TOML inside a property list and is not
// parsed: its presence is reported, with what it can do.
func codexMDM(r *shadowReport, o Options, effect string) {
	r.blind = append(r.blind, "cloud requirements (not visible from disk)")
	if o.GOOS != "darwin" {
		r.checked = append(r.checked, "no MDM requirements source exists on this OS")
		return
	}
	hits, desc := mdmProfiles(o, codexMDMDomain)
	r.checked = append(r.checked, desc)
	if len(hits) > 0 {
		r.blind = append(r.blind, "the content of the MDM profile "+hits[0]+" ("+effect+")")
	}
}

// codexMDMDomain is the macOS managed-preferences domain Codex reads its
// MDM requirements and configuration from.
const codexMDMDomain = "com.openai.codex"

// mdmProfiles finds the managed-preferences plists of a domain, machine-wide
// and per user, and describes what was looked at. The directory is reached
// through the same confined walk as every other file.
func mdmProfiles(o Options, domain string) (hits []string, checked string) {
	base := hostPath(o.Root, "/Library/Managed Preferences", "darwin")
	name := domain + ".plist"
	look := func(p string) {
		if fi, err := lstatIn(p, o.Root); err == nil && !fi.IsDir() {
			hits = append(hits, p)
		}
	}
	look(filepath.Join(base, name))
	for _, e := range listDir(base, o.Root) {
		if e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
			look(filepath.Join(base, e.Name(), name))
		}
	}
	return hits, "/Library/Managed Preferences/" + name + " (machine and per user)"
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
		hits, desc := mdmProfiles(o, claudeMDMDomain)
		r.checked = append(r.checked, desc)
		if len(hits) > 0 {
			r.shadowed = true
			r.why = "an MDM policy (" + hits[0] + `) outranks the managed settings files; Claude Code ignores this file unless that policy sets managedSourcesBehavior to "merge"`
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

