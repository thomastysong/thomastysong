package fleetgen

import (
	"sort"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/mcpconf"
)

// The vocabulary the policies match on. Each table here classifies values
// that originate elsewhere; tests in vocab_test.go fail when the embedded
// catalog gains a value that is in neither the "bypass" nor the "not
// bypass" table, so a new flag is a decision, not a silent gap.

// bypassArgs are catalog risky_flags (catalog spelling, which is what
// spoor_agent_processes.flags stores) that make an agent run tool calls
// without a per-call approval, or skip a consent check that guards hooks.
// One flag string has one meaning across products: a test checks that no
// flag is classified both ways.
var bypassArgs = map[string]string{
	"--dangerously-skip-permissions":            "claude-code: every permission prompt skipped",
	"--permission-mode bypassPermissions":       "claude-code: bypass permission mode",
	"--dangerously-bypass-approvals-and-sandbox": "codex: approvals and sandbox off",
	"--yolo":                       "codex, copilot-cli, gemini-cli, cursor, cline: approve everything",
	"--ask-for-approval never":     "codex: approvals off",
	"--dangerously-bypass-hook-trust": "codex: hooks run without the trust check",
	"--allow-all":                  "copilot-cli: every tool, path and URL allowed",
	"--allow-all-tools":            "copilot-cli: every tool allowed without asking",
	"--approval-mode yolo":         "gemini-cli: approve everything",
	"--force":                      "cursor-agent: run commands without asking",
	"--yes-always":                 "aider: confirm every prompt, shell commands included",
	"--yes":                        "aider: older spelling of --yes-always",
	"--auto_run":                   "open-interpreter: run generated code without confirmation",
	"-y":                           "open-interpreter: short form of --auto_run",
}

// nonBypassArgs are the remaining catalog risky_flags, with the reason they
// do not count as a permission bypass. They stay visible in
// spoor_agent_processes.flags and in reports.
var nonBypassArgs = map[string]string{
	"--allow-dangerously-skip-permissions": "makes bypass selectable inside a session; not active by itself",
	"--permission-mode dontAsk":            "denies tools that were not pre-approved",
	"--permission-mode auto":               "a model classifier approves; approvals are not switched off",
	"--permission-mode acceptEdits":        "file edits only",
	"--bare":                               "an attribute: managed hooks still run (BUILD-B addendum 2)",
	"--safe-mode":                          "skips user hooks; managed hooks run",
	"--no-session-persistence":             "no transcript; reported as coverage, not as bypass",
	"--dangerously-load-development-channels": "loads unreleased channels",
	"--sandbox danger-full-access":         "removes the sandbox; approvals stay on",
	// UNVERIFIED: research/agent-surfaces-a.md lists both as dangerous
	// without describing them; the name suggests an automatic reviewer.
	"--approve-for-me":     "approvals delegated to an automatic reviewer, not switched off",
	"--not-so-yolo":        "alias of --approve-for-me",
	"--full-auto":          "sandboxed workspace writes with on-request approval",
	"--ephemeral":          "no session files; reported as coverage",
	"--ignore-user-config": "configuration loading",
	"--ignore-rules":       "configuration loading",
	"--allow-all-paths":    "path scope only",
	"--allow-all-urls":     "URL scope only",
	// UNVERIFIED: semantics not documented in the research reports.
	"--autopilot":               "continues without user turns; tool approvals unchanged",
	"--no-ask-user":             "no clarifying questions; tool approvals unchanged",
	"--approval-mode auto_edit": "file edits only",
}

// bypassSettings are catalog setting flags (spoor_agents.risk_flags) that
// configure an agent to skip approvals by default.
var bypassSettings = map[string]string{
	"bypass_permissions_default": "claude-code: permissions.defaultMode bypassPermissions",
	"approvals_disabled":         "codex: approval_policy never",
	"allow_all_tools_env":        "copilot-cli: COPILOT_ALLOW_ALL in the agent's environment",
	"auto_approve_all_tools":     "VS Code: chat tools auto-approve",
}

// nonBypassSettings are the remaining catalog setting flags.
var nonBypassSettings = map[string]string{
	"auto_approve_default":             "dontAsk or auto mode: approvals are not off",
	"bypass_warning_accepted":          "the bypass warning was accepted once; not a current mode",
	"bypass_mode_not_locked":           "management posture",
	"yolo_mode_not_locked":             "management posture",
	"secure_mode_not_enforced":         "management posture",
	"managed_policy_present":           "management posture",
	"managed_hooks_not_exclusive":      "management posture",
	"managed_settings_path_overridden": "management posture",
	"hooks_disabled":                   "hook coverage (hooks policy)",
	"bare_mode_hooks_skipped":          "hook coverage (hooks policy)",
	"safe_mode_user_hooks_skipped":     "hook coverage",
	"hook_consent_bypassed":            "hook consent, not tool approval",
	"sandbox_disabled":                 "sandbox, not approvals",
	"unsandboxed_commands_allowed":     "sandbox, not approvals",
	"api_base_url_override":            "model endpoint",
	"transcript_suppressed":            "coverage",
	"prompt_history_disabled":          "coverage",
	"state_dir_relocated":              "coverage",
	"project_trusted":                  "trust record",
	"saved_approvals_present":          "remembered approvals, not a mode",
	"cli_allowlist_present":            "an allow list, not a mode",
	"listen_address_overridden":        "model runtime exposure",
	"listen_port_overridden":           "model runtime exposure",
}

// riskyMCPFlags are internal/mcpconf risk flags the MCP policy fails on.
var riskyMCPFlags = []string{
	mcpconf.RiskUnpinnedPackage,
	mcpconf.RiskInlineSecret,
	mcpconf.RiskTokenInURL,
}

// autorunFlags are the project control-file flags of internal/discovery
// (unexported there; vocab_test.go runs a project scan to hold them
// together) for files that make an agent or editor run something, or
// steer it, as soon as the folder is opened: the planted-launcher class of
// research/threats.md (R04; Mini Shai-Hulud, ChainDrop, Tensorlake).
var autorunFlags = []string{
	"autorun_hook",
	"autorun_rule",
	"autorun_task",
	"git_exec_key",
	"ide_exec_path_in_workspace",
}

// ai_tools (Fleet's fleetd table) risk flags, from
// fleetdm/fleet schema/tables/ai_tools.yml (research/fleet.md section 3).
var (
	aiToolsBypassFlags = []string{"bypass_permissions", "skip_permissions_runtime"}
	aiToolsMCPFlags    = []string{"unpinned_dependency", "plaintext_secret"}
)

// vocabulary is what one catalog contributes.
type vocabulary struct {
	hookAgents     []string // catalog ids with a hook dialect spoor speaks
	bypassArgs     []string // bypass switches present in the catalog
	bypassSettings []string // bypass setting flags present in the catalog
	catalogVersion string
}

func vocabularyOf(c *catalog.Catalog) vocabulary {
	v := vocabulary{catalogVersion: c.Version()}
	args, settings := map[string]bool{}, map[string]bool{}
	for _, p := range c.Products() {
		if p.Hooks != nil && p.Hooks.Dialect != "" {
			v.hookAgents = append(v.hookAgents, p.ID)
		}
		for _, f := range p.RiskyFlags {
			if _, ok := bypassArgs[f]; ok {
				args[f] = true
			}
		}
		for _, s := range p.Settings {
			if _, ok := bypassSettings[s.Flag]; ok {
				settings[s.Flag] = true
			}
		}
	}
	sort.Strings(v.hookAgents)
	v.bypassArgs = sortedKeys(args)
	v.bypassSettings = sortedKeys(settings)
	return v
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
