package catalog

import (
	"encoding/json"
	"io/fs"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func TestLoadAndVersion(t *testing.T) {
	c := mustLoad(t)
	if !regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}$`).MatchString(c.Version()) {
		t.Errorf("Version() = %q, want a date-style version", c.Version())
	}
	if n := c.Len(); n < 80 {
		t.Errorf("catalog has %d products, the spec asks for at least 80", n)
	}
	if got := len(c.Products()); got != c.Len() {
		t.Errorf("Products() returned %d, Len() %d", got, c.Len())
	}
	// A second Load must return an independent handle on the same data.
	c2 := mustLoad(t)
	if c2 == c {
		t.Error("Load returned the same *Catalog twice; overlays on one would leak into the other")
	}
	if c2.Version() != c.Version() || c2.Len() != c.Len() {
		t.Error("two loads disagree")
	}
}

func TestDataFilesSplitByCategory(t *testing.T) {
	names, err := fs.Glob(dataFS, "data/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	want := []string{"data/agents.yaml", "data/browsers.yaml", "data/desktop.yaml", "data/extensions.yaml", "data/ides.yaml", "data/runtimes.yaml"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("embedded files = %v, want %v", names, want)
	}
	for _, name := range names {
		b, _ := dataFS.ReadFile(name)
		df, err := parseFile(name, b)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if df.Version == "" || len(df.Products) == 0 {
			t.Errorf("%s: version %q, %d products", name, df.Version, len(df.Products))
		}
	}
}

func TestEveryProductIsWellFormed(t *testing.T) {
	c := mustLoad(t)
	seen := map[string]bool{}
	kinds := map[string]int{}
	for _, p := range c.Products() {
		if seen[p.ID] {
			t.Errorf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
		kinds[p.Kind]++
		if !hasFingerprint(&p) {
			t.Errorf("%s has no fingerprint", p.ID)
		}
		if p.Name == "" || p.Vendor == "" {
			t.Errorf("%s: name %q vendor %q", p.ID, p.Name, p.Vendor)
		}
		if !productKinds[p.Kind] {
			t.Errorf("%s: kind %q", p.ID, p.Kind)
		}
		if len(p.Sources) == 0 {
			t.Errorf("%s has no provenance in sources", p.ID)
		}
		got, ok := c.Get(p.ID)
		if !ok || got.ID != p.ID {
			t.Errorf("Get(%q) failed", p.ID)
		}
		// Hook dialects are only claimed for the agents spoor implements.
		if p.Hooks != nil && p.Hooks.Dialect != "" {
			switch p.ID {
			case "claude-code", "codex", "copilot-cli", "gemini-cli", "cursor", "cursor-agent":
			default:
				t.Errorf("%s declares hook dialect %q", p.ID, p.Hooks.Dialect)
			}
		}
		// Unverified must point at fields that are actually set, otherwise
		// the marker has gone stale.
		for _, u := range p.Unverified {
			top, _, _ := strings.Cut(u, ".")
			if !fieldIsSet(p, top) {
				t.Errorf("%s: unverified lists %q but the field is empty", p.ID, u)
			}
		}
	}
	for _, k := range []event.AssetKind{event.AssetAgent, event.AssetApp, event.AssetIDEExtension, event.AssetBrowser, event.AssetBrowserExtension, event.AssetModelRuntime, event.AssetCIAgent} {
		if kinds[string(k)] == 0 {
			t.Errorf("no product of kind %s", k)
		}
	}
	if _, ok := c.Get("no-such-product"); ok {
		t.Error("Get of an unknown id succeeded")
	}
}

func fieldIsSet(p Product, yamlName string) bool {
	i, ok := yamlFields(productType)[yamlName]
	if !ok {
		return false
	}
	return !reflect.ValueOf(p).Field(i).IsZero()
}

// The shared-fingerprint rule, checked with code independent of the loader:
// any value two products both carry must be acknowledged by both.
func TestNoUndeclaredDuplicateClaims(t *testing.T) {
	c := mustLoad(t)
	type owner struct{ id string }
	seen := map[string][]string{}
	add := func(class, v, id string) {
		k := class + "\x00" + strings.ToLower(v)
		for _, o := range seen[k] {
			if o == id {
				return
			}
		}
		seen[k] = append(seen[k], id)
	}
	byID := map[string]Product{}
	for _, p := range c.Products() {
		byID[p.ID] = p
		for _, v := range p.Binaries {
			add("exe", v, p.ID)
		}
		for _, v := range p.ProcessNames {
			add("exe", v, p.ID)
		}
		for _, v := range p.BundleIDs {
			add("bundle", v, p.ID)
		}
		for _, v := range p.ExtensionIDs {
			add("ext", v, p.ID)
		}
		for _, v := range p.JetBrainsIDs {
			add("jb", v, p.ID)
		}
		for _, v := range p.ChromeIDs {
			add("chrome", v, p.ID)
		}
		for _, v := range p.DesktopIDs {
			add("desktop", v, p.ID)
		}
		for _, v := range p.Appx {
			add("appx", v, p.ID)
		}
		for _, v := range p.WinDisplay {
			add("win", v, p.ID)
		}
		for _, v := range p.Packages {
			add("pkg", packageKey(v), p.ID)
		}
		for _, l := range [][]string{p.StateDirs.Linux, p.StateDirs.Darwin, p.StateDirs.Windows} {
			for _, v := range l {
				add("state", strings.TrimRight(strings.ReplaceAll(v, `\`, "/"), "/"), p.ID)
			}
		}
	}
	shared := 0
	for k, ids := range seen {
		if len(ids) < 2 {
			continue
		}
		shared++
		for _, a := range ids {
			for _, b := range ids {
				if a != b && !lists(byID[a].Aliases, b) {
					t.Errorf("%q is claimed by %v but %s does not list %s in aliases", strings.ReplaceAll(k, "\x00", ":"), ids, a, b)
				}
			}
		}
	}
	// The data really does contain shared fingerprints (claude, ~/.codex,
	// ~/.kiro ...); if this drops to zero the test stopped testing.
	if shared < 8 {
		t.Errorf("only %d shared fingerprints found", shared)
	}
}

func TestFiveMajorsAreComplete(t *testing.T) {
	c := mustLoad(t)
	dialect := map[string]string{
		"claude-code": DialectClaude, "codex": DialectCodex, "copilot-cli": DialectCopilot,
		"gemini-cli": DialectGemini, "cursor": DialectCursor,
	}
	for id, d := range dialect {
		p, ok := c.Get(id)
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		if p.Hooks == nil || p.Hooks.Dialect != d {
			t.Errorf("%s: hooks = %+v, want dialect %s", id, p.Hooks, d)
			continue
		}
		for _, goos := range []string{"linux", "darwin", "windows"} {
			if len(p.Hooks.ManagedPaths.For(goos)) == 0 {
				t.Errorf("%s: no managed hook path for %s", id, goos)
			}
			if len(p.Hooks.UserPaths.For(goos)) == 0 {
				t.Errorf("%s: no user hook path for %s", id, goos)
			}
			if p.Transcript == nil || len(p.Transcript.Globs.For(goos)) == 0 {
				t.Errorf("%s: no transcript glob for %s", id, goos)
			}
		}
		if len(p.Hooks.ProjectPaths) == 0 || p.Hooks.Notes == "" {
			t.Errorf("%s: hooks project paths or notes missing", id)
		}
		if p.Transcript == nil || p.Transcript.Format == "" {
			t.Errorf("%s: transcript missing", id)
		}
		if len(p.MCP) == 0 {
			t.Errorf("%s: MCP config locations missing", id)
		}
		hasUser, hasProject := false, false
		for _, m := range p.MCP {
			hasUser = hasUser || m.Scope == string(event.ScopeUser)
			hasProject = hasProject || m.Scope == string(event.ScopeProject)
		}
		if !hasUser {
			t.Errorf("%s: no user-scope MCP config", id)
		}
		if id != "copilot-cli" && !hasProject {
			t.Errorf("%s: no project-scope MCP config", id)
		}
		if len(p.EnvMarkers) == 0 {
			t.Errorf("%s: env markers missing", id)
		}
		if len(p.RiskyFlags) == 0 {
			t.Errorf("%s: risky flags missing", id)
		}
		if len(p.Settings) == 0 {
			t.Errorf("%s: settings probes missing", id)
		}
	}

	// Exact values from research/agent-surfaces-a.md. These are the facts
	// the hook installer and the process monitor act on.
	cc, _ := c.Get("claude-code")
	wantEq(t, "claude managed hook (linux)", cc.Hooks.ManagedPaths.Linux, []string{"/etc/claude-code/managed-settings.d/50-spoor.json"})
	wantEq(t, "claude managed hook (darwin)", cc.Hooks.ManagedPaths.Darwin, []string{"/Library/Application Support/ClaudeCode/managed-settings.d/50-spoor.json"})
	wantEq(t, "claude managed hook (windows)", cc.Hooks.ManagedPaths.Windows, []string{`C:\Program Files\ClaudeCode\managed-settings.d\50-spoor.json`})
	wantEq(t, "claude session env", cc.SessionEnv[:1], []string{"CLAUDE_CODE_SESSION_ID"})
	wantHas(t, "claude env markers", cc.EnvMarkers, "CLAUDECODE", "CLAUDE_CODE_CHILD_SESSION")
	wantHas(t, "claude home env", cc.HomeEnv, "CLAUDE_CONFIG_DIR")
	wantHas(t, "claude risky flags", cc.RiskyFlags, "--dangerously-skip-permissions", "--permission-mode bypassPermissions", "--bare", "--no-session-persistence")
	wantEq(t, "claude transcript format", []string{cc.Transcript.Format}, []string{TranscriptClaudeJSONL})
	if cc.Signers.WindowsPublisher != "Anthropic, PBC" {
		t.Errorf("claude windows publisher = %q", cc.Signers.WindowsPublisher)
	}
	wantSetting(t, cc, "skipDangerousModePermissionPrompt", "bypass_warning_accepted")
	wantSetting(t, cc, "disableAllHooks", "hooks_disabled")
	wantSetting(t, cc, "permissions.defaultMode", "bypass_permissions_default")

	cx, _ := c.Get("codex")
	wantEq(t, "codex managed hook (linux)", cx.Hooks.ManagedPaths.Linux, []string{"/etc/codex/requirements.toml"})
	wantEq(t, "codex managed hook (windows)", cx.Hooks.ManagedPaths.Windows, []string{`%ProgramData%\OpenAI\Codex\requirements.toml`})
	wantHas(t, "codex session env", cx.SessionEnv, "CODEX_SESSION_ID", "CODEX_THREAD_ID")
	wantHas(t, "codex home env", cx.HomeEnv, "CODEX_HOME")
	wantHas(t, "codex risky flags", cx.RiskyFlags, "--dangerously-bypass-approvals-and-sandbox", "--yolo", "--sandbox danger-full-access", "--ask-for-approval never", "--dangerously-bypass-hook-trust")
	wantEq(t, "codex transcript format", []string{cx.Transcript.Format}, []string{TranscriptCodexRollout})
	wantSetting(t, cx, "approval_policy", "approvals_disabled")
	wantSetting(t, cx, "sandbox_mode", "sandbox_disabled")

	cp, _ := c.Get("copilot-cli")
	wantEq(t, "copilot managed hook (linux)", cp.Hooks.ManagedPaths.Linux, []string{"/etc/github-copilot/policy.d/spoor.json"})
	wantEq(t, "copilot managed hook (windows)", cp.Hooks.ManagedPaths.Windows, []string{`C:\ProgramData\GitHub\Copilot\policy.d\spoor.json`})
	wantEq(t, "copilot binary", cp.Binaries, []string{"copilot"}) // uber/ADR has github-copilot-cli, which is wrong
	wantHas(t, "copilot risky flags", cp.RiskyFlags, "--allow-all", "--yolo", "--allow-all-tools", "--autopilot", "--no-ask-user")
	wantEq(t, "copilot transcript format", []string{cp.Transcript.Format}, []string{TranscriptCopilotEvents})
	wantHas(t, "copilot home env", cp.HomeEnv, "COPILOT_HOME")

	gm, _ := c.Get("gemini-cli")
	wantEq(t, "gemini managed hook (linux)", gm.Hooks.ManagedPaths.Linux, []string{"/etc/gemini-cli/settings.json"})
	wantEq(t, "gemini managed hook (darwin)", gm.Hooks.ManagedPaths.Darwin, []string{"/Library/Application Support/GeminiCli/settings.json"})
	wantEq(t, "gemini managed hook (windows)", gm.Hooks.ManagedPaths.Windows, []string{`C:\ProgramData\gemini-cli\settings.json`})
	wantEq(t, "gemini env markers", gm.EnvMarkers, []string{"GEMINI_CLI"})
	wantHas(t, "gemini risky flags", gm.RiskyFlags, "--yolo", "--approval-mode yolo", "--approval-mode auto_edit")
	wantEq(t, "gemini transcript format", []string{gm.Transcript.Format}, []string{TranscriptGeminiChats})
	wantSetting(t, gm, "hooksConfig.enabled", "hooks_disabled")

	cu, _ := c.Get("cursor")
	wantEq(t, "cursor managed hook (linux)", cu.Hooks.ManagedPaths.Linux, []string{"/etc/cursor/hooks.json"})
	wantEq(t, "cursor managed hook (darwin)", cu.Hooks.ManagedPaths.Darwin, []string{"/Library/Application Support/Cursor/hooks.json"})
	wantEq(t, "cursor managed hook (windows)", cu.Hooks.ManagedPaths.Windows, []string{`C:\ProgramData\Cursor\hooks.json`})
	wantEq(t, "cursor user hook", cu.Hooks.UserPaths.Linux, []string{"~/.cursor/hooks.json"})
	wantEq(t, "cursor transcript format", []string{cu.Transcript.Format}, []string{TranscriptCursorSQLite})
	wantEq(t, "cursor bundle id", cu.BundleIDs, []string{"com.todesktop.230313mzl4w4u92"})
	// Cursor's vendor docs were unreachable: the entry must say so.
	if !cu.IsUnverified("risky_flags") || !cu.IsUnverified("settings") {
		t.Error("cursor risky_flags and settings must be marked unverified")
	}
}

func wantEq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func wantHas(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("%s = %q, missing %q", what, got, w)
		}
	}
}

func wantSetting(t *testing.T, p Product, key, flag string) {
	t.Helper()
	for _, s := range p.Settings {
		if s.Key == key && s.Flag == flag {
			return
		}
	}
	t.Errorf("%s: no setting probe %s -> %s", p.ID, key, flag)
}

// Every id in uber/ADR's catalog.json (version 2026.10.12) must resolve,
// by id or through an alias when we renamed it.
func TestCoversUberADRCatalog(t *testing.T) {
	c := mustLoad(t)
	adr := map[string]string{
		"claude-code": "claude-code", "gemini-cli": "gemini-cli", "antigravity-cli": "antigravity-cli",
		"antigravity": "antigravity", "codex-cli": "codex", "aider": "aider", "opencode": "opencode",
		"goose": "goose", "cursor": "cursor", "claude-desktop": "claude-desktop", "vscode": "vscode",
		"ollama": "ollama", "lm-studio": "lm-studio", "continue": "continue", "github-copilot": "github-copilot",
		"comet": "comet", "amp": "amp", "crush": "crush", "qwen-code": "qwen-code", "kilo-cli": "kilo-cli",
		"github-copilot-cli": "copilot-cli", "windsurf": "devin-desktop", "zed": "zed", "trae": "trae",
		"chatgpt-desktop": "chatgpt", "perplexity-desktop": "perplexity", "cline": "cline",
		"roo-code": "roo-code", "kilo-code": "kilo-code", "jetbrains-ai": "jetbrains-ai",
		"llama-cpp": "llama-cpp", "vllm": "vllm", "gpt4all": "gpt4all", "jan": "jan", "localai": "localai",
		"open-webui": "open-webui", "arc": "arc",
	}
	if len(adr) != 37 {
		t.Fatalf("test table has %d ADR ids, the catalog has 37", len(adr))
	}
	for theirs, ours := range adr {
		p, ok := c.Resolve(theirs)
		if !ok {
			t.Errorf("ADR id %q does not resolve", theirs)
			continue
		}
		if p.ID != ours {
			t.Errorf("ADR id %q resolved to %q, want %q", theirs, p.ID, ours)
		}
	}
	// Their fingerprints must find the same products (the correct ones;
	// the stale ones named in research/agent-surfaces-b.md section 2 are
	// deliberately not carried over).
	for bundle, id := range map[string]string{
		"com.todesktop.230313mzl4w4u92": "cursor", "com.anthropic.claudefordesktop": "claude-desktop",
		"com.microsoft.VSCode": "vscode", "com.exafunction.windsurf": "devin-desktop", "dev.zed.Zed": "zed",
		"com.trae.app": "trae", "ai.perplexity.comet": "comet", "company.thebrowser.Browser": "arc",
		"ai.elementlabs.lmstudio": "lm-studio", "com.google.antigravity": "antigravity",
		"com.openai.chat": "chatgpt", "com.openai.codex": "chatgpt", "ai.perplexity.macv3": "perplexity",
		"jan.ai.app": "jan",
	} {
		if p, ok := c.ByBundleID(bundle); !ok || p.ID != id {
			t.Errorf("ByBundleID(%q) = %q, want %q", bundle, p.ID, id)
		}
	}
	for ext, id := range map[string]string{
		"continue.continue": "continue", "github.copilot": "github-copilot", "github.copilot-chat": "github-copilot",
		"saoudrizwan.claude-dev": "cline", "rooveterinaryinc.roo-cline": "roo-code", "kilocode.kilo-code": "kilo-code",
		"GitHub.Copilot": "github-copilot", "ZooCodeOrganization.zoo-code": "zoo-code",
	} {
		if p, ok := c.ByExtensionID(ext); !ok || p.ID != id {
			t.Errorf("ByExtensionID(%q) = %q, want %q", ext, p.ID, id)
		}
	}
	if p, ok := c.ByJetBrainsID("com.intellij.ml.llm"); !ok || p.ID != "jetbrains-ai" {
		t.Errorf("ByJetBrainsID = %q", p.ID)
	}
	for pkg, id := range map[string]string{
		"npm:@anthropic-ai/claude-code": "claude-code", "npm:@google/gemini-cli": "gemini-cli",
		"npm:@openai/codex": "codex", "pipx:aider-chat": "aider", "uv:aider-chat": "aider",
		"npm:opencode-ai": "opencode", "npm:@qwen-code/qwen-code": "qwen-code", "npm:@kilocode/cli": "kilo-cli",
		"npm:@github/copilot": "copilot-cli", "brew:llama.cpp": "llama-cpp", "pipx:vllm": "vllm",
		"brew:localai": "localai", "pipx:open-webui": "open-webui", "brew:ollama": "ollama",
		"npm:@ampcode/cli": "amp", "npm:@sourcegraph/amp": "amp",
	} {
		mgr, name, _ := strings.Cut(pkg, ":")
		if p, ok := c.ByPackage(mgr, name); !ok || p.ID != id {
			t.Errorf("ByPackage(%q, %q) = %q, want %q", mgr, name, p.ID, id)
		}
	}
}

// research/agent-surfaces-b.md section 1: every product named there.
func TestCoversLongTailSurfaces(t *testing.T) {
	c := mustLoad(t)
	want := []string{
		// 1a terminal agents
		"antigravity-cli", "gemini-cli", "kiro-cli", "cursor-agent", "copilot-cli", "opencode", "kilo-cli",
		"cline-cli", "amp", "goose", "crush", "qwen-code", "droid", "junie", "kimi-code", "mistral-vibe",
		"grok-build", "pi", "auggie", "aider", "hermes", "openclaw", "picoclaw", "zeroclaw", "ironclaw",
		"nullclaw", "nanobot", "openhands",
		// "also fingerprint"
		"letta-code", "codebuff", "forgecode", "gptme", "llm-cli", "mini-swe-agent", "codebuddy-code",
		"iflow-cli", "neovate", "cody-cli", "jules", "continue-cli", "every-code", "claude-agent-acp",
		"codex-acp", "happy", "claude-code-router", "claude-flow", "oh-my-pi",
		// 1b IDEs, desktop apps, browsers
		"devin-desktop", "kiro", "antigravity", "antigravity-ide", "zed", "cline", "kilo-code", "zoo-code",
		"roo-code", "continue", "jetbrains-ai", "jetbrains-air", "warp", "claude-desktop", "chatgpt",
		"chatgpt-atlas", "comet", "perplexity", "dia", "microsoft-365-copilot", "copilot-for-xcode",
		"gemini-app", "raycast", "replit", "manus", "trae", "qoder", "codebuddy", "zcode", "kimi-desktop",
		"doubao", "poe", "void", "browseros", "conductor", "superset-desktop", "emdash", "sculptor",
		"t3-code", "nimbalyst", "cmux", "aionui", "opencode-desktop", "factory-desktop", "goose-desktop",
		// 1c runtimes
		"ollama", "lm-studio", "llama-cpp", "jan", "gpt4all", "localai", "mlx-lm", "osaurus", "vllm",
		"koboldcpp", "text-generation-webui", "lemonade", "docker-model-runner", "exo", "litellm",
		"open-webui", "ramalama", "foundry-local", "xinference", "sglang",
		// 1d SDKs
		"claude-agent-sdk", "openai-agents-sdk", "langgraph", "crewai", "autogen", "google-adk",
		"google-antigravity-sdk", "microsoft-agent-framework", "pydantic-ai", "strands-agents",
		"smolagents", "agno", "browser-use", "mastra", "vercel-ai-sdk", "cline-sdk", "cursor-sdk",
		"copilot-sdk", "opencode-sdk", "mcp-sdk",
	}
	for _, id := range want {
		if _, ok := c.Get(id); !ok {
			t.Errorf("product %q from the long-tail report is missing", id)
		}
	}
	// 2026 renames are recorded as aliases.
	for old, id := range map[string]string{
		"windsurf": "devin-desktop", "Windsurf": "devin-desktop", "amazon-q": "kiro-cli",
		"clawdbot": "openclaw", "moltbot": "openclaw", "codex-app": "chatgpt", "happy-coder": "happy",
		"kimi-cli": "kimi-code", "sst-opencode": "opencode", "roo-cline": "roo-code",
		"claude-code-acp": "claude-agent-acp", "sourcegraph-amp": "amp",
	} {
		if p, ok := c.Resolve(old); !ok || p.ID != id {
			t.Errorf("Resolve(%q) = %q, want %q", old, p.ID, id)
		}
	}
	// A sibling's id in aliases is a shared-fingerprint link, not a rename.
	if p, _ := c.Resolve("claude-desktop"); p.ID != "claude-desktop" {
		t.Errorf("Resolve(claude-desktop) = %q", p.ID)
	}
	for id, status := range map[string]string{"roo-code": StatusDiscontinued, "chatgpt-atlas": StatusDiscontinued, "arc": StatusDiscontinued, "msty": StatusDeprecated} {
		if p, _ := c.Get(id); p.Status != status {
			t.Errorf("%s status = %q, want %q", id, p.Status, status)
		}
	}
	// Windows identifiers exist where the research found them.
	windows := 0
	for _, p := range c.Products() {
		if len(p.WinDisplay)+len(p.Appx) > 0 || len(p.InstallPaths.Windows)+len(p.StateDirs.Windows) > 0 {
			windows++
		}
		for _, pkg := range p.Packages {
			if strings.HasPrefix(pkg, "winget:") || strings.HasPrefix(pkg, "scoop:") {
				windows++
				break
			}
		}
	}
	if windows < 40 {
		t.Errorf("only %d products carry a Windows identifier", windows)
	}
}

func TestLookups(t *testing.T) {
	c := mustLoad(t)

	ids := func(ps []Product) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.ID)
		}
		sort.Strings(out)
		return out
	}
	wantEq(t, "ByBinary(claude)", ids(c.ByBinary("claude")), []string{"claude-code", "claude-desktop"})
	wantEq(t, "ByBinary(CLAUDE.EXE)", ids(c.ByBinary("CLAUDE.EXE")), []string{"claude-code", "claude-desktop"})
	wantEq(t, "ByBinary(path)", ids(c.ByBinary(`C:\x\codex.exe`)), []string{"chatgpt", "codex"})
	wantEq(t, "ByBinary(agent)", ids(c.ByBinary("agent")), []string{"cursor-agent", "grok-build"})
	wantEq(t, "ByBinary(copilot)", ids(c.ByBinary("copilot")), []string{"copilot-cli"})
	if got := c.ByBinary("node"); got != nil {
		t.Errorf("ByBinary(node) = %v", ids(got))
	}
	if got := c.ByBinary(""); got != nil {
		t.Errorf("ByBinary(\"\") = %v", ids(got))
	}

	if p, ok := c.ByBundleID("COM.ANTHROPIC.CLAUDEFORDESKTOP"); !ok || p.ID != "claude-desktop" {
		t.Errorf("bundle ids must match case-insensitively: %q %v", p.ID, ok)
	}
	if _, ok := c.ByBundleID("com.macpaw.site.Gemini2"); ok {
		t.Error("MacPaw Gemini must not be catalogued")
	}
	if _, ok := c.ByExtensionID("esbenp.prettier-vscode"); ok {
		t.Error("Prettier is not an AI extension")
	}

	// Package managers of one ecosystem are interchangeable, names are
	// normalized, and squats do not resolve.
	for _, tc := range []struct{ mgr, name, want string }{
		{"npm", "@anthropic-ai/claude-code", "claude-code"},
		{"pnpm", "@anthropic-ai/claude-code", "claude-code"},
		{"pip", "aider-chat", "aider"},
		{"pipx", "Aider_Chat", "aider"},
		{"uv", "aider.chat", "aider"},
		{"cask", "claude-code", "claude-code"},
		{"cask", "claude", "claude-desktop"}, // uber/ADR lists brew:claude for the CLI
		{"winget", "Anthropic.ClaudeCode", "claude-code"},
		{"winget", "GitHub.Copilot", "copilot-cli"},
		{"scoop", "goose", "goose-desktop"},
		{"brew", "block-goose-cli", "goose"},
		{"brew", "charmbracelet/tap/crush", "crush"},
		{"gha", "anthropics/claude-code-action", "claude-code-action"},
		{"docker", "ghcr.io/openhands/agent-canvas", "openhands"},
		{"dnf", "claude-code", "claude-code"},
	} {
		if p, ok := c.ByPackage(tc.mgr, tc.name); !ok || p.ID != tc.want {
			t.Errorf("ByPackage(%q, %q) = %q, want %q", tc.mgr, tc.name, p.ID, tc.want)
		}
	}
	for _, tc := range []struct{ mgr, name string }{
		{"brew", "goose"},                  // pressly/goose, a migration tool
		{"brew", "amp"},                    // a text editor
		{"npm", "kiro-cli"},                // a squat
		{"npm", "antigravity-cli"},         // a squat
		{"npm", "@google/antigravity-cli"}, // does not exist
		{"npm", "openhands"},               // holding package
		{"pip", "exo"},                     // genomics tool
		{"pip", "localai"},                 // unrelated project
		{"brew", "claude"},                 // no such formula; the cask is Desktop
		{"", ""}, {"npm", ""}, {"nosuch", "claude-code"},
	} {
		if p, ok := c.ByPackage(tc.mgr, tc.name); ok {
			t.Errorf("ByPackage(%q, %q) = %q, want no match", tc.mgr, tc.name, p.ID)
		}
	}

	for _, tc := range []struct{ in, want string }{
		{"Cursor", "cursor"}, {"Cursor (User)", "cursor"}, {"cursor 1.2.3", "cursor"},
		{"Kiro (User)", "kiro"}, {"Claude", "claude-desktop"}, {"Zed", "zed"},
		{"Microsoft Visual Studio Code (User)", "vscode"},
		{"Microsoft Visual Studio Code Insiders", "vscode-insiders"},
		{"Antigravity IDE", "antigravity-ide"}, {"Windsurf", "devin-desktop"},
		{"Ollama version 0.12.3", "ollama"}, {"Arc", "arc"}, {"Comet", "comet"},
		{"  Granola  ", "granola"}, {"Chatbox", "chatbox"},
	} {
		if p, ok := c.ByWinDisplay(tc.in); !ok || p.ID != tc.want {
			t.Errorf("ByWinDisplay(%q) = %q, want %q", tc.in, p.ID, tc.want)
		}
	}
	for _, in := range []string{
		"NVIDIA Control Panel", "CursorSense", "Mouse Cursor Highlighter", "Arc Welder Pro",
		"ArcGIS Pro", "Comet Backup", "Zedboard Tools", "Claude Monet Screensaver", "Trader Workstation",
		"", strings.Repeat("Cursor", 10000),
	} {
		if p, ok := c.ByWinDisplay(in); ok {
			t.Errorf("ByWinDisplay(%.40q) = %q, want no match", in, p.ID)
		}
	}

	if p, ok := c.ByChromeID("ofpnmcalabcbjgholdjcjblkibolbppb"); !ok || p.ID != "monica" {
		t.Errorf("ByChromeID = %q", p.ID)
	}
	if p, ok := c.ByDesktopID("dev.zed.Zed.desktop"); !ok || p.ID != "zed" {
		t.Errorf("ByDesktopID = %q", p.ID)
	}
	for _, in := range []string{"Microsoft.Copilot", "Microsoft.Copilot_8wekyb3d8bbwe", "Microsoft.Copilot_1.25.3.0_x64__8wekyb3d8bbwe"} {
		if p, ok := c.ByAppx(in); !ok || p.ID != "microsoft-copilot" {
			t.Errorf("ByAppx(%q) = %q", in, p.ID)
		}
	}
	for _, in := range []string{"Claude_pzs8sxrjxfjjc", "Claude_1.0.0.0_x64__pzs8sxrjxfjjc"} {
		if p, ok := c.ByAppx(in); !ok || p.ID != "claude-desktop" {
			t.Errorf("ByAppx(%q) = %q", in, p.ID)
		}
	}
	if _, ok := c.ByAppx("Microsoft.WindowsCalculator_8wekyb3d8bbwe"); ok {
		t.Error("ByAppx matched the calculator")
	}

	wantEq(t, "ByPort(11434)", ids(c.ByPort(11434)), []string{"ollama"})
	wantEq(t, "ByPort(9931)", ids(c.ByPort(9931)), []string{"llama-cpp"})
	if len(c.ByPort(8080)) < 3 {
		t.Error("8080 is shared by several runtimes; ByPort must return all of them")
	}
	if c.ByPort(22) != nil || c.ByPort(-1) != nil {
		t.Error("ByPort matched a port nobody declares")
	}
	// Ports the research says uber/ADR misses.
	for _, port := range []int{9931, 1337, 4891, 5001, 13305, 12434, 52415, 4000} {
		if len(c.ByPort(port)) == 0 {
			t.Errorf("no runtime declares port %d", port)
		}
	}

	wantEq(t, "ByEnvMarker(CLAUDECODE)", ids(c.ByEnvMarker("CLAUDECODE")), []string{"claude-code"})
	wantEq(t, "ByEnvMarker(CLAUDE_CODE_SESSION_ID)", ids(c.ByEnvMarker("CLAUDE_CODE_SESSION_ID")), []string{"claude-code"})
	wantEq(t, "ByEnvMarker(CODEX_THREAD_ID)", ids(c.ByEnvMarker("CODEX_THREAD_ID")), []string{"codex"})
	wantEq(t, "ByEnvMarker(GEMINI_CLI)", ids(c.ByEnvMarker("GEMINI_CLI")), []string{"gemini-cli"})
	if c.ByEnvMarker("PATH") != nil || c.ByEnvMarker("CLAUDE_PROJECT_DIR") != nil {
		t.Error("PATH and CLAUDE_PROJECT_DIR are not agent markers")
	}

	wantHas(t, "ByAPIHost(api.anthropic.com)", ids(c.ByAPIHost("api.anthropic.com")), "claude-code", "claude-desktop")
	wantEq(t, "ByAPIHost wildcard", ids(c.ByAPIHost("d1.api.augmentcode.com.")), []string{"auggie"})
	if c.ByAPIHost("example.com") != nil || c.ByAPIHost("") != nil {
		t.Error("ByAPIHost matched an unknown host")
	}
}

func TestReturnedProductsAreCopies(t *testing.T) {
	c := mustLoad(t)
	p, _ := c.Get("claude-code")
	p.Binaries[0] = "evil"
	p.Hooks.Dialect = "evil"
	p.Hooks.ManagedPaths.Linux[0] = "/tmp/evil"
	p.Transcript.Globs.Linux[0] = "/tmp/evil"
	p.MCP[0].Paths.Linux[0] = "/tmp/evil"
	p.Settings[0].File.Linux[0] = "/tmp/evil"
	p.Settings[0].Flag = "evil"
	p.SessionEnv = append(p.SessionEnv[:0], "EVIL")
	all := c.Products()
	all[0].ID = "evil"

	q, _ := c.Get("claude-code")
	b, _ := json.Marshal(q)
	if strings.Contains(string(b), "evil") || strings.Contains(string(b), "EVIL") {
		t.Fatalf("mutating a returned product changed the catalog: %s", b)
	}
	if c.Products()[0].ID == "evil" {
		t.Fatal("mutating Products() changed the catalog")
	}
	if _, ok := c.MatchProcess("evil", "", nil); ok {
		t.Fatal("mutated binary name is matchable")
	}
}

func TestProductJSONIsStable(t *testing.T) {
	c := mustLoad(t)
	p, _ := c.Get("codex")
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "name", "kind", "binaries", "packages", "state_dirs", "home_env", "session_env", "mcp", "transcript", "hooks", "risky_flags", "settings"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON of a product lacks %q: %s", k, b)
		}
	}
	// Empty structs must not appear as noise.
	q, _ := c.Get("langgraph")
	b, _ = json.Marshal(q)
	for _, k := range []string{`"signers"`, `"install_paths"`, `"state_dirs"`, `"hooks"`} {
		if strings.Contains(string(b), k) {
			t.Errorf("empty %s serialized: %s", k, b)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	c := mustLoad(t)
	dir := t.TempDir()
	writeFile(t, dir, "x.yaml", "products:\n  - {id: acme-agent, name: Acme, vendor: Acme, kind: agent, binaries: [acme-agent]}\n")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.MatchProcess("claude", "/home/u/.local/bin/claude", []string{"claude"})
				c.ByBinary("codex")
				c.Products()
				c.Version()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			if err := c.LoadOverlay(dir); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
}

func TestVocabularyHelpers(t *testing.T) {
	mgrs := PackageManagers()
	for _, m := range []string{"npm", "pip", "pipx", "uv", "brew", "cask", "winget", "scoop", "choco", "cargo", "go", "apt", "snap", "flatpak"} {
		if !contains(mgrs, m) {
			t.Errorf("PackageManagers() lacks %q from the spec", m)
		}
	}
	caps := Capabilities()
	for _, m := range []string{"executes_shell", "edits_files", "browses", "local_inference", "mcp_client"} {
		if !contains(caps, m) {
			t.Errorf("Capabilities() lacks %q from the spec", m)
		}
	}
	if !sort.StringsAreSorted(mgrs) || !sort.StringsAreSorted(caps) {
		t.Error("vocabulary helpers must return sorted lists")
	}
	p := Product{Unverified: []string{"signers.darwin_team_id", "ports"}}
	if !p.IsUnverified("signers.darwin_team_id") || !p.IsUnverified("ports") || p.IsUnverified("signers") || p.IsUnverified("signers.windows_publisher") || p.IsUnverified("port") {
		t.Error("IsUnverified is wrong")
	}
	p = Product{Unverified: []string{"signers"}}
	if !p.IsUnverified("signers.darwin_team_id") {
		t.Error("a parent field covers its children")
	}
	p = Product{EnvMarkers: []string{"A"}, SessionEnv: []string{"B"}}
	wantEq(t, "MarkerEnv", p.MarkerEnv(), []string{"A", "B"})

	o := OSPaths{Linux: []string{"l"}, Darwin: []string{"d"}, Windows: []string{"w"}}
	wantEq(t, "For(linux)", o.For("linux"), []string{"l"})
	wantEq(t, "For(darwin)", o.For("darwin"), []string{"d"})
	wantEq(t, "For(windows)", o.For("windows"), []string{"w"})
	wantEq(t, "For(freebsd)", o.For("freebsd"), []string{"l"})
	if len(o.For("")) != 1 {
		t.Error("For(\"\") must use the running OS")
	}
	if !(OSPaths{}).IsZero() || o.IsZero() {
		t.Error("IsZero is wrong")
	}
}

// The exported API named in the build spec, pinned at compile time so a
// refactor cannot drift from what the other packages were written against.
var (
	_ func() (*Catalog, error)                                 = Load
	_ func(*Catalog) string                                    = (*Catalog).Version
	_ func(*Catalog) []Product                                 = (*Catalog).Products
	_ func(*Catalog, string) (Product, bool)                   = (*Catalog).Get
	_ func(*Catalog, string) []Product                         = (*Catalog).ByBinary
	_ func(*Catalog, string) (Product, bool)                   = (*Catalog).ByBundleID
	_ func(*Catalog, string) (Product, bool)                   = (*Catalog).ByExtensionID
	_ func(*Catalog, string, string) (Product, bool)           = (*Catalog).ByPackage
	_ func(*Catalog, string, string, []string) (Product, bool) = (*Catalog).MatchProcess
	_ func(*Catalog, string) error                             = (*Catalog).LoadOverlay
	_ func(string, string, map[string]string, string) string   = Expand
	_                                                          = OSPaths{Linux: nil, Darwin: nil, Windows: nil}
	_                                                          = MCPConfig{Paths: OSPaths{}, ProjectPaths: nil, Format: "", Scope: ""}
	_                                                          = Transcript{Format: "", Globs: OSPaths{}, HomeEnv: ""}
	_                                                          = Hooks{Dialect: "", ManagedPaths: OSPaths{}, UserPaths: OSPaths{}, ProjectPaths: nil, Notes: ""}
	_                                                          = Setting{File: OSPaths{}, Format: "", Key: "", Op: "", Value: "", Flag: "", Severity: ""}
)

func TestProductHasEverySpecField(t *testing.T) {
	want := map[string]string{
		"ID": "string", "Name": "string", "Vendor": "string", "Kind": "string",
		"Aliases": "[]string", "Binaries": "[]string", "ProcessNames": "[]string", "ProcessArgs": "[]string",
		"Packages": "[]string", "BundleIDs": "[]string", "WinDisplay": "[]string", "Appx": "[]string",
		"DesktopIDs": "[]string", "ExtensionIDs": "[]string", "JetBrainsIDs": "[]string", "ChromeIDs": "[]string",
		"InstallPaths": "catalog.OSPaths", "StateDirs": "catalog.OSPaths", "HomeEnv": "[]string",
		"EnvMarkers": "[]string", "SessionEnv": "[]string", "MCP": "[]catalog.MCPConfig",
		"Skills": "[]string", "Rules": "[]string", "Plugins": "[]string", "Subagents": "[]string", "Commands": "[]string",
		"Transcript": "*catalog.Transcript", "Hooks": "*catalog.Hooks", "RiskyFlags": "[]string",
		"Settings": "[]catalog.Setting", "Ports": "[]int", "APIHosts": "[]string",
		"Capabilities": "[]string", "Sources": "[]string", "Unverified": "[]string",
	}
	typ := reflect.TypeOf(Product{})
	for name, ty := range want {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("Product lacks field %s", name)
			continue
		}
		if f.Type.String() != ty {
			t.Errorf("Product.%s is %s, want %s", name, f.Type, ty)
		}
	}
	var p Product
	p.Signers.DarwinTeamID, p.Signers.WindowsPublisher = "ABCDE12345", "Example, Inc."
	// Every field must have a YAML key, and the keys must be unique.
	keys := yamlFields(typ)
	if len(keys) != typ.NumField() {
		t.Errorf("%d YAML keys for %d fields", len(keys), typ.NumField())
	}
	for k := range productFields {
		if _, ok := keys[k]; !ok {
			t.Errorf("productFields lists %q, which is not a YAML key of Product", k)
		}
	}
}

func TestZeroCatalogIsEmptyNotFatal(t *testing.T) {
	var c Catalog
	if c.Len() != 0 || c.Version() != "" || len(c.Products()) != 0 {
		t.Error("zero catalog is not empty")
	}
	if _, ok := c.Get("claude-code"); ok {
		t.Error("zero catalog returned a product")
	}
	if _, ok := c.MatchProcess("claude", "/usr/bin/claude", []string{"claude"}); ok {
		t.Error("zero catalog matched a process")
	}
	if c.ByBinary("claude") != nil || c.ByPort(11434) != nil || c.IsAmbiguousName("claude") {
		t.Error("zero catalog lookups returned data")
	}
	if _, ok := c.ByWinDisplay("Claude"); ok {
		t.Error("zero catalog matched a display name")
	}
	var np *Catalog
	if _, ok := np.Get("x"); ok || np.Len() != 0 {
		t.Error("nil catalog returned data")
	}
	if err := np.LoadOverlay(t.TempDir()); err == nil {
		t.Error("LoadOverlay on a nil catalog must fail")
	}
	// A zero catalog can still be populated from an overlay directory.
	dir := t.TempDir()
	writeFile(t, dir, "x.yaml", "version: \"2026.01.01\"\nproducts:\n  - {id: acme, name: Acme, vendor: A, kind: agent, binaries: [acme]}\n")
	if err := c.LoadOverlay(dir); err == nil {
		// The overlay version key is ignored, so a catalog built only from
		// overlays has no version and is rejected; that is the documented
		// behaviour, not an accident.
		t.Error("an overlay-only catalog has no base version and must be rejected")
	}
}

// Facts that came from memory or from a third party's table must say so.
// The allowlists below are the values that were read from a primary source;
// adding to them is a claim that you checked.
func TestUnverifiedMarkersAreHonest(t *testing.T) {
	c := mustLoad(t)
	verifiedTeamID := map[string]bool{
		// The cask zaps VEKTX9H2N7.group.com.github.CopilotForXcode.prefs.plist.
		"copilot-for-xcode": true,
	}
	verifiedPublisher := map[string]bool{
		// code.claude.com/docs/en/setup.md: signed by "Anthropic, PBC".
		"claude-code": true,
	}
	marked, total := 0, 0
	for _, p := range c.Products() {
		total++
		if len(p.Unverified) > 0 {
			marked++
		}
		if p.Signers.DarwinTeamID != "" && !verifiedTeamID[p.ID] && !p.IsUnverified("signers.darwin_team_id") {
			t.Errorf("%s: team id %s is not marked unverified", p.ID, p.Signers.DarwinTeamID)
		}
		if p.Signers.WindowsPublisher != "" && !verifiedPublisher[p.ID] && !p.IsUnverified("signers.windows_publisher") {
			t.Errorf("%s: windows publisher %q is not marked unverified", p.ID, p.Signers.WindowsPublisher)
		}
		// No Chrome Web Store id was fetched from the store.
		if len(p.ChromeIDs) > 0 && !p.IsUnverified("chrome_ids") {
			t.Errorf("%s: chrome ids are not marked unverified", p.ID)
		}
		// Cursor's vendor documentation was unreachable.
		if p.Vendor == "Anysphere" && p.Kind != "ci_agent" && len(p.RiskyFlags) > 0 && !p.IsUnverified("risky_flags") {
			t.Errorf("%s: Cursor flags are not marked unverified", p.ID)
		}
	}
	if marked == 0 || marked == total {
		t.Errorf("%d of %d products carry an unverified marker; neither none nor all is believable", marked, total)
	}
}

func TestLookupsAreBoundedOnHostileInput(t *testing.T) {
	c := mustLoad(t)
	huge := strings.Repeat("a.", 2<<20)
	start := time.Now()
	c.ByAPIHost(huge)
	c.ByBundleID(huge)
	c.ByExtensionID(huge)
	c.ByJetBrainsID(huge)
	c.ByChromeID(huge)
	c.ByDesktopID(huge)
	c.ByAppx(strings.Repeat("a_", 2<<20))
	c.ByPackage(huge, huge)
	c.ByPackage("npm", huge)
	c.ByBinary(huge)
	c.ByWinDisplay(huge)
	c.ByEnvMarker(huge)
	c.Resolve(huge)
	c.Get(huge)
	c.IsAmbiguousName(huge)
	MatchGlob(huge, huge, "linux")
	Expand(huge, huge, map[string]string{huge: huge}, "windows")
	Unexpanded(huge, "windows")
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("lookups on 4 MiB inputs took %v", d)
	}
	for _, in := range []string{"\xff\xfe", "a\x00b", "", " ", "../../etc/passwd", "claude\ncode"} {
		c.ByAPIHost(in)
		c.ByBundleID(in)
		c.ByPackage(in, in)
		c.ByBinary(in)
		c.ByWinDisplay(in)
		c.ByAppx(in)
		c.Resolve(in)
	}
}
