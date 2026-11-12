package catalog

import (
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Transcript formats that have (or are planned to have) a reader in
// internal/transcript. Other formats are legal in the data: they tell the
// scanner where a log lives even when spoor cannot parse it yet.
const (
	TranscriptClaudeJSONL    = "claude-jsonl"
	TranscriptCodexRollout   = "codex-rollout"
	TranscriptCopilotEvents  = "copilot-events"
	TranscriptGeminiChats    = "gemini-chats"
	TranscriptCursorSQLite   = "cursor-sqlite"
	TranscriptOpenCodeSQLite = "opencode-sqlite"
	TranscriptClineJSON      = "cline-json"
)

// Hook dialects, mirroring internal/hookio.
const (
	DialectClaude  = "claude"
	DialectCodex   = "codex"
	DialectCopilot = "copilot"
	DialectGemini  = "gemini"
	DialectCursor  = "cursor"
)

// Product status values.
const (
	StatusActive       = "active"
	StatusDeprecated   = "deprecated"
	StatusDiscontinued = "discontinued"
)

// productKinds are the event.AssetKind values a catalog entry may have.
// Declared items (MCP servers, skills, hooks) are discovered, not catalogued.
var productKinds = map[string]bool{
	string(event.AssetAgent):            true,
	string(event.AssetApp):              true,
	string(event.AssetIDEExtension):     true,
	string(event.AssetBrowser):          true,
	string(event.AssetBrowserExtension): true,
	string(event.AssetModelRuntime):     true,
	string(event.AssetCIAgent):          true,
}

// kindRank breaks ties when two products match a process equally well: the
// agent that executes commands is the more useful identity for a responder.
var kindRank = map[string]int{
	string(event.AssetAgent):            0,
	string(event.AssetApp):              1,
	string(event.AssetBrowser):          2,
	string(event.AssetModelRuntime):     3,
	string(event.AssetIDEExtension):     4,
	string(event.AssetBrowserExtension): 5,
	string(event.AssetCIAgent):          6,
}

// managerCanon maps every accepted package manager to the ecosystem it
// installs from. A package found in a pipx venv and one found in a uv tool
// directory are the same PyPI project, so lookups compare ecosystems.
var managerCanon = map[string]string{
	"npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
	"pip": "pypi", "pipx": "pypi", "uv": "pypi", "pypi": "pypi",
	"brew":    "brew",
	"cask":    "cask",
	"winget":  "winget",
	"scoop":   "scoop",
	"choco":   "choco",
	"cargo":   "cargo",
	"go":      "go",
	"apt":     "apt",
	"deb":     "apt",
	"dpkg":    "apt",
	"rpm":     "rpm",
	"dnf":     "rpm",
	"yum":     "rpm",
	"apk":     "apk",
	"pacman":  "pacman",
	"aur":     "pacman",
	"nix":     "nix",
	"snap":    "snap",
	"flatpak": "flatpak",
	"oci":     "oci",
	"docker":  "oci",
	// gha is a GitHub Actions "uses:" reference (owner/repo), which is how a
	// CI agent is installed.
	"gha": "gha",
}

// PackageManagers lists every manager prefix accepted in Product.Packages,
// sorted.
func PackageManagers() []string {
	out := make([]string, 0, len(managerCanon))
	for m := range managerCanon {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// capabilities is the closed vocabulary for Product.Capabilities.
var capabilities = map[string]bool{
	"executes_shell":     true, // runs commands on the host
	"edits_files":        true,
	"browses":            true, // drives or is a web browser
	"local_inference":    true, // serves or runs models locally
	"mcp_client":         true, // connects to MCP servers
	"computer_use":       true, // controls mouse, keyboard or screen
	"orchestrates":       true, // launches other catalogued agents
	"sdk":                true, // a library embedded in other programs
	"model_gateway":      true, // proxies model API traffic
	"remote_control":     true, // accepts instructions from a network channel
	"captures_av":        true, // records microphone or screen
	"cloud_execution":    true, // work runs off the endpoint
	"persistent_service": true, // installs a daemon or login item
}

// Capabilities lists the closed capability vocabulary, sorted.
func Capabilities() []string {
	out := make([]string, 0, len(capabilities))
	for c := range capabilities {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

var hookDialects = map[string]bool{
	"": true, DialectClaude: true, DialectCodex: true, DialectCopilot: true,
	DialectGemini: true, DialectCursor: true,
}

// mcpFormats mirrors internal/mcpconf.Format. The catalog cannot import
// mcpconf (both are leaves), so the names are repeated here and a test in
// the integrating package should keep them in step.
var mcpFormats = map[string]bool{
	"":              true, // sniff by content
	"mcpServers":    true,
	"claude.json":   true,
	"vscode":        true,
	"zed":           true,
	"codex.toml":    true,
	"opencode":      true,
	"continue.yaml": true,
	"goose.yaml":    true,
}

var scopes = map[string]bool{
	string(event.ScopeManaged): true,
	string(event.ScopeSystem):  true,
	string(event.ScopeUser):    true,
	string(event.ScopeProject): true,
	string(event.ScopePlugin):  true,
}

var settingFormats = map[string]bool{
	"json": true, "jsonc": true, "toml": true, "yaml": true,
	"env": true, "plist": true, "registry": true,
}

var settingOps = map[string]bool{
	"eq": true, "ne": true, "exists": true, "contains": true, "in": true,
}

var statuses = map[string]bool{
	"": true, StatusActive: true, StatusDeprecated: true, StatusDiscontinued: true,
}

// productFields are the YAML field names Product.Unverified may reference,
// so a typo there is caught instead of silently vouching for a value.
var productFields = map[string]bool{
	"name": true, "vendor": true, "kind": true, "status": true, "aliases": true,
	"binaries": true, "process_names": true, "process_args": true, "packages": true,
	"bundle_ids": true, "win_display": true, "appx": true, "desktop_ids": true,
	"extension_ids": true, "jetbrains_ids": true, "chrome_ids": true,
	"install_paths": true, "state_dirs": true, "home_env": true, "env_markers": true,
	"session_env": true, "mcp": true, "skills": true, "rules": true, "plugins": true,
	"subagents": true, "commands": true, "transcript": true, "hooks": true,
	"risky_flags": true, "settings": true, "ports": true, "api_hosts": true,
	"signers": true, "capabilities": true,
}

// genericNames can never identify a product: they are interpreters, shells
// and placeholder names that thousands of unrelated programs use. uber/ADR's
// catalog lists "server" for llama.cpp, which matches every Python dev
// server on the machine.
var genericNames = map[string]bool{
	"node": true, "nodejs": true, "bun": true, "deno": true, "python": true,
	"python3": true, "java": true, "ruby": true, "perl": true, "php": true,
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true,
	"cmd": true, "powershell": true, "pwsh": true, "conhost": true,
	"server": true, "main": true, "app": true, "electron": true, "helper": true,
	"run": true, "start": true, "cli": true, "index": true, "docker": true,
	"npx": true, "npm": true, "uv": true, "uvx": true, "pipx": true, "pip": true,
}

// builtinInterpreters are host processes whose first script argument, not
// their own name, says what is running. The map value is the package
// ecosystem a script launched by that interpreter belongs to.
var builtinInterpreters = map[string]string{
	"node": "npm", "nodejs": "npm", "bun": "npm", "deno": "npm", "tsx": "npm",
	"ts-node": "npm", "electron": "npm",
	"python": "pypi", "python2": "pypi", "python3": "pypi", "pythonw": "pypi",
	"py": "pypi", "pypy": "pypi", "pypy3": "pypi",
}

// launchers run a package by name: the first non-flag argument after the
// subcommand is a package spec. The value is {ecosystem, subcommand words
// that must precede the spec}.
type launcher struct {
	eco string
	sub []string
}

var launchers = map[string][]launcher{
	"npx":    {{eco: "npm"}},
	"bunx":   {{eco: "npm"}},
	"pnpx":   {{eco: "npm"}},
	"pnpm":   {{eco: "npm", sub: []string{"dlx"}}},
	"yarn":   {{eco: "npm", sub: []string{"dlx"}}},
	"npm":    {{eco: "npm", sub: []string{"exec"}}},
	"bun":    {{eco: "npm", sub: []string{"x"}}},
	"uvx":    {{eco: "pypi"}},
	"uv":     {{eco: "pypi", sub: []string{"tool", "run"}}, {eco: "pypi", sub: []string{"run"}}},
	"pipx":   {{eco: "pypi", sub: []string{"run"}}},
	"docker": {{eco: "oci", sub: []string{"run"}}},
	"podman": {{eco: "oci", sub: []string{"run"}}},
}

// interpreterEco returns the ecosystem for an interpreter process name
// (already lowercased, extension stripped). Versioned Python names such as
// python3.12 are recognised by prefix.
func interpreterEco(name string, extra map[string]string) (string, bool) {
	if eco, ok := builtinInterpreters[name]; ok {
		return eco, true
	}
	if eco, ok := extra[name]; ok {
		return eco, true
	}
	if strings.HasPrefix(name, "python") && isVersionSuffix(name[len("python"):]) {
		return "pypi", true
	}
	return "", false
}

func isVersionSuffix(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9') && s[i] != '.' {
			return false
		}
	}
	return true
}
