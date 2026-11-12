package procmon

import (
	"path"
	"strings"
)

// LifecycleParent values.
const (
	LifecycleNPM           = "npm"
	LifecycleYarn          = "yarn"
	LifecyclePNPM          = "pnpm"
	LifecycleBun           = "bun"
	LifecyclePip           = "pip"
	LifecycleSetupPy       = "setup.py"
	LifecycleExtensionHost = "extension_host"
	LifecycleURLHandler    = "url_handler"
)

// ancestor is one process above an agent root, read fresh when the root is
// found (the table keeps only names for ordinary processes).
type ancestor struct {
	pid  int
	name string
	exe  string
	args []string
}

// lifecycleParent says what launched an agent when that launcher is the
// kind of parent rule R01 (research/threats.md) cares about: a package
// manager running a lifecycle or package script, a Python package install,
// an editor extension host, or a URL/protocol handler. The agent's own
// environment is checked first because it is explicit: npm, yarn, pnpm and
// bun all export npm_lifecycle_event to the scripts they run, and every
// process below inherits it. Ancestors are checked nearest first.
func lifecycleParent(env map[string]string, ancestors []ancestor) string {
	if ev := strings.TrimSpace(env["npm_lifecycle_event"]); ev != "" {
		return managerFromEnv(env)
	}
	for _, a := range ancestors {
		if v := lifecycleOf(a); v != "" {
			return v
		}
	}
	return ""
}

// managerFromEnv names the package manager that exported npm_lifecycle_event:
// npm_config_user_agent starts with "<manager>/<version>" for all four.
func managerFromEnv(env map[string]string) string {
	ua := strings.ToLower(strings.TrimSpace(env["npm_config_user_agent"]))
	for _, m := range []string{LifecycleYarn, LifecyclePNPM, LifecycleBun, LifecycleNPM} {
		if strings.HasPrefix(ua, m+"/") {
			return m
		}
	}
	exec := strings.ToLower(baseAny(env["npm_execpath"]))
	switch {
	case strings.Contains(exec, "yarn"):
		return LifecycleYarn
	case strings.Contains(exec, "pnpm"):
		return LifecyclePNPM
	case strings.Contains(exec, "bun"):
		return LifecycleBun
	}
	return LifecycleNPM
}

// Package-manager subcommands that only launch a package (npx-style) are
// not lifecycle parents: a person running "npx @openai/codex" chose to run
// the agent.
var runnerSubcommands = map[string]bool{"exec": true, "x": true, "dlx": true, "create": true, "init": true}

// bun runs arbitrary scripts directly, so only its install-type subcommands
// count when the environment marker is missing.
var bunInstall = map[string]bool{"install": true, "i": true, "add": true, "a": true, "update": true, "pm": true}

func lifecycleOf(a ancestor) string {
	args := a.args
	// Node programs (npm, yarn, pnpm) set process.title, which rewrites
	// argv[0] into one space-separated string ("npm install foo") and the
	// kernel name with it.
	if len(args) > 0 && strings.Contains(args[0], " ") && len(args[0]) <= 4096 {
		f := strings.Fields(args[0])
		if len(f) > 64 {
			f = f[:64]
		}
		args = append(f, args[1:]...)
	}
	name := a.name
	if i := strings.IndexByte(name, ' '); i > 0 {
		name = name[:i]
	}
	name = normName(name)
	exe := normName(baseAny(a.exe))
	// node running a package manager's JavaScript entry point.
	if isNode(name) || isNode(exe) {
		if script, rest := scriptArg(args); script != "" {
			switch s := normName(baseAny(script)); {
			case s == "npm-cli.js" || s == "npx-cli.js":
				return pmVerdict(LifecycleNPM, rest)
			case s == "yarn.js" || s == "yarn.cjs" || strings.HasPrefix(s, "yarn-"):
				return pmVerdict(LifecycleYarn, rest)
			case s == "pnpm.cjs" || s == "pnpm.js" || s == "pnpm.mjs":
				return pmVerdict(LifecyclePNPM, rest)
			}
		}
	}
	for _, n := range []string{name, exe} {
		switch n {
		case "npm":
			return pmVerdict(LifecycleNPM, tail(args))
		case "yarn", "yarnpkg":
			return pmVerdict(LifecycleYarn, tail(args))
		case "pnpm":
			return pmVerdict(LifecyclePNPM, tail(args))
		case "bun":
			if bunInstall[firstWord(tail(args))] {
				return LifecycleBun
			}
		case "pip", "pip3":
			return LifecyclePip
		}
		if strings.HasPrefix(n, "pip3.") {
			return LifecyclePip
		}
	}
	// python -m pip ..., python setup.py ...
	if isPython(name) || isPython(exe) {
		rest := tail(args)
		for i, x := range rest {
			if x == "-m" && i+1 < len(rest) {
				if rest[i+1] == "pip" || rest[i+1] == "pip3" {
					return LifecyclePip
				}
				break
			}
			if strings.HasPrefix(x, "-") {
				continue
			}
			if normName(baseAny(x)) == "setup.py" {
				return LifecycleSetupPy
			}
			break
		}
	}
	if isExtensionHost(a.name, args) {
		return LifecycleExtensionHost
	}
	if isURLHandler(name, exe, args) {
		return LifecycleURLHandler
	}
	return ""
}

func pmVerdict(manager string, rest []string) string {
	if runnerSubcommands[firstWord(rest)] {
		return ""
	}
	return manager
}

// isExtensionHost recognises the VS Code family extension host. The process
// carries --type=extensionHost (older Electron layouts) or runs as the
// node.mojom.NodeService utility process; on macOS the helper is named
// "<App> Helper (Plugin)". UNVERIFIED: these spellings are from memory of
// VS Code's process model, not from a primary source read for this package.
func isExtensionHost(name string, args []string) bool {
	if strings.HasSuffix(strings.ToLower(name), "helper (plugin)") {
		return true
	}
	if len(args) > 64 {
		args = args[:64]
	}
	for _, a := range args {
		if a == "--type=extensionHost" || strings.HasPrefix(a, "--utility-sub-type=node.mojom.NodeService") {
			return true
		}
	}
	return false
}

// urlHandlerNames are programs that open URLs and protocol links on behalf
// of a browser or the desktop. UNVERIFIED: the chain through which a
// browser hands a custom-scheme link to a registered agent handler differs
// by desktop environment; these are the usual openers and browsers.
var urlHandlerNames = map[string]bool{
	"xdg-open": true, "gio": true, "gvfs-open": true, "kde-open": true, "kde-open5": true, "kioclient5": true,
	"gnome-open": true, "exo-open": true,
	"firefox": true, "firefox-bin": true, "chrome": true, "chromium": true, "chromium-browser": true,
	"google-chrome": true, "msedge": true, "brave": true, "opera": true, "vivaldi": true, "safari": true,
}

func isURLHandler(name, exe string, args []string) bool {
	if urlHandlerNames[name] || urlHandlerNames[exe] {
		return true
	}
	// Windows: rundll32 url.dll,FileProtocolHandler <url>.
	if name == "rundll32" || exe == "rundll32" {
		for _, a := range tail(args) {
			if strings.Contains(strings.ToLower(a), "url.dll") {
				return true
			}
		}
	}
	return false
}

// normName lowercases a process name and drops a Windows ".exe".
func normName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".exe")
}

// baseAny is the last element of a path with either separator.
func baseAny(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if p == "" {
		return ""
	}
	return path.Base(p)
}

func isNode(n string) bool { return n == "node" || n == "nodejs" }

func isPython(n string) bool {
	if n == "python" || n == "python2" || n == "python3" {
		return true
	}
	return strings.HasPrefix(n, "python3.") || strings.HasPrefix(n, "python2.")
}

// scriptArg returns the script an interpreter runs (the first argument after
// argv[0] that is not a flag) and the arguments after it.
func scriptArg(args []string) (string, []string) {
	rest := tail(args)
	for i, a := range rest {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, rest[i+1:]
	}
	return "", nil
}

func tail(args []string) []string {
	if len(args) <= 1 {
		return nil
	}
	return args[1:]
}

// firstWord returns the first argument that is not a flag.
func firstWord(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}
