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
	// utilityType is the VS Code utility-process type ("extensionHost",
	// "ptyHost", ...) of an Electron utility process, read from its
	// environment; "" for every other process.
	utilityType string
}

// VS Code (and its forks) start every utility process with
// VSCODE_CRASH_REPORTER_PROCESS_TYPE=<type> in its environment, and nothing
// on the way removes it, so an agent an extension spawns inherits
// "extensionHost". The command line cannot tell the extension host from the
// terminal's pty host: both are "--type=utility
// --utility-sub-type=node.mojom.NodeService", and VS Code's own process
// explorer only calls them "utility-process". Verified 2026-11-12 in
// microsoft/vscode main: platform/utilityProcess/electron-main/
// utilityProcess.ts (createEnv), extensions/electron-main/
// extensionHostStarter.ts (type "extensionHost"), terminal/electron-main/
// electronPtyHostStarter.ts (type "ptyHost"), base/node/ps.ts (findName).
const (
	vscodeProcTypeEnv = "VSCODE_CRASH_REPORTER_PROCESS_TYPE"
	vscodeExtHost     = "extensionHost"
)

// lifecycleParent says what launched an agent when that launcher is the
// kind of parent rule R01 (research/threats.md) cares about: a package
// manager running a lifecycle or package script, a Python package install,
// an editor extension host, or a URL/protocol handler. The agent's own
// environment is checked first because it is explicit: npm, yarn, pnpm and
// bun all export npm_lifecycle_event to the scripts they run, and every
// process below inherits it. Ancestors are checked nearest first. Last, the
// agent's inherited VS Code process type covers an extension host whose own
// environment could not be read.
func lifecycleParent(env map[string]string, ancestors []ancestor) string {
	if ev := strings.TrimSpace(env["npm_lifecycle_event"]); ev != "" {
		return managerFromEnv(env)
	}
	for _, a := range ancestors {
		if v := lifecycleOf(a); v != "" {
			return v
		}
	}
	if env[vscodeProcTypeEnv] == vscodeExtHost {
		return LifecycleExtensionHost
	}
	return ""
}

// isElectronUtility reports an Electron utility process, the only kind of
// ancestor whose environment is read for its VS Code process type.
func isElectronUtility(args []string) bool {
	if len(args) > 64 {
		args = args[:64]
	}
	for _, a := range args {
		if a == "--type=utility" {
			return true
		}
	}
	return false
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

// expandTitle undoes a Node process.title rewrite for parsing. npm, yarn and
// pnpm set process.title, and libuv writes the title over the whole argv
// area, so /proc/<pid>/cmdline (and the kernel name) become one
// space-separated string such as "npm exec @openai/codex --yolo".
// Splitting it on white space is the best reading there is (an argument
// that contained a space is lost either way). A first argument that is a
// path with a space in it (a macOS app bundle, C:\Program Files) is left
// alone.
func expandTitle(args []string) []string {
	if len(args) == 0 || len(args[0]) > 4096 || !strings.ContainsRune(args[0], ' ') {
		return args
	}
	f := strings.Fields(args[0])
	if len(f) == 0 || strings.ContainsAny(f[0], `/\`) {
		return args
	}
	if len(f) > 64 {
		f = f[:64]
	}
	return append(f, args[1:]...)
}

func lifecycleOf(a ancestor) string {
	args := expandTitle(a.args)
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
	if isExtensionHost(a, args) {
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

// isExtensionHost recognises the VS Code family extension host:
//   - a utility process whose environment says "extensionHost" (see
//     vscodeProcTypeEnv);
//   - "--type=extensionHost" on the command line, which is how the remote
//     (server-side) extension host runs (base/node/ps.ts normalises it);
//   - on macOS, the "<App> Helper (Plugin)" executable. The extension host
//     is the only VS Code utility process started with
//     allowLoadingUnsignedLibraries (checked against the pty host, shared
//     process, file watcher and agent host starters), and Electron runs
//     such processes from the Plugin helper. UNVERIFIED: the Electron half
//     (Plugin helper for allowLoadingUnsignedLibraries) is from Electron's
//     utilityProcess documentation as remembered, not re-read.
func isExtensionHost(a ancestor, args []string) bool {
	if a.utilityType == vscodeExtHost {
		return true
	}
	if strings.HasSuffix(strings.ToLower(a.name), "helper (plugin)") {
		return true
	}
	if len(args) > 64 {
		args = args[:64]
	}
	for _, x := range args {
		if x == "--type=extensionHost" {
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
