package hookinstall

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

// target is one hook file of one agent in one scope.
type target struct {
	agentID string
	also    []string // other catalog ids that share this file
	// cmdAgent is the --agent value written into the command line.
	cmdAgent string
	dialect  string
	scope    event.Scope
	kind     fileKind
	// logical is the path as the agent sees it, in the style of the target
	// OS; path is where this process finds it (Root applied).
	logical string
	path    string
	// owned marks a file that exists only for spoor (a drop-in), so
	// uninstall may delete it instead of leaving an empty shell behind.
	owned bool
	// unsupported, when set, is why nothing can be installed here.
	unsupported string
	product     catalog.Product
}

// resolveTargets maps the requested agents to hook files. Products that
// share a hook file (the Cursor IDE and the Cursor CLI) yield one target:
// two registrations in one file would report every event twice.
func resolveTargets(c *catalog.Catalog, o Options, scope event.Scope) []target {
	var products []catalog.Product
	var out []target
	if len(o.Agents) == 0 {
		for _, p := range c.Products() {
			if p.Hooks != nil && p.Hooks.Dialect != "" {
				products = append(products, p)
			}
		}
	} else {
		seen := map[string]bool{}
		for _, id := range o.Agents {
			p, ok := c.Get(id)
			if !ok {
				p, ok = c.Resolve(id)
			}
			if !ok {
				out = append(out, target{agentID: id, scope: scope, unsupported: "agent is not in the catalog"})
				continue
			}
			if seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			products = append(products, p)
		}
	}

	byPath := map[string]int{}
	for _, p := range products {
		t := resolveTarget(p, o, scope)
		if t.unsupported == "" {
			key := t.dialect + "\x00" + pathKey(t.logical, o.GOOS)
			if i, dup := byPath[key]; dup {
				out[i] = mergeShared(out[i], t)
				continue
			}
			byPath[key] = len(out)
		}
		out = append(out, t)
	}
	return out
}

// mergeShared keeps one target for a shared file. The product whose id is
// the one hookio stamps on events wins, so "--agent" and Event.Agent.ID
// agree; otherwise catalog order decides.
func mergeShared(a, b target) target {
	canon, _ := hookio.AgentIDFor(a.dialect)
	if b.agentID == canon && a.agentID != canon {
		a, b = b, a
	}
	a.also = append(a.also, b.agentID)
	a.also = append(a.also, b.also...)
	sort.Strings(a.also)
	return a
}

func resolveTarget(p catalog.Product, o Options, scope event.Scope) target {
	t := target{agentID: p.ID, scope: scope, product: p}
	if p.Hooks == nil || p.Hooks.Dialect == "" {
		t.unsupported = "spoor has no hook dialect for this agent"
		return t
	}
	t.dialect = p.Hooks.Dialect
	if _, ok := dialects[t.dialect]; !ok {
		t.unsupported = "unknown hook dialect in the catalog entry"
		return t
	}
	if _, ok := hookio.Get(t.dialect); !ok {
		t.unsupported = "hook dialect is not implemented"
		return t
	}
	t.cmdAgent = p.ID
	if canon, ok := hookio.AgentIDFor(t.dialect); ok {
		t.cmdAgent = canon
	}
	if !validAgentID(t.cmdAgent) {
		t.unsupported = "agent id cannot be used on a command line"
		return t
	}

	var raw string
	switch scope {
	case event.ScopeManaged:
		raw = pick(p.Hooks.ManagedPaths.For(o.GOOS), managedPrefs[t.dialect])
		if raw == "" {
			t.unsupported = "the catalog lists no managed hook path for " + o.GOOS
			return t
		}
	case event.ScopeSystem:
		// Only Codex has a machine-wide tier that is not policy: hooks.json
		// beside the system config.toml, which is also where the system
		// requirements.toml lives.
		if t.dialect != "codex" {
			t.unsupported = "this agent has no system tier; use scope managed"
			return t
		}
		raw = pick(p.Hooks.ManagedPaths.For(o.GOOS), managedPrefs[t.dialect])
		if raw == "" {
			t.unsupported = "the catalog lists no system path for " + o.GOOS
			return t
		}
	case event.ScopeUser:
		raw = pick(p.Hooks.UserPaths.For(o.GOOS), userPrefs[t.dialect])
		if raw == "" {
			t.unsupported = "the catalog lists no user hook path for " + o.GOOS
			return t
		}
	default:
		t.unsupported = "unsupported scope"
		return t
	}

	// Machine-wide paths are fixed locations: neither the caller's Env nor
	// a home directory may move them (%ProgramData% resolves to its
	// conventional value). User paths follow the variables that relocate
	// the agent's directory.
	home, env := o.Home, o.Env
	if scope != event.ScopeUser {
		home, env = "", nil
	}
	logical := catalog.Expand(raw, home, env, o.GOOS)
	if left := catalog.Unexpanded(logical, o.GOOS); len(left) > 0 {
		t.unsupported = "hook path depends on an unresolved variable (" + strings.Join(left, ", ") + ")"
		return t
	}
	dir, base := splitPath(logical, o.GOOS)
	if t.dialect == "codex" {
		// The catalog may list config.toml (user) or requirements.toml
		// (managed); hooks.json sits beside either.
		switch {
		case scope == event.ScopeSystem, scope == event.ScopeUser && strings.EqualFold(base, "config.toml"):
			base = "hooks.json"
		}
	}
	if base == "*.json" {
		// A drop-in directory: spoor adds its own file. The Claude Code
		// directory is merged in alphabetical order, hence the prefix.
		base = sensorName + ".json"
		if t.dialect == "claude" {
			base = "50-" + sensorName + ".json"
		}
	}
	logical = joinPath(dir, base, o.GOOS)
	if strings.ContainsAny(logical, "*?") || hasControl(logical) || len(logical) > maxPathLen || !absFor(logical, o.GOOS) {
		t.unsupported = "the catalog hook path is not a usable absolute path"
		return t
	}
	t.logical = logical
	t.path = hostPath(o.Root, logical, o.GOOS)

	low := strings.ToLower(base)
	switch t.dialect {
	case "claude", "gemini":
		t.kind = kindGroups
	case "codex":
		t.kind = kindGroups
		if strings.HasSuffix(low, ".toml") {
			t.kind = kindTOML
		}
	default:
		t.kind = kindFlat
	}
	if t.kind != kindTOML && !strings.HasSuffix(low, ".json") {
		t.unsupported = "the catalog hook path is not a JSON file"
		return t
	}
	_, parent := splitPath(dir, o.GOOS)
	switch t.dialect {
	case "claude":
		t.owned = strings.EqualFold(parent, "managed-settings.d")
	case "copilot":
		t.owned = low == sensorName+".json"
	}
	return t
}

// managedPrefs and userPrefs choose among several catalog paths by a
// fragment of the path, most wanted first. With no match the first path is
// used.
var (
	managedPrefs = map[string][]string{
		"claude":  {"managed-settings.d"},
		"codex":   {"requirements.toml", "hooks.json"},
		"copilot": {"policy.d"},
	}
	userPrefs = map[string][]string{
		"claude":  {"settings.json"},
		"codex":   {"hooks.json", "config.toml"},
		"copilot": {"hooks"},
	}
)

func pick(paths []string, prefs []string) string {
	for _, want := range prefs {
		for _, p := range paths {
			norm := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
			if strings.HasSuffix(norm, "/"+want) || strings.Contains(norm, "/"+want+"/") {
				return p
			}
		}
	}
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

// splitPath splits a logical path in the style of goos, whatever OS this
// process runs on (path/filepath only knows the host's separators).
func splitPath(p, goos string) (dir, base string) {
	seps := "/"
	if goos == "windows" {
		seps = `/\`
	}
	i := strings.LastIndexAny(p, seps)
	if i < 0 {
		return "", p
	}
	if i == 0 {
		return p[:1], p[1:]
	}
	return p[:i], p[i+1:]
}

func joinPath(dir, base, goos string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	if strings.HasSuffix(dir, "/") || (goos == "windows" && strings.HasSuffix(dir, `\`)) {
		return dir + base
	}
	return dir + sep + base
}

// pathKey normalises a logical path for comparison: macOS and Windows file
// systems fold case, Windows also accepts either separator and ignores
// trailing dots and spaces in a name.
// Known gap: 8.3 short names (PROGRA~1) are not resolved.
func pathKey(p, goos string) string {
	switch goos {
	case "windows":
		p = strings.ReplaceAll(p, "/", `\`)
		parts := strings.Split(p, `\`)
		for i, s := range parts {
			parts[i] = strings.TrimRight(s, ". ")
		}
		return strings.ToLower(strings.Join(parts, `\`))
	case "darwin":
		return strings.ToLower(p)
	}
	return p
}

// hostPath maps a logical path to where this process can open it. With a
// Root, a Windows path keeps its drive as a directory (C:\ProgramData\x
// becomes <Root>/C/ProgramData/x) so a Windows layout can be rendered and
// tested on any OS.
func hostPath(root, logical, goos string) string {
	if goos == "windows" {
		if root == "" {
			if runtime.GOOS == "windows" {
				return filepath.Clean(logical)
			}
			// No Root and not on Windows: keep the logical path. Apply
			// refuses it (it is not absolute here), a plan can still be shown.
			return logical
		}
		p := strings.ReplaceAll(logical, `\`, "/")
		switch {
		case strings.HasPrefix(p, "//"):
			p = "UNC/" + strings.TrimLeft(p, "/")
		case len(p) >= 2 && p[1] == ':':
			p = p[:1] + p[2:]
		}
		return filepath.Join(root, filepath.FromSlash(p))
	}
	if root == "" {
		return filepath.FromSlash(logical)
	}
	return filepath.Join(root, filepath.FromSlash(logical))
}

// siblingDir returns the on-disk directory that holds t.path.
func (t target) dir() string { return filepath.Dir(t.path) }
