package catalog

import (
	"fmt"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// OSPaths is a per-OS list of paths or globs. "~" is the user's home,
// %VAR%, $VAR and ${VAR:-default} are expanded by the consumer with Expand.
//
// In YAML an OSPaths may be written as a plain list (the same paths on every
// OS) or as a mapping with the keys all, posix (linux and darwin), linux,
// darwin and windows.
type OSPaths struct {
	Linux   []string `yaml:"linux,omitempty" json:"linux,omitempty"`
	Darwin  []string `yaml:"darwin,omitempty" json:"darwin,omitempty"`
	Windows []string `yaml:"windows,omitempty" json:"windows,omitempty"`
}

// For returns the list for an operating system ("" means the running one).
// Unix-like systems other than macOS use the Linux list because they share
// its XDG layout.
func (o OSPaths) For(goos string) []string {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "windows":
		return append([]string(nil), o.Windows...)
	case "darwin":
		return append([]string(nil), o.Darwin...)
	default:
		return append([]string(nil), o.Linux...)
	}
}

// IsZero reports whether no path is set for any OS.
func (o OSPaths) IsZero() bool {
	return len(o.Linux) == 0 && len(o.Darwin) == 0 && len(o.Windows) == 0
}

// all returns every path with the OS it belongs to, for validation and
// indexing.
func (o OSPaths) all() []osPath {
	out := make([]osPath, 0, len(o.Linux)+len(o.Darwin)+len(o.Windows))
	for _, p := range o.Linux {
		out = append(out, osPath{"linux", p})
	}
	for _, p := range o.Darwin {
		out = append(out, osPath{"darwin", p})
	}
	for _, p := range o.Windows {
		out = append(out, osPath{"windows", p})
	}
	return out
}

type osPath struct{ os, path string }

func (o OSPaths) clone() OSPaths {
	return OSPaths{
		Linux:   append([]string(nil), o.Linux...),
		Darwin:  append([]string(nil), o.Darwin...),
		Windows: append([]string(nil), o.Windows...),
	}
}

// UnmarshalYAML accepts the list shorthand and the keyed form. Unknown keys
// are an error so that a typo ("window:") cannot silently drop a path list.
func (o *OSPaths) UnmarshalYAML(n *yaml.Node) error {
	*o = OSPaths{}
	switch n.Kind {
	case yaml.ScalarNode, yaml.SequenceNode:
		var l []string
		if err := decodeStringList(n, &l); err != nil {
			return err
		}
		o.addAll(l)
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			var l []string
			if err := decodeStringList(n.Content[i+1], &l); err != nil {
				return fmt.Errorf("%w (under %q)", err, key)
			}
			switch key {
			case "all":
				o.addAll(l)
			case "posix":
				o.Linux = append(o.Linux, l...)
				o.Darwin = append(o.Darwin, l...)
			case "linux":
				o.Linux = append(o.Linux, l...)
			case "darwin":
				o.Darwin = append(o.Darwin, l...)
			case "windows":
				o.Windows = append(o.Windows, l...)
			default:
				return fmt.Errorf("line %d: unknown OS key %q (want all, posix, linux, darwin or windows)", n.Content[i].Line, key)
			}
		}
		return nil
	default:
		return fmt.Errorf("line %d: paths must be a list or a mapping keyed by OS", n.Line)
	}
}

func (o *OSPaths) addAll(l []string) {
	o.Linux = append(o.Linux, l...)
	o.Darwin = append(o.Darwin, l...)
	o.Windows = append(o.Windows, l...)
}

// decodeStringList reads a string or a list of strings. yaml.v3 would
// happily turn 42 or true into "42" and "true"; a path list that is not made
// of strings is a mistake in the file, so it is reported.
func decodeStringList(n *yaml.Node, out *[]string) error {
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil
		}
		if n.Tag != "!!str" {
			return fmt.Errorf("line %d: expected a string, found %s", n.Line, strings.TrimPrefix(n.Tag, "!!"))
		}
		*out = []string{n.Value}
		return nil
	case yaml.SequenceNode:
		l := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			if c.Kind == yaml.AliasNode && c.Alias != nil {
				c = c.Alias
			}
			if c.Kind != yaml.ScalarNode || c.Tag != "!!str" {
				return fmt.Errorf("line %d: expected a string in the list", c.Line)
			}
			l = append(l, c.Value)
		}
		*out = l
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
}

// MCPConfig describes one place an agent declares MCP servers.
type MCPConfig struct {
	Paths OSPaths `yaml:"paths,omitempty" json:"paths,omitzero"`
	// ProjectPaths are relative to a project root (".mcp.json", ".cursor/mcp.json").
	ProjectPaths []string `yaml:"project_paths,omitempty" json:"project_paths,omitempty"`
	// Format is an internal/mcpconf format name; "" lets the parser sniff.
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	// Scope is an event.Scope value: managed | system | user | project | plugin.
	Scope string `yaml:"scope,omitempty" json:"scope,omitempty"`
}

// Transcript describes where an agent writes its session log.
type Transcript struct {
	// Format names the record layout: claude-jsonl | codex-rollout |
	// copilot-events | gemini-chats | cursor-sqlite | opencode-sqlite | ...
	Format string  `yaml:"format" json:"format"`
	Globs  OSPaths `yaml:"globs,omitempty" json:"globs,omitzero"`
	// HomeEnv is the variable that relocates the log root. Globs already
	// encode the relocation as ${VAR:-default}; the name is kept so the
	// scanner can report "relocated" without parsing the glob.
	HomeEnv string `yaml:"home_env,omitempty" json:"home_env,omitempty"`
}

// Hooks describes an agent's hook system.
type Hooks struct {
	// Dialect is the internal/hookio dialect: claude | codex | copilot |
	// gemini | cursor, or "" when spoor cannot speak the agent's hook
	// protocol (the files are still inventoried).
	Dialect string `yaml:"dialect,omitempty" json:"dialect,omitempty"`
	// ManagedPaths are the admin-tier file(s) spoor would write.
	ManagedPaths OSPaths  `yaml:"managed_paths,omitempty" json:"managed_paths,omitzero"`
	UserPaths    OSPaths  `yaml:"user_paths,omitempty" json:"user_paths,omitzero"`
	ProjectPaths []string `yaml:"project_paths,omitempty" json:"project_paths,omitempty"`
	Notes        string   `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Setting is one risky or relevant setting to probe.
//
// Format says how to read the value: json | jsonc | toml | yaml (a file),
// env (Key is an environment variable of the agent process; File is unused),
// plist (macOS preferences file) or registry (File.Windows holds registry
// key paths and Key is the value name). Key is a dotted path; a segment may
// be "*" to match any key at that level, and a segment containing dots is
// written in double quotes. Op is eq | ne | exists | contains | in. See Eval
// for the exact comparison rules.
type Setting struct {
	File     OSPaths `yaml:"file,omitempty" json:"file,omitzero"`
	Format   string  `yaml:"format" json:"format"`
	Key      string  `yaml:"key" json:"key"`
	Op       string  `yaml:"op" json:"op"`
	Value    string  `yaml:"value,omitempty" json:"value,omitempty"`
	Flag     string  `yaml:"flag" json:"flag"`
	Severity string  `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// Product is one catalogued piece of AI software.
type Product struct {
	ID     string `yaml:"id" json:"id"`
	Name   string `yaml:"name" json:"name"`
	Vendor string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	// Kind is an event.AssetKind value.
	Kind string `yaml:"kind" json:"kind"`
	// Status is active (default when empty), deprecated or discontinued.
	// State left behind by a dead product is still worth reporting, but as
	// residue rather than as a live agent.
	Status string `yaml:"status,omitempty" json:"status,omitempty"`
	// Aliases are former names and renames, used for documentation and
	// matching. The ids of products that legitimately share a fingerprint
	// with this one are listed here too (see the package comment).
	Aliases []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	// Binaries are executable basenames without ".exe".
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	// ProcessNames are process names when they differ from the binaries.
	ProcessNames []string `yaml:"process_names,omitempty" json:"process_names,omitempty"`
	// ProcessArgs are RE2 patterns matched against the full command line
	// of interpreter-launched agents.
	ProcessArgs []string `yaml:"process_args,omitempty" json:"process_args,omitempty"`
	// Packages are "<mgr>:<name>" references; see PackageManagers.
	Packages  []string `yaml:"packages,omitempty" json:"packages,omitempty"`
	BundleIDs []string `yaml:"bundle_ids,omitempty" json:"bundle_ids,omitempty"`
	// WinDisplay are registry Uninstall DisplayName patterns: a
	// case-insensitive substring matched on word boundaries, optionally
	// anchored with a leading "^" and a trailing "$".
	WinDisplay []string `yaml:"win_display,omitempty" json:"win_display,omitempty"`
	Appx       []string `yaml:"appx,omitempty" json:"appx,omitempty"`
	DesktopIDs []string `yaml:"desktop_ids,omitempty" json:"desktop_ids,omitempty"`
	// ExtensionIDs are VS Code family ids, "publisher.name".
	ExtensionIDs []string `yaml:"extension_ids,omitempty" json:"extension_ids,omitempty"`
	JetBrainsIDs []string `yaml:"jetbrains_ids,omitempty" json:"jetbrains_ids,omitempty"`
	ChromeIDs    []string `yaml:"chrome_ids,omitempty" json:"chrome_ids,omitempty"`
	InstallPaths OSPaths  `yaml:"install_paths,omitempty" json:"install_paths,omitzero"`
	StateDirs    OSPaths  `yaml:"state_dirs,omitempty" json:"state_dirs,omitzero"`
	// HomeEnv are variables that relocate the state directory.
	HomeEnv []string `yaml:"home_env,omitempty" json:"home_env,omitempty"`
	// EnvMarkers are variable names the agent sets for child processes.
	EnvMarkers []string `yaml:"env_markers,omitempty" json:"env_markers,omitempty"`
	// SessionEnv are variable names carrying the session id for children.
	SessionEnv []string    `yaml:"session_env,omitempty" json:"session_env,omitempty"`
	MCP        []MCPConfig `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	// Skills, Rules, Plugins, Subagents and Commands are user-level
	// directories or files ("~" relative); project-relative ones are
	// prefixed "./".
	Skills     []string    `yaml:"skills,omitempty" json:"skills,omitempty"`
	Rules      []string    `yaml:"rules,omitempty" json:"rules,omitempty"`
	Plugins    []string    `yaml:"plugins,omitempty" json:"plugins,omitempty"`
	Subagents  []string    `yaml:"subagents,omitempty" json:"subagents,omitempty"`
	Commands   []string    `yaml:"commands,omitempty" json:"commands,omitempty"`
	Transcript *Transcript `yaml:"transcript,omitempty" json:"transcript,omitempty"`
	Hooks      *Hooks      `yaml:"hooks,omitempty" json:"hooks,omitempty"`
	// RiskyFlags are argv flags that disable approvals, the sandbox, hooks
	// or persistence. An entry is either a bare flag ("--yolo") or a flag
	// and its value separated by one space ("--sandbox danger-full-access"),
	// which also matches the "--flag=value" spelling. See RiskyArgs.
	RiskyFlags []string  `yaml:"risky_flags,omitempty" json:"risky_flags,omitempty"`
	Settings   []Setting `yaml:"settings,omitempty" json:"settings,omitempty"`
	// Ports are default listening ports. A port is never identity on its
	// own: 8080, 8000 and 3000 belong to everybody.
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	APIHosts []string `yaml:"api_hosts,omitempty" json:"api_hosts,omitempty"`
	Signers  struct {
		DarwinTeamID     string `yaml:"darwin_team_id,omitempty" json:"darwin_team_id,omitempty"`
		WindowsPublisher string `yaml:"windows_publisher,omitempty" json:"windows_publisher,omitempty"`
	} `yaml:"signers,omitempty" json:"signers,omitzero"`
	// Capabilities is a closed vocabulary; see Capabilities.
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	// Sources are provenance URLs for the fingerprints.
	Sources []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	// Unverified lists field names (YAML spelling, optionally dotted, for
	// example "signers.darwin_team_id") whose values were not verified
	// against a primary source.
	Unverified []string `yaml:"unverified,omitempty" json:"unverified,omitempty"`
	// Notes is free text for humans: collisions, renames, caveats.
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// IsUnverified reports whether a field (YAML spelling, for example
// "signers" or "signers.darwin_team_id") or one of its parents is listed in
// Unverified.
func (p Product) IsUnverified(field string) bool {
	for _, u := range p.Unverified {
		if u == field || strings.HasPrefix(field, u+".") {
			return true
		}
	}
	return false
}

// MarkerEnv returns every environment variable name that marks a child
// process of this agent: EnvMarkers followed by SessionEnv.
func (p Product) MarkerEnv() []string {
	out := make([]string, 0, len(p.EnvMarkers)+len(p.SessionEnv))
	out = append(out, p.EnvMarkers...)
	return append(out, p.SessionEnv...)
}

func (p Product) clone() Product {
	c := p
	c.Aliases = cloneStrings(p.Aliases)
	c.Binaries = cloneStrings(p.Binaries)
	c.ProcessNames = cloneStrings(p.ProcessNames)
	c.ProcessArgs = cloneStrings(p.ProcessArgs)
	c.Packages = cloneStrings(p.Packages)
	c.BundleIDs = cloneStrings(p.BundleIDs)
	c.WinDisplay = cloneStrings(p.WinDisplay)
	c.Appx = cloneStrings(p.Appx)
	c.DesktopIDs = cloneStrings(p.DesktopIDs)
	c.ExtensionIDs = cloneStrings(p.ExtensionIDs)
	c.JetBrainsIDs = cloneStrings(p.JetBrainsIDs)
	c.ChromeIDs = cloneStrings(p.ChromeIDs)
	c.InstallPaths = p.InstallPaths.clone()
	c.StateDirs = p.StateDirs.clone()
	c.HomeEnv = cloneStrings(p.HomeEnv)
	c.EnvMarkers = cloneStrings(p.EnvMarkers)
	c.SessionEnv = cloneStrings(p.SessionEnv)
	if p.MCP != nil {
		c.MCP = make([]MCPConfig, len(p.MCP))
		for i, m := range p.MCP {
			m.Paths = m.Paths.clone()
			m.ProjectPaths = cloneStrings(m.ProjectPaths)
			c.MCP[i] = m
		}
	}
	c.Skills = cloneStrings(p.Skills)
	c.Rules = cloneStrings(p.Rules)
	c.Plugins = cloneStrings(p.Plugins)
	c.Subagents = cloneStrings(p.Subagents)
	c.Commands = cloneStrings(p.Commands)
	if p.Transcript != nil {
		t := *p.Transcript
		t.Globs = t.Globs.clone()
		c.Transcript = &t
	}
	if p.Hooks != nil {
		h := *p.Hooks
		h.ManagedPaths = h.ManagedPaths.clone()
		h.UserPaths = h.UserPaths.clone()
		h.ProjectPaths = cloneStrings(h.ProjectPaths)
		c.Hooks = &h
	}
	c.RiskyFlags = cloneStrings(p.RiskyFlags)
	if p.Settings != nil {
		c.Settings = make([]Setting, len(p.Settings))
		for i, s := range p.Settings {
			s.File = s.File.clone()
			c.Settings[i] = s
		}
	}
	c.Ports = append([]int(nil), p.Ports...)
	c.APIHosts = cloneStrings(p.APIHosts)
	c.Capabilities = cloneStrings(p.Capabilities)
	c.Sources = cloneStrings(p.Sources)
	c.Unverified = cloneStrings(p.Unverified)
	return c
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}
