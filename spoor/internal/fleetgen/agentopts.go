package fleetgen

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/state"
)

// Fleet agent options vocabulary (docs/Configuration/agent-configuration.md).
const (
	aoConfig    = "config"
	aoOverrides = "overrides"
	aoPlatforms = "platforms"
	aoATC       = "auto_table_construction"
)

// overrideSkip are override platform keys that never run spoor.
var overrideSkip = map[string]bool{"chrome": true}

// ATCFragment returns the agent options fragment spoor needs: the Linux
// block in config (Linux distributions report their own os_version.platform,
// ubuntu, rhel and so on, and read the base config) and complete darwin and
// windows blocks in overrides.platforms. It is a fragment: see
// MergeAgentOptions for how it must be combined with existing options.
func (c *Content) ATCFragment() map[string]any {
	ov := map[string]any{}
	for _, p := range Platforms {
		if p == PlatformLinux {
			continue
		}
		ov[p] = map[string]any{aoATC: atcCopy(c.ATC[p])}
	}
	return map[string]any{
		aoConfig:    map[string]any{aoATC: atcCopy(c.ATC[PlatformLinux])},
		aoOverrides: map[string]any{aoPlatforms: ov},
	}
}

// ExampleBaseAgentOptions is a typical agent options document with the
// options and decorators Fleet's documentation shows; the example file
// merges the spoor fragment into it.
func ExampleBaseAgentOptions() map[string]any {
	return map[string]any{
		aoConfig: map[string]any{
			"options": map[string]any{
				"distributed_interval":         10,
				"distributed_plugin":           "tls",
				"distributed_tls_max_attempts": 3,
				"logger_tls_endpoint":          "/api/osquery/log",
				"logger_tls_period":            10,
				"pack_delimiter":               "/",
			},
			"decorators": map[string]any{
				"load": []any{
					"SELECT uuid AS host_uuid FROM system_info;",
					"SELECT hostname AS hostname FROM system_info;",
				},
			},
		},
		aoOverrides: map[string]any{},
	}
}

// MergeAgentOptions returns current (Fleet's agent options as decoded from
// JSON or YAML; nil for none) with spoor's ATC tables added, without
// changing anything else. Fleet replaces agent options as a whole and does
// not merge a platform override with the base config, so:
//
//   - the Linux tables go into config.auto_table_construction and into every
//     existing override other than darwin, windows and chrome (an override
//     keyed by a distribution name, such as ubuntu, hides the base config
//     from those hosts);
//   - darwin and windows get their own tables in overrides.platforms.<os>;
//     when that override does not exist yet it is created as a copy of the
//     base config, so those hosts keep the options, decorators and other
//     ATC tables they had. From then on, a change to the base config must
//     be repeated in those overrides.
//
// Existing spoor_* ATC entries are replaced; other entries are kept.
func (c *Content) MergeAgentOptions(current map[string]any) (map[string]any, error) {
	out, err := copyOptions(current)
	if err != nil {
		return nil, err
	}
	cfg, err := subMap(out, aoConfig, true)
	if err != nil {
		return nil, err
	}
	ovs, err := subMap(out, aoOverrides, true)
	if err != nil {
		return nil, err
	}
	plats, err := subMap(ovs, aoPlatforms, true)
	if err != nil {
		return nil, err
	}
	// Overrides that exist before this merge (Linux distributions among them).
	keys := make([]string, 0, len(plats))
	for k := range plats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == PlatformDarwin || k == PlatformWindows || overrideSkip[k] {
			continue
		}
		ov, ok := plats[k].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("fleetgen: overrides.platforms.%s is not a mapping", k)
		}
		if err := putATC(ov, c.ATC[PlatformLinux]); err != nil {
			return nil, fmt.Errorf("fleetgen: overrides.platforms.%s: %w", k, err)
		}
	}
	for _, p := range []string{PlatformDarwin, PlatformWindows} {
		var ov map[string]any
		switch v := plats[p].(type) {
		case map[string]any:
			ov = v
		case nil:
			cp, err := copyOptions(cfg)
			if err != nil {
				return nil, err
			}
			ov = cp
		default:
			return nil, fmt.Errorf("fleetgen: overrides.platforms.%s is not a mapping", p)
		}
		if err := putATC(ov, c.ATC[p]); err != nil {
			return nil, fmt.Errorf("fleetgen: overrides.platforms.%s: %w", p, err)
		}
		plats[p] = ov
	}
	if err := putATC(cfg, c.ATC[PlatformLinux]); err != nil {
		return nil, fmt.Errorf("fleetgen: config: %w", err)
	}
	return out, nil
}

// StripAgentOptions returns current without any spoor_* ATC entry, for
// uninstalling. Overrides that MergeAgentOptions created are left in place:
// they hold the operator's own options.
func StripAgentOptions(current map[string]any) (map[string]any, error) {
	out, err := copyOptions(current)
	if err != nil {
		return nil, err
	}
	strip := func(cfg map[string]any) error {
		atc, err := subMap(cfg, aoATC, false)
		if err != nil || atc == nil {
			return err
		}
		removeSpoor(atc)
		if len(atc) == 0 {
			delete(cfg, aoATC)
		}
		return nil
	}
	if cfg, err := subMap(out, aoConfig, false); err != nil {
		return nil, err
	} else if cfg != nil {
		if err := strip(cfg); err != nil {
			return nil, err
		}
	}
	ovs, err := subMap(out, aoOverrides, false)
	if err != nil || ovs == nil {
		return out, err
	}
	plats, err := subMap(ovs, aoPlatforms, false)
	if err != nil || plats == nil {
		return out, err
	}
	for k, v := range plats {
		ov, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if err := strip(ov); err != nil {
			return nil, fmt.Errorf("fleetgen: overrides.platforms.%s: %w", k, err)
		}
	}
	return out, nil
}

// AgentOptionsSpec renders agent options as a `fleetctl apply -f` document
// (kind config). JSON is valid YAML, and JSON keeps numbers and strings as
// Fleet returned them.
func AgentOptionsSpec(agentOptions map[string]any) ([]byte, error) {
	if agentOptions == nil {
		return nil, errors.New("fleetgen: no agent options")
	}
	doc := map[string]any{
		"apiVersion": "v1",
		"kind":       "config",
		"spec":       map[string]any{"agent_options": agentOptions},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// putATC replaces the spoor entries of cfg's ATC block with tables.
func putATC(cfg map[string]any, tables map[string]any) error {
	atc, err := subMap(cfg, aoATC, true)
	if err != nil {
		return err
	}
	removeSpoor(atc)
	for k, v := range atcCopy(tables) {
		atc[k] = v
	}
	return nil
}

func removeSpoor(atc map[string]any) {
	for k := range atc {
		if strings.HasPrefix(k, state.TablePrefix) {
			delete(atc, k)
		}
	}
}

// subMap returns m[key] as a mapping, creating it (when create) if it is
// absent or null. A non-mapping value is an error: guessing would discard
// the operator's configuration.
func subMap(m map[string]any, key string, create bool) (map[string]any, error) {
	switch v := m[key].(type) {
	case map[string]any:
		return v, nil
	case nil:
		if !create {
			return nil, nil
		}
		n := map[string]any{}
		m[key] = n
		return n, nil
	default:
		return nil, fmt.Errorf("fleetgen: %s is a %T, not a mapping", key, v)
	}
}

// atcCopy deep-copies an ATC block so callers can never alias Content.
func atcCopy(tables map[string]any) map[string]any {
	out := make(map[string]any, len(tables))
	for name, e := range tables {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		c := make(map[string]any, len(entry))
		for k, v := range entry {
			if cols, ok := v.([]string); ok {
				l := make([]any, len(cols))
				for i, s := range cols {
					l[i] = s
				}
				c[k] = l
				continue
			}
			c[k] = v
		}
		out[name] = c
	}
	return out
}

// maxOptionsDepth bounds recursion over an operator-supplied document.
const maxOptionsDepth = 64

// copyOptions deep-copies a decoded document. YAML decoding can produce
// map[any]any in older decoders and integer keys; they are refused rather
// than silently converted.
func copyOptions(m map[string]any) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}
	v, err := deepCopy(m, 0)
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func deepCopy(v any, depth int) (any, error) {
	if depth > maxOptionsDepth {
		return nil, errors.New("fleetgen: agent options nested too deeply")
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			c, err := deepCopy(e, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			c, err := deepCopy(e, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case []string:
		return append([]string(nil), x...), nil
	case string, bool, int, int64, float64, json.Number, nil:
		return x, nil
	default:
		return nil, fmt.Errorf("fleetgen: unsupported value of type %T in agent options", v)
	}
}

// ---- rendering ----

const atcFragmentNotes = `#
# THIS IS A FRAGMENT. Merge it into your existing agent options; do not use
# it as your agent options file. Fleet replaces agent options as a whole, so
# applying this file alone DROPS your existing ATC tables, decorators and
# options, and Fleet does not merge overrides.platforms.<os> with config, so
# a darwin or windows override must carry that OS's full configuration.
#
# How to merge (GitOps: the file named by agent_options.path):
#   1. Add every entry of config.auto_table_construction below to your
#      config.auto_table_construction. If you have overrides for Linux
#      distributions (ubuntu, rhel ...), add them there as well.
#   2. If you already have overrides.platforms.darwin / .windows, add the
#      matching auto_table_construction entries to them. If you do not, copy
#      your whole config section into a new override for that OS first, then
#      add the entries; otherwise those hosts lose your base options.
#   3. Validate with: fleetctl gitops -f default.yml --dry-run
# agent-options.example.yml shows the result on a typical base; the
# fleetgen.MergeAgentOptions function does the same merge programmatically.
#
# Do not deploy this together with the spoor osquery extension: both
# provide the spoor_* tables, and osquery keeps only one owner per table
# name. Numbers are TEXT under ATC; the shipped queries compare them through
# CAST(... AS INTEGER). Table names, columns and queries come from
# internal/state (state.ATCConfig).
`

func (c *Content) renderATCFragment() ([]byte, error) {
	n, err := anyNode(c.ATCFragment())
	if err != nil {
		return nil, err
	}
	return encodeDoc(c.header("auto table construction (ATC) fragment.", "")+atcFragmentNotes, n)
}

func (c *Content) renderATCExample() ([]byte, error) {
	merged, err := c.MergeAgentOptions(ExampleBaseAgentOptions())
	if err != nil {
		return nil, err
	}
	n, err := anyNode(merged)
	if err != nil {
		return nil, err
	}
	notes := "#\n# EXAMPLE: the ATC fragment merged into a typical base configuration\n" +
		"# (fleetgen.ExampleBaseAgentOptions). The darwin and windows overrides\n" +
		"# repeat the base options and decorators because Fleet does not merge\n" +
		"# overrides with config. Replace the base part with your own options.\n"
	return encodeDoc(c.header("agent options example with ATC merged in.", "")+notes, n)
}
