package fleetgen

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func atcOf(t *testing.T, cfg any) map[string]any {
	t.Helper()
	m, ok := cfg.(map[string]any)
	if !ok {
		t.Fatalf("config is %T", cfg)
	}
	atc, _ := m[aoATC].(map[string]any)
	return atc
}

func spoorPath(t *testing.T, atc map[string]any) string {
	t.Helper()
	e, ok := atc["spoor_health"].(map[string]any)
	if !ok {
		t.Fatalf("no spoor_health in %v", atc)
	}
	return e["path"].(string)
}

func overrides(t *testing.T, ao map[string]any) map[string]any {
	t.Helper()
	return ao[aoOverrides].(map[string]any)[aoPlatforms].(map[string]any)
}

// fleetJSON decodes agent options the way they come back from
// `fleetctl get config --json` (numbers as float64).
func fleetJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMergeAgentOptions(t *testing.T) {
	c := mustBuild(t, Options{})
	// The agent options of the live test server before verification.
	current := fleetJSON(t, `{
	  "config": {
	    "auto_table_construction": {"ai_agents_atc": {"columns": ["name"], "path": "/x/state.db", "platform": "linux", "query": "SELECT name FROM ai_agents"},
	                                "spoor_health": {"columns": ["old"], "path": "/old/state.db", "query": "SELECT old FROM health"}},
	    "decorators": {"load": ["SELECT uuid AS host_uuid FROM system_info;"]},
	    "options": {"distributed_interval": 3, "pack_delimiter": "/"}
	  },
	  "overrides": {"platforms": {"ubuntu": {"options": {"distributed_interval": 7}},
	                              "windows": {"options": {"distributed_interval": 60}},
	                              "chrome": {"options": {}}}}
	}`)
	before, _ := json.Marshal(current)
	got, err := c.MergeAgentOptions(current)
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := json.Marshal(current); string(after) != string(before) {
		t.Fatal("MergeAgentOptions modified its input")
	}
	base := atcOf(t, got[aoConfig])
	if base["ai_agents_atc"] == nil {
		t.Error("existing non-spoor ATC table dropped")
	}
	if spoorPath(t, base) != "/var/lib/spoor/state.db" || len(base) != len(c.ATC["linux"])+1 {
		t.Errorf("base ATC: %v", base)
	}
	if cols := base["spoor_health"].(map[string]any)["columns"].([]any); len(cols) < 5 {
		t.Error("old spoor_health entry was not replaced")
	}
	cfg := got[aoConfig].(map[string]any)
	if cfg["options"].(map[string]any)["distributed_interval"] != float64(3) || cfg["decorators"] == nil {
		t.Error("base options or decorators changed")
	}
	ov := overrides(t, got)
	// ubuntu hosts read only their override: it must get the Linux tables.
	if spoorPath(t, atcOf(t, ov["ubuntu"])) != "/var/lib/spoor/state.db" {
		t.Error("Linux distribution override did not get the Linux tables")
	}
	if ov["ubuntu"].(map[string]any)["options"].(map[string]any)["distributed_interval"] != float64(7) {
		t.Error("ubuntu override options changed")
	}
	// An existing windows override keeps its own options.
	win := ov["windows"].(map[string]any)
	if win["options"].(map[string]any)["distributed_interval"] != float64(60) || win["decorators"] != nil {
		t.Error("existing windows override replaced by a copy of the base")
	}
	if spoorPath(t, atcOf(t, win)) != `C:\ProgramData\spoor\state.db` {
		t.Error("windows override has the wrong tables")
	}
	// darwin had no override: it becomes a copy of the base config.
	dar := ov["darwin"].(map[string]any)
	if dar["decorators"] == nil || dar["options"].(map[string]any)["distributed_interval"] != float64(3) {
		t.Error("new darwin override does not carry the base options and decorators")
	}
	datc := atcOf(t, dar)
	if datc["ai_agents_atc"] == nil || spoorPath(t, datc) != "/Library/Application Support/spoor/state.db" {
		t.Errorf("darwin ATC: %v", datc)
	}
	if atcOf(t, ov["chrome"]) != nil {
		t.Error("ChromeOS override must not get spoor tables")
	}
	// Idempotent.
	again, err := c.MergeAgentOptions(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Error("merging twice differs from merging once")
	}
	// Strip removes exactly what merge added (overrides it created remain).
	stripped, err := StripAgentOptions(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []any{stripped[aoConfig], overrides(t, stripped)["darwin"], overrides(t, stripped)["windows"], overrides(t, stripped)["ubuntu"]} {
		for k := range atcOf(t, cfg) {
			if strings.HasPrefix(k, "spoor_") {
				t.Errorf("strip left %s", k)
			}
		}
	}
	if atcOf(t, stripped[aoConfig])["ai_agents_atc"] == nil {
		t.Error("strip removed a non-spoor table")
	}
	if _, ok := overrides(t, stripped)["windows"].(map[string]any)[aoATC]; ok {
		t.Error("strip left an empty ATC block")
	}
}

func TestMergeAgentOptionsEmptyAndHostile(t *testing.T) {
	c := mustBuild(t, Options{})
	got, err := c.MergeAgentOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(atcOf(t, got[aoConfig])) != len(c.ATC["linux"]) || len(overrides(t, got)) != 2 {
		t.Errorf("merge into nothing: %v", got)
	}
	// overrides: null and platforms: null, as Fleet returns them.
	if _, err := c.MergeAgentOptions(fleetJSON(t, `{"config": {}, "overrides": null}`)); err != nil {
		t.Errorf("null overrides: %v", err)
	}
	if _, err := c.MergeAgentOptions(fleetJSON(t, `{"overrides": {"platforms": null}}`)); err != nil {
		t.Errorf("null platforms: %v", err)
	}
	for _, bad := range []string{
		`{"config": "x"}`,
		`{"config": {"auto_table_construction": []}}`,
		`{"overrides": {"platforms": {"darwin": 3}}}`,
		`{"overrides": {"platforms": {"ubuntu": []}}}`,
		`{"overrides": []}`,
	} {
		if _, err := c.MergeAgentOptions(fleetJSON(t, bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	deep := strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200)
	if _, err := c.MergeAgentOptions(fleetJSON(t, `{"config": {"x": `+deep+`}}`)); err == nil {
		t.Error("deeply nested options accepted")
	}
	// YAML-decoded options (ints, not floats) are accepted too.
	var y map[string]any
	if err := yaml.Unmarshal([]byte("config:\n  options:\n    distributed_interval: 10\n"), &y); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MergeAgentOptions(y); err != nil {
		t.Errorf("yaml input: %v", err)
	}
}

func TestAgentOptionsSpec(t *testing.T) {
	c := mustBuild(t, Options{})
	merged, err := c.MergeAgentOptions(ExampleBaseAgentOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := AgentOptionsSpec(merged)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Spec       struct {
			AgentOptions map[string]any `yaml:"agent_options"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != "v1" || doc.Kind != "config" || doc.Spec.AgentOptions[aoConfig] == nil {
		t.Errorf("spec: %s", b)
	}
	if _, err := AgentOptionsSpec(nil); err == nil {
		t.Error("nil agent options accepted")
	}
}

// TestFragmentIsOnlySpoor: the fragment carries nothing but spoor tables,
// one complete block per OS, each with that OS's platform and path.
func TestFragmentIsOnlySpoor(t *testing.T) {
	c := mustBuild(t, Options{})
	fr := c.ATCFragment()
	blocks := map[string]map[string]any{"linux": atcOf(t, fr[aoConfig])}
	for p, v := range overrides(t, fr) {
		blocks[p] = atcOf(t, v)
	}
	if len(blocks) != 3 {
		t.Fatalf("blocks for %d platforms", len(blocks))
	}
	for p, atc := range blocks {
		if len(atc) != len(c.ATC["linux"]) {
			t.Errorf("%s: %d tables", p, len(atc))
		}
		for name, e := range atc {
			m := e.(map[string]any)
			if !strings.HasPrefix(name, "spoor_") || m["platform"] != p || m["path"] != DefaultDBPaths()[p] {
				t.Errorf("%s/%s: %v", p, name, m)
			}
		}
	}
	// Mutating the fragment does not reach Content.
	blocks["linux"]["spoor_health"].(map[string]any)["path"] = "/tmp/x"
	if c.ATC["linux"]["spoor_health"].(map[string]any)["path"] == "/tmp/x" {
		t.Error("fragment aliases Content")
	}
}
