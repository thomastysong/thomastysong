package catalog

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// buildFrom parses inline YAML as if it were the whole embedded catalog.
func buildFrom(t *testing.T, files ...string) (*snapshot, error) {
	t.Helper()
	st := &state{interpreters: map[string]string{}}
	for i, content := range files {
		df, err := parseFile("inline"+itoa(i)+".yaml", []byte(content))
		if err != nil {
			return nil, err
		}
		if err := st.add("inline"+itoa(i)+".yaml", df, false); err != nil {
			return nil, err
		}
	}
	return st.build()
}

func TestOSPathsYAMLForms(t *testing.T) {
	tests := []struct {
		yaml string
		want OSPaths
	}{
		{`["~/.a", "~/.b"]`, OSPaths{Linux: []string{"~/.a", "~/.b"}, Darwin: []string{"~/.a", "~/.b"}, Windows: []string{"~/.a", "~/.b"}}},
		{`"~/.a"`, OSPaths{Linux: []string{"~/.a"}, Darwin: []string{"~/.a"}, Windows: []string{"~/.a"}}},
		{`{all: ["~/.a"]}`, OSPaths{Linux: []string{"~/.a"}, Darwin: []string{"~/.a"}, Windows: []string{"~/.a"}}},
		{`{posix: ["~/.a"]}`, OSPaths{Linux: []string{"~/.a"}, Darwin: []string{"~/.a"}}},
		{`{linux: ["/etc/a"], darwin: "/Library/a", windows: ['C:\ProgramData\a']}`, OSPaths{Linux: []string{"/etc/a"}, Darwin: []string{"/Library/a"}, Windows: []string{`C:\ProgramData\a`}}},
		{`{all: ["~/.a"], linux: ["~/.config/a"]}`, OSPaths{Linux: []string{"~/.a", "~/.config/a"}, Darwin: []string{"~/.a"}, Windows: []string{"~/.a"}}},
		{`{posix: ["~/.a"], darwin: ["~/Library/a"]}`, OSPaths{Linux: []string{"~/.a"}, Darwin: []string{"~/.a", "~/Library/a"}}},
		{`{linux: ~}`, OSPaths{}},
		{`~`, OSPaths{}},
		{`[]`, OSPaths{Linux: []string{}, Darwin: []string{}, Windows: []string{}}},
	}
	for _, tc := range tests {
		var got OSPaths
		if err := yaml.Unmarshal([]byte(tc.yaml), &got); err != nil {
			t.Errorf("%s: %v", tc.yaml, err)
			continue
		}
		if len(got.Linux) != len(tc.want.Linux) || len(got.Darwin) != len(tc.want.Darwin) || len(got.Windows) != len(tc.want.Windows) ||
			strings.Join(got.Linux, "|") != strings.Join(tc.want.Linux, "|") ||
			strings.Join(got.Darwin, "|") != strings.Join(tc.want.Darwin, "|") ||
			strings.Join(got.Windows, "|") != strings.Join(tc.want.Windows, "|") {
			t.Errorf("%s decoded to %+v, want %+v", tc.yaml, got, tc.want)
		}
	}
	for _, bad := range []string{
		`{window: ["~/.a"]}`, `{macos: ["~/.a"]}`, `{linux: {a: b}}`, `42`, `true`, `[1, 2]`, `[["~/.a"]]`,
		`{linux: [1]}`, `{linux: 3.14}`, `[{a: b}]`,
	} {
		var got OSPaths
		if err := yaml.Unmarshal([]byte(bad), &got); err == nil {
			t.Errorf("%s decoded to %+v, want an error", bad, got)
		}
	}
	// The lists of the three OSes must not alias one another.
	var o OSPaths
	if err := yaml.Unmarshal([]byte(`["~/.a"]`), &o); err != nil {
		t.Fatal(err)
	}
	o.Linux[0] = "changed"
	if o.Darwin[0] != "~/.a" || o.Windows[0] != "~/.a" {
		t.Error("OS lists share one backing array")
	}
}

func TestBuildRules(t *testing.T) {
	const head = "version: \"2026.01.01\"\n"
	ok := []string{
		head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		// Mutual aliases allow a shared fingerprint; case of the id in aliases does not matter.
		head + "products:\n  - {id: a, name: A, kind: agent, binaries: [same], aliases: [B]}\n  - {id: b, name: B, kind: app, process_names: [Same], aliases: [a]}\n",
		// One product may repeat a value across its own fields.
		head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], process_names: [AAA]}\n",
		// The same path on two OS lists is one claim.
		head + "products:\n  - {id: a, name: A, kind: agent, state_dirs: {linux: ['~/.a'], darwin: ['~/.a']}}\n",
		// Ports, hosts and env markers are not exclusive.
		head + "products:\n  - {id: a, name: A, kind: model_runtime, binaries: [aaa], ports: [8080], api_hosts: [x.example], env_markers: [M]}\n  - {id: b, name: B, kind: model_runtime, binaries: [bbb], ports: [8080], api_hosts: [x.example], env_markers: [M]}\n",
		// Anchors and merge keys are understood by the strict checker.
		head + "products:\n  - id: a\n    name: A\n    kind: agent\n    binaries: [aaa]\n    settings:\n      - &s {file: ['~/.a/s.json'], format: json, key: k, op: eq, value: v, flag: f1, severity: low}\n      - {<<: *s, key: k2, flag: f2}\n",
	}
	for i, y := range ok {
		if _, err := buildFrom(t, y); err != nil {
			t.Errorf("valid catalog %d rejected: %v", i, err)
		}
	}

	bad := map[string]string{
		"duplicate id":                        head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n  - {id: a, name: A2, kind: agent, binaries: [bbb]}\n",
		"shared binary":                       head + "products:\n  - {id: a, name: A, kind: agent, binaries: [same]}\n  - {id: b, name: B, kind: agent, binaries: [same]}\n",
		"shared binary, case differs":         head + "products:\n  - {id: a, name: A, kind: agent, binaries: [same]}\n  - {id: b, name: B, kind: app, process_names: [SAME]}\n",
		"shared binary, one-sided alias":      head + "products:\n  - {id: a, name: A, kind: agent, binaries: [same], aliases: [b]}\n  - {id: b, name: B, kind: agent, binaries: [same]}\n",
		"shared package across managers":      head + "products:\n  - {id: a, name: A, kind: agent, packages: ['pip:some-pkg']}\n  - {id: b, name: B, kind: agent, packages: ['uv:Some_Pkg']}\n",
		"shared bundle id":                    head + "products:\n  - {id: a, name: A, kind: app, bundle_ids: [com.x.y]}\n  - {id: b, name: B, kind: app, bundle_ids: [COM.X.Y]}\n",
		"shared extension id":                 head + "products:\n  - {id: a, name: A, kind: ide_extension, extension_ids: [Pub.name]}\n  - {id: b, name: B, kind: ide_extension, extension_ids: [pub.NAME]}\n",
		"shared chrome id":                    head + "products:\n  - {id: a, name: A, kind: browser_extension, chrome_ids: [abcdefghijklmnopabcdefghijklmnop]}\n  - {id: b, name: B, kind: browser_extension, chrome_ids: [abcdefghijklmnopabcdefghijklmnop]}\n",
		"shared state dir":                    head + "products:\n  - {id: a, name: A, kind: agent, state_dirs: ['~/.same']}\n  - {id: b, name: B, kind: agent, state_dirs: {linux: ['~/.same/']}}\n",
		"shared install path":                 head + "products:\n  - {id: a, name: A, kind: agent, install_paths: ['~/.x/bin']}\n  - {id: b, name: B, kind: agent, install_paths: ['~/.x/bin']}\n",
		"shared windows display name":         head + "products:\n  - {id: a, name: A, kind: app, win_display: [Same App]}\n  - {id: b, name: B, kind: app, win_display: [same app]}\n",
		"no version anywhere":                 "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		"malformed version":                   "version: \"not a version!\"\nproducts:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		"missing name":                        head + "products:\n  - {id: a, kind: agent, binaries: [aaa]}\n",
		"missing kind":                        head + "products:\n  - {id: a, name: A, binaries: [aaa]}\n",
		"missing id":                          head + "products:\n  - {name: A, kind: agent, binaries: [aaa]}\n",
		"no fingerprint, only ports":          head + "products:\n  - {id: a, name: A, kind: model_runtime, ports: [8080], api_hosts: [x.example]}\n",
		"bad status":                          head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], status: dead}\n",
		"binary with .exe":                    head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa.exe]}\n",
		"binary named server":                 head + "products:\n  - {id: a, name: A, kind: model_runtime, binaries: [server]}\n",
		"process name python3":                head + "products:\n  - {id: a, name: A, kind: agent, process_names: [Python3]}\n",
		"repeated list entry":                 head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa, aaa]}\n",
		"padded list entry":                   head + "products:\n  - {id: a, name: A, kind: agent, binaries: [' aaa']}\n",
		"empty list entry":                    head + "products:\n  - {id: a, name: A, kind: agent, binaries: ['']}\n",
		"package without manager":             head + "products:\n  - {id: a, name: A, kind: agent, packages: [just-a-name]}\n",
		"package without name":                head + "products:\n  - {id: a, name: A, kind: agent, packages: ['npm:']}\n",
		"extension id without publisher":      head + "products:\n  - {id: a, name: A, kind: ide_extension, extension_ids: [nopublisher]}\n",
		"bundle id without dots":              head + "products:\n  - {id: a, name: A, kind: app, bundle_ids: [nodots]}\n",
		"short windows display pattern":       head + "products:\n  - {id: a, name: A, kind: app, win_display: ['^ab$']}\n",
		"relative state dir":                  head + "products:\n  - {id: a, name: A, kind: agent, state_dirs: ['relative/dir']}\n",
		"project-relative state dir":          head + "products:\n  - {id: a, name: A, kind: agent, state_dirs: ['./.a']}\n",
		"env name with a dash":                head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], env_markers: [NOT-A-VAR]}\n",
		"env name with a value":               head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], session_env: ['A=1']}\n",
		"api host with scheme":                head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], api_hosts: ['https://x.example']}\n",
		"api host uppercase":                  head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], api_hosts: [X.Example]}\n",
		"unknown capability":                  head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], capabilities: [flies]}\n",
		"source that is not a reference":      head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], sources: ['http://insecure.example']}\n",
		"unverified names no field":           head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], unverified: [sgners]}\n",
		"mcp without paths":                   head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], mcp: [{format: mcpServers, scope: user}]}\n",
		"mcp bad format":                      head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], mcp: [{paths: ['~/x'], format: xml, scope: user}]}\n",
		"mcp bad scope":                       head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], mcp: [{paths: ['~/x'], scope: global}]}\n",
		"mcp project path with a variable":    head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], mcp: [{project_paths: ['$HOME/x'], scope: project}]}\n",
		"mcp project path with a drive":       head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], mcp: [{project_paths: ['C:\\x'], scope: project}]}\n",
		"transcript without globs":            head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], transcript: {format: claude-jsonl}}\n",
		"transcript bad format":               head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], transcript: {format: 'Claude JSONL', globs: ['~/x']}}\n",
		"transcript bad home_env":             head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], transcript: {format: x, globs: ['~/x'], home_env: 'A B'}}\n",
		"hooks without paths":                 head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], hooks: {dialect: claude}}\n",
		"setting without key":                 head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, op: exists, flag: f}]}\n",
		"setting without flag":                head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, key: k, op: exists}]}\n",
		"setting eq without value":            head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, key: k, op: eq, flag: f}]}\n",
		"setting exists with a value":         head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, key: k, op: exists, value: v, flag: f}]}\n",
		"setting bad format":                  head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: ini, key: k, op: exists, flag: f}]}\n",
		"setting bad severity":                head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, key: k, op: exists, flag: f, severity: urgent}]}\n",
		"setting file missing":                head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{format: json, key: k, op: exists, flag: f}]}\n",
		"setting malformed key":               head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: json, key: 'a..b', op: exists, flag: f}]}\n",
		"env setting with a file":             head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: ['~/x'], format: env, key: K, op: exists, flag: f}]}\n",
		"env setting with a dotted key":       head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{format: env, key: a.b, op: exists, flag: f}]}\n",
		"registry setting on linux":           head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: {linux: ['HKLM\\X']}, format: registry, key: K, op: exists, flag: f}]}\n",
		"registry setting with a file path":   head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: {windows: ['C:\\x.json']}, format: registry, key: K, op: exists, flag: f}]}\n",
		"plist setting on windows":            head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], settings: [{file: {windows: ['C:\\x.plist']}, format: plist, key: K, op: exists, flag: f}]}\n",
		"bad team id":                         head + "products:\n  - {id: a, name: A, kind: app, bundle_ids: [com.x.y], signers: {darwin_team_id: short}}\n",
		"unknown signer key":                  head + "products:\n  - {id: a, name: A, kind: app, bundle_ids: [com.x.y], signers: {linux_key: x}}\n",
		"too many process_args":               head + "products:\n  - {id: a, name: A, kind: agent, process_args: [" + strings.TrimSuffix(strings.Repeat("'x1', ", 1)+manyPatterns(maxProcessArgs+1), ", ") + "]}\n",
		"ambiguous_names is not a list":       head + "ambiguous_names: 7\nproducts:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		"interpreters is not a map":           head + "interpreters: [ruby]\nproducts:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		"replace is not a bool":               head + "products:\n  - {id: a, name: A, kind: agent, binaries: [aaa], replace: maybe}\n",
		"merge key bringing an unknown field": head + "x: &x {bogus: 1}\nproducts:\n  - {<<: *x, id: a, name: A, kind: agent, binaries: [aaa]}\n",
	}
	for desc, y := range bad {
		t.Run(desc, func(t *testing.T) {
			snap, err := buildFrom(t, y)
			if err == nil {
				t.Fatalf("accepted; %d products", len(snap.products))
			}
			t.Logf("rejected with: %v", err)
			if !strings.HasPrefix(err.Error(), "catalog:") {
				t.Errorf("error lacks the package prefix: %v", err)
			}
			if len(err.Error()) > 16<<10 {
				t.Errorf("error message is %d bytes", len(err.Error()))
			}
		})
	}
}

func manyPatterns(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("'p" + itoa(i) + "x', ")
	}
	return b.String()
}

func TestErrorsAreBoundedAndNamed(t *testing.T) {
	// A file with hundreds of broken products reports a bounded number of
	// errors, each naming the product.
	var b strings.Builder
	b.WriteString("version: \"2026.01.01\"\nproducts:\n")
	for i := 0; i < 500; i++ {
		b.WriteString("  - {id: p" + itoa(i) + ", name: P, kind: nonsense, binaries: [b" + itoa(i) + "]}\n")
	}
	_, err := buildFrom(t, b.String())
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	if n := strings.Count(msg, "\n") + 1; n > maxErrors+1 {
		t.Errorf("%d error lines, limit is %d", n, maxErrors+1)
	}
	if !strings.Contains(msg, `product "p0"`) || !strings.Contains(msg, "more errors not shown") {
		t.Errorf("unexpected message: %.300s", msg)
	}
	// Parse errors carry the file name and a line number.
	_, err = parseFile("some/file.yaml", []byte("products:\n  - {id: a}\n  - {id: b, bogus: 1}\n"))
	if err == nil || !strings.Contains(err.Error(), "some/file.yaml") || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), `"bogus"`) {
		t.Errorf("parse error lacks context: %v", err)
	}
}

func TestVersionIsHighestAcrossFiles(t *testing.T) {
	snap, err := buildFrom(t,
		"version: \"2026.03.01\"\nproducts:\n  - {id: a, name: A, kind: agent, binaries: [aaa]}\n",
		"version: \"2026.11.11\"\nproducts:\n  - {id: b, name: B, kind: agent, binaries: [bbb]}\n",
		"version: \"2026.07.30\"\nproducts:\n  - {id: c, name: C, kind: agent, binaries: [ccc]}\n",
	)
	if err != nil {
		t.Fatal(err)
	}
	if snap.version != "2026.11.11" {
		t.Errorf("version = %q", snap.version)
	}
	// Products keep file order then position, which is the tie-break order.
	ids := []string{snap.products[0].ID, snap.products[1].ID, snap.products[2].ID}
	if !reflect.DeepEqual(ids, []string{"a", "b", "c"}) {
		t.Errorf("order = %v", ids)
	}
}

func TestTieBreakPrefersAgentThenOrder(t *testing.T) {
	snap, err := buildFrom(t, `version: "2026.01.01"
products:
  - {id: the-app, name: App, kind: app, process_names: [Shared], aliases: [the-agent, second-agent]}
  - {id: the-agent, name: Agent, kind: agent, binaries: [shared], aliases: [the-app, second-agent]}
  - {id: second-agent, name: Agent2, kind: agent, binaries: [shared], aliases: [the-app, the-agent]}
`)
	if err != nil {
		t.Fatal(err)
	}
	c := &Catalog{}
	c.snap.Store(snap)
	if p, ok := c.MatchProcess("shared", "", nil); !ok || p.ID != "the-agent" {
		t.Errorf("lowercase name: got %q, want the first agent", p.ID)
	}
	if p, ok := c.MatchProcess("Shared", "", nil); !ok || p.ID != "the-app" {
		t.Errorf("exact-case name: got %q, want the app that spells it that way", p.ID)
	}
	if p, ok := c.MatchProcess("SHARED.EXE", "", nil); !ok || p.ID != "the-agent" {
		t.Errorf("windows spelling: got %q", p.ID)
	}
}

// Guard against the data silently losing the properties the tests above
// rely on: flip one thing in a copy of the embedded data and expect the
// loader to object.
func TestEmbeddedDataMutationsAreCaught(t *testing.T) {
	read := func(name string) string {
		b, err := dataFS.ReadFile("data/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files := map[string]string{}
	for _, n := range []string{"agents.yaml", "browsers.yaml", "desktop.yaml", "extensions.yaml", "ides.yaml", "runtimes.yaml"} {
		files[n] = read(n)
	}
	build := func(mutated map[string]string) error {
		var all []string
		for _, n := range []string{"agents.yaml", "browsers.yaml", "desktop.yaml", "extensions.yaml", "ides.yaml", "runtimes.yaml"} {
			if m, ok := mutated[n]; ok {
				all = append(all, m)
			} else {
				all = append(all, files[n])
			}
		}
		_, err := buildFrom(t, all...)
		return err
	}
	if err := build(nil); err != nil {
		t.Fatalf("unmodified data does not build: %v", err)
	}
	mutations := []struct {
		desc, file, old, new string
	}{
		{"drop the alias that admits the shared claude name", "desktop.yaml", "aliases: [claude-code, cowork, Claude Cowork]", "aliases: [cowork, Claude Cowork]"},
		{"drop the alias that admits the shared ~/.codex", "desktop.yaml", "aliases: [chatgpt-desktop, codex-app, Codex desktop, codex]", "aliases: [chatgpt-desktop, codex-app, Codex desktop]"},
		{"give Ollama the generic name server", "runtimes.yaml", "binaries: [ollama]", "binaries: [ollama, server]"},
		{"misspell a field", "ides.yaml", "    bundle_ids: [dev.zed.Zed]", "    bundle_id: [dev.zed.Zed]"},
		{"claim another product's bundle id", "browsers.yaml", "bundle_ids: [company.thebrowser.dia]", "bundle_ids: [com.todesktop.230313mzl4w4u92]"},
		{"claim another product's extension", "extensions.yaml", "extension_ids: [supermaven.supermaven]", "extension_ids: [github.copilot]"},
		{"invent a hook dialect", "agents.yaml", "      dialect: gemini", "      dialect: qwen"},
	}
	for _, m := range mutations {
		t.Run(m.desc, func(t *testing.T) {
			if !strings.Contains(files[m.file], m.old) {
				t.Fatalf("the data no longer contains %q; update this test", m.old)
			}
			err := build(map[string]string{m.file: strings.Replace(files[m.file], m.old, m.new, 1)})
			if err == nil {
				t.Error("the loader accepted the mutated data")
			}
		})
	}
}
