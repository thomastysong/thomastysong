package fleetgen

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/discovery"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/mcpconf"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func loadCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestCatalogFlagsClassified fails when the catalog gains a command-line
// switch or a setting flag the bypass policy has not classified: a new
// flag is a decision, never a silent gap.
func TestCatalogFlagsClassified(t *testing.T) {
	c := loadCatalog(t)
	for f := range bypassArgs {
		if _, both := nonBypassArgs[f]; both {
			t.Errorf("switch %q is classified both ways", f)
		}
	}
	for f := range bypassSettings {
		if _, both := nonBypassSettings[f]; both {
			t.Errorf("setting flag %q is classified both ways", f)
		}
	}
	seenArgs, seenSettings := map[string]bool{}, map[string]bool{}
	for _, p := range c.Products() {
		for _, f := range p.RiskyFlags {
			seenArgs[f] = true
			_, b := bypassArgs[f]
			_, n := nonBypassArgs[f]
			if !b && !n {
				t.Errorf("catalog %s: switch %q is not classified in vocab.go (bypassArgs or nonBypassArgs)", p.ID, f)
			}
		}
		for _, s := range p.Settings {
			seenSettings[s.Flag] = true
			_, b := bypassSettings[s.Flag]
			_, n := nonBypassSettings[s.Flag]
			if !b && !n {
				t.Errorf("catalog %s: setting flag %q is not classified in vocab.go", p.ID, s.Flag)
			}
		}
	}
	// Entries the catalog no longer has are dead weight in the SQL.
	for f := range bypassArgs {
		if !seenArgs[f] {
			t.Errorf("bypass switch %q is not in the catalog any more", f)
		}
	}
	for f := range bypassSettings {
		if !seenSettings[f] {
			t.Errorf("bypass setting %q is not in the catalog any more", f)
		}
	}
	for _, f := range []string{"--dangerously-skip-permissions", "--yolo", "--dangerously-bypass-approvals-and-sandbox"} {
		if _, ok := bypassArgs[f]; !ok {
			t.Errorf("%s must count as a bypass", f)
		}
	}
	if _, ok := bypassArgs["--bare"]; ok {
		t.Error("--bare is an attribute, not a bypass (design/BUILD-B.md, Addendum 2)")
	}
}

func TestHookAgentsFromCatalog(t *testing.T) {
	c := loadCatalog(t)
	v := vocabularyOf(c)
	var want []string
	for _, p := range c.Products() {
		if p.Hooks != nil && p.Hooks.Dialect != "" {
			want = append(want, p.ID)
		}
	}
	sort.Strings(want)
	if strings.Join(v.hookAgents, ",") != strings.Join(want, ",") || len(want) == 0 {
		t.Errorf("hook agents %v, catalog %v", v.hookAgents, want)
	}
	if v.catalogVersion != c.Version() {
		t.Error("catalog version not carried")
	}
}

// TestMCPFlagsExist holds riskyMCPFlags to internal/mcpconf.
func TestMCPFlagsExist(t *testing.T) {
	known := map[string]bool{
		mcpconf.RiskUnpinnedPackage: true, mcpconf.RiskInlineSecret: true, mcpconf.RiskTokenInURL: true,
	}
	for _, f := range riskyMCPFlags {
		if !known[f] {
			t.Errorf("MCP flag %q is not an mcpconf risk flag", f)
		}
	}
}

// TestAutorunFlagsFromDiscovery plants one file per auto-run class in a
// project, runs the real project scan, and checks that every flag the
// policy matches is one discovery emits on a project_config asset, and
// that the scan's events trip the policy SQL through the state database.
func TestAutorunFlagsFromDiscovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Discovery's owner gate compares the file owner with the user's
		// uid, which has no POSIX form there.
		t.Skip("project ownership gate needs a POSIX uid")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "src", "app")
	plant(t, proj, map[string]string{
		".claude/settings.json": `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./x.sh"}]}]}}`,
		".cursor/rules/a.mdc":   "---\nalwaysApply: true\n---\nalways do x\n",
		".vscode/tasks.json":    `{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"./setup.sh","runOptions":{"runOn":"folderOpen"}}]}`,
		".vscode/settings.json": `{"python.defaultInterpreterPath":"./venv/bin/python"}`,
		".git/config":           "[core]\n\tfsmonitor = ./hook.sh\n",
		".mcp.json":             `{"mcpServers":{"x":{"command":"npx","args":["-y","some-mcp-server"]}}}`,
	})
	res, err := discovery.ScanProject(context.Background(), proj,
		platform.UserHome{Name: "ana", UID: strconv.Itoa(os.Getuid()), Home: home},
		discovery.Options{Catalog: loadCatalog(t), Host: fixtureHost})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ledger: %+v", res.Ledger)
	emitted := map[string]bool{}
	mcpFlags := map[string]bool{}
	f := newFixture(t)
	f.healthy()
	for _, e := range res.Events {
		if e.Asset == nil {
			continue
		}
		switch e.Asset.Kind {
		case event.AssetProjectConfig:
			for _, fl := range e.Asset.RiskFlags {
				emitted[fl] = true
			}
		case event.AssetMCPServer:
			for _, fl := range e.Asset.RiskFlags {
				mcpFlags[fl] = true
			}
		}
		f.apply(e)
	}
	for _, fl := range autorunFlags {
		if !emitted[fl] {
			t.Errorf("auto-run flag %q was not emitted by a project scan (emitted %v)", fl, emitted)
		}
	}
	if !mcpFlags[mcpconf.RiskUnpinnedPackage] {
		t.Errorf("npx -y server not flagged unpinned: %v", mcpFlags)
	}
	e := newEmu(t, f.close(), atcFlavour)
	got := failing(policyResults(e, mustProfile(t, mustBuild(t, Options{}), ProfileStock)))
	if strings.Join(got, ",") != "no_autorun_plant,no_risky_mcp" {
		t.Errorf("planted project: failing %v, want no_autorun_plant and no_risky_mcp", got)
	}
}

func plant(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
