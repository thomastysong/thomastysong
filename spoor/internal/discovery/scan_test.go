package discovery

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func scanFixture(t *testing.T) (*fx, *Result, fixtureIndex) {
	t.Helper()
	f := newFixture(t)
	f.plantMachine()
	res, err := Scan(context.Background(), f.opts(f.user("alice")))
	if err != nil {
		t.Fatal(err)
	}
	return f, res, fixtureIndex{events: res.Events}
}

func TestScanFixtureAgents(t *testing.T) {
	_, res, x := scanFixture(t)

	cc := x.one(t, event.AssetAgent, "claude-code")
	if cc.Version != "2.1.3" {
		t.Errorf("claude-code version = %q, want the package manifest's 2.1.3", cc.Version)
	}
	for _, ev := range []string{"package:npm", "binary", "path", "state_dir"} {
		if !has(cc.Evidence, ev) {
			t.Errorf("claude-code evidence %v lacks %s", cc.Evidence, ev)
		}
	}
	if cc.Confidence != "high" || cc.Owner != "alice" || cc.Scope != event.ScopeUser {
		t.Errorf("claude-code confidence/owner/scope = %s/%s/%s", cc.Confidence, cc.Owner, cc.Scope)
	}
	for _, fl := range []string{"bypass_permissions_default", "api_base_url_override", "project:bypass_permissions_default"} {
		if !has(cc.RiskFlags, fl) {
			t.Errorf("claude-code risk flags %v lack %s", cc.RiskFlags, fl)
		}
	}
	// The managed file locks bypass mode and makes managed hooks exclusive.
	for _, fl := range []string{"bypass_mode_not_locked", "managed_hooks_not_exclusive", flagManagedMissing} {
		if has(cc.RiskFlags, fl) {
			t.Errorf("claude-code risk flags %v must not hold %s", cc.RiskFlags, fl)
		}
	}
	if cc.Telemetry == nil || cc.Telemetry.Hooks != hooksManaged || cc.Telemetry.Transcript != transcriptFound || cc.Telemetry.NativeOTel != otelEnabled {
		t.Errorf("claude-code telemetry = %+v", cc.Telemetry)
	}
	if cc.SHA256 == "" || len(cc.ID) != 32 {
		t.Errorf("claude-code id/sha256 = %q/%q", cc.ID, cc.SHA256)
	}

	codex := x.one(t, event.AssetAgent, "codex")
	if codex.Version != "0.80.0" || !has(codex.RiskFlags, "approvals_disabled") {
		t.Errorf("codex = %s %v", codex.Version, codex.RiskFlags)
	}
	if codex.Telemetry == nil || codex.Telemetry.Hooks != hooksMissing || codex.Telemetry.Transcript != transcriptFound {
		t.Errorf("codex telemetry = %+v", codex.Telemetry)
	}

	gem := x.one(t, event.AssetAgent, "gemini-cli")
	if gem.Version != "0.10.1" || !has(gem.Evidence, "package:brew") {
		t.Errorf("gemini = %s %v", gem.Version, gem.Evidence)
	}
	if gem.Telemetry == nil || gem.Telemetry.Hooks != hooksDisabled || !has(gem.RiskFlags, "hooks_disabled") {
		t.Errorf("gemini telemetry/flags = %+v %v", gem.Telemetry, gem.RiskFlags)
	}
	if !has(gem.RiskFlags, flagManagedMissing) {
		t.Errorf("gemini flags %v lack %s (no system settings.json)", gem.RiskFlags, flagManagedMissing)
	}

	cop := x.one(t, event.AssetAgent, "copilot-cli")
	if cop.Telemetry == nil || cop.Telemetry.Hooks != hooksUser {
		t.Errorf("copilot telemetry = %+v", cop.Telemetry)
	}

	cur := x.one(t, event.AssetApp, "cursor")
	if !has(cur.Evidence, "desktop_id") {
		t.Errorf("cursor evidence = %v", cur.Evidence)
	}
	// ~/.cursor alone is shared by the IDE and the CLI: no CLI asset.
	if l := x.find(event.AssetAgent, "cursor-agent"); len(l) != 0 {
		t.Errorf("cursor-agent reported from a shared state dir alone: %+v", l[0])
	}

	ol := x.one(t, event.AssetModelRuntime, "ollama")
	if ol.Confidence != "high" || ol.Scope != event.ScopeUser {
		t.Errorf("ollama = %s %s %v", ol.Confidence, ol.Scope, ol.Evidence)
	}
	aider := x.one(t, event.AssetAgent, "aider")
	if aider.Version != "0.86.1" || !has(aider.Evidence, "package:pipx") {
		t.Errorf("aider = %s %v", aider.Version, aider.Evidence)
	}
	zed := x.one(t, event.AssetApp, "zed")
	if zed.Confidence != "low" {
		t.Errorf("zed from a state dir only: confidence %s", zed.Confidence)
	}

	// Editor extensions: newest version wins; JetBrains plugin from the jar.
	exts := x.find(event.AssetIDEExtension, "github-copilot")
	if len(exts) != 2 {
		t.Fatalf("github-copilot extensions = %d, want VS Code + JetBrains", len(exts))
	}
	for _, e := range exts {
		switch e.Parent {
		case "vscode":
			if e.Version != "0.30.0" || !has(e.Evidence, evExtension) {
				t.Errorf("vscode extension = %+v", e)
			}
		case "":
			if e.Version != "1.5.40" || !has(e.Evidence, evJetBrains) || e.Detail["ide"] != "IntelliJIdea2025.2" {
				t.Errorf("jetbrains plugin = %+v", e)
			}
		default:
			t.Errorf("unexpected parent %q", e.Parent)
		}
	}

	if res.Ledger.Roots < 2 || res.Ledger.Files == 0 {
		t.Errorf("ledger = %+v", res.Ledger)
	}
}

func TestScanFixtureNegativeControls(t *testing.T) {
	_, _, x := scanFixture(t)
	for _, e := range x.events {
		a := e.Asset
		if a.Kind == event.AssetMCPServer && strings.Contains(a.Path, "mcp_config.json") {
			t.Errorf("dangling symlink produced %s", a.Name)
		}
		if strings.Contains(a.Path, "mcp-config.json") {
			t.Errorf("FIFO config produced %s %s", a.Kind, a.Name)
		}
		low := strings.ToLower(a.Name + " " + a.CatalogID + " " + a.Path)
		for _, bad := range []string{"slack", "prettier", "goose", "shadow", "evil.md"} {
			if strings.Contains(low, bad) {
				t.Errorf("negative control %q produced %s %q at %s", bad, a.Kind, a.Name, a.Path)
			}
		}
	}
}

func TestScanFixtureMCP(t *testing.T) {
	_, _, x := scanFixture(t)
	fs := x.one(t, event.AssetMCPServer, "fs")
	if fs.Parent != "claude-code" || fs.Scope != event.ScopeUser || fs.MCP == nil || fs.MCP.Runner != "npx" {
		t.Errorf("fs = %+v %+v", fs, fs.MCP)
	}
	for _, fl := range []string{"unpinned_package", "remote_fetch_exec", "broad_filesystem"} {
		if !has(fs.RiskFlags, fl) {
			t.Errorf("fs flags %v lack %s", fs.RiskFlags, fl)
		}
	}
	if len(fs.SHA256) != 64 {
		t.Errorf("fs definition hash = %q", fs.SHA256)
	}
	if st := x.one(t, event.AssetMCPServer, "stage"); !has(st.RiskFlags, flagUntrustedLocation) {
		t.Errorf("stage (command in /tmp) flags = %v", st.RiskFlags)
	}
	if hd := x.one(t, event.AssetMCPServer, "hidden"); !has(hd.RiskFlags, flagUntrustedLocation) {
		t.Errorf("hidden (script in ~/.evil) flags = %v", hd.RiskFlags)
	}
	if fmtm := x.one(t, event.AssetMCPServer, "fmt-mcp"); fmtm.Scope != event.ScopePlugin {
		t.Errorf("plugin MCP scope = %s", fmtm.Scope)
	}
	lo := x.one(t, event.AssetMCPServer, "local-one")
	if lo.Scope != event.ScopeProject || lo.Detail["project"] != aliceProject || !has(lo.RiskFlags, "inline_secret") {
		t.Errorf("local-one = %+v", lo)
	}
	if c := x.one(t, event.AssetMCPServer, "corp-search"); c.Scope != event.ScopeManaged {
		t.Errorf("corp-search scope = %s", c.Scope)
	}
	br := x.one(t, event.AssetMCPServer, "browser")
	if br.Parent != "cursor-agent" || !strings.Contains(br.Detail["also_read_by"], "cursor") {
		t.Errorf("shared ~/.cursor/mcp.json: parent %q also %q", br.Parent, br.Detail["also_read_by"])
	}
	for _, n := range []string{"search", "gh", "zed-ctx", "oc", "proj-srv", "tool-srv", "remote", "vs-srv", "cont-srv"} {
		x.one(t, event.AssetMCPServer, n)
	}
	if s := x.one(t, event.AssetMCPServer, "sys-srv"); s.Scope != event.ScopeSystem || s.Owner != "" {
		t.Errorf("system-scope server = %s owner %q", s.Scope, s.Owner)
	}
	if pv := x.one(t, event.AssetMCPServer, "proj-vs"); pv.Scope != event.ScopeProject || !has(pv.RiskFlags, "plaintext_transport") {
		t.Errorf("project vscode server = %s %v", pv.Scope, pv.RiskFlags)
	}
}

func TestScanFixtureHooksSkillsRules(t *testing.T) {
	_, _, x := scanFixture(t)
	var spoorSeen, fetch, encoded, repo bool
	for _, e := range x.events {
		a := e.Asset
		if a.Kind != event.AssetHook {
			continue
		}
		if a.Detail["spoor"] == "true" {
			spoorSeen = true
			if a.Scope == event.ScopeManaged && a.Detail["spoor_agent"] != "claude-code" {
				t.Errorf("spoor hook agent = %q", a.Detail["spoor_agent"])
			}
		}
		if has(a.RiskFlags, flagHookRemoteFetchExec) && has(a.RiskFlags, flagHookNetworkTool) {
			fetch = true
		}
		if e.Content == nil || e.Content.FileContent == "" {
			t.Errorf("hook %s: command not carried in Content", a.Name)
		}
		if has(a.RiskFlags, flagHookEncoded) {
			encoded = true
		}
		if has(a.RiskFlags, flagHookRunsRepoScript) && a.Scope == event.ScopeProject {
			repo = true
		}
		if len(a.SHA256) != 64 {
			t.Errorf("hook %s has no definition hash", a.Name)
		}
	}
	if !spoorSeen || !fetch || !encoded || !repo {
		t.Errorf("hooks: spoor=%v fetch=%v encoded=%v repo=%v", spoorSeen, fetch, encoded, repo)
	}

	basic := x.one(t, event.AssetSkill, "basic")
	if basic.SHA256 != adrBasicHash {
		t.Errorf("skill folder hash = %s, want ADR golden %s", basic.SHA256, adrBasicHash)
	}
	if ps := x.one(t, event.AssetSkill, "proj-skill"); ps.Scope != event.ScopeProject {
		t.Errorf("project skill scope = %s", ps.Scope)
	}
	if fm := x.one(t, event.AssetSkill, "fmt"); fm.Scope != event.ScopePlugin || fm.Detail["plugin"] != "formatter@acme-market" {
		t.Errorf("plugin skill = %+v", fm)
	}

	var claudeMD *event.Asset
	for _, a := range x.find(event.AssetRulesFile, "CLAUDE.md") {
		if a.Scope == event.ScopeUser {
			claudeMD = a
		}
	}
	if claudeMD == nil {
		t.Fatal("user CLAUDE.md not found")
	}
	for _, fl := range []string{flagHiddenUnicode, flagDropperText, flagInjectionMarkers} {
		if !has(claudeMD.RiskFlags, fl) {
			t.Errorf("CLAUDE.md flags %v lack %s", claudeMD.RiskFlags, fl)
		}
	}
	x.one(t, event.AssetSubagent, "reviewer")
	x.one(t, event.AssetCommand, "ops:deploy")

	pl := x.one(t, event.AssetPlugin, "formatter@acme-market")
	if pl.Version != "1.2.0" || pl.Detail["pinned"] != "true" || pl.Detail["marketplace_repo"] != "acme/plugins" || pl.Detail["enabled"] != "true" {
		t.Errorf("plugin = %+v", pl.Detail)
	}
}

func TestScanFixtureProject(t *testing.T) {
	_, _, x := scanFixture(t)
	want := map[string][]string{
		".claude/settings.json":    {flagAutorunHook, flagEscalatePerms, flagBaseURLOverride, "bypass_permissions_default"},
		".gemini/settings.json":    {flagAutorunHook, flagEscalatePerms},
		".gemini/.env":             {flagBaseURLOverride},
		".codex/config.toml":       {flagAutorunHook, flagEscalatePerms},
		".cursor/hooks.json":       {flagAutorunHook},
		".cursor/rules/always.mdc": {flagAutorunRule},
		".vscode/tasks.json":       {flagAutorunTask},
		".vscode/settings.json":    {flagIDEExecPath, flagIDEAutoApprove},
		"app.code-workspace":       {flagIDEExecPath},
		".git/config":              {flagGitExecKey},
	}
	got := map[string]*event.Asset{}
	for _, e := range x.events {
		if a := e.Asset; a.Kind == event.AssetProjectConfig && a.Detail["project"] == aliceProject {
			got[a.Name] = a
		}
	}
	for name, flags := range want {
		a := got[name]
		if a == nil {
			t.Errorf("project_config %s missing", name)
			continue
		}
		for _, fl := range flags {
			if !has(a.RiskFlags, fl) {
				t.Errorf("%s flags %v lack %s", name, a.RiskFlags, fl)
			}
		}
	}
	if a := got[".cursor/rules/sometimes.mdc"]; a != nil {
		t.Errorf("alwaysApply: false flagged: %+v", a)
	}
	if g := got[".git/config"]; g != nil && !strings.Contains(g.Detail["keys"], "core.fsmonitor") {
		t.Errorf("git keys = %q", g.Detail["keys"])
	}
	if v := got[".vscode/settings.json"]; v != nil && strings.Contains(v.Detail["keys"], "git.path") {
		t.Errorf("an absolute executable path outside the workspace was flagged: %q", v.Detail["keys"])
	}
	ci := x.one(t, event.AssetCIAgent, "claude-code-action")
	if !has(ci.RiskFlags, flagCIUntrustedTrigger) || ci.Detail["action"] != "anthropics/claude-code-action" || ci.Detail["pinned"] != "false" {
		t.Errorf("ci agent = %+v", ci)
	}
	// Projects came from three agents' state; the traversal entry did not.
	projects := map[string]bool{}
	for _, e := range x.events {
		if p := e.Asset.Detail["project"]; p != "" {
			projects[p] = true
		}
	}
	for _, p := range []string{aliceProject, aliceProject2} {
		if !projects[p] {
			t.Errorf("project %s not scanned (have %v)", p, projects)
		}
	}
}

func TestScanFixtureNoCanaryLeaks(t *testing.T) {
	f, res, _ := scanFixture(t)
	if len(f.canaries) < 5 {
		t.Fatal("fixture planted too few canaries")
	}
	var all strings.Builder
	for _, e := range res.Events {
		b, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	for _, n := range res.Ledger.Notes {
		all.WriteString(n)
	}
	out := all.String()
	for _, c := range f.canaries {
		if strings.Contains(out, c) {
			t.Errorf("canary %s... leaked into serialized output", c[:16])
		}
		if strings.Contains(out, c[len(c)/2:]) {
			t.Errorf("canary tail %s... leaked into serialized output", c[:16])
		}
	}
}

func TestScanProjectFastPath(t *testing.T) {
	f := newFixture(t)
	f.plantMachine()
	start := time.Now()
	res, err := ScanProject(context.Background(), aliceProject, f.user("alice"), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	x := fixtureIndex{events: res.Events}
	x.one(t, event.AssetMCPServer, "proj-srv")
	x.one(t, event.AssetCIAgent, "claude-code-action")
	for _, e := range res.Events {
		if e.Asset.Scope != event.ScopeProject {
			t.Errorf("ScanProject reported a %s-scope %s %q", e.Asset.Scope, e.Asset.Kind, e.Asset.Name)
		}
	}
	// The spec target is 50 ms; the bound here is loose for slow CI.
	if took > 2*time.Second {
		t.Errorf("ScanProject took %v", took)
	}
	t.Logf("ScanProject: %v, %d records", took, len(res.Events))
	if _, err := ScanProject(context.Background(), "relative/dir", f.user("alice"), f.opts()); err == nil {
		t.Error("relative project dir accepted")
	}
}

func BenchmarkScanProject(b *testing.B) {
	f := newFixture(b)
	f.plantMachine()
	o := f.opts()
	u := f.user("alice")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScanProject(context.Background(), aliceProject, u, o); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScan(b *testing.B) {
	f := newFixture(b)
	f.plantMachine()
	o := f.opts(f.user("alice"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Scan(context.Background(), o); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDifferential(t *testing.T) {
	f := newFixture(t)
	f.plantMachine()
	o := f.opts(f.user("alice"))
	first, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	prev := map[string]string{}
	for _, e := range first.Events {
		if e.Asset.Change != event.ChangeNew {
			t.Fatalf("first scan change = %q", e.Asset.Change)
		}
		prev[e.Asset.ID] = e.Asset.SHA256
	}
	if first.Ledger.Errors != 0 {
		t.Fatalf("fixture scan has errors: %v", first.Ledger.Notes)
	}
	o.Prev = prev
	again, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Events) != 0 {
		for _, e := range again.Events {
			t.Errorf("unchanged rescan returned %s %s %q (change %s)", e.Asset.Kind, e.Asset.ID, e.Asset.Name, e.Asset.Change)
		}
	}
	o.Full = true
	full, _ := Scan(context.Background(), o)
	if len(full.Events) != len(first.Events) {
		t.Errorf("full snapshot = %d records, want %d", len(full.Events), len(first.Events))
	}
	for _, e := range full.Events {
		if e.Asset.Change != event.ChangeUnchanged {
			t.Errorf("full snapshot change = %q", e.Asset.Change)
		}
	}
	o.Full = false

	// A settings change makes the agent "changed"; a deleted skill "removed".
	f.file("/home/alice/.claude/settings.json", `{"permissions":{"defaultMode":"default"}}`, 0o644)
	if err := os.RemoveAll(f.real("/home/alice/.claude/agents/reviewer.md")); err != nil {
		t.Fatal(err)
	}
	third, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var changedAgent, removed bool
	for _, e := range third.Events {
		a := e.Asset
		if a.Kind == event.AssetAgent && a.CatalogID == "claude-code" && a.Change == event.ChangeChanged {
			changedAgent = true
		}
		if a.Change == event.ChangeRemoved {
			removed = true
			if a.Kind != "" || a.Name != "" {
				t.Errorf("removed record carries more than its id: %+v", a)
			}
		}
	}
	if !changedAgent || !removed {
		t.Errorf("changed agent=%v removed=%v in %d records", changedAgent, removed, len(third.Events))
	}
}

func TestDeadlineGivesPartialResult(t *testing.T) {
	f := newFixture(t)
	f.plantMachine()
	o := f.opts(f.user("alice"))
	o.Deadline = time.Nanosecond
	o.Prev = map[string]string{"deadbeef": "x"}
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ledger.Truncated {
		t.Error("deadline did not mark the ledger truncated")
	}
	for _, e := range res.Events {
		if e.Asset.Change == event.ChangeRemoved {
			t.Error("a truncated scan reported a removal")
		}
	}
}

// TestAmbiguousNameNeedsSecondEvidence: brew's goose (a migration tool)
// in /usr/bin is nothing; with goose's own state it is the agent.
func TestAmbiguousNameNeedsSecondEvidence(t *testing.T) {
	f := newFixture(t)
	f.file("/usr/bin/goose", "ELF", 0o755)
	f.dir("/home/alice")
	res, err := Scan(context.Background(), f.opts(f.user("alice")))
	if err != nil {
		t.Fatal(err)
	}
	if l := (fixtureIndex{events: res.Events}).find(event.AssetAgent, "goose"); len(l) != 0 {
		t.Fatalf("goose from an ambiguous binary alone: %+v", l[0])
	}
	f.file("/home/alice/.config/goose/config.yaml", "extensions:\n  goose-ext:\n    type: stdio\n    cmd: npx\n    args: [-y, goose-mcp]\n    enabled: true\n", 0o644)
	res, err = Scan(context.Background(), f.opts(f.user("alice")))
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	g := x.one(t, event.AssetAgent, "goose")
	if !has(g.Evidence, evBinary) || !has(g.Evidence, evStateDir) || g.Confidence != "high" {
		t.Errorf("goose = %v %s", g.Evidence, g.Confidence)
	}
	if m := x.one(t, event.AssetMCPServer, "goose-ext"); m.Parent != "goose" {
		t.Errorf("goose-ext parent = %s", m.Parent)
	}
}

func TestScanRequiresCatalog(t *testing.T) {
	if _, err := Scan(context.Background(), Options{}); err == nil {
		t.Error("nil catalog accepted")
	}
}
