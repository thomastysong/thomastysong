//go:build e2e

// The Fleet harness produces what deploy/fleet/verify.sh needs to check the
// generated Fleet content against a live Fleet server and osquery host:
// state databases written through state.Store.Apply from real-shaped
// events (the daemon's writer), fleetctl apply specs with a unique name
// prefix, the agent options with the ATC tables merged in, and the expected
// policy and label results per scenario. It never talks to Fleet itself.
//
//	SPOOR_E2E_FLEET=1 go test -tags e2e ./test/e2e -run Fleet -v
//
// runs it as a self-test into t.TempDir(). verify.sh sets SPOOR_FLEET_OUT
// (artifact directory), SPOOR_FLEET_DB (the path osquery reads),
// SPOOR_FLEET_BIN (the binary path the "installed" label looks for),
// SPOOR_FLEET_AGENT_OPTIONS (the server's current agent options as JSON),
// SPOOR_FLEET_PREFIX and SPOOR_FLEET_SCENARIO; those paths are the one
// place this test writes outside t.TempDir(), on explicit request.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/discovery"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/fleetgen"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/state"
)

// Scenarios verify.sh walks through, in order.
var fleetScenarios = []string{"healthy", "planted", "stale", "stale25h", "removed"}

type fleetEnv struct {
	out, db, bin, prefix, agentOptions, scenario string
}

func fleetSetup(t *testing.T) fleetEnv {
	t.Helper()
	if os.Getenv("SPOOR_E2E_FLEET") == "" {
		t.Skip("set SPOOR_E2E_FLEET=1 (deploy/fleet/verify.sh does)")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the Fleet harness builds POSIX paths")
	}
	e := fleetEnv{
		out:          os.Getenv("SPOOR_FLEET_OUT"),
		db:           os.Getenv("SPOOR_FLEET_DB"),
		bin:          os.Getenv("SPOOR_FLEET_BIN"),
		prefix:       os.Getenv("SPOOR_FLEET_PREFIX"),
		agentOptions: os.Getenv("SPOOR_FLEET_AGENT_OPTIONS"),
		scenario:     os.Getenv("SPOOR_FLEET_SCENARIO"),
	}
	if e.out == "" {
		e.out = t.TempDir()
	}
	if e.db == "" {
		e.db = filepath.Join(e.out, "data", "state.db")
	}
	if e.bin == "" {
		e.bin = filepath.Join(e.out, "bin", "spoor")
	}
	if e.prefix == "" {
		e.prefix = "spoor-c5-"
	}
	for _, p := range []string{e.out, e.db, e.bin} {
		if !filepath.IsAbs(p) {
			t.Fatalf("%s is not absolute", p)
		}
	}
	return e
}

func (e fleetEnv) options() fleetgen.Options {
	return fleetgen.Options{
		DBPaths:  map[string]string{fleetgen.PlatformLinux: e.db},
		BinPaths: map[string]string{fleetgen.PlatformLinux: e.bin},
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFleetContent writes the apply specs, the merged agent options, the
// list of tables to query and the expected results.
func TestFleetContent(t *testing.T) {
	e := fleetSetup(t)
	c, err := fleetgen.Build(e.options())
	if err != nil {
		t.Fatal(err)
	}
	stock, _ := c.Profile(fleetgen.ProfileStock)
	specs, err := fleetgen.ApplySpecs(stock, e.prefix)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.out, "specs.yml"), specs)

	current := map[string]any(nil)
	if e.agentOptions != "" {
		b, err := os.ReadFile(e.agentOptions)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &current); err != nil {
			t.Fatalf("%s: %v", e.agentOptions, err)
		}
	} else {
		current = fleetgen.ExampleBaseAgentOptions()
	}
	merged, err := c.MergeAgentOptions(current)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := fleetgen.AgentOptionsSpec(merged)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.out, "atc-apply.json"), spec)

	var tables []string
	for _, td := range state.Tables {
		tables = append(tables, td.OsqueryName())
	}
	writeFile(t, filepath.Join(e.out, "tables.txt"), []byte(strings.Join(tables, "\n")+"\n"))

	// Policy and report SQL for live queries (one file each, name first).
	var q strings.Builder
	for _, p := range stock.Policies {
		fmt.Fprintf(&q, "%s%s\t%s\n", e.prefix, p.Name, oneLine(p.Query))
	}
	writeFile(t, filepath.Join(e.out, "policies.tsv"), []byte(q.String()))
	q.Reset()
	for _, r := range append(append([]fleetgen.Report{}, stock.Reports...), c.OptIn...) {
		fmt.Fprintf(&q, "%s\t%s\t%s\n", r.Name, r.Platform, oneLine(r.Query))
	}
	writeFile(t, filepath.Join(e.out, "reports.tsv"), []byte(q.String()))

	exp := map[string]any{}
	for _, sc := range fleetScenarios {
		exp[sc] = expectations(stock, e.prefix, sc)
	}
	b, _ := json.MarshalIndent(exp, "", "  ")
	writeFile(t, filepath.Join(e.out, "expected.json"), append(b, '\n'))

	// The binary the "installed" label looks for. A placeholder file is
	// enough: the label reads osquery's file table, it never runs it.
	if _, err := os.Stat(e.bin); err != nil {
		writeFile(t, e.bin, []byte("#!/bin/sh\necho spoor placeholder for the Fleet verification\n"))
	}
	t.Logf("wrote %s", e.out)
}

func oneLine(q string) string {
	f := strings.Fields(q)
	return strings.Join(f, " ")
}

// expectations states the design: what each scenario must do to each
// policy and label of the stock profile.
func expectations(p fleetgen.Profile, prefix, scenario string) map[string]map[string]string {
	pol := map[string]string{}
	for _, x := range p.Policies {
		sensor := x.Key == "sensor_reporting"
		r := "pass"
		switch scenario {
		case "planted":
			if !sensor {
				r = "fail"
			}
		case "stale":
			if sensor {
				r = "fail"
			}
		case "stale25h", "removed":
			r = "fail"
		}
		pol[prefix+x.Name] = r
	}
	lab := map[string]string{
		prefix + "spoor installed":          "member",
		prefix + "AI agents present":        "member",
		prefix + "spoor sensor unhealthy":   "not member",
		prefix + "spoor tables unavailable": "not member",
	}
	switch scenario {
	case "stale", "stale25h":
		lab[prefix+"spoor sensor unhealthy"] = "member"
	case "removed":
		lab[prefix+"spoor sensor unhealthy"] = "member"
		lab[prefix+"AI agents present"] = "not member"
	}
	return map[string]map[string]string{"policies": pol, "labels": lab}
}

// TestFleetStateDB writes the scenario database at SPOOR_FLEET_DB (verify.sh)
// or, as a self-test, every scenario into t.TempDir() and checks it.
func TestFleetStateDB(t *testing.T) {
	e := fleetSetup(t)
	if e.scenario != "" {
		h := &harness{t: t, root: e.out, db: e.db, now: time.Now().UTC()}
		h.build(e.scenario)
		t.Logf("scenario %s written to %s", e.scenario, e.db)
		return
	}
	for _, sc := range fleetScenarios {
		t.Run(sc, func(t *testing.T) {
			dir := t.TempDir()
			h := &harness{t: t, root: dir, db: filepath.Join(dir, "data", "state.db"), now: time.Now().UTC()}
			h.build(sc)
			h.check(sc)
		})
	}
}

// harness writes one scenario through state.Store, as the daemon would.
type harness struct {
	t    *testing.T
	root string // scratch directory for planted projects
	db   string
	now  time.Time
	s    *state.Store
	user *event.User
	host *event.Host
}

func (h *harness) build(scenario string) {
	t := h.t
	// A scenario is a fresh database: remove the file and its sidecars
	// first. Never rename over it: a surviving -wal would be replayed over
	// the new file (state package doc).
	for _, suf := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(h.db + suf); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if scenario == "removed" {
		return
	}
	s, err := state.Open(h.db)
	if err != nil {
		t.Fatal(err)
	}
	h.s = s
	defer func() {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h.user = &event.User{Name: u.Username, ID: u.Uid}
	hostname, _ := os.Hostname()
	h.host = &event.Host{ID: "5e8102a2-f0ef-46ef-a315-39f770849362", Name: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH}

	switch scenario {
	case "healthy":
		h.healthy(time.Minute)
	case "planted":
		h.healthy(time.Minute)
		h.plant()
	case "stale":
		h.healthy(2 * time.Hour)
	case "stale25h":
		h.healthy(25 * time.Hour)
	default:
		t.Fatalf("unknown scenario %q (want one of %v)", scenario, fleetScenarios)
	}
}

func (h *harness) apply(evs ...*event.Event) {
	h.t.Helper()
	if err := h.s.Apply(evs); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) ev(kind event.Kind, typ string, src event.Source, ago time.Duration) *event.Event {
	e := event.New(kind, typ, src)
	e.TS = event.At(h.now.Add(-ago))
	e.Host = h.host
	e.User = h.user
	e.Integrity = event.IntegrityRoot
	e.Writer = "fleet-harness"
	return e
}

// asset is an inventory record shaped like discovery's (id from
// discovery.AssetID, owner, evidence, telemetry for agents).
func (h *harness) asset(a event.Asset) *event.Event {
	e := h.ev(event.KindInventory, event.TypeInventoryAsset, event.SourceScan, 0)
	a.Owner = h.user.Name
	a.ID = discovery.AssetID(h.host.ID, &a)
	a.Change = event.ChangeNew
	e.Asset = &a
	return e
}

func (h *harness) agent(catalogID, hooks string, flags ...string) *event.Event {
	return h.asset(event.Asset{
		Kind: event.AssetAgent, Name: catalogID, CatalogID: catalogID, Version: "2.1.3",
		Path: filepath.Join(h.root, "home", ".local", "bin", catalogID), Scope: event.ScopeUser,
		Evidence: []string{"path", "package:npm"}, Confidence: "high", RiskFlags: flags,
		Telemetry: &event.Telemetry{Hooks: hooks, Transcript: "tailing", NativeOTel: "disabled"},
	})
}

func (h *harness) heartbeat(ago time.Duration, bundle string) *event.Event {
	e := h.ev(event.KindHealth, event.TypeHealthHeartbeat, event.SourceSensor, ago)
	e.User = nil
	e.Privacy = "standard"
	e.Labels = map[string]string{
		state.LabelRulesVersion: "2026.11.11", state.LabelBundleVersion: bundle, state.LabelHostIDSource: "osquery",
	}
	e.Health = &event.Health{SensorVersion: "0.1.0-fleet-harness", Mode: "daemon", UptimeS: 7200,
		RulesCount: 132, RulesHash: "5d1c0e7a", CatalogVer: "2026.11.11",
		Counters: map[string]uint64{"stream.detection.emitted": 1, "stream.activity.emitted": 40},
		Surfaces: []event.SurfaceStatus{{Name: "hooks", Status: "ok", Events: 40}, {Name: "transcripts", Status: "ok", Events: 38}}}
	return e
}

// healthy is a host where every policy passes: managed hooks, a pinned MCP
// server, only a low detection, no bypass, covered agents, a complete scan
// and a current bundle. beatAgo sets the heartbeat age.
func (h *harness) healthy(beatAgo time.Duration) {
	t := h.t
	claude := h.agent("claude-code", "managed", "managed_policy_present")
	codex := h.agent("codex", "managed")
	mcp := h.asset(event.Asset{
		Kind: event.AssetMCPServer, Name: "filesystem", Parent: "claude-code", Scope: event.ScopeUser,
		Path: filepath.Join(h.root, "home", ".claude.json"), SHA256: "4b8a",
		MCP: &event.MCP{Transport: "stdio", Command: "npx", Runner: "npx", Ecosystem: "npm",
			Package: "@modelcontextprotocol/server-filesystem", Version: "2025.8.21", Pinned: true, AuthMode: "none"},
	})
	skill := h.asset(event.Asset{Kind: event.AssetSkill, Name: "release-notes", Parent: "claude-code",
		Scope: event.ScopeUser, Path: filepath.Join(h.root, "home", ".claude", "skills", "release-notes"), SHA256: "77aa"})
	det := h.ev(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor, 5*time.Minute)
	det.Agent = &event.Agent{ID: "claude-code"}
	det.Session = &event.Session{ID: "0c6f-healthy"}
	det.Detection = &event.Detection{RuleID: "SPR-NET-004", Title: "Agent fetched from a first-seen host",
		Class: event.ClassFinding, Severity: event.SevLow, Confidence: "medium", Maturity: "experimental",
		Category: "exfiltration", Tags: []string{"attack.t1105"}, DedupKey: "net-004-healthy", Count: 1}
	sum := h.ev(event.KindSummary, event.TypeSessionSummary, event.SourceSensor, 0)
	sum.Agent = &event.Agent{ID: "claude-code"}
	sum.Session = &event.Session{ID: "0c6f-healthy", PermissionMode: "default"}
	sum.Summary = &event.Summary{Started: event.At(h.now.Add(-40 * time.Minute)), Events: 31,
		ToolCalls: map[string]int{"shell": 9, "file_edit": 6}, Surfaces: []event.Source{event.SourceHook, event.SourceTranscript},
		Coverage: "covered", Detections: []string{"SPR-NET-004"}, MaxSeverity: event.SevLow}
	h.apply(claude, codex, mcp, skill, det, sum)
	if err := h.s.SetAgentProcesses([]state.AgentProcess{{
		PID: os.Getpid(), StartTime: h.now.Add(-time.Hour), AgentID: "claude-code", User: h.user.Name,
		UserID: h.user.ID, Exe: claude.Asset.Path, Flags: []string{"--permission-mode acceptEdits"}, SessionID: "0c6f-healthy",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.SetCoverage([]event.Coverage{
		{AgentID: "claude-code", User: h.user.Name, Hooks: "managed", Transcript: "tailing", Processes: 1, State: "covered"},
		{AgentID: "codex", User: h.user.Name, Hooks: "managed", Transcript: "found", State: "absent"},
	}); err != nil {
		t.Fatal(err)
	}
	ids := []string{claude.Asset.ID, codex.Asset.ID, mcp.Asset.ID, skill.Asset.ID}
	if err := h.s.MarkScan(h.now.Add(-2*time.Minute), h.now.Add(-time.Minute), ids); err != nil {
		t.Fatal(err)
	}
	h.apply(h.heartbeat(beatAgo, "3"))
}

// plant adds one violation for every "no X" policy. The project auto-run
// files and the unpinned MCP server come from discovery's real project
// scan of planted files; the rest are records shaped as their producers
// emit them.
func (h *harness) plant() {
	t := h.t
	proj := filepath.Join(h.root, "home", "src", "planted-repo")
	files := map[string]string{
		".vscode/tasks.json": `{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"./setup.sh","runOptions":{"runOn":"folderOpen"}}]}`,
		".git/config":        "[core]\n\tfsmonitor = ./hook.sh\n",
		".mcp.json":          `{"mcpServers":{"helper":{"command":"npx","args":["-y","totally-legit-mcp"],"env":{"API_TOKEN":"sk-live-0123456789abcdef0123456789abcdef"}}}}`,
	}
	for rel, body := range files {
		writeFile(t, filepath.Join(proj, filepath.FromSlash(rel)), []byte(body))
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := discovery.ScanProject(context.Background(), proj,
		platform.UserHome{Name: h.user.Name, UID: strconv.Itoa(os.Getuid()), Home: filepath.Join(h.root, "home")},
		discovery.Options{Catalog: cat, Host: h.host})
	if err != nil {
		t.Fatal(err)
	}
	var autorun, risky bool
	for _, ev := range res.Events {
		if ev.Asset == nil {
			continue
		}
		for _, f := range ev.Asset.RiskFlags {
			autorun = autorun || ev.Asset.Kind == event.AssetProjectConfig && strings.HasPrefix(f, "autorun_")
			risky = risky || ev.Asset.Kind == event.AssetMCPServer && f == "unpinned_package"
		}
	}
	if !autorun || !risky {
		t.Fatalf("project scan did not flag the planted files (autorun %v, unpinned MCP %v): %+v", autorun, risky, res.Ledger)
	}
	h.apply(res.Events...)

	gemini := h.agent("gemini-cli", "missing")
	codex := h.agent("codex", "managed", "approvals_disabled")
	det := h.ev(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor, time.Minute)
	det.Agent = &event.Agent{ID: "claude-code"}
	det.Session = &event.Session{ID: "9e1a-planted"}
	det.Detection = &event.Detection{RuleID: "SPR-EXEC-001", Title: "Remote script piped to a shell",
		Class: event.ClassAlert, Severity: event.SevHigh, Confidence: "high", Maturity: "stable",
		Category: "execution", Tags: []string{"attack.t1059.004", "owasp.asi05"}, Response: "ask",
		DedupKey: "exec-001-planted", Count: 1}
	sum := h.ev(event.KindSummary, event.TypeSessionSummary, event.SourceSensor, 0)
	sum.Agent = &event.Agent{ID: "claude-code"}
	sum.Session = &event.Session{ID: "9e1a-planted", PermissionMode: "bypass"}
	sum.Summary = &event.Summary{Started: event.At(h.now.Add(-10 * time.Minute)), Events: 5,
		ToolCalls: map[string]int{"shell": 2}, Surfaces: []event.Source{event.SourceTranscript}, Coverage: "partial",
		Detections: []string{"SPR-EXEC-001"}, MaxSeverity: event.SevHigh}
	post := h.ev(event.KindPosture, event.TypePostureCheck, event.SourceScan, 0)
	post.Check = &event.Check{ID: "SPR-POST-003", Title: "Bypass mode is the default", Status: "fail",
		Severity: event.SevHigh, AgentID: "claude-code", Scope: event.ScopeUser, Subject: "permissions.defaultMode",
		Owner: h.user.Name, Actual: "bypassPermissions", Remedy: "Set permissions.disableBypassPermissionsMode in managed settings."}
	h.apply(gemini, codex, det, sum, post, h.heartbeat(0, "0"))
	if err := h.s.SetAgentProcesses([]state.AgentProcess{{
		PID: os.Getpid(), StartTime: h.now.Add(-time.Hour), AgentID: "claude-code", User: h.user.Name,
		UserID: h.user.ID, Exe: "/usr/local/bin/claude", Flags: []string{"--dangerously-skip-permissions"},
		SessionID: "9e1a-planted",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := h.s.SetCoverage([]event.Coverage{{AgentID: "claude-code", User: h.user.Name,
		Hooks: "missing", Transcript: "none", Processes: 1, State: "blind"}}); err != nil {
		t.Fatal(err)
	}
	// A scan that hit its deadline.
	if err := h.s.MarkScan(h.now, time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
}

// check is the self-test: the rows each scenario must contain.
func (h *harness) check(scenario string) {
	t := h.t
	if scenario == "removed" {
		if _, err := os.Stat(h.db); !os.IsNotExist(err) {
			t.Fatalf("removed scenario left %s", h.db)
		}
		return
	}
	s, err := state.OpenReadOnly(h.db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := func(table string) []map[string]string {
		rows, err := s.Query(table, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	hb := q("health")
	if len(hb) != 1 {
		t.Fatalf("health rows %d", len(hb))
	}
	age := map[string]time.Duration{"healthy": time.Minute, "planted": 0, "stale": 2 * time.Hour, "stale25h": 25 * time.Hour}[scenario]
	beat, err := time.Parse(state.TimeFormat, hb[0]["heartbeat"])
	if err != nil {
		t.Fatal(err)
	}
	if d := h.now.Sub(beat); d < age-time.Second || d > age+time.Minute {
		t.Errorf("heartbeat age %v, want about %v", d, age)
	}
	var tables []string
	for _, td := range state.Tables {
		if n := len(q(td.Name)); n == 0 {
			tables = append(tables, td.Name)
		}
	}
	sort.Strings(tables)
	if scenario != "planted" && strings.Join(tables, ",") != "posture" {
		t.Errorf("%s: empty tables %v, want only posture", scenario, tables)
	}
	if scenario == "planted" {
		if len(tables) != 0 {
			t.Errorf("planted: empty tables %v", tables)
		}
		if hb[0]["bundle_version"] != "0" || hb[0]["scan_complete"] != "0" {
			t.Errorf("planted health row %v", hb[0])
		}
	}
}
