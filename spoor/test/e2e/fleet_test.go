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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

// binaryScenarios exist only with a real spoor binary (verify.sh with
// SPOOR_BIN): "hook" is a healthy host plus one real high detection, a
// curl | sh tool call recorded by `spoor hook` and detected by `spoor run`.
// The harness writes their expectations, never their databases.
var binaryScenarios = []string{"hook"}

// detectionsPolicyKey is the only stock policy the "hook" scenario fails.
const detectionsPolicyKey = "no_high_detections_24h"

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
	writeFile(t, filepath.Join(e.out, "atc-apply.yml"), spec)

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
	for _, sc := range append(append([]string{}, fleetScenarios...), binaryScenarios...) {
		exp[sc] = expectations(stock, e.prefix, sc)
	}
	found := false
	for _, p := range stock.Policies {
		found = found || p.Key == detectionsPolicyKey
	}
	if !found {
		t.Fatalf("no stock policy %q: the hook scenario's expectations would be wrong", detectionsPolicyKey)
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
		case "hook":
			if x.Key == detectionsPolicyKey {
				r = "fail"
			}
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

// fleetScriptImage is a local Debian image (no Docker Hub pulls here).
const fleetScriptImage = "mirror.gcr.io/library/redis:7"

// TestFleetInstallScripts runs the Fleet install, uninstall and
// post-install scripts in a throwaway Debian container with fake
// systemctl and spoor binaries, under SPOOR_ROOT so nothing outside the
// mounted directory changes. It checks: a wrong SHA-256 installs nothing;
// the extension tier refuses a host where orbit's extensions.load is in use
// (orbit then overrides osquery's autoload file) and installs nothing;
// install writes the binary, extension, unit and osquery's default
// extensions.load (other lines kept, also a last line without a newline)
// and schedules a detached osquery restart; a second run changes nothing;
// orbit's extensions.load is never written; the atc tier unregisters and
// works with orbit's file in use; uninstall is idempotent and keeps data.
func TestFleetInstallScripts(t *testing.T) {
	if os.Getenv("SPOOR_E2E_FLEET") == "" {
		t.Skip("set SPOOR_E2E_FLEET=1 (needs docker and " + fleetScriptImage + ")")
	}
	if err := exec.Command("docker", "image", "inspect", fleetScriptImage).Run(); err != nil {
		t.Skipf("image %s not available: %v", fleetScriptImage, err)
	}
	_, file, _, _ := runtime.Caller(0)
	scripts := filepath.Join(filepath.Dir(file), "..", "..", "deploy", "fleet", "scripts")
	work := t.TempDir()
	fake := filepath.Join(work, "fakebin")
	spoorBin := "#!/bin/sh\n# fake spoor\ncase \"$1 $2\" in\n\"export config\") printf 'data_dir: /var/lib/spoor\\n' > \"$4\" ;;\n\"version \") echo spoor-fake-1 ;;\nesac\n"
	writeFile(t, filepath.Join(work, "spoor"), []byte(spoorBin))
	writeFile(t, filepath.Join(fake, "systemctl"), []byte("#!/bin/sh\necho \"systemctl $*\" >> /work/systemctl.log\n"+
		"[ \"$1 $2\" = \"cat orbit.service\" ] && [ ! -f /work/orbit ] && exit 1\nexit 0\n"))
	for _, p := range []string{filepath.Join(fake, "systemctl"), filepath.Join(work, "spoor")} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(work, "root")
	orbitLoad := filepath.Join(root, "opt", "orbit", "extensions.load")
	const orbitManaged = "/opt/orbit/bin/extensions/fleet.ext\n"
	writeFile(t, orbitLoad, nil)
	load := filepath.Join(root, "etc", "osquery", "extensions.load")
	// No final newline: registration must not glue spoor's line to it.
	writeFile(t, load, []byte("/usr/lib/other/other.ext"))

	name := fmt.Sprintf("spoor-c5-scripts-%d", os.Getpid())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--network", "none",
		"-v", scripts+":/scripts:ro", "-v", work+":/work", fleetScriptImage, "sleep", "600").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })

	sum := sha256Hex(t, filepath.Join(work, "spoor"))
	run := func(script string, env ...string) (string, int) {
		t.Helper()
		args := []string{"exec"}
		base := []string{"PATH=/work/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"SPOOR_ROOT=/work/root", "SPOOR_SRC=/work/spoor",
			"SPOOR_SHA256_LINUX_AMD64=" + sum, "SPOOR_SHA256_LINUX_ARM64=" + sum}
		for _, e := range append(base, env...) {
			args = append(args, "-e", e)
		}
		args = append(args, name, "sh", "/scripts/"+script)
		cmd := exec.Command("docker", args...)
		b, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(b), code
	}
	readLog := func() string {
		b, _ := os.ReadFile(filepath.Join(work, "systemctl.log"))
		os.Remove(filepath.Join(work, "systemctl.log"))
		return string(b)
	}
	lines := func(p string) []string {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		return strings.Fields(string(b))
	}
	ext := "/work/root/usr/lib/spoor/spoor.ext"

	// 1. Wrong hash: nothing installed.
	o, code := run("install-spoor.sh", "SPOOR_SHA256_LINUX_AMD64="+strings.Repeat("0", 64), "SPOOR_SHA256_LINUX_ARM64="+strings.Repeat("0", 64))
	if code == 0 || !strings.Contains(o, "SHA-256 mismatch") {
		t.Fatalf("wrong hash: exit %d\n%s", code, o)
	}
	if _, err := os.Stat(filepath.Join(root, "usr", "bin", "spoor")); !os.IsNotExist(err) {
		t.Fatal("binary installed despite a hash mismatch")
	}
	// 2. orbit manages extensions on this host: osquery would never read
	// its default autoload file, so the extension tier refuses, and so
	// does the packages' post-install script.
	writeFile(t, orbitLoad, []byte(orbitManaged))
	o, code = run("install-spoor.sh")
	if code == 0 || !strings.Contains(o, "osquery ignores /work/root/etc/osquery/extensions.load") {
		t.Fatalf("extension tier with orbit's extensions.load in use: exit %d\n%s", code, o)
	}
	if _, err := os.Stat(filepath.Join(root, "usr", "bin", "spoor")); !os.IsNotExist(err) {
		t.Fatal("binary installed although the extension tier was refused")
	}
	writeFile(t, filepath.Join(root, "usr", "bin", "spoor"), []byte(spoorBin))
	os.Chmod(filepath.Join(root, "usr", "bin", "spoor"), 0o755)
	if o, code = run("register-extension.sh"); code == 0 || !strings.Contains(o, "osquery ignores") {
		t.Errorf("register-extension with orbit's extensions.load in use: exit %d\n%s", code, o)
	}
	os.Remove(filepath.Join(root, "usr", "bin", "spoor"))
	if b, _ := os.ReadFile(load); string(b) != "/usr/lib/other/other.ext" {
		t.Fatalf("refused runs changed extensions.load: %q", b)
	}
	readLog()
	// orbit installed, but no extension managed by Fleet: its file is empty
	// and osquery reads the default one.
	writeFile(t, orbitLoad, nil)
	// 3. Install.
	o, code = run("install-spoor.sh")
	t.Logf("install:\n%s", o)
	if code != 0 || !strings.Contains(o, "osquery (osqueryd) restarts in 10 s") {
		t.Fatalf("install: exit %d\n%s", code, o)
	}
	log := readLog()
	for _, w := range []string{"systemctl daemon-reload", "systemctl enable spoor", "systemctl restart spoor"} {
		if !strings.Contains(log, w) {
			t.Errorf("install did not run %q:\n%s", w, log)
		}
	}
	if b, _ := os.ReadFile(load); string(b) != "/usr/lib/other/other.ext\n"+ext+"\n" {
		t.Errorf("extensions.load = %q", b)
	}
	for p, mode := range map[string]os.FileMode{
		filepath.Join(root, "usr", "bin", "spoor"):                                                 0o755,
		filepath.Join(root, "usr", "lib", "spoor", "spoor.ext"):                                    0o755,
		filepath.Join(root, "etc", "systemd", "system", "spoor.service"):                           0o644,
		filepath.Join(root, "etc", "systemd", "system", "spoor.service.d", "10-outbox-group.conf"): 0o644,
		filepath.Join(root, "var", "lib", "spoor"):                                                 0o750 | os.ModeDir,
		load: 0o644,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if fi.Mode()&(os.ModePerm|os.ModeDir) != mode {
			t.Errorf("%s: mode %v, want %v", p, fi.Mode(), mode)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "spoor", "spoor.yaml")); !strings.Contains(string(b), "data_dir") {
		t.Error("config not written with `spoor export config`")
	}
	// StateDirectory= re-owns the data directory to the service's group at
	// each start, so the service runs with the outbox readers' group.
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "systemd", "system", "spoor.service.d", "10-outbox-group.conf")); string(b) != "[Service]\nGroup=spoor\n" {
		t.Errorf("group drop-in = %q", b)
	}
	// 4. Again: nothing changes, the service is only started.
	o, code = run("install-spoor.sh")
	log = readLog()
	if code != 0 || strings.Contains(o, "restarts in 10 s") || strings.Contains(log, "restart spoor") || !strings.Contains(log, "systemctl start spoor") {
		t.Errorf("second install not idempotent: exit %d\n%s\n%s", code, o, log)
	}
	if got := lines(load); len(got) != 2 {
		t.Errorf("extensions.load after second run: %v", got)
	}
	// 5. With orbit present, orbit is what restarts; the atc tier does not
	// need osquery's autoload file, so orbit's file being in use is fine.
	writeFile(t, filepath.Join(work, "orbit"), nil)
	writeFile(t, orbitLoad, []byte(orbitManaged))
	if o, code = run("install-spoor.sh", "SPOOR_TIER=atc"); code != 0 || !strings.Contains(o, "osquery (orbit) restarts") {
		t.Errorf("atc tier with orbit: exit %d\n%s", code, o)
	}
	if got := lines(load); strings.Join(got, ",") != "/usr/lib/other/other.ext" {
		t.Errorf("atc tier left %v", got)
	}
	readLog()
	writeFile(t, orbitLoad, nil)
	// 6. Post-install registration of a packaged binary, twice.
	if o, code = run("register-extension.sh"); code != 0 || !strings.Contains(o, "restarts in 10 s") {
		t.Errorf("register-extension: exit %d\n%s", code, o)
	}
	if o, _ = run("register-extension.sh"); strings.Contains(o, "restarts") {
		t.Errorf("register-extension not idempotent:\n%s", o)
	}
	if got := lines(load); len(got) != 2 {
		t.Errorf("after register-extension: %v", got)
	}
	// 7. Uninstall, twice: data kept, other autoload lines kept.
	if o, code = run("uninstall-spoor.sh"); code != 0 || !strings.Contains(o, "restarts in 10 s") {
		t.Errorf("uninstall: exit %d\n%s", code, o)
	}
	if o, code = run("uninstall-spoor.sh"); code != 0 || strings.Contains(o, "restarts") {
		t.Errorf("second uninstall: exit %d\n%s", code, o)
	}
	for _, p := range []string{"usr/bin/spoor", "usr/lib/spoor/spoor.ext", "etc/systemd/system/spoor.service", "etc/systemd/system/spoor.service.d"} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Errorf("%s left after uninstall", p)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "spoor", "spoor.yaml")); err != nil {
		t.Error("uninstall removed the configuration without SPOOR_PURGE")
	}
	if got := lines(load); strings.Join(got, ",") != "/usr/lib/other/other.ext" {
		t.Errorf("extensions.load after uninstall: %v", got)
	}
	if b, err := os.ReadFile(orbitLoad); err != nil || len(b) != 0 {
		t.Errorf("orbit's extensions.load was modified: %q, %v", b, err)
	}
}

func sha256Hex(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
