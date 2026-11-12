package fleetgen

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

// host is the fixture's host; the fields mirror what the daemon stamps.
var fixtureHost = &event.Host{ID: "5e8102a2-f0ef-46ef-a315-39f770849362", Name: "vm", OS: "linux", Arch: "amd64"}

var fixtureUser = &event.User{Name: "ana", ID: "1000"}

// fixture builds a state database through state.Store, the same writer the
// daemon uses, so the policies are tested against the real schema and the
// real value encodings (fixed-width times, joined lists, integer flags).
type fixture struct {
	t     *testing.T
	path  string
	store *state.Store
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state", "state.db")
	s, err := state.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &fixture{t: t, path: p, store: s, now: time.Now().UTC()}
}

// close checkpoints and closes the store so a read-only reader sees
// everything, the way osquery reads a file the daemon is writing.
func (f *fixture) close() string {
	f.t.Helper()
	if err := f.store.Close(); err != nil {
		f.t.Fatal(err)
	}
	return f.path
}

func (f *fixture) apply(evs ...*event.Event) {
	f.t.Helper()
	if err := f.store.Apply(evs); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) ev(kind event.Kind, typ string, ago time.Duration) *event.Event {
	e := event.New(kind, typ, event.SourceSensor)
	e.TS = event.At(f.now.Add(-ago))
	e.Host = fixtureHost
	e.User = fixtureUser
	e.Integrity = event.IntegrityRoot
	return e
}

// heartbeat writes the health row as the daemon's heartbeat does.
func (f *fixture) heartbeat(ago time.Duration, bundle string) {
	e := f.ev(event.KindHealth, event.TypeHealthHeartbeat, ago)
	e.Source = event.SourceSensor
	e.User = nil
	e.Writer = "daemon-1"
	e.Privacy = "standard"
	e.Labels = map[string]string{
		state.LabelRulesVersion: "2026.11.11", state.LabelHostIDSource: "osquery",
	}
	if bundle != "" {
		e.Labels[state.LabelBundleVersion] = bundle
	}
	e.Health = &event.Health{
		SensorVersion: "0.1.0", Mode: "daemon", UptimeS: 3600, RulesCount: 120, RulesHash: "9f2c",
		CatalogVer: "2026.11.11",
		Counters: map[string]uint64{
			state.CounterEventsIn: 1200, state.CounterEventsOut: 300, state.CounterDetections: 2,
		},
	}
	f.apply(e)
}

func (f *fixture) asset(a event.Asset) *event.Event {
	e := f.ev(event.KindInventory, event.TypeInventoryAsset, 0)
	e.Source = event.SourceScan
	a.Owner = fixtureUser.Name
	e.Asset = &a
	return e
}

func (f *fixture) agent(id, catalogID string, kind event.AssetKind, hooks string, flags ...string) *event.Event {
	return f.asset(event.Asset{
		ID: id, Kind: kind, Name: catalogID, Vendor: "vendor", Version: "1.0.0", CatalogID: catalogID,
		Path: "/home/ana/.local/bin/" + catalogID, Scope: event.ScopeUser, Confidence: "high",
		Evidence: []string{"path", "package:npm"}, RiskFlags: flags,
		Telemetry: &event.Telemetry{Hooks: hooks, Transcript: "tailing"},
	})
}

func (f *fixture) mcp(id string, pinned bool, flags ...string) *event.Event {
	v := "2025.1.14"
	if !pinned {
		v = ""
	}
	return f.asset(event.Asset{
		ID: id, Kind: event.AssetMCPServer, Name: "filesystem", Parent: "claude-code",
		Path: "/home/ana/.claude.json", Scope: event.ScopeUser, SHA256: "ab12", RiskFlags: flags,
		MCP: &event.MCP{Transport: "stdio", Command: "npx", Runner: "npx", Ecosystem: "npm",
			Package: "@modelcontextprotocol/server-filesystem", Version: v, Pinned: pinned, AuthMode: "none"},
	})
}

func (f *fixture) ext(id string, kind event.AssetKind, flags ...string) *event.Event {
	return f.asset(event.Asset{
		ID: id, Kind: kind, Name: string(kind) + "-" + id, Parent: "claude-code",
		Path: "/home/ana/src/app/.vscode/tasks.json", Scope: event.ScopeProject, SHA256: "cd34", RiskFlags: flags,
	})
}

func (f *fixture) detection(id, rule, severity string, ago time.Duration) *event.Event {
	e := f.ev(event.KindDetection, event.TypeDetectionFinding, ago)
	e.ID = id
	e.Agent = &event.Agent{ID: "claude-code"}
	e.Session = &event.Session{ID: "sess-1"}
	e.Detection = &event.Detection{RuleID: rule, Title: rule + " title", Class: event.ClassFinding,
		Severity: severity, Confidence: "high", Maturity: "stable", Category: "execution",
		Tags: []string{"attack.t1059.004"}, DedupKey: id, Count: 1}
	return e
}

func (f *fixture) summary(session, mode string) *event.Event {
	e := f.ev(event.KindSummary, event.TypeSessionSummary, 0)
	e.Agent = &event.Agent{ID: "claude-code"}
	e.Session = &event.Session{ID: session, PermissionMode: mode}
	e.Summary = &event.Summary{Started: event.At(f.now.Add(-time.Hour)), Events: 12,
		ToolCalls: map[string]int{"shell": 4}, Surfaces: []event.Source{event.SourceHook, event.SourceTranscript},
		Coverage: "covered"}
	return e
}

func (f *fixture) check(id, severity string) *event.Event {
	e := f.ev(event.KindPosture, event.TypePostureCheck, 0)
	e.Source = event.SourceScan
	e.Check = &event.Check{ID: id, Title: id, Status: "fail", Severity: severity, AgentID: "claude-code",
		Subject: "permissions.defaultMode", Owner: fixtureUser.Name, Remedy: "fix it"}
	return e
}

func (f *fixture) processes(flags ...string) {
	f.t.Helper()
	err := f.store.SetAgentProcesses([]state.AgentProcess{{
		PID: 4242, StartTime: f.now.Add(-time.Hour), AgentID: "claude-code", User: "ana", UserID: "1000",
		Exe: "/home/ana/.local/bin/claude", Flags: flags, SessionID: "sess-1",
	}})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) coverage(st string) {
	f.t.Helper()
	if err := f.store.SetCoverage([]event.Coverage{{AgentID: "claude-code", User: "ana",
		Hooks: "managed", Transcript: "tailing", Processes: 1, State: st}}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) scan(complete bool, ids ...string) {
	f.t.Helper()
	fin := f.now
	if !complete {
		fin = time.Time{}
	}
	if err := f.store.MarkScan(f.now.Add(-time.Minute), fin, ids); err != nil {
		f.t.Fatal(err)
	}
}

// healthy fills a database on which every spoor policy passes: managed
// hooks, a pinned MCP server, extensions without auto-run flags (one with
// a flag that is not auto-run), only an old high detection and a recent
// low one, no bypass anywhere, a low posture failure, covered agents and a
// current bundle.
func (f *fixture) healthy() {
	f.apply(
		f.agent("a-claude", "claude-code", event.AssetAgent, "managed", "managed_policy_present"),
		f.agent("a-codex", "codex", event.AssetAgent, "managed"),
		f.agent("a-ollama", "ollama", event.AssetModelRuntime, "unsupported", "listen_address_overridden"),
		f.mcp("m-fs", true),
		f.ext("x-skill", event.AssetSkill),
		f.ext("x-proj", event.AssetProjectConfig, "settings_escalate_permissions"),
		f.detection("d-old-high", "SPR-EXEC-001", event.SevHigh, 72*time.Hour),
		f.detection("d-low", "SPR-NET-002", event.SevLow, time.Minute),
		f.summary("sess-1", "default"),
		f.check("SPR-POST-LOW", event.SevLow),
	)
	f.processes("--permission-mode acceptEdits")
	f.coverage("covered")
	f.scan(true, "a-claude", "a-codex", "a-ollama", "m-fs", "x-skill", "x-proj")
	f.heartbeat(time.Minute, "3")
}
