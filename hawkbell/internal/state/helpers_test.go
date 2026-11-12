package state

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// clock is a settable time source for a Store under test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testEvent keeps test tables short.
type testEvent = event.Event

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// newStore opens a fresh database under t.TempDir with a fake clock at t0.
func newStore(t *testing.T) (*Store, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c := &clock{t: t0}
	s.now = c.now
	t.Cleanup(func() { s.Close() })
	return s, c
}

func mustApply(t *testing.T, s *Store, evs ...*event.Event) {
	t.Helper()
	if err := s.Apply(evs); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func mustQuery(t *testing.T, s *Store, table string, cols ...string) []map[string]string {
	t.Helper()
	rows, err := s.Query(table, cols)
	if err != nil {
		t.Fatalf("Query(%s): %v", table, err)
	}
	return rows
}

// one returns the single row of a table that has key = val.
func one(t *testing.T, s *Store, table, key, val string) map[string]string {
	t.Helper()
	var hit []map[string]string
	for _, r := range mustQuery(t, s, table) {
		if r[key] == val {
			hit = append(hit, r)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%s where %s=%q: got %d rows, want 1", table, key, val, len(hit))
	}
	return hit[0]
}

func at(d time.Duration) event.Time { return event.At(t0.Add(d)) }

func user(name, id string) *event.User { return &event.User{Name: name, ID: id} }

// assetEvent builds an inventory event.
func assetEvent(ts time.Duration, a event.Asset, u *event.User) *event.Event {
	return &event.Event{
		V: event.SchemaVersion, ID: event.NewIDAt(t0.Add(ts)), TS: at(ts),
		Kind: event.KindInventory, Type: event.TypeInventoryAsset, Source: event.SourceScan,
		Integrity: event.IntegrityRoot, User: u, Asset: &a,
	}
}

func agentAsset(id string) event.Asset {
	return event.Asset{
		ID: id, Kind: event.AssetAgent, Name: "Claude Code", Vendor: "Anthropic", Version: "2.1.0",
		CatalogID: "claude-code", Path: "/usr/local/bin/claude", Scope: event.ScopeUser, Owner: "alice",
		SHA256: "aa11", Evidence: []string{"package:npm", "path"}, Confidence: "high",
		RiskFlags: []string{"bypass_default"},
		Telemetry: &event.Telemetry{Hooks: "managed", Transcript: "tailing", NativeOTel: "disabled"},
	}
}

func mcpAsset(id string) event.Asset {
	return event.Asset{
		ID: id, Kind: event.AssetMCPServer, Name: "github", Parent: "cursor", Scope: event.ScopeUser,
		Owner: "alice", Path: "/home/alice/.cursor/mcp.json", SHA256: "bb22",
		RiskFlags: []string{"unpinned_dependency"},
		MCP: &event.MCP{
			Transport: "stdio", Command: "/home/alice/.nvm/bin/npx", Args: []string{"-y", "@x/server"},
			Runner: "npx", Ecosystem: "npm", Package: "@x/server", Version: "latest",
			EnvKeys: []string{"GITHUB_TOKEN"}, AuthMode: "env",
		},
	}
}

func skillAsset(id string) event.Asset {
	return event.Asset{
		ID: id, Kind: event.AssetSkill, Name: "pdf", Parent: "claude-code", Scope: event.ScopeUser,
		Owner: "alice", Path: "/home/alice/.claude/skills/pdf", SHA256: "cc33",
	}
}

func detectionEvent(id string, ts time.Duration, rule, sev, dedup string, u *event.User, session string) *event.Event {
	e := &event.Event{
		V: event.SchemaVersion, ID: id, TS: at(ts), Kind: event.KindDetection,
		Type: event.TypeDetectionFinding, Source: event.SourceSensor, Integrity: event.IntegrityUser,
		User: u, Agent: &event.Agent{ID: "claude-code"},
		Detection: &event.Detection{
			RuleID: rule, Title: "Pipe to shell", Severity: sev, Confidence: "high", Maturity: "stable",
			Category: "execution", Tags: []string{"attack.t1059.004"}, Response: "ask", DedupKey: dedup,
		},
	}
	if session != "" {
		e.Session = &event.Session{ID: session}
	}
	return e
}

func heartbeat(id string, ts time.Duration, writer string, counters map[string]uint64) *event.Event {
	return &event.Event{
		V: event.SchemaVersion, ID: id, TS: at(ts), Kind: event.KindHealth, Type: event.TypeHealthHeartbeat,
		Source: event.SourceSensor, Integrity: event.IntegrityRoot, Writer: writer, Privacy: "minimal",
		Host: &event.Host{ID: "host-uuid-1"},
		Labels: map[string]string{
			LabelRulesVersion: "2026.11.1", LabelBundleVersion: "7", LabelHostIDSource: "file",
		},
		Health: &event.Health{
			SensorVersion: "0.1.0", Mode: "daemon", UptimeS: 60, Counters: counters,
			RulesCount: 54, RulesHash: "rh", CatalogVer: "cv",
		},
	}
}

// rawDB opens a second, independent read-write connection to the file, for
// inspecting internals and simulating other writers.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// fileBytes returns the database and its sidecars, for "this value must
// never be on disk" assertions.
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	var all []byte
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		b, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ids(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%05d", prefix, i)
	}
	return out
}
