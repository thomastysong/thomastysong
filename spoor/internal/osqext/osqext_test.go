package osqext

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

var t0 = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

// writeState creates a state database with a little of everything.
func writeState(t *testing.T, path string) *state.Store {
	t.Helper()
	s, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	alice := &event.User{Name: "alice", ID: "1000"}
	asset := func(a event.Asset) *event.Event {
		return &event.Event{ID: event.NewID(), TS: event.At(t0), Kind: event.KindInventory, User: alice, Asset: &a}
	}
	det := func(id, rule, sev string, ago time.Duration) *event.Event {
		return &event.Event{
			ID: id, TS: event.At(t0.Add(-ago)), Kind: event.KindDetection, User: alice, Integrity: event.IntegrityRoot,
			Agent: &event.Agent{ID: "claude-code"}, Session: &event.Session{ID: "s1"},
			Detection: &event.Detection{RuleID: rule, Title: "t", Severity: sev},
		}
	}
	err = s.Apply([]*event.Event{
		asset(event.Asset{ID: "agent-1", Kind: event.AssetAgent, Name: "Claude Code", CatalogID: "claude-code", Owner: "alice", Path: "/usr/bin/claude",
			Telemetry: &event.Telemetry{Hooks: "managed"}}),
		asset(event.Asset{ID: "agent-2", Kind: event.AssetAgent, Name: "Codex", CatalogID: "codex", Owner: "alice", Running: true, PID: 77}),
		asset(event.Asset{ID: "mcp-1", Kind: event.AssetMCPServer, Name: "github", Parent: "cursor", Owner: "alice",
			MCP: &event.MCP{Transport: "stdio", Command: "npx", Pinned: true}}),
		asset(event.Asset{ID: "skill-1", Kind: event.AssetSkill, Name: "pdf", Parent: "claude-code", Owner: "alice"}),
		{ID: "chk", TS: event.At(t0), Kind: event.KindPosture, User: alice,
			Check: &event.Check{ID: "SPR-POS-001", Status: "fail", Severity: "high", Subject: "x"}},
		det("det-1", "SPR-EXE-001", "critical", 0),
		det("det-2", "SPR-EXE-002", "low", 2*time.Hour),
		det("det-3", "SPR-EXE-003", "medium", 4*time.Hour),
		{ID: "sum", TS: event.At(t0), Kind: event.KindSummary, User: alice, Agent: &event.Agent{ID: "claude-code"},
			Session: &event.Session{ID: "s1"}, Summary: &event.Summary{ToolCalls: map[string]int{"shell": 3}}},
		{ID: "hb", TS: event.At(t0), Kind: event.KindHealth, Type: event.TypeHealthHeartbeat, Writer: "w",
			Host: &event.Host{ID: "H"}, Health: &event.Health{SensorVersion: "0.1.0", Mode: "daemon",
				Counters: map[string]uint64{state.CounterEventsIn: 12345678901}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAgentProcesses([]state.AgentProcess{
		{PID: 9, StartTime: t0, AgentID: "claude-code", User: "alice", UserID: "1000", SessionID: "s1"},
		{PID: 10, StartTime: t0, AgentID: "codex", User: "alice", UserID: "1000"},
		{PID: 100, StartTime: t0, AgentID: "codex", User: "alice", UserID: "1000"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCoverage([]event.Coverage{{AgentID: "claude-code", User: "alice", State: "covered", Processes: 1}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func constraints(col string, pairs ...any) table.QueryContext {
	var cl table.ConstraintList
	for i := 0; i < len(pairs); i += 2 {
		cl.Constraints = append(cl.Constraints, table.Constraint{Operator: pairs[i].(table.Operator), Expression: pairs[i+1].(string)})
	}
	return table.QueryContext{Constraints: map[string]table.ConstraintList{col: cl}}
}

func TestPluginsMirrorStateTables(t *testing.T) {
	ps := plugins(newSource(filepath.Join(t.TempDir(), "state.db")))
	if len(ps) != len(state.Tables) {
		t.Fatalf("%d plugins for %d tables", len(ps), len(state.Tables))
	}
	wantType := map[string]string{state.TypeText: "TEXT", state.TypeInteger: "INTEGER", state.TypeBigInt: "BIGINT"}
	for i, p := range ps {
		def := state.Tables[i]
		if p.Name() != "spoor_"+def.Name || p.RegistryName() != "table" {
			t.Errorf("plugin %d is %s/%s", i, p.RegistryName(), p.Name())
		}
		routes := p.Routes()
		if len(routes) != len(def.Columns) {
			t.Fatalf("%s: %d columns registered, %d defined", def.Name, len(routes), len(def.Columns))
		}
		for j, r := range routes {
			c := def.Columns[j]
			if r["id"] != "column" || r["name"] != c.Name || r["type"] != wantType[c.Type] {
				t.Errorf("%s.%s registered as %v", def.Name, c.Name, r)
			}
			// Option bit 1 is INDEX.
			if (r["op"] == "1") != c.Key {
				t.Errorf("%s.%s: index option %q, Key=%v", def.Name, c.Name, r["op"], c.Key)
			}
		}
	}
	// Typed, as promised: these are the columns ATC can only offer as text.
	for _, want := range []struct{ table, col, typ string }{
		{"agent_processes", "pid", "INTEGER"}, {"detections", "count", "INTEGER"},
		{"health", "events_in", "BIGINT"}, {"mcp_servers", "pinned", "INTEGER"}, {"detections", "ts", "TEXT"},
	} {
		def, _ := state.Table(want.table)
		for _, c := range columns(def) {
			if c.Name == want.col && string(c.Type) != want.typ {
				t.Errorf("%s.%s is %s, want %s", want.table, want.col, c.Type, want.typ)
			}
		}
	}
}

func TestGenerateEveryTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s := writeState(t, path)
	src := newSource(path)
	defer src.close()
	want := map[string]int{
		"agents": 2, "mcp_servers": 1, "extensions": 1, "posture": 1, "detections": 3, "sessions": 1,
		"agent_processes": 3, "coverage": 1, "health": 1,
	}
	for _, def := range state.Tables {
		rows, err := generator(src, def)(t.Context(), table.QueryContext{})
		if err != nil {
			t.Fatalf("%s: %v", def.Name, err)
		}
		if len(rows) != want[def.Name] {
			t.Errorf("%s: %d rows, want %d", def.Name, len(rows), want[def.Name])
		}
		for _, r := range rows {
			if len(r) != len(def.Columns) {
				t.Errorf("%s: row has %d columns, want %d", def.Name, len(r), len(def.Columns))
			}
			for _, c := range def.Columns {
				if _, ok := r[c.Name]; !ok {
					t.Errorf("%s: row lacks %s", def.Name, c.Name)
				}
			}
		}
	}
	// The extension and a direct query agree exactly.
	def, _ := state.Table("health")
	got, _ := generator(src, def)(t.Context(), table.QueryContext{})
	direct, _ := s.Query("health", nil)
	if !reflect.DeepEqual(got, direct) {
		t.Fatalf("extension rows differ from the store's:\n%v\n%v", got, direct)
	}
	if got[0]["events_in"] != "12345678901" {
		t.Errorf("BIGINT rendered as %q", got[0]["events_in"])
	}
}

func TestMissingDatabaseIsEmptyNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	src := newSource(path)
	defer src.close()
	health, _ := state.Table("health")
	gen := generator(src, health)

	rows, err := gen(t.Context(), table.QueryContext{})
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("no database: rows=%v err=%v, want empty and no error", rows, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("the extension created the database")
	}
	// The sensor starts later: rows appear without restarting anything.
	s := writeState(t, path)
	if rows, err = gen(t.Context(), table.QueryContext{}); err != nil || len(rows) != 1 {
		t.Fatalf("after the sensor started: rows=%v err=%v", rows, err)
	}
	// Uninstalled again.
	s.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		os.Remove(p)
	}
	if rows, err = gen(t.Context(), table.QueryContext{}); err != nil || len(rows) != 0 {
		t.Fatalf("after removal: rows=%v err=%v", rows, err)
	}
	// Reinstalled: a different file at the same path must be picked up.
	s2, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.SetHealth(state.Health{SensorVersion: "9.9.9", Mode: "daemon"}); err != nil {
		t.Fatal(err)
	}
	rows, err = gen(t.Context(), table.QueryContext{})
	if err != nil || len(rows) != 1 || rows[0]["sensor_version"] != "9.9.9" {
		t.Fatalf("after reinstall: rows=%v err=%v", rows, err)
	}
}

func TestReplacedDatabaseIsReopened(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s := writeState(t, path)
	src := newSource(path)
	defer src.close()
	health, _ := state.Table("health")
	gen := generator(src, health)
	if rows, err := gen(t.Context(), table.QueryContext{}); err != nil || rows[0]["sensor_version"] != "0.1.0" {
		t.Fatalf("first read: %v %v", rows, err)
	}
	// While the extension still holds the old file open, the path gets a new one.
	s.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	s2, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.SetHealth(state.Health{SensorVersion: "2.0.0"})
	rows, err := gen(t.Context(), table.QueryContext{})
	if err != nil || len(rows) != 1 || rows[0]["sensor_version"] != "2.0.0" {
		t.Fatalf("stale handle served after the file was replaced: %v %v", rows, err)
	}
}

func TestGenerateReportsRealErrors(t *testing.T) {
	dir := t.TempDir()
	// Not a database at all.
	junk := filepath.Join(dir, "junk.db")
	os.WriteFile(junk, []byte(strings.Repeat("this is not sqlite ", 200)), 0o600)
	agents, _ := state.Table("agents")
	src := newSource(junk)
	defer src.close()
	if rows, err := generator(src, agents)(t.Context(), table.QueryContext{}); err == nil {
		t.Fatalf("garbage file served %d rows without error", len(rows))
	} else if !strings.Contains(err.Error(), "spoor_agents") {
		t.Errorf("error does not name the table: %v", err)
	}
	// A directory at the path.
	src2 := newSource(dir)
	defer src2.close()
	if _, err := generator(src2, agents)(t.Context(), table.QueryContext{}); err == nil {
		t.Fatal("a directory was accepted as the database")
	}
	// A cancelled query context ends promptly with an error.
	path := filepath.Join(dir, "state.db")
	writeState(t, path)
	src3 := newSource(path)
	defer src3.close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := generator(src3, agents)(ctx, table.QueryContext{}); err == nil {
		t.Fatal("cancelled context produced rows")
	}
	// A panic inside generate becomes an error, never a crashed extension.
	if rows, err := generator(nil, agents)(t.Context(), table.QueryContext{}); err == nil || rows != nil ||
		!strings.Contains(err.Error(), "internal error") {
		t.Fatalf("panic not contained: rows=%v err=%v", rows, err)
	}
}

func TestFiltersTranslation(t *testing.T) {
	agents, _ := state.Table("agents")
	procs, _ := state.Table("agent_processes")
	dets, _ := state.Table("detections")
	eq, gt, ge, lt, le := table.OperatorEquals, table.Operator(table.OperatorGreaterThan),
		table.Operator(table.OperatorGreaterThanOrEquals), table.Operator(table.OperatorLessThan),
		table.Operator(table.OperatorLessThanOrEquals)
	like, glob := table.Operator(table.OperatorLike), table.Operator(table.OperatorGlob)
	many := make([]any, 0, 2*(state.MaxFilterValues+1))
	for i := 0; i <= state.MaxFilterValues; i++ {
		many = append(many, eq, fmt.Sprint("v", i))
	}
	for _, tc := range []struct {
		name string
		def  state.TableDef
		qc   table.QueryContext
		want []state.Filter
	}{
		{"none", agents, table.QueryContext{}, nil},
		{"text equality", agents, constraints("asset_id", eq, "a1"),
			[]state.Filter{{Column: "asset_id", Op: "=", Values: []string{"a1"}}}},
		{"several equalities become one IN", agents, constraints("asset_id", eq, "a1", eq, "a2"),
			[]state.Filter{{Column: "asset_id", Op: "=", Values: []string{"a1", "a2"}}}},
		{"integer equality", procs, constraints("pid", eq, "42"),
			[]state.Filter{{Column: "pid", Op: "=", Values: []string{"42"}}}},
		{"negative integer", procs, constraints("pid", eq, "-1"),
			[]state.Filter{{Column: "pid", Op: "=", Values: []string{"-1"}}}},
		{"non-canonical number is left to osquery", procs, constraints("pid", eq, "42.0"), nil},
		{"spaced number is left to osquery", procs, constraints("pid", eq, " 42"), nil},
		{"exponent is left to osquery", procs, constraints("pid", eq, "4e1"), nil},
		{"huge number is left to osquery", procs, constraints("pid", eq, "9999999999999999999"), nil},
		{"one bad value spoils the IN list", procs, constraints("pid", eq, "1", eq, "x"), nil},
		{"numeric ranges are left to osquery", procs, constraints("pid", gt, "5", le, "9"), nil},
		{"text ranges are pushed", dets, constraints("ts", ge, "2026-11-01", lt, "2026-12-01"),
			[]state.Filter{{Column: "ts", Op: ">=", Values: []string{"2026-11-01"}}, {Column: "ts", Op: "<", Values: []string{"2026-12-01"}}}},
		{"all four range operators", dets, constraints("ts", gt, "a", ge, "b", lt, "c", le, "d"),
			[]state.Filter{{Column: "ts", Op: ">", Values: []string{"a"}}, {Column: "ts", Op: ">=", Values: []string{"b"}},
				{Column: "ts", Op: "<", Values: []string{"c"}}, {Column: "ts", Op: "<=", Values: []string{"d"}}}},
		{"LIKE and GLOB are left to osquery", agents, constraints("name", like, "Cl%", glob, "C*"), nil},
		{"unknown column is ignored", agents, constraints("no_such_column", eq, "x"), nil},
		{"internal column is ignored", agents, constraints("removed_at", eq, ""), nil},
		{"oversized IN list is left to osquery", agents, constraints("name", many...), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := filters(tc.def, tc.qc); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("filters = %+v, want %+v", got, tc.want)
			}
		})
	}
	// Columns are visited in definition order whatever the map order was.
	qc := table.QueryContext{Constraints: map[string]table.ConstraintList{
		"user":    {Constraints: []table.Constraint{{Operator: eq, Expression: "alice"}}},
		"rule_id": {Constraints: []table.Constraint{{Operator: eq, Expression: "R"}}},
		"ts":      {Constraints: []table.Constraint{{Operator: gt, Expression: "2026"}}},
	}}
	got := filters(dets, qc)
	if len(got) != 3 || got[0].Column != "ts" || got[1].Column != "rule_id" || got[2].Column != "user" {
		t.Errorf("unstable filter order: %+v", got)
	}
}

// Pushdown must never drop a row osquery itself would have kept. For each
// constraint set the generator's rows are compared with filtering the full
// table the way osquery does afterwards.
func TestPushdownNeverLosesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	writeState(t, path)
	src := newSource(path)
	defer src.close()
	eq, gt, ge, lt, le := table.OperatorEquals, table.Operator(table.OperatorGreaterThan),
		table.Operator(table.OperatorGreaterThanOrEquals), table.Operator(table.OperatorLessThan),
		table.Operator(table.OperatorLessThanOrEquals)
	ts := func(ago time.Duration) string { return state.FormatTime(t0.Add(-ago)) }
	for _, tc := range []struct {
		name  string
		table string
		qc    table.QueryContext
		key   string
		keep  func(map[string]string) bool // osquery's own filter
		want  []string
	}{
		{"by id", "agents", constraints("asset_id", eq, "agent-2"), "asset_id",
			func(r map[string]string) bool { return r["asset_id"] == "agent-2" }, []string{"agent-2"}},
		{"by id, no such", "agents", constraints("asset_id", eq, "zzz"), "asset_id",
			func(r map[string]string) bool { return false }, nil},
		{"pid = 9 is not pid LIKE 9%", "agent_processes", constraints("pid", eq, "9"), "pid",
			func(r map[string]string) bool { return r["pid"] == "9" }, []string{"9"}},
		{"pid IN (9, 100)", "agent_processes", constraints("pid", eq, "9", eq, "100"), "pid",
			func(r map[string]string) bool { return r["pid"] == "9" || r["pid"] == "100" }, []string{"100", "9"}},
		{"pid < 50 is numeric, so 100 is excluded and 9 is not", "agent_processes", constraints("pid", lt, "50"), "pid",
			func(r map[string]string) bool { return r["pid"] == "9" || r["pid"] == "10" }, []string{"10", "9"}},
		{"detections in the last 3 hours", "detections", constraints("ts", ge, ts(3*time.Hour)), "event_id",
			func(r map[string]string) bool { return r["ts"] >= ts(3*time.Hour) }, []string{"det-1", "det-2"}},
		{"detections in a window", "detections", constraints("ts", gt, ts(5*time.Hour), lt, ts(time.Hour)), "event_id",
			func(r map[string]string) bool { return r["ts"] > ts(5*time.Hour) && r["ts"] < ts(time.Hour) }, []string{"det-2", "det-3"}},
		{"boundary is inclusive for <=", "detections", constraints("ts", le, ts(2*time.Hour)), "event_id",
			func(r map[string]string) bool { return r["ts"] <= ts(2*time.Hour) }, []string{"det-2", "det-3"}},
		{"severity equality", "detections", constraints("severity", eq, "critical"), "event_id",
			func(r map[string]string) bool { return r["severity"] == "critical" }, []string{"det-1"}},
		{"empty-string equality", "agents", constraints("signer", eq, ""), "asset_id",
			func(r map[string]string) bool { return r["signer"] == "" }, []string{"agent-1", "agent-2"}},
		{"range against the empty string", "agents", constraints("signer", lt, "a"), "asset_id",
			func(r map[string]string) bool { return r["signer"] < "a" }, []string{"agent-1", "agent-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			def, _ := state.Table(tc.table)
			rows, err := generator(src, def)(t.Context(), tc.qc)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range rows {
				if tc.keep(r) {
					got = append(got, r[tc.key])
				}
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("after osquery's filter: %v, want %v (generator returned %d rows)", got, tc.want, len(rows))
			}
		})
	}
	// And pushdown really narrows: an id lookup does not return the table.
	def, _ := state.Table("agents")
	rows, _ := generator(src, def)(t.Context(), constraints("asset_id", eq, "agent-2"))
	if len(rows) != 1 {
		t.Errorf("equality on a key returned %d rows; the constraint was not pushed down", len(rows))
	}
}

func TestConcurrentGenerate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s := writeState(t, path)
	src := newSource(path)
	defer src.close()
	errs := make(chan error, 64)
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() { // the daemon keeps writing
		defer close(writerDone)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cov := []event.Coverage{{AgentID: "claude-code", User: "alice", State: fmt.Sprint("gen-", i)}}
			if err := s.SetCoverage(cov); err != nil {
				errs <- fmt.Errorf("writer: %w", err)
				return
			}
		}
	}()
	var readers sync.WaitGroup
	for g := 0; g < 8; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 60; i++ {
				def := state.Tables[(g+i)%len(state.Tables)]
				if _, err := generator(src, def)(context.Background(), table.QueryContext{}); err != nil {
					errs <- fmt.Errorf("%s: %w", def.Name, err)
					return
				}
				if i%20 == 7 {
					src.close() // a reopen in the middle of everyone's queries
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	<-writerDone
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestHostUUID(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  map[string]string
		err  error
		want string
	}{
		{"lower-case uuid", map[string]string{"uuid": "5e8102a2-f0ef-46ef-a315-39f770849362"}, nil, "5e8102a2-f0ef-46ef-a315-39f770849362"},
		{"upper-case is kept verbatim", map[string]string{"uuid": "9C6E5B4A-0000-5000-8000-0123456789AB"}, nil, "9C6E5B4A-0000-5000-8000-0123456789AB"},
		{"surrounding space", map[string]string{"uuid": "  host-1\n"}, nil, "host-1"},
		{"query failed", nil, errors.New("no such table"), ""},
		{"empty", map[string]string{"uuid": ""}, nil, ""},
		{"missing column", map[string]string{"other": "x"}, nil, ""},
		{"path traversal", map[string]string{"uuid": "../../etc/cron.d/x"}, nil, ""},
		{"embedded newline", map[string]string{"uuid": "abc\nroot:x:0:0"}, nil, ""},
		{"NUL", map[string]string{"uuid": "abc\x00def"}, nil, ""},
		{"too long", map[string]string{"uuid": strings.Repeat("a", 129)}, nil, ""},
		{"non-ASCII", map[string]string{"uuid": "hôst"}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostUUID(fakeQuerier{row: tc.row, err: tc.err})
			if got != tc.want || (tc.want == "") != (err != nil) {
				t.Errorf("hostUUID = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

type fakeQuerier struct {
	row map[string]string
	err error
	sql *string
}

func (f fakeQuerier) QueryRow(sql string) (map[string]string, error) {
	if f.sql != nil {
		*f.sql = sql
	}
	return f.row, f.err
}

func TestWriteHostID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "spoor") // does not exist yet
	file := filepath.Join(dir, "host_id")
	const id = "5e8102a2-f0ef-46ef-a315-39f770849362"
	if err := writeHostID(file, id); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if string(b) != id+"\n" {
		t.Fatalf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(file)
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("mode %04o, want 0644: unprivileged hooks must be able to read it", fi.Mode().Perm())
		}
	}
	// Unchanged: not rewritten.
	old := time.Now().Add(-time.Hour)
	os.Chtimes(file, old, old)
	if err := writeHostID(file, id); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(file); !fi.ModTime().Equal(old) {
		t.Error("an unchanged host id file was rewritten")
	}
	// Changed: replaced, no temp files left behind.
	if err := writeHostID(file, "other-host"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "other-host\n" {
		t.Fatalf("content after change %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leftovers in %s: %v", dir, entries)
	}
	// Invalid ids never reach the disk.
	for _, bad := range []string{"", "a b", "x\ny", "../x", strings.Repeat("z", 200), "id;rm"} {
		if err := writeHostID(file, bad); err == nil {
			t.Errorf("writeHostID(%q) succeeded", bad)
		}
	}
	if b, _ := os.ReadFile(file); string(b) != "other-host\n" {
		t.Fatalf("a rejected id changed the file: %q", b)
	}
	if err := writeHostID("", id); err == nil {
		t.Error("empty path accepted")
	}
	if err := writeHostID("a\x00b", id); err == nil {
		t.Error("path with NUL accepted")
	}
	// The directory is a regular file.
	if err := writeHostID(filepath.Join(file, "nested"), id); err == nil {
		t.Error("wrote below a regular file")
	}
}

func TestSyncHostIDRetriesThenStops(t *testing.T) {
	prev := hostIDDelays
	hostIDDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}
	prevLog := Logf
	var logged []string
	var mu sync.Mutex
	Logf = func(f string, a ...any) { mu.Lock(); logged = append(logged, fmt.Sprintf(f, a...)); mu.Unlock() }
	t.Cleanup(func() { hostIDDelays, Logf = prev, prevLog })

	file := filepath.Join(t.TempDir(), "host_id")
	attempts, closed := 0, 0
	var asked string
	dial := func() (rowQuerier, func(), error) {
		attempts++
		done := func() { closed++ }
		switch attempts {
		case 1:
			return nil, nil, errors.New("socket not ready")
		case 2:
			return fakeQuerier{err: errors.New("database is locked")}, done, nil
		default:
			return fakeQuerier{row: map[string]string{"uuid": "HOST-1"}, sql: &asked}, done, nil
		}
	}
	syncHostID(make(chan struct{}), dial, file)
	if b, _ := os.ReadFile(file); string(b) != "HOST-1\n" {
		t.Fatalf("host id file %q after %d attempts", b, attempts)
	}
	if attempts != 3 || closed != 2 {
		t.Errorf("attempts=%d closed=%d, want 3 and 2 (every opened connection is closed, and it stops after success)", attempts, closed)
	}
	if asked != "SELECT uuid FROM system_info" {
		t.Errorf("asked osquery %q", asked)
	}
	if len(logged) != 0 {
		t.Errorf("logged on success: %v", logged)
	}

	// All attempts fail: it gives up, says so once, and writes nothing.
	file2 := filepath.Join(t.TempDir(), "host_id")
	n := 0
	syncHostID(make(chan struct{}), func() (rowQuerier, func(), error) { n++; return nil, nil, errors.New("down") }, file2)
	if n != len(hostIDDelays) {
		t.Errorf("%d attempts, want %d", n, len(hostIDDelays))
	}
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Error("a host id file was written without an answer from osquery")
	}
	mu.Lock()
	if len(logged) != 1 || !strings.Contains(logged[0], "down") {
		t.Errorf("log = %v", logged)
	}
	mu.Unlock()

	// A closed stop channel ends it before the first attempt.
	hostIDDelays = []time.Duration{time.Hour}
	stop := make(chan struct{})
	close(stop)
	finished := make(chan struct{})
	go func() {
		syncHostID(stop, func() (rowQuerier, func(), error) { t.Error("dialled after stop"); return nil, nil, nil }, file2)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("syncHostID ignored stop")
	}
	// A panicking dialler is contained.
	hostIDDelays = []time.Duration{0}
	syncHostID(make(chan struct{}), func() (rowQuerier, func(), error) { panic("boom") }, file2)
}

func TestRunRejectsBadArguments(t *testing.T) {
	dir := t.TempDir()
	if err := Run("", time.Second, time.Second, filepath.Join(dir, "s.db"), ""); err == nil {
		t.Error("empty socket accepted")
	}
	if err := Run(filepath.Join(dir, "osq.em"), time.Second, time.Second, " ", ""); err == nil {
		t.Error("empty database path accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	// No osquery listening: an error within the timeout, not a hang.
	start := time.Now()
	err := Run(filepath.Join(dir, "nobody.em"), 300*time.Millisecond, time.Second, filepath.Join(dir, "s.db"), "")
	if err == nil || errors.Is(err, ErrOsqueryGone) {
		t.Errorf("Run without osquery = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("Run took %v to give up", time.Since(start))
	}
	// A socket path longer than a sockaddr can hold is refused up front.
	if err := Run("/"+strings.Repeat("x", 200), time.Second, time.Second, filepath.Join(dir, "s.db"), ""); err == nil {
		t.Error("over-long socket path accepted")
	}
}
