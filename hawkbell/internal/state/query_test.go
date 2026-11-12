package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// specColumns is the table list of the build spec (B3), with the two
// documented deviations: "path" is install_path / source_path because ATC
// reserves the name, and agent_processes gained "running".
var specColumns = map[string]string{
	"agents":          "asset_id name vendor kind catalog_id version install_path owner scope running pid sha256 signer confidence evidence risk_flags hooks transcript native_otel first_seen last_seen change",
	"mcp_servers":     "asset_id name parent scope owner source_path transport command runner ecosystem package version pinned url_host env_keys auth_mode risk_flags sha256 first_seen last_seen last_changed",
	"extensions":      "asset_id kind name parent scope owner source_path sha256 risk_flags first_seen last_seen last_changed",
	"posture":         "check_id title severity agent_id asset_id scope subject owner actual remedy first_seen last_seen",
	"detections":      "event_id ts rule_id title severity confidence maturity category tags agent_id user session_ref integrity response enforced count dedup_key",
	"sessions":        "session_ref agent_id user started last_event permission_mode tool_calls detections max_severity sources coverage",
	"agent_processes": "pid start_time agent_id user exe flags session_ref container_id first_seen last_seen running",
	"coverage":        "agent_id user hooks transcript processes state updated",
	"health":          "sensor_version mode profile started heartbeat last_scan scan_complete rules_count rules_version rules_hash catalog_version bundle_version events_in events_out dropped detections errors host_id host_id_source",
}

// sqliteKeywords that cannot be used as a bare column name. ATC queries and
// operators' SQL name our columns without quotes.
var sqliteKeywords = strings.Fields(`add all alter and as autoincrement between case check collate commit
	constraint create default deferrable delete distinct drop else escape except exists foreign from group having
	in index insert intersect into is isnull join limit not nothing notnull null on or order primary references
	select set table then to transaction union unique update using values when where`)

func TestTablesMatchSpec(t *testing.T) {
	if len(Tables) != len(specColumns) {
		t.Fatalf("%d tables defined, spec has %d", len(Tables), len(specColumns))
	}
	ident := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for _, td := range Tables {
		want, ok := specColumns[td.Name]
		if !ok {
			t.Errorf("table %s is not in the spec", td.Name)
			continue
		}
		if got := strings.Join(td.ColumnNames(), " "); got != want {
			t.Errorf("%s columns:\n got %s\nwant %s", td.Name, got, want)
		}
		if td.Description == "" || td.RowCap() <= 0 || td.OsqueryName() != "hawkbell_"+td.Name {
			t.Errorf("%s: description, row cap or osquery name missing", td.Name)
		}
		if got, ok := Table(td.OsqueryName()); !ok || got.Name != td.Name {
			t.Errorf("Table(%q) lookup failed", td.OsqueryName())
		}
		seen := map[string]bool{}
		for _, c := range td.allColumns() {
			if seen[c.Name] {
				t.Errorf("%s.%s defined twice", td.Name, c.Name)
			}
			seen[c.Name] = true
		}
		for _, c := range td.Columns {
			if !ident.MatchString(c.Name) {
				t.Errorf("%s.%s is not a plain identifier", td.Name, c.Name)
			}
			for _, kw := range sqliteKeywords {
				if c.Name == kw {
					t.Errorf("%s.%s is an SQLite keyword", td.Name, c.Name)
				}
			}
			if c.Name == "path" {
				t.Errorf("%s.path: the name is reserved by osquery ATC", td.Name)
			}
			if c.Description == "" {
				t.Errorf("%s.%s has no description", td.Name, c.Name)
			}
			switch c.Type {
			case TypeText:
			case TypeInteger, TypeBigInt:
				if !strings.Contains(c.Description, "CAST(") {
					t.Errorf("%s.%s: numeric columns must document the CAST needed under ATC", td.Name, c.Name)
				}
			default:
				t.Errorf("%s.%s: unknown type %q", td.Name, c.Name, c.Type)
			}
		}
		for _, k := range td.key {
			if !seen[k] {
				t.Errorf("%s: key column %s is not defined", td.Name, k)
			}
		}
	}
	if _, ok := Table("no_such"); ok {
		t.Error("Table(no_such) found something")
	}
}

// populate fills every table with a couple of rows.
func populate(t *testing.T, s *Store, c *clock) {
	t.Helper()
	alice, bob := user("alice", "1000"), user("bob", "1001")
	b := agentAsset("agent-2")
	b.Owner, b.CatalogID, b.Name = "bob", "codex", "Codex"
	b.Telemetry = &event.Telemetry{Hooks: "missing"}
	mustApply(t, s,
		assetEvent(0, agentAsset("agent-1"), alice),
		assetEvent(0, b, bob),
		assetEvent(0, mcpAsset("mcp-1"), alice),
		assetEvent(0, skillAsset("skill-1"), alice),
		&event.Event{ID: "chk", TS: at(0), Kind: event.KindPosture, User: alice,
			Check: &event.Check{ID: "HB-POS-001", Status: "fail", Severity: "high", Owner: "alice", Subject: "s"}},
		detectionEvent("det-1", 0, "HB-EXE-001", "critical", "k1", alice, "s1"),
		detectionEvent("det-2", -time.Hour, "HB-EXE-002", "low", "k2", bob, "s2"),
		&event.Event{ID: "sum", TS: at(0), Kind: event.KindSummary, User: alice, Agent: &event.Agent{ID: "claude-code"},
			Session: &event.Session{ID: "s1"}, Summary: &event.Summary{ToolCalls: map[string]int{"shell": 12}}},
		heartbeat("hb", 0, "w1", map[string]uint64{CounterEventsIn: 7}),
	)
	if err := s.SetAgentProcesses([]AgentProcess{
		{PID: 9, StartTime: t0, AgentID: "claude-code", User: "alice", UserID: "1000", SessionID: "s1"},
		{PID: 100, StartTime: t0, AgentID: "codex", User: "bob", UserID: "1001"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCoverage([]event.Coverage{{AgentID: "claude-code", User: "alice", State: "covered"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkScan(c.now(), c.now(), []string{"agent-1", "agent-2", "mcp-1", "skill-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryEveryTable(t *testing.T) {
	s, c := newStore(t)
	populate(t, s, c)
	for _, td := range Tables {
		for _, name := range []string{td.Name, td.OsqueryName()} {
			rows, err := s.Query(name, nil)
			if err != nil {
				t.Fatalf("Query(%s): %v", name, err)
			}
			if len(rows) == 0 {
				t.Fatalf("Query(%s) returned no rows from a populated database", name)
			}
			for _, r := range rows {
				if got := sortedKeys(r); !reflect.DeepEqual(got, sortedCopy(td.ColumnNames())) {
					t.Fatalf("%s row has columns %v", name, got)
				}
				for _, col := range td.Columns {
					if col.Numeric() && !regexp.MustCompile(`^-?\d+$`).MatchString(r[col.Name]) {
						t.Errorf("%s.%s = %q, want a decimal number", name, col.Name, r[col.Name])
					}
				}
			}
		}
	}
	// Column selection.
	rows, err := s.Query("detections", []string{"rule_id", "count"})
	if err != nil || len(rows) != 2 || len(rows[0]) != 2 {
		t.Fatalf("column selection: %v %v", rows, err)
	}
	// Errors.
	if _, err := s.Query("sqlite_master", nil); !errors.Is(err, ErrUnknownTable) {
		t.Errorf("Query(sqlite_master) = %v, want ErrUnknownTable", err)
	}
	if _, err := s.Query("meta", nil); !errors.Is(err, ErrUnknownTable) {
		t.Errorf("Query(meta) = %v, want ErrUnknownTable", err)
	}
	if _, err := s.Query("agents; DROP TABLE agents", nil); !errors.Is(err, ErrUnknownTable) {
		t.Errorf("injection through the table name = %v", err)
	}
	for _, col := range []string{"removed_at", "owner_id", "fp", "nope", `name" FROM agents; --`} {
		if _, err := s.Query("agents", []string{col}); err == nil {
			t.Errorf("Query(agents, %q) succeeded: internal or unknown columns must not be readable", col)
		}
	}
	if _, err := s.Query("detections", []string{"user_id"}); err == nil {
		t.Error("detections.user_id must not be readable")
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func TestQueryWhere(t *testing.T) {
	s, c := newStore(t)
	populate(t, s, c)
	ctx := t.Context()
	count := func(table string, f ...Filter) int {
		t.Helper()
		rows, err := s.QueryWhere(ctx, table, nil, f)
		if err != nil {
			t.Fatalf("QueryWhere(%s, %v): %v", table, f, err)
		}
		return len(rows)
	}
	eq := func(col string, vals ...string) Filter { return Filter{Column: col, Op: OpEq, Values: vals} }
	for _, tc := range []struct {
		name  string
		table string
		f     []Filter
		want  int
	}{
		{"no filter", "agents", nil, 2},
		{"text equality", "agents", []Filter{eq("asset_id", "agent-1")}, 1},
		{"IN list", "agents", []Filter{eq("asset_id", "agent-1", "agent-2", "agent-3")}, 2},
		{"no match", "agents", []Filter{eq("asset_id", "nope")}, 0},
		{"two columns are ANDed", "agents", []Filter{eq("owner", "alice"), eq("catalog_id", "codex")}, 0},
		{"two filters on one column are ANDed", "agents", []Filter{eq("owner", "alice"), eq("owner", "bob")}, 0},
		{"numeric equality from text", "agent_processes", []Filter{eq("pid", "9")}, 1},
		{"numeric equality is not a prefix match", "agent_processes", []Filter{eq("pid", "1")}, 0},
		{"numeric with non-number", "agent_processes", []Filter{eq("pid", "nine")}, 0},
		{"time range lower", "detections", []Filter{{Column: "ts", Op: OpGe, Values: []string{FormatTime(t0)}}}, 1},
		{"time range upper", "detections", []Filter{{Column: "ts", Op: OpLt, Values: []string{FormatTime(t0)}}}, 1},
		{"time window", "detections", []Filter{
			{Column: "ts", Op: OpGt, Values: []string{FormatTime(t0.Add(-2 * time.Hour))}},
			{Column: "ts", Op: OpLe, Values: []string{FormatTime(t0)}}}, 2},
		{"value with quotes is data, not SQL", "agents", []Filter{eq("name", `x' OR '1'='1`)}, 0},
		{"removed rows stay hidden under a filter", "extensions", []Filter{eq("kind", "skill")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := count(tc.table, tc.f...); got != tc.want {
				t.Errorf("got %d rows, want %d", got, tc.want)
			}
		})
	}
	for name, f := range map[string]Filter{
		"unknown column":   eq("nope", "x"),
		"internal column":  eq("removed_at", ""),
		"no values":        {Column: "name", Op: OpEq},
		"bad operator":     {Column: "name", Op: "LIKE", Values: []string{"%"}},
		"range two values": {Column: "first_seen", Op: OpGt, Values: []string{"a", "b"}},
		"too many values":  eq("name", make([]string, MaxFilterValues+1)...),
	} {
		if _, err := s.QueryWhere(ctx, "agents", nil, []Filter{f}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// atcViews gives a raw connection the same tables osquery would construct:
// hawkbell_<name> defined by ATCQuery, every column TEXT.
func atcViews(t *testing.T, s *Store) *sql.DB {
	t.Helper()
	db := rawDB(t, s.Path())
	db.SetMaxOpenConns(1)
	for name, entry := range ATCConfig(s.Path(), "linux") {
		e := entry.(map[string]any)
		// ATC hands back every declared column as TEXT, whatever the source type.
		var cast []string
		for _, col := range e["columns"].([]string) {
			cast = append(cast, fmt.Sprintf("CAST(%s AS TEXT) AS %s", col, col))
		}
		view := fmt.Sprintf("CREATE TEMP VIEW %s AS SELECT %s FROM (%s)", name, strings.Join(cast, ", "), e["query"])
		if _, err := db.Exec(view); err != nil {
			t.Fatalf("ATC query for %s does not run: %v\n%s", name, err, e["query"])
		}
	}
	return db
}

func TestATCConfig(t *testing.T) {
	s, c := newStore(t)
	populate(t, s, c)
	// One removed extension must not surface through ATC either.
	gone := skillAsset("skill-1")
	gone.Change = event.ChangeRemoved
	mustApply(t, s, assetEvent(0, gone, nil))

	cfg := ATCConfig("/var/lib/hawkbell/state.db", "linux")
	if len(cfg) != len(Tables) {
		t.Fatalf("%d ATC entries for %d tables", len(cfg), len(Tables))
	}
	for _, td := range Tables {
		e, ok := cfg[td.OsqueryName()].(map[string]any)
		if !ok {
			t.Fatalf("no ATC entry for %s", td.OsqueryName())
		}
		if e["path"] != "/var/lib/hawkbell/state.db" || e["platform"] != "linux" {
			t.Errorf("%s: path/platform = %v/%v", td.Name, e["path"], e["platform"])
		}
		if !reflect.DeepEqual(e["columns"], td.ColumnNames()) {
			t.Errorf("%s: columns = %v", td.Name, e["columns"])
		}
		q := e["query"].(string)
		if strings.ContainsAny(q, "\"'`;\n") && td.visible == "" {
			t.Errorf("%s: query needs escaping in YAML: %s", td.Name, q)
		}
		for _, in := range td.internal {
			if in.Name == "id" {
				continue
			}
			if strings.Contains(strings.SplitN(q, " FROM ", 2)[0], in.Name) {
				t.Errorf("%s: ATC query selects internal column %s", td.Name, in.Name)
			}
		}
	}
	if e := ATCConfig("x", "")["hawkbell_health"].(map[string]any); len(e) != 3 {
		t.Errorf("an empty platform must be omitted: %v", e)
	}
	// It must survive both serializations Fleet content is written in.
	if _, err := json.Marshal(cfg); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	y, err := yaml.Marshal(map[string]any{"auto_table_construction": cfg})
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	var back map[string]map[string]map[string]any
	if err := yaml.Unmarshal(y, &back); err != nil || len(back["auto_table_construction"]) != len(Tables) {
		t.Fatalf("YAML round trip: %v", err)
	}

	// Every query runs in SQLite and yields exactly what Query yields.
	db := atcViews(t, s)
	for _, td := range Tables {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + td.OsqueryName()).Scan(&n); err != nil {
			t.Fatalf("%s: %v", td.OsqueryName(), err)
		}
		if want := len(mustQuery(t, s, td.Name)); n != want {
			t.Errorf("%s: ATC sees %d rows, Query sees %d", td.Name, n, want)
		}
	}
	var n int
	db.QueryRow("SELECT count(*) FROM hawkbell_extensions").Scan(&n)
	if n != 0 {
		t.Errorf("a removed extension is visible through ATC")
	}
}

func TestPolicySQLFailsClosed(t *testing.T) {
	s, _ := newStore(t)
	s.now = time.Now // policies compare against SQLite's own clock
	db := atcViews(t, s)
	passes := func(q string) bool {
		t.Helper()
		var one int
		err := db.QueryRow(strings.TrimSuffix(q, ";")).Scan(&one)
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			t.Fatalf("policy does not run: %v\n%s", err, q)
		}
		return err == nil
	}
	noCritical := PolicySQL("SELECT 1 FROM hawkbell_detections WHERE severity = 'critical';")
	if !strings.HasSuffix(noCritical, ";") || strings.Count(noCritical, ";") != 1 {
		t.Fatalf("PolicySQL must emit exactly one statement: %s", noCritical)
	}
	if !strings.Contains(noCritical, "hawkbell_health") || !strings.Contains(noCritical, "NOT EXISTS") {
		t.Fatalf("PolicySQL lost the guard: %s", noCritical)
	}
	naive := "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM hawkbell_detections WHERE severity = 'critical')"

	// 1. Sensor never ran: the tables exist (ATC) but are empty.
	if !passes(naive) {
		t.Fatal("test premise: the unguarded policy passes on an empty database")
	}
	for _, p := range Policies {
		if passes(p.Query) {
			t.Errorf("policy %s passes with no sensor data at all", p.Name)
		}
	}
	if passes(noCritical) || passes(PolicySQL("")) {
		t.Fatal("guarded policy passes with no heartbeat")
	}

	// 2. Healthy sensor, nothing wrong: everything passes.
	now := time.Now()
	fresh := func(id string) *event.Event {
		e := heartbeat(id, 0, "w", nil)
		e.TS = event.At(time.Now())
		return e
	}
	mustApply(t, s, fresh("hb-1"))
	if err := s.MarkScan(now.Add(-time.Minute), now, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range Policies {
		if !passes(p.Query) {
			t.Errorf("policy %s fails on a healthy host:\n%s", p.Name, p.Query)
		}
	}
	if !passes(noCritical) || !passes(PolicySQL("")) {
		t.Fatal("guarded policy fails on a healthy host")
	}

	// 3. Each violation fails exactly its own policy.
	violate := map[string]func(){
		"no_high_detections_24h": func() {
			e := detectionEvent("d1", 0, "R", "critical", "", user("a", "1"), "s")
			e.TS = event.At(now.Add(-time.Hour))
			mustApply(t, s, e)
		},
		"no_critical_posture": func() {
			mustApply(t, s, &event.Event{ID: "c", TS: event.At(now), Kind: event.KindPosture,
				Check: &event.Check{ID: "C", Status: "fail", Severity: "high"}})
		},
		"hooks_effective": func() {
			a := agentAsset("a1")
			a.Telemetry.Hooks = "shadowed"
			e := assetEvent(0, a, nil)
			e.TS = event.At(now)
			mustApply(t, s, e)
		},
		"no_blind_agents": func() { s.SetCoverage([]event.Coverage{{AgentID: "codex", User: "bob", State: "blind"}}) },
		"scan_complete":   func() { s.MarkScan(time.Now(), time.Time{}, nil) },
	}
	for name, do := range violate {
		p, ok := PolicyByName(name)
		if !ok {
			t.Fatalf("no policy named %s", name)
		}
		if !passes(p.Query) {
			t.Fatalf("%s already failing before its violation", name)
		}
		do()
		if passes(p.Query) {
			t.Errorf("policy %s still passes after its violation:\n%s", name, p.Query)
		}
	}
	if passes(noCritical) {
		t.Error("custom PolicySQL still passes with a critical detection present")
	}
	if !passes(PolicySQL("")) {
		t.Error("the heartbeat policy must not depend on findings")
	}
	// A detection older than the window does not count against the 24h policy.
	if _, err := s.PurgeUser("a"); err != nil {
		t.Fatal(err)
	}
	old := detectionEvent("d-old", 0, "R", "critical", "", user("zed", "9"), "s")
	old.TS = event.At(now.Add(-25 * time.Hour))
	mustApply(t, s, old)
	if p, _ := PolicyByName("no_high_detections_24h"); !passes(p.Query) {
		t.Error("a 25-hour-old detection failed the 24-hour policy")
	}

	// 4. The sensor stops. Two windows: the sensor-reporting policy (the one
	// to alert on) fails after 30 minutes; every "no X" policy embeds a 24 h
	// guard, so a laptop that slept for an hour does not turn them all red,
	// but a removed sensor fails them within a day.
	s.SetCoverage(nil)
	setHeartbeatAge := func(age time.Duration) {
		t.Helper()
		if _, err := rawDB(t, s.Path()).Exec("DELETE FROM health"); err != nil {
			t.Fatal(err)
		}
		hb := heartbeat("hb-"+age.String(), 0, "w2", nil)
		hb.TS = event.At(now.Add(-age))
		mustApply(t, s, hb)
	}
	reporting, _ := PolicyByName("sensor_reporting")
	noBlind, _ := PolicyByName("no_blind_agents")

	setHeartbeatAge(31 * time.Minute)
	if passes(reporting.Query) {
		t.Error("sensor_reporting passes with a 31-minute-old heartbeat")
	}
	if !passes(noBlind.Query) || !passes(PolicySQL("SELECT 1 FROM hawkbell_coverage WHERE state = 'blind'")) {
		t.Error("a guarded policy fails with a 31-minute-old heartbeat; its guard is 24 h")
	}
	setHeartbeatAge(25 * time.Hour)
	for _, p := range Policies {
		if passes(p.Query) {
			t.Errorf("policy %s passes with a 25-hour-old heartbeat", p.Name)
		}
	}
	if passes(PolicySQL("")) {
		t.Error("PolicySQL passes with a 25-hour-old heartbeat")
	}
	if !passes(PolicySQLWithin("", 48*time.Hour)) {
		t.Error("PolicySQLWithin(48h) must accept a 25-hour-old heartbeat")
	}
	if PolicySQLWithin("", 0) != PolicySQL("") {
		t.Error("a non-positive max age must mean the default")
	}
}

func TestSQLTimeAgoMatchesStoredFormat(t *testing.T) {
	s, _ := newStore(t)
	var got string
	if err := s.db.QueryRow("SELECT " + SQLTimeAgo(0)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(FormatTime(time.Now())) {
		t.Fatalf("SQLite renders %q, Go renders %q: widths differ, text comparison would be wrong", got, FormatTime(time.Now()))
	}
	parsed, err := time.Parse(TimeFormat, got)
	if err != nil || time.Since(parsed) > time.Minute || time.Since(parsed) < -time.Minute {
		t.Fatalf("SQLTimeAgo(0) = %q (%v)", got, err)
	}
	s.db.QueryRow("SELECT " + SQLTimeAgo(36*time.Hour)).Scan(&got)
	parsed, _ = time.Parse(TimeFormat, got)
	if d := time.Since(parsed); d < 36*time.Hour-time.Minute || d > 36*time.Hour+time.Minute {
		t.Fatalf("SQLTimeAgo(36h) is %v ago", d)
	}
	if SQLTimeAgo(-time.Hour) != SQLTimeAgo(0) {
		t.Error("negative durations must clamp to now")
	}
}

// A writer committing continuously while readers run must never produce an
// error or a torn view: the property ATC depends on.
func TestConcurrentReadersSeeConsistentSnapshots(t *testing.T) {
	s, _ := newStore(t)
	s.now = time.Now
	const agents = 40
	write := func(gen int) error {
		cov := make([]event.Coverage, agents)
		for i := range cov {
			cov[i] = event.Coverage{AgentID: fmt.Sprintf("agent-%02d", i), User: "u", State: fmt.Sprintf("gen-%d", gen)}
		}
		return s.SetCoverage(cov)
	}
	if err := write(0); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var commits, reads atomic.Int64
	errs := make(chan error, 16)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for gen := 1; ; gen++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := write(gen); err != nil {
				errs <- fmt.Errorf("writer: %w", err)
				return
			}
			mustApplyNoFatal(s, errs, heartbeat(fmt.Sprint("hb", gen), 0, "w", nil))
			commits.Add(1)
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ro, err := OpenReadOnly(s.Path())
			if err != nil {
				errs <- err
				return
			}
			defer ro.Close()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rows, err := ro.Query("coverage", nil)
				if err != nil {
					errs <- fmt.Errorf("reader: %w", err)
					return
				}
				gens := map[string]bool{}
				for _, row := range rows {
					gens[row["state"]] = true
				}
				if len(rows) != agents || len(gens) != 1 {
					errs <- fmt.Errorf("torn read: %d rows, generations %v", len(rows), gens)
					return
				}
				reads.Add(1)
			}
		}()
	}
	select {
	case err := <-errs:
		close(stop)
		wg.Wait()
		t.Fatal(err)
	case <-time.After(1500 * time.Millisecond):
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	if commits.Load() < 20 || reads.Load() < 20 {
		t.Fatalf("too little work to mean anything: %d commits, %d reads", commits.Load(), reads.Load())
	}
	t.Logf("%d commits, %d consistent reads", commits.Load(), reads.Load())
}

func mustApplyNoFatal(s *Store, errs chan<- error, evs ...*event.Event) {
	if err := s.Apply(evs); err != nil {
		select {
		case errs <- err:
		default:
		}
	}
}

// Two stores on one file (a one-shot scan while the daemon runs) must both
// succeed: busy_timeout and immediate transactions cover the overlap.
func TestTwoWritersDoNotFail(t *testing.T) {
	s1, _ := newStore(t)
	s2, err := Open(s1.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for w, st := range []*Store{s1, s2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				a := agentAsset(fmt.Sprintf("w%d-%03d", w, i))
				if err := st.Apply([]*event.Event{assetEvent(0, a, nil)}); err != nil {
					errs <- fmt.Errorf("writer %d: %w", w, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := len(mustQuery(t, s1, "agents")); n != 300 {
		t.Fatalf("rows = %d, want 300", n)
	}
}

func BenchmarkApplyInventory(b *testing.B) {
	path := b.TempDir() + "/state.db"
	s, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	evs := make([]*event.Event, 1000)
	for i := range evs {
		a := mcpAsset(fmt.Sprintf("m%05d", i))
		evs[i] = assetEvent(0, a, user("alice", "1000"))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Apply(evs); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*len(evs)), "µs/asset")
}

func BenchmarkQueryFullTable(b *testing.B) {
	path := b.TempDir() + "/state.db"
	s, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	evs := make([]*event.Event, 10000)
	for i := range evs {
		evs[i] = assetEvent(0, skillAsset(fmt.Sprintf("s%05d", i)), user("alice", "1000"))
	}
	if err := s.Apply(evs); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := s.Query("extensions", nil)
		if err != nil || len(rows) != 10000 {
			b.Fatal(len(rows), err)
		}
	}
}
