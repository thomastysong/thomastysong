package state

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func seedInventory(t *testing.T, s *Store) {
	t.Helper()
	u := user("alice", "1000")
	mustApply(t, s,
		assetEvent(0, agentAsset("agent-1"), u),
		assetEvent(0, agentAsset("agent-2"), u),
		assetEvent(0, mcpAsset("mcp-1"), u),
		assetEvent(0, mcpAsset("mcp-2"), u),
		assetEvent(0, skillAsset("skill-1"), u),
		assetEvent(0, skillAsset("skill-2"), u),
	)
}

func TestMarkScanRemovesUnseenAndReportsThem(t *testing.T) {
	s, c := newStore(t)
	seedInventory(t, s)
	if ev, err := s.Removed(); err != nil || len(ev) != 0 {
		t.Fatalf("Removed before any scan: %v %v", ev, err)
	}

	c.add(time.Hour)
	started, finished := c.now().Add(-time.Minute), c.now()
	// The scan saw one of each kind; an unknown id in seen is harmless.
	if err := s.MarkScan(started, finished, []string{"agent-1", "mcp-1", "skill-1", "never-stored", ""}); err != nil {
		t.Fatal(err)
	}

	// agents keep the row, flagged; the other tables stop showing it.
	if r := one(t, s, "agents", "asset_id", "agent-2"); r["change"] != "removed" || r["running"] != "0" {
		t.Fatalf("unseen agent: %v", r)
	}
	if r := one(t, s, "agents", "asset_id", "agent-1"); r["change"] != "new" || r["last_seen"] != FormatTime(finished) {
		t.Fatalf("seen agent: %v", r)
	}
	for table, want := range map[string]string{"mcp_servers": "mcp-1", "extensions": "skill-1"} {
		rows := mustQuery(t, s, table)
		if len(rows) != 1 || rows[0]["asset_id"] != want || rows[0]["last_seen"] != FormatTime(finished) {
			t.Fatalf("%s after scan: %v", table, rows)
		}
	}
	h := mustQuery(t, s, "health")
	if len(h) != 1 || h[0]["last_scan"] != FormatTime(finished) || h[0]["scan_complete"] != "1" {
		t.Fatalf("health after scan: %v", h)
	}
	if h[0]["heartbeat"] != "" {
		t.Fatal("a scan must not fabricate a heartbeat")
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"agent-1": "aa11", "mcp-1": "bb22", "skill-1": "cc33"}; !reflect.DeepEqual(snap, want) {
		t.Fatalf("Snapshot = %v, want %v", snap, want)
	}

	removed, err := s.Removed()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*event.Event{}
	for _, e := range removed {
		got[e.Asset.ID] = e
	}
	if len(removed) != 3 || got["agent-2"] == nil || got["mcp-2"] == nil || got["skill-2"] == nil {
		t.Fatalf("Removed returned %d events: %v", len(removed), got)
	}
	for id, e := range got {
		if e.Kind != event.KindInventory || e.Type != event.TypeInventoryAsset || e.Source != event.SourceScan ||
			e.V != event.SchemaVersion || e.Asset.Change != event.ChangeRemoved || !e.TS.Equal(finished) || e.ID == "" {
			t.Errorf("%s: malformed removal event %+v", id, e)
		}
		if e.User == nil || e.User.Name != "alice" || e.User.ID != "1000" || e.Asset.Owner != "alice" {
			t.Errorf("%s: owner lost: user=%+v owner=%q", id, e.User, e.Asset.Owner)
		}
		if !e.Asset.FirstSeen.Equal(t0) {
			t.Errorf("%s: first_seen = %v", id, e.Asset.FirstSeen)
		}
		if _, err := e.MarshalLine(); err != nil {
			t.Errorf("%s: does not serialize: %v", id, err)
		}
	}
	if a := got["agent-2"].Asset; a.Kind != event.AssetAgent || a.Name != "Claude Code" || a.CatalogID != "claude-code" || a.Path != "/usr/local/bin/claude" {
		t.Errorf("agent removal lost identity: %+v", a)
	}
	if a := got["mcp-2"].Asset; a.Kind != event.AssetMCPServer || a.MCP == nil || a.MCP.Package != "@x/server" || a.Parent != "cursor" || a.MCP.Command != "npx" {
		t.Errorf("mcp removal lost identity: %+v %+v", a, a.MCP)
	}
	if a := got["skill-2"].Asset; a.Kind != event.AssetSkill || a.MCP != nil || a.SHA256 != "cc33" {
		t.Errorf("skill removal lost identity: %+v", a)
	}

	// Asking again gives the same events with the same ids.
	again, _ := s.Removed()
	if len(again) != len(removed) {
		t.Fatalf("second Removed returned %d events", len(again))
	}
	for i := range again {
		if again[i].ID != removed[i].ID || again[i].Asset.ID != removed[i].Asset.ID {
			t.Fatalf("Removed is not idempotent: %s/%s vs %s/%s", again[i].ID, again[i].Asset.ID, removed[i].ID, removed[i].Asset.ID)
		}
	}

	// The next complete scan supersedes: nothing new went missing.
	c.add(time.Hour)
	if err := s.MarkScan(c.now(), c.now(), []string{"agent-1", "mcp-1", "skill-1"}); err != nil {
		t.Fatal(err)
	}
	if ev, _ := s.Removed(); len(ev) != 0 {
		t.Fatalf("Removed after a scan that lost nothing: %d events", len(ev))
	}
	// A removal reported by an event (not by MarkScan) is not reported again.
	gone := skillAsset("skill-1")
	gone.Change = event.ChangeRemoved
	mustApply(t, s, assetEvent(2*time.Hour, gone, nil))
	if ev, _ := s.Removed(); len(ev) != 0 {
		t.Fatalf("an event-reported removal came back from Removed: %d", len(ev))
	}
}

func TestPartialScanRemovesNothing(t *testing.T) {
	s, c := newStore(t)
	seedInventory(t, s)
	if err := s.MarkScan(c.now(), c.now(), []string{"agent-1", "agent-2", "mcp-1", "mcp-2", "skill-1", "skill-2"}); err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	// Deadline hit: zero finish time, and whatever was seen so far.
	if err := s.MarkScan(c.now(), time.Time{}, []string{"agent-1"}); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot()
	if len(snap) != 6 {
		t.Fatalf("a partial scan removed assets: %d left", len(snap))
	}
	h := mustQuery(t, s, "health")[0]
	if h["scan_complete"] != "0" || h["last_scan"] != FormatTime(t0) {
		t.Fatalf("health after a partial scan: %v", h)
	}
	if ev, _ := s.Removed(); len(ev) != 0 {
		t.Fatalf("Removed after a partial scan: %d", len(ev))
	}
	if err := s.MarkScan(c.now(), c.now().Add(-time.Second), nil); err == nil {
		t.Fatal("a scan that finished before it started was accepted")
	}

	// A complete scan that saw nothing at all means everything is gone.
	c.add(time.Hour)
	if err := s.MarkScan(c.now(), c.now(), nil); err != nil {
		t.Fatal(err)
	}
	if snap, _ := s.Snapshot(); len(snap) != 0 {
		t.Fatalf("Snapshot = %v", snap)
	}
	if ev, _ := s.Removed(); len(ev) != 6 {
		t.Fatalf("Removed = %d events, want 6", len(ev))
	}
}

func TestMarkScanHandlesLargeSeenSets(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	s, c := newStore(t)
	var evs []*event.Event
	all := ids("big", 9000)
	for _, id := range all {
		evs = append(evs, assetEvent(0, event.Asset{ID: id, Kind: event.AssetRulesFile, Name: "CLAUDE.md", SHA256: id}, nil))
	}
	mustApply(t, s, evs...)
	c.add(time.Hour)
	seen := append(append([]string{}, all[:8990]...), all[:100]...) // duplicates are fine
	start := time.Now()
	if err := s.MarkScan(c.now(), c.now(), seen); err != nil {
		t.Fatal(err)
	}
	t.Logf("MarkScan with %d seen ids: %v", len(seen), time.Since(start))
	removed, _ := s.Removed()
	if len(removed) != 10 {
		t.Fatalf("Removed = %d, want 10", len(removed))
	}
	var gotIDs []string
	for _, e := range removed {
		gotIDs = append(gotIDs, e.Asset.ID)
	}
	sort.Strings(gotIDs)
	if !reflect.DeepEqual(gotIDs, all[8990:]) {
		t.Fatalf("wrong assets removed: %v", gotIDs)
	}
	if snap, _ := s.Snapshot(); len(snap) != 8990 || snap["big00000"] != "big00000" {
		t.Fatalf("Snapshot size %d", len(snap))
	}
}

func TestAgentProcesses(t *testing.T) {
	s, c := newStore(t)
	p1 := AgentProcess{
		PID: 100, StartTime: t0.Add(-time.Hour), AgentID: "claude-code", User: "alice", UserID: "1000",
		Exe: "/usr/local/bin/claude", Flags: []string{"--dangerously-skip-permissions", "--bare"},
		SessionID: "sess-A", ContainerID: "c0ffee",
	}
	p2 := AgentProcess{PID: 200, StartTime: t0.Add(-time.Minute), AgentID: "codex", User: "bob"}
	if err := s.SetAgentProcesses([]AgentProcess{p1, p2, {PID: 0, AgentID: "ignored"}, {PID: -4}}); err != nil {
		t.Fatal(err)
	}
	r := one(t, s, "agent_processes", "pid", "100")
	for k, v := range map[string]string{
		"start_time": FormatTime(t0.Add(-time.Hour)), "agent_id": "claude-code", "user": "alice",
		"exe": "/usr/local/bin/claude", "flags": "--dangerously-skip-permissions,--bare",
		"session_ref": SessionRef("1000", "claude-code", "sess-A"), "container_id": "c0ffee",
		"first_seen": FormatTime(t0), "last_seen": FormatTime(t0), "running": "1",
	} {
		if r[k] != v {
			t.Errorf("agent_processes.%s = %q, want %q", k, r[k], v)
		}
	}
	if n := len(mustQuery(t, s, "agent_processes")); n != 2 {
		t.Fatalf("rows = %d, want 2 (pid <= 0 is not a process)", n)
	}

	// Same set a few seconds later: no write at all.
	walBefore := fileBytes(t, s.Path())
	c.add(10 * time.Second)
	if err := s.SetAgentProcesses([]AgentProcess{p2, p1}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(walBefore, fileBytes(t, s.Path())) {
		t.Fatal("an unchanged process set caused a write")
	}
	if r = one(t, s, "agent_processes", "pid", "100"); r["last_seen"] != FormatTime(t0) {
		t.Fatalf("last_seen moved without a write: %v", r["last_seen"])
	}
	// After a minute it is refreshed.
	c.add(time.Minute)
	s.SetAgentProcesses([]AgentProcess{p1, p2})
	if r = one(t, s, "agent_processes", "pid", "100"); r["last_seen"] != FormatTime(c.now()) || r["first_seen"] != FormatTime(t0) {
		t.Fatalf("refresh: %v", r)
	}

	// p1 exits: it stays, marked not running, last_seen frozen.
	exitAt := c.now()
	c.add(5 * time.Second)
	if err := s.SetAgentProcesses([]AgentProcess{p2}); err != nil {
		t.Fatal(err)
	}
	if r = one(t, s, "agent_processes", "pid", "100"); r["running"] != "0" || r["last_seen"] != FormatTime(exitAt) {
		t.Fatalf("exited process: %v", r)
	}
	if r = one(t, s, "agent_processes", "pid", "200"); r["running"] != "1" || r["user"] != "bob" {
		t.Fatalf("surviving process: %v", r)
	}
	// The pid is reused by a new process: a separate row.
	reuse := AgentProcess{PID: 100, StartTime: c.now(), AgentID: "gemini-cli", User: "alice", UserID: "1000"}
	c.add(time.Second)
	s.SetAgentProcesses([]AgentProcess{p2, reuse})
	if n := len(mustQuery(t, s, "agent_processes")); n != 3 {
		t.Fatalf("rows = %d after pid reuse, want 3", n)
	}
	// Everything exits.
	c.add(time.Second)
	if err := s.SetAgentProcesses(nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range mustQuery(t, s, "agent_processes") {
		if r["running"] != "0" {
			t.Fatalf("still running after an empty set: %v", r)
		}
	}
	// Exited rows age out by Retention.Processes; default 24 hours.
	c.add(23 * time.Hour)
	s.Prune(c.now(), Retention{})
	if n := len(mustQuery(t, s, "agent_processes")); n != 3 {
		t.Fatalf("pruned too early: %d rows", n)
	}
	c.add(2 * time.Hour)
	s.Prune(c.now(), Retention{})
	if n := len(mustQuery(t, s, "agent_processes")); n != 0 {
		t.Fatalf("not pruned after retention: %d rows", n)
	}
}

func TestCoverageIsReplaced(t *testing.T) {
	s, c := newStore(t)
	set := []event.Coverage{
		{AgentID: "claude-code", User: "alice", Hooks: "managed", Transcript: "tailing", Processes: 2, State: "covered"},
		{AgentID: "codex", User: "alice", Hooks: "missing", Transcript: "found", State: "partial"},
		{AgentID: "codex", User: "bob", Hooks: "missing", Transcript: "none", Processes: 1, State: "blind"},
		{AgentID: "", User: "nobody", State: "covered"},                                 // no agent: not a statement
		{AgentID: "codex", User: "bob", Hooks: "user", State: "partial", Processes: -3}, // later statement wins
	}
	if err := s.SetCoverage(set); err != nil {
		t.Fatal(err)
	}
	rows := mustQuery(t, s, "coverage")
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	byKey := map[string]map[string]string{}
	for _, r := range rows {
		byKey[r["agent_id"]+"/"+r["user"]] = r
	}
	if r := byKey["claude-code/alice"]; r["hooks"] != "managed" || r["transcript"] != "tailing" || r["processes"] != "2" ||
		r["state"] != "covered" || r["updated"] != FormatTime(t0) {
		t.Fatalf("claude-code/alice: %v", r)
	}
	if r := byKey["codex/bob"]; r["hooks"] != "user" || r["state"] != "partial" || r["processes"] != "0" {
		t.Fatalf("codex/bob: %v", r)
	}
	// Unchanged within a minute: not rewritten.
	c.add(20 * time.Second)
	s.SetCoverage(set)
	if got := mustQuery(t, s, "coverage")[0]["updated"]; got != FormatTime(t0) {
		t.Fatalf("updated moved to %s without a change", got)
	}
	// A changed set replaces everything at once.
	c.add(time.Second)
	if err := s.SetCoverage(set[:1]); err != nil {
		t.Fatal(err)
	}
	rows = mustQuery(t, s, "coverage")
	if len(rows) != 1 || rows[0]["agent_id"] != "claude-code" || rows[0]["updated"] != FormatTime(c.now()) {
		t.Fatalf("after replacement: %v", rows)
	}
	if err := s.SetCoverage(nil); err != nil {
		t.Fatal(err)
	}
	if n := len(mustQuery(t, s, "coverage")); n != 0 {
		t.Fatalf("rows = %d after an empty set", n)
	}
}

func TestPruneByAge(t *testing.T) {
	s, c := newStore(t)
	u := user("alice", "1000")
	c.add(100 * 24 * time.Hour)
	day := 24 * time.Hour
	now := c.now()
	ago := func(d time.Duration) time.Duration { return now.Add(-d).Sub(t0) }

	mustApply(t, s,
		detectionEvent("d-old", ago(31*day), "R", "low", "", u, "s"),
		detectionEvent("d-new", ago(29*day), "R", "low", "", u, "s"),
	)
	summary := func(id string, age time.Duration) *event.Event {
		return &event.Event{
			ID: id, TS: at(ago(age)), Kind: event.KindSummary, User: u, Agent: &event.Agent{ID: "a"},
			Session: &event.Session{ID: id}, Summary: &event.Summary{},
		}
	}
	mustApply(t, s, summary("s-old", 8*day), summary("s-new", 6*day))
	for i, age := range []time.Duration{8 * day, 6 * day} {
		for _, a := range []event.Asset{agentAsset(fmt.Sprint("agent-", i)), mcpAsset(fmt.Sprint("mcp-", i)), skillAsset(fmt.Sprint("skill-", i))} {
			mustApply(t, s, assetEvent(ago(40*day), a, u))
			a.Change = event.ChangeRemoved
			mustApply(t, s, assetEvent(ago(age), a, u))
		}
	}
	// A live asset last seen long ago is not "removed" and must stay.
	mustApply(t, s, assetEvent(ago(90*day), agentAsset("agent-live"), u))

	if err := s.Prune(now, Retention{}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Stats()
	want := map[string]int{"detections": 1, "sessions": 1, "agents": 2, "mcp_servers": 1, "extensions": 1}
	for table, n := range want {
		if st.Rows[table] != n {
			t.Errorf("%s: %d rows after default prune, want %d", table, st.Rows[table], n)
		}
	}
	one(t, s, "detections", "event_id", "d-new")
	one(t, s, "agents", "asset_id", "agent-live")
	one(t, s, "agents", "asset_id", "agent-1")

	// Custom retention; negative values switch a rule off.
	if err := s.Prune(now, Retention{Detections: day, Sessions: -1, RemovedAssets: -1}); err != nil {
		t.Fatal(err)
	}
	st, _ = s.Stats()
	if st.Rows["detections"] != 0 || st.Rows["sessions"] != 1 || st.Rows["agents"] != 2 {
		t.Fatalf("custom retention: %v", st.Rows)
	}
	if d := DefaultRetention(); d.Detections != 30*day || d.Sessions != 7*day || d.RemovedAssets != 7*day || d.PostureScans != 2 {
		t.Fatalf("DefaultRetention = %+v", d)
	}
}

func TestPurgeUser(t *testing.T) {
	s, c := newStore(t)
	const victim, victimID = "mallory-the-departing", "S-1-5-21-777-1001"
	v, other := user(victim, victimID), user("alice", "1000")
	own := func(a event.Asset, owner string) event.Asset { a.Owner = owner; return a }
	for _, u := range []*event.User{v, other} {
		p := u.Name
		mustApply(t, s,
			assetEvent(0, own(agentAsset("agent-"+p), u.Name), u),
			assetEvent(0, own(mcpAsset("mcp-"+p), u.Name), u),
			assetEvent(0, own(skillAsset("skill-"+p), u.Name), u),
			&event.Event{ID: "chk-" + p, TS: at(0), Kind: event.KindPosture, User: u,
				Check: &event.Check{ID: "C1", Status: "fail", Owner: u.Name, Subject: "x"}},
			detectionEvent("det-"+p, 0, "R", "high", "k", u, "sess-"+p),
			&event.Event{ID: "sum-" + p, TS: at(0), Kind: event.KindSummary, User: u, Agent: &event.Agent{ID: "a"},
				Session: &event.Session{ID: "sess-" + p}, Summary: &event.Summary{}},
		)
	}
	// System-scope rows have no owner at all.
	mustApply(t, s, assetEvent(0, own(agentAsset("agent-system"), ""), nil), heartbeat("hb", 0, "w", nil))
	s.SetAgentProcesses([]AgentProcess{
		{PID: 1, AgentID: "a", User: victim, UserID: victimID}, {PID: 2, AgentID: "a", User: "alice", UserID: "1000"},
	})
	cov := []event.Coverage{{AgentID: "a", User: victim, State: "covered"}, {AgentID: "a", User: "alice", State: "covered"}}
	s.SetCoverage(cov)

	if _, err := s.PurgeUser("  "); err == nil {
		t.Fatal("PurgeUser with an empty name must be refused: it would match system-scope rows")
	}
	if n, err := s.PurgeUser("nobody-by-that-name"); err != nil || n != 0 {
		t.Fatalf("PurgeUser(unknown) = %d, %v", n, err)
	}
	n, err := s.PurgeUser(victim)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("PurgeUser removed %d rows, want 8 (one in each user-bearing table)", n)
	}
	st, _ := s.Stats()
	want := map[string]int{
		"agents": 2, "mcp_servers": 1, "extensions": 1, "posture": 1, "detections": 1, "sessions": 1,
		"agent_processes": 1, "coverage": 1, "health": 1,
	}
	if !reflect.DeepEqual(st.Rows, want) {
		t.Fatalf("rows after purge = %v, want %v", st.Rows, want)
	}
	// Erasure means gone from the bytes on disk, not just from query results.
	raw := fileBytes(t, s.Path())
	if bytes.Contains(raw, []byte(victim)) || bytes.Contains(raw, []byte(victimID)) {
		t.Fatal("the purged account is still present in the database file or its WAL")
	}
	// The sets pushed on the next tick must be written again even though
	// they look unchanged to the write throttle.
	c.add(time.Second)
	s.SetCoverage(cov)
	if n := len(mustQuery(t, s, "coverage")); n != 2 {
		t.Fatalf("coverage rows after re-set = %d, want 2", n)
	}

	// Purge by id reaches rows whose shown name differs.
	n, err = s.PurgeUser("1000")
	if err != nil || n != 7 {
		t.Fatalf("PurgeUser by id = %d, %v; want 7 (coverage carries only the name)", n, err)
	}
	if n, _ := s.PurgeUser("alice"); n != 1 {
		t.Fatalf("PurgeUser by name after id = %d, want the 1 coverage row", n)
	}
	st, _ = s.Stats()
	if st.Rows["agents"] != 1 || st.Rows["health"] != 1 {
		t.Fatalf("system rows must survive: %v", st.Rows)
	}
}
