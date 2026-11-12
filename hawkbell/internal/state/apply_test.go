package state

import (
	"bytes"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestAssetsRouteByKind(t *testing.T) {
	s, _ := newStore(t)
	want := map[event.AssetKind]string{
		event.AssetAgent: "agents", event.AssetApp: "agents", event.AssetIDEExtension: "agents",
		event.AssetBrowser: "agents", event.AssetBrowserExtension: "agents", event.AssetModelRuntime: "agents",
		event.AssetMCPServer: "mcp_servers",
		event.AssetSkill:     "extensions", event.AssetPlugin: "extensions", event.AssetHook: "extensions",
		event.AssetRulesFile: "extensions", event.AssetSubagent: "extensions", event.AssetCommand: "extensions",
		event.AssetCIAgent: "extensions", event.AssetProjectConfig: "extensions",
		event.AssetKind("kind_from_the_future"): "extensions",
	}
	var evs []*event.Event
	for kind := range want {
		evs = append(evs, assetEvent(0, event.Asset{ID: "id-" + string(kind), Kind: kind, Name: "n"}, nil))
	}
	mustApply(t, s, evs...)
	counts := map[string]int{}
	for kind, table := range want {
		row := one(t, s, table, "asset_id", "id-"+string(kind))
		counts[table]++
		if table != "mcp_servers" && row["kind"] != string(kind) {
			t.Errorf("%s: kind column = %q", kind, row["kind"])
		}
	}
	for table, n := range counts {
		if got := len(mustQuery(t, s, table)); got != n {
			t.Errorf("%s holds %d rows, want %d", table, got, n)
		}
	}
}

func TestAgentRowContent(t *testing.T) {
	s, _ := newStore(t)
	a := agentAsset("a1")
	a.Running, a.PID, a.Signer = true, 4242, "TEAMID1234"
	mustApply(t, s, assetEvent(0, a, user("alice", "1000")))
	got := one(t, s, "agents", "asset_id", "a1")
	want := map[string]string{
		"asset_id": "a1", "name": "Claude Code", "vendor": "Anthropic", "kind": "agent",
		"catalog_id": "claude-code", "version": "2.1.0", "install_path": "/usr/local/bin/claude",
		"owner": "alice", "scope": "user", "running": "1", "pid": "4242", "sha256": "aa11",
		"signer": "TEAMID1234", "confidence": "high", "evidence": "package:npm,path",
		"risk_flags": "bypass_default", "hooks": "managed", "transcript": "tailing", "native_otel": "disabled",
		"first_seen": FormatTime(t0), "last_seen": FormatTime(t0), "change": "new",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("agents.%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("columns returned: %v", sortedKeys(got))
	}
}

func TestMCPRowKeepsNoCommandLineOrSecrets(t *testing.T) {
	s, _ := newStore(t)
	const canary = "CANARY_ghp_9f8e7d6c5b4a39281706"
	a := mcpAsset("m1")
	a.MCP.Args = []string{"--token", canary, "/home/alice/secret-project"}
	a.MCP.Command = `C:\Users\alice\AppData\Roaming\npm\npx.cmd`
	a.MCP.URLHost, a.MCP.URLPath = "mcp.example.com", "/v1/"+canary
	a.MCP.HeaderKeys = []string{"Authorization"}
	a.MCP.Pinned = true
	a.Detail = map[string]string{"note": canary}
	e := assetEvent(0, a, user("alice", "1000"))
	e.Content = &event.Content{FileContent: canary}
	mustApply(t, s, e)

	got := one(t, s, "mcp_servers", "asset_id", "m1")
	want := map[string]string{
		"name": "github", "parent": "cursor", "scope": "user", "owner": "alice",
		"source_path": "/home/alice/.cursor/mcp.json", "transport": "stdio", "command": "npx.cmd",
		"runner": "npx", "ecosystem": "npm", "package": "@x/server", "version": "latest", "pinned": "1",
		"url_host": "mcp.example.com", "env_keys": "GITHUB_TOKEN", "auth_mode": "env",
		"risk_flags": "unpinned_dependency", "sha256": "bb22", "last_changed": FormatTime(t0),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("mcp_servers.%s = %q, want %q", k, got[k], v)
		}
	}
	if bytes.Contains(fileBytes(t, s.Path()), []byte(canary)) {
		t.Fatal("a value from MCP args, URL path, detail or content reached the database file")
	}
	if bytes.Contains(fileBytes(t, s.Path()), []byte("secret-project")) {
		t.Fatal("an MCP argument reached the database file")
	}
}

func TestAssetChangeLifecycle(t *testing.T) {
	s, c := newStore(t)
	c.add(24 * time.Hour) // the events below are spread over the past day
	u := user("alice", "1000")
	step := func(ts time.Duration, mutate func(*event.Asset)) map[string]string {
		t.Helper()
		a := agentAsset("a1")
		if mutate != nil {
			mutate(&a)
		}
		mustApply(t, s, assetEvent(ts, a, u))
		return one(t, s, "agents", "asset_id", "a1")
	}
	if r := step(0, nil); r["change"] != "new" {
		t.Fatalf("first sight: change=%q", r["change"])
	}
	if r := step(time.Hour, nil); r["change"] != "unchanged" || r["first_seen"] != FormatTime(t0) ||
		r["last_seen"] != FormatTime(t0.Add(time.Hour)) {
		t.Fatalf("second sight: %v", r)
	}
	// The scanner's own label is not trusted over what the table held.
	if r := step(2*time.Hour, func(a *event.Asset) { a.Change = event.ChangeNew }); r["change"] != "unchanged" {
		t.Fatalf("scanner said new for a known asset: change=%q", r["change"])
	}
	// Volatile fields do not count as a change.
	if r := step(3*time.Hour, func(a *event.Asset) { a.Running, a.PID = true, 99 }); r["change"] != "unchanged" || r["pid"] != "99" {
		t.Fatalf("running toggled: %v", r)
	}
	if r := step(4*time.Hour, func(a *event.Asset) { a.Version = "2.2.0" }); r["change"] != "changed" || r["version"] != "2.2.0" {
		t.Fatalf("version bump: %v", r)
	}
	if r := step(5*time.Hour, func(a *event.Asset) { a.Version = "2.2.0"; a.RiskFlags = nil }); r["change"] != "changed" {
		t.Fatalf("risk flags cleared: %v", r)
	}
	// Explicit removal keeps the row, flagged.
	r := step(6*time.Hour, func(a *event.Asset) { a.Change = event.ChangeRemoved; a.Running = true })
	if r["change"] != "removed" || r["running"] != "0" || r["version"] != "2.2.0" {
		t.Fatalf("removed: %v", r)
	}
	if snap, _ := s.Snapshot(); len(snap) != 0 {
		t.Fatalf("Snapshot still lists a removed asset: %v", snap)
	}
	// Removing again, or removing something never seen, is a no-op.
	step(7*time.Hour, func(a *event.Asset) { a.Change = event.ChangeRemoved })
	mustApply(t, s, assetEvent(7*time.Hour, event.Asset{ID: "ghost", Kind: event.AssetAgent, Change: event.ChangeRemoved}, u))
	if n := len(mustQuery(t, s, "agents")); n != 1 {
		t.Fatalf("rows = %d after removing an unknown asset", n)
	}
	// Reappearing: new again, but the original first_seen survives.
	r = step(8*time.Hour, func(a *event.Asset) { a.Version = "2.2.0"; a.RiskFlags = nil })
	if r["change"] != "new" || r["first_seen"] != FormatTime(t0) {
		t.Fatalf("reappeared: %v", r)
	}
	// An older record replayed late must not move last_seen backwards.
	r = step(time.Minute, func(a *event.Asset) { a.Version = "2.2.0"; a.RiskFlags = nil })
	if r["last_seen"] != FormatTime(t0.Add(8*time.Hour)) {
		t.Fatalf("last_seen went backwards: %v", r["last_seen"])
	}
}

func TestExtensionLastChanged(t *testing.T) {
	s, c := newStore(t)
	c.add(24 * time.Hour)
	apply := func(ts time.Duration, sha string) map[string]string {
		a := skillAsset("s1")
		a.SHA256 = sha
		mustApply(t, s, assetEvent(ts, a, user("alice", "1000")))
		return one(t, s, "extensions", "asset_id", "s1")
	}
	if r := apply(0, "h1"); r["last_changed"] != FormatTime(t0) || r["source_path"] != "/home/alice/.claude/skills/pdf" {
		t.Fatalf("new: %v", r)
	}
	if r := apply(time.Hour, "h1"); r["last_changed"] != FormatTime(t0) || r["last_seen"] != FormatTime(t0.Add(time.Hour)) {
		t.Fatalf("unchanged: %v", r)
	}
	if r := apply(2*time.Hour, "h2"); r["last_changed"] != FormatTime(t0.Add(2*time.Hour)) || r["sha256"] != "h2" {
		t.Fatalf("content changed: %v", r)
	}
	// A removed extension disappears from the table osquery sees...
	a := skillAsset("s1")
	a.Change = event.ChangeRemoved
	mustApply(t, s, assetEvent(3*time.Hour, a, nil))
	if rows := mustQuery(t, s, "extensions"); len(rows) != 0 {
		t.Fatalf("removed extension still visible: %v", rows)
	}
	// ...but is remembered, so it comes back with its history.
	if r := apply(4*time.Hour, "h2"); r["first_seen"] != FormatTime(t0) || r["last_changed"] != FormatTime(t0.Add(4*time.Hour)) {
		t.Fatalf("reappeared: %v", r)
	}
}

func TestOwnerIDOnlyTrustedWhenNamesAgree(t *testing.T) {
	s, _ := newStore(t)
	a := agentAsset("a1") // owner alice
	mustApply(t, s, assetEvent(0, a, user("alice", "1000")))
	b := agentAsset("a2")
	mustApply(t, s, assetEvent(0, b, user("root", "0"))) // scanned by root, owned by alice
	c := agentAsset("a3")
	c.Owner = ""
	mustApply(t, s, assetEvent(0, c, user("bob", "1001"))) // owner taken from the event user
	ownerID := func(id string) (owner, oid string) {
		s.db.QueryRow("SELECT owner, owner_id FROM agents WHERE asset_id = ?", id).Scan(&owner, &oid)
		return
	}
	if o, id := ownerID("a1"); o != "alice" || id != "1000" {
		t.Errorf("a1 owner=%q id=%q", o, id)
	}
	if o, id := ownerID("a2"); o != "alice" || id != "" {
		t.Errorf("a2 owner=%q id=%q: root's uid must not be recorded as alice's", o, id)
	}
	if o, id := ownerID("a3"); o != "bob" || id != "1001" {
		t.Errorf("a3 owner=%q id=%q", o, id)
	}
}

func TestPostureFailuresOnly(t *testing.T) {
	s, c := newStore(t)
	c.add(4 * time.Hour)
	check := func(ts time.Duration, status, actual string) *event.Event {
		return &event.Event{
			ID: event.NewID(), TS: at(ts), Kind: event.KindPosture, Type: event.TypePostureCheck,
			User: user("alice", "1000"),
			Check: &event.Check{
				ID: "HB-POS-001", Title: "Bypass mode is default", Status: status, Severity: "high",
				AgentID: "claude-code", AssetID: "a1", Scope: event.ScopeUser,
				Subject: "permissions.defaultMode", Actual: actual, Owner: "alice", Remedy: "Remove the setting",
				Expected: "default",
			},
		}
	}
	mustApply(t, s, check(0, "fail", "bypassPermissions"))
	r := one(t, s, "posture", "check_id", "HB-POS-001")
	for k, v := range map[string]string{
		"title": "Bypass mode is default", "severity": "high", "agent_id": "claude-code", "asset_id": "a1",
		"scope": "user", "subject": "permissions.defaultMode", "owner": "alice", "actual": "bypassPermissions",
		"remedy": "Remove the setting", "first_seen": FormatTime(t0), "last_seen": FormatTime(t0),
	} {
		if r[k] != v {
			t.Errorf("posture.%s = %q, want %q", k, r[k], v)
		}
	}
	// Still failing an hour later: one row, first_seen kept.
	mustApply(t, s, check(time.Hour, "fail", "bypassPermissions"))
	r = one(t, s, "posture", "check_id", "HB-POS-001")
	if r["first_seen"] != FormatTime(t0) || r["last_seen"] != FormatTime(t0.Add(time.Hour)) {
		t.Fatalf("re-observed failure: %v", r)
	}
	// "unknown" (could not evaluate) neither clears nor refreshes.
	mustApply(t, s, check(2*time.Hour, "unknown", ""))
	if r = one(t, s, "posture", "check_id", "HB-POS-001"); r["last_seen"] != FormatTime(t0.Add(time.Hour)) {
		t.Fatalf("unknown status changed the row: %v", r)
	}
	// A different subject is a different failure.
	other := check(2*time.Hour, "fail", "false")
	other.Check.Subject = "sandbox.enabled"
	mustApply(t, s, other)
	if n := len(mustQuery(t, s, "posture")); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	// Pass deletes exactly its own row.
	mustApply(t, s, check(3*time.Hour, "pass", "default"))
	rows := mustQuery(t, s, "posture")
	if len(rows) != 1 || rows[0]["subject"] != "sandbox.enabled" {
		t.Fatalf("after pass: %v", rows)
	}

	// Ageing: a failure not re-observed in two complete scans is pruned.
	scan := func() {
		c.add(time.Hour)
		if err := s.MarkScan(c.now(), c.now(), nil); err != nil {
			t.Fatal(err)
		}
		if err := s.Prune(c.now(), Retention{}); err != nil {
			t.Fatal(err)
		}
	}
	scan() // the scan that observed it
	scan() // first scan without it
	if n := len(mustQuery(t, s, "posture")); n != 1 {
		t.Fatalf("pruned after one missed scan (rows=%d)", n)
	}
	scan() // second scan without it
	if n := len(mustQuery(t, s, "posture")); n != 0 {
		t.Fatalf("still present after two missed scans (rows=%d)", n)
	}
	// Re-observing in every scan keeps it indefinitely.
	for i := 0; i < 4; i++ {
		mustApply(t, s, check(time.Duration(10+i)*time.Hour, "fail", "x"))
		scan()
	}
	if n := len(mustQuery(t, s, "posture")); n != 1 {
		t.Fatalf("a re-observed failure was pruned (rows=%d)", n)
	}
	// And the rule can be switched off.
	scan()
	scan()
	if n := len(mustQuery(t, s, "posture")); n != 0 {
		t.Fatalf("rows=%d", n)
	}
	mustApply(t, s, check(30*time.Hour, "fail", "x"))
	for i := 0; i < 3; i++ {
		c.add(time.Hour)
		s.MarkScan(c.now(), c.now(), nil)
		if err := s.Prune(c.now(), Retention{PostureScans: -1}); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(mustQuery(t, s, "posture")); n != 1 {
		t.Fatalf("PostureScans<0 must disable ageing (rows=%d)", n)
	}
}

func TestDetectionsAggregate(t *testing.T) {
	s, _ := newStore(t)
	alice, bob := user("alice", "1000"), user("bob", "1001")
	mustApply(t, s, detectionEvent("ev-1", 0, "HB-EXE-001", "high", "k1", alice, "sess-raw-1"))
	r := one(t, s, "detections", "event_id", "ev-1")
	for k, v := range map[string]string{
		"ts": FormatTime(t0), "rule_id": "HB-EXE-001", "title": "Pipe to shell", "severity": "high",
		"confidence": "high", "maturity": "stable", "category": "execution", "tags": "attack.t1059.004",
		"agent_id": "claude-code", "user": "alice", "integrity": "user", "response": "ask", "enforced": "0",
		"count": "1", "dedup_key": "k1", "session_ref": SessionRef("1000", "claude-code", "sess-raw-1"),
	} {
		if r[k] != v {
			t.Errorf("detections.%s = %q, want %q", k, r[k], v)
		}
	}

	// Replay of the same event: nothing changes.
	mustApply(t, s, detectionEvent("ev-1", 0, "HB-EXE-001", "high", "k1", alice, "sess-raw-1"))
	if r = one(t, s, "detections", "event_id", "ev-1"); r["count"] != "1" {
		t.Fatalf("replay changed count to %s", r["count"])
	}
	// A repeat folds in: count adds, the row moves to the newer event.
	rep := detectionEvent("ev-2", time.Minute, "HB-EXE-001", "high", "k1", alice, "sess-raw-1")
	rep.Detection.Count = 4
	rep.Detection.Enforced = true
	mustApply(t, s, rep)
	rows := mustQuery(t, s, "detections")
	if len(rows) != 1 || rows[0]["event_id"] != "ev-2" || rows[0]["count"] != "5" ||
		rows[0]["ts"] != FormatTime(t0.Add(time.Minute)) || rows[0]["enforced"] != "1" {
		t.Fatalf("after repeat: %v", rows)
	}
	// Replay of the folded event keeps the aggregate.
	mustApply(t, s, rep)
	if r = one(t, s, "detections", "event_id", "ev-2"); r["count"] != "5" {
		t.Fatalf("replay of folded event: count=%s", r["count"])
	}
	// An older occurrence arriving late counts but does not rewind the row.
	mustApply(t, s, detectionEvent("ev-0", -time.Hour, "HB-EXE-001", "high", "k1", alice, "sess-raw-1"))
	if r = one(t, s, "detections", "event_id", "ev-2"); r["count"] != "6" || r["ts"] != FormatTime(t0.Add(time.Minute)) {
		t.Fatalf("late older event: %v", r)
	}
	// Same key for another user, another rule, or no key at all: separate rows.
	mustApply(t, s,
		detectionEvent("ev-3", 0, "HB-EXE-001", "high", "k1", bob, "s"),
		detectionEvent("ev-4", 0, "HB-EXE-002", "low", "k1", alice, "s"),
		detectionEvent("ev-5", 0, "HB-EXE-001", "high", "", alice, "s"),
		detectionEvent("ev-6", 0, "HB-EXE-001", "high", "", alice, "s"),
	)
	if n := len(mustQuery(t, s, "detections")); n != 5 {
		t.Fatalf("rows = %d, want 5", n)
	}
	if st, _ := s.Stats(); st.Rejected != 0 {
		t.Fatalf("Rejected = %d", st.Rejected)
	}
}

func TestDetectionStoresNoEvidenceOrContent(t *testing.T) {
	s, _ := newStore(t)
	const canary = "CANARY-AKIA" + "IOSFODNN7EXAMPLE-curl-evil.sh" // split: no key-shaped literal in the source
	const session = "0199a7c2-raw-session-id-4d8e"
	e := detectionEvent("ev-1", 0, "HB-EXE-001", "critical", "k", user("alice", "1000"), session)
	e.Detection.Evidence = map[string]string{"command": canary}
	e.Detection.EventIDs = []string{"src-event-1"}
	e.Detection.Remedy = "do something"
	e.Target = &event.Target{Command: canary, Path: "/home/alice/" + canary, URL: "https://x/" + canary}
	e.Session.CWD, e.Session.Transcript = "/home/alice/work/"+canary, "/home/alice/.claude/"+canary
	e.Prompt = &event.Prompt{Text: canary, Len: 10}
	e.Tool = &event.Tool{Name: "Bash", Input: map[string]any{"command": canary}, Output: canary}
	e.Process = &event.Process{Args: []string{canary}}
	e.Content = &event.Content{PromptText: canary, ToolOutput: canary, ToolInput: map[string]any{"c": canary}}
	e.Labels = map[string]string{"x": canary}
	sum := &event.Event{
		ID: "sum-1", TS: at(0), Kind: event.KindSummary, Type: event.TypeSessionSummary,
		User: user("alice", "1000"), Agent: &event.Agent{ID: "claude-code"},
		Session: &event.Session{ID: session, CWD: "/home/alice/" + canary, PermissionMode: "bypass"},
		Summary: &event.Summary{
			Events: 3, ToolCalls: map[string]int{"shell": 2}, Hosts: []string{canary + ".example.com"},
			Installs: []string{"npm:" + canary}, MCPServers: []string{canary}, Detections: []string{"HB-EXE-001"},
		},
	}
	mustApply(t, s, e, sum)
	if err := s.SetAgentProcesses([]AgentProcess{{
		PID: 1, StartTime: t0, AgentID: "claude-code", User: "alice", UserID: "1000",
		Exe: "/usr/bin/claude", Flags: []string{"--dangerously-skip-permissions"}, SessionID: session,
	}}); err != nil {
		t.Fatal(err)
	}
	raw := fileBytes(t, s.Path())
	if bytes.Contains(raw, []byte(canary)) {
		t.Fatal("command, path, prompt, tool or evidence content reached the database file")
	}
	if bytes.Contains(raw, []byte(session)) {
		t.Fatal("the raw session id reached the database file")
	}
	ref := SessionRef("1000", "claude-code", session)
	if len(ref) != 16 || strings.Contains(session, ref) {
		t.Fatalf("SessionRef = %q", ref)
	}
	// The three tables join on the reference.
	if one(t, s, "detections", "event_id", "ev-1")["session_ref"] != ref ||
		one(t, s, "sessions", "session_ref", ref)["permission_mode"] != "bypass" ||
		one(t, s, "agent_processes", "pid", "1")["session_ref"] != ref {
		t.Fatal("session_ref does not join detections, sessions and agent_processes")
	}
}

func TestSessionRef(t *testing.T) {
	a := SessionRef("1000", "claude-code", "s1")
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) {
		t.Fatalf("SessionRef = %q", a)
	}
	if SessionRef("1000", "claude-code", "") != "" {
		t.Fatal("empty session id must give an empty ref")
	}
	seen := map[string]bool{a: true}
	for _, in := range [][3]string{
		{"1001", "claude-code", "s1"}, {"1000", "codex", "s1"}, {"1000", "claude-code", "s2"},
		// Field boundaries matter: shifting a character must change the ref.
		{"100", "0claude-code", "s1"}, {"1000", "claude-codes", "1"},
	} {
		r := SessionRef(in[0], in[1], in[2])
		if seen[r] {
			t.Fatalf("collision for %v", in)
		}
		seen[r] = true
	}
}

func TestSessionSummariesAreMonotonic(t *testing.T) {
	s, c := newStore(t)
	c.add(time.Hour)
	sum := func(id string, ts time.Duration, calls, dets int, sev, mode, cov string, final bool) *event.Event {
		d := make([]string, dets)
		for i := range d {
			d[i] = fmt.Sprintf("HB-%d", i)
		}
		return &event.Event{
			ID: id, TS: at(ts), Kind: event.KindSummary, Type: event.TypeSessionSummary,
			User: user("alice", "1000"), Agent: &event.Agent{ID: "codex"},
			Session: &event.Session{ID: "sess-1", PermissionMode: mode},
			Summary: &event.Summary{
				Started: at(-time.Hour), Ended: at(ts), Final: final, Events: calls * 2,
				ToolCalls: map[string]int{"shell": calls - 1, "file_read": 1}, Detections: d, MaxSeverity: sev,
				Surfaces: []event.Source{event.SourceHook}, Coverage: cov,
			},
		}
	}
	ref := SessionRef("1000", "codex", "sess-1")
	mustApply(t, s, sum("s1", 0, 5, 1, "medium", "default", "partial", false))
	r := one(t, s, "sessions", "session_ref", ref)
	for k, v := range map[string]string{
		"agent_id": "codex", "user": "alice", "started": FormatTime(t0.Add(-time.Hour)),
		"last_event": FormatTime(t0), "permission_mode": "default", "tool_calls": "5", "detections": "1",
		"max_severity": "medium", "sources": "hook", "coverage": "partial",
	} {
		if r[k] != v {
			t.Errorf("sessions.%s = %q, want %q", k, r[k], v)
		}
	}
	// A later rollup: totals grow, state fields follow the newer record.
	later := sum("s2", 15*time.Minute, 9, 2, "high", "bypass", "covered", false)
	later.Summary.Surfaces = []event.Source{event.SourceHook, event.SourceTranscript}
	mustApply(t, s, later)
	r = one(t, s, "sessions", "session_ref", ref)
	if r["tool_calls"] != "9" || r["detections"] != "2" || r["max_severity"] != "high" ||
		r["permission_mode"] != "bypass" || r["coverage"] != "covered" || r["sources"] != "hook,transcript" ||
		r["last_event"] != FormatTime(t0.Add(15*time.Minute)) {
		t.Fatalf("after later rollup: %v", r)
	}
	// The first rollup replayed afterwards changes nothing.
	mustApply(t, s, sum("s1", 0, 5, 1, "medium", "default", "partial", false))
	if again := one(t, s, "sessions", "session_ref", ref); fmt.Sprint(again) != fmt.Sprint(r) {
		t.Fatalf("stale replay changed the row:\n got %v\nwant %v", again, r)
	}
	// A summary without a session id cannot be keyed.
	bad := sum("s3", 0, 1, 0, "", "", "", false)
	bad.Session = nil
	mustApply(t, s, bad)
	if st, _ := s.Stats(); st.Rejected != 1 || st.Rows["sessions"] != 1 {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestHealthHeartbeatMapping(t *testing.T) {
	s, c := newStore(t)
	c.add(time.Hour)
	if rows := mustQuery(t, s, "health"); len(rows) != 0 {
		t.Fatalf("health has %d rows before any heartbeat: a missing sensor must read as no row", len(rows))
	}
	mustApply(t, s, heartbeat("hb-1", 0, "w1", map[string]uint64{
		CounterEventsIn: 100, CounterEventsOut: 40, CounterDropped: 2, CounterDetections: 3, CounterErrors: 1,
	}))
	rows := mustQuery(t, s, "health")
	if len(rows) != 1 {
		t.Fatalf("health rows = %d", len(rows))
	}
	for k, v := range map[string]string{
		"sensor_version": "0.1.0", "mode": "daemon", "profile": "minimal",
		"started": FormatTime(t0.Add(-time.Minute)), "heartbeat": FormatTime(t0), "last_scan": "",
		"scan_complete": "0", "rules_count": "54", "rules_version": "2026.11.1", "rules_hash": "rh",
		"catalog_version": "cv", "bundle_version": "7", "events_in": "100", "events_out": "40", "dropped": "2",
		"detections": "3", "errors": "1", "host_id": "host-uuid-1", "host_id_source": "file",
	} {
		if rows[0][k] != v {
			t.Errorf("health.%s = %q, want %q", k, rows[0][k], v)
		}
	}
	// Next beat of the same writer: totals replace, started is stable even
	// though uptime arithmetic would shift it.
	hb := heartbeat("hb-2", 5*time.Minute, "w1", map[string]uint64{CounterEventsIn: 250, CounterEventsOut: 90})
	hb.Health.UptimeS = 361
	mustApply(t, s, hb)
	r := mustQuery(t, s, "health")[0]
	if r["events_in"] != "250" || r["events_out"] != "90" || r["started"] != FormatTime(t0.Add(-time.Minute)) ||
		r["heartbeat"] != FormatTime(t0.Add(5*time.Minute)) {
		t.Fatalf("second beat: %v", r)
	}
	// Replaying a beat is a no-op; a stale beat never moves time backwards.
	mustApply(t, s, hb, heartbeat("hb-0", -time.Hour, "w1", nil))
	if r2 := mustQuery(t, s, "health")[0]; r2["heartbeat"] != FormatTime(t0.Add(5*time.Minute)) {
		t.Fatalf("heartbeat moved backwards: %v", r2["heartbeat"])
	}
	// The table stays a single row.
	if n := len(mustQuery(t, s, "health")); n != 1 {
		t.Fatalf("health rows = %d", n)
	}
}

func TestHealthIntervalCountersAccumulatePerWriter(t *testing.T) {
	s, c := newStore(t)
	c.add(time.Hour)
	interval := func(id string, ts time.Duration, w string) *event.Event {
		e := heartbeat(id, ts, w, map[string]uint64{
			"stream.detection.emitted": 2, "stream.inventory.emitted": 10, "stream.activity.dropped": 1,
			"stream.detection.first_seq": 1000, "spool.something": 7,
		})
		e.Health.Surfaces = []event.SurfaceStatus{{Name: "hooks", Status: "ok", Events: 50}, {Name: "scan", Status: "ok", Events: 5}}
		return e
	}
	mustApply(t, s, interval("a", 0, "w1"), interval("b", 5*time.Minute, "w1"))
	r := mustQuery(t, s, "health")[0]
	if r["events_out"] != "24" || r["dropped"] != "2" || r["detections"] != "4" || r["events_in"] != "55" {
		t.Fatalf("two intervals of one writer: %v", r)
	}
	// An error record counts without touching the heartbeat.
	mustApply(t, s, &event.Event{
		ID: "err-1", TS: at(6 * time.Minute), Kind: event.KindHealth, Type: event.TypeHealthError, Writer: "w1",
		Health: &event.Health{SensorVersion: "0.1.0", Mode: "daemon", Reason: "spool.dropped"},
	})
	r = mustQuery(t, s, "health")[0]
	if r["errors"] != "1" || r["heartbeat"] != FormatTime(t0.Add(5*time.Minute)) {
		t.Fatalf("after health.error: %v", r)
	}
	mustApply(t, s, interval("c", 10*time.Minute, "w1"))
	if r = mustQuery(t, s, "health")[0]; r["errors"] != "1" || r["events_out"] != "36" {
		t.Fatalf("third interval: %v", r)
	}
	// A restart (new writer) starts the totals again.
	mustApply(t, s, interval("d", 20*time.Minute, "w2"))
	r = mustQuery(t, s, "health")[0]
	if r["events_out"] != "12" || r["detections"] != "2" || r["errors"] != "0" ||
		r["started"] != FormatTime(t0.Add(19*time.Minute)) {
		t.Fatalf("after restart: %v", r)
	}
}

func TestHealthErrorAloneDoesNotLookAlive(t *testing.T) {
	s, _ := newStore(t)
	mustApply(t, s, &event.Event{
		ID: "err-1", TS: at(0), Kind: event.KindHealth, Type: event.TypeHealthError,
		Health: &event.Health{SensorVersion: "0.1.0", Mode: "scan"},
	})
	r := mustQuery(t, s, "health")[0]
	if r["heartbeat"] != "" || r["errors"] != "1" {
		t.Fatalf("an error record must not produce a heartbeat: %v", r)
	}
}

func TestSetHealth(t *testing.T) {
	s, c := newStore(t)
	if err := s.MarkScan(c.now(), c.now(), nil); err != nil {
		t.Fatal(err)
	}
	h := Health{
		SensorVersion: "1.2.3", Mode: "scan", Profile: "standard", Started: t0.Add(-time.Hour),
		RulesCount: 10, RulesVersion: "rv", RulesHash: "rh", CatalogVersion: "cv", BundleVersion: "bv",
		EventsIn: 1, EventsOut: 2, Dropped: 3, Detections: 4, Errors: ^uint64(0), HostID: "H", HostIDSource: "dmi",
	}
	if err := s.SetHealth(h); err != nil {
		t.Fatal(err)
	}
	r := mustQuery(t, s, "health")[0]
	for k, v := range map[string]string{
		"sensor_version": "1.2.3", "mode": "scan", "profile": "standard",
		"started": FormatTime(t0.Add(-time.Hour)), "heartbeat": FormatTime(t0), "last_scan": FormatTime(t0),
		"scan_complete": "1", "rules_count": "10", "rules_version": "rv", "rules_hash": "rh",
		"catalog_version": "cv", "bundle_version": "bv", "events_in": "1", "events_out": "2", "dropped": "3",
		"detections": "4", "errors": "9223372036854775807", "host_id": "H", "host_id_source": "dmi",
	} {
		if r[k] != v {
			t.Errorf("health.%s = %q, want %q", k, r[k], v)
		}
	}
}

func TestApplyIgnoresWhatItDoesNotStore(t *testing.T) {
	s, _ := newStore(t)
	evs := []*event.Event{
		nil,
		{ID: "act", Kind: event.KindActivity, Type: event.TypeToolPre, Target: &event.Target{Command: "rm -rf /"}},
		{ID: "odd", Kind: event.Kind("unheard-of")},
		{ID: "inv-no-asset", Kind: event.KindInventory},
		{ID: "inv-no-id", Kind: event.KindInventory, Asset: &event.Asset{Kind: event.AssetAgent, Name: "x"}},
		{ID: "pos-no-check", Kind: event.KindPosture},
		{ID: "pos-no-id", Kind: event.KindPosture, Check: &event.Check{Status: "fail"}},
		{ID: "det-no-det", Kind: event.KindDetection},
		{ID: "det-no-rule", Kind: event.KindDetection, Detection: &event.Detection{}},
		{Kind: event.KindDetection, Detection: &event.Detection{RuleID: "R"}}, // no event id
		{ID: "sum-no-sum", Kind: event.KindSummary},
		{ID: "hl-no-hl", Kind: event.KindHealth},
	}
	mustApply(t, s, evs...)
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range st.Rows {
		if n != 0 {
			t.Errorf("%s has %d rows", table, n)
		}
	}
	if st.Rejected != 9 {
		t.Errorf("Rejected = %d, want 9 (every stored kind without a usable key)", st.Rejected)
	}
	if err := s.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fileBytes(t, s.Path()), []byte("rm -rf")) {
		t.Fatal("activity content reached the database file")
	}
}

func TestHostileStringsAreCleanedAndClipped(t *testing.T) {
	s, _ := newStore(t)
	huge := strings.Repeat("A", 1<<20)
	a := agentAsset("a1")
	a.Name = "claude\x00code\r\nINJECTED\u202Egnp.exe\x1b[31m"
	a.Vendor = string([]byte{0xff, 0xfe, 'v', 0xc3})
	a.Path = "/opt/" + huge
	a.Version = huge
	a.RiskFlags = append([]string{"ok_flag", "with,comma", " spaced ", ""}, strings.Split(strings.Repeat("flag_x,", 500), ",")...)
	a.Evidence = []string{huge}
	mustApply(t, s, assetEvent(0, a, user("ali\nce", "10\x0000")))
	m := mcpAsset("m1")
	m.MCP.EnvKeys = []string{"GOOD", "A,B", "C\nD"}
	mustApply(t, s, assetEvent(0, m, nil))

	r := one(t, s, "agents", "asset_id", "a1")
	for col, v := range r {
		if !utf8.ValidString(v) {
			t.Errorf("agents.%s is not valid UTF-8", col)
		}
		if strings.ContainsAny(v, "\x00\r\n\x1b\u202e") {
			t.Errorf("agents.%s kept a control or override character: %q", col, v)
		}
		if len(v) > maxPath+8 {
			t.Errorf("agents.%s is %d bytes", col, len(v))
		}
	}
	if !strings.HasPrefix(r["name"], "claude\uFFFDcode") || !strings.Contains(r["name"], "INJECTED") {
		t.Errorf("name = %q", r["name"])
	}
	flags := strings.Split(r["risk_flags"], ",")
	if flags[0] != "ok_flag" || flags[1] != "with\uFFFDcomma" || flags[2] != "spaced" {
		t.Errorf("risk_flags start = %q", flags[:3])
	}
	if flags[len(flags)-1] != "..." || len(flags) > maxItems+1 {
		t.Errorf("a cut list must end in ... and stay bounded: %d items, last %q", len(flags), flags[len(flags)-1])
	}
	if keys := one(t, s, "mcp_servers", "asset_id", "m1")["env_keys"]; len(strings.Split(keys, ",")) != 3 {
		t.Errorf("env_keys = %q: a comma inside a name forged an extra element", keys)
	}

	// An over-long or unclean asset id is still one stable key.
	long := event.Asset{ID: strings.Repeat("z", 5000), Kind: event.AssetSkill, Name: "x"}
	mustApply(t, s, assetEvent(0, long, nil), assetEvent(time.Hour, long, nil))
	if n := len(mustQuery(t, s, "extensions")); n != 1 {
		t.Fatalf("over-long id produced %d rows", n)
	}
}

func TestTimestampsAreFixedWidthAndClamped(t *testing.T) {
	s, c := newStore(t)
	farFuture := event.At(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	wayOut := event.At(time.Date(12026, 1, 1, 0, 0, 0, 0, time.UTC))
	ancient := event.At(time.Date(1066, 10, 14, 0, 0, 0, 0, time.UTC))
	// Events from another zone are stored in UTC.
	est := time.FixedZone("EST", -5*3600)
	zoned := event.Time{Time: t0.In(est)}

	d1 := detectionEvent("future", 0, "R1", "high", "", user("u", "1"), "s")
	d1.TS = farFuture
	d2 := detectionEvent("wayout", 0, "R2", "high", "", user("u", "1"), "s")
	d2.TS = wayOut
	d3 := detectionEvent("ancient", 0, "R3", "high", "", user("u", "1"), "s")
	d3.TS = ancient
	d4 := detectionEvent("zero", 0, "R4", "high", "", user("u", "1"), "s")
	d4.TS = event.Time{}
	d5 := detectionEvent("zoned", 0, "R5", "high", "", user("u", "1"), "s")
	d5.TS = zoned
	a := agentAsset("a1")
	a.FirstSeen, a.LastSeen = ancient, farFuture
	mustApply(t, s, d1, d2, d3, d4, d5, assetEvent(0, a, nil), heartbeat("hb", 0, "w", nil))
	s.SetAgentProcesses([]AgentProcess{{PID: 1, StartTime: t0.In(est), AgentID: "x"}, {PID: 2, AgentID: "y"}})
	s.SetCoverage([]event.Coverage{{AgentID: "x", User: "u", State: "covered"}})
	s.MarkScan(c.now(), c.now(), []string{"a1"})

	shape := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)
	now := FormatTime(c.now())
	tsCols := map[string][]string{
		"agents": {"first_seen", "last_seen"}, "detections": {"ts"}, "agent_processes": {"start_time", "first_seen", "last_seen"},
		"coverage": {"updated"}, "health": {"started", "heartbeat", "last_scan"},
	}
	for table, cols := range tsCols {
		for _, r := range mustQuery(t, s, table) {
			for _, col := range cols {
				v := r[col]
				if v == "" {
					continue
				}
				if len(v) != 27 || !shape.MatchString(v) {
					t.Errorf("%s.%s = %q: not the fixed-width form", table, col, v)
				}
				if v > FormatTime(c.now().Add(futureSlack)) {
					t.Errorf("%s.%s = %q is in the future (now %s)", table, col, v, now)
				}
			}
		}
	}
	for _, id := range []string{"future", "wayout", "ancient", "zero"} {
		if got := one(t, s, "detections", "event_id", id)["ts"]; got != now {
			t.Errorf("detection %s: ts = %q, want the local clock %q", id, got, now)
		}
	}
	if got := one(t, s, "detections", "event_id", "zoned")["ts"]; got != FormatTime(t0) {
		t.Errorf("zoned ts = %q, want UTC %q", got, FormatTime(t0))
	}
	if got := one(t, s, "agent_processes", "pid", "2")["start_time"]; got != "" {
		t.Errorf("unset start_time = %q, want empty", got)
	}

	if FormatTime(time.Time{}) != "" || FormatTime(wayOut.Time) != "" || FormatTime(ancient.Time) != "" {
		t.Error("FormatTime must return empty for unset or out-of-range times")
	}
	if got := FormatTime(time.Date(2026, 1, 2, 3, 4, 5, 6789, est)); got != "2026-01-02T08:04:05.000006Z" {
		t.Errorf("FormatTime = %q", got)
	}
}

func TestRowCapsEvictOldest(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts every table past its cap")
	}
	s, c := newStore(t)
	caps := RowCaps()
	for table, want := range map[string]int{"detections": 5000, "sessions": 2000, "extensions": 10000, "agent_processes": 500} {
		if caps[table] != want {
			t.Fatalf("cap of %s = %d, want %d", table, caps[table], want)
		}
	}
	u := user("alice", "1000")
	const extra = 120

	// detections: oldest by ts go first.
	var evs []*event.Event
	for i := 0; i < caps["detections"]+extra; i++ {
		evs = append(evs, detectionEvent(fmt.Sprintf("d%05d", i), time.Duration(i)*time.Second, "R", "low", "", u, "s"))
	}
	rand.New(rand.NewSource(1)).Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
	c.add(48 * time.Hour) // so none of the timestamps is in the future
	for i := 0; i < len(evs); i += 1000 {
		mustApply(t, s, evs[i:min(i+1000, len(evs))]...)
		if st, _ := s.Stats(); st.Rows["detections"] > caps["detections"] {
			t.Fatalf("detections exceeded its cap between batches: %d", st.Rows["detections"])
		}
	}
	rows := mustQuery(t, s, "detections", "event_id")
	if len(rows) != caps["detections"] {
		t.Fatalf("detections = %d rows, want %d", len(rows), caps["detections"])
	}
	for _, r := range rows {
		if r["event_id"] < fmt.Sprintf("d%05d", extra) {
			t.Fatalf("an old detection (%s) survived while newer ones were evicted", r["event_id"])
		}
	}

	// sessions: oldest by last_event.
	evs = evs[:0]
	for i := 0; i < caps["sessions"]+extra; i++ {
		evs = append(evs, &event.Event{
			ID: fmt.Sprintf("s%05d", i), TS: at(time.Duration(i) * time.Second), Kind: event.KindSummary,
			User: u, Agent: &event.Agent{ID: "a"}, Session: &event.Session{ID: fmt.Sprintf("sess%05d", i)},
			Summary: &event.Summary{},
		})
	}
	mustApply(t, s, evs...)
	if n := len(mustQuery(t, s, "sessions")); n != caps["sessions"] {
		t.Fatalf("sessions = %d rows", n)
	}
	if rows, _ := s.QueryWhere(t.Context(), "sessions", nil, []Filter{{Column: "session_ref", Op: OpEq, Values: []string{SessionRef("1000", "a", "sess00000")}}}); len(rows) != 0 {
		t.Fatal("the oldest session survived")
	}

	// extensions: removed rows go before live ones.
	evs = evs[:0]
	for i, id := range ids("x", caps["extensions"]) {
		evs = append(evs, assetEvent(time.Duration(i)*time.Millisecond, event.Asset{ID: id, Kind: event.AssetSkill, Name: "s"}, u))
	}
	mustApply(t, s, evs...)
	gone := event.Asset{ID: "x09999", Kind: event.AssetSkill, Change: event.ChangeRemoved}
	mustApply(t, s, assetEvent(time.Hour, gone, u)) // the newest row, now removed
	evs = evs[:0]
	for _, id := range ids("y", extra) {
		evs = append(evs, assetEvent(2*time.Hour, event.Asset{ID: id, Kind: event.AssetSkill, Name: "s"}, u))
	}
	mustApply(t, s, evs...)
	st, _ := s.Stats()
	if st.Rows["extensions"] != caps["extensions"] {
		t.Fatalf("extensions = %d rows", st.Rows["extensions"])
	}
	var n int
	s.db.QueryRow("SELECT count(*) FROM extensions WHERE asset_id = 'x09999'").Scan(&n)
	if n != 0 {
		t.Fatal("a removed extension was kept while live ones were evicted")
	}
	s.db.QueryRow("SELECT count(*) FROM extensions WHERE asset_id LIKE 'y%'").Scan(&n)
	if n != extra {
		t.Fatalf("newest extensions kept: %d of %d", n, extra)
	}
	if st.Evicted["extensions"] != extra || st.Evicted["detections"] != extra || st.Evicted["sessions"] != extra {
		t.Fatalf("Evicted = %v", st.Evicted)
	}

	// agent_processes: exited rows go first; more live ones than the cap keeps the newest.
	var procs []AgentProcess
	for i := 0; i < caps["agent_processes"]; i++ {
		procs = append(procs, AgentProcess{PID: 1000 + i, StartTime: t0.Add(time.Duration(i) * time.Second), AgentID: "a"})
	}
	if err := s.SetAgentProcesses(procs); err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	var next []AgentProcess
	for i := 0; i < caps["agent_processes"]+extra; i++ {
		next = append(next, AgentProcess{PID: 50000 + i, StartTime: t0.Add(2*time.Hour + time.Duration(i)*time.Second), AgentID: "a"})
	}
	if err := s.SetAgentProcesses(next); err != nil {
		t.Fatal(err)
	}
	prows := mustQuery(t, s, "agent_processes")
	if len(prows) != caps["agent_processes"] {
		t.Fatalf("agent_processes = %d rows", len(prows))
	}
	for _, r := range prows {
		if r["running"] != "1" || r["pid"] < fmt.Sprint(50000+extra) {
			t.Fatalf("kept the wrong process: %v", r)
		}
	}
}

// Random, hostile events must never panic, fail the batch or grow a cell
// without bound.
func TestApplySurvivesRandomEvents(t *testing.T) {
	s, _ := newStore(t)
	rng := rand.New(rand.NewSource(42))
	junk := func() string {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		return string(b)
	}
	kinds := []event.Kind{event.KindInventory, event.KindPosture, event.KindDetection, event.KindSummary, event.KindHealth, event.KindActivity, ""}
	assetKinds := []event.AssetKind{event.AssetAgent, event.AssetMCPServer, event.AssetHook, "", event.AssetKind(junk())}
	for round := 0; round < 20; round++ {
		var evs []*event.Event
		for i := 0; i < 50; i++ {
			e := &event.Event{
				ID: junk(), Kind: kinds[rng.Intn(len(kinds))], Type: junk(), Writer: junk(), Privacy: junk(),
				TS:     event.At(time.Unix(rng.Int63n(1<<40)-(1<<39), rng.Int63())),
				Labels: map[string]string{junk(): junk(), LabelRulesVersion: junk()},
			}
			if rng.Intn(4) > 0 {
				e.User = &event.User{Name: junk(), ID: junk()}
				e.Agent = &event.Agent{ID: junk()}
				e.Session = &event.Session{ID: junk(), PermissionMode: junk()}
				e.Host = &event.Host{ID: junk()}
			}
			if rng.Intn(3) > 0 {
				e.Asset = &event.Asset{
					ID: junk(), Kind: assetKinds[rng.Intn(len(assetKinds))], Name: junk(), Path: junk(),
					Owner: junk(), RiskFlags: []string{junk(), junk()}, Change: event.Change(junk()),
					PID: rng.Intn(1<<31) - (1 << 30),
				}
				if rng.Intn(2) == 0 {
					e.Asset.MCP = &event.MCP{Command: junk(), EnvKeys: []string{junk()}, Args: []string{junk()}}
					e.Asset.Telemetry = &event.Telemetry{Hooks: junk()}
				}
				e.Check = &event.Check{ID: junk(), Status: []string{"fail", "pass", "unknown", junk()}[rng.Intn(4)], Subject: junk(), Owner: junk()}
				e.Detection = &event.Detection{RuleID: junk(), DedupKey: junk(), Count: rng.Intn(1<<31) - (1 << 30), Tags: []string{junk()}}
				e.Summary = &event.Summary{ToolCalls: map[string]int{junk(): rng.Intn(1<<31) - (1 << 30)}, Detections: []string{junk()}, MaxSeverity: junk()}
				e.Health = &event.Health{SensorVersion: junk(), UptimeS: rng.Int63() - (1 << 62), RulesCount: -5,
					Counters: map[string]uint64{junk(): rng.Uint64(), "stream.x.emitted": rng.Uint64(), CounterErrors: rng.Uint64()}}
			}
			evs = append(evs, e)
		}
		if err := s.Apply(evs); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	for _, td := range Tables {
		for _, r := range mustQuery(t, s, td.Name) {
			for col, v := range r {
				if !utf8.ValidString(v) || len(v) > maxPath+8 {
					t.Fatalf("%s.%s: invalid or oversized value (%d bytes)", td.Name, col, len(v))
				}
			}
		}
	}
}

func TestClip(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 10, "plain"},
		{"toolong", 4, "tool"},
		{"", 4, ""},
		{"héllo", 2, "h"},  // never cut inside a rune
		{"héllo", 3, "hé"}, //
		{"a\x00b", 10, "a\uFFFDb"},
		{"a\tb\nc", 10, "a\uFFFDb\uFFFDc"},
		{string([]byte{'a', 0xff, 'b'}), 10, "a\uFFFDb"},
		{"x\u200by\u2066z\ufeff", 20, "x\uFFFDy\uFFFDz\uFFFD"},
		{"日本語", 6, "日本"},
		{"keep\uFFFDas-is", 20, "keep\uFFFDas-is"},
	} {
		if got := clip(tc.in, tc.max); got != tc.want {
			t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"/usr/bin/npx", "npx"}, {`C:\Tools\uvx.exe`, "uvx.exe"}, {"npx", "npx"}, {"/a/b/", "b"}, {"", ""},
		{`mixed/sep\node`, "node"},
	} {
		if got := baseName(tc.in); got != tc.want {
			t.Errorf("baseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
