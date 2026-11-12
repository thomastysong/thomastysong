package fleetgen

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func mustBuild(t *testing.T, o Options) *Content {
	t.Helper()
	c, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustProfile(t *testing.T, c *Content, name string) Profile {
	t.Helper()
	p, ok := c.Profile(name)
	if !ok {
		t.Fatalf("no profile %s", name)
	}
	return p
}

// policyResults evaluates every policy of a profile.
func policyResults(e *emu, p Profile) map[string]bool {
	out := map[string]bool{}
	for _, pol := range p.Policies {
		out[pol.Key] = e.passes(pol.Query)
	}
	return out
}

func failing(res map[string]bool) []string {
	var out []string
	for k, ok := range res {
		if !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var spoorPolicyKeys = []string{
	"bundle_current", "hooks_effective", "no_autorun_plant", "no_blind_agents", "no_bypass",
	"no_critical_posture", "no_high_detections_24h", "no_risky_mcp", "scan_complete", "sensor_reporting",
}

func without(all []string, drop ...string) []string {
	var out []string
	for _, a := range all {
		keep := true
		for _, d := range drop {
			if a == d {
				keep = false
			}
		}
		if keep {
			out = append(out, a)
		}
	}
	return out
}

func TestPolicyKeysComplete(t *testing.T) {
	c := mustBuild(t, Options{})
	for _, name := range []string{ProfileStock, ProfileFleetd} {
		var keys []string
		for _, p := range mustProfile(t, c, name).Policies {
			keys = append(keys, p.Key)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != strings.Join(spoorPolicyKeys, ",") {
			t.Errorf("%s policies %v, test table expects %v", name, keys, spoorPolicyKeys)
		}
	}
}

// TestPoliciesFailClosed is the core property (BUILD-C C5 and addendum):
// every policy passes on a healthy database, each planted violation fails
// exactly its own policy, a missing database fails all of them, and the two
// heartbeat windows separate a sleeping laptop from a dead sensor.
func TestPoliciesFailClosed(t *testing.T) {
	c := mustBuild(t, Options{})
	type scenario struct {
		name  string
		build func(f *fixture) // nil: no database at all
		fail  []string
	}
	scenarios := []scenario{
		{"healthy", func(f *fixture) { f.healthy() }, nil},
		{"missing database", nil, spoorPolicyKeys},
		{"late heartbeat record does not move the beat back", func(f *fixture) {
			f.healthy()
			f.heartbeat(2*time.Hour, "3")
		}, nil},
		{"only heartbeat is 25h old (sensor gone)", func(f *fixture) {
			f.apply(f.agent("a-claude", "claude-code", event.AssetAgent, "managed"))
			f.scan(true, "a-claude")
			f.heartbeat(25*time.Hour, "3")
		}, spoorPolicyKeys},
		{"hooks: user scope only", func(f *fixture) {
			f.healthy()
			f.apply(f.agent("a-gemini", "gemini-cli", event.AssetAgent, "user"))
		}, []string{"hooks_effective"}},
		{"hooks: missing for an IDE", func(f *fixture) {
			f.healthy()
			f.apply(f.agent("a-cursor", "cursor", event.AssetApp, "missing"))
		}, []string{"hooks_effective"}},
		{"hooks: unsupported agent is not counted", func(f *fixture) {
			f.healthy()
			f.apply(f.agent("a-goose", "goose", event.AssetAgent, "unsupported"))
		}, nil},
		{"high detection now", func(f *fixture) {
			f.healthy()
			f.apply(f.detection("d-new", "SPR-EXFIL-003", event.SevCritical, time.Minute))
		}, []string{"no_high_detections_24h"}},
		{"bypass switch on a process", func(f *fixture) {
			f.healthy()
			f.processes("--dangerously-skip-permissions")
		}, []string{"no_bypass"}},
		{"bypass multi-word switch", func(f *fixture) {
			f.healthy()
			f.processes("--model x", "--permission-mode bypassPermissions")
		}, []string{"no_bypass"}},
		{"bypass default in settings", func(f *fixture) {
			f.healthy()
			f.apply(f.agent("a-claude", "claude-code", event.AssetAgent, "managed", "bypass_permissions_default"))
		}, []string{"no_bypass"}},
		{"bypass session", func(f *fixture) {
			f.healthy()
			f.apply(f.summary("sess-2", "bypass"))
		}, []string{"no_bypass"}},
		{"hook-trust switch is not a bypass", func(f *fixture) {
			f.healthy()
			f.processes("--dangerously-bypass-hook-trust")
		}, nil},
		{"unpinned MCP", func(f *fixture) {
			f.healthy()
			f.apply(f.mcp("m-bad", false, "unpinned_package", "remote_fetch_exec"))
		}, []string{"no_risky_mcp"}},
		{"inline secret MCP", func(f *fixture) {
			f.healthy()
			f.apply(f.mcp("m-secret", true, "inline_secret"))
		}, []string{"no_risky_mcp"}},
		{"auto-run task in a project", func(f *fixture) {
			f.healthy()
			f.apply(f.ext("x-task", event.AssetProjectConfig, "autorun_task"))
		}, []string{"no_autorun_plant"}},
		{"auto-run flag on a non-project item is not a plant", func(f *fixture) {
			f.healthy()
			f.apply(f.ext("x-hook", event.AssetHook, "autorun_hook"))
		}, nil},
		{"heartbeat without bundle label keeps the known bundle", func(f *fixture) {
			f.healthy()
			f.heartbeat(0, "")
		}, nil},
		{"no bundle ever installed", func(f *fixture) {
			f.apply(f.agent("a-claude", "claude-code", event.AssetAgent, "managed"))
			f.processes()
			f.coverage("covered")
			f.scan(true, "a-claude")
			f.heartbeat(0, "")
		}, []string{"bundle_current"}},
		{"bundle below minimum", func(f *fixture) {
			f.healthy()
			f.heartbeat(0, "0")
		}, []string{"bundle_current"}},
		{"scan incomplete", func(f *fixture) {
			f.healthy()
			f.scan(false)
		}, []string{"scan_complete"}},
		{"blind agent", func(f *fixture) {
			f.healthy()
			f.coverage("blind")
		}, []string{"no_blind_agents"}},
		{"high posture failure", func(f *fixture) {
			f.healthy()
			f.apply(f.check("SPR-POST-HIGH", event.SevHigh))
		}, []string{"no_critical_posture"}},
	}
	for _, sc := range scenarios {
		for _, fl := range []flavour{atcFlavour, typedFlavour} {
			t.Run(sc.name+"/"+fl.String(), func(t *testing.T) {
				path := "" // nil build: no database at all
				if sc.build != nil {
					f := newFixture(t)
					sc.build(f)
					path = f.close()
				}
				e := newEmu(t, path, fl)
				for _, prof := range []string{ProfileStock, ProfileFleetd} {
					got := failing(policyResults(e, mustProfile(t, c, prof)))
					want := append([]string(nil), sc.fail...)
					sort.Strings(want)
					if strings.Join(got, ",") != strings.Join(want, ",") {
						t.Errorf("%s: failing policies %v, want %v", prof, got, want)
					}
				}
			})
		}
	}
}

// TestHeartbeatWindows shows the trade-off the README states: a sensor
// that last beat 2 hours ago fails only the sensor policy; after 24 hours
// everything fails.
func TestHeartbeatWindows(t *testing.T) {
	c := mustBuild(t, Options{})
	p := mustProfile(t, c, ProfileStock)
	for _, tc := range []struct {
		ago  time.Duration
		fail []string
	}{
		{10 * time.Minute, nil},
		{2 * time.Hour, []string{"sensor_reporting"}},
		{23 * time.Hour, []string{"sensor_reporting"}},
		{25 * time.Hour, spoorPolicyKeys},
	} {
		t.Run(human(tc.ago), func(t *testing.T) {
			f := newFixture(t)
			f.apply(f.agent("a-claude", "claude-code", event.AssetAgent, "managed"))
			f.processes()
			f.coverage("covered")
			f.scan(true, "a-claude")
			f.heartbeat(tc.ago, "3")
			e := newEmu(t, f.close(), atcFlavour)
			got := failing(policyResults(e, p))
			if strings.Join(got, ",") != strings.Join(tc.fail, ",") {
				t.Errorf("failing %v, want %v", got, tc.fail)
			}
		})
	}
}

func TestFleetdPoliciesConsultAITools(t *testing.T) {
	c := mustBuild(t, Options{})
	f := newFixture(t)
	f.healthy()
	path := f.close()
	for _, tc := range []struct {
		row  []any
		fail string
	}{
		{[]any{"agents", "claude", "bypass_permissions, auto_accept_edits"}, "no_bypass"},
		{[]any{"agents", "claude", "skip_permissions_runtime"}, "no_bypass"},
		{[]any{"mcp_server", "fs", "mcp_fs_write,unpinned_dependency"}, "no_risky_mcp"},
		{[]any{"mcp_server", "fs", "plaintext_secret"}, "no_risky_mcp"},
		{[]any{"agents", "claude", "auto_accept_edits"}, ""},
		{[]any{"mcp_server", "fs", "unpinned_dependency_x"}, ""}, // whole tokens only
	} {
		e := newEmu(t, path, atcFlavour)
		e.exec("INSERT INTO ai_tools (type, name, risk_flags) VALUES (?, ?, ?)", tc.row...)
		got := failing(policyResults(e, mustProfile(t, c, ProfileFleetd)))
		want := ""
		if tc.fail != "" {
			want = tc.fail
		}
		if strings.Join(got, ",") != want {
			t.Errorf("ai_tools %v: failing %v, want %q", tc.row, got, want)
		}
		// The stock profile never reads ai_tools.
		if got := failing(policyResults(e, mustProfile(t, c, ProfileStock))); len(got) != 0 {
			t.Errorf("stock profile reacted to ai_tools: %v", got)
		}
	}
}

func TestBuiltinPolicies(t *testing.T) {
	c := mustBuild(t, Options{})
	p := mustProfile(t, c, ProfileBuiltin)
	for _, pol := range p.Policies {
		if pol.Window != 0 || strings.Contains(pol.Query, "spoor_") {
			t.Errorf("%s: builtin policies must not depend on spoor tables", pol.Name)
		}
	}
	e := newEmu(t, "", atcFlavour)
	if got := failing(policyResults(e, p)); len(got) != 0 {
		t.Errorf("empty ai_tools: failing %v", got)
	}
	e.exec("INSERT INTO ai_tools (type, name, risk_flags) VALUES ('agents', 'claude', 'bypass_permissions')")
	e.exec("INSERT INTO ai_tools (type, name, risk_flags) VALUES ('mcp_server', 'x', 'plaintext_secret')")
	if got := failing(policyResults(e, p)); strings.Join(got, ",") != "no_bypass,no_risky_mcp" {
		t.Errorf("risky ai_tools: failing %v", got)
	}
}

func labelResults(e *emu, p Profile) map[string]bool {
	out := map[string]bool{}
	for _, l := range p.Labels {
		out[l.Name] = e.passes(l.Query)
	}
	return out
}

func TestLabels(t *testing.T) {
	c := mustBuild(t, Options{})
	stock := mustProfile(t, c, ProfileStock)
	healthy := newFixture(t)
	healthy.healthy()
	hpath := healthy.close()
	old := newFixture(t)
	old.heartbeat(3*time.Hour, "3")
	opath := old.close()

	type tc struct {
		name     string
		db       string
		platform string
		files    []string
		noTables bool
		want     map[string]bool
	}
	cases := []tc{
		{"healthy linux host", hpath, "linux", []string{"/usr/bin/spoor", "/var/lib/spoor/state.db"}, false,
			map[string]bool{"spoor installed": true, "AI agents present": true, "spoor sensor unhealthy": false, "spoor tables unavailable": false}},
		{"stale heartbeat", opath, "linux", []string{"/usr/bin/spoor"}, false,
			map[string]bool{"spoor installed": true, "AI agents present": false, "spoor sensor unhealthy": true, "spoor tables unavailable": false}},
		{"database deleted", "", "linux", []string{"/usr/bin/spoor"}, false,
			map[string]bool{"spoor installed": true, "AI agents present": false, "spoor sensor unhealthy": true, "spoor tables unavailable": false}},
		{"extension not loaded", hpath, "linux", []string{"/usr/bin/spoor"}, true,
			map[string]bool{"spoor installed": true, "AI agents present": true, "spoor sensor unhealthy": false, "spoor tables unavailable": true}},
		{"not installed", "", "linux", nil, false,
			map[string]bool{"spoor installed": false, "AI agents present": false, "spoor sensor unhealthy": false, "spoor tables unavailable": false}},
		// A POSIX path on Windows resolves to a directory any user can
		// create (C:\usr\bin\spoor); it must not count there.
		{"posix path on windows is ignored", "", "windows", []string{"/usr/bin/spoor"}, false,
			map[string]bool{"spoor installed": false, "AI agents present": false, "spoor sensor unhealthy": false, "spoor tables unavailable": false}},
		{"windows install", "", "windows", []string{`C:\Program Files\spoor\spoor.exe`}, false,
			map[string]bool{"spoor installed": true, "AI agents present": false, "spoor sensor unhealthy": true, "spoor tables unavailable": false}},
		{"darwin db only", "", "darwin", []string{"/Library/Application Support/spoor/state.db"}, false,
			map[string]bool{"spoor installed": true, "AI agents present": false, "spoor sensor unhealthy": true, "spoor tables unavailable": false}},
		{"unknown platform", "", "freebsd", []string{"/usr/bin/spoor"}, false,
			map[string]bool{"spoor installed": false, "AI agents present": false, "spoor sensor unhealthy": false, "spoor tables unavailable": false}},
	}
	for _, x := range cases {
		for _, fl := range []flavour{atcFlavour, typedFlavour} {
			t.Run(x.name+"/"+fl.String(), func(t *testing.T) {
				e := newEmu(t, x.db, fl)
				e.exec("UPDATE osquery_info SET build_platform = ?", x.platform)
				for _, p := range x.files {
					e.exec("INSERT INTO file (path) VALUES (?)", p)
				}
				if x.noTables {
					e.exec("DELETE FROM osquery_registry")
				}
				got := labelResults(e, stock)
				for name, want := range x.want {
					if got[name] != want {
						t.Errorf("label %q = %v, want %v", name, got[name], want)
					}
				}
			})
		}
	}
	// fleetd: AI agents present comes from ai_tools, not spoor.
	e := newEmu(t, "", atcFlavour)
	fl := labelResults(e, mustProfile(t, c, ProfileFleetd))
	if fl["AI agents present"] {
		t.Error("fleetd AI agents present without ai_tools rows")
	}
	e.exec("INSERT INTO ai_tools (type, name) VALUES ('sockets', 'x')")
	if labelResults(e, mustProfile(t, c, ProfileFleetd))["AI agents present"] {
		t.Error("a live socket alone must not make a host an AI-agent host")
	}
	e.exec("INSERT INTO ai_tools (type, name) VALUES ('agents', 'claude')")
	if !labelResults(e, mustProfile(t, c, ProfileFleetd))["AI agents present"] {
		t.Error("fleetd AI agents present with an ai_tools agent row")
	}
}

func TestReportsRun(t *testing.T) {
	c := mustBuild(t, Options{})
	f := newFixture(t)
	f.healthy()
	f.apply(f.mcp("m-bad", false, "unpinned_package"), f.ext("x-task", event.AssetProjectConfig, "autorun_task"))
	path := f.close()
	for _, fl := range []flavour{atcFlavour, typedFlavour} {
		e := newEmu(t, path, fl)
		e.exec("INSERT INTO ai_tools (type, name, version, risk_flags, running) VALUES ('agents', 'claude', '2.1', '', 1)")
		for _, p := range c.Profiles {
			for _, r := range p.Reports {
				rows := e.rows(r.Query)
				switch r.Key {
				case "detections":
					// Both fixture detections are within 7 days.
					if len(rows) != 2 {
						t.Errorf("%s/%s/%s: %d rows, want 2", fl, p.Name, r.Name, len(rows))
					}
				case "inventory":
					if len(rows) != 1 {
						t.Fatalf("%s/%s/%s: %d rows, want one packed row", fl, p.Name, r.Name, len(rows))
					}
					for k, v := range rows[0] {
						if strings.HasSuffix(k, "_total") {
							continue
						}
						var list []map[string]any
						if err := json.Unmarshal([]byte(v), &list); err != nil {
							t.Errorf("%s/%s: column %s is not a JSON list: %v", fl, r.Name, k, err)
						}
						if k == "mcp_servers" && (len(list) != 2 || list[0]["risk_flags"] != "unpinned_package") {
							t.Errorf("%s: risky MCP servers must come first: %v", fl, list)
						}
					}
				case "health":
					if len(rows) != 1 || rows[0]["bundle_version"] != "3" {
						t.Errorf("%s: health rows %v", fl, rows)
					}
				case "coverage":
					if len(rows) != 1 || rows[0]["state"] != "covered" {
						t.Errorf("%s: coverage rows %v", fl, rows)
					}
				}
			}
		}
	}
}

// TestPackedReportBounded fills every inventory table past the report's
// list cap with maximum-length values full of characters JSON must escape,
// and checks the one-row result stays below Fleet's 512 KiB per-host cap.
func TestPackedReportBounded(t *testing.T) {
	c := mustBuild(t, Options{})
	f := newFixture(t)
	long := strings.Repeat(`"\`, 600) // clipped by state, doubled by JSON escaping
	var evs []*event.Event
	for i := 0; i < packedRows+50; i++ {
		id := fmt.Sprintf("%04d", i)
		a := f.agent("a"+id, long, event.AssetAgent, long, long, long)
		a.Asset.Name, a.Asset.Version, a.Asset.Owner = long, long, long
		m := f.mcp("m"+id, false, long, long)
		m.Asset.Name, m.Asset.Parent, m.Asset.Owner = long, long, long
		m.Asset.MCP.Package, m.Asset.MCP.Version, m.Asset.MCP.URLHost = long, long, long
		x := f.ext("x"+id, event.AssetProjectConfig, long, long)
		x.Asset.Name, x.Asset.Parent, x.Asset.Owner = long, long, long
		evs = append(evs, a, m, x)
	}
	f.apply(evs...)
	f.heartbeat(0, "3")
	e := newEmu(t, f.close(), atcFlavour)
	for i := 0; i < packedRows+50; i++ {
		e.exec("INSERT INTO ai_tools (type, name, identifier, version, source, risk_flags, running) VALUES (?, ?, ?, ?, ?, ?, 1)",
			long, long, long, long, long, long)
	}
	for _, p := range c.Profiles {
		for _, r := range p.Reports {
			if r.Key != "inventory" {
				continue
			}
			rows := e.rows(r.Query)
			size := 0
			for k, v := range rows[0] {
				size += len(k) + len(v)
			}
			t.Logf("%s/%s: %d bytes", p.Name, r.Name, size)
			if size >= 512<<10 {
				t.Errorf("%s/%s: %d bytes, Fleet drops host results of 512 KiB or more", p.Name, r.Name, size)
			}
			if rows[0]["agents_total"] != "" && rows[0]["agents_total"] != fmt.Sprint(packedRows+50) {
				t.Errorf("agents_total = %s, want the true total", rows[0]["agents_total"])
			}
		}
	}
}

// TestOptInExecReportsAcrossRuns: osquery hands a scheduled query only the
// events since its previous run, so the agent's shell (depth 1) usually
// started in an earlier batch than the command it runs (depth 2). The
// report must still attribute that command, through the live processes
// table, and must not trust a reused pid that started after the command.
func TestOptInExecReportsAcrossRuns(t *testing.T) {
	c := mustBuild(t, Options{})
	f := newFixture(t)
	f.healthy() // agent root pid 4242 running
	path := f.close()
	for _, fl := range []flavour{atcFlavour, typedFlavour} {
		e := newEmu(t, path, fl)
		// This run's batch: 5001 (parent 5000, the shell from an earlier
		// run), 5101 (parent 5100, a pid reused after the event) and 5201
		// (parent 5200, gone from the process table).
		e.exec(`INSERT INTO process_events (pid, parent, path, cmdline, cwd, uid, time) VALUES
			(5001, 5000, '/usr/bin/curl', 'curl x', '/home/ana/src', 1000, 2000),
			(5101, 5100, '/usr/bin/id', 'id', '/', 1000, 2000),
			(5201, 5200, '/usr/bin/env', 'env', '/', 1000, 2000)`)
		e.exec(`INSERT INTO es_process_events (pid, parent, path, cmdline, cwd, uid, time, event_type) VALUES
			(5001, 5000, '/usr/bin/curl', 'curl x', '/', 501, 2000, 'exec')`)
		e.exec(`INSERT INTO process_etw_events (pid, ppid, path, cmdline, username, time, type) VALUES
			(5001, 5000, 'C:\Windows\System32\curl.exe', 'curl x', 'ana', 2000, 'ProcessStart')`)
		e.exec(`INSERT INTO processes (pid, parent, start_time) VALUES
			(5000, 4242, 1000), (5100, 4242, 2500), (6000, 1, 10)`)
		for _, r := range c.OptIn {
			rows := e.rows(r.Query)
			if len(rows) != 1 {
				t.Fatalf("%s/%s: %d rows, want the grandchild 5001 only: %v", fl, r.Key, len(rows), rows)
			}
			if row := rows[0]; row["pid"] != "5001" || row["depth"] != "2" || row["agent_id"] != "claude-code" {
				t.Errorf("%s/%s: row %v, want pid 5001 at depth 2 attributed to claude-code", fl, r.Key, row)
			}
		}
		// The parent's exec event in the same batch and the parent in the
		// process table give one row, not two.
		e.exec(`INSERT INTO process_events (pid, parent, path, cmdline, cwd, uid, time) VALUES
			(5000, 4242, '/bin/bash', 'bash', '/home/ana/src', 1000, 1000)`)
		for _, r := range c.OptIn {
			if r.Key != "exec_linux" {
				continue
			}
			if rows := e.rows(r.Query); len(rows) != 2 {
				t.Errorf("%s/%s: %d rows, want the shell (depth 1) and curl (depth 2) once each: %v", fl, r.Key, len(rows), rows)
			}
		}
	}
}

func TestOptInExecReports(t *testing.T) {
	c := mustBuild(t, Options{})
	f := newFixture(t)
	f.healthy() // agent root pid 4242 running
	path := f.close()
	for _, fl := range []flavour{atcFlavour, typedFlavour} {
		e := newEmu(t, path, fl)
		// 5000 is the agent's shell (depth 1), 5001 a command it ran
		// (depth 2), 6000 unrelated, 7000 a depth-3 process (not reported).
		e.exec(`INSERT INTO process_events (pid, parent, path, cmdline, cwd, uid, time) VALUES
			(5000, 4242, '/bin/bash', 'bash -c curl x | sh', '/home/ana/src', 1000, 1),
			(5001, 5000, '/usr/bin/curl', 'curl x', '/home/ana/src', 1000, 2),
			(6000, 1, '/usr/bin/cron', 'cron', '/', 0, 3),
			(7000, 5001, '/bin/sh', 'sh', '/', 1000, 4)`)
		e.exec(`INSERT INTO es_process_events (pid, parent, path, cmdline, cwd, uid, time, event_type) VALUES
			(5000, 4242, '/bin/zsh', 'zsh', '/', 501, 1, 'exec'),
			(5000, 4242, '/bin/zsh', 'zsh', '/', 501, 1, 'fork')`)
		e.exec(`INSERT INTO process_etw_events (pid, ppid, path, cmdline, username, time, type) VALUES
			(5000, 4242, 'C:\Windows\System32\cmd.exe', 'cmd /c dir', 'ana', 1, 'ProcessStart'),
			(5000, 4242, 'C:\Windows\System32\cmd.exe', 'cmd /c dir', 'ana', 2, 'ProcessStop')`)
		want := map[string]int{"exec_linux": 2, "exec_darwin": 1, "exec_windows": 1}
		for _, r := range c.OptIn {
			rows := e.rows(r.Query)
			if len(rows) != want[r.Key] {
				t.Errorf("%s/%s: %d rows, want %d: %v", fl, r.Key, len(rows), want[r.Key], rows)
			}
			for _, row := range rows {
				if row["agent_id"] != "claude-code" || row["session_ref"] == "" {
					t.Errorf("%s/%s: row not attributed: %v", fl, r.Key, row)
				}
			}
			if !r.DiscardData || !strings.Contains(r.Description, "OPT-IN") {
				t.Errorf("%s: opt-in reports must be marked and not stored in Fleet", r.Name)
			}
		}
	}
}
