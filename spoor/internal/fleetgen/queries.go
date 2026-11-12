package fleetgen

import (
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

// Lookback windows of the policies and reports that look at recent
// activity rather than at current state.
const (
	// DetectionLookback is the window of the detection and bypass policies:
	// Fleet evaluates policies about once an hour, so a policy over
	// "running now" would miss a session that ended between two runs.
	DetectionLookback = 24 * time.Hour
	// detectionReportWindow bounds the differential detection report, so the
	// first run on a host sends a bounded backlog to the log destination.
	detectionReportWindow = 7 * 24 * time.Hour
	// execAgentWindow is how long an exited agent root process still
	// attributes child processes in the opt-in exec reports.
	execAgentWindow = time.Hour
)

// Packed reports return one row per host. Fleet does not store a host's
// result above 512 KiB and drops log lines above 1 MiB, so every list is
// capped in rows and every field in characters; a test fills the tables
// with maximum-length values and checks the result stays under the limit.
const (
	packedRows  = 100
	packedField = 64
	packedFlags = 256
)

// Fleet policy and report vocabulary.
const (
	loggingSnapshot          = "snapshot"
	loggingDifferentialNoRem = "differential_ignore_removals"
)

// Report intervals in seconds.
const (
	intervalDetections = 900
	intervalHealth     = 3600
	intervalCoverage   = 3600
	intervalInventory  = 4 * 3600
	intervalExec       = 600
)

// ---- labels ----

// installedPredicate is true for a row of osquery's file table that is one
// of spoor's own files for the OS osquery was built for. Every path is
// stat'ed (the IN list is what osquery pushes down to the file table), but
// only the running OS's paths count: on Windows "/usr/bin/spoor" resolves to
// \usr\bin\spoor on the current drive, a directory an unprivileged user can
// create, so a POSIX path must never be accepted there.
func (g *gen) installedPredicate() string {
	var all []string
	var cases []string
	for _, p := range Platforms {
		paths := []string{g.r.binPaths[p], g.r.dbPaths[p]}
		all = append(all, paths...)
		cases = append(cases, "    WHEN "+sqlString(p)+" THEN "+sqlIn("path", paths))
	}
	return sqlIn("path", all) + "\n  AND CASE (SELECT build_platform FROM osquery_info)\n" +
		strings.Join(cases, "\n") + "\n    ELSE 0 END"
}

func (g *gen) labelInstalled() Label {
	return Label{
		Name: "spoor installed",
		Description: "The spoor binary or its state database exists at the path a system install uses " +
			"(binary or state database; exact paths, no wildcards). Uses only osquery's file table, so it " +
			"works before any spoor table is available and can scope the rollout.",
		Query: "SELECT 1 FROM file\nWHERE " + g.installedPredicate() + "\nLIMIT 1;",
	}
}

func (g *gen) labelUnhealthy() Label {
	return Label{
		Name: "spoor sensor unhealthy",
		Description: "spoor is installed but its heartbeat is older than " + human(g.r.alert) +
			" or missing. A host whose spoor tables are not loaded at all cannot answer this " +
			"query; it appears in \"spoor tables unavailable\" instead.",
		Query: "SELECT 1 FROM file\nWHERE " + g.installedPredicate() +
			"\n  AND NOT " + state.HeartbeatGuard(g.r.alert) + "\nLIMIT 1;",
	}
}

func (g *gen) labelTablesUnavailable() Label {
	return Label{
		Name: "spoor tables unavailable",
		Description: "spoor is installed but osquery has no spoor_health table: the extension is not " +
			"loaded or the ATC agent options did not reach the host. Every spoor policy shows no " +
			"response (neither pass nor fail) on such a host.",
		Query: "SELECT 1 FROM file\nWHERE " + g.installedPredicate() +
			"\n  AND NOT EXISTS (SELECT 1 FROM osquery_registry\n" +
			"    WHERE registry = 'table' AND name = " + sqlString(tbl("health")) + " AND active = 1)\nLIMIT 1;",
	}
}

func labelAgentsSpoor() Label {
	return Label{
		Name:        "AI agents present",
		Description: "spoor's inventory lists at least one AI agent, AI app or IDE extension, AI browser or local model runtime that has not been removed.",
		Query:       "SELECT 1 FROM " + tbl("agents") + " WHERE change != 'removed' LIMIT 1;",
	}
}

// aiToolsTypes are the ai_tools rows that mean "an AI tool is installed"
// (sockets are live connections, agent_instruction are files).
var aiToolsTypes = []string{"agents", "apps", "ide_plugins", "mcp_server", "browser_extension"}

func labelAgentsAITools() Label {
	return Label{
		Name: "AI agents present",
		Description: "Fleet's ai_tools table (fleetd 1.59.0 or later) lists an AI agent, app, IDE plugin, " +
			"MCP server or browser extension. Needs no spoor table, so it can scope the spoor rollout.",
		Query: "SELECT 1 FROM ai_tools WHERE " + sqlIn("type", aiToolsTypes) + " LIMIT 1;",
	}
}

// ---- policies ----

// sensorPolicy is the dedicated freshness policy: the one to alert on.
func (g *gen) sensorPolicy() Policy {
	return Policy{
		Key:  "sensor_reporting",
		Name: "spoor - sensor is reporting",
		Description: "The spoor sensor wrote a heartbeat to its state database in the last " + human(g.r.alert) +
			". This is the policy to alert on: every other spoor policy only fails after " + human(g.r.guard) +
			" without a heartbeat, so that a laptop waking from sleep does not turn them all red.",
		Resolution: "Check that the spoor service is installed and running (`spoor doctor`) and that the " +
			"state database path in the agent options matches the sensor's configuration.",
		Window: g.r.alert,
	}
}

// guarded builds a "no X" policy with the long heartbeat guard.
func (g *gen) guarded(key, name, desc, resolution, violation string) Policy {
	return Policy{
		Key:  key,
		Name: name,
		Description: desc + " Fails closed: it also fails when the sensor has not written a heartbeat in " +
			human(g.r.guard) + " or its database is missing, because a missing database reads as empty tables.",
		Resolution: resolution,
		Violation:  violation,
		Window:     g.r.guard,
	}
}

func (g *gen) hooksPolicy() Policy {
	return g.guarded("hooks_effective",
		"spoor - managed hooks effective for every AI agent",
		"Every installed agent whose hook protocol spoor speaks ("+strings.Join(g.v.hookAgents, ", ")+
			") has spoor's managed hooks in place and unmodified. User-scope hooks do not count: the "+
			"user can remove them.",
		"Run `spoor hooks status` on the host, then `spoor hooks install --scope managed`. For "+
			"'shadowed', deliver the hooks through the higher-precedence policy source the agent reads.",
		"SELECT 1 FROM "+tbl("agents")+"\nWHERE change != 'removed'\n  AND "+
			sqlIn("catalog_id", g.v.hookAgents)+"\n  AND hooks != 'managed'")
}

func (g *gen) detectionsPolicy() Policy {
	return g.guarded("no_high_detections_24h",
		"spoor - no high or critical agent detections in 24 h",
		"No spoor detection of severity high or critical was recorded on this host in the last "+
			human(DetectionLookback)+".",
		"Review the detection in your SIEM (join on event_id) and the agent session it belongs to "+
			"(session_ref); spoor_detections lists the rule and the user.",
		"SELECT 1 FROM "+tbl("detections")+"\nWHERE severity IN ('high', 'critical')\n  AND ts >= "+
			since(DetectionLookback))
}

// bypassViolation finds an agent running, or configured to run, without
// per-call approval: a root process started with a bypass switch, an
// install whose settings make bypass the default, or a session that
// reported bypass mode.
func (g *gen) bypassViolation() string {
	return unionAll(
		"SELECT 1 FROM "+tbl("agent_processes")+"\nWHERE last_seen >= "+since(DetectionLookback)+
			"\n  AND "+listHasAny("flags", g.v.bypassArgs, false),
		"SELECT 1 FROM "+tbl("agents")+"\nWHERE change != 'removed'\n  AND "+
			listHasAny("risk_flags", g.v.bypassSettings, false),
		"SELECT 1 FROM "+tbl("sessions")+"\nWHERE permission_mode = 'bypass'\n  AND last_event >= "+
			since(DetectionLookback),
	)
}

const bypassResolution = "Remove the switch from the launcher or alias that starts the agent and the " +
	"bypass default from its settings; enforce the managed setting that disables bypass mode where " +
	"the agent has one."

func (g *gen) bypassPolicy(withAITools bool) Policy {
	v := g.bypassViolation()
	desc := "No AI agent ran with tool approvals switched off in the last " + human(DetectionLookback) +
		" (command-line switches such as " + strings.Join(g.v.exampleBypassArgs(), ", ") +
		"), none is configured to do so by default, and no session reported bypass mode."
	if withAITools {
		v = unionAll(v, "SELECT 1 FROM ai_tools\nWHERE type = 'agents'\n  AND "+
			listHasAny("risk_flags", aiToolsBypassFlags, true))
		desc += " Also fails on the bypass flags of Fleet's ai_tools table."
	}
	return g.guarded("no_bypass", "spoor - no AI agent in permission-bypass mode", desc, bypassResolution, v)
}

func (g *gen) mcpPolicy(withAITools bool) Policy {
	v := "SELECT 1 FROM " + tbl("mcp_servers") + "\nWHERE " + listHasAny("risk_flags", riskyMCPFlags, false)
	desc := "No MCP server declared in an agent configuration on this host launches an unpinned package " +
		"or image, or carries a credential in its arguments, environment, headers or URL."
	if withAITools {
		v = unionAll(v, "SELECT 1 FROM ai_tools\nWHERE type = 'mcp_server'\n  AND "+
			listHasAny("risk_flags", aiToolsMCPFlags, true))
		desc += " Also fails on the matching flags of Fleet's ai_tools table."
	}
	return g.guarded("no_risky_mcp", "spoor - no unpinned or inline-secret MCP server", desc,
		"Pin the package to an exact version (or the image to a digest) and move secrets to the "+
			"environment or a credential helper; spoor_mcp_servers lists the declaring file.", v)
}

func (g *gen) autorunPolicy() Policy {
	return g.guarded("no_autorun_plant",
		"spoor - no auto-run file planted in a project",
		"No project an agent worked in contains a control file that makes an agent or editor run "+
			"something as soon as the folder is opened (project hooks, always-on rules, folder-open "+
			"tasks, .git/config exec keys, workspace executable paths).",
		"Inspect the file named in spoor_extensions.source_path; if nobody on the team added it, treat "+
			"the repository as compromised.",
		"SELECT 1 FROM "+tbl("extensions")+"\nWHERE kind = "+sqlString(string(event.AssetProjectConfig))+
			"\n  AND "+listHasAny("risk_flags", autorunFlags, false))
}

func (g *gen) bundlePolicy() Policy {
	min := strconv.FormatUint(g.r.minBundleVersion, 10)
	return g.guarded("bundle_current",
		"spoor - rules bundle is current",
		"The sensor has a signed content bundle of version "+min+" or later installed. Raise the "+
			"minimum (`spoor export fleet --min-bundle-version`) each time you publish a bundle; "+
			"remove this policy if you ship rules only with the binary.",
		"Check the bundle URL and key in the sensor configuration and `spoor bundle pull` on the host.",
		"SELECT 1 FROM "+tbl("health")+"\nWHERE bundle_version = ''\n  OR CAST(bundle_version AS INTEGER) < "+min)
}

// fromState wraps one of state.Policies with the long guard; those checks
// depend only on the state package's own columns.
func (g *gen) fromState(name, policyName string) Policy {
	p, ok := state.PolicyByName(name)
	if !ok {
		panic("fleetgen: state has no policy " + name)
	}
	return g.guarded(name, policyName, p.Description, p.Resolution, p.Violation)
}

// spoorPolicies is the policy set of the stock and fleetd profiles.
func (g *gen) spoorPolicies(withAITools bool) []Policy {
	ps := []Policy{
		g.sensorPolicy(),
		g.hooksPolicy(),
		g.detectionsPolicy(),
		g.bypassPolicy(withAITools),
		g.mcpPolicy(withAITools),
		g.autorunPolicy(),
		g.bundlePolicy(),
		g.fromState("scan_complete", "spoor - inventory scan complete and recent"),
		g.fromState("no_blind_agents", "spoor - no AI agent running unobserved"),
		g.fromState("no_critical_posture", "spoor - no high or critical agent configuration failure"),
	}
	for i := range ps {
		ps[i].Platform = fleetPlatforms
		ps[i].Query = policySQL(ps[i].Violation, ps[i].Window)
	}
	return ps
}

// ---- reports ----

func detectionsReport() Report {
	return Report{
		Key:  "detections",
		Name: "spoor - detections",
		Description: "spoor detections of the last 7 days, sent to the log destination as they appear " +
			"(differential, removals ignored: rows that age out or are evicted are not news). Evidence " +
			"values are never in the state database; join to the detection stream on event_id.",
		Query:    selectCols("detections", "WHERE ts >= "+since(detectionReportWindow)) + ";",
		Interval: intervalDetections, Logging: loggingDifferentialNoRem, AutomationsEnabled: true,
	}
}

func coverageReport() Report {
	return Report{
		Key:  "coverage",
		Name: "spoor - telemetry coverage",
		Description: "Which telemetry surfaces deliver for each agent and user (covered, partial, blind, " +
			"absent). Not collected must never read as clean.",
		Query:    selectCols("coverage", "") + ";",
		Interval: intervalCoverage, Logging: loggingSnapshot, AutomationsEnabled: true,
	}
}

func healthReport() Report {
	return Report{
		Key:         "health",
		Name:        "spoor - sensor health",
		Description: "The sensor's single health row: version, privacy profile, heartbeat, last scan, rule and bundle versions and counters.",
		Query:       selectCols("health", "") + ";",
		Interval:    intervalHealth, Logging: loggingSnapshot, AutomationsEnabled: true,
	}
}

// clipped is a JSON field clipped to n characters.
func clipped(col string, n int) string {
	return "substr(" + col + ", 1, " + strconv.Itoa(n) + ")"
}

// jsonObject renders json_object('a', expr, ...) from name/expression pairs.
func jsonObject(pairs ...string) string {
	parts := make([]string, 0, len(pairs))
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sqlString(pairs[i])+", "+pairs[i+1])
	}
	return "json_object(" + strings.Join(parts, ", ") + ")"
}

// packedList is a json_group_array over at most packedRows rows of a CTE.
func packedList(cte, obj, where, order string) string {
	q := "SELECT " + cte + ".* FROM " + cte
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY " + order + " LIMIT " + strconv.Itoa(packedRows)
	return "(SELECT json_group_array(" + obj + ") FROM (" + q + "))"
}

func stockInventoryReport() Report {
	f := func(c string) string { return clipped(c, packedField) }
	agents := jsonObject("name", f("name"), "kind", f("kind"), "catalog_id", f("catalog_id"),
		"version", f("version"), "owner", f("owner"), "scope", f("scope"), "hooks", f("hooks"),
		"running", "CAST(running AS INTEGER)", "risk_flags", clipped("risk_flags", packedFlags))
	mcp := jsonObject("name", f("name"), "parent", f("parent"), "owner", f("owner"), "scope", f("scope"),
		"transport", f("transport"), "runner", f("runner"), "package", f("package"), "version", f("version"),
		"pinned", "CAST(pinned AS INTEGER)", "url_host", f("url_host"), "risk_flags", clipped("risk_flags", packedFlags))
	ext := jsonObject("kind", f("kind"), "name", f("name"), "parent", f("parent"), "owner", f("owner"),
		"scope", f("scope"), "risk_flags", clipped("risk_flags", packedFlags))
	q := "WITH a AS MATERIALIZED (SELECT name, kind, catalog_id, version, owner, scope, hooks, running, risk_flags\n" +
		"    FROM " + tbl("agents") + " WHERE change != 'removed'),\n" +
		"  m AS MATERIALIZED (SELECT name, parent, owner, scope, transport, runner, package, version, pinned, url_host, risk_flags\n" +
		"    FROM " + tbl("mcp_servers") + "),\n" +
		"  x AS MATERIALIZED (SELECT kind, name, parent, owner, scope, risk_flags FROM " + tbl("extensions") + ")\n" +
		"SELECT\n" +
		"  (SELECT count(*) FROM a) AS agents_total,\n" +
		"  " + packedList("a", agents, "", "catalog_id, owner, name") + " AS agents,\n" +
		"  (SELECT count(*) FROM m) AS mcp_servers_total,\n" +
		"  " + packedList("m", mcp, "", "risk_flags = '', parent, name") + " AS mcp_servers,\n" +
		"  (SELECT count(*) FROM x) AS extensions_total,\n" +
		"  " + packedList("x", ext, "risk_flags != ''", "kind, name") + " AS flagged_extensions;"
	return Report{
		Key:  "inventory",
		Name: "spoor - AI inventory (packed)",
		Description: "One row per host: AI agents and apps, declared MCP servers (risky first) and " +
			"extensions with risk flags, each list capped at " + strconv.Itoa(packedRows) + " entries with " +
			"the true totals alongside, so the host result stays far below Fleet's 512 KiB limit.",
		Query:    q,
		Interval: intervalInventory, Logging: loggingSnapshot, AutomationsEnabled: true,
	}
}

func aiToolsPacked(withSpoor bool) Report {
	f := func(c string) string { return clipped(c, packedField) }
	tools := jsonObject("type", f("type"), "name", f("name"), "identifier", f("identifier"),
		"version", f("version"), "source", f("source"), "running", "running",
		"risk_flags", clipped("risk_flags", packedFlags))
	q := "WITH t AS MATERIALIZED (SELECT type, name, identifier, version, source, running, risk_flags\n" +
		"    FROM ai_tools WHERE type != 'sockets')"
	sel := "SELECT\n" +
		"  (SELECT count(*) FROM t) AS ai_tools_total,\n" +
		"  " + packedList("t", tools, "", "risk_flags = '', type, name") + " AS ai_tools"
	r := Report{
		Key:  "inventory",
		Name: "AI tools (packed)",
		Description: "One row per host from Fleet's ai_tools table (fleetd 1.59.0 or later), risky entries " +
			"first, capped at " + strconv.Itoa(packedRows) + " entries with the true total alongside.",
		Interval: intervalInventory, Logging: loggingSnapshot, AutomationsEnabled: true,
	}
	if withSpoor {
		ext := jsonObject("kind", f("kind"), "name", f("name"), "parent", f("parent"), "owner", f("owner"),
			"scope", f("scope"), "risk_flags", clipped("risk_flags", packedFlags))
		q += ",\n  x AS MATERIALIZED (SELECT kind, name, parent, owner, scope, risk_flags FROM " + tbl("extensions") + ")"
		sel += ",\n  (SELECT count(*) FROM x) AS extensions_total,\n" +
			"  " + packedList("x", ext, "risk_flags != ''", "kind, name") + " AS flagged_extensions"
		r.Name = "spoor - AI inventory (packed, with ai_tools)"
		r.Description = "One row per host: Fleet's ai_tools inventory (risky entries first) plus the " +
			"extensions and project control files spoor flagged, each list capped at " +
			strconv.Itoa(packedRows) + " entries with the true totals alongside."
	}
	r.Query = q + "\n" + sel + ";"
	return r
}

// ---- profiles ----

func (g *gen) stock() Profile {
	return Profile{
		Name:  ProfileStock,
		Title: "spoor on plain osquery",
		Summary: "For any osquery 5 host (fleetd or not) with the spoor sensor, reading spoor's tables " +
			"through ATC or the spoor extension.",
		Labels:   []Label{g.labelInstalled(), labelAgentsSpoor(), g.labelUnhealthy(), g.labelTablesUnavailable()},
		Policies: g.spoorPolicies(false),
		Reports:  withReportPlatform([]Report{detectionsReport(), stockInventoryReport(), coverageReport(), healthReport()}),
	}
}

func (g *gen) fleetd() Profile {
	return Profile{
		Name:  ProfileFleetd,
		Title: "spoor on fleetd",
		Summary: "For hosts running Fleet's agent (fleetd 1.59.0 or later): inventory questions also " +
			"consult Fleet's ai_tools table; spoor adds detections, hook coverage, sensor health, project " +
			"auto-run files and agent processes.",
		Labels:   []Label{g.labelInstalled(), labelAgentsAITools(), g.labelUnhealthy(), g.labelTablesUnavailable()},
		Policies: g.spoorPolicies(true),
		Reports:  withReportPlatform([]Report{detectionsReport(), aiToolsPacked(true), coverageReport(), healthReport()}),
	}
}

// builtin is tier 1: no spoor binary, Fleet's own table only. ai_tools is
// computed when queried, so an empty result is a real "none" and these
// policies need no heartbeat guard.
func (g *gen) builtin() Profile {
	bypass := Policy{
		Key:  "no_bypass",
		Name: "AI agents - no permission bypass (ai_tools)",
		Description: "Fleet's ai_tools table reports no agent configured or running with permission " +
			"prompts skipped. Live view only: an agent that ran in bypass mode and exited is not seen.",
		Resolution: bypassResolution,
		Query: "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM ai_tools\n  WHERE type = 'agents'\n  AND " +
			listHasAny("risk_flags", aiToolsBypassFlags, true) + ");",
	}
	mcp := Policy{
		Key:  "no_risky_mcp",
		Name: "AI agents - no unpinned or plaintext-secret MCP server (ai_tools)",
		Description: "Fleet's ai_tools table reports no MCP server with an unpinned dependency or a " +
			"plaintext secret.",
		Resolution: "Pin the package to an exact version and move secrets out of the configuration file.",
		Query: "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM ai_tools\n  WHERE type = 'mcp_server'\n  AND " +
			listHasAny("risk_flags", aiToolsMCPFlags, true) + ");",
	}
	ps := []Policy{bypass, mcp}
	for i := range ps {
		ps[i].Platform = fleetPlatforms
	}
	return Profile{
		Name:  ProfileBuiltin,
		Title: "No spoor binary: Fleet's built-in ai_tools table",
		Summary: "Tier 1 for fleetd hosts: inventory and configuration posture from Fleet's own table. " +
			"No detections, no hook coverage, no history between queries.",
		Labels:   []Label{labelAgentsAITools()},
		Policies: ps,
		Reports:  withReportPlatform([]Report{aiToolsPacked(false)}),
	}
}

func withReportPlatform(rs []Report) []Report {
	for i := range rs {
		if rs[i].Platform == "" {
			rs[i].Platform = fleetPlatforms
		}
	}
	return rs
}

// human renders a window the way the descriptions use it.
func human(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0 && d >= 48*time.Hour:
		return strconv.Itoa(int(d/(24*time.Hour))) + " days"
	case d%time.Hour == 0:
		if d == time.Hour {
			return "1 hour"
		}
		return strconv.Itoa(int(d/time.Hour)) + " hours"
	case d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + " minutes"
	default:
		return strconv.Itoa(int(d/time.Second)) + " seconds"
	}
}

// exampleBypassArgs names the best-known bypass switches present in the
// catalog, for descriptions.
func (v vocabulary) exampleBypassArgs() []string {
	var out []string
	for _, a := range []string{"--dangerously-skip-permissions", "--yolo", "--dangerously-bypass-approvals-and-sandbox"} {
		for _, b := range v.bypassArgs {
			if a == b {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 && len(v.bypassArgs) > 0 {
		out = v.bypassArgs[:1]
	}
	return out
}
