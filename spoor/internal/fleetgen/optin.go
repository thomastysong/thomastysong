package fleetgen

import "strings"

// OptInWarning heads the opt-in report file and its documentation.
const OptInWarning = `PRIVACY WARNING - OPT-IN EXAMPLE ONLY.
These reports schedule osquery's evented process tables through Fleet. Every
row carries the full command line, working directory and user of a process
an AI agent started, and Fleet sends those rows to the Fleet server and to
its log destination, outside spoor's privacy profiles (minimal, standard,
full), its secret redaction and its exclusions. Command lines routinely
contain tokens and passwords. This is why spoor's daemon reads the same
tables locally over the osquery extension socket and applies its privacy
policy before anything leaves the host. Deploy these only with a documented
purpose, a retention limit at the log destination and, where it applies,
your works council's or DPO's agreement.`

// execSource describes one OS's evented process table.
type execSource struct {
	platform string // Fleet platform value
	title    string
	table    string
	// cols are the event columns selected, renamed to a common shape:
	// time, pid, parent, path, cmdline, cwd, uid.
	cols string
	// filter keeps exec records only ("" when the table has nothing else).
	filter string
	flags  string // osquery flags the table needs
}

// Columns from osquery's schema for 5.19 (fleetdm/fleet
// schema/osquery_fleet_schema.json; see research/fleet.md section 2).
var execSources = []execSource{
	{
		platform: PlatformLinux,
		title:    "Linux, audit",
		table:    "process_events",
		cols:     "time, pid, parent, path, cmdline, cwd, uid",
		flags: "disable_events: false, disable_audit: false, audit_allow_process_events: true, " +
			"audit_persist: true (command_line_flags; orbit restarts osquery when they change)",
	},
	{
		platform: PlatformDarwin,
		title:    "macOS, EndpointSecurity",
		table:    "es_process_events",
		cols:     "time, pid, parent, path, cmdline, cwd, uid",
		filter:   "event_type = 'exec'",
		flags: "disable_events: false, disable_endpointsecurity: false; osquery needs Full Disk Access " +
			"(PPPC profile)",
	},
	{
		// UNVERIFIED: no Windows host was available; columns are from the
		// schema, the 'ProcessStart' type value from osquery's table docs.
		platform: PlatformWindows,
		title:    "Windows, ETW",
		table:    "process_etw_events",
		cols:     "time, pid, ppid AS parent, path, cmdline, '' AS cwd, username AS uid",
		filter:   "type = 'ProcessStart'",
		flags:    "disable_events: false, enable_process_etw_events: true",
	},
}

// optIn builds the exec-events reports: children and grandchildren of
// agent root processes recorded in spoor_agent_processes. The agent table
// is read once (MATERIALIZED): ATC re-reads its file for every row of a
// join's outer loop, measured at 2.6 s against 0.2 s for a 10,000-row table.
//
// A scheduled query over an evented table only sees the events since its
// previous run, so the exec event of a grandchild's parent (an agent's
// long-lived shell, say) is usually in an earlier batch. Depth 2 therefore
// also looks the parent up in the live processes table, accepting it only
// when it started no later than the grandchild (a reused pid started after
// it). What remains invisible is a grandchild whose parent both started
// before the previous run and exited before this one.
func (g *gen) optIn() []Report {
	agents := "SELECT CAST(pid AS INTEGER) AS pid, agent_id, user, session_ref\n" +
		"    FROM " + tbl("agent_processes") + "\n" +
		"    WHERE CAST(running AS INTEGER) = 1 OR last_seen >= " + since(execAgentWindow)
	out := make([]Report, 0, len(execSources))
	for _, s := range execSources {
		ev := "SELECT " + s.cols + " FROM " + s.table
		if s.filter != "" {
			ev += " WHERE " + s.filter
		}
		cols := "e.time, e.pid, e.parent, e.path, e.cmdline, e.cwd, e.uid, a.agent_id, a.user AS agent_user, a.session_ref"
		q := "WITH agents AS MATERIALIZED (\n    " + agents + "),\n" +
			"  ev AS MATERIALIZED (" + ev + "),\n" +
			"  live AS MATERIALIZED (SELECT pid, parent, start_time FROM processes WHERE pid IN (SELECT parent FROM ev))\n" +
			"SELECT " + cols + ", 1 AS depth\n" +
			"FROM ev e JOIN agents a ON e.parent = a.pid\n" +
			"UNION\n" +
			"SELECT " + cols + ", 2 AS depth\n" +
			"FROM ev e JOIN ev c ON e.parent = c.pid JOIN agents a ON c.parent = a.pid\n" +
			"UNION\n" +
			"SELECT " + cols + ", 2 AS depth\n" +
			"FROM ev e JOIN live c ON e.parent = c.pid AND c.start_time <= e.time JOIN agents a ON c.parent = a.pid;"
		out = append(out, Report{
			Key:  "exec_" + s.platform,
			Name: "spoor opt-in - agent child processes (" + s.title + ")",
			Description: "OPT-IN, sends raw command lines to Fleet: processes started by an AI agent's " +
				"root process (depth 1) or by its direct children (depth 2), from " + s.table +
				" joined to spoor_agent_processes. Needs " + s.flags + ". osquery returns only the events " +
				"since the previous run, so a depth-2 parent from an earlier run is looked up in the " +
				"processes table; a grandchild whose parent started before the previous run and has " +
				"exited is not attributed (join earlier depth-1 rows on pid downstream). A pid reused within " +
				human(execAgentWindow) + " of the agent exiting can be misattributed.",
			Query:    q,
			Platform: s.platform,
			Interval: intervalExec, Logging: loggingDifferentialNoRem, AutomationsEnabled: true,
			DiscardData: true,
		})
	}
	return out
}

// optInHeader is OptInWarning as YAML comment lines.
func optInHeader() string {
	var b strings.Builder
	for _, l := range strings.Split(OptInWarning, "\n") {
		b.WriteString("# " + l + "\n")
	}
	return b.String()
}
