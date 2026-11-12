package state

import (
	"fmt"
	"strings"
	"time"
)

// ATCConfig returns the value of osquery's "auto_table_construction"
// configuration key for the state database at dbPath: one entry per table in
// Tables, named with TablePrefix. With Fleet it goes under
// agent_options.config.auto_table_construction.
//
// platform is passed through as the entry's "platform" (osquery matches it
// as a substring: linux, darwin, windows, posix); an empty platform omits
// the key. One table name maps to one path, and Fleet does not merge
// platform overrides with the base config, so a fleet with several operating
// systems needs one complete block per OS in overrides.platforms.
//
// Under ATC every column is TEXT: compare numbers through
// CAST(col AS INTEGER), and rely on the fixed-width timestamps for time
// comparisons. osquery adds a "path" column of its own holding dbPath.
func ATCConfig(dbPath, platform string) map[string]any {
	out := make(map[string]any, len(Tables))
	for _, t := range Tables {
		entry := map[string]any{
			"query":   ATCQuery(t),
			"path":    dbPath,
			"columns": t.ColumnNames(),
		}
		if platform != "" {
			entry["platform"] = platform
		}
		out[t.OsqueryName()] = entry
	}
	return out
}

// ATCQuery is the SELECT osquery runs inside the state database for one
// table: the visible columns, minus rows that are only bookkeeping.
func ATCQuery(t TableDef) string {
	q := "SELECT " + strings.Join(t.ColumnNames(), ", ") + " FROM " + t.Name
	if t.visible != "" {
		q += " WHERE " + t.visible
	}
	return q
}

// Heartbeat windows. Policies use two on purpose:
//
//   - DefaultAlertMaxAge (30 min) is for the one policy to alert on, "sensor
//     reporting": six missed beats at the default five-minute interval.
//   - DefaultHeartbeatMaxAge (24 h) is the guard every "no X" policy embeds,
//     so that a removed sensor or a deleted database fails within a day
//     (a missing database reads as zero rows, which would otherwise pass)
//     without turning every policy red each time a laptop wakes from sleep.
const (
	DefaultAlertMaxAge     = 30 * time.Minute
	DefaultHeartbeatMaxAge = 24 * time.Hour
)

// SQLTimeAgo returns a SQL expression for the timestamp d before now, in the
// same fixed-width form the tables store, so that it can be compared with a
// timestamp column as text in both ATC and extension tables:
//
//	ts >= strftime('%Y-%m-%dT%H:%M:%S.000000Z', 'now', '-86400 seconds')
func SQLTimeAgo(d time.Duration) string {
	secs := int64(d / time.Second)
	if secs < 0 {
		secs = 0
	}
	return fmt.Sprintf("strftime('%%Y-%%m-%%dT%%H:%%M:%%S.000000Z', 'now', '-%d seconds')", secs)
}

// HeartbeatGuard is the predicate every policy over spoor tables must
// include: true only when the sensor wrote a heartbeat within maxAge. Without
// it a host with no sensor, a stopped sensor or a deleted database satisfies
// every "no bad row" policy, because all of those read as empty tables.
func HeartbeatGuard(maxAge time.Duration) string {
	if maxAge <= 0 {
		maxAge = DefaultHeartbeatMaxAge
	}
	return "EXISTS (SELECT 1 FROM " + TablePrefix + "health WHERE heartbeat >= " + SQLTimeAgo(maxAge) + ")"
}

// PolicySQL builds a fail-closed Fleet policy query. check is a SELECT over
// spoor tables that returns at least one row when the host VIOLATES the
// policy; the result passes (returns a row) only when the sensor's heartbeat
// is fresh and check returns nothing. An empty check gives the plain
// "sensor is reporting" policy.
//
//	PolicySQL("SELECT 1 FROM spoor_detections WHERE severity = 'critical'")
//
// Remember that numeric columns need CAST(col AS INTEGER) under ATC.
func PolicySQL(check string) string { return PolicySQLWithin(check, DefaultHeartbeatMaxAge) }

// PolicySQLWithin is PolicySQL with an explicit heartbeat age limit.
func PolicySQLWithin(check string, maxAge time.Duration) string {
	check = strings.TrimSpace(check)
	check = strings.TrimSpace(strings.TrimRight(check, ";"))
	q := "SELECT 1 WHERE " + HeartbeatGuard(maxAge)
	if check != "" {
		q += " AND NOT EXISTS (" + check + ")"
	}
	return q + ";"
}

// Policy is a ready-made fail-closed policy over the state tables.
type Policy struct {
	Name        string // short stable key
	Title       string
	Description string
	Resolution  string
	// Violation is the row-returning check that PolicySQL wraps ("" for the
	// heartbeat policy itself).
	Violation string
	Query     string
}

// Policies are the policies whose meaning depends only on this package's
// own columns. Deployment content builds on them and adds policies that need
// catalog vocabulary (risk flag names, command-line switches).
var Policies = buildPolicies()

func buildPolicies() []Policy {
	p := TablePrefix
	day := SQLTimeAgo(24 * time.Hour)
	list := []Policy{
		{
			Name:        "sensor_reporting",
			Title:       "spoor sensor is reporting",
			Description: "The sensor wrote a heartbeat in the last 30 minutes.",
			Resolution:  "Check that the spoor service is installed and running and that its state database path matches the osquery configuration.",
		},
		{
			Name:        "scan_complete",
			Title:       "spoor inventory scan is complete and recent",
			Description: "The last discovery scan finished without hitting its deadline, within the last 26 hours.",
			Resolution:  "Look at the sensor's health stream for scan errors; a scan that keeps timing out usually means an unreachable or very large home directory.",
			Violation: "SELECT 1 FROM " + p + "health WHERE CAST(scan_complete AS INTEGER) != 1 OR last_scan < " +
				SQLTimeAgo(26*time.Hour),
		},
		{
			Name:        "hooks_effective",
			Title:       "AI agents have working spoor hooks",
			Description: "No installed agent that supports hooks has them missing, modified, disabled or shadowed by a higher-precedence policy source.",
			Resolution:  "Run `spoor hooks status` on the host and reinstall managed hooks; for 'shadowed', deliver the hooks through the policy source the agent actually reads.",
			Violation: "SELECT 1 FROM " + p + "agents WHERE change != 'removed' AND hooks IN " +
				"('missing', 'modified', 'disabled', 'shadowed')",
		},
		{
			Name:        "no_blind_agents",
			Title:       "No AI agent is running unobserved",
			Description: "No agent and user pair is in coverage state 'blind' (a running agent with no telemetry surface delivering).",
			Resolution:  "Check hook installation and transcript access for the listed agent and user.",
			Violation:   "SELECT 1 FROM " + p + "coverage WHERE state = 'blind'",
		},
		{
			Name:        "no_high_detections_24h",
			Title:       "No high or critical agent detections in the last 24 hours",
			Description: "No root- or user-integrity detection of severity high or critical was recorded in the last day.",
			Resolution:  "Review the detection in your SIEM (join on event_id) and the session it belongs to.",
			Violation:   "SELECT 1 FROM " + p + "detections WHERE severity IN ('high', 'critical') AND ts >= " + day,
		},
		{
			Name:        "no_critical_posture",
			Title:       "No high or critical agent configuration failures",
			Description: "No posture check of severity high or critical is currently failing.",
			Resolution:  "Apply the remedy column of the failing rows in spoor_posture.",
			Violation:   "SELECT 1 FROM " + p + "posture WHERE severity IN ('high', 'critical')",
		},
	}
	for i := range list {
		if list[i].Name == "sensor_reporting" {
			list[i].Query = PolicySQLWithin("", DefaultAlertMaxAge)
			continue
		}
		list[i].Query = PolicySQL(list[i].Violation)
	}
	return list
}

// PolicyByName returns one of Policies.
func PolicyByName(name string) (Policy, bool) {
	for _, p := range Policies {
		if p.Name == name {
			return p, true
		}
	}
	return Policy{}, false
}
