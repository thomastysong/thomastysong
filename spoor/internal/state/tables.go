package state

import (
	"fmt"
	"strings"
)

// TablePrefix is prepended to a TableDef name to form the osquery table name.
const TablePrefix = "spoor_"

// Column types. BIGINT and INTEGER are both stored with INTEGER affinity;
// the distinction only tells the osquery extension which type to declare.
const (
	TypeText    = "TEXT"
	TypeInteger = "INTEGER"
	TypeBigInt  = "BIGINT"
)

// ColumnDef is one column osquery sees.
type ColumnDef struct {
	Name        string
	Type        string // TypeText, TypeInteger or TypeBigInt
	Description string
	// Key marks identifier columns. The extension declares them as indexed so
	// osquery prefers passing equality constraints on them.
	Key bool
}

// Numeric reports whether the column holds a number. Under ATC such a column
// is still TEXT and must be compared through CAST(col AS INTEGER).
func (c ColumnDef) Numeric() bool { return c.Type == TypeInteger || c.Type == TypeBigInt }

// TableDef describes one table: the single source of truth for the SQLite
// schema, the ATC configuration and the osquery extension.
type TableDef struct {
	Name        string // without TablePrefix
	Description string
	Columns     []ColumnDef

	// key is the primary key. internal columns exist in the file but are
	// never shown. visible is the row filter every reader applies. evict is
	// the ORDER BY that puts the rows to drop first once rowCap is exceeded.
	key      []string
	internal []ColumnDef
	visible  string
	evict    string
	rowCap   int
	extra    string
	indexes  []string
}

// OsqueryName is the table name inside osquery.
func (t TableDef) OsqueryName() string { return TablePrefix + t.Name }

// ColumnNames lists the visible columns in declaration order.
func (t TableDef) ColumnNames() []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name
	}
	return out
}

// Column looks a visible column up by name.
func (t TableDef) Column(name string) (ColumnDef, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return ColumnDef{}, false
}

// RowCap is the most rows the table may hold; the oldest are evicted beyond it.
func (t TableDef) RowCap() int { return t.rowCap }

// Table finds a definition by name, with or without TablePrefix.
func Table(name string) (TableDef, bool) {
	name = strings.TrimPrefix(name, TablePrefix)
	for _, t := range Tables {
		if t.Name == name {
			return t, true
		}
	}
	return TableDef{}, false
}

// RowCaps returns the row cap of every table by name. The caps exist because
// ATC reads a whole table for every query (see the package comment).
func RowCaps() map[string]int {
	out := make(map[string]int, len(Tables))
	for _, t := range Tables {
		out[t.Name] = t.rowCap
	}
	return out
}

func text(name, desc string) ColumnDef {
	return ColumnDef{Name: name, Type: TypeText, Description: desc}
}
func key(name, desc string) ColumnDef {
	return ColumnDef{Name: name, Type: TypeText, Description: desc, Key: true}
}
func integer(name, desc string) ColumnDef {
	return ColumnDef{Name: name, Type: TypeInteger, Description: desc + " (number; under ATC compare with CAST(" + name + " AS INTEGER))"}
}
func bigint(name, desc string) ColumnDef {
	return ColumnDef{Name: name, Type: TypeBigInt, Description: desc + " (number; under ATC compare with CAST(" + name + " AS INTEGER))"}
}

const tsNote = " (fixed-width RFC 3339 UTC; empty when unset)"

// Internal columns shared by the three asset tables. fp is a digest of the
// descriptive columns, used to tell "changed" from "seen again"; removed_at
// and removed_scan record a removal without deleting the row, so a
// reappearing asset keeps its first_seen and Removed can report the loss.
var assetInternal = []ColumnDef{
	text("owner_id", ""),
	text("fp", ""),
	text("removed_at", ""),
	{Name: "removed_scan", Type: TypeInteger},
}

// Tables defines every table. Order is the order of documentation and of the
// generated ATC configuration.
var Tables = []TableDef{
	{
		Name:        "agents",
		Description: "AI agents, AI apps and IDEs, AI extensions and local model runtimes found on this host, one row per install and owner. Removed installs stay for the removed-asset retention with change = 'removed'.",
		Columns: []ColumnDef{
			key("asset_id", "Stable id of the asset; equals asset.id in inventory events"),
			text("name", "Product name"),
			text("vendor", "Vendor"),
			text("kind", "agent | app | ide_extension | ai_browser | browser_extension | model_runtime"),
			text("catalog_id", "Catalog entry that identified it; empty when unknown"),
			text("version", "Version read from package metadata; never obtained by running the binary"),
			text("install_path", "Install location"),
			text("owner", "OS account the install belongs to"),
			text("scope", "managed | system | user | project | plugin"),
			integer("running", "1 when a matching process was running at scan time"),
			integer("pid", "Process id when running, else 0"),
			text("sha256", "Content hash of the binary when computed"),
			text("signer", "Verified code-signing identity"),
			text("confidence", "high | medium | low"),
			text("evidence", "Comma-separated classes of evidence that established identity"),
			text("risk_flags", "Comma-separated posture flags from settings probes"),
			text("hooks", "Hook coverage: managed | user | missing | modified | shadowed | unsupported | disabled"),
			text("transcript", "Transcript coverage: tailing | found | none | relocated | disabled"),
			text("native_otel", "Agent-native OpenTelemetry: enabled | disabled | unsupported"),
			text("first_seen", "First scan that saw it"+tsNote),
			text("last_seen", "Last scan that saw it"+tsNote),
			text("change", "new | changed | unchanged | removed, relative to the previous state of this table"),
		},
		key:      []string{"asset_id"},
		internal: assetInternal,
		evict:    "(removed_at = '') ASC, last_seen ASC",
		rowCap:   2000,
	},
	{
		Name:        "mcp_servers",
		Description: "MCP servers declared in agent configuration files, one row per declaration. Launch arguments and secret values are never stored.",
		Columns: []ColumnDef{
			key("asset_id", "Stable id of the declaration"),
			text("name", "Server name as declared"),
			text("parent", "Catalog id of the agent whose config declares it"),
			text("scope", "managed | system | user | project | plugin"),
			text("owner", "OS account the config belongs to"),
			text("source_path", "Config file that declares it"),
			text("transport", "stdio | http | sse | ws"),
			text("command", "Base name of the launch executable"),
			text("runner", "Package launcher: npx | bunx | uvx | pipx | pip | docker | podman | node | python | deno | binary"),
			text("ecosystem", "npm | pypi | oci"),
			text("package", "Package or image name"),
			text("version", "Declared version or tag"),
			integer("pinned", "1 only for an exact version or image digest"),
			text("url_host", "Host of a remote server"),
			text("env_keys", "Comma-separated environment variable names (never values)"),
			text("auth_mode", "none | env | header | oauth | inherited"),
			text("risk_flags", "Comma-separated risk flags"),
			text("sha256", "Hash of the normalized definition"),
			text("first_seen", "First scan that saw it"+tsNote),
			text("last_seen", "Last scan that saw it"+tsNote),
			text("last_changed", "When the definition last appeared or changed"+tsNote),
		},
		key:      []string{"asset_id"},
		internal: assetInternal,
		visible:  "removed_at = ''",
		evict:    "(removed_at = '') ASC, last_seen ASC",
		rowCap:   5000,
	},
	{
		Name:        "extensions",
		Description: "Things that extend or steer an agent: skills, plugins, hooks, rules files, subagents, commands, project control files and CI agent workflows.",
		Columns: []ColumnDef{
			key("asset_id", "Stable id of the item"),
			text("kind", "skill | plugin | hook | rules_file | subagent | command | project_config | ci_agent"),
			text("name", "Item name"),
			text("parent", "Catalog id of the agent it belongs to"),
			text("scope", "managed | system | user | project | plugin"),
			text("owner", "OS account it belongs to"),
			text("source_path", "File or folder that defines it"),
			text("sha256", "Content hash (folder hash for skills, definition hash for hooks)"),
			text("risk_flags", "Comma-separated risk flags"),
			text("first_seen", "First scan that saw it"+tsNote),
			text("last_seen", "Last scan that saw it"+tsNote),
			text("last_changed", "When the content last appeared or changed"+tsNote),
		},
		key:      []string{"asset_id"},
		internal: assetInternal,
		visible:  "removed_at = ''",
		evict:    "(removed_at = '') ASC, last_seen ASC",
		rowCap:   10000,
	},
	{
		Name:        "posture",
		Description: "Configuration checks that currently fail. A check that passes has no row, so always combine with a fresh spoor_health heartbeat.",
		Columns: []ColumnDef{
			key("check_id", "Rule id of the posture check"),
			text("title", "Check title"),
			text("severity", "info | low | medium | high | critical"),
			text("agent_id", "Catalog id of the agent checked"),
			text("asset_id", "Asset the check applies to"),
			text("scope", "managed | system | user | project | plugin"),
			text("subject", "File or setting key that was checked"),
			text("owner", "OS account the subject belongs to"),
			text("actual", "Observed value, cleaned and clipped"),
			text("remedy", "How to fix it"),
			text("first_seen", "When the failure was first observed"+tsNote),
			text("last_seen", "When the failure was last observed"+tsNote),
		},
		key: []string{"check_id", "agent_id", "asset_id", "scope", "subject", "owner"},
		internal: []ColumnDef{
			text("owner_id", ""),
			{Name: "seen_scan", Type: TypeInteger},
		},
		evict:  "last_seen ASC",
		rowCap: 5000,
	},
	{
		Name:        "detections",
		Description: "Recent rule matches, one row per finding. Repeats that share a dedup key, rule and user collapse into one row whose count grows. Evidence values are never stored: join to the detection stream on event_id.",
		Columns: []ColumnDef{
			key("event_id", "Id of the most recent detection event this row stands for"),
			text("ts", "Time of the most recent match"+tsNote),
			key("rule_id", "Rule id"),
			text("title", "Rule title"),
			text("severity", "info | low | medium | high | critical"),
			text("confidence", "low | medium | high"),
			text("maturity", "experimental | stable"),
			text("category", "Rule category"),
			text("tags", "Comma-separated framework tags"),
			text("agent_id", "Catalog id of the agent"),
			text("user", "OS account"),
			key("session_ref", "Session reference; joins spoor_sessions and spoor_agent_processes"),
			text("integrity", "root | user: who could have altered the underlying records"),
			text("response", "none | ask | block: what the rule asked for"),
			integer("enforced", "1 when that response was returned to the agent"),
			integer("count", "Matches this row stands for"),
			text("dedup_key", "Key that groups repeats"),
		},
		key:      []string{"event_id"},
		internal: []ColumnDef{text("user_id", "")},
		evict:    "ts ASC",
		rowCap:   5000,
		indexes: []string{
			"CREATE INDEX IF NOT EXISTS detections_dedup ON detections (dedup_key, rule_id, user)",
		},
	},
	{
		Name:        "sessions",
		Description: "Recent agent sessions as counts and classes; no content.",
		Columns: []ColumnDef{
			key("session_ref", "sha256(user id, agent id, session id) truncated to 16 hex digits"),
			text("agent_id", "Catalog id of the agent"),
			text("user", "OS account"),
			text("started", "Session start"+tsNote),
			text("last_event", "Most recent activity"+tsNote),
			text("permission_mode", "default | plan | accept_edits | auto | dont_ask | bypass"),
			integer("tool_calls", "Tool calls observed"),
			integer("detections", "Rule matches in the session"),
			text("max_severity", "Highest severity matched"),
			text("sources", "Comma-separated surfaces that reported the session"),
			text("coverage", "covered | partial | blind"),
		},
		key:      []string{"session_ref"},
		internal: []ColumnDef{text("user_id", "")},
		evict:    "last_event ASC",
		rowCap:   2000,
	},
	{
		Name:        "agent_processes",
		Description: "Agent root processes seen by the process monitor. Exited processes stay with running = 0 for the process retention so interval queries can still attribute their children.",
		Columns: []ColumnDef{
			{Name: "pid", Type: TypeInteger, Key: true, Description: "Process id (number; under ATC compare with CAST(pid AS INTEGER))"},
			text("start_time", "Process start; with pid it identifies the process"+tsNote),
			text("agent_id", "Catalog id of the agent"),
			text("user", "OS account"),
			text("exe", "Executable path"),
			text("flags", "Comma-separated risky command-line flags recognized by the catalog; no other arguments"),
			key("session_ref", "Session reference when known"),
			text("container_id", "Container id when the process runs in one"),
			text("first_seen", "First observation"+tsNote),
			text("last_seen", "Most recent observation"+tsNote),
			integer("running", "1 while the process is in the monitor's current set"),
		},
		key:      []string{"pid", "start_time"},
		internal: []ColumnDef{text("user_id", "")},
		evict:    "running ASC, last_seen ASC, start_time ASC",
		rowCap:   500,
	},
	{
		Name:        "coverage",
		Description: "Which telemetry surfaces are delivering, per agent and user. Not collected must never read as clean.",
		Columns: []ColumnDef{
			key("agent_id", "Catalog id of the agent"),
			text("user", "OS account"),
			text("hooks", "managed | user | missing | modified | shadowed | unsupported | disabled"),
			text("transcript", "tailing | found | none | relocated | disabled"),
			integer("processes", "Running agent processes seen"),
			text("state", "covered | partial | blind | absent"),
			text("updated", "When this statement was written"+tsNote),
		},
		key:    []string{"agent_id", "user"},
		evict:  "updated ASC",
		rowCap: 2000,
	},
	{
		Name:        "health",
		Description: "Sensor health, a single row. heartbeat is the freshness guard every policy must check: with the sensor absent this table has no row at all.",
		Columns: []ColumnDef{
			text("sensor_version", "Sensor version"),
			text("mode", "daemon | scan"),
			text("profile", "Privacy profile: minimal | standard | full"),
			text("started", "When the writing process started"+tsNote),
			text("heartbeat", "Most recent heartbeat"+tsNote),
			text("last_scan", "End of the most recent complete scan"+tsNote),
			integer("scan_complete", "1 when the most recent scan attempt completed"),
			integer("rules_count", "Loaded rules"),
			text("rules_version", "Version of the loaded rule content"),
			text("rules_hash", "Hash of the loaded rule content"),
			text("catalog_version", "Catalog version"),
			text("bundle_version", "Installed content bundle version"),
			bigint("events_in", "Records received since start"),
			bigint("events_out", "Records written for shipping since start"),
			bigint("dropped", "Records dropped since start"),
			bigint("detections", "Detections emitted since start"),
			bigint("errors", "Sensor errors since start"),
			text("host_id", "Host id stamped on events"),
			text("host_id_source", "Where the host id came from"),
		},
		key: []string{"id"},
		internal: []ColumnDef{
			{Name: "id", Type: TypeInteger},
			text("writer", ""),
			text("last_event_id", ""),
			text("scan_started", ""),
		},
		evict:  "heartbeat ASC",
		rowCap: 1,
		extra:  "CHECK (id = 1)",
	},
}

// allColumns is visible columns followed by internal ones.
func (t TableDef) allColumns() []ColumnDef {
	out := make([]ColumnDef, 0, len(t.Columns)+len(t.internal))
	out = append(out, t.Columns...)
	return append(out, t.internal...)
}

// ddl renders CREATE TABLE. Every column is NOT NULL with a default: a NULL
// would compare differently here than the empty string osquery receives,
// and constraint pushdown must never return fewer rows than osquery's own
// filter would keep.
func (t TableDef) ddl() string {
	var b strings.Builder
	fmt.Fprintf(&b, "CREATE TABLE IF NOT EXISTS %s (", quoteIdent(t.Name))
	for i, c := range t.allColumns() {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(columnDDL(c))
	}
	fmt.Fprintf(&b, ", PRIMARY KEY (%s)", quoteIdents(t.key))
	if t.extra != "" {
		b.WriteString(", " + t.extra)
	}
	b.WriteString(")")
	return b.String()
}

func columnDDL(c ColumnDef) string {
	if c.Numeric() {
		return quoteIdent(c.Name) + " INTEGER NOT NULL DEFAULT 0"
	}
	return quoteIdent(c.Name) + " TEXT NOT NULL DEFAULT ''"
}

// quoteIdent double-quotes an identifier. Names come from Tables only, but
// quoting keeps a future column called "order" or "group" from breaking DDL.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func quoteIdents(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = quoteIdent(n)
	}
	return strings.Join(out, ", ")
}
