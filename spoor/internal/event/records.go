package event

// AssetKind classifies an inventory record.
type AssetKind string

const (
	AssetAgent            AssetKind = "agent"             // CLI or headless coding agent
	AssetApp              AssetKind = "app"               // desktop AI app or AI IDE
	AssetIDEExtension     AssetKind = "ide_extension"     // VS Code / JetBrains AI extension
	AssetBrowser          AssetKind = "ai_browser"        // agentic browser
	AssetBrowserExtension AssetKind = "browser_extension" // AI browser extension
	AssetModelRuntime     AssetKind = "model_runtime"     // Ollama, LM Studio, llama.cpp ...
	AssetMCPServer        AssetKind = "mcp_server"        // declared in a client config
	AssetSkill            AssetKind = "skill"
	AssetPlugin           AssetKind = "plugin"
	AssetHook             AssetKind = "hook"       // hook definition in an agent config
	AssetRulesFile        AssetKind = "rules_file" // CLAUDE.md, AGENTS.md, .cursor/rules ...
	AssetSubagent         AssetKind = "subagent"
	AssetCommand          AssetKind = "command" // slash command / prompt file
	AssetCIAgent          AssetKind = "ci_agent"
	// AssetProjectConfig is a repository-local file that can make an agent or
	// IDE run something when the folder is opened (settings with hooks, rules
	// that always apply, auto-run tasks, .git/config exec keys).
	AssetProjectConfig AssetKind = "project_config"
)

// Scope is where a configuration item is declared.
type Scope string

const (
	ScopeManaged Scope = "managed" // admin-controlled tier (MDM, system policy path)
	ScopeSystem  Scope = "system"  // machine-wide but not policy
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
	ScopePlugin  Scope = "plugin" // contributed by a plugin or extension
)

// Change describes how an asset differs from the previous scan.
type Change string

const (
	ChangeNew       Change = "new"
	ChangeChanged   Change = "changed"
	ChangeRemoved   Change = "removed"
	ChangeUnchanged Change = "unchanged"
)

// Asset is one inventory record. ID is stable across scans for the same
// (host, kind, identity, owner, location) so downstream can upsert.
type Asset struct {
	ID      string    `json:"id"`
	Kind    AssetKind `json:"kind"`
	Name    string    `json:"name"`
	Vendor  string    `json:"vendor,omitempty"`
	Version string    `json:"version,omitempty"`
	// CatalogID is the catalog entry that identified the asset ("" when unknown).
	CatalogID string `json:"catalog_id,omitempty"`
	// Parent is the catalog id of the agent that owns this item
	// (an MCP server declared in Cursor's config has Parent "cursor").
	Parent  string `json:"parent,omitempty"`
	Path    string `json:"path,omitempty"`  // install path or declaring file
	Scope   Scope  `json:"scope,omitempty"` // for declared items
	Owner   string `json:"owner,omitempty"` // OS user the item belongs to
	Running bool   `json:"running,omitempty"`
	PID     int    `json:"pid,omitempty"`
	// SHA256 is the content hash: binary hash for agents, definition hash for
	// MCP servers and hooks, folder hash for skills.
	SHA256 string `json:"sha256,omitempty"`
	// Evidence lists how identity was established, e.g. "package:npm",
	// "bundle_id", "path", "process", "signature". Two independent classes
	// are required for Confidence "high".
	Evidence   []string `json:"evidence,omitempty"`
	Confidence string   `json:"confidence,omitempty"` // high | medium | low
	// Signer is the code-signing identity when verified (team id / publisher).
	Signer    string `json:"signer,omitempty"`
	FirstSeen Time   `json:"first_seen,omitzero"`
	LastSeen  Time   `json:"last_seen,omitzero"`
	Change    Change `json:"change,omitempty"`
	// RiskFlags are closed-vocabulary posture hints computed at scan time.
	RiskFlags []string `json:"risk_flags,omitempty"`
	MCP       *MCP     `json:"mcp,omitempty"`
	// Telemetry describes how well spoor can see this agent (agents only).
	Telemetry *Telemetry        `json:"telemetry,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
}

func (a *Asset) clone() *Asset {
	c := *a
	c.Evidence = append([]string(nil), a.Evidence...)
	c.RiskFlags = append([]string(nil), a.RiskFlags...)
	if a.MCP != nil {
		m := *a.MCP
		m.Args = append([]string(nil), a.MCP.Args...)
		m.EnvKeys = append([]string(nil), a.MCP.EnvKeys...)
		m.HeaderKeys = append([]string(nil), a.MCP.HeaderKeys...)
		c.MCP = &m
	}
	if a.Telemetry != nil {
		t := *a.Telemetry
		c.Telemetry = &t
	}
	if a.Detail != nil {
		c.Detail = make(map[string]string, len(a.Detail))
		for k, v := range a.Detail {
			c.Detail[k] = v
		}
	}
	return &c
}

// MCP holds normalized launch facts for a declared MCP server, so a central
// team can hunt for a bad package or endpoint across the fleet.
type MCP struct {
	Transport string   `json:"transport,omitempty"` // stdio | http | sse | ws
	Command   string   `json:"command,omitempty"`   // executable as declared (basename unless tier is full)
	Args      []string `json:"args,omitempty"`      // secrets redacted
	// Runner is the package launcher when one is used: npx | bunx | uvx |
	// pipx | pip | docker | podman | node | python | deno | binary.
	Runner    string `json:"runner,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"` // npm | pypi | oci | ""
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	// Pinned is true only for an exact version or an image digest.
	Pinned          bool     `json:"pinned"`
	URLHost         string   `json:"url_host,omitempty"`
	URLPath         string   `json:"url_path,omitempty"`
	EnvKeys         []string `json:"env_keys,omitempty"` // names only, never values
	HeaderKeys      []string `json:"header_keys,omitempty"`
	HasInlineSecret bool     `json:"has_inline_secret,omitempty"`
	AuthMode        string   `json:"auth_mode,omitempty"` // none | env | header | oauth | inherited
	Enabled         *bool    `json:"enabled,omitempty"`
}

// Telemetry is per-agent coverage state: which surfaces spoor has.
type Telemetry struct {
	// Hooks: managed | user | missing | modified | unsupported | disabled.
	Hooks string `json:"hooks,omitempty"`
	// Transcript: tailing | found | none | relocated | disabled.
	Transcript string `json:"transcript,omitempty"`
	// NativeOTel: enabled | disabled | unsupported.
	NativeOTel string `json:"native_otel,omitempty"`
}

// Check is one posture check result.
type Check struct {
	ID       string `json:"id"` // rule id of the posture rule
	Title    string `json:"title,omitempty"`
	Status   string `json:"status"` // pass | fail | unknown
	Severity string `json:"severity,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
	AssetID  string `json:"asset_id,omitempty"`
	Scope    Scope  `json:"scope,omitempty"`
	Subject  string `json:"subject,omitempty"` // file path or setting key checked
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Remedy   string `json:"remedy,omitempty"`
}

// Detection classes, lowest to highest.
const (
	ClassSignal  = "signal"
	ClassFinding = "finding"
	ClassAlert   = "alert"
)

// ClassRank orders detection classes; unknown strings rank as finding.
func ClassRank(c string) int {
	switch c {
	case ClassSignal:
		return 1
	case ClassAlert:
		return 3
	default:
		return 2
	}
}

// Severity levels, lowest to highest.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// SeverityRank orders severities; unknown strings rank below info.
func SeverityRank(s string) int {
	switch s {
	case SevInfo:
		return 1
	case SevLow:
		return 2
	case SevMedium:
		return 3
	case SevHigh:
		return 4
	case SevCritical:
		return 5
	default:
		return 0
	}
}

// Detection is a rule match.
type Detection struct {
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`
	// Class is how much attention the match deserves: "signal" (counted into
	// the session summary, not shipped by default), "finding" (shipped, no
	// page) or "alert" (expected to be silent on ordinary developer work).
	Class      string `json:"class,omitempty"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"` // low | medium | high
	Maturity   string `json:"maturity,omitempty"`   // experimental | stable
	Category   string `json:"category,omitempty"`
	// Tags carries framework mappings in Sigma tag style:
	// attack.t1059.004, atlas.aml.t0051, owasp.asi05.
	Tags []string `json:"tags,omitempty"`
	// Evidence is a small redacted map of the field values that matched.
	Evidence map[string]string `json:"evidence,omitempty"`
	// EventIDs are the ids of the events that produced the match, oldest
	// first; for sequence rules this is the chain.
	EventIDs []string `json:"event_ids,omitempty"`
	// Flags are the session flags that were required and present.
	Flags []string `json:"flags,omitempty"`
	// Response is what the rule asks for (none | ask | block); Enforced says
	// whether spoor actually returned that decision to the agent.
	Response string `json:"response,omitempty"`
	Enforced bool   `json:"enforced,omitempty"`
	// DedupKey groups repeats of the same finding; Count is how many matches
	// this record stands for after suppression.
	DedupKey string `json:"dedup_key,omitempty"`
	Count    int    `json:"count,omitempty"`
	// Escalate marks findings that are suspicious but not conclusive and are
	// good candidates for a downstream LLM or human judge.
	Escalate bool   `json:"escalate,omitempty"`
	Remedy   string `json:"remedy,omitempty"`
}

func (d *Detection) clone() *Detection {
	c := *d
	c.Tags = append([]string(nil), d.Tags...)
	c.EventIDs = append([]string(nil), d.EventIDs...)
	c.Flags = append([]string(nil), d.Flags...)
	if d.Evidence != nil {
		c.Evidence = make(map[string]string, len(d.Evidence))
		for k, v := range d.Evidence {
			c.Evidence[k] = v
		}
	}
	return &c
}

// Health is the sensor heartbeat. It is deliberately content-free.
type Health struct {
	SensorVersion string `json:"sensor_version"`
	// Mode: daemon | extension | hook | scan.
	Mode       string            `json:"mode"`
	UptimeS    int64             `json:"uptime_s,omitempty"`
	Counters   map[string]uint64 `json:"counters,omitempty"`
	Surfaces   []SurfaceStatus   `json:"surfaces,omitempty"`
	Coverage   []Coverage        `json:"coverage,omitempty"`
	RulesCount int               `json:"rules_count,omitempty"`
	RulesHash  string            `json:"rules_hash,omitempty"`
	CatalogVer string            `json:"catalog_version,omitempty"`
	LastScan   Time              `json:"last_scan,omitzero"`
	// Reason is a closed-vocabulary code for health.error records.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (h *Health) clone() *Health {
	c := *h
	if h.Counters != nil {
		c.Counters = make(map[string]uint64, len(h.Counters))
		for k, v := range h.Counters {
			c.Counters[k] = v
		}
	}
	c.Surfaces = append([]SurfaceStatus(nil), h.Surfaces...)
	c.Coverage = append([]Coverage(nil), h.Coverage...)
	return &c
}

// SurfaceStatus reports one collector.
type SurfaceStatus struct {
	Name string `json:"name"` // hooks | transcripts | processes | scan
	// Status: ok | degraded | failed | disabled.
	Status      string `json:"status"`
	LastEvent   Time   `json:"last_event,omitzero"`
	Events      uint64 `json:"events,omitempty"`
	Errors      uint64 `json:"errors,omitempty"`
	SchemaDrift bool   `json:"schema_drift,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Coverage is the per-agent, per-user visibility statement: which surfaces
// are actually delivering. "Not collected" must never read as "clean".
type Coverage struct {
	AgentID    string `json:"agent_id"`
	User       string `json:"user,omitempty"`
	Hooks      string `json:"hooks,omitempty"`      // see Telemetry.Hooks
	Transcript string `json:"transcript,omitempty"` // see Telemetry.Transcript
	Processes  int    `json:"processes,omitempty"`  // running agent processes seen
	// State: covered | partial | blind | absent.
	State string `json:"state"`
}

// Summary is the per-session rollup: enough to answer fleet-wide questions
// ("which hosts called MCP server X", "which sessions loaded skill hash Y")
// from a small indexed stream while raw activity stays local or in cold
// storage. It carries counts, classes and identifiers, never content.
type Summary struct {
	Started  Time `json:"started,omitzero"`
	Ended    Time `json:"ended,omitzero"`
	Final    bool `json:"final,omitempty"` // true when the session ended; false for periodic rollups
	Events   int  `json:"events"`
	Prompts  int  `json:"prompts,omitempty"`
	Subagent int  `json:"subagents,omitempty"`
	// ToolCalls counts tool calls by normalized kind.
	ToolCalls map[string]int `json:"tool_calls,omitempty"`
	// Hosts are distinct network hosts contacted through tools (capped).
	Hosts       []string `json:"hosts,omitempty"`
	HostClasses []string `json:"host_classes,omitempty"`
	// PathClasses are the distinct sensitive path classes touched.
	PathClasses []string `json:"path_classes,omitempty"`
	MCPServers  []string `json:"mcp_servers,omitempty"`
	// Installs are packages installed by the agent as "manager:name".
	Installs    []string `json:"installs,omitempty"`
	Detections  []string `json:"detections,omitempty"` // rule ids
	MaxSeverity string   `json:"max_severity,omitempty"`
	Flags       []string `json:"flags,omitempty"` // session flags set by rules
	// Surfaces that reported this session and the resulting coverage state
	// (covered | partial | blind).
	Surfaces []Source `json:"surfaces,omitempty"`
	Coverage string   `json:"coverage,omitempty"`
	Denied   int      `json:"denied,omitempty"`  // tool calls denied by user, policy or guard
	Blocked  int      `json:"blocked,omitempty"` // tool calls blocked by spoor guard mode
}

func (s *Summary) clone() *Summary {
	c := *s
	if s.ToolCalls != nil {
		c.ToolCalls = make(map[string]int, len(s.ToolCalls))
		for k, v := range s.ToolCalls {
			c.ToolCalls[k] = v
		}
	}
	c.Hosts = append([]string(nil), s.Hosts...)
	c.HostClasses = append([]string(nil), s.HostClasses...)
	c.PathClasses = append([]string(nil), s.PathClasses...)
	c.MCPServers = append([]string(nil), s.MCPServers...)
	c.Installs = append([]string(nil), s.Installs...)
	c.Detections = append([]string(nil), s.Detections...)
	c.Flags = append([]string(nil), s.Flags...)
	c.Surfaces = append([]Source(nil), s.Surfaces...)
	return &c
}
