// Package event defines the normalized record that every spoor source emits
// and every sink serializes. It is the single contract between collection
// (hooks, transcripts, process monitor, scanner), detection and output.
//
// Design rules:
//   - One Event is one JSON object on one line (NDJSON).
//   - Fields tagged `json:"-"` are local-only: they feed detection on the
//     endpoint and are never serialized. What leaves the machine is decided by
//     the redaction stage according to the configured privacy tier.
//   - Every enum is a closed vocabulary declared in this package. Free-form
//     vendor strings go in Labels or in the typed sub-struct that owns them.
package event

import (
	"encoding/json"
)

// SchemaVersion is the value of Event.V. Bump only on breaking changes;
// adding optional fields is not breaking.
const SchemaVersion = 1

// Kind is the top-level class of a record and selects the output stream.
type Kind string

const (
	KindActivity  Kind = "activity"  // something an agent did or was asked to do
	KindInventory Kind = "inventory" // an asset that exists on the endpoint
	KindPosture   Kind = "posture"   // the result of a configuration check
	KindDetection Kind = "detection" // a rule matched
	KindHealth    Kind = "health"    // sensor heartbeat, coverage and errors
	KindSummary   Kind = "summary"   // per-session rollup, small enough to index centrally
)

// Stream returns the output stream name for the kind. Sinks use it for file
// names (<stream>-*.ndjson) and Fluent Bit tags (spoor.<stream>).
func (k Kind) Stream() string {
	switch k {
	case KindActivity, KindInventory, KindPosture, KindDetection, KindHealth, KindSummary:
		return string(k)
	default:
		return "activity"
	}
}

// Streams lists every stream in a stable order.
var Streams = []string{"activity", "detection", "inventory", "posture", "health", "summary"}

// Source is the collection method that produced a record.
type Source string

const (
	SourceHook       Source = "hook"       // agent hook invoked spoor (real time, self-reported by the agent)
	SourceTranscript Source = "transcript" // parsed from the agent's on-disk session log
	SourceProcess    Source = "process"    // observed from the OS process table
	SourceScan       Source = "scan"       // discovery / posture scan of files and packages
	SourceOTel       Source = "otel"       // agent-native OpenTelemetry received locally
	SourceOsquery    Source = "osquery"    // rows from osquery evented tables read from its local results log
	SourceAdapter    Source = "adapter"    // records converted from another sensor's output
	SourceSensor     Source = "sensor"     // produced by spoor itself (detections, health, correlation)
)

// Fidelity says whether the record was directly observed or reconstructed.
type Fidelity string

const (
	FidelityObserved Fidelity = "observed"
	FidelityInferred Fidelity = "inferred"
)

// Activity event types (Event.Type when Kind == KindActivity).
const (
	TypeSessionStart       = "session.start"
	TypeSessionEnd         = "session.end"
	TypePromptSubmit       = "prompt.submit"
	TypeToolPre            = "tool.pre"  // before execution; the only type guard mode can block
	TypeToolPost           = "tool.post" // after execution, success or failure (see Outcome)
	TypeTurnEnd            = "turn.end"
	TypeSubagentStart      = "subagent.start"
	TypeSubagentStop       = "subagent.stop"
	TypePermissionDecision = "permission.decision"
	TypeConfigChange       = "config.change"
	TypeNotification       = "notification"
	TypeCompact            = "context.compact"
	TypeAgentProcessStart  = "agent.process.start"
	TypeAgentProcessStop   = "agent.process.stop"
	TypeProcessExec        = "process.exec" // child process attributed to an agent session
)

// Non-activity event types.
const (
	TypeInventoryAsset   = "inventory.asset"
	TypePostureCheck     = "posture.check"
	TypeDetectionFinding = "detection.finding"
	TypeHealthHeartbeat  = "health.heartbeat"
	TypeHealthError      = "health.error"
	TypeSessionSummary   = "session.summary"
)

// Integrity says who could have altered a record before it was written.
// Hooks run as the monitored user, so their records are advisory until a
// privileged collector corroborates them; anything a Fleet policy depends on
// must be root-integrity.
type Integrity string

const (
	IntegrityRoot Integrity = "root" // written by a privileged scan or daemon
	IntegrityUser Integrity = "user" // written by an unprivileged process the monitored user controls
)

// ToolKind is the cross-agent normalized class of a tool call.
type ToolKind string

const (
	ToolShell     ToolKind = "shell"
	ToolFileRead  ToolKind = "file_read"
	ToolFileWrite ToolKind = "file_write" // create or overwrite
	ToolFileEdit  ToolKind = "file_edit"  // in-place modification
	ToolFileList  ToolKind = "file_list"  // glob, grep, ls style discovery
	ToolWebFetch  ToolKind = "web_fetch"
	ToolWebSearch ToolKind = "web_search"
	ToolMCP       ToolKind = "mcp"
	ToolSubagent  ToolKind = "subagent"
	ToolBrowser   ToolKind = "browser"
	ToolOther     ToolKind = "other"
)

// Event is the normalized record.
type Event struct {
	V   int    `json:"v"`
	ID  string `json:"id"`
	TS  Time   `json:"ts"`
	Seq uint64 `json:"seq,omitempty"` // monotonic per (Writer, stream), for gap detection downstream
	// Dedupe is identical for every record that describes the same action,
	// whichever surface reported it (see DedupeKey).
	Dedupe   string   `json:"dedupe,omitempty"`
	Kind     Kind     `json:"kind"`
	Type     string   `json:"type"`
	Source   Source   `json:"source"`
	Fidelity Fidelity `json:"fidelity,omitempty"`
	// Sources lists every surface that corroborated this event after
	// cross-surface correlation (for example ["hook","transcript"]).
	Sources   []Source  `json:"sources,omitempty"`
	Integrity Integrity `json:"integrity,omitempty"`
	// Writer identifies the process that wrote the record (random per process
	// start). Seq is monotonic per Writer, and heartbeats report per-writer
	// counts, so a consumer can prove that nothing was lost or removed.
	Writer string `json:"writer,omitempty"`

	Host      *Host      `json:"host,omitempty"`
	User      *User      `json:"user,omitempty"`
	Agent     *Agent     `json:"agent,omitempty"`
	Account   *Account   `json:"account,omitempty"`
	Session   *Session   `json:"session,omitempty"`
	Tool      *Tool      `json:"tool,omitempty"`
	Target    *Target    `json:"target,omitempty"`
	Prompt    *Prompt    `json:"prompt,omitempty"`
	Outcome   *Outcome   `json:"outcome,omitempty"`
	Process   *Process   `json:"process,omitempty"`
	Container *Container `json:"container,omitempty"`
	Repo      *Repo      `json:"repo,omitempty"`

	Asset     *Asset     `json:"asset,omitempty"`     // Kind == inventory
	Check     *Check     `json:"check,omitempty"`     // Kind == posture
	Detection *Detection `json:"detection,omitempty"` // Kind == detection
	Health    *Health    `json:"health,omitempty"`    // Kind == health
	Summary   *Summary   `json:"summary,omitempty"`   // Kind == summary

	// Privacy is the tier that was applied when the record was emitted.
	Privacy string `json:"privacy,omitempty"`
	// Truncated names fields whose values were cut; their full-value hash is
	// kept alongside so truncation is never silent.
	Truncated []string          `json:"truncated,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`

	// Content is the raw material detection may inspect locally. Never serialized.
	Content *Content `json:"-"`
	// Feat holds features computed by enrichers (shell AST facts, path and
	// host classes, content scan hits). Never serialized.
	Feat map[string]any `json:"-"`
}

// Content carries raw, possibly sensitive material for on-endpoint detection.
type Content struct {
	PromptText  string         // user prompt as submitted
	ToolInput   map[string]any // tool arguments as the agent supplied them
	ToolOutput  string         // tool result text (may be truncated by the source)
	FileContent string         // content being written, when the tool carries it
	Raw         json.RawMessage
}

// Host identifies the endpoint. ID should equal osquery's system_info.uuid so
// events join to Fleet hosts.
type Host struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	OS   string `json:"os,omitempty"`   // linux | darwin | windows
	Arch string `json:"arch,omitempty"` // amd64 | arm64
}

// User is the OS account the agent runs as.
type User struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"` // uid on POSIX, SID on Windows
}

// Agent identifies the AI agent product.
type Agent struct {
	ID      string `json:"id"` // catalog id, e.g. "claude-code"
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PID     int    `json:"pid,omitempty"`
	// Surface is how the agent was run: cli | ide | desktop | sdk | ci | cloud.
	Surface string `json:"surface,omitempty"`
}

// Account is the identity the agent is signed in with, when a surface
// reports it (vendor OpenTelemetry does; hooks usually do not). It answers
// the first governance question: corporate tenant, personal account or a
// raw API key on a managed machine.
type Account struct {
	// ID is the vendor account identifier; emitted as a keyed digest unless
	// the privacy profile is full.
	ID  string `json:"id,omitempty"`
	Org string `json:"org,omitempty"`
	// Kind: organization | personal | api_key | unknown.
	Kind string `json:"kind,omitempty"`
}

// Session identifies one agent conversation.
type Session struct {
	ID       string `json:"id,omitempty"`
	ParentID string `json:"parent_id,omitempty"` // parent session for subagents
	TurnID   string `json:"turn_id,omitempty"`
	CWD      string `json:"cwd,omitempty"`
	// PermissionMode is the agent's own vocabulary, normalized to:
	// default | plan | accept_edits | auto | dont_ask | bypass.
	PermissionMode string `json:"permission_mode,omitempty"`
	Model          string `json:"model,omitempty"`
	Transcript     string `json:"transcript,omitempty"` // path of the session log, when known
	SubagentID     string `json:"subagent_id,omitempty"`
	SubagentType   string `json:"subagent_type,omitempty"`
}

// Tool describes the tool call.
type Tool struct {
	Name      string   `json:"name,omitempty"` // agent's own tool name, e.g. "Bash"
	Kind      ToolKind `json:"kind,omitempty"`
	UseID     string   `json:"use_id,omitempty"`     // agent's tool-call id; join key across surfaces
	MCPServer string   `json:"mcp_server,omitempty"` // for Kind == mcp
	MCPTool   string   `json:"mcp_tool,omitempty"`
	// InputSHA256 is the hash of the canonical JSON of the tool input, so
	// identical calls correlate without shipping content.
	InputSHA256 string `json:"input_sha256,omitempty"`
	// InputKeys lists top-level argument names (metadata tier).
	InputKeys []string `json:"input_keys,omitempty"`
	// Input is the redacted tool input; present only in tiers redacted/full.
	Input map[string]any `json:"input,omitempty"`
	// Output is the redacted, truncated tool output; tiers redacted/full only.
	Output       string `json:"output,omitempty"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	OutputLen    int    `json:"output_len,omitempty"`
}

// Target is what the tool call acts on, extracted and normalized.
type Target struct {
	Command string   `json:"command,omitempty"` // shell command line, secrets redacted
	Path    string   `json:"path,omitempty"`    // primary file path
	Paths   []string `json:"paths,omitempty"`   // additional paths referenced
	URL     string   `json:"url,omitempty"`     // userinfo, query and fragment stripped unless tier is full
	Host    string   `json:"host,omitempty"`    // network host
	Hosts   []string `json:"hosts,omitempty"`
	Query   string   `json:"query,omitempty"` // web search query; tiers redacted/full only
}

// Prompt summarizes a user prompt without necessarily carrying it.
type Prompt struct {
	Len    int    `json:"len"`
	SHA256 string `json:"sha256,omitempty"` // keyed hash when a tenant key is configured
	Text   string `json:"text,omitempty"`   // tiers redacted/full only
}

// Outcome is the result of a tool call or turn.
type Outcome struct {
	// Status: ok | error | denied | interrupted | unknown.
	Status     string `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	// Decision: allow | deny | ask, when a permission decision was observed.
	Decision       string `json:"decision,omitempty"`
	DecisionSource string `json:"decision_source,omitempty"` // user | policy | hook | spoor
}

// Process describes an OS process.
type Process struct {
	PID       int      `json:"pid,omitempty"`
	PPID      int      `json:"ppid,omitempty"`
	Name      string   `json:"name,omitempty"`
	Exe       string   `json:"exe,omitempty"`
	Args      []string `json:"args,omitempty"` // secrets redacted
	StartTime Time     `json:"start_time,omitzero"`
	User      string   `json:"user,omitempty"`
	// Ancestors is the chain of process names from parent to root.
	Ancestors []string `json:"ancestors,omitempty"`
	// EnvMarkers are agent marker variable NAMES found in the environment
	// (values are never emitted except session ids copied into Session).
	EnvMarkers []string `json:"env_markers,omitempty"`
	// Flags are risky argv flags recognized by the catalog,
	// e.g. "--dangerously-skip-permissions".
	Flags []string `json:"flags,omitempty"`
}

// Container locates the workload when the agent runs in a container.
type Container struct {
	ID        string `json:"id,omitempty"`
	Runtime   string `json:"runtime,omitempty"` // docker | containerd | cri-o | podman
	Image     string `json:"image,omitempty"`
	Name      string `json:"name,omitempty"`
	Pod       string `json:"pod,omitempty"`
	PodUID    string `json:"pod_uid,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Node      string `json:"node,omitempty"`
}

// Repo describes the source repository of the session's working directory.
type Repo struct {
	Root   string `json:"root,omitempty"`
	Remote string `json:"remote,omitempty"` // credentials stripped
	Branch string `json:"branch,omitempty"`
}

// MarshalLine returns the event as one NDJSON line including the trailing
// newline. The result never contains a raw newline inside the object.
func (e *Event) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Clone returns a deep-enough copy for redaction: every emitted pointer
// struct and slice is duplicated so the redactor can mutate the copy while
// detection keeps the original. Content and Feat are shared (never emitted).
func (e *Event) Clone() *Event {
	if e == nil {
		return nil
	}
	c := *e
	c.Sources = append([]Source(nil), e.Sources...)
	c.Truncated = append([]string(nil), e.Truncated...)
	if e.Labels != nil {
		c.Labels = make(map[string]string, len(e.Labels))
		for k, v := range e.Labels {
			c.Labels[k] = v
		}
	}
	if e.Host != nil {
		v := *e.Host
		c.Host = &v
	}
	if e.User != nil {
		v := *e.User
		c.User = &v
	}
	if e.Agent != nil {
		v := *e.Agent
		c.Agent = &v
	}
	if e.Account != nil {
		v := *e.Account
		c.Account = &v
	}
	if e.Session != nil {
		v := *e.Session
		c.Session = &v
	}
	if e.Tool != nil {
		v := *e.Tool
		v.InputKeys = append([]string(nil), e.Tool.InputKeys...)
		v.Input = cloneMap(e.Tool.Input)
		c.Tool = &v
	}
	if e.Target != nil {
		v := *e.Target
		v.Paths = append([]string(nil), e.Target.Paths...)
		v.Hosts = append([]string(nil), e.Target.Hosts...)
		c.Target = &v
	}
	if e.Prompt != nil {
		v := *e.Prompt
		c.Prompt = &v
	}
	if e.Outcome != nil {
		v := *e.Outcome
		c.Outcome = &v
	}
	if e.Process != nil {
		v := *e.Process
		v.Args = append([]string(nil), e.Process.Args...)
		v.Ancestors = append([]string(nil), e.Process.Ancestors...)
		v.EnvMarkers = append([]string(nil), e.Process.EnvMarkers...)
		v.Flags = append([]string(nil), e.Process.Flags...)
		c.Process = &v
	}
	if e.Container != nil {
		v := *e.Container
		c.Container = &v
	}
	if e.Repo != nil {
		v := *e.Repo
		c.Repo = &v
	}
	if e.Asset != nil {
		c.Asset = e.Asset.clone()
	}
	if e.Check != nil {
		v := *e.Check
		c.Check = &v
	}
	if e.Detection != nil {
		c.Detection = e.Detection.clone()
	}
	if e.Health != nil {
		c.Health = e.Health.clone()
	}
	if e.Summary != nil {
		c.Summary = e.Summary.clone()
	}
	return &c
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneAny(v)
	}
	return out
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMap(t)
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cloneAny(t[i])
		}
		return out
	default:
		return v
	}
}
