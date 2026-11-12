package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// MaxNumbatLine is the longest numbat record that is decoded. numbat's
// default records are a few kilobytes; with --content full or raw a record
// can embed tool payloads of up to 16 MiB each. A longer line is not
// dropped: Numbat returns ErrTooLarge together with a minimal event built
// from the record's envelope, so the action stays visible.
const MaxNumbatLine = 8 << 20

// Errors returned by Numbat. They wrap the cause where there is one and are
// meant to be counted by the caller, per kind.
var (
	// ErrMalformed: the line is not a JSON object.
	ErrMalformed = errors.New("adapter: malformed numbat record")
	// ErrNotNumbat: valid JSON without numbat's record_type/schema_version.
	ErrNotNumbat = errors.New("adapter: not a numbat record")
	// ErrVersion: a schema_version outside 0.5.x. The record is not
	// converted, because field meanings are only known for 0.5.
	ErrVersion = errors.New("adapter: unsupported numbat schema_version")
	// ErrUnknownRecord: a record_type this adapter has never heard of.
	ErrUnknownRecord = errors.New("adapter: unknown numbat record_type")
	// ErrTooLarge: the line exceeds MaxNumbatLine (see there).
	ErrTooLarge = errors.New("adapter: numbat record too large")
	// ErrInternal: a bug in the adapter was contained.
	ErrInternal = errors.New("adapter: internal error")
)

// numbatRecord is the union of the numbat 0.5.0 record schemas
// (docs/schema/v0.5.0/*-record.schema.json). Every member is optional here:
// the schemas say what numbat emits, not what a file on disk contains.
type numbatRecord struct {
	SchemaVersion lstr      `json:"schema_version"`
	RecordType    lstr      `json:"record_type"`
	RunID         lstr      `json:"run_id"`
	Endpoint      nEndpoint `json:"endpoint"`
	CaseID        lstr      `json:"case_id"`

	// event
	EventID         lstr `json:"event_id"`
	SourceAgent     lstr `json:"source_agent"`
	SourceType      lstr `json:"source_type"` // artifact | hook | otel
	Timestamp       lstr `json:"timestamp"`
	ProjectPath     lstr `json:"project_path"`
	SessionID       lstr `json:"session_id"`
	SessionTreeID   lstr `json:"session_tree_id"`
	ParentSessionID lstr `json:"parent_session_id"`
	Actor           lstr `json:"actor"`
	EventType       lstr `json:"event_type"`
	ToolName        lstr `json:"tool_name"`
	Command         lstr `json:"command"`
	FilePath        lstr `json:"file_path"`
	// Decision is allowed|denied|asked on events and deny|no_override on
	// enforcement records.
	Decision            lstr      `json:"decision"`
	ToolCallID          lstr      `json:"tool_call_id"`
	DiffSHA256          lstr      `json:"diff_sha256"`
	DiffBytes           lint      `json:"diff_bytes"`
	ExitCode            lint      `json:"exit_code"`
	DurationMS          lint      `json:"duration_ms"`
	ApprovalRequired    lbool     `json:"approval_required"`
	ApprovalDecision    lstr      `json:"approval_decision"`
	MCPServer           lstr      `json:"mcp_server"`
	MCPTool             lstr      `json:"mcp_tool"`
	URL                 lstr      `json:"url"`
	Model               lstr      `json:"model"`
	ModelProvider       lstr      `json:"model_provider"`
	GitBranch           lstr      `json:"git_branch"`
	Entrypoint          lstr      `json:"entrypoint"`
	CLIVersion          lstr      `json:"cli_version"`
	SubAgent            lstr      `json:"sub_agent"`
	SubAgentID          lstr      `json:"sub_agent_id"`
	ContentPreview      lstr      `json:"content_preview"`
	ContentPreviewCut   lbool     `json:"content_preview_truncated"`
	Content             lstr      `json:"content"`
	ContentBytes        lint      `json:"content_bytes"`
	ContentTruncated    lbool     `json:"content_truncated"`
	ContentOmitted      lstrs     `json:"content_omitted"`
	ToolInput           lstr      `json:"tool_input"`
	ToolInputBytes      lint      `json:"tool_input_bytes"`
	ToolInputTruncated  lbool     `json:"tool_input_truncated"`
	ToolResult          lstr      `json:"tool_result"`
	ToolResultBytes     lint      `json:"tool_result_bytes"`
	ToolResultTruncated lbool     `json:"tool_result_truncated"`
	Tags                lstrs     `json:"tags"`
	Confidence          lstr      `json:"confidence"`
	Evidence            nEvidence `json:"evidence"`

	// finding
	FindingID         lstr  `json:"finding_id"`
	DetectedAt        lstr  `json:"detected_at"`
	RuleID            lstr  `json:"rule_id"`
	RuleVersion       lstr  `json:"rule_version"`
	Severity          lstr  `json:"severity"`
	ProjectPathHash   lstr  `json:"project_path_hash"`
	Title             lstr  `json:"title"`
	ObservedEventType lstr  `json:"observed_event_type"`
	ObservedActor     lstr  `json:"observed_actor"`
	ObservedCommand   lstr  `json:"observed_command"`
	ObservedFilePath  lstr  `json:"observed_file_path"`
	ObservedURL       lstr  `json:"observed_url"`
	ObservedMCPServer lstr  `json:"observed_mcp_server"`
	ObservedMCPTool   lstr  `json:"observed_mcp_tool"`
	CitedEventIDs     lstrs `json:"cited_event_ids"`
	Redacted          lbool `json:"redacted"`

	// enforcement
	DecisionID      lstr  `json:"decision_id"`
	Mode            lstr  `json:"mode"`   // monitor | enforce
	Reason          lstr  `json:"reason"` // monitor_mode | no_enforce_eligible_match | fail_open | enforce_rule_match
	ActionEventIDs  lstrs `json:"action_event_ids"`
	FindingIDs      lstrs `json:"finding_ids"`
	RuleIDs         lstrs `json:"rule_ids"`
	DenyRuleID      lstr  `json:"deny_rule_id"`
	DenyRuleVersion lstr  `json:"deny_rule_version"`

	// indicator
	Type            lstr `json:"type"` // domain | ipv4 | ipv6 | url | email | md5 | sha1 | sha256
	Value           lstr `json:"value"`
	Count           lint `json:"count"`
	FirstSeen       lstr `json:"first_seen"`
	LastSeen        lstr `json:"last_seen"`
	SampleEventID   lstr `json:"sample_event_id"`
	SampleSessionID lstr `json:"sample_session_id"`
	SampleProjHash  lstr `json:"sample_project_path_hash"`
}

type nEndpointFields struct {
	Hostname lstr `json:"hostname"`
	OS       lstr `json:"os"`
	Arch     lstr `json:"arch"`
	Username lstr `json:"username"`
	UID      lstr `json:"uid"`
	DeviceID lstr `json:"device_id"`
}

// nEndpoint is numbat's endpoint object; a value of another type reads as
// absent.
type nEndpoint struct{ nEndpointFields }

func (e *nEndpoint) UnmarshalJSON(b []byte) error {
	*e = nEndpoint{}
	if len(b) > 0 && b[0] == '{' {
		_ = json.Unmarshal(b, &e.nEndpointFields)
	}
	return nil
}

type nEvidenceFields struct {
	ArtifactType lstr `json:"artifact_type"`
	LocalPath    lstr `json:"local_path"`
}

// nEvidence is numbat's evidence reference.
type nEvidence struct{ nEvidenceFields }

func (e *nEvidence) UnmarshalJSON(b []byte) error {
	*e = nEvidence{}
	if len(b) > 0 && b[0] == '{' {
		_ = json.Unmarshal(b, &e.nEvidenceFields)
	}
	return nil
}

// Numbat converts one NDJSON line written by perplexityai/numbat (record
// schema 0.5.x) into spoor events:
//
//	event        one activity event (none for message.assistant and
//	             message.reasoning, which have no spoor counterpart)
//	finding      one detection event
//	enforcement  one activity event: permission.decision for a deny,
//	             notification for no_override
//	indicator    one activity notification with the indicator as its target
//	scan_summary, diagnostic
//	             nothing (numbat's own run accounting)
//
// A nil slice with a nil error means the record was understood and has
// nothing to contribute. Numbat never panics. See the package documentation
// for the field mapping and for what is UNVERIFIED.
func Numbat(line []byte) ([]*event.Event, error) {
	return numbat(line, time.Now)
}

func numbat(line []byte, now func() time.Time) (evs []*event.Event, err error) {
	defer func() {
		if p := recover(); p != nil {
			evs, err = nil, fmt.Errorf("%w: %v", ErrInternal, p)
		}
	}()
	b := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("\xef\xbb\xbf")))
	if len(b) == 0 || b[0] != '{' {
		return nil, ErrMalformed
	}
	if len(b) > MaxNumbatLine {
		return oversize(b, now), ErrTooLarge
	}
	var r numbatRecord
	if err := json.Unmarshal(b, &r); err != nil {
		// The decoder's message can quote the input; keep only the position.
		var syn *json.SyntaxError
		if errors.As(err, &syn) {
			return nil, fmt.Errorf("%w: syntax error at offset %d", ErrMalformed, syn.Offset)
		}
		return nil, ErrMalformed
	}
	if r.RecordType == "" || r.SchemaVersion == "" {
		return nil, ErrNotNumbat
	}
	if !supportedVersion(string(r.SchemaVersion)) {
		return nil, fmt.Errorf("%w %q (this adapter reads 0.5.x)", ErrVersion, labelValue(string(r.SchemaVersion), 32))
	}
	c := &nctx{r: &r, now: now, line: b}
	switch r.RecordType {
	case "event":
		return c.event(), nil
	case "finding":
		return c.finding(), nil
	case "enforcement":
		return c.enforcement(), nil
	case "indicator":
		return c.indicator(), nil
	case "scan_summary", "diagnostic":
		return nil, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownRecord, labelValue(string(r.RecordType), 64))
}

// supportedVersion accepts 0.5 and 0.5.<anything>.
func supportedVersion(v string) bool {
	return v == "0.5" || strings.HasPrefix(v, "0.5.")
}

// nctx carries one record through conversion.
type nctx struct {
	r    *numbatRecord
	now  func() time.Time
	line []byte
}

// agentID maps numbat's source_agent enum to spoor's catalog ids. The two
// vocabularies agree except for "copilot" (numbat) and "copilot-cli"
// (spoor), which toolmap.Canonical resolves; numbat's other agents pass
// through unchanged.
func agentID(source string) string {
	id := labelValue(strings.ToLower(source), 64)
	if id == "" {
		return "unknown"
	}
	return toolmap.Canonical(id)
}

// stamp parses a record timestamp, falling back to now.
func (c *nctx) stamp(candidates ...lstr) (t time.Time, sensor bool) {
	for _, s := range candidates {
		if t, ok := parseTime(string(s)); ok {
			return t, false
		}
	}
	return c.now().UTC(), true
}

// embeddedTime finds the run timestamp numbat puts in the ids it generates
// for live records ("hook-run-20260724T151125.690671167-fa0a4148090fa1ba").
var embeddedTime = regexp.MustCompile(`(\d{8}T\d{6})(\.\d{1,9})?`)

// numbatID derives the spoor id of a numbat event, finding or decision from
// numbat's own id alone. That is what lets a finding's cited_event_ids and
// an enforcement record's finding_ids be translated into the ids of the
// converted records without having seen them: this function is stateless
// and the two lines may be converted in different processes.
//
// Ids are UUIDv8 like every deterministic spoor id. Their time prefix comes
// from the timestamp embedded in numbat's id when there is one, so they
// still sort by time; ids without one get a zero prefix.
// UNVERIFIED: the embedded-timestamp id format is taken from the README
// examples, not from a documented contract; nothing depends on it but sort
// order.
func numbatID(kind, id string) string {
	t := time.Unix(0, 0)
	if len(id) <= maxID {
		if m := embeddedTime.FindStringSubmatch(id); m != nil {
			if p, err := time.Parse("20060102T150405", m[1]); err == nil && !p.Before(minTime) && p.Before(maxTime) {
				t = p
				if m[2] != "" {
					if frac, err := time.ParseDuration("0" + m[2] + "s"); err == nil {
						t = t.Add(frac)
					}
				}
			}
		}
	}
	return event.StableID(t, "numbat", kind, id)
}

func numbatIDs(kind string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && len(out) < maxIDs {
			out = append(out, numbatID(kind, id))
		}
	}
	return out
}

// base starts an event with what every numbat record carries.
func (c *nctx) base(kind event.Kind, typ string, ts time.Time, sensorTime bool) *event.Event {
	r := c.r
	ev := &event.Event{
		V:      event.SchemaVersion,
		TS:     event.At(ts),
		Kind:   kind,
		Type:   typ,
		Source: event.SourceAdapter,
		// numbat runs as the monitored user and writes a file that user
		// owns; nothing about a record is root-attested.
		Integrity: event.IntegrityUser,
		Labels:    map[string]string{"adapter": "numbat"},
	}
	setLabel(ev, "numbat_schema", string(r.SchemaVersion))
	setLabel(ev, "numbat_run_id", string(r.RunID))
	setLabel(ev, "numbat_source_type", string(r.SourceType))
	setLabel(ev, "numbat_case_id", string(r.CaseID))
	if sensorTime {
		setLabel(ev, "ts_source", "sensor")
	}
	ep := r.Endpoint
	if ep.Hostname != "" || ep.OS != "" || ep.Arch != "" {
		ev.Host = &event.Host{
			Name: field(ev, "host.name", string(ep.Hostname), maxName),
			OS:   labelValue(string(ep.OS), 32),
			Arch: labelValue(string(ep.Arch), 32),
		}
	}
	// NUMBAT_DEVICE_ID is an operator-chosen opaque id. It is not put in
	// Host.ID, which must be osquery's system_info.uuid to join to Fleet.
	setLabel(ev, "numbat_device_id", string(ep.DeviceID))
	if ep.Username != "" || ep.UID != "" {
		ev.User = &event.User{
			Name: field(ev, "user.name", string(ep.Username), maxName),
			ID:   field(ev, "user.id", string(ep.UID), maxName),
		}
	}
	if r.SourceAgent != "" || kind == event.KindActivity {
		ev.Agent = &event.Agent{ID: agentID(string(r.SourceAgent))}
		ev.Agent.Version = field(ev, "agent.version", string(r.CLIVersion), 64)
	}
	if raw := labelValue(strings.ToLower(string(r.SourceAgent)), 64); raw != "" && ev.Agent != nil && raw != ev.Agent.ID {
		setLabel(ev, "numbat_source_agent", raw)
	}
	s := &event.Session{}
	s.ID = field(ev, "session.id", string(r.SessionID), maxID)
	s.ParentID = field(ev, "session.parent_id", string(r.ParentSessionID), maxID)
	s.Model = field(ev, "session.model", string(r.Model), maxName)
	// sub_agent_id is the stable child identity; sub_agent is display
	// context such as a role or profile (docs/event-model.md).
	s.SubagentID = field(ev, "session.subagent_id", string(r.SubAgentID), maxID)
	s.SubagentType = field(ev, "session.subagent_type", string(r.SubAgent), maxName)
	if *s != (event.Session{}) {
		ev.Session = s
	}
	if id, _ := cleanID(string(r.SessionTreeID), maxLabel); id != "" {
		setLabel(ev, "session_tree_id", id)
	}
	setLabel(ev, "model_provider", string(r.ModelProvider))
	return ev
}

func (c *nctx) session(ev *event.Event) *event.Session {
	if ev.Session == nil {
		ev.Session = &event.Session{}
	}
	return ev.Session
}

// lineKey identifies a record that has no id of its own.
func (c *nctx) lineKey() string {
	sum := sha256.Sum256(c.line)
	return hex.EncodeToString(sum[:16])
}

// oversize builds the stand-in for a record that is too long to decode,
// from a non-allocating scan of its top-level members. Dropping it silently
// would be an evasion primitive: pad a tool argument and the action
// disappears from spoor's view of numbat's stream.
func oversize(b []byte, now func() time.Time) []*event.Event {
	top, _ := scanTop(b, map[string]bool{
		"record_type": true, "schema_version": true, "run_id": true, "event_id": true, "event_type": true,
		"source_agent": true, "source_type": true, "session_id": true, "timestamp": true,
		"tool_name": true, "tool_call_id": true, "finding_id": true, "rule_id": true,
	})
	get := func(k string) lstr { return lstr(top[k].text) }
	r := &numbatRecord{
		SchemaVersion: get("schema_version"), RecordType: get("record_type"), RunID: get("run_id"),
		SourceAgent: get("source_agent"), SourceType: get("source_type"), SessionID: get("session_id"),
	}
	c := &nctx{r: r, now: now, line: b}
	ts, sensor := c.stamp(get("timestamp"))
	ev := c.base(event.KindActivity, event.TypeNotification, ts, sensor)
	sum := sha256.Sum256(b)
	ev.ID = event.StableID(ts, "numbat", "oversize", hex.EncodeToString(sum[:16]))
	setLabel(ev, "adapter_anomaly", "oversize")
	setLabel(ev, "line_bytes", fmt.Sprint(len(b)))
	setLabel(ev, "line_sha256", hex.EncodeToString(sum[:]))
	setLabel(ev, "numbat_record_type", string(get("record_type")))
	setLabel(ev, "numbat_event_type", string(get("event_type")))
	if id, _ := cleanID(string(get("event_id")), maxLabel); id != "" {
		setLabel(ev, "numbat_event_id", id)
	}
	setLabel(ev, "numbat_rule_id", string(get("rule_id")))
	if name := string(get("tool_name")); name != "" {
		t := &event.Tool{}
		t.Name = field(ev, "tool.name", name, maxName)
		t.UseID = field(ev, "tool.use_id", string(get("tool_call_id")), maxID)
		t.Kind, t.MCPServer, t.MCPTool = toolmap.Kind(ev.Agent.ID, t.Name)
		ev.Tool = t
	}
	ev.Truncated = appendUnique(ev.Truncated, "record")
	return []*event.Event{ev}
}
