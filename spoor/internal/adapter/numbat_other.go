package adapter

import (
	"net"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// RulePrefix namespaces numbat rule ids in Detection.RuleID, so that a
// numbat rule and a spoor rule with the same id stay distinct in the state
// database, in suppressions and in SIEM content.
const RulePrefix = "numbat:"

// finding converts a numbat finding into a detection record. The finding is
// numbat's verdict, evaluated by numbat's rules on the endpoint: spoor
// relays it and does not re-evaluate it. Response is "none" because the
// finding itself never implies a deny (see enforcement).
func (c *nctx) finding() []*event.Event {
	r := c.r
	// timestamp is the matched activity's time and may be absent;
	// detected_at is when numbat created the finding.
	ts, sensor := c.stamp(r.Timestamp, r.DetectedAt)
	ev := c.base(event.KindDetection, event.TypeDetectionFinding, ts, sensor)
	if r.FindingID != "" {
		ev.ID = numbatID("finding", string(r.FindingID))
		if id, _ := cleanID(string(r.FindingID), maxLabel); id != "" {
			setLabel(ev, "numbat_finding_id", id)
		}
	} else {
		ev.ID = event.StableID(ts, "numbat", "line", c.lineKey())
	}
	setLabel(ev, "numbat_detected_at", string(r.DetectedAt))
	setLabel(ev, "project_path_hash", string(r.ProjectPathHash))

	ruleID, _ := cleanID(string(r.RuleID), maxLabel)
	d := &event.Detection{
		RuleID:   RulePrefix + labelValue(ruleID, maxLabel),
		Title:    oneLine(string(r.Title), maxName),
		Response: "none",
		Count:    1,
		// numbat has no class vocabulary; its findings are findings.
		Class: event.ClassFinding,
	}
	if d.Title == "" {
		d.Title = d.RuleID
	}
	// Same five levels as spoor. An unknown level is reported as info and
	// kept as a label rather than trusted.
	d.Severity = string(r.Severity)
	if event.SeverityRank(d.Severity) == 0 {
		d.Severity = event.SevInfo
		setLabel(ev, "numbat_severity", string(r.Severity))
	}
	switch r.Confidence {
	case "high", "medium", "low":
		d.Confidence = string(r.Confidence)
	}
	// numbat rule ids are "<family>.<name>" (chain.secret_read_then_egress).
	if i := strings.IndexByte(ruleID, '.'); i > 0 {
		d.Category = labelValue(ruleID[:i], 64)
	}
	// numbat's tags are Sigma-style already ("attack.t1048").
	for _, tag := range r.Tags {
		if v := labelValue(tag, 64); v != "" && len(d.Tags) < 32 {
			d.Tags = append(d.Tags, v)
		}
	}
	d.EventIDs = numbatIDs("event", r.CitedEventIDs)
	// One group per rule and session, so the engine's suppression counts
	// repeats instead of emitting each.
	d.DedupKey = event.DedupeKey("numbat", string(r.RuleID), string(r.SessionID), string(r.Endpoint.Hostname))

	// numbat masks credentials in finding fields before it writes them
	// ("redacted" says whether anything was masked): "credential query
	// parameters, URL userinfo passwords, Basic/Bearer authorization values,
	// secret-like assignments, and self-identifying token formats"
	// (docs/cli.md). The values are relayed as numbat masked them, flattened
	// and bounded, and the event says so in Labels evidence_redaction, so
	// the privacy stage can apply spoor's own patterns before the record
	// leaves the host. This package does not import the redactor: it must
	// build and convert on its own (CI, central re-evaluation). The observed
	// content preview is prompt or model text and is not copied at all.
	evd := map[string]string{}
	put := func(k, v string) {
		if v = oneLine(v, maxEvidence); v != "" {
			evd[k] = v
		}
	}
	put("event_type", string(r.ObservedEventType))
	put("actor", string(r.ObservedActor))
	put("command", string(r.ObservedCommand))
	put("file_path", string(r.ObservedFilePath))
	if u := string(r.ObservedURL); u != "" {
		put("url", bareURL(u))
	}
	put("mcp_server", string(r.ObservedMCPServer))
	put("mcp_tool", string(r.ObservedMCPTool))
	put("rule_version", string(r.RuleVersion))
	if r.Redacted.ok {
		put("redacted", boolText(r.Redacted.v))
	}
	if len(evd) > 0 {
		d.Evidence = evd
	}
	if evd["command"] != "" || evd["file_path"] != "" || evd["url"] != "" {
		setLabel(ev, "evidence_redaction", "numbat")
	}
	ev.Detection = d
	return []*event.Event{ev}
}

// enforcement converts numbat's computed policy decision for a pre-action
// hook. "It does not prove that the control response was delivered or
// honored by the host" (enforcement-record schema), so a deny is recorded
// as a permission decision made by a hook, not as a blocked tool call.
//
// no_override means numbat left the host's normal permission flow alone
// (monitor mode, no enforce-eligible match, or fail-open). That is not a
// decision about the call, so it becomes a notification; fail_open is the
// one worth alerting on.
func (c *nctx) enforcement() []*event.Event {
	r := c.r
	typ := event.TypeNotification
	deny := r.Decision == "deny"
	if deny {
		typ = event.TypePermissionDecision
	}
	ts, sensor := c.stamp(r.Timestamp)
	ev := c.base(event.KindActivity, typ, ts, sensor)
	if r.DecisionID != "" {
		ev.ID = numbatID("enforcement", string(r.DecisionID))
		if id, _ := cleanID(string(r.DecisionID), maxLabel); id != "" {
			setLabel(ev, "numbat_decision_id", id)
		}
	} else {
		ev.ID = event.StableID(ts, "numbat", "line", c.lineKey())
	}
	setLabel(ev, "numbat_decision", string(r.Decision))
	setLabel(ev, "numbat_mode", string(r.Mode))
	setLabel(ev, "numbat_reason", string(r.Reason))
	setListLabel(ev, "numbat_rule_ids", r.RuleIDs)
	if r.DenyRuleID != "" {
		setLabel(ev, "deny_rule", RulePrefix+string(r.DenyRuleID))
		setLabel(ev, "deny_rule_version", string(r.DenyRuleVersion))
	}
	// Joins to the converted findings and action events.
	setListLabel(ev, "finding_ids", numbatIDs("finding", r.FindingIDs))
	setListLabel(ev, "action_event_ids", numbatIDs("event", r.ActionEventIDs))

	if r.ToolName != "" || r.ToolCallID != "" {
		t := &event.Tool{}
		t.Name = field(ev, "tool.name", string(r.ToolName), maxName)
		t.UseID = field(ev, "tool.use_id", string(r.ToolCallID), maxID)
		if t.Name != "" {
			kind, server, tool := toolmap.Kind(ev.Agent.ID, t.Name)
			t.Kind = kind
			t.MCPServer, _ = cleanID(server, maxName)
			t.MCPTool, _ = cleanID(tool, maxName)
		}
		ev.Tool = t
	}
	if deny {
		ev.Outcome = &event.Outcome{Status: "denied", Decision: "deny", DecisionSource: "hook"}
	}
	return []*event.Event{ev}
}

// indicator converts numbat's deduplicated indicator projection (a domain,
// address, URL, e-mail address or file hash seen N times in a run) into a
// notification whose Target carries the indicator, so host and URL
// classification and the rules built on it apply unchanged.
//
// numbat's collect mode re-emits an indicator whenever its count changes
// and asks consumers to upsert by (run_id, type, value); the event id is
// derived from exactly those three, so a later snapshot replaces an earlier
// one downstream.
func (c *nctx) indicator() []*event.Event {
	r := c.r
	typ, value := string(r.Type), strings.TrimSpace(string(r.Value))
	if value == "" {
		return nil
	}
	ts, sensor := c.stamp(r.LastSeen, r.FirstSeen)
	ev := c.base(event.KindActivity, event.TypeNotification, ts, sensor)
	ev.ID = numbatID("indicator", string(r.RunID)+"\x00"+typ+"\x00"+value)
	ev.Dedupe = event.DedupeKey("numbat-indicator", string(r.RunID), typ, value)
	setLabel(ev, "numbat_record", "indicator")
	setLabel(ev, "indicator_type", typ)
	if r.Count.ok && r.Count.v > 0 {
		setLabel(ev, "indicator_count", itoa(r.Count.v))
	}
	setLabel(ev, "first_seen", string(r.FirstSeen))
	setLabel(ev, "last_seen", string(r.LastSeen))
	setLabel(ev, "project_path_hash", string(r.SampleProjHash))
	if r.SampleSessionID != "" {
		c.session(ev).ID = field(ev, "session.id", string(r.SampleSessionID), maxID)
	}
	if r.SampleEventID != "" {
		setLabel(ev, "sample_event_id", numbatID("event", string(r.SampleEventID)))
	}

	t := &event.Target{}
	switch typ {
	case "domain":
		t.Host = hostToken(value)
	case "ipv4", "ipv6":
		if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
			t.Host = ip.String()
		}
	case "url":
		t.URL, t.Host = toolmap.CleanURL(value)
	case "md5", "sha1", "sha256":
		if isHex(value) {
			setLabel(ev, "indicator_value", strings.ToLower(value))
		}
	case "email":
		// An address identifies a person. Only its domain is kept.
		if i := strings.LastIndexByte(value, '@'); i > 0 && i < len(value)-1 {
			t.Host = hostToken(value[i+1:])
		}
	default:
		setLabel(ev, "adapter_unmapped", "1")
	}
	if t.Host != "" || t.URL != "" {
		ev.Target = t
	}
	return []*event.Event{ev}
}

// bareURL returns a URL without userinfo, query and fragment: the parts that
// carry credentials and tokens. A value that does not parse as an absolute
// URL is reduced to nothing rather than passed through.
func bareURL(raw string) string {
	clean, host := toolmap.CleanURL(raw)
	if clean == "" || host == "" {
		return ""
	}
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	return clean
}

// hostToken accepts a DNS name: lower-cased, bounded, letters, digits, dots
// and hyphens (and underscores, which occur in the wild). Anything else is
// rejected rather than repaired.
func hostToken(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > 253 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return ""
		}
	}
	return s
}

func isHex(s string) bool {
	if len(s) < 32 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
