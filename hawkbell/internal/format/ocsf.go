package format

import (
	"fmt"
	"sync/atomic"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// OCSFVersion is the schema version the mapping targets (metadata.version).
// 1.9.0 is the first release with the ai_agent object; the MCP specific
// ai_capability object only exists on the 1.10 development branch, so MCP
// details stay under unmapped.hawkbell.
const OCSFVersion = "1.9.0"

// Framework versions stamped on finding_info.attacks[]. Rule tags carry only
// technique ids, so these name the matrices the built-in rules were written
// against (research/standards.md: ATT&CK v20.1, ATLAS content 2026.10).
const (
	AttackVersion = "ATT&CK v20.1"
	AtlasVersion  = "ATLAS 2026.10"
)

const (
	productName = "hawkbell"
	vendorName  = "hawkbell"
)

var productVersion atomic.Pointer[string]

// SetProductVersion records the sensor version emitted as
// metadata.product.version. OCSF has no version parameter because it is
// called per event on the hot path; the binary sets this once at start.
func SetProductVersion(v string) { productVersion.Store(&v) }

// ocsfClass is one row of the type-to-class table.
type ocsfClass struct {
	uid     int
	name    string
	catUID  int
	catName string
}

var (
	clsBase       = ocsfClass{0, "Base Event", 0, "Uncategorized"}
	clsFile       = ocsfClass{1001, "File System Activity", 1, "System Activity"}
	clsProcess    = ocsfClass{1007, "Process Activity", 1, "System Activity"}
	clsCompliance = ocsfClass{2003, "Compliance Finding", 2, "Findings"}
	clsDetection  = ocsfClass{2004, "Detection Finding", 2, "Findings"}
	clsNetwork    = ocsfClass{4001, "Network Activity", 4, "Network Activity"}
	clsHTTP       = ocsfClass{4002, "HTTP Activity", 4, "Network Activity"}
	clsSoftware   = ocsfClass{5020, "Software Inventory Info", 5, "Discovery"}
	clsLifecycle  = ocsfClass{6002, "Application Lifecycle", 6, "Application Activity"}
	clsAPI        = ocsfClass{6003, "API Activity", 6, "Application Activity"}
)

var severityCaption = [...]string{"Unknown", "Informational", "Low", "Medium", "High", "Critical"}

// OCSF maps an event to an OCSF 1.9.0 event object.
//
// Class selection:
//
//	detection.finding                      Detection Finding 2004 / Create
//	posture.check                          Compliance Finding 2003 / Create
//	inventory.asset                        Software Inventory Info 5020 / Collect
//	tool.pre|post shell, process.exec,
//	agent.process.start|stop               Process Activity 1007 / Launch, Terminate
//	tool.pre|post file_read|write|edit|list File System Activity 1001 / Read, Create, Update, Other
//	tool.pre|post web_fetch|browser + URL  HTTP Activity 4002 / Get
//	tool.pre|post other web                Network Activity 4001 / Open
//	tool.pre|post mcp                      API Activity 6003 / Other
//	session.start|end                      Application Lifecycle 6002 / Start, Stop
//	everything else                        Base Event 0 / Other
//
// When a class's required object cannot be built from the event (a file tool
// call without a path, for example) the event falls back to Base Event rather
// than emitting an invalid record. Every result has metadata.product,
// metadata.version, time in epoch milliseconds, severity_id, and the complete
// native event under unmapped.hawkbell.
//
// OCSF never panics and never returns nil: on an internal error it returns a
// minimal Base Event that names the error under unmapped.hawkbell_error.
func OCSF(e *event.Event) (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			out = ocsfFailure(e, fmt.Sprint(r))
		}
	}()
	if e == nil {
		return ocsfFailure(nil, ErrNilEvent.Error())
	}
	b := &ocsfBuilder{e: e, m: make(map[string]any, 24), profiles: []string{"host"}}
	switch {
	case e.Kind == event.KindDetection && e.Detection != nil:
		b.detection()
	case e.Kind == event.KindPosture && e.Check != nil:
		b.compliance()
	case e.Kind == event.KindInventory && e.Asset != nil:
		b.inventory()
	case e.Kind == event.KindActivity:
		b.activity()
	default:
		b.base()
	}
	b.finish()
	return b.m
}

// ocsfFailure is the last-resort record. It reads only scalar fields so it
// cannot fail the same way the full mapping did.
func ocsfFailure(e *event.Event, reason string) map[string]any {
	m := map[string]any{
		"class_uid": clsBase.uid, "class_name": clsBase.name,
		"category_uid": clsBase.catUID, "category_name": clsBase.catName,
		"activity_id": 99, "activity_name": "Other", "type_uid": 99,
		"severity_id": 0, "severity": severityCaption[0], "time": int64(0),
		"metadata": map[string]any{"version": OCSFVersion, "product": productObj()},
	}
	un := map[string]any{"hawkbell_error": reason}
	if e != nil {
		m["time"] = epochMillis(e.TS)
		m["metadata"].(map[string]any)["uid"] = e.ID
		un["hawkbell"] = map[string]any{"id": e.ID, "kind": string(e.Kind), "type": e.Type}
	}
	m["unmapped"] = un
	return m
}

type ocsfBuilder struct {
	e        *event.Event
	m        map[string]any
	profiles []string
}

func (b *ocsfBuilder) profile(name string) {
	b.profiles = appendUnique(b.profiles, name)
}

// head writes the classification attributes. type_uid is class_uid*100 +
// activity_id by definition.
func (b *ocsfBuilder) head(c ocsfClass, activityID int, activityName string) {
	b.m["class_uid"] = c.uid
	b.m["class_name"] = c.name
	b.m["category_uid"] = c.catUID
	b.m["category_name"] = c.catName
	b.m["activity_id"] = activityID
	b.m["activity_name"] = activityName
	b.m["type_uid"] = c.uid*100 + activityID
	b.m["type_name"] = c.name + ": " + activityName
}

// finish adds what every class shares: time, severity, device, metadata and
// the native event.
func (b *ocsfBuilder) finish() {
	e := b.e
	b.m["time"] = epochMillis(e.TS)
	sev := SeverityID(e)
	b.m["severity_id"] = sev
	b.m["severity"] = severityCaption[sev]
	b.m["device"] = b.device()

	md := map[string]any{
		"version":    OCSFVersion,
		"product":    productObj(),
		"event_code": e.Type,
		"log_name":   productName + "." + e.Kind.Stream(),
	}
	if e.ID != "" {
		md["uid"] = e.ID
	}
	if e.Seq != 0 {
		md["sequence"] = e.Seq
	}
	if e.Session != nil && e.Session.ID != "" {
		md["correlation_uid"] = e.Session.ID
	}
	if len(e.Truncated) > 0 {
		md["is_truncated"] = true
	}
	md["profiles"] = stringsToAny(b.profiles)
	b.m["metadata"] = md

	un := map[string]any{}
	if native, err := Native(e); err == nil {
		un["hawkbell"] = native
	} else {
		un["hawkbell"] = map[string]any{"id": e.ID, "kind": string(e.Kind), "type": e.Type}
		un["hawkbell_error"] = err.Error()
	}
	b.m["unmapped"] = un
}

func productObj() map[string]any {
	p := map[string]any{"name": productName, "vendor_name": vendorName}
	if v := productVersion.Load(); v != nil && *v != "" {
		p["version"] = *v
	}
	return p
}

// base is the fallback class. It still carries actor and outcome so a SIEM
// can pivot on user and agent without understanding unmapped.hawkbell.
func (b *ocsfBuilder) base() {
	b.head(clsBase, 99, "Other")
	if a := b.actor(false); a != nil {
		b.m["actor"] = a
	}
	b.status()
	b.m["message"] = b.activityMessage()
}

// activity dispatches tool calls and process events to their class.
func (b *ocsfBuilder) activity() {
	e := b.e
	switch e.Type {
	case event.TypeProcessExec, event.TypeAgentProcessStart, event.TypeAgentProcessStop:
		if e.Process != nil {
			b.processEvent()
			return
		}
	case event.TypeSessionStart, event.TypeSessionEnd:
		if e.Agent != nil && (e.Agent.ID != "" || e.Agent.Name != "") {
			b.lifecycle()
			return
		}
	case event.TypeToolPre, event.TypeToolPost:
		if e.Tool != nil && b.toolCall() {
			return
		}
	}
	b.base()
}

// toolCall maps one tool call; it reports false when the class's required
// object is missing so the caller can fall back to Base Event.
func (b *ocsfBuilder) toolCall() bool {
	e := b.e
	switch e.Tool.Kind {
	case event.ToolShell:
		b.shellCall()
		return true
	case event.ToolFileRead, event.ToolFileWrite, event.ToolFileEdit, event.ToolFileList:
		return b.fileCall()
	case event.ToolWebFetch, event.ToolWebSearch, event.ToolBrowser:
		return b.webCall()
	case event.ToolMCP:
		b.mcpCall()
		return true
	}
	return false
}

func (b *ocsfBuilder) activityMessage() string {
	e := b.e
	msg := e.Type
	if e.Agent != nil {
		if n := firstNonEmpty(e.Agent.ID, e.Agent.Name); n != "" {
			msg = n + " " + msg
		}
	}
	if e.Tool != nil && e.Tool.Name != "" {
		msg += " " + e.Tool.Name
	}
	if e.Health != nil && e.Health.Reason != "" {
		msg += " " + e.Health.Reason
	}
	return clip(msg, 256)
}

// status maps Outcome onto the base status attributes and, when a permission
// decision was observed, onto the security_control profile. Finding classes
// do not call it: their status_id enumerates the finding lifecycle instead.
func (b *ocsfBuilder) status() {
	o := b.e.Outcome
	if o == nil {
		return
	}
	switch o.Status {
	case "ok":
		b.m["status_id"], b.m["status"] = 1, "Success"
	case "error":
		b.m["status_id"], b.m["status"] = 2, "Failure"
	case "denied":
		b.m["status_id"], b.m["status"] = 2, "Failure"
		b.m["status_detail"] = "denied"
	case "interrupted":
		b.m["status_id"], b.m["status"] = 99, "Interrupted"
	case "unknown":
		b.m["status_id"], b.m["status"] = 0, "Unknown"
	}
	if o.Error != "" {
		b.m["status_detail"] = o.Error
	}
	if o.DurationMS > 0 {
		b.m["duration"] = o.DurationMS
	}
	switch o.Decision {
	case "allow":
		b.m["action_id"], b.m["action"] = 1, "Allowed"
		b.profile("security_control")
	case "deny":
		b.m["action_id"], b.m["action"] = 2, "Denied"
		b.profile("security_control")
	}
}
