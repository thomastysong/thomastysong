package format

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// maxRelated caps finding_info.related_events and similar lists so a long
// sequence match cannot inflate the mapped half of the record; the full list
// is still under unmapped.hawkbell.
const maxRelated = 64

// processObj builds an OCSF process from an observed OS process.
func (b *ocsfBuilder) processObj(p *event.Process) map[string]any {
	m := map[string]any{}
	if p.PID > 0 {
		m["pid"] = p.PID
	}
	setStr(m, "name", firstNonEmpty(p.Name, baseName(p.Exe)))
	if p.Exe != "" {
		m["file"] = fileObj(p.Exe, 1, "Regular File")
	}
	if len(p.Args) > 0 {
		m["cmd_line"] = strings.Join(p.Args, " ")
	}
	if !p.StartTime.IsZero() {
		m["created_time"] = epochMillis(p.StartTime)
	}
	if u := userObj(p.User, ""); u != nil {
		m["user"] = u
	}
	if pp := parentObj(p); pp != nil {
		m["parent_process"] = pp
	}
	return m
}

func parentObj(p *event.Process) map[string]any {
	if p.PPID <= 0 {
		return nil
	}
	pp := map[string]any{"pid": p.PPID}
	if len(p.Ancestors) > 0 {
		setStr(pp, "name", p.Ancestors[0])
	}
	return pp
}

// ensureProcessID gives a process without a pid a producer-assigned uid:
// OCSF requires one of pid, uid or cpid, and a hook reports the command
// before any process exists.
func (b *ocsfBuilder) ensureProcessID(p map[string]any) {
	if _, ok := p["pid"]; ok {
		return
	}
	id := b.e.ID
	if b.e.Tool != nil && b.e.Tool.UseID != "" {
		id = b.e.Tool.UseID
	}
	setStr(p, "uid", firstNonEmpty(id, "unknown"))
}

// shellCall: the agent asked for a command to run. The process is the
// command, the actor is the agent.
func (b *ocsfBuilder) shellCall() {
	e := b.e
	b.head(clsProcess, 1, "Launch")
	p := map[string]any{}
	if e.Process != nil {
		p = b.processObj(e.Process)
	}
	if e.Target != nil && e.Target.Command != "" {
		p["cmd_line"] = e.Target.Command
	}
	if e.Session != nil {
		setStr(p, "working_directory", e.Session.CWD)
	}
	b.ensureProcessID(p)
	b.m["process"] = p
	if e.Outcome != nil && e.Outcome.ExitCode != nil {
		b.m["exit_code"] = *e.Outcome.ExitCode
	}
	b.m["actor"] = b.actor(true)
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
}

// processEvent: an OS process observed by the process monitor.
func (b *ocsfBuilder) processEvent() {
	e := b.e
	if e.Type == event.TypeAgentProcessStop {
		b.head(clsProcess, 2, "Terminate")
	} else {
		b.head(clsProcess, 1, "Launch")
	}
	p := b.processObj(e.Process)
	if e.Session != nil {
		setStr(p, "working_directory", e.Session.CWD)
	}
	b.ensureProcessID(p)
	b.m["process"] = p

	var a map[string]any
	if e.Type == event.TypeProcessExec {
		// A child of the agent: the agent is the actor.
		a = b.actor(true)
		if _, ok := a["process"]; !ok {
			if pp := parentObj(e.Process); pp != nil {
				a["process"] = pp
			}
		}
	} else {
		// The agent process itself: the actor is whoever started it.
		a = map[string]any{}
		if u := b.eventUser(); u != nil {
			a["user"] = u
		}
		if pp := parentObj(e.Process); pp != nil {
			a["process"] = pp
		}
		if len(a) == 0 {
			a["app_name"] = "unknown"
		}
	}
	b.m["actor"] = a
	if e.Outcome != nil && e.Outcome.ExitCode != nil {
		b.m["exit_code"] = *e.Outcome.ExitCode
	}
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
}

// fileCall maps a file tool call. A listing may target a file, a directory
// or a glob, so its file type stays Unknown and its activity is Other.
func (b *ocsfBuilder) fileCall() bool {
	e := b.e
	path := ""
	if e.Target != nil {
		path = e.Target.Path
		if path == "" && len(e.Target.Paths) > 0 {
			path = e.Target.Paths[0]
		}
	}
	if path == "" {
		return false
	}
	typeID, typeName := 1, "Regular File"
	switch e.Tool.Kind {
	case event.ToolFileRead:
		b.head(clsFile, 2, "Read")
	case event.ToolFileWrite:
		b.head(clsFile, 1, "Create")
	case event.ToolFileEdit:
		b.head(clsFile, 3, "Update")
	default:
		b.head(clsFile, 99, "List")
		typeID, typeName = 0, "Unknown"
	}
	b.m["file"] = fileObj(path, typeID, typeName)
	b.m["actor"] = b.actor(true)
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
	return true
}

// webCall maps web tools. A fetch or browser navigation with a URL is HTTP
// Activity with method GET (what fetch tools issue; the hook does not report
// a method). Anything else, such as a search with only a query, is Network
// Activity from this endpoint.
func (b *ocsfBuilder) webCall() bool {
	e := b.e
	t := e.Target
	host, port := targetHost(t)
	if e.Tool.Kind != event.ToolWebSearch && t != nil && t.URL != "" {
		b.head(clsHTTP, 3, "Get")
		b.m["http_request"] = map[string]any{"http_method": "GET", "url": urlObj(t.URL)}
	} else {
		if e.Tool.Kind == event.ToolBrowser && host == "" {
			return false
		}
		b.head(clsNetwork, 1, "Open")
	}
	if ep := endpointObj(host, port); ep != nil {
		b.m["dst_endpoint"] = ep
	}
	b.m["src_endpoint"] = b.srcEndpoint()
	if a := b.actor(false); a != nil {
		b.m["actor"] = a
	}
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
	return true
}

// mcpCall maps an MCP tool call to API Activity: the server is the service,
// the tool is the operation, the agent's tool-call id is the request id.
func (b *ocsfBuilder) mcpCall() {
	e := b.e
	b.head(clsAPI, 99, "Other")
	api := map[string]any{"operation": firstNonEmpty(e.Tool.MCPTool, e.Tool.Name, "tools/call")}
	if e.Tool.MCPServer != "" {
		api["service"] = map[string]any{"name": e.Tool.MCPServer}
	}
	if e.Tool.UseID != "" {
		api["request"] = map[string]any{"uid": e.Tool.UseID}
	}
	if e.Outcome != nil && e.Outcome.Error != "" {
		api["response"] = map[string]any{"error_message": e.Outcome.Error}
	}
	b.m["api"] = api
	b.m["actor"] = b.actor(true)
	b.m["src_endpoint"] = b.srcEndpoint()
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
}

// lifecycle maps session start and end to the agent application starting
// and stopping.
func (b *ocsfBuilder) lifecycle() {
	e := b.e
	if e.Type == event.TypeSessionEnd {
		b.head(clsLifecycle, 4, "Stop")
	} else {
		b.head(clsLifecycle, 3, "Start")
	}
	app := map[string]any{}
	setStr(app, "uid", e.Agent.ID)
	setStr(app, "name", firstNonEmpty(e.Agent.Name, e.Agent.ID))
	setStr(app, "version", e.Agent.Version)
	b.m["application"] = app
	if a := b.actor(false); a != nil {
		b.m["actor"] = a
	}
	b.withAIAgent()
	b.status()
	b.m["message"] = b.activityMessage()
}

// detection maps a rule match to Detection Finding.
func (b *ocsfBuilder) detection() {
	e, d := b.e, b.e.Detection
	b.head(clsDetection, 1, "Create")
	b.m["status_id"], b.m["status"] = 1, "New"
	b.m["is_alert"] = true
	b.m["message"] = clip(firstNonEmpty(d.Title, d.RuleID), 512)
	switch d.Confidence {
	case "low":
		b.m["confidence_id"], b.m["confidence"] = 1, "Low"
	case "medium":
		b.m["confidence_id"], b.m["confidence"] = 2, "Medium"
	case "high":
		b.m["confidence_id"], b.m["confidence"] = 3, "High"
	}
	// Only a decision hawkbell actually returned to the agent counts as an
	// action; a rule that merely asks for "block" in observe mode did not
	// stop anything and must not read as if it had.
	switch {
	case d.Enforced && d.Response == "block":
		b.m["action_id"], b.m["action"] = 2, "Denied"
		b.m["disposition_id"], b.m["disposition"] = 2, "Blocked"
	case d.Enforced && d.Response == "ask":
		b.m["action_id"], b.m["action"] = 3, "Observed"
		b.m["disposition_id"], b.m["disposition"] = 23, "Challenge"
	default:
		b.m["action_id"], b.m["action"] = 3, "Observed"
		b.m["disposition_id"], b.m["disposition"] = 15, "Detected"
	}
	b.profile("security_control")
	if d.Count > 1 {
		b.m["count"] = d.Count
	}

	analytic := map[string]any{"type_id": 1, "type": "Rule"}
	setStr(analytic, "uid", d.RuleID)
	setStr(analytic, "name", firstNonEmpty(d.Title, d.RuleID))
	setStr(analytic, "category", d.Category)
	switch d.Maturity {
	case "experimental":
		analytic["state_id"], analytic["state"] = 3, "Experimental"
	case "stable":
		analytic["state_id"], analytic["state"] = 1, "Active"
	}
	// A dedup key is stable across repeats of the same finding, which is
	// what lets a SIEM upsert instead of piling up rows.
	fi := map[string]any{
		"uid":      firstNonEmpty(d.DedupKey, e.ID, d.RuleID, "unknown"),
		"title":    firstNonEmpty(d.Title, d.RuleID),
		"analytic": analytic,
	}
	if ms := epochMillis(e.TS); ms != 0 {
		fi["created_time"] = ms
	}
	attacks, types := attacksFromTags(d.Tags)
	if len(attacks) > 0 {
		fi["attacks"] = attacks
	}
	if len(types) > 0 {
		fi["types"] = stringsToAny(types)
	}
	if len(e.Sources) > 0 {
		src := make([]any, 0, len(e.Sources))
		for _, s := range e.Sources {
			src = append(src, string(s))
		}
		fi["data_sources"] = src
	}
	if n := len(d.EventIDs); n > 0 {
		ids := d.EventIDs
		if n > maxRelated {
			ids = ids[n-maxRelated:]
		}
		rel := make([]any, 0, len(ids))
		for _, id := range ids {
			rel = append(rel, map[string]any{"uid": id})
		}
		fi["related_events"] = rel
		fi["related_events_count"] = n
	}
	b.m["finding_info"] = fi

	if ev := b.evidence(); ev != nil {
		b.m["evidences"] = []any{ev}
	}
	if d.Remedy != "" {
		b.m["remediation"] = map[string]any{"desc": d.Remedy}
	}
}

// evidence builds the single evidences[] entry from what the detection
// event carries. In 1.9.0 an entry with only ai_agent fails the object's
// at_least_one constraint, so nil is returned unless something else exists.
func (b *ocsfBuilder) evidence() map[string]any {
	e, d := b.e, b.e.Detection
	ev := map[string]any{}
	if len(d.Evidence) > 0 {
		data := make(map[string]any, len(d.Evidence))
		for k, v := range d.Evidence {
			data[k] = v
		}
		ev["data"] = data
	}
	var proc map[string]any
	if e.Process != nil {
		proc = b.processObj(e.Process)
	}
	if t := e.Target; t != nil {
		if t.Command != "" {
			if proc == nil {
				proc = map[string]any{}
			}
			proc["cmd_line"] = t.Command
		}
		if t.Path != "" {
			ev["file"] = fileObj(t.Path, 0, "Unknown")
		}
		if t.URL != "" {
			ev["url"] = urlObj(t.URL)
		} else if host, port := targetHost(t); host != "" {
			ev["dst_endpoint"] = endpointObj(host, port)
		}
	}
	if proc != nil {
		b.ensureProcessID(proc)
		ev["process"] = proc
	}
	if a := b.actor(false); a != nil {
		ev["actor"] = a
	}
	if len(ev) == 0 {
		return nil
	}
	ev["name"] = "match"
	if ai := b.aiAgent(); ai != nil {
		ev["ai_agent"] = ai
	}
	return ev
}

// compliance maps a posture check to Compliance Finding.
func (b *ocsfBuilder) compliance() {
	e, c := b.e, b.e.Check
	b.head(clsCompliance, 1, "Create")
	b.m["status_id"], b.m["status"] = 1, "New"
	title := firstNonEmpty(c.Title, c.ID)
	b.m["message"] = clip(title+": "+firstNonEmpty(c.Status, "unknown"), 512)

	statusID, status := 0, "Unknown"
	switch c.Status {
	case "pass":
		statusID, status = 1, "Pass"
	case "fail":
		statusID, status = 3, "Fail"
	}
	comp := map[string]any{"status_id": statusID, "status": status}
	setStr(comp, "control", c.ID)
	var detail []string
	if c.Expected != "" {
		detail = append(detail, "expected: "+c.Expected)
	}
	if c.Actual != "" {
		detail = append(detail, "actual: "+c.Actual)
	}
	if len(detail) > 0 {
		comp["status_detail"] = strings.Join(detail, "; ")
	}
	chk := map[string]any{"status_id": statusID, "status": status}
	setStr(chk, "uid", c.ID)
	setStr(chk, "name", c.Title)
	if r := event.SeverityRank(c.Severity); r > 0 {
		chk["severity_id"], chk["severity"] = r, severityCaption[r]
	}
	comp["checks"] = []any{chk}
	b.m["compliance"] = comp

	// The finding uid is stable for one (check, subject) on one device so a
	// later pass replaces an earlier fail. The subject is hashed: it is a
	// path or setting name taken from the endpoint, not an identifier.
	h := sha256.Sum256([]byte(strings.Join([]string{c.ID, c.AgentID, c.AssetID, string(c.Scope), c.Subject, c.Owner}, "\x00")))
	analytic := map[string]any{"type_id": 1, "type": "Rule"}
	setStr(analytic, "uid", c.ID)
	setStr(analytic, "name", title)
	fi := map[string]any{
		"uid":      firstNonEmpty(c.ID, "check") + "/" + hex.EncodeToString(h[:8]),
		"title":    title,
		"analytic": analytic,
	}
	if ms := epochMillis(e.TS); ms != 0 {
		fi["created_time"] = ms
	}
	b.m["finding_info"] = fi

	if c.Subject != "" || c.AssetID != "" {
		res := map[string]any{}
		setStr(res, "uid", c.AssetID)
		setStr(res, "name", c.Subject)
		setStr(res, "type", string(c.Scope))
		if u := userObj(c.Owner, ""); u != nil {
			res["owner"] = u
		}
		b.m["resources"] = []any{res}
	}
	if c.Remedy != "" {
		b.m["remediation"] = map[string]any{"desc": c.Remedy}
	}
	if a := b.actor(false); a != nil {
		b.m["actor"] = a
	}
}

// inventory maps an asset to Software Inventory Info. The deprecated
// top-level package attribute is not emitted; sbom.package is its successor.
// package.version is required by the schema, so an unknown version is the
// literal "unknown" rather than an empty string.
func (b *ocsfBuilder) inventory() {
	a := b.e.Asset
	b.head(clsSoftware, 2, "Collect")
	msg := string(a.Kind) + " " + a.Name
	if a.Change != "" {
		msg += " (" + string(a.Change) + ")"
	}
	b.m["message"] = clip(msg, 512)

	pkg := map[string]any{"name": firstNonEmpty(a.Name, "unknown"), "version": firstNonEmpty(a.Version, "unknown")}
	if m := a.MCP; m != nil && m.Package != "" {
		// For a declared MCP server the thing worth hunting across a fleet
		// is the package it launches, not the local nickname.
		pkg["name"] = m.Package
		pkg["version"] = firstNonEmpty(m.Version, a.Version, "unknown")
		setStr(pkg, "package_manager", m.Ecosystem)
		setStr(pkg, "purl", purl(m.Ecosystem, m.Package, m.Version))
	}
	setStr(pkg, "uid", a.ID)
	setStr(pkg, "vendor_name", a.Vendor)
	switch a.Kind {
	case event.AssetAgent, event.AssetApp, event.AssetBrowser, event.AssetModelRuntime:
		pkg["type_id"], pkg["type"] = 1, "Application"
	}
	if isHex(a.SHA256, 64) {
		pkg["hash"] = map[string]any{"algorithm_id": 3, "algorithm": "SHA-256", "value": strings.ToLower(a.SHA256)}
	}
	b.m["sbom"] = map[string]any{"package": pkg, "software_components": []any{}}

	actor := map[string]any{}
	if u := userObj(a.Owner, ""); u != nil {
		actor["user"] = u
	} else if u := b.eventUser(); u != nil {
		actor["user"] = u
	}
	if len(actor) > 0 {
		b.m["actor"] = actor
	}
}

func isHex(s string, n int) bool {
	if len(s) != n {
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

// purl builds a package URL for the two ecosystems whose rules are simple
// enough to get right without a library. Names come from agent config files,
// so anything outside the registries' own character sets yields no purl
// instead of a malformed one.
func purl(ecosystem, name, version string) string {
	if name == "" || version == "" || !purlSafe(version) {
		return ""
	}
	switch ecosystem {
	case "npm":
		scope, pkg := "", name
		if strings.HasPrefix(name, "@") {
			i := strings.IndexByte(name, '/')
			if i < 2 || i == len(name)-1 {
				return ""
			}
			scope, pkg = name[1:i], name[i+1:]
			if !purlSafe(scope) {
				return ""
			}
		}
		if !purlSafe(pkg) {
			return ""
		}
		if scope != "" {
			return "pkg:npm/%40" + strings.ToLower(scope) + "/" + strings.ToLower(pkg) + "@" + version
		}
		return "pkg:npm/" + strings.ToLower(pkg) + "@" + version
	case "pypi":
		if !purlSafe(name) {
			return ""
		}
		// The purl spec normalizes PyPI names: lower case, "_" becomes "-".
		return "pkg:pypi/" + strings.ReplaceAll(strings.ToLower(name), "_", "-") + "@" + version
	}
	return ""
}

// purlSafe accepts only characters that need no percent-encoding in a purl.
func purlSafe(s string) bool {
	if s == "" || len(s) > 214 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '~':
		default:
			return false
		}
	}
	return true
}
