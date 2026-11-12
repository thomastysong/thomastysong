package privacy

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Detection evidence.
//
// A rule names the fields it wants as evidence. Without a limit, a rule
// pack (which can be updated through a signed bundle) becomes a covert
// content search: "match anything, evidence: [prompt.text]" would ship
// every prompt in the default profile. Evidence is therefore copied only
// from a fixed allowlist of non-content fields: the redacted command,
// paths, hosts, classes, counts, names and ids. Prompt text, tool input
// and tool output can never be evidence in minimal or standard, whatever a
// rule asks for; in full they are redacted and capped. A field that was
// asked for but is not allowed is reported as "[WITHHELD]" so the rule's
// request is visible to whoever reviews the finding.

// Withheld is the evidence value for a field the policy refuses to copy.
const Withheld = "[WITHHELD]"

const maxEvidenceFields = 32

// evMode is how an allowed evidence value is redacted.
type evMode uint8

const (
	evName    evMode = iota // identifiers, names, enums: pattern pass only
	evPath                  // paths: pattern pass, home-relative
	evCommand               // structural command redaction
	evURL                   // URL without query (with query in full)
	evArgs                  // argument vector
	evValue                 // structured value (NAME=value, flags)
	evCount                 // number; bucketed outside full
	evContent               // prompt / tool content: full profile only
)

// evidenceFields is the allowlist of event fields by their JSON names.
var evidenceFields = map[string]evMode{
	"id": evName, "type": evName, "kind": evName, "source": evName, "fidelity": evName, "integrity": evName,
	"host.id": evName, "host.name": evName, "host.os": evName, "host.arch": evName,
	"user.name": evName, "user.id": evName,
	"agent.id": evName, "agent.name": evName, "agent.version": evName, "agent.surface": evName, "agent.pid": evName,
	"account.kind": evName, "account.org": evName,
	"session.id": evName, "session.parent_id": evName, "session.turn_id": evName, "session.permission_mode": evName,
	"session.model": evName, "session.subagent_id": evName, "session.subagent_type": evName, "session.cwd": evPath,
	"tool.name": evName, "tool.kind": evName, "tool.use_id": evName, "tool.mcp_server": evName, "tool.mcp_tool": evName,
	"tool.input_keys": evName, "tool.output_len": evCount,
	"target.command": evCommand, "target.path": evPath, "target.paths": evPath, "target.url": evURL,
	"target.host": evName, "target.hosts": evName,
	"prompt.len":     evCount,
	"outcome.status": evName, "outcome.exit_code": evName, "outcome.decision": evName, "outcome.decision_source": evName,
	"outcome.duration_ms": evName,
	"process.pid":         evName, "process.ppid": evName, "process.name": evName, "process.exe": evPath, "process.args": evArgs,
	"process.user": evName, "process.ancestors": evName, "process.env_markers": evName, "process.flags": evName,
	"container.id": evName, "container.runtime": evName, "container.image": evName, "container.name": evName,
	"container.pod": evName, "container.namespace": evName,
	"repo.root": evPath, "repo.remote": evURL, "repo.branch": evValue,
	"asset.id": evName, "asset.kind": evName, "asset.name": evName, "asset.vendor": evName, "asset.version": evName,
	"asset.catalog_id": evName, "asset.parent": evName, "asset.path": evPath, "asset.scope": evName, "asset.owner": evName,
	"asset.risk_flags": evName, "asset.change": evName, "asset.confidence": evName, "asset.signer": evName,
	"asset.mcp.transport": evName, "asset.mcp.command": evPath, "asset.mcp.args": evArgs, "asset.mcp.runner": evName,
	"asset.mcp.ecosystem": evName, "asset.mcp.package": evValue, "asset.mcp.version": evName, "asset.mcp.pinned": evName,
	"asset.mcp.url_host": evName, "asset.mcp.env_keys": evName, "asset.mcp.header_keys": evName,
	"asset.mcp.has_inline_secret": evName, "asset.mcp.auth_mode": evName,
	"check.id": evName, "check.status": evName, "check.severity": evName, "check.agent_id": evName, "check.scope": evName,
	"check.subject": evValue, "check.expected": evValue, "check.actual": evValue,
	// Content: full profile only.
	"prompt.text": evContent, "tool.input": evContent, "tool.output": evContent, "target.query": evContent,
	"content.prompt_text": evContent, "content.tool_input": evContent, "content.tool_output": evContent,
	"content.file_content": evContent,
}

// featureFields are computed features whose string values are closed
// vocabularies, names, paths or hosts (never free text). Boolean and
// numeric features are always allowed.
var featureFields = map[string]evMode{
	"shell.commands": evName, "shell.urls": evURL, "shell.hosts": evName, "shell.host_classes": evName,
	"shell.reads": evPath, "shell.writes": evPath, "shell.deletes": evPath, "shell.read_classes": evName,
	"shell.write_classes": evName, "shell.delete_classes": evName, "shell.interpreters": evName,
	"shell.obfuscation": evName, "shell.destructive": evName, "shell.persistence": evName,
	"shell.defense_evasion": evName, "shell.cred_access": evName, "shell.exfil": evName, "shell.net_tools": evName,
	"shell.recon": evName, "shell.privilege": evName, "shell.git_ops": evName, "shell.installs": evValue,
	"shell.install_sources": evURL, "shell.env_assign": evName, "shell.secret_kinds": evName,
	"shell.opaque": evName, "shell.executes_paths": evPath,
	"path.classes": evName, "path.ext": evName,
	"net.host": evName, "net.host_classes": evName, "net.scheme": evName,
	"prompt.secret_kinds": evName, "prompt.markers": evName,
	"write.secret_kinds": evName, "write.markers": evName, "write.exec_keys": evName,
	"output.markers": evName, "output.secret_kinds": evName,
	"mcp.server": evName, "mcp.tool": evName, "mcp.arg_paths": evPath, "mcp.arg_path_classes": evName,
	"mcp.arg_hosts": evName, "mcp.arg_host_classes": evName, "mcp.arg_secret_kinds": evName,
	"session.flags": evName, "session.written_exec_path": evPath,
	"flow.secret_kinds": evName, "host.tags": evName,
}

// allowedEvidence returns the redaction mode for a field name, and whether
// it may be copied at all under level lv.
func allowedEvidence(name string, lv level) (evMode, bool) {
	if m, ok := evidenceFields[name]; ok {
		return m, m != evContent || lv == levelFull
	}
	if strings.HasPrefix(name, "tool.input.") || strings.HasPrefix(name, "content.tool_input.") {
		return evContent, lv == levelFull
	}
	if m, ok := featureFields[name]; ok {
		return m, true
	}
	// Closed-vocabulary feature families.
	for _, suf := range []string{"_classes", "_kinds", ".classes", ".kinds", ".markers", "_markers"} {
		if strings.HasSuffix(name, suf) {
			return evName, true
		}
	}
	return 0, false
}

// Evidence returns redacted, capped values of the requested fields of src
// for Detection.Evidence. Fields outside the allowlist are reported as
// Withheld; fields src does not have are omitted. Values are rendered as
// text: lists as JSON arrays, booleans and numbers in Go syntax.
func (p *Policy) Evidence(src *event.Event, fields []string) (ev map[string]string) {
	if src == nil || len(fields) == 0 {
		return nil
	}
	defer func() {
		if recover() != nil {
			ev = map[string]string{"_error": Withheld}
		}
	}()
	s := p.settings()
	lv := levelStandard
	if s.profile == ProfileFull {
		lv = levelFull
	}
	r := &run{p: p, s: s, lv: lv, src: src, goos: eventOS(src), user: actingUser(src)}
	var others func(string) string
	if s.pseudo && s.key != nil {
		others = p.Pseudonym
	}
	r.home = newHomeRewriter(p.homeOf(r.user, r.goos), r.goos, others)
	ev = map[string]string{}
	for _, f := range fields {
		if len(ev) >= maxEvidenceFields {
			break
		}
		f = strings.TrimSpace(f)
		if f == "" || len(f) > 128 {
			continue
		}
		if _, dup := ev[f]; dup {
			continue
		}
		mode, ok := allowedEvidence(f, lv)
		if !ok {
			// Unknown fields and content outside full: refuse, visibly.
			if isBoolOrNumberFeature(src, f) {
				v, _ := renderScalar(src.Feat[f])
				ev[f] = v
				continue
			}
			ev[f] = Withheld
			continue
		}
		raw, present := r.evidenceValue(src, f, mode)
		if !present {
			continue
		}
		ev[f] = raw
	}
	if len(ev) == 0 {
		return nil
	}
	return ev
}

func isBoolOrNumberFeature(src *event.Event, f string) bool {
	if src.Feat == nil {
		return false
	}
	_, ok := renderScalar(src.Feat[f])
	return ok
}

// renderScalar renders booleans and numbers.
func renderScalar(v any) (string, bool) {
	switch t := v.(type) {
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	}
	return "", false
}

// inputKey recognises tool-input evidence fields and returns the member
// path ("" for the whole input).
func inputKey(f string) (string, bool) {
	for _, p := range []string{"tool.input", "content.tool_input"} {
		if f == p {
			return "", true
		}
		if strings.HasPrefix(f, p+".") {
			return f[len(p)+1:], true
		}
	}
	return "", false
}

func toolInputOf(e *event.Event) map[string]any {
	if e.Content != nil && e.Content.ToolInput != nil {
		return e.Content.ToolInput
	}
	if e.Tool != nil {
		return e.Tool.Input
	}
	return nil
}

// identityFields carry account names; with pseudonyms on they are emitted
// exactly as Emit would emit them.
var identityFields = map[string]bool{"user.name": true, "user.id": true, "process.user": true, "asset.owner": true}

// evidenceValue extracts and redacts one allowed field.
func (r *run) evidenceValue(src *event.Event, f string, mode evMode) (string, bool) {
	var v any
	var ok bool
	if key, isInput := inputKey(f); isInput {
		// Redact the whole input first (shell commands structurally), then
		// pick the member: a member alone loses the structure that says
		// "this string is a command".
		in := toolInputOf(src)
		if in == nil {
			return "", false
		}
		red := r.toolInput(in)
		if key == "" {
			v, ok = red, true
		} else {
			v, ok = lookupAny(red, key)
		}
		if !ok {
			return "", false
		}
		if m, isMap := v.(map[string]any); isMap {
			b, err := json.Marshal(m)
			if err != nil {
				return Withheld, true
			}
			out, _ := cutString(rewriteMarkers(r.home.rewrite(string(b)), r.s.key), r.s.evidCap, true)
			return out, true
		}
		s, _ := v.(string)
		return r.finishStr(s, "detection.evidence."+f, r.s.evidCap, true), true
	}
	if fv, has := eventField(src, f); has {
		v, ok = fv, true
	} else if src.Feat != nil {
		if fv, has := src.Feat[f]; has {
			v, ok = fv, true
		}
	}
	if !ok {
		return "", false
	}
	if identityFields[f] && r.s.pseudo {
		sv, _ := v.(string)
		if sv == "" || r.s.key == nil {
			return "", false
		}
		r.keyed = true
		return r.p.Pseudonym(sv), true
	}
	if sv, isScalar := renderScalar(v); isScalar {
		if mode == evCount {
			if n, err := strconv.Atoi(sv); err == nil {
				return strconv.Itoa(r.length(n)), true
			}
		}
		return sv, true
	}
	name := "detection.evidence." + f
	cap := r.s.evidCap
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", false
		}
		return r.evidenceString(t, name, mode, cap), true
	case []string:
		if len(t) == 0 {
			return "", false
		}
		var items []string
		if mode == evArgs {
			items = r.argsStr(t, name, cap, maxArgs)
		} else {
			items = r.list(t, name, func(s string) string { return r.evidenceString(s, name, mode, cap) })
		}
		b, err := json.Marshal(items)
		if err != nil {
			return Withheld, true
		}
		out, cut := cutString(string(b), cap, true)
		if cut {
			r.note(name)
		}
		return out, true
	case map[string]any:
		if mode != evContent {
			return Withheld, true
		}
		red := r.toolInput(t)
		b, err := json.Marshal(red)
		if err != nil {
			return Withheld, true
		}
		out, _ := cutString(rewriteMarkers(r.home.rewrite(string(b)), r.s.key), cap, true)
		return out, true
	}
	return Withheld, true
}

func (r *run) evidenceString(s, name string, mode evMode, cap int) string {
	switch mode {
	case evCommand:
		return r.commandStr(s, name, cap)
	case evURL:
		return r.urlStr(s, name, r.lv == levelFull, cap)
	case evValue:
		return r.valueStr(s, name, cap)
	case evContent:
		return r.textStr(s, name, cap, true)
	case evArgs:
		return r.argsStr([]string{s}, name, cap, 1)[0]
	}
	return r.textStr(s, name, cap, false)
}

// eventField reads an allowlisted field by its JSON name. Identity fields
// are pseudonymized here exactly as Emit would.
func eventField(e *event.Event, f string) (any, bool) {
	head, rest, _ := strings.Cut(f, ".")
	str := func(s string) (any, bool) { return s, s != "" }
	strs := func(s []string) (any, bool) { return s, len(s) > 0 }
	num := func(n int) (any, bool) { return n, n != 0 }
	switch head {
	case "id":
		return str(e.ID)
	case "type":
		return str(e.Type)
	case "kind":
		return str(string(e.Kind))
	case "source":
		return str(string(e.Source))
	case "fidelity":
		return str(string(e.Fidelity))
	case "integrity":
		return str(string(e.Integrity))
	case "host":
		if h := e.Host; h != nil {
			switch rest {
			case "id":
				return str(h.ID)
			case "name":
				return str(h.Name)
			case "os":
				return str(h.OS)
			case "arch":
				return str(h.Arch)
			}
		}
	case "user":
		if u := e.User; u != nil {
			switch rest {
			case "name":
				return str(u.Name)
			case "id":
				return str(u.ID)
			}
		}
	case "agent":
		if a := e.Agent; a != nil {
			switch rest {
			case "id":
				return str(a.ID)
			case "name":
				return str(a.Name)
			case "version":
				return str(a.Version)
			case "surface":
				return str(a.Surface)
			case "pid":
				return num(a.PID)
			}
		}
	case "account":
		if a := e.Account; a != nil {
			switch rest {
			case "kind":
				return str(a.Kind)
			case "org":
				return str(a.Org)
			}
		}
	case "session":
		if s := e.Session; s != nil {
			switch rest {
			case "id":
				return str(s.ID)
			case "parent_id":
				return str(s.ParentID)
			case "turn_id":
				return str(s.TurnID)
			case "permission_mode":
				return str(s.PermissionMode)
			case "model":
				return str(s.Model)
			case "subagent_id":
				return str(s.SubagentID)
			case "subagent_type":
				return str(s.SubagentType)
			case "cwd":
				return str(s.CWD)
			}
		}
	case "tool":
		return toolField(e, rest)
	case "target":
		if t := e.Target; t != nil {
			switch rest {
			case "command":
				return str(t.Command)
			case "path":
				return str(t.Path)
			case "paths":
				return strs(t.Paths)
			case "url":
				return str(t.URL)
			case "host":
				return str(t.Host)
			case "hosts":
				return strs(t.Hosts)
			case "query":
				return str(t.Query)
			}
		}
	case "prompt":
		if pr := e.Prompt; pr != nil || (e.Content != nil && e.Content.PromptText != "") {
			switch rest {
			case "len":
				if pr != nil && pr.Len > 0 {
					return pr.Len, true
				}
				if e.Content != nil {
					return num(len([]rune(e.Content.PromptText)))
				}
			case "text":
				if e.Content != nil && e.Content.PromptText != "" {
					return e.Content.PromptText, true
				}
				if pr != nil {
					return str(pr.Text)
				}
			}
		}
	case "content":
		if c := e.Content; c != nil {
			switch {
			case rest == "prompt_text":
				return str(c.PromptText)
			case rest == "tool_output":
				return str(c.ToolOutput)
			case rest == "file_content":
				return str(c.FileContent)
			case rest == "tool_input":
				return c.ToolInput, c.ToolInput != nil
			case strings.HasPrefix(rest, "tool_input."):
				return lookupAny(c.ToolInput, strings.TrimPrefix(rest, "tool_input."))
			}
		}
	case "outcome":
		if o := e.Outcome; o != nil {
			switch rest {
			case "status":
				return str(o.Status)
			case "decision":
				return str(o.Decision)
			case "decision_source":
				return str(o.DecisionSource)
			case "duration_ms":
				return int64(o.DurationMS), o.DurationMS != 0
			case "exit_code":
				if o.ExitCode != nil {
					return *o.ExitCode, true
				}
			}
		}
	case "process":
		if p := e.Process; p != nil {
			switch rest {
			case "pid":
				return num(p.PID)
			case "ppid":
				return num(p.PPID)
			case "name":
				return str(p.Name)
			case "exe":
				return str(p.Exe)
			case "args":
				return strs(p.Args)
			case "user":
				return str(p.User)
			case "ancestors":
				return strs(p.Ancestors)
			case "env_markers":
				return strs(p.EnvMarkers)
			case "flags":
				return strs(p.Flags)
			}
		}
	case "container":
		if c := e.Container; c != nil {
			switch rest {
			case "id":
				return str(c.ID)
			case "runtime":
				return str(c.Runtime)
			case "image":
				return str(c.Image)
			case "name":
				return str(c.Name)
			case "pod":
				return str(c.Pod)
			case "namespace":
				return str(c.Namespace)
			}
		}
	case "repo":
		if rp := e.Repo; rp != nil {
			switch rest {
			case "root":
				return str(rp.Root)
			case "remote":
				return str(rp.Remote)
			case "branch":
				return str(rp.Branch)
			}
		}
	case "asset":
		return assetField(e.Asset, rest)
	case "check":
		if c := e.Check; c != nil {
			switch rest {
			case "id":
				return str(c.ID)
			case "status":
				return str(c.Status)
			case "severity":
				return str(c.Severity)
			case "agent_id":
				return str(c.AgentID)
			case "scope":
				return str(string(c.Scope))
			case "subject":
				return str(c.Subject)
			case "expected":
				return str(c.Expected)
			case "actual":
				return str(c.Actual)
			}
		}
	}
	return nil, false
}

func toolField(e *event.Event, rest string) (any, bool) {
	t := e.Tool
	str := func(s string) (any, bool) { return s, s != "" }
	switch {
	case rest == "input":
		if e.Content != nil && e.Content.ToolInput != nil {
			return e.Content.ToolInput, true
		}
		if t != nil && t.Input != nil {
			return t.Input, true
		}
	case strings.HasPrefix(rest, "input."):
		key := strings.TrimPrefix(rest, "input.")
		if e.Content != nil && e.Content.ToolInput != nil {
			return lookupAny(e.Content.ToolInput, key)
		}
		if t != nil {
			return lookupAny(t.Input, key)
		}
	case rest == "output":
		if e.Content != nil && e.Content.ToolOutput != "" {
			return e.Content.ToolOutput, true
		}
		if t != nil {
			return str(t.Output)
		}
	}
	if t == nil {
		return nil, false
	}
	switch rest {
	case "name":
		return str(t.Name)
	case "kind":
		return str(string(t.Kind))
	case "use_id":
		return str(t.UseID)
	case "mcp_server":
		return str(t.MCPServer)
	case "mcp_tool":
		return str(t.MCPTool)
	case "input_keys":
		if len(t.InputKeys) > 0 {
			return t.InputKeys, true
		}
		if e.Content != nil && len(e.Content.ToolInput) > 0 {
			keys := make([]string, 0, len(e.Content.ToolInput))
			for k := range e.Content.ToolInput {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return keys, true
		}
	case "output_len":
		if t.OutputLen > 0 {
			return t.OutputLen, true
		}
	}
	return nil, false
}

func assetField(a *event.Asset, rest string) (any, bool) {
	if a == nil {
		return nil, false
	}
	str := func(s string) (any, bool) { return s, s != "" }
	strs := func(s []string) (any, bool) { return s, len(s) > 0 }
	switch rest {
	case "id":
		return str(a.ID)
	case "kind":
		return str(string(a.Kind))
	case "name":
		return str(a.Name)
	case "vendor":
		return str(a.Vendor)
	case "version":
		return str(a.Version)
	case "catalog_id":
		return str(a.CatalogID)
	case "parent":
		return str(a.Parent)
	case "path":
		return str(a.Path)
	case "scope":
		return str(string(a.Scope))
	case "owner":
		return str(a.Owner)
	case "risk_flags":
		return strs(a.RiskFlags)
	case "change":
		return str(string(a.Change))
	case "confidence":
		return str(a.Confidence)
	case "signer":
		return str(a.Signer)
	}
	m := a.MCP
	if m == nil || !strings.HasPrefix(rest, "mcp.") {
		return nil, false
	}
	switch strings.TrimPrefix(rest, "mcp.") {
	case "transport":
		return str(m.Transport)
	case "command":
		return str(m.Command)
	case "args":
		return strs(m.Args)
	case "runner":
		return str(m.Runner)
	case "ecosystem":
		return str(m.Ecosystem)
	case "package":
		return str(m.Package)
	case "version":
		return str(m.Version)
	case "pinned":
		return m.Pinned, true
	case "url_host":
		return str(m.URLHost)
	case "env_keys":
		return strs(m.EnvKeys)
	case "header_keys":
		return strs(m.HeaderKeys)
	case "has_inline_secret":
		return m.HasInlineSecret, true
	case "auth_mode":
		return str(m.AuthMode)
	}
	return nil, false
}

// lookupAny follows a dotted path into decoded JSON.
func lookupAny(m map[string]any, path string) (any, bool) {
	var cur any = m
	for depth, part := range strings.Split(path, ".") {
		if depth > maxInputDeep {
			return nil, false
		}
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[part]
		if !ok {
			return nil, false
		}
	}
	switch t := cur.(type) {
	case string:
		return t, t != ""
	case map[string]any:
		return t, true
	case []any:
		return map[string]any{"value": t}, true
	}
	if s, ok := renderScalar(cur); ok {
		return s, true
	}
	return nil, false
}

// sanitizeEvidence re-applies the allowlist and redaction to evidence that
// arrived on a detection record (the engine may have filled it from raw
// fields). Values already redacted pass through unchanged.
func (r *run) sanitizeEvidence(in map[string]string) map[string]string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxEvidenceFields {
		keys = keys[:maxEvidenceFields]
		r.note("detection.evidence")
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := in[k]
		mode, ok := allowedEvidence(k, r.lv)
		if !ok {
			if _, err := strconv.ParseFloat(v, 64); err == nil || v == "true" || v == "false" || v == Withheld {
				out[k] = v
				continue
			}
			out[k] = Withheld
			continue
		}
		name := "detection.evidence." + k
		if identityFields[k] && r.s.pseudo {
			switch {
			case strings.HasPrefix(v, "u_") && len(v) == 18:
				out[k] = v
			case r.s.key != nil && v != "":
				r.keyed = true
				out[k] = r.p.Pseudonym(v)
			}
			continue
		}
		if mode == evArgs || (strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !isMarkerOnly(v)) {
			var items []string
			if json.Unmarshal([]byte(v), &items) == nil {
				var red []string
				if mode == evArgs {
					red = r.argsStr(items, name, r.s.evidCap, maxArgs)
				} else {
					red = r.list(items, name, func(s string) string { return r.evidenceString(s, name, mode, r.s.evidCap) })
				}
				if b, err := json.Marshal(red); err == nil {
					s, cut := cutString(string(b), r.s.evidCap, true)
					if cut {
						r.note(name)
					}
					out[k] = s
					continue
				}
			}
		}
		if mode == evCount {
			if n, err := strconv.Atoi(v); err == nil {
				out[k] = strconv.Itoa(r.length(n))
				continue
			}
		}
		out[k] = r.evidenceString(v, name, mode, r.s.evidCap)
	}
	return out
}
