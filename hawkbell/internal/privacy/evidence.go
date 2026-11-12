package privacy

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/features"
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
	"id": evName, "type": evName, "kind": evName, "source": evName, "sources": evName, "fidelity": evName, "integrity": evName,
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
	"shell.opaque": evName, "shell.executes_paths": evPath, "shell.changes": evPath, "shell.change_classes": evName,
	"shell.proc_root": evName, "shell.aliases": evPath,
	"path.classes": evName, "path.ext": evName, "path.targets": evPath,
	"net.host": evName, "net.host_classes": evName, "net.scheme": evName,
	"prompt.secret_kinds": evName, "prompt.markers": evName,
	"write.secret_kinds": evName, "write.markers": evName, "write.exec_keys": evName,
	"output.markers": evName, "output.secret_kinds": evName,
	"mcp.server": evName, "mcp.tool": evName, "mcp.arg_paths": evPath, "mcp.arg_path_classes": evName,
	"mcp.arg_hosts": evName, "mcp.arg_host_classes": evName, "mcp.arg_secret_kinds": evName,
	"session.flags": evName, "session.written_exec_path": evPath, "shell.inherited_kinds": evName,
	"flow.secret_kinds": evName, "host.tags": evName,
	// Closed vocabularies (features.Registry lists them with Vocab).
	"shell.dialect": evName, "shell.inline_langs": evName, "shell.install_managers": evName,
	"output.untrusted_source": evName, "write.autorun_kinds": evName, "session.secret_flow_kinds": evName,
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
	if src.Feat == nil || !scalarField(f) {
		return false
	}
	_, ok := renderScalar(src.Feat[f])
	return ok
}

// scalarField reports a field the rule registry types as a boolean or a
// number and that is not content. Only such a field may pass the
// allowlist as a bare scalar: "it parses as a number" is not enough, as an
// OTP in a prompt, a card number in tool output or numeric file content
// parse as numbers too.
func scalarField(f string) bool {
	if m, ok := evidenceFields[f]; ok && m == evContent {
		return false
	}
	fi, ok := features.Lookup(f)
	return ok && (fi.Type == features.TypeBool || fi.Type == features.TypeNumber)
}

// scalarValue reports whether v is a valid rendering of field f's
// registry type.
func scalarValue(f, v string) bool {
	fi, ok := features.Lookup(f)
	if !ok {
		return false
	}
	switch fi.Type {
	case features.TypeBool:
		return v == "true" || v == "false"
	case features.TypeNumber:
		_, err := strconv.ParseFloat(v, 64)
		return err == nil
	}
	return false
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
	if l, isList := v.([]any); isList {
		// Decoded JSON or a feature computed as []any: only a list of
		// strings is evidence; anything nested is withheld.
		strs, ok := stringList(l)
		if !ok {
			return Withheld, true
		}
		v = strs
	}
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
			if items = r.argsEvidence(t, f, mcpCommand(src), name, cap); items == nil {
				return Withheld, true
			}
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

// argsEvidence redacts an argument vector for evidence. Flag-aware
// redaction needs the program word (mysql -p, redis-cli -a): process.args
// carries it, an MCP server's args do not, so the server's command is put
// in front for redaction and taken off again. Without a known command an
// MCP argument list is withheld (nil).
func (r *run) argsEvidence(args []string, field, prog, name string, cap int) []string {
	if field != "asset.mcp.args" {
		return r.argsStr(args, name, cap, maxArgs)
	}
	if strings.TrimSpace(prog) == "" {
		return nil
	}
	full := r.argsStr(append([]string{prog}, args...), name, cap, maxArgs+1)
	return full[1:]
}

func mcpCommand(e *event.Event) string {
	if e == nil || e.Asset == nil || e.Asset.MCP == nil {
		return ""
	}
	return e.Asset.MCP.Command
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
		// An argument vector flattened into one string reads as a
		// command line.
		return r.commandStr(s, name, cap)
	}
	return r.textStr(s, name, cap, false)
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
			if v == Withheld || scalarField(k) && scalarValue(k, v) {
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
					if red = r.argsEvidence(items, k, mcpCommand(r.src), name, r.s.evidCap); red == nil {
						out[k] = Withheld
						continue
					}
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
		if mode == evArgs && k == "asset.mcp.args" {
			// Not a list, and its program is not part of it: there is no
			// structure to redact by.
			out[k] = Withheld
			continue
		}
		out[k] = r.evidenceString(v, name, mode, r.s.evidCap)
	}
	return out
}
