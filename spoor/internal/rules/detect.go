package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// destinationFields name where an action goes. Alert-class dedup keys
// always include them, so suppressing one alert cannot silence the same
// rule firing against a different host or file.
var destinationFields = []string{
	"net.host", "target.host", "target.url", "target.path", "target.paths", "shell.hosts",
	"shell.writes", "shell.deletes", "mcp.arg_hosts", "mcp.arg_paths", "session.written_exec_path",
}

// fieldString renders a field value for keys and evidence.
func fieldString(v any, sep string) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		return strings.Join(t, sep)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func dedupKey(r *rule, class, skey string, fields map[string]any) string {
	h := sha256.New()
	h.Write([]byte(r.ID))
	h.Write([]byte{0})
	h.Write([]byte(skey))
	for _, f := range r.dedup {
		h.Write([]byte{0})
		h.Write([]byte(f))
		h.Write([]byte{1})
		h.Write([]byte(fieldString(fields[f], "\x01")))
	}
	if class == event.ClassAlert {
		for _, f := range destinationFields {
			h.Write([]byte{2})
			h.Write([]byte(fieldString(fields[f], "\x01")))
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// evidence renders the rule's evidence fields: credentials redacted
// (structurally for commands, argument vectors and URLs, then by
// classify.Redact), the engine's home directory shown as "~", each value
// capped. Detections leave the host in every privacy profile, so this is a
// floor even though the privacy stage may rebuild evidence from the shared
// Content and Feat with the keys of this map.
//
// memo caches rendered values by field for the event being evaluated:
// several rules firing on one event usually name the same evidence fields,
// and structural redaction re-parses argument vectors.
func (e *Engine) evidence(r *rule, fields map[string]any, memo evidenceMemo) map[string]string {
	if len(r.evidence) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.evidence))
	for _, f := range r.evidence {
		v, ok := memo[f]
		if !ok {
			v = e.renderEvidence(f, fields)
			if memo != nil {
				memo[f] = v
			}
		}
		if v != "" {
			out[f] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (e *Engine) labels(r *rule) map[string]string {
	l := map[string]string{"rule_pack": r.pack, "rule_pack_version": r.packVersion}
	if len(e.hash) >= 12 {
		l["rules_hash"] = e.hash[:12]
	}
	return l
}

// detection builds the detection.finding record for r firing on ev.
func (e *Engine) detection(r *rule, ev *event.Event, fields map[string]any, used []flagEntryNamed, chain []hit, now time.Time, skey string, memo evidenceMemo) *event.Event {
	c := ev.Clone()
	ts := ev.TS
	if ts.IsZero() {
		ts = event.At(now)
	}
	natural := ev.Dedupe
	if natural == "" {
		natural = ev.ID
	}
	class := r.Class
	tags := append([]string(nil), r.Tags...)
	if r.novelty != nil {
		parts := []string{r.ID}
		for _, f := range r.novelty.fields {
			parts = append(parts, fieldString(fields[f], "\x01"))
		}
		if !e.baseline.Seen(event.DedupeKey(parts...)) {
			tags = append(tags, "spoor.first_seen")
			if r.novelty.raise {
				class = raiseClass(class)
			}
		}
	}
	// The chain is every event that contributed, oldest first: the events
	// that set the required flags, then the threshold hits (the last of
	// which is ev).
	type link struct {
		t  time.Time
		id string
	}
	var links []link
	var flagNames []string
	for _, u := range used {
		flagNames = append(flagNames, u.name)
		if u.ev != "" {
			links = append(links, link{u.at, u.ev})
		}
	}
	for _, h := range chain {
		if h.ev != "" {
			links = append(links, link{h.t, h.ev})
		}
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].t.Before(links[j].t) })
	var ids []string
	seen := map[string]bool{}
	for _, l := range links {
		if !seen[l.id] {
			seen[l.id] = true
			ids = append(ids, l.id)
		}
	}
	sort.Strings(flagNames)
	d := &event.Event{
		V:         event.SchemaVersion,
		ID:        event.StableID(ts.Time, "detection", r.ID, natural),
		TS:        ts,
		Dedupe:    event.DedupeKey("detection", r.ID, natural),
		Kind:      event.KindDetection,
		Type:      event.TypeDetectionFinding,
		Source:    event.SourceSensor,
		Integrity: ev.Integrity,
		Host:      c.Host, User: c.User, Agent: c.Agent, Account: c.Account, Session: c.Session,
		Tool: c.Tool, Target: c.Target, Process: c.Process, Container: c.Container, Repo: c.Repo,
		Labels:  e.labels(r),
		Content: ev.Content,
		Feat:    ev.Feat,
		Detection: &event.Detection{
			RuleID:     r.ID,
			Title:      r.Title,
			Class:      class,
			Severity:   r.Severity,
			Confidence: r.Confidence,
			Maturity:   r.Maturity,
			Category:   r.Category,
			Tags:       tags,
			Evidence:   e.evidence(r, fields, memo),
			EventIDs:   ids,
			Flags:      flagNames,
			Response:   r.response,
			Escalate:   r.escalate,
			Remedy:     r.remedy,
			Count:      1,
		},
	}
	d.Detection.DedupKey = dedupKey(r, class, skey, fields)
	return d
}

func raiseClass(c string) string {
	switch c {
	case event.ClassSignal:
		return event.ClassFinding
	default:
		return event.ClassAlert
	}
}

// posture builds the posture.check failure an inventory rule reports.
func (e *Engine) posture(r *rule, ev *event.Event, fields map[string]any, now time.Time, memo evidenceMemo) *event.Event {
	c := ev.Clone()
	ts := ev.TS
	if ts.IsZero() {
		ts = event.At(now)
	}
	chk := &event.Check{
		ID: r.ID, Title: r.Title, Status: "fail", Severity: r.Severity, Remedy: r.remedy,
	}
	natural := ev.ID
	if a := ev.Asset; a != nil {
		chk.AssetID, chk.Scope, chk.Subject, chk.Owner = a.ID, a.Scope, a.Path, a.Owner
		switch {
		case a.Parent != "":
			chk.AgentID = a.Parent
		case a.Kind == event.AssetAgent || a.Kind == event.AssetApp:
			chk.AgentID = a.CatalogID
		}
		if a.ID != "" {
			natural = a.ID
		}
	}
	if chk.AgentID == "" && ev.Agent != nil {
		chk.AgentID = ev.Agent.ID
	}
	if ev := e.evidence(r, fields, memo); len(ev) > 0 {
		keys := make([]string, 0, len(ev))
		for k := range ev {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+ev[k])
		}
		chk.Actual = cutString(strings.Join(parts, "; "), 512)
	}
	return &event.Event{
		V:         event.SchemaVersion,
		ID:        event.StableID(ts.Time, "posture", r.ID, natural),
		TS:        ts,
		Dedupe:    event.DedupeKey("posture", r.ID, natural),
		Kind:      event.KindPosture,
		Type:      event.TypePostureCheck,
		Source:    event.SourceSensor,
		Integrity: ev.Integrity,
		Host:      c.Host, User: c.User, Agent: c.Agent, Container: c.Container,
		Labels: e.labels(r),
		Check:  chk,
	}
}

// evidenceMemo maps an evidence field name to its rendered value for one
// event.
type evidenceMemo map[string]string

func (e *Engine) renderEvidence(f string, fields map[string]any) string {
	s := evidenceValue(f, fields)
	if s == "" {
		return ""
	}
	red, _ := classify.Redact(s)
	if h := e.o.Home; h != "" && len(h) > 1 {
		red = strings.ReplaceAll(red, h, "~")
	}
	return cutString(red, maxEvidenceValue)
}

// evidenceValue renders one evidence field before free-text redaction.
// classify.Redact recognises a secret by its shape; a password given as a
// flag value ("mysql -pHunter2", "curl -u admin:pw", "--token x") has none,
// so fields that hold command lines or argument vectors are redacted from
// the parsed commands first, and URLs by query parameter name.
func evidenceValue(field string, fields map[string]any) string {
	v := fields[field]
	switch field {
	case "target.command":
		s, _ := v.(string)
		return redactCommand(s, fields)
	case "shell.argv":
		if _, ok := v.([]string); !ok {
			return ""
		}
		var parts []string
		for _, argv := range redactedCommands(fields) {
			parts = append(parts, argv[1:]...)
		}
		if parts == nil {
			// No parsed commands to anchor on: redact the flat list.
			parts = classify.RedactArgs(append([]string{""}, v.([]string)...))[1:]
		}
		return strings.Join(parts, ", ")
	case "process.args":
		l, _ := v.([]string)
		return strings.Join(classify.RedactArgs(l), " ")
	case "target.url", "shell.urls", "net.url":
		switch t := v.(type) {
		case string:
			return classify.RedactURL(t, true)
		case []string:
			out := make([]string, len(t))
			for i, u := range t {
				out[i] = classify.RedactURL(u, true)
			}
			return strings.Join(out, ", ")
		}
	}
	return fieldString(v, ", ")
}

// redactedCommands returns the classify.RedactArgs form of every parsed
// command's argv, program first.
func redactedCommands(fields map[string]any) [][]string {
	cmds, _ := fields["shell.cmds"].([]map[string]any)
	out := make([][]string, 0, len(cmds))
	for _, c := range cmds {
		path, _ := c["path"].(string)
		args, _ := c["args"].([]string)
		out = append(out, classify.RedactArgs(append([]string{path}, args...)))
	}
	return out
}

// redactCommand replaces, in the command line as written, every argument
// that classify.RedactArgs redacts in the parsed commands. When an argument
// cannot be found verbatim (the parser removed quotes or escapes around
// it), the command is rendered from the redacted argument vectors instead:
// losing the original layout is better than keeping a credential.
func redactCommand(s string, fields map[string]any) string {
	if s == "" {
		return ""
	}
	cmds, _ := fields["shell.cmds"].([]map[string]any)
	out := s
	rebuilt := make([]string, 0, len(cmds))
	exact := true
	for _, c := range cmds {
		path, _ := c["path"].(string)
		args, _ := c["args"].([]string)
		argv := append([]string{path}, args...)
		red := classify.RedactArgs(argv)
		rebuilt = append(rebuilt, strings.Join(red, " "))
		for i := 1; i < len(argv); i++ {
			if red[i] == argv[i] || argv[i] == "" {
				continue
			}
			var n int
			out, n = replaceTokens(out, argv[i], red[i])
			if n == 0 {
				exact = false
			}
		}
	}
	if !exact {
		return strings.Join(rebuilt, "; ")
	}
	return out
}

// tokenSep are the bytes that end a shell word or a key=value / user:pass
// part of one.
const tokenSep = " \t\r\n'\"=:;|&()<>,"

// replaceTokens replaces occurrences of old in s that stand as a whole
// shell word or word part (bounded on both sides by the start or end of s
// or a tokenSep byte), so a short secret does not rewrite unrelated text.
// It returns the count replaced.
func replaceTokens(s, old, repl string) (string, int) {
	if old == "" {
		return s, 0
	}
	var b strings.Builder
	n, i := 0, 0
	for {
		j := strings.Index(s[i:], old)
		if j < 0 {
			break
		}
		start, end := i+j, i+j+len(old)
		before := start == 0 || strings.IndexByte(tokenSep, s[start-1]) >= 0
		after := end == len(s) || strings.IndexByte(tokenSep, s[end]) >= 0
		if before && after {
			b.WriteString(s[i:start])
			b.WriteString(repl)
			n++
		} else {
			b.WriteString(s[i:end])
		}
		i = end
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[i:])
	return b.String(), n
}
