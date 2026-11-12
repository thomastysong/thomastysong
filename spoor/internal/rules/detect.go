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

// evidence renders the rule's evidence fields: secrets replaced by
// classify.Redact markers, the engine's home directory shown as "~", each
// value capped. The privacy stage may rebuild it from the shared Content
// and Feat with the keys of this map.
func (e *Engine) evidence(r *rule, fields map[string]any) map[string]string {
	if len(r.evidence) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.evidence))
	for _, f := range r.evidence {
		s := fieldString(fields[f], ", ")
		if s == "" {
			continue
		}
		red, _ := classify.Redact(s)
		if h := e.o.Home; h != "" && len(h) > 1 {
			red = strings.ReplaceAll(red, h, "~")
		}
		out[f] = cutString(red, maxEvidenceValue)
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
func (e *Engine) detection(r *rule, ev *event.Event, fields map[string]any, used []flagEntryNamed, chain []hit, now time.Time, skey string) *event.Event {
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
			Evidence:   e.evidence(r, fields),
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
func (e *Engine) posture(r *rule, ev *event.Event, fields map[string]any, now time.Time) *event.Event {
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
	if ev := e.evidence(r, fields); len(ev) > 0 {
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
