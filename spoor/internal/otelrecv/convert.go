package otelrecv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// Labels set on converted events. They are the contract with the coverage
// correlator in the engine.
const (
	// LabelEvent holds the agent's own event name with its vendor prefix,
	// for example "claude_code.hook_execution_complete". It is set on
	// every event this package produces.
	LabelEvent = "otel_event"
	// LabelHookEvent holds the hook event type as the agent names it
	// ("PreToolUse"), on events that report hook registration or execution.
	// The hook dialects use the same key and value for the events spoor's
	// own hook receives, so the two can be compared directly.
	LabelHookEvent = "hook_event"
	// LabelHookRuns is the number of hook commands a hook-run event stands for.
	LabelHookRuns = "hook_runs"
)

// ErrTooLarge is returned by Convert for a body above MaxConvertBytes.
var ErrTooLarge = errors.New("otelrecv: body too large")

// Result is what one export request produced.
type Result struct {
	Events []*event.Event
	// Records is the number of log records in the request.
	Records int
	// Unknown counts records by event name for names this package has never
	// heard of, or records with no recognizable agent (under "" when the
	// record has no name at all). A non-empty map means the agent's
	// telemetry schema has drifted. At most maxUnknownNames distinct names
	// are kept; the overflow is counted under "_other".
	Unknown map[string]int
	// Ignored counts records whose event name is known and deliberately
	// not converted (API requests, token accounting, surveys).
	Ignored int
	// Dropped counts records beyond MaxRecords.
	Dropped int
}

const maxUnknownNames = 64

// Convert turns an OTLP/HTTP JSON logs export request into events. It never
// panics. Unknown event names are counted (see ConvertDetail), not errors;
// an error means the body is not a usable export request at all.
//
// The result is deterministic for a given body except for records that carry
// no timestamp, which are stamped with the current time and labelled
// ts_source=sensor.
func Convert(body []byte) ([]*event.Event, error) {
	res, err := ConvertDetail(body)
	if err != nil {
		return nil, err
	}
	return res.Events, nil
}

// ConvertDetail is Convert with the per-request accounting.
func ConvertDetail(body []byte) (*Result, error) {
	return convert(body, time.Now)
}

func convert(body []byte, now func() time.Time) (res *Result, err error) {
	defer func() {
		// A parser bug must cost one request, not the daemon.
		if p := recover(); p != nil {
			res, err = nil, fmt.Errorf("otelrecv: internal error: %v", p)
		}
	}()
	if len(body) > MaxConvertBytes {
		return nil, ErrTooLarge
	}
	req, err := decodeRequest(body)
	if err != nil {
		return nil, err
	}
	res = &Result{}
	c := &converter{res: res, now: now}
	for _, group := range [][]resourceLogs{req.ResourceLogs, req.ResourceLogsSnake} {
		for i := range group {
			rl := &group[i]
			var resAttrs attrs
			if rl.Resource != nil {
				resAttrs = decodeAttrs(rl.Resource.Attributes, 0)
			}
			for _, scopes := range [][]scopeLogs{rl.ScopeLogs, rl.ScopeLogsSnake} {
				for j := range scopes {
					sl := &scopes[j]
					scope := ""
					if sl.Scope != nil {
						scope = string(sl.Scope.Name)
					}
					for _, recs := range [][]logRecord{sl.LogRecords, sl.LogRecordsSnake} {
						for k := range recs {
							res.Records++
							if res.Records > MaxRecords {
								res.Dropped++
								continue
							}
							c.record(&recs[k], resAttrs, scope)
						}
					}
				}
			}
		}
	}
	return res, nil
}

type converter struct {
	res *Result
	now func() time.Time
}

// rec is one log record resolved to an agent and an event name.
type rec struct {
	agent string // canonical agent id (toolmap.Agent*)
	name  string // event name without the vendor prefix
	full  string // event name with the vendor prefix, as labelled
	ts    time.Time
	// stamped is true when the record carried no usable time and ts is the
	// receive time.
	stamped bool
	a       attrs // record attributes
	res     attrs // resource attributes
	key     string
}

func (c *converter) record(lr *logRecord, res attrs, scope string) {
	a := decodeAttrs(lr.Attributes, 0)
	var body string
	if v, ok := decodeAny(lr.Body, 0); ok {
		body, _ = v.(string)
	}
	name := eventName(lr, a, body)
	agent, short := identify(name, body, res, scope)
	if agent == "" || short == "" {
		c.unknown(name)
		return
	}
	r := &rec{agent: agent, name: short, a: a, res: res}
	r.full = vendorPrefix[agent] + short
	r.ts, r.stamped = c.stamp(lr, a)
	r.key = recordKey(lr, a)

	var evs []*event.Event
	var known bool
	switch agent {
	case toolmap.AgentClaude:
		evs, known = r.claude()
	case toolmap.AgentCodex:
		evs, known = r.codex()
	case toolmap.AgentGemini:
		evs, known = r.gemini()
	}
	switch {
	case len(evs) > 0:
		c.res.Events = append(c.res.Events, evs...)
	case known:
		c.res.Ignored++
	default:
		c.unknown(r.full)
	}
}

func (c *converter) unknown(name string) {
	if c.res.Unknown == nil {
		c.res.Unknown = map[string]int{}
	}
	name = labelValue(name, maxLabel)
	if _, ok := c.res.Unknown[name]; !ok && len(c.res.Unknown) >= maxUnknownNames {
		name = "_other"
	}
	c.res.Unknown[name]++
}

// stamp picks the record time: the record's own time, then the agent's
// event.timestamp attribute, then the collector-observed time, then now.
func (c *converter) stamp(lr *logRecord, a attrs) (time.Time, bool) {
	for _, n := range []flexUint{lr.TimeUnixNano, lr.TimeUnixNanoSnake} {
		if t, ok := nanoTime(n); ok {
			return t, false
		}
	}
	if s, ok := a.text("event.timestamp"); ok {
		if t, ok := parseStamp(s); ok {
			return t, false
		}
	}
	for _, n := range []flexUint{lr.ObservedTimeUnixNano, lr.ObservedTimeNanoSnake} {
		if t, ok := nanoTime(n); ok {
			return t, false
		}
	}
	return c.now().UTC(), true
}

// recordKey hashes what identifies a record, so that a retried export (OTLP
// senders retry on timeouts and 5xx) yields the same event ids and
// downstream can drop the duplicates. encoding/json writes map keys sorted,
// which makes the serialization canonical.
func recordKey(lr *logRecord, a attrs) string {
	h := sha256.New()
	b, _ := json.Marshal(map[string]any(a))
	_, _ = h.Write(b)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(lr.Body)
	_, _ = fmt.Fprintf(h, "\x00%d", uint64(lr.TimeUnixNano)|uint64(lr.TimeUnixNanoSnake))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// eventName finds the record's event name. Claude Code puts the prefixed
// name in the body and the bare name in the event.name attribute; Codex and
// Gemini CLI put the prefixed name in event.name (Gemini's body is prose).
// The LogRecord.event_name field (OTLP 1.5+) is read first when a sender
// fills it.
func eventName(lr *logRecord, a attrs, body string) string {
	for _, cand := range []string{string(lr.EventName), string(lr.EventNameSnake), a.str("event.name")} {
		if cand != "" {
			return cand
		}
	}
	if looksLikeName(body) {
		return body
	}
	return ""
}

// looksLikeName reports whether a log body is an event name rather than
// prose: one short dotted identifier.
func looksLikeName(s string) bool {
	if s == "" || len(s) > 96 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

var vendorPrefix = map[string]string{
	toolmap.AgentClaude: "claude_code.",
	toolmap.AgentCodex:  "codex.",
	toolmap.AgentGemini: "gemini_cli.",
}

// identify resolves the agent and the unprefixed event name. The name's own
// vendor prefix is the strongest evidence; service.name is used only for
// bare names, because OTEL_SERVICE_NAME lets a user rename the service.
func identify(name, body string, res attrs, scope string) (agent, short string) {
	ids := [...]string{toolmap.AgentClaude, toolmap.AgentCodex, toolmap.AgentGemini}
	for _, id := range ids {
		if rest, ok := strings.CutPrefix(name, vendorPrefix[id]); ok && rest != "" {
			return id, rest
		}
	}
	if name != "" && looksLikeName(body) {
		// Claude Code: bare name in the attribute, prefixed name in the body.
		for _, id := range ids {
			if strings.HasPrefix(body, vendorPrefix[id]) {
				return id, name
			}
		}
	}
	if name == "" {
		return "", ""
	}
	svc := strings.ToLower(res.str("service.name"))
	switch {
	// "claude-code" for terminal sessions, "claude-code-desktop" for the
	// Desktop app's Code tab (monitoring reference, "Service information").
	case svc == "claude-code" || svc == "claude-code-desktop" || strings.HasPrefix(scope, "com.anthropic.claude_code"):
		return toolmap.AgentClaude, name
	// Codex takes service_name from its embedder ("codex-cli" in the otel
	// crate README; other front ends pass their own).
	// UNVERIFIED: the exact names used by the app-server and exec front ends.
	case strings.HasPrefix(svc, "codex"):
		return toolmap.AgentCodex, name
	case svc == "gemini-cli":
		return toolmap.AgentGemini, name
	}
	return "", ""
}

// newEvent starts an activity event for the record. The id is deterministic
// (see recordKey); Dedupe is left empty on purpose: the engine derives it
// from host, agent, session, tool-call id and type for every surface, and a
// key computed here without the host would never match the hook's.
func (r *rec) newEvent(typ string) *event.Event {
	ev := &event.Event{
		V:        event.SchemaVersion,
		ID:       event.StableID(r.ts, "otel", r.agent, r.full, typ, r.key),
		TS:       event.At(r.ts),
		Kind:     event.KindActivity,
		Type:     typ,
		Source:   event.SourceOTel,
		Fidelity: event.FidelityObserved,
		// The sender is an unprivileged process: any local user can post
		// here, and loopback TCP carries no peer identity (see package doc).
		Integrity: event.IntegrityUser,
		Agent:     &event.Agent{ID: r.agent},
		Session:   &event.Session{},
		Labels:    map[string]string{},
	}
	setLabel(ev, LabelEvent, r.full)
	if r.stamped {
		setLabel(ev, "ts_source", "sensor")
	}
	// app.version is opt-in on Claude Code (OTEL_METRICS_INCLUDE_VERSION);
	// service.version on the resource is always there.
	ev.Agent.Version = field(ev, "agent.version", firstNonEmpty(r.std("app.version"), r.res.str("service.version")), 64)
	// session.id (Claude Code, Gemini CLI) and conversation.id (Codex) are
	// the ids the same agents pass to their hooks as session_id.
	// UNVERIFIED for Codex: that conversation.id equals the hook session_id.
	ev.Session.ID = field(ev, "session.id", firstNonEmpty(r.std("session.id"), r.std("conversation.id")), maxID)
	if d := emailDomain(r.std("user.email")); d != "" {
		// The address itself is never kept (see emailDomain).
		setLabel(ev, "account_domain", d)
	}
	setLabel(ev, "terminal", r.std("terminal.type"))
	return ev
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// content returns the event's local-only content holder.
func content(ev *event.Event) *event.Content {
	if ev.Content == nil {
		ev.Content = &event.Content{}
	}
	return ev.Content
}

// setPrompt records a prompt. The text is placed only in Content (never
// serialized here); whether it leaves the host is the privacy stage's
// decision. Agents replace the text with a placeholder unless prompt logging
// is enabled, and then only the length is known.
func setPrompt(ev *event.Event, a attrs, textKeys ...string) {
	p := &event.Prompt{}
	text, has := a.text(textKeys...)
	if has && !isRedacted(text) && text != "" {
		content(ev).PromptText = text
		p.Len = len(text) // bytes, as on the hook and transcript surfaces
	} else if n, ok := a.count("prompt_length"); ok {
		// The agents report characters here, not bytes: label the unit so
		// the two are not compared as equal.
		p.Len = n
		setLabel(ev, "prompt_len_unit", "chars")
	}
	ev.Prompt = p
}

// isRedacted recognizes the placeholders agents write instead of content:
// "<REDACTED>" (Claude Code) and "[REDACTED]" (Codex).
func isRedacted(s string) bool {
	switch strings.TrimSpace(s) {
	case "<REDACTED>", "[REDACTED]", "<redacted>", "[redacted]":
		return true
	}
	return false
}

// toolInputFromText turns the serialized arguments of a tool call into the
// input map detection works on. Text that is not a JSON object (a freeform
// patch, or JSON the agent truncated mid-value) is wrapped, as the hook and
// transcript surfaces do, so the content still reaches local detection.
func toolInputFromText(ev *event.Event, text, wrapKey string) map[string]any {
	if text == "" || isRedacted(text) {
		return nil
	}
	if m, ok := embeddedObject(text); ok {
		return m
	}
	if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{") {
		// Looked like an object and did not parse: cut by the agent.
		ev.Truncated = appendUnique(ev.Truncated, "tool.input")
	}
	return map[string]any{wrapKey: text}
}

// setOutcomeStatus maps a success flag to the outcome vocabulary.
func setOutcomeStatus(o *event.Outcome, a attrs) {
	if ok, has := a.boolean("success"); has {
		if ok {
			o.Status = "ok"
		} else {
			o.Status = "error"
		}
		return
	}
	o.Status = "unknown"
}

// setError records a failure without emitting its text: an error category
// when the agent gives one, else a fingerprint. Error messages quote file
// content and command output, so the message itself goes to Content only.
func setError(ev *event.Event, o *event.Outcome, category, message string) {
	if category != "" {
		o.Error = labelValue(category, maxLabel)
	} else if message != "" {
		o.Error = "tool error fp:" + fingerprint(message)
	}
	if message != "" {
		c := content(ev)
		if c.ToolOutput == "" {
			c.ToolOutput = message
		}
	}
}

// IsHookRun reports whether ev is an OTel record of completed hook
// execution, and if so which hook event it was for and how many hook
// commands ran. The coverage correlator compares these against the hook
// events spoor's own hook delivered for the same session: an agent that
// reports running hooks spoor never heard from has a broken or replaced hook.
func IsHookRun(ev *event.Event) (hookEvent string, runs int, ok bool) {
	if ev == nil || ev.Source != event.SourceOTel || ev.Type != event.TypeNotification {
		return "", 0, false
	}
	switch ev.Labels[LabelEvent] {
	case "claude_code.hook_execution_complete", "gemini_cli.hook_call":
	default:
		return "", 0, false
	}
	runs = 1
	if n, err := strconv.Atoi(ev.Labels[LabelHookRuns]); err == nil && n >= 0 {
		runs = n
	}
	return ev.Labels[LabelHookEvent], runs, true
}
