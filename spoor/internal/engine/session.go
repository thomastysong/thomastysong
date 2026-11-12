package engine

import (
	"sort"
	"strconv"
	"time"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// Per-session bookkeeping: the summary accumulators (C2 item 10), the
// activity token bucket (item 11), the context ring (item 9) and the
// coverage inputs of the hook-bypass logic (item 4). Everything here is
// counts, classes, names and ids: no content is kept except in the context
// ring, whose records have their Content removed and are rendered with the
// standard field policy before they are written.

const (
	maxSummaryList = 64  // hosts, servers, installs ... per summary
	maxUnmatched   = 256 // tool-call ids remembered per session
	maxUses        = 1024
	maxPromptTexts = 512 // distinct prompt texts remembered per session and surface
	maxPromptOccs  = 64  // occurrences remembered per prompt text
	// promptRepeatWindow: two records of one surface with the same prompt
	// text, no prompt id and no record id in common, are one submission
	// (a hook registered twice, managed and user settings) when they are
	// this close in time, and two submissions otherwise.
	promptRepeatWindow = 2 * time.Second
)

type session struct {
	key     string
	attrKey string // host, agent and session id, for OTel attribution
	host    *event.Host
	user    *event.User
	agent   *event.Agent
	sess    event.Session
	userInt bool // a user-writable surface contributed

	first, last time.Time // event times
	lastWall    time.Time
	lastSummary time.Time
	created     time.Time
	dirty       bool
	ended       bool
	finalDue    bool // ended; the final summary waits for held records
	finalSent   bool
	heldN       int // records of the session waiting for their hook twin
	sumN        int

	events, prompts, subagents, denied, blocked, suppressed int
	toolCalls                                               map[string]int
	uses                                                    map[string]bool
	useOrder                                                []string
	hosts, hostClasses, pathClasses, mcp, installs          orderedSet
	detections, flags                                       orderedSet
	maxSev                                                  string
	surfaces                                                map[event.Source]bool

	bkt bucket // activity token bucket

	ring []*event.Event

	unmatched     map[string]string // tool-call id -> event id
	unmatchedIDs  []string
	hookRecords   map[string]int // hook records by event type
	otelRuns      map[string]int // OTel hook firings by event type
	otelLast      time.Time
	bypassSignal  bool
	bypassFinding bool

	promptSeen  map[string]*promptList // surface + prompt digest -> occurrences
	promptOrder []string
}

type promptOcc struct {
	id, turn string
	ts       time.Time
}

type promptList struct {
	occ   []promptOcc
	extra int
}

type orderedSet struct {
	items []string
	seen  map[string]bool
	cut   bool
}

func (o *orderedSet) add(vs ...string) {
	for _, v := range vs {
		if v == "" || o.seen[v] {
			continue
		}
		if len(o.items) >= maxSummaryList {
			o.cut = true
			continue
		}
		if o.seen == nil {
			o.seen = map[string]bool{}
		}
		o.seen[v] = true
		o.items = append(o.items, v)
	}
}

func (o *orderedSet) list() []string {
	if len(o.items) == 0 {
		return nil
	}
	return append([]string(nil), o.items...)
}

func (o *orderedSet) sorted() []string {
	l := o.list()
	sort.Strings(l)
	return l
}

func newSession(ev *event.Event, key string, now time.Time) *session {
	s := &session{
		key:         key,
		created:     now,
		lastWall:    now,
		lastSummary: now,
		toolCalls:   map[string]int{},
		uses:        map[string]bool{},
		surfaces:    map[event.Source]bool{},
		unmatched:   map[string]string{},
		hookRecords: map[string]int{},
		otelRuns:    map[string]int{},
		promptSeen:  map[string]*promptList{},
	}
	if ev.Host != nil {
		h := *ev.Host
		s.host = &h
	}
	if ev.User != nil {
		u := *ev.User
		s.user = &u
	}
	if ev.Agent != nil {
		a := event.Agent{ID: ev.Agent.ID, Name: ev.Agent.Name, Version: ev.Agent.Version, Surface: ev.Agent.Surface}
		s.agent = &a
	}
	if ev.Session != nil {
		s.sess = event.Session{ID: ev.Session.ID, ParentID: ev.Session.ParentID, CWD: ev.Session.CWD,
			PermissionMode: ev.Session.PermissionMode, Model: ev.Session.Model}
	}
	return s
}

// sessionFor returns the live session of ev, creating it (and synthesizing
// its start) on first sight.
func (p *Pipeline) sessionFor(ev *event.Event, key string, now time.Time) *session {
	if el, ok := p.sessions[key]; ok {
		p.lru.MoveToFront(el)
		return el.Value.(*session)
	}
	s := newSession(ev, key, now)
	p.sessions[key] = p.lru.PushFront(s)
	p.indexSession(s)
	for len(p.sessions) > maxSessions {
		el := p.lru.Back()
		old := el.Value.(*session)
		p.summary(old, now, true, "evicted")
		p.removeSession(old.key)
	}
	if ev.Type != event.TypeSessionStart {
		// The SessionStart hook does not fire in every mode (--bare), so a
		// session is started by its first record, whatever the surface.
		p.synthesizeStart(ev, s, now)
	}
	return s
}

func (p *Pipeline) synthesizeStart(ev *event.Event, s *session, now time.Time) {
	st := &event.Event{
		V:         event.SchemaVersion,
		TS:        ev.TS,
		Kind:      event.KindActivity,
		Type:      event.TypeSessionStart,
		Source:    ev.Source,
		Fidelity:  event.FidelityInferred,
		Integrity: ev.Integrity,
		Labels:    map[string]string{"synthesized": "true"},
	}
	if s.host != nil {
		h := *s.host
		st.Host = &h
	}
	if s.user != nil {
		u := *s.user
		st.User = &u
	}
	if s.agent != nil {
		a := *s.agent
		st.Agent = &a
	}
	ss := s.sess
	if ev.Session != nil {
		ss.SubagentID, ss.SubagentType = ev.Session.SubagentID, ev.Session.SubagentType
	}
	st.Session = &ss
	host, user, agent, sid := idParts(st)
	st.Dedupe = event.DedupeKey(host, user, agent, sid, "session", st.Type)
	st.ID = event.StableID(st.TS.Time, "spoor/session.start", st.Dedupe)
	p.ctr.synthesized++
	p.corr.markPrimary(st.Dedupe, event.SourceSensor, now)
	p.evaluate(st, s, now)
}

func (p *Pipeline) removeSession(key string) {
	if el, ok := p.sessions[key]; ok {
		p.unindexSession(el.Value.(*session))
		p.lru.Remove(el)
		delete(p.sessions, key)
	}
}

// dropSession forgets a session without a summary (it became excluded).
func (p *Pipeline) dropSession(key string) { p.removeSession(key) }

// add folds an evaluated activity record into the summary.
func (s *session) add(ev *event.Event) {
	s.events++
	s.dirty = true
	if ev.Integrity != event.IntegrityRoot {
		s.userInt = true
	}
	t := ev.TS.Time
	if s.first.IsZero() || t.Before(s.first) {
		s.first = t
	}
	if t.After(s.last) {
		s.last = t
	}
	if ev.Session != nil {
		if s.sess.CWD == "" {
			s.sess.CWD = ev.Session.CWD
		}
		if ev.Session.Model != "" {
			s.sess.Model = ev.Session.Model
		}
		if ev.Session.PermissionMode != "" {
			s.sess.PermissionMode = ev.Session.PermissionMode
		}
	}
	if s.agent != nil && ev.Agent != nil && ev.Agent.Version != "" {
		s.agent.Version = ev.Agent.Version
	}
	switch ev.Type {
	case event.TypePromptSubmit:
		s.prompts++
	case event.TypeSubagentStart:
		s.subagents++
	case event.TypeToolPre, event.TypeToolPost:
		s.countTool(ev)
	}
	if o := ev.Outcome; o != nil {
		if o.Status == "denied" || o.Decision == "deny" {
			s.denied++
			if o.DecisionSource == "spoor" {
				s.blocked++
			}
		}
	}
	f := ev.Feat
	strs := func(k string) []string { v, _ := f[k].([]string); return v }
	s.hosts.add(strs("net.host")...)
	s.hostClasses.add(strs("net.host_classes")...)
	for _, k := range []string{"path.classes", "shell.read_classes", "shell.write_classes", "shell.delete_classes", "mcp.arg_path_classes"} {
		for _, c := range strs(k) {
			if sensitiveClass[c] {
				s.pathClasses.add(c)
			}
		}
	}
	if ev.Tool != nil && ev.Tool.Kind == event.ToolMCP && ev.Tool.MCPServer != "" {
		s.mcp.add(ev.Tool.MCPServer)
	}
	s.installs.add(strs("shell.installs")...)
	s.flags.add(strs("session.flags")...)
}

var sensitiveClass = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range classify.SensitiveReadClasses() {
		m[c] = true
	}
	for _, c := range classify.SensitiveWriteClasses() {
		m[c] = true
	}
	return m
}()

// countTool counts a tool call once, whether one or both of its pre and
// post records arrive.
func (s *session) countTool(ev *event.Event) {
	kind := "other"
	if ev.Tool != nil && ev.Tool.Kind != "" {
		kind = string(ev.Tool.Kind)
	}
	id := ""
	if ev.Tool != nil {
		id = ev.Tool.UseID
	}
	if id != "" {
		if s.uses[id] {
			return
		}
		s.uses[id] = true
		s.useOrder = append(s.useOrder, id)
		if len(s.useOrder) > maxUses {
			delete(s.uses, s.useOrder[0])
			s.useOrder = s.useOrder[1:]
		}
	} else if ev.Type == event.TypeToolPost {
		// Without an id a post record cannot be paired with its pre record;
		// count the pre record only.
		return
	}
	s.toolCalls[kind]++
}

func (s *session) addDetection(d *event.Detection) {
	s.detections.add(d.RuleID)
	if event.SeverityRank(d.Severity) > event.SeverityRank(s.maxSev) {
		s.maxSev = d.Severity
	}
	s.dirty = true
}

// promptDedupe gives a prompt with text the Dedupe of its occurrence.
//
// The prompt text is the only natural key every surface shares (the hook
// and OTel carry a prompt id, Claude Code's transcript does not), but the
// same text is often submitted twice ("continue", "yes"). Each surface's
// records with one text are therefore numbered in order of submission
// within the session, and the k-th hook record pairs with the k-th
// transcript record. A record is the same submission as an earlier one of
// its surface when it has the same record id (a replay), the same prompt
// id, or, with no prompt id on either, a time within promptRepeatWindow.
func (p *Pipeline) promptDedupe(ev *event.Event, s *session) {
	nat := p.naturalKey(ev)
	if nat == "" {
		return
	}
	turn := ""
	if ev.Session != nil {
		turn = ev.Session.TurnID
	}
	n := s.promptOccurrence(ev.Source, nat, ev.ID, turn, ev.TS.Time)
	host, user, agent, sid := idParts(ev)
	ev.Dedupe = event.DedupeKey(host, user, agent, sid, nat+"#"+strconv.Itoa(n), ev.Type)
}

func (s *session) promptOccurrence(src event.Source, nat, id, turn string, ts time.Time) int {
	k := string(src) + "\x00" + nat
	l := s.promptSeen[k]
	if l == nil {
		if len(s.promptOrder) >= maxPromptTexts {
			delete(s.promptSeen, s.promptOrder[0])
			s.promptOrder = s.promptOrder[1:]
		}
		l = &promptList{}
		s.promptSeen[k] = l
		s.promptOrder = append(s.promptOrder, k)
	}
	for i, o := range l.occ {
		switch {
		case id != "" && o.id == id, turn != "" && o.turn == turn:
			return i
		case turn == "" && o.turn == "" && ts.Sub(o.ts).Abs() <= promptRepeatWindow:
			return i
		}
	}
	if len(l.occ) < maxPromptOccs {
		l.occ = append(l.occ, promptOcc{id: id, turn: turn, ts: ts})
		return len(l.occ) - 1
	}
	// Past the cap a record is always a new occurrence: a replay is then
	// written twice rather than a new prompt dropped.
	l.extra++
	return maxPromptOccs - 1 + l.extra
}

// push adds a processed record to the context ring.
func (s *session) push(ev *event.Event, n int) {
	if n <= 0 {
		return
	}
	c := *ev
	c.Content = nil // context is rendered with the standard policy: no content
	if len(s.ring) >= n {
		copy(s.ring, s.ring[1:])
		s.ring = s.ring[:n-1]
	}
	s.ring = append(s.ring, &c)
}

func (s *session) unmatchedCall(useID, eventID string) {
	if _, ok := s.unmatched[useID]; ok || len(s.unmatched) >= maxUnmatched {
		return
	}
	s.unmatched[useID] = eventID
	s.unmatchedIDs = append(s.unmatchedIDs, eventID)
}

func (s *session) matchedLate(useID string) {
	if id, ok := s.unmatched[useID]; ok {
		delete(s.unmatched, useID)
		for i, x := range s.unmatchedIDs {
			if x == id {
				s.unmatchedIDs = append(s.unmatchedIDs[:i], s.unmatchedIDs[i+1:]...)
				break
			}
		}
	}
}

// hookTypes maps the agents' hook event names (OTel hook_event) to event
// types. Only tool hooks are compared: spoor always registers them, while
// a firing of another hook event may belong to someone else's hook.
var hookTypes = map[string]string{
	"PreToolUse": event.TypeToolPre, "preToolUse": event.TypeToolPre, "BeforeTool": event.TypeToolPre,
	"PostToolUse": event.TypeToolPost, "postToolUse": event.TypeToolPost, "AfterTool": event.TypeToolPost,
	"PostToolUseFailure": event.TypeToolPost,
}

func (s *session) noteOTelHookRun(hookEvent string, runs int, now time.Time) {
	t, ok := hookTypes[hookEvent]
	if !ok || runs <= 0 {
		return
	}
	s.otelRuns[t]++
	s.otelLast = now
}

// otelMismatch is how many tool-hook firings the agent reported over OTel
// beyond the hook records spoor received, once the last firing is older
// than HoldFor (hook records and OTel batches arrive at different times).
func (s *session) otelMismatch(now time.Time) int {
	if len(s.otelRuns) == 0 || now.Sub(s.otelLast) < HoldFor {
		return 0
	}
	n := 0
	for t, runs := range s.otelRuns {
		if d := runs - s.hookRecords[t]; d > n {
			n = d
		}
	}
	return n
}

// summary writes the session summary record.
func (p *Pipeline) summary(s *session, now time.Time, final bool, reason string) {
	if s.events == 0 && !s.dirty {
		return
	}
	s.sumN++
	sum := &event.Summary{
		Started:     event.At(s.first),
		Final:       final,
		Events:      s.events,
		Prompts:     s.prompts,
		Subagent:    s.subagents,
		Hosts:       s.hosts.list(),
		HostClasses: s.hostClasses.sorted(),
		PathClasses: s.pathClasses.sorted(),
		MCPServers:  s.mcp.list(),
		Installs:    s.installs.list(),
		Detections:  s.detections.list(),
		MaxSeverity: s.maxSev,
		Flags:       s.flags.sorted(),
		Coverage:    s.coverageState(),
		Denied:      s.denied,
		Blocked:     s.blocked,
	}
	if s.first.IsZero() {
		sum.Started = event.Time{}
	}
	if final && !s.last.IsZero() {
		sum.Ended = event.At(s.last)
	}
	if len(s.toolCalls) > 0 {
		sum.ToolCalls = make(map[string]int, len(s.toolCalls))
		for k, v := range s.toolCalls {
			sum.ToolCalls[k] = v
		}
	}
	for _, src := range []event.Source{event.SourceHook, event.SourceTranscript, event.SourceOTel, event.SourceProcess, event.SourceOsquery, event.SourceAdapter} {
		if s.surfaces[src] {
			sum.Surfaces = append(sum.Surfaces, src)
		}
	}
	ev := &event.Event{
		V:         event.SchemaVersion,
		TS:        event.At(now),
		Kind:      event.KindSummary,
		Type:      event.TypeSessionSummary,
		Source:    event.SourceSensor,
		Fidelity:  event.FidelityInferred,
		Integrity: p.integrity,
		Host:      s.host,
		User:      s.user,
		Agent:     s.agent,
		Summary:   sum,
		Labels:    map[string]string{"end_reason": reason},
	}
	if !final {
		ev.Labels = map[string]string{}
	}
	if s.userInt {
		ev.Integrity = event.IntegrityUser
	}
	ss := s.sess
	ev.Session = &ss
	if s.suppressed > 0 {
		ev.Labels["activity_suppressed"] = strconv.Itoa(s.suppressed)
	}
	if s.hosts.cut || s.mcp.cut || s.installs.cut || s.detections.cut {
		ev.Labels["summary_capped"] = "true"
	}
	if len(ev.Labels) == 0 {
		ev.Labels = nil
	}
	host, user, agent, sid := idParts(ev)
	ev.Dedupe = event.DedupeKey(host, user, agent, sid, "summary")
	ev.ID = event.StableID(now, "spoor/summary", s.key, p.writer, strconv.Itoa(s.sumN))
	p.ctr.summaries++
	p.emit(ev, now, true)
	s.lastSummary = now
	s.dirty = false
	if final {
		s.finalSent, s.finalDue = true, false
	}
}

// coverageState is the session's coverage: covered (hook and another
// surface), partial (one self-reported surface), blind (only the OS saw it).
func (s *session) coverageState() string {
	hook := s.surfaces[event.SourceHook]
	other := s.surfaces[event.SourceTranscript] || s.surfaces[event.SourceOTel]
	os := s.surfaces[event.SourceProcess] || s.surfaces[event.SourceOsquery]
	switch {
	case hook && (other || os):
		return "covered"
	case hook || other:
		return "partial"
	case os:
		return "blind"
	}
	return "partial"
}

// sweepSessions emits rolling summaries for active sessions and final
// summaries for idle ones (all of them when closing).
func (p *Pipeline) sweepSessions(now time.Time, closing bool) {
	all := make([]*session, 0, len(p.sessions))
	for _, el := range p.sessions {
		all = append(all, el.Value.(*session))
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key < all[j].key })
	var idle []*session
	for _, s := range all {
		switch {
		case closing:
			// A daemon restart does not end anyone's session.
			final := p.mode != ModeDaemon || s.ended
			if s.dirty || s.finalDue {
				p.summary(s, now, final, "close")
			}
		case now.Sub(s.lastWall) >= SessionIdle:
			idle = append(idle, s)
		case s.dirty && !s.ended && now.Sub(s.lastSummary) >= SummaryEvery:
			p.summary(s, now, false, "")
		}
	}
	for _, s := range idle {
		if s.dirty || s.finalDue {
			reason := "idle"
			switch {
			case s.finalSent:
				// Records processed after the final summary (a collector
				// that delivered late): this one supersedes it.
				reason = "late_records"
			case s.ended:
				reason = "session_end"
			}
			p.summary(s, now, true, reason)
		}
		p.removeSession(s.key)
	}
}
