package engine

import (
	"sort"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
	"github.com/thomastysong/spoor/internal/rules"
)

// processSafe is process behind a recover: one hostile or malformed record
// must never take the daemon down.
func (p *Pipeline) processSafe(ev *event.Event, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			p.ctr.panics++
			p.ctr.errors++
		}
	}()
	p.process(ev, now)
}

// process runs one arriving record through the pipeline; pmu is held.
func (p *Pipeline) process(ev *event.Event, now time.Time) {
	if ev == nil {
		return
	}
	p.ctr.processed++
	// Surface health counts arrivals, whatever becomes of the record.
	p.observeSurface(ev, now)
	p.processAs(ev, now, attrOwn)
	p.adoptPending(now)
}

// processAsSafe is processAs behind a recover, for records processed after
// a wait (attribution).
func (p *Pipeline) processAsSafe(ev *event.Event, now time.Time, how attribution) {
	defer func() {
		if r := recover(); r != nil {
			p.ctr.panics++
			p.ctr.errors++
		}
	}()
	p.processAs(ev, now, how)
}

// processAs processes a record whose account came from how.
func (p *Pipeline) processAs(ev *event.Event, now time.Time, how attribution) {
	// 0. A record without an account (OTel) takes the account of the one
	// live session it belongs to, or waits for it (attribution.go).
	if how == attrOwn && needsAccount(ev) {
		var ok bool
		if how, ok = p.attribute(ev, now, false); !ok {
			return
		}
	}
	// 1. Exclusions first, before any content is looked at. An excluded
	// session stays excluded even for its later records that lack the
	// identity fields the exclusion matched on.
	skey := ""
	if ev.Session != nil && ev.Session.ID != "" {
		skey = rules.SessionKey(ev)
	}
	if skey != "" {
		if _, ok := p.excluded[skey]; ok {
			p.ctr.excluded++
			return
		}
	}
	if p.pol.Excluded(ev) {
		p.ctr.excluded++
		if skey != "" {
			if len(p.excluded) >= maxExcluded {
				clear(p.excluded)
			}
			p.excluded[skey] = struct{}{}
			p.excludeAttr(p.attrKeyOf(ev))
			p.dropSession(skey)
		}
		return
	}
	// 2. Identity.
	p.normalize(ev, now)

	switch ev.Kind {
	case event.KindActivity:
		p.activity(ev, skey, now, how)
	case event.KindInventory:
		p.inventory(ev, now)
	case event.KindDetection:
		// Detections from another sensor (adapter). They are not ours to
		// re-evaluate; they are routed, filtered by class and summarised.
		p.foreignDetection(ev, now)
	default:
		// posture, health, summary records from collectors and scans.
		p.emit(ev, now, true)
	}
}

// userKind are the surfaces the monitored user can write: they are
// user-integrity whatever the process that read them (DECISIONS A6, A28).
func userSurface(s event.Source) bool {
	switch s {
	case event.SourceHook, event.SourceTranscript, event.SourceOTel, event.SourceAdapter:
		return true
	}
	return false
}

// knownSource reports a Source of the closed vocabulary.
func knownSource(s event.Source) bool {
	switch s {
	case event.SourceHook, event.SourceTranscript, event.SourceProcess, event.SourceScan,
		event.SourceOTel, event.SourceOsquery, event.SourceAdapter, event.SourceSensor:
		return true
	}
	return false
}

// knownToolKind reports a ToolKind of the closed vocabulary.
func knownToolKind(k event.ToolKind) bool {
	switch k {
	case event.ToolShell, event.ToolFileRead, event.ToolFileWrite, event.ToolFileEdit, event.ToolFileList,
		event.ToolWebFetch, event.ToolWebSearch, event.ToolMCP, event.ToolSubagent, event.ToolBrowser, event.ToolOther:
		return true
	}
	return false
}

// normalize sets V, kind, ts, host, integrity, Dedupe and ID, and clears
// what only the pipeline may set.
func (p *Pipeline) normalize(ev *event.Event, now time.Time) {
	if ev.V == 0 {
		ev.V = event.SchemaVersion
	}
	switch ev.Kind {
	case event.KindActivity, event.KindInventory, event.KindPosture, event.KindDetection, event.KindHealth, event.KindSummary:
	default:
		// Closed vocabulary: anything else is treated as activity, which
		// is also what the privacy stage does with unknown kinds.
		ev.Kind = event.KindActivity
	}
	// Emitted is the time this pipeline writes the record (SIEM rules
	// schedule on it) and Sources the surfaces this pipeline correlated; a
	// value a (user-writable) source carries would move the record out of
	// detection windows or claim corroboration that never happened. Detect
	// mode re-evaluates records an earlier pipeline correlated, so it keeps
	// their Sources.
	ev.Emitted = event.Time{}
	if p.mode != ModeDetect {
		ev.Sources = nil
	}
	// Tool.Kind keys per-session counters and the summary: an unknown kind
	// from a user-written record becomes "other" instead of a new key.
	if ev.Tool != nil && ev.Tool.Kind != "" && !knownToolKind(ev.Tool.Kind) {
		ev.Tool.Kind = event.ToolOther
		p.ctr.unknownVocab++
	}
	if ev.TS.IsZero() {
		ev.TS = event.At(now)
	}
	if p.forceHost {
		h := p.o.Host
		ev.Host = &h
	}
	if userSurface(ev.Source) {
		ev.Integrity = event.IntegrityUser
	}
	if ev.Integrity == "" {
		ev.Integrity = p.integrity
	}
	if p.integrity == event.IntegrityUser && ev.Integrity == event.IntegrityRoot {
		// An unprivileged process cannot vouch for anything.
		ev.Integrity = event.IntegrityUser
	}
	if ev.Integrity != event.IntegrityRoot && ev.Integrity != event.IntegrityUser {
		ev.Integrity = event.IntegrityUser
	}

	host, user, agent, sess := idParts(ev)
	if ev.Kind == event.KindActivity {
		if nat := p.naturalKey(ev); nat != "" {
			// Every surface gets the same Dedupe for the same action. It is
			// recomputed even when the source set one, because the host was
			// just forced and a hook running unprivileged may have used a
			// different host id. The user id is part of it so one account
			// can never collapse another's record downstream. A key derived
			// from content (the prompt text) is an HMAC under the identity
			// key, because every other part is in the shipped record.
			ev.Dedupe = event.DedupeKey(host, user, agent, sess, nat, ev.Type)
		}
	}
	if ev.Dedupe == "" {
		if ev.ID == "" {
			// A source id is kept as it is (it is the source's join key);
			// one derived here from content is keyed (contentKey).
			ev.ID = event.StableID(ev.TS.Time, "spoor/engine", string(ev.Source), ev.Type, p.contentKey(ev))
		}
		ev.Dedupe = event.DedupeKey(host, user, agent, sess, "id:"+ev.ID, ev.Type)
	}
	if ev.ID == "" {
		ev.ID = event.StableID(ev.TS.Time, "spoor/engine", string(ev.Source), ev.Dedupe)
	}
}

func idParts(ev *event.Event) (host, user, agent, sess string) {
	if ev.Host != nil {
		host = ev.Host.ID
	}
	if ev.User != nil {
		user = ev.User.ID
	}
	if ev.Agent != nil {
		agent = ev.Agent.ID
	}
	if ev.Session != nil {
		sess = ev.Session.ID
	}
	return
}

// activity handles one activity record.
func (p *Pipeline) activity(ev *event.Event, skey string, now time.Time, how attribution) {
	var s *session
	if skey != "" {
		s = p.sessionFor(ev, skey, now)
	}
	if s != nil && ev.Type == event.TypePromptSubmit {
		p.promptDedupe(ev, s)
	}
	p.observeCoverage(ev, s, now)
	if s != nil {
		// Source is a free string in a user-written record: only the
		// closed vocabulary becomes a key of the session's surfaces.
		if knownSource(ev.Source) {
			s.surfaces[ev.Source] = true
		}
		s.lastWall = now
	}
	if hookEvent, runs, ok := hookRun(ev); ok && s != nil {
		s.noteOTelHookRun(hookEvent, runs, now)
	}
	if ev.Source == event.SourceHook && s != nil && toolRecord(ev) {
		// Only tool hooks are compared with OTel hook-run counts.
		s.hookRecords[ev.Type]++
	}
	switch p.corr.decide(p, ev, s, now, how) {
	case corrHeld, corrDuplicate:
		return
	}
	if how == attrSession {
		// Not folded into a twin: on its own it is not that account's.
		p.withoutAccount(ev, now)
		return
	}
	p.evaluate(ev, s, now)
	if s != nil {
		p.maybeFinal(s, now)
	}
}

// evaluate computes features, runs the rules and writes the activity record
// and any detections; pmu is held.
func (p *Pipeline) evaluate(ev *event.Event, s *session, now time.Time) {
	uid, name := "", ""
	if ev.User != nil {
		uid, name = ev.User.ID, ev.User.Name
	}
	ctx := features.Context{Home: p.homes.home(uid, name, now)}
	if ev.Host != nil {
		ctx.OS = ev.Host.OS
	}
	// Compute is idempotent: the rules engine's own call becomes a no-op,
	// so features see this account's home rather than one engine-wide home.
	features.Compute(ev, ctx)
	p.firstSeen(ev)
	res := p.eng.Eval(ev)
	if res.Timeout {
		p.ctr.ruleTimeouts++
	}
	if flow, _ := ev.Feat["session.secret_flow"].(bool); flow {
		// This record carries a credential value read earlier in the
		// session, in some encoding (base64, hex, URL) the redactor cannot
		// recognise on its own. Detection is done; nothing written from it
		// (record, detections, context, summary) may carry the value.
		p.ctr.flowScrubbed++
		scrubFlow(ev)
		for _, d := range res.Detections {
			scrubFlow(d)
		}
	}
	if s != nil {
		s.add(ev)
	}
	if ev.Kind == event.KindActivity {
		p.emitActivity(ev, s, now)
	}
	for _, d := range res.Detections {
		p.ruleDetection(d, s, now)
	}
	if s != nil {
		s.push(ev, p.contextN)
		if ev.Type == event.TypeSessionEnd {
			s.ended = true
			// Records of the session still waiting for their hook twin
			// belong in its final summary: it is written when the last of
			// them has been processed, and not before HoldFor after the
			// end (maybeFinal).
			s.finalDue = true
			if s.endAt.IsZero() {
				s.endAt = now
			}
		}
	}
}

// maybeFinal writes the final summary of an ended session once none of its
// records is held and HoldFor has passed since the session ended. The wait
// is the correlation hold window: the other surfaces' copies of the
// session's last records (the transcript tailer polls, OTel batches) arrive
// within it, after the SessionEnd hook record that ends the session, and
// the summary's surfaces and coverage must include them. In the real-agent
// run the transcript delivered 0.2 s after SessionEnd, and a summary
// written at once said surfaces [hook], coverage partial, while the
// coverage table said covered. Tick writes it when the window has passed
// (sweepSessions); Close writes it at once.
func (p *Pipeline) maybeFinal(s *session, now time.Time) {
	if !s.finalDue || s.heldN > 0 || now.Sub(s.endAt) < HoldFor {
		return
	}
	s.finalDue = false
	p.summary(s, now, true, "session_end")
}

// emitActivity writes an activity record unless a token bucket is empty
// (limits.go): detection has already run on it either way, so the limit
// only bounds volume, never what is detected.
func (p *Pipeline) emitActivity(ev *event.Event, s *session, now time.Time) {
	at := now
	if p.mode == ModeDetect || p.mode == ModeScan {
		// Replays run at disk speed; their rate is the recorded one.
		at = ev.TS.Time
	}
	if !p.allowActivity(ev, s, at) {
		if s != nil {
			s.suppressed++
		}
		p.ctr.activitySuppressed++
		return
	}
	if out, ok := p.emit(ev, now, false); ok {
		p.corr.noteWritten(ev.Dedupe, out)
	}
}

// inventory evaluates inventory rules (they yield posture failures) and
// routes the asset.
func (p *Pipeline) inventory(ev *event.Event, now time.Time) {
	p.observeInventory(ev, now)
	features.Compute(ev, features.Context{})
	p.firstSeenAsset(ev)
	res := p.eng.Eval(ev)
	p.emit(ev, now, true)
	for _, d := range res.Detections {
		p.ruleDetection(d, nil, now)
	}
}

// stamp labels a finding with the content that produced it, so a rule
// that searches content is attributable: the pack and its version and the
// rules hash come from the rules engine; the set version and the bundle
// version are added here.
func (p *Pipeline) stamp(d *event.Event) {
	if d.Labels == nil {
		d.Labels = map[string]string{}
	}
	if p.rulesVer != "" {
		d.Labels[LabelRulesVersion] = p.rulesVer
	}
	if p.bundleVer != "" {
		d.Labels[LabelBundleVersion] = p.bundleVer
	}
	if _, ok := d.Labels["rules_hash"]; !ok && len(p.rulesHash) >= 12 {
		d.Labels["rules_hash"] = p.rulesHash[:12]
	}
}

// Label keys stamped on findings and heartbeats; they match the names the
// state package reads from heartbeats.
const (
	LabelRulesVersion  = "rules_version"
	LabelBundleVersion = "bundle_version"
)

// ruleDetection handles one record from rules.Result.Detections.
func (p *Pipeline) ruleDetection(d *event.Event, s *session, now time.Time) {
	if d == nil {
		return
	}
	p.stamp(d)
	if d.Kind == event.KindPosture {
		p.emit(d, now, true)
		return
	}
	if d.Detection == nil {
		return
	}
	// Evidence is rebuilt through the privacy allowlist from the record's
	// own fields, Content and Feat: prompt text and tool output can never
	// be evidence outside the full profile, whatever the rule asked for.
	if len(d.Detection.Evidence) > 0 {
		keys := make([]string, 0, len(d.Detection.Evidence))
		for k := range d.Detection.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d.Detection.Evidence = p.pol.Evidence(d, keys)
	}
	p.detection(d, s, now)
}

// foreignDetection routes a detection another sensor produced.
func (p *Pipeline) foreignDetection(d *event.Event, now time.Time) {
	var s *session
	if d.Session != nil && d.Session.ID != "" {
		if el, ok := p.sessions[rules.SessionKey(d)]; ok {
			s = el.Value.(*session)
		}
	}
	if d.Detection == nil {
		// A detection-kind record without a detection is not something any
		// collector produces: keep it local, never ship it as a finding.
		p.ctr.malformed++
		return
	}
	p.detection(d, s, now)
}

// detection applies the class floor and writes a finding with its context.
func (p *Pipeline) detection(d *event.Event, s *session, now time.Time) {
	if s != nil {
		s.addDetection(d.Detection)
	}
	if event.ClassRank(d.Detection.Class) < p.minRank {
		// Signals still count into the session summary (above).
		p.ctr.belowMinClass++
		return
	}
	if _, ok := p.emit(d, now, true); !ok {
		return
	}
	p.ctr.detections++
	if s == nil || p.contextN == 0 || event.ClassRank(d.Detection.Class) < event.ClassRank(event.ClassFinding) {
		return
	}
	for _, c := range p.pol.ContextFor(d.ID, s.ring, p.contextN) {
		if c == nil {
			continue
		}
		p.ctr.contextRecords++
		p.write(c, true, now)
	}
}
