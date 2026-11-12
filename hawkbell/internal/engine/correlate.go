package engine

import (
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/otelrecv"
)

// Cross-surface correlation (BUILD-C C2 item 3, DECISIONS A22).
//
// One activity record per action, and the hook is the primary surface. The
// key is the record's Dedupe, which normalize derives from (host, user,
// agent, session, tool-call id or prompt digest, type) for every surface, so
// a hook record and the transcript or OTel record of the same call share it
// and records of different accounts never do.
//
//   - hook first: processed; a later transcript or OTel record of the call
//     only adds its surface to the session.
//   - transcript or OTel tool record first: held for HoldFor. If the hook
//     record arrives in time the held one is dropped and its surface added
//     to the hook record's Sources; otherwise it is processed as the
//     activity record itself and counted as a tool call the hook did not
//     report (the input of the hook-bypass logic).
//   - a hook record that arrives after its transcript twin was released is
//     a late hook: it adds its surface and takes the call off the
//     unmatched list.
//
// Records without a natural key (no tool-call id, no prompt text) are not
// correlated, except OTel tool and prompt records in a session that has
// hook or transcript records: Gemini CLI's telemetry has no call id, and
// prompt text is redacted from OTel by default, so such a record can never
// be matched and would duplicate the other surface's record of the same
// action; it only corroborates.
//
// A held record is counted on its session (heldN): a session that ends
// while some of its records are held writes its final summary once they
// have been processed, so the one final summary is complete.
//
// Corroboration on the record. When a twin from another surface collapses
// into an activity record, that surface goes into the Sources of the record
// that is written, if it has not been written yet: a held transcript or
// OTel record whose hook arrives (Sources [hook, transcript]), or a record
// still buffered in this processing round (written and corroborated within
// one batch). A record that has already been handed to its sink cannot
// change, so a twin that arrives after that is counted instead: heartbeat
// correlate.corroborated_after_write and, per session, the summary label
// corroborated_after_write, once per record however many surfaces arrive
// late (Claude Code with OTel on reports one tool call on three), so
// either is a subset of correlate.corroborated and of the label
// corroborated. In the daemon the hook record is written within
// milliseconds and the transcript tailer delivers its copy a poll later, so
// hook-first corroboration is usually the counted kind; the session
// summary's Surfaces and coverage show it as well.
// correlate.corroborated counts every activity record another surface
// confirmed, written with it or counted.

type corrAction int

const (
	corrProcess corrAction = iota
	corrHeld
	corrDuplicate
)

type corrEntry struct {
	sources []event.Source
	at      time.Time
	primary bool // a record for the key was processed
	hook    bool // a hook record for the key was seen
	held    *held
	// out is the activity record written for the key while it is still
	// buffered (until the next flushWrites): a twin that arrives meanwhile
	// is added to its Sources.
	out *event.Event
	// corroborated: another surface confirmed the action (counted once).
	corroborated bool
	// late: a surface confirmed the action after its record was written
	// (counted once, however many such surfaces come).
	late bool
	// synthetic: the entry of a session start the pipeline synthesized.
	synthetic bool
}

type held struct {
	ev   *event.Event
	key  string
	skey string
	at   time.Time
	done bool
	// noBypass: an OTel record whose account was attributed through its
	// session id (attribution.go). Released unmatched, it is not a tool
	// call the hook missed, and it is processed without the account.
	noBypass bool
}

type corrFIFO struct {
	key string
	at  time.Time
}

type correlator struct {
	entries map[string]*corrEntry
	fifo    []corrFIFO // insertion order, for expiry and the size cap
	held    []*held    // arrival order
	// buffered are the entries whose out record is not flushed yet.
	buffered []*corrEntry
}

func newCorrelator() *correlator {
	return &correlator{entries: map[string]*corrEntry{}}
}

// holdable records wait for their hook twin. Prompts are held too, so the
// hook stays the primary record whichever surface is faster; only tool
// calls count as unmatched when released.
func holdable(ev *event.Event) bool {
	switch ev.Type {
	case event.TypeToolPre, event.TypeToolPost, event.TypePromptSubmit:
		return true
	}
	return false
}

func toolRecord(ev *event.Event) bool {
	return ev.Type == event.TypeToolPre || ev.Type == event.TypeToolPost
}

func addSource(l []event.Source, s event.Source) []event.Source {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

func (c *correlator) put(key string, e *corrEntry, now time.Time) {
	c.entries[key] = e
	c.fifo = append(c.fifo, corrFIFO{key, now})
	for n := len(c.fifo); n > 0 && len(c.entries) > maxCorrelation && len(c.fifo) > 0; n-- {
		c.evictFront()
	}
}

func (c *correlator) evictFront() {
	f := c.fifo[0]
	c.fifo = c.fifo[1:]
	e, ok := c.entries[f.key]
	if !ok || !e.at.Equal(f.at) {
		return
	}
	if e.held != nil {
		// Still waiting for its hook: keep it, and its expiry slot.
		c.fifo = append(c.fifo, f)
		return
	}
	delete(c.entries, f.key)
}

// expire forgets keys older than corrTTL. A key whose entry was refreshed
// later than its FIFO slot is kept (its later slot expires it).
func (c *correlator) expire(now time.Time) {
	for n := len(c.fifo); n > 0 && len(c.fifo) > 0 && now.Sub(c.fifo[0].at) > corrTTL; n-- {
		c.evictFront()
	}
	if cap(c.fifo) > 1024 && len(c.fifo) < cap(c.fifo)/4 {
		c.fifo = append([]corrFIFO(nil), c.fifo...)
	}
}

// markPrimary records that a record for key was processed by a surface
// that is not part of the hook/transcript pairing (the synthesized session
// start).
func (c *correlator) markPrimary(key string, src event.Source, now time.Time) {
	if key == "" {
		return
	}
	if e, ok := c.entries[key]; ok {
		e.primary = true
		e.sources = addSource(e.sources, src)
		return
	}
	c.put(key, &corrEntry{sources: []event.Source{src}, at: now, primary: true, synthetic: true}, now)
}

// decide applies the rules above to ev; pmu is held.
func (c *correlator) decide(p *Pipeline, ev *event.Event, s *session, now time.Time, how attribution) corrAction {
	if s == nil || !hasNaturalKey(ev) {
		if ev.Source == event.SourceOTel && s != nil && (toolRecord(ev) || ev.Type == event.TypePromptSubmit) &&
			(s.surfaces[event.SourceHook] || s.surfaces[event.SourceTranscript]) {
			p.ctr.uncorrelatable++
			return corrDuplicate
		}
		return corrProcess
	}
	key := ev.Dedupe
	ent := c.entries[key]
	switch ev.Source {
	case event.SourceHook:
		switch {
		case ent == nil:
			c.put(key, &corrEntry{sources: []event.Source{event.SourceHook}, at: now, primary: true, hook: true}, now)
			return corrProcess
		case ent.held != nil:
			// The transcript/OTel twin was waiting for this record: the
			// record written now carries both surfaces.
			ent.held.done = true
			if s.heldN > 0 {
				s.heldN--
			}
			ent.held = nil
			ent.primary, ent.hook = true, true
			ent.sources = addSource(ent.sources, event.SourceHook)
			ev.Sources = append([]event.Source{event.SourceHook}, without(ent.sources, event.SourceHook)...)
			p.ctr.matched++
			p.markCorroborated(ent, s)
			return corrProcess
		case ent.hook:
			// The same hook record again (at-least-once spool replay).
			p.ctr.duplicates++
			return corrDuplicate
		case ent.primary:
			// The twin was already released as the activity record.
			ent.hook = true
			ent.sources = addSource(ent.sources, event.SourceHook)
			if ev.Tool != nil {
				s.matchedLate(ev.Tool.UseID)
			}
			p.ctr.lateHook++
			p.corroborate(ent, event.SourceHook, s)
			return corrDuplicate
		default:
			ent.primary, ent.hook = true, true
			ent.sources = addSource(ent.sources, event.SourceHook)
			return corrProcess
		}
	case event.SourceTranscript, event.SourceOTel:
		switch {
		case ent == nil:
			// A record without an account never waits: no hook record
			// (which always has one) could match it.
			if !holdable(ev) || how == attrNone {
				c.put(key, &corrEntry{sources: []event.Source{ev.Source}, at: now, primary: true}, now)
				return corrProcess
			}
			h := &held{ev: ev, key: key, skey: s.key, at: now, noBypass: how != attrOwn}
			c.put(key, &corrEntry{sources: []event.Source{ev.Source}, at: now, held: h}, now)
			c.held = append(c.held, h)
			s.heldN++
			p.ctr.held++
			if len(c.held) > maxHeld {
				p.ctr.heldOverflow++
				p.releaseOne(c.held[0], now, false)
				c.held = c.held[1:]
			}
			return corrHeld
		default:
			// A second surface for a call already seen: corroboration only.
			known := hasSource(ent.sources, ev.Source)
			ent.sources = addSource(ent.sources, ev.Source)
			p.ctr.duplicates++
			if ent.held != nil {
				// Not written yet: the held record carries it (and the hook
				// record, should the hook still come, takes ent.sources).
				ent.held.ev.Sources = addSource(ent.held.ev.Sources, ev.Source)
				return corrDuplicate
			}
			if ent.primary && !known {
				p.corroborate(ent, ev.Source, s)
			}
			return corrDuplicate
		}
	}
	// Root-observed and sensor records are never folded into a hook record.
	return corrProcess
}

func hasSource(l []event.Source, s event.Source) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// corroborate records that surface src also reported the action of ent,
// whose activity record was processed already: added to that record's
// Sources while it is still buffered, counted once it has been written.
// The session start the pipeline synthesized is inferred, not reported by
// a surface, and is not corroborated.
func (p *Pipeline) corroborate(ent *corrEntry, src event.Source, s *session) {
	if ent.synthetic {
		return
	}
	if out := ent.out; out != nil && out.Source != src {
		orig := out.Sources
		next := append([]event.Source(nil), orig...)
		if len(next) == 0 {
			next = []event.Source{out.Source}
		}
		out.Sources = addSource(next, src)
		if p.lineFits(out) {
			p.markCorroborated(ent, s)
			return
		}
		// The record is at the line cap: it is written as it was.
		out.Sources = orig
	}
	p.markCorroborated(ent, s)
	if ent.late {
		return
	}
	ent.late = true
	p.ctr.corroboratedLate++
	if s != nil {
		s.corroboratedLate++
	}
}

// markCorroborated counts an action that another surface confirmed, once.
func (p *Pipeline) markCorroborated(ent *corrEntry, s *session) {
	if ent.corroborated {
		return
	}
	ent.corroborated = true
	p.ctr.corroborated++
	if s != nil {
		s.corroborated++
	}
}

// noteWritten links an activity record that was just buffered for writing
// to its correlation entry, until the next flush.
func (c *correlator) noteWritten(key string, out *event.Event) {
	if key == "" || out == nil {
		return
	}
	if e := c.entries[key]; e != nil {
		e.out = out
		c.buffered = append(c.buffered, e)
	}
}

// flushed forgets the buffered records: they have reached their sinks.
func (c *correlator) flushed() {
	for _, e := range c.buffered {
		e.out = nil
	}
	clear(c.buffered)
	c.buffered = c.buffered[:0]
	if cap(c.buffered) > 4096 {
		c.buffered = nil
	}
}

func without(l []event.Source, s event.Source) []event.Source {
	out := make([]event.Source, 0, len(l))
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// releaseHeld processes held records whose hook did not arrive in time
// (all of them when closing).
func (p *Pipeline) releaseHeld(now time.Time, all bool) {
	c := p.corr
	i := 0
	for ; i < len(c.held); i++ {
		h := c.held[i]
		due := now.Sub(h.at) >= HoldFor
		if !all && !due {
			break
		}
		// Released early (shutdown), a record has not had its chance to be
		// matched and does not count as a call the hook missed.
		p.releaseOne(h, now, due)
	}
	c.held = c.held[i:]
	if cap(c.held) > 1024 && len(c.held) < cap(c.held)/4 {
		c.held = append([]*held(nil), c.held...)
	}
}

func (p *Pipeline) releaseOne(h *held, now time.Time, unmatched bool) {
	if h.done {
		return
	}
	h.done = true
	ent := p.corr.entries[h.key]
	if ent != nil && ent.held == h {
		ent.held = nil
		ent.primary = true
		h.ev.Sources = append([]event.Source(nil), ent.sources...)
	}
	p.ctr.released++
	var s *session
	if el, ok := p.sessions[h.skey]; ok {
		s = el.Value.(*session)
		if s.heldN > 0 {
			s.heldN--
		}
		if unmatched && !h.noBypass && toolRecord(h.ev) && h.ev.Tool != nil && h.ev.Tool.UseID != "" {
			s.unmatchedCall(h.ev.Tool.UseID, h.ev.ID)
		}
	}
	if h.noBypass {
		// An attributed OTel record without its twin (attribution.go).
		p.withoutAccount(h.ev, now)
	} else {
		p.processHeld(h.ev, s, now)
	}
	if s != nil {
		p.maybeFinal(s, now)
	}
}

// processHeld evaluates a released record. Its session may have been
// evicted meanwhile; it is then processed without session bookkeeping.
func (p *Pipeline) processHeld(ev *event.Event, s *session, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			p.ctr.panics++
			p.ctr.errors++
		}
	}()
	p.evaluate(ev, s, now)
}

// hookRun wraps otelrecv.IsHookRun.
func hookRun(ev *event.Event) (string, int, bool) {
	if ev.Source != event.SourceOTel {
		return "", 0, false
	}
	return otelrecv.IsHookRun(ev)
}
