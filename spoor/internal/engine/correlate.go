package engine

import (
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/otelrecv"
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
// correlated, except OTel tool records without a call id in a session that
// has hook records: those can never be matched and would duplicate every
// hook record, so they only corroborate.

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
}

type held struct {
	ev   *event.Event
	key  string
	skey string
	at   time.Time
	done bool
}

type corrFIFO struct {
	key string
	at  time.Time
}

type correlator struct {
	entries map[string]*corrEntry
	fifo    []corrFIFO // insertion order, for expiry and the size cap
	held    []*held    // arrival order
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
	c.put(key, &corrEntry{sources: []event.Source{src}, at: now, primary: true}, now)
}

// decide applies the rules above to ev; pmu is held.
func (c *correlator) decide(p *Pipeline, ev *event.Event, s *session, now time.Time) corrAction {
	if s == nil || naturalKey(ev) == "" {
		if ev.Source == event.SourceOTel && toolRecord(ev) && s != nil && s.surfaces[event.SourceHook] {
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
			// The transcript/OTel twin was waiting for this record.
			ent.held.done = true
			ent.held = nil
			ent.primary, ent.hook = true, true
			ent.sources = addSource(ent.sources, event.SourceHook)
			ev.Sources = append([]event.Source{event.SourceHook}, without(ent.sources, event.SourceHook)...)
			p.ctr.matched++
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
			return corrDuplicate
		default:
			ent.primary, ent.hook = true, true
			ent.sources = addSource(ent.sources, event.SourceHook)
			return corrProcess
		}
	case event.SourceTranscript, event.SourceOTel:
		switch {
		case ent == nil:
			if !holdable(ev) {
				c.put(key, &corrEntry{sources: []event.Source{ev.Source}, at: now, primary: true}, now)
				return corrProcess
			}
			h := &held{ev: ev, key: key, skey: s.key, at: now}
			c.put(key, &corrEntry{sources: []event.Source{ev.Source}, at: now, held: h}, now)
			c.held = append(c.held, h)
			p.ctr.held++
			if len(c.held) > maxHeld {
				p.ctr.heldOverflow++
				p.releaseOne(c.held[0], now)
				c.held = c.held[1:]
			}
			return corrHeld
		default:
			// A second surface for a call already seen: corroboration only.
			ent.sources = addSource(ent.sources, ev.Source)
			if ent.held != nil {
				ent.held.ev.Sources = addSource(ent.held.ev.Sources, ev.Source)
			}
			p.ctr.duplicates++
			return corrDuplicate
		}
	}
	// Root-observed and sensor records are never folded into a hook record.
	return corrProcess
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
		if !all && now.Sub(h.at) < HoldFor {
			break
		}
		p.releaseOne(h, now)
	}
	c.held = c.held[i:]
	if cap(c.held) > 1024 && len(c.held) < cap(c.held)/4 {
		c.held = append([]*held(nil), c.held...)
	}
}

func (p *Pipeline) releaseOne(h *held, now time.Time) {
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
		if toolRecord(h.ev) && h.ev.Tool != nil && h.ev.Tool.UseID != "" {
			s.unmatchedCall(h.ev.Tool.UseID, h.ev.ID)
		}
	}
	p.processHeld(h.ev, s, now)
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
