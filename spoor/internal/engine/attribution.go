package engine

import (
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Account attribution for records that arrive without one (OTel).
//
// The OTel receiver listens on loopback, where TCP carries no portable peer
// identity, so its records have no User. Sessions, Dedupe and coverage are
// keyed by the account, so an account-less OTel record of a call the hook
// already reported would never meet its twin: it would become a second
// activity record in a second, account-less session, and the OTel hook-run
// counts would never be compared with that account's hook records.
//
// The engine therefore attributes such a record to the one live session,
// with an account, that has the same host, agent and session id:
//
//   - exactly one: the record takes that session's account. Because any
//     local user can post OTel, an attributed record only corroborates and
//     is compared: it adds its surface, folds into its twin, feeds the
//     hook-run comparison and, unmatched, is written as that session's
//     activity, but it never counts as a tool call the hook missed (the
//     input of the hook-bypass finding), so one account cannot push another
//     towards a finding with forged calls.
//   - several (two accounts claim the same session id, which only a forgery
//     produces): the record is dropped and counted.
//   - none yet: the record waits up to HoldFor (OTel batches usually arrive
//     after the hook record, but not always); a session created for the
//     key in the meantime adopts it. After the wait it is processed without
//     an account, so an agent that only OTel reports on keeps its coverage.
//     Such records never wait again for a hook twin (a hook record always
//     has an account and could never match).
//   - an excluded session has the key: the record is excluded too.

// attribution says where an activity record's account came from.
type attribution uint8

const (
	attrOwn     attribution = iota // the collector established it (or there is none to find)
	attrSession                    // OTel record given the account of the one live session with its id
	attrNone                       // OTel record no account's session claimed within HoldFor
)

// pendingRec is an OTel record waiting for its account.
type pendingRec struct {
	ev  *event.Event
	key string
	at  time.Time
}

// needsAccount reports whether ev is an OTel record without an account that
// names a session it could be attributed to.
func needsAccount(ev *event.Event) bool {
	if ev.Source != event.SourceOTel {
		return false
	}
	if ev.User != nil && (ev.User.ID != "" || ev.User.Name != "") {
		return false
	}
	return ev.Session != nil && ev.Session.ID != "" && ev.Agent != nil && ev.Agent.ID != ""
}

func attrKey(host, agent, sid string) string {
	return host + "\x00" + agent + "\x00" + sid
}

// attrKeyOf is the attribution key of an incoming record: the host it will
// carry after normalize (the forced host when there is one).
func (p *Pipeline) attrKeyOf(ev *event.Event) string {
	host := ""
	if p.forceHost {
		host = p.o.Host.ID
	} else if ev.Host != nil {
		host = ev.Host.ID
	}
	agent, sid := "", ""
	if ev.Agent != nil {
		agent = ev.Agent.ID
	}
	if ev.Session != nil {
		sid = ev.Session.ID
	}
	if agent == "" || sid == "" {
		return ""
	}
	return attrKey(host, agent, sid)
}

// indexSession makes a new session with an account findable for
// attribution, and schedules the adoption of records waiting for it.
func (p *Pipeline) indexSession(s *session) {
	if s.user == nil || userKey(s.user) == "" || s.agent == nil || s.agent.ID == "" || s.sess.ID == "" {
		return
	}
	host := ""
	if s.host != nil {
		host = s.host.ID
	}
	s.attrKey = attrKey(host, s.agent.ID, s.sess.ID)
	set := p.attrIdx[s.attrKey]
	if set == nil {
		set = map[string]struct{}{}
		p.attrIdx[s.attrKey] = set
	}
	set[s.key] = struct{}{}
	if p.pendingKeys[s.attrKey] > 0 {
		p.adopt = append(p.adopt, s.attrKey)
	}
}

func (p *Pipeline) unindexSession(s *session) {
	if s.attrKey == "" {
		return
	}
	if set := p.attrIdx[s.attrKey]; set != nil {
		delete(set, s.key)
		if len(set) == 0 {
			delete(p.attrIdx, s.attrKey)
		}
	}
}

// excludeAttr remembers that the session behind key is excluded, so OTel
// records of it are excluded too (they carry nothing an exclusion could
// match on).
func (p *Pipeline) excludeAttr(key string) {
	if key == "" {
		return
	}
	if len(p.attrExcl) >= maxExcluded {
		clear(p.attrExcl)
	}
	p.attrExcl[key] = struct{}{}
}

// attribute tries to give ev an account. ok reports whether ev should be
// processed now (with how); otherwise it was queued, excluded or dropped,
// and counted. final is set after the wait: no candidate then means "no
// account".
func (p *Pipeline) attribute(ev *event.Event, now time.Time, final bool) (how attribution, ok bool) {
	k := p.attrKeyOf(ev)
	if _, excl := p.attrExcl[k]; excl {
		p.ctr.excluded++
		return attrOwn, false
	}
	set := p.attrIdx[k]
	if len(set) > 1 {
		p.ctr.otelAmbiguous++
		return attrOwn, false
	}
	for sk := range set {
		if el, live := p.sessions[sk]; live {
			u := *el.Value.(*session).user
			ev.User = &u
			p.ctr.otelAttributed++
			return attrSession, true
		}
	}
	if final {
		p.ctr.otelUnattributed++
		return attrNone, true
	}
	p.pend(ev, k, now)
	return attrOwn, false
}

func (p *Pipeline) pend(ev *event.Event, key string, now time.Time) {
	p.pending = append(p.pending, &pendingRec{ev: ev, key: key, at: now})
	p.pendingKeys[key]++
	p.ctr.otelPending++
	if len(p.pending) > maxHeld {
		// Bounded: the oldest waits no longer.
		r := p.pending[0]
		p.pending = p.pending[1:]
		p.unpend(r)
		p.ctr.heldOverflow++
		p.resolvePending(r, now, true)
	}
}

func (p *Pipeline) unpend(r *pendingRec) {
	if p.pendingKeys[r.key] <= 1 {
		delete(p.pendingKeys, r.key)
	} else {
		p.pendingKeys[r.key]--
	}
}

// resolvePending attributes a waiting record again and processes it.
func (p *Pipeline) resolvePending(r *pendingRec, now time.Time, final bool) {
	how, ok := p.attribute(r.ev, now, final)
	if ok {
		p.processAsSafe(r.ev, now, how)
	}
}

// adoptPending processes the records that were waiting for a session that
// has just been created. It runs after the record that created the session,
// so that record is processed first, as it arrived first.
func (p *Pipeline) adoptPending(now time.Time) {
	for len(p.adopt) > 0 {
		k := p.adopt[0]
		p.adopt = p.adopt[1:]
		if p.pendingKeys[k] == 0 {
			continue
		}
		var take []*pendingRec
		keep := p.pending[:0:0]
		for _, r := range p.pending {
			if r.key == k {
				take = append(take, r)
				p.unpend(r)
			} else {
				keep = append(keep, r)
			}
		}
		p.pending = keep
		for _, r := range take {
			p.resolvePending(r, now, false)
		}
	}
}

// releasePending ends the wait of records older than HoldFor (all of them
// when closing).
func (p *Pipeline) releasePending(now time.Time, all bool) {
	i := 0
	for ; i < len(p.pending); i++ {
		if !all && now.Sub(p.pending[i].at) < HoldFor {
			break
		}
	}
	if i == 0 {
		return
	}
	due := p.pending[:i]
	p.pending = append([]*pendingRec(nil), p.pending[i:]...)
	for _, r := range due {
		p.unpend(r)
	}
	for _, r := range due {
		p.resolvePending(r, now, true)
	}
}
