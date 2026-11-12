package engine

import (
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Activity volume (C2 item 11). Every activity record takes a token from two
// buckets: its session's (or, for a record without a session id, its
// account and agent's) and its account's. The account bucket holds
// accountBucketFactor times as much, so a few concurrent sessions are not
// limited by it, while rotating session ids or dropping them (both possible
// in user-written records) cannot lift the volume control. Detection runs
// on every record either way; only writing is limited.

const (
	accountBucketFactor = 8
	maxBuckets          = 4096
)

type bucket struct {
	tokens float64
	refill time.Time
	init   bool
}

// fill refills the bucket for the time elapsed since the last refill.
func (b *bucket) fill(at time.Time, rate, burst float64) {
	if !b.init {
		b.tokens, b.refill, b.init = burst, at, true
		return
	}
	if d := at.Sub(b.refill).Seconds(); d > 0 {
		b.tokens = min(burst, b.tokens+d*rate)
		b.refill = at
	}
}

// bucketFor returns the shared bucket for key, creating it. The map is
// bounded; when it is full it starts over (a reset bucket is full, which
// only ever lets more through for a moment, never less).
func (p *Pipeline) bucketFor(key string) *bucket {
	b := p.buckets[key]
	if b == nil {
		if len(p.buckets) >= maxBuckets {
			clear(p.buckets)
		}
		b = &bucket{}
		p.buckets[key] = b
	}
	return b
}

// allowActivity takes one token from the record's buckets, or none when
// either is empty.
func (p *Pipeline) allowActivity(ev *event.Event, s *session, at time.Time) bool {
	host, _, agent, _ := idParts(ev)
	acct := host + "\x00" + userKey(ev.User)
	var sb *bucket
	if s != nil {
		sb = &s.bkt
	} else {
		sb = p.bucketFor("s\x00" + acct + "\x00" + agent)
	}
	ab := p.bucketFor("a\x00" + acct)
	sb.fill(at, p.rate, p.burst)
	ab.fill(at, p.rate*accountBucketFactor, p.burst*accountBucketFactor)
	if sb.tokens < 1 || ab.tokens < 1 {
		return false
	}
	sb.tokens--
	ab.tokens--
	return true
}
