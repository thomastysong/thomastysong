package sink

import (
	"errors"

	"github.com/thomastysong/spoor/internal/event"
)

// maxDropsInARow is how many consecutive events may be dropped as refused
// by the destination without it accepting anything in between.
const maxDropsInARow = 16

// unprovenError wraps a permanent refusal that the shipper may not act on
// yet (see mayDrop). To the retry loop it is an ordinary failure.
type unprovenError struct{ err error }

func (e *unprovenError) Error() string { return e.err.Error() }
func (e *unprovenError) Unwrap() error { return e.err }

// Permanent is false so the wrapped refusal is retried, not bisected again.
func (e *unprovenError) Permanent() bool { return false }

// mayDrop reports whether a permanently refused event may be discarded.
//
// Dropping is the only way past a record the destination will never take,
// but "permanent" is the destination's claim, and a wrong URL or a proxy in
// the way can answer 400 to everything. So a refusal is only believed from
// a destination that has accepted something in this run, and only for a
// bounded number of events in a row. Otherwise the data stays on disk and
// the shipper keeps retrying, which a misconfiguration can recover from.
func (s *Shipper) mayDrop() bool {
	return s.proven && s.dropsInARow < maxDropsInARow
}

func (s *Shipper) accepted(n int) {
	s.proven, s.dropsInARow = true, 0
	s.count(func(st *ShipperStats) { st.Shipped += uint64(n); st.Batches++ })
}

// deliver writes items to the destination and returns how many leading
// items are settled (acknowledged, or permanently refused and dropped).
func (s *Shipper) deliver(items []item) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	batch := make([]*event.Event, len(items))
	for i := range items {
		batch[i] = items[i].ev
	}
	err := s.dst.Write(batch)
	if err == nil {
		err = s.dst.Flush()
	}
	var rejected *RejectedError
	switch {
	case err == nil:
		s.accepted(len(items))
		return len(items), nil
	case errors.As(err, &rejected):
		// OTLP partial success: the receiver took the request and refused
		// some records without saying which. The protocol forbids resending,
		// and resending would duplicate everything it did accept.
		n := int64(len(items))
		lost := min(rejected.Rejected, n)
		s.accepted(int(n - lost))
		s.count(func(st *ShipperStats) {
			st.Dropped += uint64(lost)
			st.LastError = printable([]byte(err.Error()), 512)
		})
		return len(items), nil
	case !IsPermanent(err):
		return 0, err
	case len(items) == 1:
		if !s.mayDrop() {
			return 0, &unprovenError{err}
		}
		s.dropsInARow++
		s.count(func(st *ShipperStats) {
			st.Dropped++
			st.LastError = printable([]byte(err.Error()), 512)
		})
		return 1, nil
	}
	// The destination refuses this batch as a whole. Halve it to find the
	// records it objects to, so one poisoned event costs one event.
	mid := len(items) / 2
	n, err := s.deliver(items[:mid])
	var unproven *unprovenError
	if n < mid && errors.As(err, &unproven) {
		// The left half is stuck on a refused record and nothing shows yet
		// that the destination accepts anything. Offer it the right half:
		// if it takes any of that, the refusal is about the record.
		m, rerr := s.deliver(items[mid:])
		if !s.mayDrop() {
			return n, err // nothing was accepted, so nothing was sent twice
		}
		k, lerr := s.deliver(items[n:mid])
		if n+k < mid {
			return n + k, lerr
		}
		return mid + m, rerr
	}
	if err != nil || n < mid {
		return n, err
	}
	m, err := s.deliver(items[mid:])
	return mid + m, err
}
