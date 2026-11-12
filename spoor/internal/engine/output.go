package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/privacy"
)

// Output (C2 items 12 and 14, Addendum: late events and line cap).
//
// Every record goes through Policy.Emit, which redacts it and says whether
// it ships (outbox) or stays on the host (local ring). The writer then sets
// Writer (this process's random id), Seq (monotonic per writer and stream,
// starting at 1), Emitted (when the record is written more than LateAfter
// after its ts) and the operator labels, and checks the encoded line
// against the cap. Records are buffered and written in one Write per
// processing round. Per-stream accounting {emitted, dropped, truncated,
// first_seq, last_seq} is kept for the heartbeat interval: a consumer of one
// destination can verify that every sequence number of the interval
// arrived.

type streamStat struct {
	emitted, dropped, truncated uint64
	firstSeq, lastSeq           uint64
}

func (p *Pipeline) stream(name string) *streamStat {
	st := p.streams[name]
	if st == nil {
		st = &streamStat{}
		p.streams[name] = st
	}
	return st
}

// emit redacts src and writes it; toState also queues the shipped record
// for the state database. It returns the written record.
func (p *Pipeline) emit(src *event.Event, now time.Time, toState bool) (*event.Event, bool) {
	if p.o.Local == nil && src.Kind == event.KindActivity && p.activityStaysLocal() {
		// Nowhere to write it: skip the redaction work.
		p.ctr.localDiscarded++
		return nil, false
	}
	in := src
	if len(p.labels) > 0 {
		// Operator labels go through the privacy stage like every other
		// field (caps, line fit); the source record is not modified.
		c := *src
		c.Labels = make(map[string]string, len(src.Labels)+len(p.labels))
		for k, v := range p.labels {
			c.Labels[k] = v
		}
		for k, v := range src.Labels {
			c.Labels[k] = v
		}
		in = &c
	}
	out, ship, ok := p.pol.Emit(in)
	if !ok || out == nil {
		p.ctr.emitRefused++
		return nil, false
	}
	if !p.write(out, ship, now) {
		return out, false
	}
	if toState && ship && p.o.State != nil {
		p.stateAdd(out, src)
	}
	return out, true
}

func (p *Pipeline) streamAllowed(stream string) bool {
	return p.streamsOK == nil || p.streamsOK[stream]
}

// write routes a rendered record to the outbox (ship) or the local ring.
func (p *Pipeline) write(out *event.Event, ship bool, now time.Time) bool {
	name := out.Kind.Stream()
	if ship && !p.streamAllowed(name) {
		// The operator restricted the shipped streams: keep it local.
		ship = false
		p.ctr.withheld++
	}
	if !ship && p.o.Local == nil {
		p.ctr.localDiscarded++
		return false
	}
	p.prepare(out, now)
	if ship {
		out.Writer = p.writer
		p.seq[name]++
		out.Seq = p.seq[name]
		if !p.fitLine(out) {
			p.stream(name).dropped++
			p.ctr.lineDrops++
			return false
		}
		p.outbox = append(p.outbox, out)
		return true
	}
	out.Writer = p.writer + localSuffix
	p.lseq[name]++
	out.Seq = p.lseq[name]
	if !p.fitLine(out) {
		p.ctr.lineDrops++
		return false
	}
	p.local = append(p.local, out)
	return true
}

// prepare sets Emitted for late records and adds the operator labels.
func (p *Pipeline) prepare(out *event.Event, now time.Time) {
	if !out.TS.IsZero() && now.Sub(out.TS.Time) > LateAfter {
		out.Emitted = event.At(now)
		p.ctr.late++
	}
	if len(p.labels) > 0 {
		if out.Labels == nil {
			out.Labels = make(map[string]string, len(p.labels))
		}
		for k, v := range p.labels {
			if _, ok := out.Labels[k]; !ok {
				out.Labels[k] = v
			}
		}
	}
}

// maxLine is the encoded-line cap, newline included.
func (p *Pipeline) maxLine() int {
	n := p.pol.MaxLine
	if n <= 0 {
		n = privacy.DefaultMaxLine
	}
	return max(n, privacy.MinMaxLine)
}

// fitLine enforces the cap on the ENCODED line (JSON escaping can inflate
// a value up to six times). Emit already fits a record under the cap minus
// privacy.LineHeadroom; what the writer adds (writer, seq, emitted,
// operator labels) is checked here. Operator labels are dropped first; a
// record that still does not fit is dropped and counted, never split.
func (p *Pipeline) fitLine(out *event.Event) bool {
	limit := p.maxLine()
	b, err := json.Marshal(out)
	if err != nil {
		p.ctr.errors++
		return false
	}
	if len(b)+1 <= limit {
		return true
	}
	if len(p.labels) > 0 && out.Labels != nil {
		for k := range p.labels {
			delete(out.Labels, k)
		}
		out.Truncated = append(out.Truncated, "labels")
		if b, err = json.Marshal(out); err == nil && len(b)+1 <= limit {
			return true
		}
	}
	return false
}

// lineFits reports whether a record already accepted by write still fits
// the line cap (after a change to it, such as a corroborating surface).
func (p *Pipeline) lineFits(out *event.Event) bool {
	b, err := json.Marshal(out)
	return err == nil && len(b)+1 <= p.maxLine()
}

// flushWrites hands the buffered records to the sinks and does the
// per-stream accounting.
func (p *Pipeline) flushWrites() {
	// From here on the buffered records are written: a twin arriving later
	// is counted, not added (correlate.go).
	p.corr.flushed()
	if len(p.outbox) > 0 {
		batch := p.outbox
		p.outbox = nil
		err := p.o.Outbox.Write(batch)
		if err != nil {
			p.ctr.errors++
			p.ctr.writeErrors++
			p.lastWriteErr = "outbox.write"
		}
		for _, r := range batch {
			st := p.stream(r.Kind.Stream())
			if err != nil {
				st.dropped++
				p.ctr.writeDropped++
				continue
			}
			st.emitted++
			p.ctr.eventsOut++
			if st.firstSeq == 0 || r.Seq < st.firstSeq {
				st.firstSeq = r.Seq
			}
			if r.Seq > st.lastSeq {
				st.lastSeq = r.Seq
			}
			if len(r.Truncated) > 0 {
				st.truncated++
			}
		}
	}
	if len(p.local) > 0 {
		batch := p.local
		p.local = nil
		if err := p.o.Local.Write(batch); err != nil {
			p.ctr.errors++
			p.ctr.localErrors++
			p.lastWriteErr = "local.write"
			p.ctr.localDropped += uint64(len(batch))
		} else {
			p.ctr.localWritten += uint64(len(batch))
		}
	}
}

// stateAdd queues a shipped record for the state database. The state gets
// what ships (so pseudonyms and redaction apply to what Fleet reads too),
// except that a detection's dedup key, which the privacy stage drops when
// there is no tenant key, is replaced by an HMAC under a per-process random
// key: rows still fold within this process's life, and nothing in the file
// lets a reader test guesses about the content behind it.
func (p *Pipeline) stateAdd(out, src *event.Event) {
	switch out.Kind {
	case event.KindInventory, event.KindPosture, event.KindSummary:
	case event.KindHealth:
		if out.Type != event.TypeHealthHeartbeat {
			return
		}
	case event.KindDetection:
		if out.Detection == nil || out.Type == privacy.TypeContext {
			return
		}
	default:
		return
	}
	c := *out
	if out.Detection != nil {
		d := *out.Detection
		if d.DedupKey == "" && src.Detection != nil && src.Detection.DedupKey != "" {
			m := hmac.New(sha256.New, p.salt)
			m.Write([]byte(src.Detection.DedupKey))
			d.DedupKey = "l" + hex.EncodeToString(m.Sum(nil)[:12])
		}
		c.Detection = &d
	}
	p.stateQ = append(p.stateQ, &c)
}

// flushState applies the batched state changes; pmu is held.
func (p *Pipeline) flushState(now time.Time) {
	st := p.o.State
	if st == nil {
		p.stateQ = nil
		return
	}
	if len(p.stateQ) > 0 {
		batch := p.stateQ
		p.stateQ = nil
		if err := st.Apply(batch); err != nil {
			p.ctr.stateErrors++
			p.ctr.errors++
		} else {
			p.ctr.stateApplied += uint64(len(batch))
		}
	}
	cov := p.coverage(now)
	for i := range cov {
		cov[i].User, _ = p.pseudoUser(cov[i].User, "")
	}
	if err := st.SetCoverage(cov); err != nil {
		p.ctr.stateErrors++
		p.ctr.errors++
	}
	if err := st.SetAgentProcesses(p.stateProcesses()); err != nil {
		p.ctr.stateErrors++
		p.ctr.errors++
	}
}

// activityStaysLocal reports whether activity records stay on the host:
// the minimal profile (also what an unknown profile falls back to), or an
// operator stream list without "activity".
func (p *Pipeline) activityStaysLocal() bool {
	if !p.streamAllowed("activity") {
		return true
	}
	prof, err := privacy.ParseProfile(string(p.pol.Profile))
	return err != nil || prof == privacy.ProfileMinimal
}
