package engine

import (
	"sort"
	"strconv"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

// counters are totals since the pipeline started; pmu guards them.
type counters struct {
	processed, excluded, malformed, emitRefused                 uint64
	held, released, matched, duplicates, lateHook, heldOverflow uint64
	uncorrelatable, synthesized                                 uint64
	activitySuppressed, belowMinClass, detections               uint64
	contextRecords, summaries, withheld, late                   uint64
	eventsOut, writeErrors, writeDropped, lineDrops             uint64
	localWritten, localDropped, localDiscarded, localErrors     uint64
	stateApplied, stateErrors, baselineErrors                   uint64
	bypassFindings, bypassSignals, ruleTimeouts, flowScrubbed   uint64
	panics, errors                                              uint64
}

// surfaceStat is what the pipeline itself observed of one collector.
type surfaceStat struct {
	events uint64
	last   time.Time
}

func surfaceName(s event.Source) string {
	switch s {
	case event.SourceHook:
		return "hooks"
	case event.SourceTranscript:
		return "transcripts"
	case event.SourceProcess:
		return "processes"
	case event.SourceScan:
		return "scan"
	case event.SourceOTel:
		return "otel"
	case event.SourceOsquery:
		return "osquery"
	case event.SourceAdapter:
		return "adapters"
	}
	return ""
}

func (p *Pipeline) observeSurface(ev *event.Event) {
	if surfaceName(ev.Source) == "" {
		return
	}
	st := p.surfaces[ev.Source]
	if st == nil {
		st = &surfaceStat{}
		p.surfaces[ev.Source] = st
	}
	st.events++
	if ev.TS.Time.After(st.last) {
		st.last = ev.TS.Time
	}
}

// totals returns the counters since start. Names are stable: dashboards
// and the state mapping (state.Counter*) read them.
func (p *Pipeline) totals() map[string]uint64 {
	c := p.ctr
	qd, dd, cd := p.queueDropped.Load(), p.disabledDropped.Load(), p.closedDropped.Load()
	m := map[string]uint64{
		state.CounterEventsIn:   p.ingested.Load(),
		state.CounterEventsOut:  c.eventsOut,
		state.CounterDropped:    qd + dd + cd + c.writeDropped + c.lineDrops,
		state.CounterDetections: c.detections,
		state.CounterErrors:     c.errors,

		"ingest.processed":           c.processed,
		"ingest.queue_dropped":       qd,
		"ingest.disabled_dropped":    dd,
		"ingest.closed_dropped":      cd,
		"ingest.excluded":            c.excluded,
		"ingest.malformed":           c.malformed,
		"correlate.held":             c.held,
		"correlate.released":         c.released,
		"correlate.matched":          c.matched,
		"correlate.duplicates":       c.duplicates,
		"correlate.late_hook":        c.lateHook,
		"correlate.held_overflow":    c.heldOverflow,
		"correlate.uncorrelatable":   c.uncorrelatable,
		"session.synthesized_start":  c.synthesized,
		"session.summaries":          c.summaries,
		"activity.suppressed":        c.activitySuppressed,
		"detections.below_min_class": c.belowMinClass,
		"detections.context":         c.contextRecords,
		"records.late":               c.late,
		"records.withheld":           c.withheld,
		"records.emit_refused":       c.emitRefused,
		"records.linecap_dropped":    c.lineDrops,
		"outbox.write_errors":        c.writeErrors,
		"outbox.dropped":             c.writeDropped,
		"local.written":              c.localWritten,
		"local.dropped":              c.localDropped,
		"local.discarded":            c.localDiscarded,
		"local.write_errors":         c.localErrors,
		"state.applied":              c.stateApplied,
		"state.errors":               c.stateErrors,
		"baseline.errors":            c.baselineErrors,
		"baseline.keys":              uint64(p.bl.Len()),
		"coverage.bypass_findings":   c.bypassFindings,
		"coverage.bypass_signals":    c.bypassSignals,
		"engine.panics":              c.panics,
		"engine.rule_timeouts":       c.ruleTimeouts,
		"engine.sessions":            uint64(len(p.sessions)),
		"engine.held":                uint64(len(p.corr.held)),
	}
	if p.eng != nil {
		for k, v := range p.eng.Stats() {
			m["rules."+k] = v
		}
	}
	return m
}

// heartbeat writes the health record and resets the interval accounting.
// It is content-free: counters, surface states, coverage, versions.
func (p *Pipeline) heartbeat(now time.Time, disabled bool) {
	// Everything written before the heartbeat is reported by it.
	p.flushWrites()
	counters := p.totals()
	names := make([]string, 0, len(p.streams))
	for n := range p.streams {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		st := p.streams[n]
		pre := "stream." + n + "."
		counters[pre+"emitted"] = st.emitted
		counters[pre+"dropped"] = st.dropped
		counters[pre+"truncated"] = st.truncated
		counters[pre+"first_seq"] = st.firstSeq
		counters[pre+"last_seq"] = st.lastSeq
	}
	if p.o.Gauges != nil {
		for k, v := range p.o.Gauges() {
			if _, taken := counters[k]; !taken && k != "" {
				counters[k] = v
			}
		}
	}
	h := &event.Health{
		SensorVersion: p.o.SensorVersion,
		Mode:          p.mode,
		UptimeS:       int64(now.Sub(p.started) / time.Second),
		Counters:      counters,
		Surfaces:      p.surfaceStatus(disabled),
		RulesCount:    p.set.Count(),
		RulesHash:     p.rulesHash,
	}
	if p.o.Catalog != nil {
		h.CatalogVer = p.o.Catalog.Version()
	}
	if !disabled {
		h.Coverage = p.coverage(now)
	}
	ev := &event.Event{
		V:         event.SchemaVersion,
		TS:        event.At(now),
		Kind:      event.KindHealth,
		Type:      event.TypeHealthHeartbeat,
		Source:    event.SourceSensor,
		Fidelity:  event.FidelityObserved,
		Integrity: p.integrity,
		Health:    h,
		Labels: map[string]string{
			state.LabelProfile: string(p.pol.Profile),
			"status":           "ok",
		},
	}
	if ev.Labels[state.LabelProfile] == "" {
		ev.Labels[state.LabelProfile] = "minimal"
	}
	if p.rulesVer != "" {
		ev.Labels[state.LabelRulesVersion] = p.rulesVer
	}
	if p.bundleVer != "" {
		ev.Labels[state.LabelBundleVersion] = p.bundleVer
	}
	if p.o.HostIDSource != "" {
		ev.Labels[state.LabelHostIDSource] = p.o.HostIDSource
	}
	if disabled {
		ev.Labels["status"] = "disabled"
	} else if p.ctr.errors > 0 && p.lastWriteErr != "" {
		ev.Labels["last_error"] = p.lastWriteErr
	}
	if p.forceHost {
		hh := p.o.Host
		ev.Host = &hh
	}
	host, _, _, _ := idParts(ev)
	ev.Dedupe = event.DedupeKey(host, p.writer, "heartbeat", strconv.FormatInt(now.UnixNano(), 10))
	ev.ID = event.StableID(now, "spoor/heartbeat", p.writer, ev.Dedupe)
	// Interval accounting restarts now; this heartbeat's own write belongs
	// to the next interval.
	p.streams = map[string]*streamStat{}
	p.lastHeartbeat = now
	// While disabled the heartbeat is not applied to the state DB: Fleet's
	// freshness policy must fail while nothing is being collected.
	p.emit(ev, now, !disabled)
}

// surfaceStatus merges what the pipeline saw with what the daemon reports
// (schema drift, errors); daemon fields win, counts come from here when
// the daemon has none.
func (p *Pipeline) surfaceStatus(disabled bool) []event.SurfaceStatus {
	by := map[string]*event.SurfaceStatus{}
	var order []string
	for src, st := range p.surfaces {
		n := surfaceName(src)
		by[n] = &event.SurfaceStatus{Name: n, Status: "ok", Events: st.events, LastEvent: event.At(st.last)}
		order = append(order, n)
	}
	if p.o.Surfaces != nil {
		for _, s := range p.o.Surfaces() {
			if s.Name == "" {
				continue
			}
			cur, ok := by[s.Name]
			if !ok {
				c := s
				by[s.Name] = &c
				order = append(order, s.Name)
				continue
			}
			ev, last := cur.Events, cur.LastEvent
			*cur = s
			if cur.Events == 0 {
				cur.Events = ev
			}
			if cur.LastEvent.IsZero() {
				cur.LastEvent = last
			}
		}
	}
	sort.Strings(order)
	out := make([]event.SurfaceStatus, 0, len(order))
	for _, n := range order {
		s := *by[n]
		if s.Status == "" {
			s.Status = "ok"
		}
		if disabled {
			s.Status, s.Reason = "disabled", "kill_switch"
		}
		out = append(out, s)
	}
	return out
}
