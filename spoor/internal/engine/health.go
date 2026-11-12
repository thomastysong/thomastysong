package engine

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/state"
)

// counters are totals since the pipeline started; pmu guards them.
type counters struct {
	processed, excluded, malformed, emitRefused                  uint64
	held, released, matched, duplicates, lateHook, heldOverflow  uint64
	uncorrelatable, synthesized                                  uint64
	activitySuppressed, belowMinClass, detections                uint64
	contextRecords, summaries, withheld, late                    uint64
	eventsOut, writeErrors, writeDropped, lineDrops              uint64
	localWritten, localDropped, localDiscarded, localErrors      uint64
	stateApplied, stateErrors, baselineErrors                    uint64
	bypassFindings, bypassSignals, ruleTimeouts, flowScrubbed    uint64
	panics, errors                                               uint64
	otelAttributed, otelUnattributed, otelAmbiguous, otelPending uint64
	otelUnmatched                                                uint64
	covUnknownAgent, untrustedProcess, unknownVocab              uint64
	firstSeenHosts, firstSeenMCP                                 uint64
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

// observeSurface counts an arriving record for its collector. The last
// event time is the arrival time: a record's ts is whatever its writer put
// there (a hook record dated 2099 would make the surface look fresh for
// good, and hooks that fall silent would never read as stale).
func (p *Pipeline) observeSurface(ev *event.Event, now time.Time) {
	if surfaceName(ev.Source) == "" {
		return
	}
	st := p.surfaces[ev.Source]
	if st == nil {
		st = &surfaceStat{}
		p.surfaces[ev.Source] = st
	}
	st.events++
	if now.After(st.last) {
		st.last = now
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

		"ingest.processed":             c.processed,
		"ingest.queue_dropped":         qd,
		"ingest.disabled_dropped":      dd,
		"ingest.closed_dropped":        cd,
		"ingest.excluded":              c.excluded,
		"ingest.malformed":             c.malformed,
		"correlate.held":               c.held,
		"correlate.released":           c.released,
		"correlate.matched":            c.matched,
		"correlate.duplicates":         c.duplicates,
		"correlate.late_hook":          c.lateHook,
		"correlate.held_overflow":      c.heldOverflow,
		"correlate.uncorrelatable":     c.uncorrelatable,
		"session.synthesized_start":    c.synthesized,
		"session.summaries":            c.summaries,
		"activity.suppressed":          c.activitySuppressed,
		"detections.below_min_class":   c.belowMinClass,
		"detections.context":           c.contextRecords,
		"records.late":                 c.late,
		"records.withheld":             c.withheld,
		"records.emit_refused":         c.emitRefused,
		"records.linecap_dropped":      c.lineDrops,
		"records.secret_flow_scrubbed": c.flowScrubbed,
		"outbox.write_errors":          c.writeErrors,
		"outbox.dropped":               c.writeDropped,
		"local.written":                c.localWritten,
		"local.dropped":                c.localDropped,
		"local.discarded":              c.localDiscarded,
		"local.write_errors":           c.localErrors,
		"state.applied":                c.stateApplied,
		"state.errors":                 c.stateErrors,
		"baseline.errors":              c.baselineErrors,
		"baseline.keys":                uint64(p.bl.Len()),
		"coverage.bypass_findings":     c.bypassFindings,
		"coverage.bypass_signals":      c.bypassSignals,
		"coverage.unknown_agent":       c.covUnknownAgent,
		"coverage.untrusted_process":   c.untrustedProcess,
		"correlate.otel_attributed":    c.otelAttributed,
		"correlate.otel_unattributed":  c.otelUnattributed,
		"correlate.otel_ambiguous":     c.otelAmbiguous,
		"correlate.otel_pending":       c.otelPending,
		"correlate.otel_unmatched":     c.otelUnmatched,
		"ingest.unknown_vocab":         c.unknownVocab,
		"baseline.first_seen_hosts":    c.firstSeenHosts,
		"baseline.first_seen_mcp":      c.firstSeenMCP,
		"engine.pending":               uint64(len(p.pending)),
		"engine.panics":                c.panics,
		"engine.rule_timeouts":         c.ruleTimeouts,
		"engine.sessions":              uint64(len(p.sessions)),
		"engine.held":                  uint64(len(p.corr.held)),
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
	var cov []event.Coverage
	if !disabled {
		cov = p.coverage(now)
	}
	p.fitHeartbeat(ev, cov)
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

// Heartbeat fit. The heartbeat must reach the outbox and the state database
// whole: its rules, bundle, profile and status labels are what Fleet's
// policies read, and the privacy line cap removes labels before it removes
// the coverage list. The coverage list grows with (agent, account) pairs,
// so the engine builds the heartbeat to fit the line before Emit:
//
//   - per-state counts of every row are counters (coverage.rows,
//     coverage.covered, .partial, .blind, .absent, coverage.rows_omitted);
//     the state database gets every row through SetCoverage.
//   - rows are taken account by account in turn (an account's rows that
//     are not covered first), so one account's rows cannot crowd out
//     another's, until the line budget is used; the rest are omitted and
//     the record says so (truncated: health.coverage).
//   - if the record still does not fit (a tiny output.max_line_bytes), the
//     surface list and then the non-essential counters go, again named in
//     truncated.

// heartbeatSlack covers what the privacy stage may add to a heartbeat
// (the privacy field, markers) beyond the writer's own headroom.
const heartbeatSlack = 512

var coverageStates = []string{"covered", "partial", "blind", "absent"}

func coverageRank(state string) int {
	switch state {
	case "blind":
		return 0
	case "partial":
		return 1
	case "absent":
		return 2
	}
	return 3
}

// fairCoverage orders rows for the budget: accounts in turn, each
// account's rows by state (blind first) and agent.
func fairCoverage(all []event.Coverage) []event.Coverage {
	by := map[string][]event.Coverage{}
	var users []string
	for _, c := range all {
		if _, ok := by[c.User]; !ok {
			users = append(users, c.User)
		}
		by[c.User] = append(by[c.User], c)
	}
	sort.Strings(users)
	longest := 0
	for _, u := range users {
		l := by[u]
		sort.SliceStable(l, func(i, j int) bool {
			if ri, rj := coverageRank(l[i].State), coverageRank(l[j].State); ri != rj {
				return ri < rj
			}
			return l[i].AgentID < l[j].AgentID
		})
		longest = max(longest, len(l))
	}
	out := make([]event.Coverage, 0, len(all))
	for i := 0; i < longest; i++ {
		for _, u := range users {
			if l := by[u]; i < len(l) {
				out = append(out, l[i])
			}
		}
	}
	return out
}

// encodedLen is the size of the heartbeat as the privacy stage will see it
// (operator labels included).
func (p *Pipeline) encodedLen(ev *event.Event) int {
	c := *ev
	if len(p.labels) > 0 {
		c.Labels = make(map[string]string, len(ev.Labels)+len(p.labels))
		for k, v := range p.labels {
			c.Labels[k] = v
		}
		for k, v := range ev.Labels {
			c.Labels[k] = v
		}
	}
	b, err := json.Marshal(&c)
	if err != nil {
		return 1 << 30
	}
	return len(b)
}

func (p *Pipeline) fitHeartbeat(ev *event.Event, cov []event.Coverage) {
	h := ev.Health
	ctr := h.Counters
	if cov != nil {
		ctr["coverage.rows"] = uint64(len(cov))
		for _, st := range coverageStates {
			ctr["coverage."+st] = 0
		}
		for _, r := range cov {
			if _, known := ctr["coverage."+r.State]; known {
				ctr["coverage."+r.State]++
			}
		}
		ctr["coverage.rows_omitted"] = 0
	}
	budget := p.maxLine() - privacy.LineHeadroom - 1 - heartbeatSlack
	total := p.encodedLen(ev) + len(`,"coverage":[]`)
	var sel []event.Coverage
	for _, r := range fairCoverage(cov) {
		probe := r
		probe.User, _ = p.pseudoUser(r.User, "")
		b, err := json.Marshal(probe)
		if err != nil {
			continue
		}
		if total+len(b)+1 > budget {
			break
		}
		total += len(b) + 1
		sel = append(sel, r)
	}
	sort.Slice(sel, func(i, j int) bool {
		if sel[i].AgentID != sel[j].AgentID {
			return sel[i].AgentID < sel[j].AgentID
		}
		return sel[i].User < sel[j].User
	})
	h.Coverage = sel
	omitted := len(cov) - len(sel)
	// Estimates can be off by what the privacy stage rewrites: verify on the
	// encoded record and give up parts, least needed first.
	for pass := 0; pass < 16 && p.encodedLen(ev) > budget; pass++ {
		switch n := len(h.Coverage); {
		case n > 0:
			keep := n * 3 / 4
			omitted += n - keep
			h.Coverage = h.Coverage[:keep]
		case len(h.Surfaces) > 0:
			h.Surfaces = nil
			ev.Truncated = append(ev.Truncated, "health.surfaces")
		default:
			if trimCounters(h) {
				ev.Truncated = append(ev.Truncated, "health.counters")
				continue
			}
			pass = 16
		}
	}
	if omitted > 0 {
		h.Counters["coverage.rows_omitted"] = uint64(omitted)
		ev.Truncated = append(ev.Truncated, "health.coverage")
	}
	if len(h.Coverage) == 0 {
		h.Coverage = nil
	}
}

// trimCounters removes counters in two steps: first all but the ones the
// state database reads and the per-stream accounting, then the per-stream
// accounting too. It reports whether it removed any.
func trimCounters(h *event.Health) bool {
	core := func(k string) bool {
		switch k {
		case state.CounterEventsIn, state.CounterEventsOut, state.CounterDropped, state.CounterDetections, state.CounterErrors:
			return true
		}
		return false
	}
	keepStreams := false
	for k := range h.Counters {
		if !core(k) && !strings.HasPrefix(k, "stream.") {
			keepStreams = true
			break
		}
	}
	removed := false
	for k := range h.Counters {
		if core(k) || (keepStreams && strings.HasPrefix(k, "stream.")) {
			continue
		}
		delete(h.Counters, k)
		removed = true
	}
	return removed
}
