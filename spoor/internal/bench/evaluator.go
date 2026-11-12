package bench

import (
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
	"github.com/thomastysong/spoor/internal/sink"
)

// Evaluator is the seam between the bench and the detection stack. Events
// are fed in stream order; each call returns the detection records
// (detection.finding, and posture.check for inventory rules) that the event
// produced. Drain is called once at the end of a stream so an evaluator
// with timers (held transcript events, session summaries) can flush them.
type Evaluator interface {
	Eval(ev *event.Event) []*event.Event
	Drain(now time.Time) []*event.Event
	Close() error
}

// Factory returns a fresh Evaluator with empty state. Scenarios get one
// each, so no scenario can leak session state into another.
type Factory func() (Evaluator, error)

// countEvery is the dedup window the bench gives the rule engine: shorter
// than the gap between any two events, so every match is emitted and a
// report counts matches, not what survived suppression.
const countEvery = time.Nanosecond

// RulesOptions configures a RulesEvaluator.
type RulesOptions struct {
	Set *rules.Set
	// Home and OS are what feature computation assumes about the monitored
	// user's machine (classify.PathCtx).
	Home, OS string
	HostTags []string
	// SuppressFor is the engine's dedup window. Zero counts every match,
	// which is what a rule-quality report needs; set the daemon's window to
	// measure what an operator would actually receive.
	SuppressFor time.Duration
}

// RulesEvaluator runs internal/features and internal/rules directly. Its
// clock follows the events: the engine's Now is the timestamp of the
// event being evaluated (never earlier than the previous one), so flag
// lifetimes and threshold windows behave as they did when the session was
// live, however fast the replay runs.
type RulesEvaluator struct {
	mu    sync.Mutex
	eng   *rules.Engine
	clock time.Time
}

// NewRulesEvaluator builds an engine over o.Set.
func NewRulesEvaluator(o RulesOptions) *RulesEvaluator {
	re := &RulesEvaluator{clock: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	sup := o.SuppressFor
	if sup <= 0 {
		sup = countEvery
	}
	re.eng = rules.NewEngine(o.Set, rules.Options{
		Now:         func() time.Time { return re.clock },
		SuppressFor: sup,
		Home:        o.Home,
		OS:          o.OS,
		HostTags:    o.HostTags,
		// A replay evaluates in bulk on a loaded machine; the per-event
		// deadline protects a hook process, not a measurement, and a
		// timeout here would silently drop rules from the counts.
		Deadline: 10 * time.Second,
	})
	return re
}

// RulesFactory returns a Factory of RulesEvaluators over the same options.
func RulesFactory(o RulesOptions) Factory {
	return func() (Evaluator, error) { return NewRulesEvaluator(o), nil }
}

// Eval implements Evaluator.
func (r *RulesEvaluator) Eval(ev *event.Event) []*event.Event {
	if ev == nil {
		return nil
	}
	r.mu.Lock()
	// The clock only moves forward, by at least a microsecond per event:
	// parallel agent threads write records in the same millisecond, and two
	// matches at the same instant would fall inside even the bench's
	// one-nanosecond dedup window.
	next := r.clock.Add(time.Microsecond)
	if !ev.TS.IsZero() && ev.TS.Time.After(next) {
		next = ev.TS.Time
	}
	r.clock = next
	r.mu.Unlock()
	return r.eng.Eval(ev).Detections
}

// Drain implements Evaluator; the rule engine has no timers.
func (r *RulesEvaluator) Drain(time.Time) []*event.Event { return nil }

// Close implements Evaluator.
func (r *RulesEvaluator) Close() error { return nil }

// Stats exposes the engine counters (timeouts and panics must be zero for
// a run to count).
func (r *RulesEvaluator) Stats() map[string]uint64 { return r.eng.Stats() }

// PipelineFuncs adapts an asynchronous pipeline such as engine.Pipeline:
// Ingest hands it events, Tick advances its timers and Collect returns the
// detection records its sinks received since the last call (wire a
// CaptureSink as the pipeline's outbox and local ring and pass its Take).
// Hold is how far Drain advances the clock past the last event so held
// records are released (the pipeline holds transcript-only tool events for
// 10 s); zero means one minute.
type PipelineFuncs struct {
	Ingest  func(evs ...*event.Event)
	Tick    func(now time.Time)
	Collect func() []*event.Event
	Shut    func() error
	Hold    time.Duration

	last time.Time
}

// Eval implements Evaluator.
func (p *PipelineFuncs) Eval(ev *event.Event) []*event.Event {
	if ev == nil || p.Ingest == nil {
		return nil
	}
	p.Ingest(ev)
	if !ev.TS.IsZero() && ev.TS.Time.After(p.last) {
		p.last = ev.TS.Time
	}
	if p.Tick != nil && !p.last.IsZero() {
		p.Tick(p.last)
	}
	return p.collect()
}

// Drain implements Evaluator.
func (p *PipelineFuncs) Drain(now time.Time) []*event.Event {
	hold := p.Hold
	if hold <= 0 {
		hold = time.Minute
	}
	if now.Before(p.last) {
		now = p.last
	}
	if p.Tick != nil {
		p.Tick(now.Add(hold))
	}
	return p.collect()
}

func (p *PipelineFuncs) collect() []*event.Event {
	if p.Collect == nil {
		return nil
	}
	return onlyDetections(p.Collect())
}

// Close implements Evaluator.
func (p *PipelineFuncs) Close() error {
	if p.Shut == nil {
		return nil
	}
	return p.Shut()
}

func onlyDetections(evs []*event.Event) []*event.Event {
	out := evs[:0:0]
	for _, e := range evs {
		if e == nil {
			continue
		}
		if (e.Kind == event.KindDetection && e.Detection != nil) || (e.Kind == event.KindPosture && e.Check != nil) {
			out = append(out, e)
		}
	}
	return out
}

// CaptureSink is a sink.Sink that keeps what it is given in memory, for
// wiring a pipeline into PipelineFuncs.
type CaptureSink struct {
	name string
	mu   sync.Mutex
	got  []*event.Event
}

var _ sink.Sink = (*CaptureSink)(nil)

// NewCaptureSink returns an empty CaptureSink.
func NewCaptureSink(name string) *CaptureSink { return &CaptureSink{name: name} }

// Name implements sink.Sink.
func (c *CaptureSink) Name() string { return c.name }

// Write implements sink.Sink.
func (c *CaptureSink) Write(batch []*event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, batch...)
	return nil
}

// Flush implements sink.Sink.
func (c *CaptureSink) Flush() error { return nil }

// Close implements sink.Sink.
func (c *CaptureSink) Close() error { return nil }

// Take returns and forgets everything written so far.
func (c *CaptureSink) Take() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.got
	c.got = nil
	return out
}

// Hit is one detection as the bench counts it.
type Hit struct {
	RuleID   string            `json:"rule_id"`
	Class    string            `json:"class,omitempty"`
	Severity string            `json:"severity,omitempty"`
	EventID  string            `json:"event_id,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// hitsOf converts detection records into hits. A posture record counts
// only when the check failed.
func hitsOf(evs []*event.Event, trigger string) []Hit {
	var out []Hit
	for _, e := range evs {
		switch {
		case e == nil:
		case e.Detection != nil:
			id := trigger
			if n := len(e.Detection.EventIDs); n > 0 {
				id = e.Detection.EventIDs[n-1]
			}
			out = append(out, Hit{RuleID: e.Detection.RuleID, Class: e.Detection.Class, Severity: e.Detection.Severity, EventID: id, Evidence: e.Detection.Evidence})
		case e.Check != nil && e.Check.Status != "pass":
			out = append(out, Hit{RuleID: e.Check.ID, Severity: e.Check.Severity, EventID: trigger})
		}
	}
	return out
}
