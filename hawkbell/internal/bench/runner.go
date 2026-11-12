package bench

import (
	"errors"
	"sort"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

// Options configures a Runner. Zero values select the defaults.
type Options struct {
	// Rules is the content under test; nil loads the embedded packs. It is
	// also where the runner looks up a rule's class and severity, whatever
	// evaluator runs the events.
	Rules *rules.Set
	// NewEvaluator builds the detection stack for one scenario (or one
	// whole replay); nil runs the rule engine over Rules directly.
	NewEvaluator Factory
	// Home and OS describe the simulated endpoint for scenarios
	// ("/home/tester", "linux", matching inline rule tests).
	Home, OS string
	// Now stamps reports.
	Now func() time.Time
}

// Runner runs scenario corpora and benign replays against one rule set.
type Runner struct {
	o     Options
	set   *rules.Set
	infos map[string]rules.Info
}

// NewRunner validates the options and loads the embedded rules when none
// are given.
func NewRunner(o Options) (*Runner, error) {
	if o.Rules == nil {
		s, err := rules.LoadEmbedded()
		if err != nil {
			return nil, err
		}
		o.Rules = s
	}
	if o.Rules.Count() == 0 {
		return nil, errors.New("bench: the rule set is empty")
	}
	if o.Home == "" {
		o.Home = scenarioHome
	}
	if o.OS == "" {
		o.OS = "linux"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	r := &Runner{o: o, set: o.Rules, infos: map[string]rules.Info{}}
	for _, in := range o.Rules.Rules() {
		r.infos[in.ID] = in
	}
	return r, nil
}

// factory returns the evaluator factory for a run on the given endpoint.
func (r *Runner) factory(home, osName string) Factory {
	if r.o.NewEvaluator != nil {
		return r.o.NewEvaluator
	}
	return RulesFactory(RulesOptions{Set: r.set, Home: home, OS: osName})
}

// scenarioFactory leaves the engine's OS unset so each event's Host.OS
// decides path semantics, as it does in the daemon, where every record is
// stamped with its host: a Windows scenario gets Windows path rules (case
// folding, trailing dots) in the same run as Linux ones.
func (r *Runner) scenarioFactory() Factory {
	return r.factory(r.o.Home, "")
}

// classOf returns the class of a hit: the detection's own class, else the
// rule's (posture records carry none).
func (r *Runner) classOf(h Hit) string {
	if h.Class != "" {
		return h.Class
	}
	if in, ok := r.infos[h.RuleID]; ok && in.Class != "" {
		return in.Class
	}
	return event.ClassFinding
}

// ruleIDs returns every enabled emitting rule id, sorted.
func (r *Runner) ruleIDs() []string {
	var out []string
	for id, in := range r.infos {
		if in.Enabled && in.Emit {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// run evaluates one event sequence on a fresh evaluator and returns the
// hits in order.
func (r *Runner) run(f Factory, evs []built) ([]Hit, error) {
	ev, err := f()
	if err != nil {
		return nil, err
	}
	defer ev.Close()
	var hits []Hit
	var last time.Time
	for _, b := range evs {
		if b.ev.Host == nil {
			b.ev.Host = &event.Host{OS: r.o.OS}
		} else if b.ev.Host.OS == "" {
			b.ev.Host.OS = r.o.OS
		}
		applyFeat(b, r.o.Home, b.ev.Host.OS)
		hits = append(hits, hitsOf(ev.Eval(b.ev), b.ev.ID)...)
		if b.ev.TS.Time.After(last) {
			last = b.ev.TS.Time
		}
	}
	hits = append(hits, hitsOf(ev.Drain(last), "")...)
	return hits, nil
}
