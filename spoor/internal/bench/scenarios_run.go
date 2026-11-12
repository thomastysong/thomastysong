package bench

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Ablations are the surface subsets every attack is replayed through: what
// a deployment with only that collection surface would have seen.
var Ablations = []struct {
	Name     string
	Surfaces []string
	Source   event.Source
	Doc      string
}{
	{"hook_only", []string{SurfaceHook}, event.SourceHook, "agent hooks only (no daemon, no session logs)"},
	{"transcript_only", []string{SurfaceTranscript}, event.SourceTranscript, "session logs only (hooks missing or bypassed)"},
	{"os_only", []string{SurfaceProcess, SurfaceScan}, "", "process monitor and posture scan only (no agent cooperation)"},
}

// Mutation outcomes in ScenarioResult.Mutations.
const (
	MutDetected = "detected"
	MutMissed   = "missed"
	MutNA       = "n/a"
)

// ScenarioResult is the outcome of one scenario.
type ScenarioResult struct {
	Name      string            `json:"name"`
	File      string            `json:"file"`
	Kind      string            `json:"kind"`
	Incident  int               `json:"incident,omitempty"`
	Technique string            `json:"technique,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Expect    []string          `json:"expect,omitempty"`
	Fired     []string          `json:"fired,omitempty"`
	Detected  bool              `json:"detected"`
	Robust    bool              `json:"robust,omitempty"`
	Mutations map[string]string `json:"mutations,omitempty"`
	Ablations map[string]bool   `json:"ablations,omitempty"`
	// FalsePositive lists the finding- and alert-class rules that fired on
	// a benign scenario.
	FalsePositive []string `json:"false_positive,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// RuleRow is one rule's scenario metrics.
type RuleRow struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Severity string `json:"severity"`
	TP       int    `json:"tp"`
	FN       int    `json:"fn"`
	FP       int    `json:"fp"`
	// Extra counts attack scenarios where the rule fired without being
	// expected (a second technique in the same chain, or over-matching).
	Extra  int  `json:"extra"`
	Recall Rate `json:"recall"`
	// Robust is recall over every applicable mutation and variant of the
	// scenarios that expect the rule.
	Robust Rate `json:"robust_recall"`
	FPRate Rate `json:"fp_rate"`
}

// TechniqueRow is per-technique scenario detection.
type TechniqueRow struct {
	Technique string `json:"technique"`
	Recall    Rate   `json:"recall"`
	Robust    Rate   `json:"robust_recall"`
	FPRate    Rate   `json:"fp_rate"`
}

// OperatorRow is recall under one mutation operator.
type OperatorRow struct {
	Operator string `json:"operator"`
	Doc      string `json:"doc"`
	Recall   Rate   `json:"recall"`
	NA       int    `json:"not_applicable"`
}

// AblationRow is recall with one surface subset.
type AblationRow struct {
	Name   string `json:"name"`
	Doc    string `json:"doc"`
	Recall Rate   `json:"recall"`
	// Blind counts attacks with no event at all on these surfaces.
	Blind int `json:"blind"`
}

// OracleRow is a trivial baseline.
type OracleRow struct {
	Name   string `json:"name"`
	Doc    string `json:"doc"`
	Recall Rate   `json:"recall"`
	FPRate Rate   `json:"fp_rate"`
}

// ScenarioReport is the result of RunScenarios.
type ScenarioReport struct {
	Date         string `json:"date"`
	RulesVersion string `json:"rules_version"`
	RulesHash    string `json:"rules_hash"`
	RulesCount   int    `json:"rules_count"`
	Files        int    `json:"files"`
	Attacks      int    `json:"attacks"`
	Benign       int    `json:"benign"`
	Incidents    int    `json:"incidents"`
	Variants     int    `json:"mutation_runs"`

	Recall       Rate            `json:"recall"`
	RobustRecall Rate            `json:"robust_recall"`
	Outcomes     map[string]Rate `json:"recall_by_outcome"`
	// AnyRecall counts an attack as seen when any finding or alert fired,
	// expected or not.
	AnyRecall Rate            `json:"any_finding_recall"`
	BenignFP  map[string]Rate `json:"benign_fp_by_class"`

	Operators  []OperatorRow    `json:"operators"`
	Ablations  []AblationRow    `json:"ablations"`
	Oracles    []OracleRow      `json:"oracles"`
	Rules      []RuleRow        `json:"rules"`
	Techniques []TechniqueRow   `json:"techniques"`
	Scenarios  []ScenarioResult `json:"scenarios"`
	Unknown    []string         `json:"unknown_rule_ids,omitempty"`
	Limits     []string         `json:"limits"`
}

// RunScenarios loads every scenario file in dir and runs it.
func (r *Runner) RunScenarios(ctx context.Context, dir string) (*ScenarioReport, error) {
	sc, err := LoadScenarios(dir)
	if err != nil {
		return nil, err
	}
	return r.RunScenarioSet(ctx, sc)
}

// RunScenarioSet runs scenarios already loaded.
func (r *Runner) RunScenarioSet(ctx context.Context, scs []Scenario) (*ScenarioReport, error) {
	rep := &ScenarioReport{
		Date:         r.o.Now().UTC().Format(time.DateOnly),
		RulesVersion: r.set.Version(),
		RulesHash:    r.set.Hash(),
		RulesCount:   r.set.Count(),
		Outcomes:     map[string]Rate{},
		BenignFP:     map[string]Rate{},
		Limits:       scenarioLimits,
	}
	f := r.factory(r.o.Home, r.o.OS)
	files := map[string]bool{}
	incidents := map[int]bool{}
	unknown := map[string]bool{}

	type ruleAcc struct{ tp, fn, fp, extra, rtp, rn int }
	acc := map[string]*ruleAcc{}
	get := func(id string) *ruleAcc {
		a := acc[id]
		if a == nil {
			a = &ruleAcc{}
			acc[id] = a
		}
		return a
	}
	type techAcc struct{ det, n, rob, fp, nb int }
	tech := map[string]*techAcc{}
	tget := func(t string) *techAcc {
		if t == "" {
			t = "(none)"
		}
		a := tech[t]
		if a == nil {
			a = &techAcc{}
			tech[t] = a
		}
		return a
	}
	opDet, opN, opNA := map[string]int{}, map[string]int{}, map[string]int{}
	ablDet, ablBlind := map[string]int{}, map[string]int{}
	outDet, outN := map[string]int{}, map[string]int{}
	classFP := map[string]int{}
	var det, robust, anyDet, attacks, benign int
	var oracleIn []oracleCase

	for _, s := range scs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		files[s.File] = true
		if s.Incident > 0 {
			incidents[s.Incident] = true
		}
		res := ScenarioResult{Name: s.Name, File: s.File, Kind: s.Kind, Incident: s.Incident, Technique: s.Technique, Outcome: s.Outcome, Expect: s.Expect}
		evs, err := buildAll(s.Events, "")
		if err != nil {
			res.Error = err.Error()
			rep.Scenarios = append(rep.Scenarios, res)
			continue
		}
		hits, err := r.run(f, evs)
		if err != nil {
			return nil, err
		}
		fired := firedSet(hits)
		res.Fired = sortedKeys(fired)
		oracleIn = append(oracleIn, oracleCase{kind: s.Kind, evs: evs})

		if s.Kind == KindBenign {
			benign++
			ta := tget(s.Technique)
			ta.nb++
			classes := map[string]bool{}
			for _, h := range hits {
				c := r.classOf(h)
				classes[c] = true
				if c != event.ClassSignal && !contains(res.FalsePositive, h.RuleID) {
					res.FalsePositive = append(res.FalsePositive, h.RuleID)
				}
			}
			for id := range fired {
				get(id).fp++
			}
			for c := range classes {
				classFP[c]++
			}
			if len(res.FalsePositive) > 0 {
				ta.fp++
			}
			sort.Strings(res.FalsePositive)
			rep.Scenarios = append(rep.Scenarios, res)
			continue
		}

		attacks++
		ta := tget(s.Technique)
		ta.n++
		outN[s.Outcome]++
		expected := map[string]bool{}
		for _, id := range s.Expect {
			expected[id] = true
			if _, ok := r.infos[id]; !ok {
				unknown[id] = true
			}
			if fired[id] {
				get(id).tp++
				res.Detected = true
			} else {
				get(id).fn++
			}
		}
		for id := range fired {
			if !expected[id] {
				get(id).extra++
			}
		}
		for _, h := range hits {
			if r.classOf(h) != event.ClassSignal {
				anyDet++
				break
			}
		}
		if res.Detected {
			det++
			ta.det++
			outDet[s.Outcome]++
		}

		// Mutations and hand-written variants.
		res.Mutations = map[string]string{}
		rob := res.Detected
		trial := func(name string, mevs []built) error {
			mh, err := r.run(f, mevs)
			if err != nil {
				return err
			}
			mf := firedSet(mh)
			hit := false
			for _, id := range s.Expect {
				a := get(id)
				a.rn++
				if mf[id] {
					a.rtp++
					hit = true
				}
			}
			if hit {
				res.Mutations[name] = MutDetected
			} else {
				res.Mutations[name] = MutMissed
				rob = false
			}
			return nil
		}
		for _, op := range Operators() {
			sel := false
			for _, o := range selectedOperators(s.Mutations) {
				sel = sel || o == op
			}
			if !sel {
				continue
			}
			mevs, applied := mutateSequence(op, cloneBuilt(evs))
			if !applied {
				res.Mutations[op.Name] = MutNA
				opNA[op.Name]++
				continue
			}
			rep.Variants++
			if err := trial(op.Name, mevs); err != nil {
				return nil, err
			}
			opN[op.Name]++
			if res.Mutations[op.Name] == MutDetected {
				opDet[op.Name]++
			}
		}
		for _, v := range s.Variants {
			vevs, err := buildAll(v.Events, "")
			if err != nil {
				res.Error = fmt.Sprintf("variant %s: %v", v.Name, err)
				rob = false
				continue
			}
			rep.Variants++
			if err := trial("variant:"+v.Name, vevs); err != nil {
				return nil, err
			}
		}
		res.Robust = rob
		if rob {
			robust++
			ta.rob++
		}

		// Surface ablations.
		res.Ablations = map[string]bool{}
		for _, ab := range Ablations {
			aevs, err := buildAll(s.Events, ab.Source)
			if err != nil {
				return nil, err
			}
			aevs = onSurfaces(aevs, ab.Surfaces)
			if len(aevs) == 0 {
				ablBlind[ab.Name]++
				res.Ablations[ab.Name] = false
				continue
			}
			ah, err := r.run(f, aevs)
			if err != nil {
				return nil, err
			}
			af := firedSet(ah)
			hit := false
			for _, id := range s.Expect {
				hit = hit || af[id]
			}
			res.Ablations[ab.Name] = hit
			if hit {
				ablDet[ab.Name]++
			}
		}
		rep.Scenarios = append(rep.Scenarios, res)
	}

	rep.Files, rep.Attacks, rep.Benign, rep.Incidents = len(files), attacks, benign, len(incidents)
	rep.Recall = NewRate(det, attacks)
	rep.RobustRecall = NewRate(robust, attacks)
	rep.AnyRecall = NewRate(anyDet, attacks)
	for o, n := range outN {
		rep.Outcomes[o] = NewRate(outDet[o], n)
	}
	for _, c := range []string{event.ClassAlert, event.ClassFinding, event.ClassSignal} {
		rep.BenignFP[c] = NewRate(classFP[c], benign)
	}
	for _, op := range Operators() {
		rep.Operators = append(rep.Operators, OperatorRow{Operator: op.Name, Doc: op.Doc, Recall: NewRate(opDet[op.Name], opN[op.Name]), NA: opNA[op.Name]})
	}
	for _, ab := range Ablations {
		rep.Ablations = append(rep.Ablations, AblationRow{Name: ab.Name, Doc: ab.Doc, Recall: NewRate(ablDet[ab.Name], attacks), Blind: ablBlind[ab.Name]})
	}
	rep.Oracles = runOracles(oracleIn)

	ids := r.ruleIDs()
	for id := range acc {
		if !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := get(id)
		in := r.infos[id]
		rep.Rules = append(rep.Rules, RuleRow{
			ID: id, Class: in.Class, Severity: in.Severity, TP: a.tp, FN: a.fn, FP: a.fp, Extra: a.extra,
			Recall: NewRate(a.tp, a.tp+a.fn), Robust: NewRate(a.rtp, a.rn), FPRate: NewRate(a.fp, benign),
		})
	}
	var techs []string
	for t := range tech {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	for _, t := range techs {
		a := tech[t]
		rep.Techniques = append(rep.Techniques, TechniqueRow{Technique: t, Recall: NewRate(a.det, a.n), Robust: NewRate(a.rob, a.n), FPRate: NewRate(a.fp, a.nb)})
	}
	rep.Unknown = sortedKeys(unknown)
	return rep, nil
}

var scenarioLimits = []string{
	"The corpus is synthetic: events were written from the incident mechanics in research/threats.md, not recorded from real attacks, and by the same project that wrote the rules (not blind). Recall here is an upper bound on recall against the incidents as they happened.",
	"Benign look-alikes bound the false-positive rate only on this hand-picked set; they say nothing about prevalence or about the alert volume of a real fleet (see benign-replay.md for real sessions).",
	"Rates over fewer than 30 trials are marked insufficient. A rule whose recall rests on one or two scenarios has not been measured.",
	"Mutations rewrite shell commands only; non-shell evasions are covered by hand-written variants where a scenario has them.",
	"Ablations replay the same events per surface; they do not model what a surface loses in practice (hook payload fields, transcript truncation, process polling misses).",
}

func buildAll(specs []EventSpec, source event.Source) ([]built, error) {
	out := make([]built, 0, len(specs))
	for i, s := range specs {
		b, err := s.build(i, source)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i+1, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// cloneBuilt deep-copies events so a mutation never changes the original.
func cloneBuilt(evs []built) []built {
	out := make([]built, len(evs))
	for i, b := range evs {
		ev := b.ev.Clone()
		if b.ev.Content != nil {
			c := *b.ev.Content
			ev.Content = &c
		}
		ev.Feat = nil
		out[i] = built{ev: ev, feat: b.feat, surfaces: b.surfaces}
	}
	return out
}

func onSurfaces(evs []built, surfaces []string) []built {
	var out []built
	for _, b := range evs {
		for _, s := range b.surfaces {
			if contains(surfaces, s) {
				out = append(out, b)
				break
			}
		}
	}
	return out
}

func firedSet(hits []Hit) map[string]bool {
	m := map[string]bool{}
	for _, h := range hits {
		m[h.RuleID] = true
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func secondsDur(i int) time.Duration { return time.Duration(i) * time.Second }

// trimLines collapses whitespace for single-line rendering.
func trimLines(s string) string { return strings.Join(strings.Fields(s), " ") }
