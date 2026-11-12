package bench

import (
	"context"
	"sort"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
)

const corpusDir = "../../bench/scenarios"

// The committed corpus is part of the deliverable: it must load, meet the
// size the specification asks for, cover every incident row of
// research/threats.md section 2 and only name rules that exist.
func TestScenarioCorpus(t *testing.T) {
	sc, err := LoadScenarios(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	set, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, in := range set.Rules() {
		known[in.ID] = true
	}
	attacks, benign := 0, 0
	incidents := map[int]bool{}
	for _, s := range sc {
		if s.Technique == "" {
			t.Errorf("%s: no technique label", s.Name)
		}
		if s.Description == "" {
			t.Errorf("%s: no description", s.Name)
		}
		switch s.Kind {
		case KindAttack:
			attacks++
			if s.Incident < 1 || s.Incident > 48 {
				t.Errorf("%s: incident %d is not a row of threats.md section 2", s.Name, s.Incident)
			}
			incidents[s.Incident] = true
			for _, id := range s.Expect {
				if !known[id] {
					t.Errorf("%s: expects unknown rule %s", s.Name, id)
				}
			}
		case KindBenign:
			benign++
		}
	}
	if attacks < 60 || benign < 60 {
		t.Errorf("corpus has %d attacks and %d benign look-alikes; the specification asks for at least 60 of each", attacks, benign)
	}
	for row := 1; row <= 48; row++ {
		if !incidents[row] {
			t.Errorf("incident row %d has no attack scenario", row)
		}
	}
	t.Logf("%d attacks over %d incident rows, %d benign look-alikes", attacks, len(incidents), benign)
}

// Gate for CI: on the committed corpus no alert-class rule may fire on a
// benign look-alike (alerts are the class promised to stay silent on
// ordinary work), every scenario must evaluate, and every expected rule
// must exist. Recall is measured and reported, not asserted.
func TestScenarioGate(t *testing.T) {
	if testing.Short() {
		t.Skip("runs every scenario with mutations")
	}
	r, err := NewRunner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.RunScenarios(context.Background(), corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unknown) > 0 {
		t.Errorf("unknown rule ids: %v", rep.Unknown)
	}
	for _, s := range rep.Scenarios {
		if s.Error != "" {
			t.Errorf("%s: %s", s.Name, s.Error)
		}
		if s.Kind != KindBenign {
			continue
		}
		for _, id := range s.FalsePositive {
			if in := r.infos[id]; in.Class == event.ClassAlert {
				t.Errorf("alert-class %s fired on benign look-alike %s", id, s.Name)
			}
		}
	}
	if rep.BenignFP[event.ClassAlert].K != 0 {
		t.Errorf("benign scenarios with an alert: %+v", rep.BenignFP[event.ClassAlert])
	}
	t.Logf("recall %s, robust %s, benign with a finding %s", rep.Recall, rep.RobustRecall, rep.BenignFP[event.ClassFinding])

	// Rules no scenario exercises are listed for review, not failed.
	expected := map[string]bool{}
	for _, s := range rep.Scenarios {
		for _, id := range s.Expect {
			expected[id] = true
		}
	}
	var unexercised []string
	for _, in := range r.set.Rules() {
		if in.Emit && in.Class != event.ClassSignal && !expected[in.ID] {
			unexercised = append(unexercised, in.ID)
		}
	}
	sort.Strings(unexercised)
	t.Logf("finding/alert rules no attack scenario expects: %v", unexercised)
}
