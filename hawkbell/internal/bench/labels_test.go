package bench

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLabels(t *testing.T) {
	good := "labels:\n  - { rule: HB-EXEC-001, event: 01a1cb8b-171a-7000-8000-000000000000, label: false_positive, reason: inline Python heuristic }\n  - { rule: HB-EVADE-001, event: e2, label: red_team, reason: osqueryd restart in the lab }\n"
	ls, err := ParseLabels([]byte(good))
	if err != nil || len(ls) != 2 || ls[1].Label != LabelRedTeam {
		t.Fatalf("parse: %v %+v", err, ls)
	}
	if m := indexLabels(ls); m[labelKey("HB-EVADE-001", "e2")].Reason == "" {
		t.Error("index")
	}
	for name, doc := range map[string]string{
		"unknown top key":  "labels: []\nextra: 1\n",
		"unknown item key": "labels:\n  - { rule: R, event: e, label: red_team, reason: x, score: 1 }\n",
		"unknown label":    "labels:\n  - { rule: R, event: e, label: maybe, reason: x }\n",
		"no reason":        "labels:\n  - { rule: R, event: e, label: red_team, reason: \"  \" }\n",
		"bad rule id":      "labels:\n  - { rule: \"../x\", event: e, label: red_team, reason: x }\n",
		"duplicate":        "labels:\n  - { rule: R, event: e, label: red_team, reason: x }\n  - { rule: R, event: e, label: rule_bug, reason: y }\n",
		"alias":            "a: &x red_team\nlabels:\n  - { rule: R, event: e, label: *x, reason: x }\n",
		"not a mapping":    "- 1\n",
	} {
		if _, err := ParseLabels([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := filepath.Join(t.TempDir(), "labels.yaml")
	os.WriteFile(p, []byte(good), 0o644)
	if ls, err := LoadLabels(p); err != nil || len(ls) != 2 {
		t.Errorf("load: %v", err)
	}
}
