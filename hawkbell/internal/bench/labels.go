package bench

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Review labels for sampled replay hits.
const (
	// LabelFalsePositive: ordinary work the rule should not have flagged.
	LabelFalsePositive = "false_positive"
	// LabelRedTeam: a deliberate red-team or security experiment in the
	// corpus; a true positive without malice (Uber's "TP non-malicious").
	LabelRedTeam = "red_team"
	// LabelRuleBug: the rule matched something it was not written to match
	// (a feature or predicate error rather than a judgement call).
	LabelRuleBug = "rule_bug"
	// LabelTruePositive: the behaviour the rule describes, done for real
	// and worth the attention its class asks for.
	LabelTruePositive = "true_positive"
)

var knownLabels = map[string]bool{LabelFalsePositive: true, LabelRedTeam: true, LabelRuleBug: true, LabelTruePositive: true}

// Label is a reviewed verdict on one replay hit, keyed by rule and the
// triggering event id (transcript event ids are deterministic, so a label
// survives re-runs over the same logs).
type Label struct {
	Rule   string `yaml:"rule" json:"rule"`
	Event  string `yaml:"event" json:"event"`
	Label  string `yaml:"label" json:"label"`
	Reason string `yaml:"reason" json:"reason"`
}

type rawLabels struct {
	Labels []Label `yaml:"labels"`
}

var labelIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// LoadLabels reads a labels file ({labels: [{rule, event, label, reason}]}).
func LoadLabels(path string) ([]Label, error) {
	data, err := readCapped(path, maxScenarioFile)
	if err != nil {
		return nil, err
	}
	return ParseLabels(data)
}

// ParseLabels parses labels strictly.
func ParseLabels(data []byte) ([]Label, error) {
	root, err := parseOne(data)
	if err != nil {
		return nil, fmt.Errorf("bench: labels: %w", err)
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("bench: labels: the document must be a mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "labels" {
			return nil, fmt.Errorf("bench: labels: unknown key %q", root.Content[i].Value)
		}
	}
	if lv := mapValue(root, "labels"); lv != nil {
		for _, it := range lv.Content {
			for i := 0; i+1 < len(it.Content); i += 2 {
				switch it.Content[i].Value {
				case "rule", "event", "label", "reason":
				default:
					return nil, fmt.Errorf("bench: labels: line %d: unknown key %q", it.Content[i].Line, it.Content[i].Value)
				}
			}
		}
	}
	var raw rawLabels
	if err := root.Decode(&raw); err != nil {
		return nil, fmt.Errorf("bench: labels: %w", err)
	}
	seen := map[string]bool{}
	for i, l := range raw.Labels {
		if !labelIDRe.MatchString(l.Rule) || !labelIDRe.MatchString(l.Event) {
			return nil, fmt.Errorf("bench: labels: entry %d: bad rule or event id", i+1)
		}
		if !knownLabels[l.Label] {
			return nil, fmt.Errorf("bench: labels: entry %d: label %q: want false_positive, red_team, rule_bug or true_positive", i+1, l.Label)
		}
		if strings.TrimSpace(l.Reason) == "" {
			return nil, fmt.Errorf("bench: labels: entry %d: a label needs a reason", i+1)
		}
		k := labelKey(l.Rule, l.Event)
		if seen[k] {
			return nil, fmt.Errorf("bench: labels: entry %d: %s labelled twice", i+1, k)
		}
		seen[k] = true
	}
	return raw.Labels, nil
}

func labelKey(rule, ev string) string { return rule + "/" + ev }

func indexLabels(ls []Label) map[string]Label {
	m := make(map[string]Label, len(ls))
	for _, l := range ls {
		m[labelKey(l.Rule, l.Event)] = l
	}
	return m
}
