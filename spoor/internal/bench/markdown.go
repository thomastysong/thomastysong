package bench

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// JSON renders the report as indented JSON.
func (rep *ScenarioReport) JSON() ([]byte, error) { return json.MarshalIndent(rep, "", "  ") }

// JSON renders the report as indented JSON.
func (rep *ReplayReport) JSON() ([]byte, error) { return json.MarshalIndent(rep, "", "  ") }

func pct(r Rate) string {
	if r.N == 0 {
		return "n/a"
	}
	s := fmt.Sprintf("%d/%d = %.1f%% [%.1f, %.1f]", r.K, r.N, 100*r.P, 100*r.Lo, 100*r.Hi)
	if r.Insufficient {
		s += " *insufficient*"
	}
	return s
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

// Markdown renders the scenario report.
func (rep *ScenarioReport) Markdown() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# Scenario benchmark\n\n")
	w("Generated %s by `internal/bench` over `bench/scenarios` (%d files): %d attack scenarios covering %d incident rows of `research/threats.md`, %d benign look-alikes, %d mutation and variant runs. Rules: %d enabled (`%s`, hash `%.12s`).\n\n",
		rep.Date, rep.Files, rep.Attacks, rep.Incidents, rep.Benign, rep.Variants, rep.RulesCount, rep.RulesVersion, rep.RulesHash)
	w("Rates are k/n with Wilson 95%% intervals; cells with n < %d are marked *insufficient*.\n\n", MinTrials)
	w("## What this corpus cannot show\n\n")
	for _, l := range rep.Limits {
		w("- %s\n", l)
	}
	w("\n## Headline\n\n| Measure | Value |\n|---|---|\n")
	w("| Plain recall (an expected rule fired on the scenario as written) | %s |\n", pct(rep.Recall))
	w("| Robust recall (detected as written and under every applicable mutation and variant) | %s |\n", pct(rep.RobustRecall))
	w("| Any finding or alert fired on the attack (expected or not) | %s |\n", pct(rep.AnyRecall))
	for _, o := range sortedKeys(rep.Outcomes) {
		w("| Recall, outcome %s | %s |\n", o, pct(rep.Outcomes[o]))
	}
	for _, c := range []string{event.ClassAlert, event.ClassFinding, event.ClassSignal} {
		w("| Benign look-alikes with a %s-class hit | %s |\n", c, pct(rep.BenignFP[c]))
	}
	w("\n## Robustness: recall per mutation operator\n\nEach operator rewrites every shell command of an attack; n is the attacks it applies to.\n\n| Operator | What it does | Recall | Not applicable |\n|---|---|---|---|\n")
	for _, o := range rep.Operators {
		w("| %s | %s | %s | %d |\n", o.Operator, cell(o.Doc), pct(o.Recall), o.NA)
	}
	w("\n## Surface ablations\n\nThe same attacks with only the events one surface would have delivered.\n\n| Surfaces | Recall | Attacks with no event on these surfaces |\n|---|---|---|\n")
	for _, a := range rep.Ablations {
		w("| %s (%s) | %s | %d |\n", a.Name, cell(a.Doc), pct(a.Recall), a.Blind)
	}
	w("\n## Trivial oracles\n\nBaselines that look only at tool and program names. The rules have to beat them on recall and false positives together.\n\n| Oracle | Recall | False-positive rate on benign look-alikes |\n|---|---|---|\n")
	w("| spoor rules (scenario detected / any finding or alert on benign) | %s | %s |\n", pct(rep.Recall), pct(benignAnyFinding(rep)))
	for _, o := range rep.Oracles {
		w("| %s: %s | %s | %s |\n", o.Name, cell(o.Doc), pct(o.Recall), pct(o.FPRate))
	}
	w("\n## Per technique\n\n| Technique | Recall | Robust recall | FP rate on look-alikes of this technique |\n|---|---|---|---|\n")
	for _, t := range rep.Techniques {
		w("| %s | %s | %s | %s |\n", t.Technique, pct(t.Recall), pct(t.Robust), pct(t.FPRate))
	}
	w("\n## Per rule\n\nTP/FN count attack scenarios that expect the rule; FP counts benign look-alikes it fired on; Extra counts attacks where it fired without being expected. Rules no scenario expects show only their false positives.\n\n| Rule | Class | TP | FN | FP | Extra | Recall | Robust recall | FP rate |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rep.Rules {
		w("| %s | %s | %d | %d | %d | %d | %s | %s | %s |\n", r.ID, r.Class, r.TP, r.FN, r.FP, r.Extra, pct(r.Recall), pct(r.Robust), pct(r.FPRate))
	}
	if len(rep.Unknown) > 0 {
		w("\nExpected rule ids that are not in the rule set: %s\n", strings.Join(rep.Unknown, ", "))
	}
	w("\n## Scenarios\n\n| Scenario | Kind | Incident | Technique | Expected | Fired | Result | Mutations missed | Surfaces that detect |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range rep.Scenarios {
		result := ""
		switch {
		case s.Error != "":
			result = "error: " + s.Error
		case s.Kind == KindBenign && len(s.FalsePositive) > 0:
			result = "FP: " + strings.Join(s.FalsePositive, ", ")
		case s.Kind == KindBenign:
			result = "clean"
		case s.Detected && s.Robust:
			result = "detected, robust"
		case s.Detected:
			result = "detected"
		default:
			result = "**missed**"
		}
		var missed, surf []string
		for _, k := range sortedKeys(s.Mutations) {
			if s.Mutations[k] == MutMissed {
				missed = append(missed, k)
			}
		}
		for _, k := range sortedKeys(s.Ablations) {
			if s.Ablations[k] {
				surf = append(surf, k)
			}
		}
		inc := ""
		if s.Incident > 0 {
			inc = fmt.Sprint(s.Incident)
		}
		w("| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", s.Name, s.Kind, inc, s.Technique, strings.Join(s.Expect, ", "),
			strings.Join(s.Fired, ", "), cell(result), strings.Join(missed, ", "), strings.Join(surf, ", "))
	}
	return b.String()
}

func benignAnyFinding(rep *ScenarioReport) Rate {
	n := 0
	for _, s := range rep.Scenarios {
		if s.Kind == KindBenign && len(s.FalsePositive) > 0 {
			n++
		}
	}
	return NewRate(n, rep.Benign)
}

// Markdown renders the replay report. before, when given, is an earlier
// run over the same corpus (typically before tuning); its numbers are
// shown next to this run's.
func (rep *ReplayReport) Markdown(before *ReplayReport) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	st := rep.Stats
	w("# Benign replay over real agent sessions\n\n")
	w("Generated %s by `internal/bench` (`Runner.Replay`). Corpus: %s.\n\n", rep.Date, rep.Corpus)
	w("| Corpus | Value |\n|---|---|\n")
	w("| Transcript files (agent threads) | %d (%d unreadable) |\n| Root sessions | %d |\n| Events | %d |\n| Tool calls (tool.pre) | %d |\n| Shell commands | %d |\n| Prompts | %d |\n| First / last event | %s / %s |\n",
		st.Threads, st.Unread, st.Sessions, st.Events, st.ToolCalls, st.Shell, st.Prompts, st.First, st.Last)
	var kinds []string
	for _, k := range sortedKeys(st.ToolKinds) {
		kinds = append(kinds, fmt.Sprintf("%s %d", k, st.ToolKinds[k]))
	}
	w("| Tool calls by kind | %s |\n", strings.Join(kinds, ", "))
	w("| Rules | %d enabled (`%s`, hash `%.12s`) |\n\n", rep.RulesCount, rep.RulesVersion, rep.RulesHash)
	w("## Limits\n\n")
	for _, l := range rep.Limits {
		w("- %s\n", l)
	}
	w("\n## Threads with at least one hit, by class\n\n| Class | Threads |\n|---|---|\n")
	for _, c := range []string{event.ClassAlert, event.ClassFinding, event.ClassSignal} {
		w("| %s | %s |\n", c, pct(rep.ThreadsAny[c]))
	}
	w("\n## Per rule\n\nHits are rule matches (no dedup window); per 1k is per 1,000 tool calls. Labels count the reviewed samples below.\n\n")
	if before != nil {
		w("| Rule | Class | Hits before | Per 1k before | Hits after | Per 1k after | Threads hit after | Hit rate after (Wilson 95%%) | Sample labels |\n|---|---|---|---|---|---|---|---|---|\n")
	} else {
		w("| Rule | Class | Hits | Per 1k | Threads hit | Hit rate (Wilson 95%%) | Sample labels |\n|---|---|---|---|---|---|---|\n")
	}
	rows := append([]ReplayRule(nil), rep.Rules...)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Hits != rows[j].Hits {
			return rows[i].Hits > rows[j].Hits
		}
		return rows[i].ID < rows[j].ID
	})
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if before != nil {
		// Rules that existed only before tuning (renamed or removed) still
		// get a row.
		for _, r := range before.Rules {
			if !contains(ids, r.ID) && r.Hits > 0 {
				rows = append(rows, ReplayRule{ID: r.ID, Class: r.Class})
				ids = append(ids, r.ID)
			}
		}
	}
	for _, r := range rows {
		if before == nil && r.Hits == 0 {
			continue
		}
		labels := labelSummary(r.Labels)
		if before != nil {
			var bh int
			var bp float64
			if br := before.rule(r.ID); br != nil {
				bh, bp = br.Hits, br.Per1k
				if r.Class == "" {
					r.Class = br.Class
				}
			}
			if bh == 0 && r.Hits == 0 {
				continue
			}
			w("| %s | %s | %d | %.2f | %d | %.2f | %d | %s | %s |\n", r.ID, r.Class, bh, bp, r.Hits, r.Per1k, r.Threads, pct(r.HitRate), labels)
		} else {
			w("| %s | %s | %d | %.2f | %d | %s | %s |\n", r.ID, r.Class, r.Hits, r.Per1k, r.Threads, pct(r.HitRate), labels)
		}
	}
	silent := 0
	for _, r := range rep.Rules {
		if r.Hits == 0 {
			silent++
		}
	}
	w("\n%d of %d rules had no hit on this corpus.\n", silent, len(rep.Rules))
	w("\n## Sampled hits\n\nEvery labelled hit and up to a few evenly spaced others per rule. Evidence is the engine's redacted evidence, redacted again and cut.\n")
	for _, r := range rows {
		if len(r.Samples) == 0 {
			continue
		}
		w("\n### %s (%s, %s): %s\n\n| Event | Thread | Tool | Evidence | Label | Why |\n|---|---|---|---|---|---|\n", r.ID, r.Class, r.Severity, r.Title)
		for _, s := range r.Samples {
			w("| `%.13s` | %s | %s | %s | %s | %s |\n", s.EventID, cell(shortThread(s.Thread)), s.Tool, cell(s.Summary), s.Label, cell(s.Reason))
		}
	}
	if len(rep.Problems) > 0 {
		w("\n## Problems\n\n")
		for _, p := range rep.Problems {
			w("- %s\n", p)
		}
	}
	return b.String()
}

func (rep *ReplayReport) rule(id string) *ReplayRule {
	if rep == nil {
		return nil
	}
	if rep.byID != nil {
		return rep.byID[id]
	}
	for i := range rep.Rules {
		if rep.Rules[i].ID == id {
			return &rep.Rules[i]
		}
	}
	return nil
}

func labelSummary(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// shortThread keeps the file name of a thread path, which identifies the
// subagent without repeating the project directory on every row.
func shortThread(t string) string {
	if i := strings.LastIndexByte(t, '/'); i >= 0 {
		return t[i+1:]
	}
	return t
}
