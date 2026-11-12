package privacy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestLineCap(t *testing.T) {
	escapeHeavy := strings.Repeat("<>&\x01\"\\", 3000) // up to 6x on encoding
	many := make([]string, 5000)
	for i := range many {
		many[i] = fmt.Sprintf("/srv/file-%05d.go", i)
	}
	bigInput := map[string]any{}
	for i := 0; i < 600; i++ {
		bigInput[fmt.Sprintf("k%03d", i)] = strings.Repeat("v", 200)
	}
	labels := map[string]string{}
	for i := 0; i < 500; i++ {
		labels[fmt.Sprintf("l%03d", i)] = strings.Repeat("x", 100)
	}
	cases := map[string]func() *event.Event{
		"huge command": func() *event.Event { return shellEvent("echo " + strings.Repeat("A", 1<<20) + " | sh") },
		"escape heavy": func() *event.Event { return shellEvent("echo '" + escapeHeavy + "'") },
		"many paths": func() *event.Event {
			e := shellEvent("ls")
			e.Target.Paths = many
			return e
		},
		"many args": func() *event.Event {
			e := activity(event.TypeProcessExec)
			e.Process = &event.Process{Name: "x", Args: many}
			return e
		},
		"big tool input": func() *event.Event {
			e := activity(event.TypeToolPre)
			e.Tool = &event.Tool{Name: "mcp", Kind: event.ToolMCP}
			e.Content = &event.Content{ToolInput: bigInput, ToolOutput: escapeHeavy, PromptText: escapeHeavy}
			e.Prompt = &event.Prompt{}
			return e
		},
		"many labels": func() *event.Event {
			e := shellEvent("ls")
			e.Labels = labels
			return e
		},
		"everything": func() *event.Event {
			e := shellEvent(strings.Repeat("<", 4096))
			e.Target.Paths = many
			e.Target.URL = "https://h/" + strings.Repeat("&", 4096)
			e.Labels = labels
			e.Outcome = &event.Outcome{Error: escapeHeavy}
			e.Process = &event.Process{Args: many, Ancestors: many}
			return e
		},
		"huge evidence": func() *event.Event {
			e := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
			ev := map[string]string{}
			for i := 0; i < 100; i++ {
				ev[fmt.Sprintf("shell.f%02d_classes", i)] = strings.Repeat("<", 3000)
			}
			e.Detection = &event.Detection{RuleID: "R1", Title: "t", Severity: "high", Class: "alert", Evidence: ev}
			return e
		},
	}
	for _, maxLine := range []int{0, 4096} {
		for name, build := range cases {
			for _, prof := range Profiles {
				p := &Policy{Profile: prof, MaxLine: maxLine, Key: testKey}
				out, _, ok := p.Emit(build())
				if !ok || out == nil {
					t.Fatalf("%s %s: dropped", name, prof)
				}
				l := line(t, out)
				limit := p.settings().maxLine - LineHeadroom
				if len(l) > limit {
					t.Errorf("%s %s maxline=%d: line is %d bytes, limit %d", name, prof, maxLine, len(l), limit)
				}
				// Simulate the writer adding its fields: still under MaxLine.
				out.Writer = "0193f5a2-1c2b-7d3e-8f4a-5b6c7d8e9f00"
				out.Seq = 18446744073709551615
				out.Emitted = event.Now()
				if l2 := line(t, out); len(l2) > p.settings().maxLine {
					t.Errorf("%s %s: with writer fields %d > %d", name, prof, len(l2), p.settings().maxLine)
				}
				if name != "many labels" && len(out.Truncated) == 0 && !strings.Contains(l, "TRUNCATED") {
					t.Errorf("%s %s: cut without a truncated note:\n%.300s", name, prof, l)
				}
				var back map[string]any
				if err := json.Unmarshal([]byte(l), &back); err != nil {
					t.Errorf("%s: invalid JSON: %v", name, err)
				}
				if out.Kind == "" || out.ID == "" {
					t.Errorf("%s: routing fields lost", name)
				}
			}
		}
	}
}

func TestLineCapCutsLargestFirst(t *testing.T) {
	e := shellEvent("echo " + strings.Repeat("c", 3000))
	e.Target.Path = "/srv/small/path.txt"
	e.Target.URL = "https://h/" + strings.Repeat("u", 3000)
	e.Outcome = &event.Outcome{Error: strings.Repeat("e", 200)}
	p := &Policy{Profile: ProfileStandard, MaxLine: MinMaxLine}
	out, _, _ := p.Emit(e)
	if out.Target.Path != "/srv/small/path.txt" {
		t.Errorf("small field was cut: %q", out.Target.Path)
	}
	if !contains(out.Truncated, "target.command") || !contains(out.Truncated, "target.url") {
		t.Errorf("truncated = %v", out.Truncated)
	}
	if l := line(t, out); len(l) > MinMaxLine-LineHeadroom {
		t.Errorf("line %d bytes", len(l))
	}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func TestJSONLenMatchesEncoder(t *testing.T) {
	for _, s := range []string{"", "plain", "<>&", "\x00\x01\x1f", "\"\\\n\r\t", "  ", "héllo wörld", "\U0001F600", "a\xffb"} {
		b, _ := json.Marshal(s)
		if got := jsonLen(s); got < len(b) {
			t.Errorf("jsonLen(%q) = %d < encoded %d", s, got, len(b))
		}
	}
}

func TestCutEncoded(t *testing.T) {
	s := strings.Repeat("<", 1000) + newMarker("password", "x") + strings.Repeat("&", 1000)
	for _, budget := range []int{40, 100, 500, 3000} {
		c := cutEncoded(s, budget)
		if n := jsonLen(c); n > budget {
			t.Errorf("budget %d: encoded %d", budget, n)
		}
		if strings.Count(c, "[REDACTED") != strings.Count(c, "[REDACTED:password:") {
			t.Errorf("marker split: %q", c)
		}
	}
}

func TestCutString(t *testing.T) {
	s := strings.Repeat("a", 100) + newMarker("password", "x") + strings.Repeat("b", 100)
	for max := 30; max < len(s); max += 7 {
		for _, head := range []bool{true, false} {
			c, cut := cutString(s, max, head)
			if !cut || len(c) > max {
				t.Errorf("max %d head %v: len %d cut %v", max, head, len(c), cut)
			}
			if strings.Contains(c, "[REDACTED:pass") && !strings.Contains(c, "[REDACTED:password:") {
				t.Errorf("marker split: %q", c)
			}
		}
	}
	if c, cut := cutString("short", 100, false); cut || c != "short" {
		t.Error("short strings are untouched")
	}
}

// TestSkeletonFitsLine (review P8): the skeleton is the last resort of the
// line cap, so it must fit too. Its fields come from the input; 128 bytes
// of "<" encode to 768, and seventeen such fields overflowed a small
// MaxLine.
func TestSkeletonFitsLine(t *testing.T) {
	lt := strings.Repeat("<", 4000)
	e := activity(event.TypeToolPre)
	e.Kind = event.KindDetection
	e.ID, e.Type, e.Writer, e.Dedupe = lt, lt, lt, lt
	e.Source, e.Fidelity, e.Integrity = event.Source(lt), event.Fidelity(lt), event.Integrity(lt)
	e.Session.ID = lt
	e.Host.ID, e.Host.OS, e.Host.Arch = lt, lt, lt
	e.Agent.ID = lt
	e.Detection = &event.Detection{RuleID: lt, Title: lt, Class: lt, Severity: lt}
	for _, ml := range []int{MinMaxLine, 3000, 4096, DefaultMaxLine} {
		p := &Policy{Profile: ProfileStandard, MaxLine: ml}
		out, ship, _ := p.Emit(e)
		if l := line(t, out); len(l) > ml-LineHeadroom {
			t.Errorf("MaxLine=%d: encoded line is %d bytes", ml, len(l))
		}
		if !ship || out.Kind == "" || out.Privacy != string(ProfileStandard) {
			t.Errorf("MaxLine=%d: routing lost: kind %q privacy %q", ml, out.Kind, out.Privacy)
		}
		// A context record keeps its join labels in the skeleton.
		act := *e
		act.Kind, act.Detection = event.KindActivity, nil
		ctx := p.ContextFor("det-x", []*event.Event{&act}, 1)
		if len(ctx) != 1 {
			t.Fatalf("MaxLine=%d: %d context records", ml, len(ctx))
		}
		for _, c := range ctx {
			if l := line(t, c); len(l) > ml-LineHeadroom || c.Labels[LabelContextFor] != "det-x" {
				t.Errorf("MaxLine=%d: context skeleton %d bytes, labels %v", ml, len(l), c.Labels)
			}
		}
	}
	// Direct: every rung of the skeleton ladder fits, whatever the input.
	s := (&Policy{MaxLine: MinMaxLine}).settings()
	stamp := map[string]string{LabelContextFor: lt, LabelContextKind: lt, LabelContextType: lt, LabelContextEventID: lt, LabelContextPolicy: "standard"}
	sk := (&Policy{}).skeleton(e, s, "minimal", "line_cap", stamp)
	if b, _ := json.Marshal(sk); sk == nil || len(b) > s.lineBudget() {
		t.Errorf("skeleton %d bytes over budget %d", len(b), s.lineBudget())
	}
}
