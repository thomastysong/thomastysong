package event

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTimeAlwaysHasFraction(t *testing.T) {
	// Fluent Bit's strict parser needs a fractional part even on whole seconds.
	whole := At(time.Date(2026, 11, 11, 10, 0, 3, 0, time.UTC))
	b, err := json.Marshal(whole)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-11-11T10:00:03.000000Z"` {
		t.Fatalf("got %s", b)
	}
	var back Time
	if err := json.Unmarshal(b, &back); err != nil || !back.Equal(whole.Time) {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestZeroTimesAreOmitted(t *testing.T) {
	e := New(KindInventory, TypeInventoryAsset, SourceScan)
	e.Asset = &Asset{ID: "a", Kind: AssetAgent, Name: "x"}
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), "first_seen") || strings.Contains(string(line), "last_seen") {
		t.Fatalf("zero times leaked: %s", line)
	}
	if !strings.HasSuffix(string(line), "\n") || strings.Count(string(line), "\n") != 1 {
		t.Fatalf("not exactly one line: %q", line)
	}
}

func TestLocalOnlyFieldsNeverSerialize(t *testing.T) {
	e := New(KindActivity, TypeToolPre, SourceHook)
	e.Content = &Content{PromptText: "CANARY-SECRET", ToolInput: map[string]any{"k": "CANARY-SECRET"}, ToolOutput: "CANARY-SECRET", FileContent: "CANARY-SECRET"}
	e.Feat = map[string]any{"x": "CANARY-SECRET"}
	line, _ := e.MarshalLine()
	if strings.Contains(string(line), "CANARY-SECRET") {
		t.Fatalf("local-only content serialized: %s", line)
	}
}

func TestNewIDIsUUIDv7AndOrdered(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	a := NewIDAt(time.UnixMilli(1_700_000_000_000))
	b := NewIDAt(time.UnixMilli(1_700_000_000_001))
	if !re.MatchString(a) || !re.MatchString(b) {
		t.Fatalf("bad uuid7: %s %s", a, b)
	}
	if !(a[:13] < b[:13]) {
		t.Fatalf("not time ordered: %s %s", a, b)
	}
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		id := NewID()
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
}

func TestCloneIsolatesEmittedFields(t *testing.T) {
	e := New(KindActivity, TypeToolPre, SourceHook)
	e.Tool = &Tool{Name: "Bash", Kind: ToolShell, Input: map[string]any{"command": "ls", "nested": map[string]any{"a": []any{"b"}}}}
	e.Target = &Target{Command: "ls", Paths: []string{"/a"}}
	e.Detection = &Detection{RuleID: "r", Evidence: map[string]string{"k": "v"}, EventIDs: []string{"1"}}
	c := e.Clone()
	c.Tool.Input["command"] = "REDACTED"
	c.Tool.Input["nested"].(map[string]any)["a"].([]any)[0] = "X"
	c.Target.Paths[0] = "/b"
	c.Detection.Evidence["k"] = "w"
	if e.Tool.Input["command"] != "ls" || e.Tool.Input["nested"].(map[string]any)["a"].([]any)[0] != "b" || e.Target.Paths[0] != "/a" || e.Detection.Evidence["k"] != "v" {
		t.Fatal("clone shares emitted state with original")
	}
}

func TestSeverityRank(t *testing.T) {
	if !(SeverityRank(SevCritical) > SeverityRank(SevHigh) && SeverityRank(SevHigh) > SeverityRank(SevMedium) && SeverityRank(SevMedium) > SeverityRank(SevLow) && SeverityRank(SevLow) > SeverityRank(SevInfo) && SeverityRank("bogus") == 0) {
		t.Fatal("severity order wrong")
	}
}

func TestStableIDDeterministicAndTimeOrdered(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	t0 := time.UnixMilli(1_794_400_000_000)
	a := StableID(t0, "host", "claude-code", "sess", "toolu_1", "tool.pre")
	b := StableID(t0, "host", "claude-code", "sess", "toolu_1", "tool.pre")
	c := StableID(t0, "host", "claude-code", "sess", "toolu_2", "tool.pre")
	d := StableID(t0.Add(time.Millisecond), "host", "claude-code", "sess", "toolu_1", "tool.pre")
	if a != b || a == c || !re.MatchString(a) {
		t.Fatalf("stable id wrong: %s %s %s", a, b, c)
	}
	if !(a[:13] < d[:13]) {
		t.Fatalf("not time ordered: %s %s", a, d)
	}
	// Part boundaries matter: ("ab","c") must differ from ("a","bc").
	if StableID(t0, "ab", "c") == StableID(t0, "a", "bc") || DedupeKey("ab", "c") == DedupeKey("a", "bc") {
		t.Fatal("ambiguous part concatenation")
	}
}
