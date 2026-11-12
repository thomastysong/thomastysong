package rules

import (
	"testing"
)

// The shipped content must load, pass its own tests and lint without
// errors: this is the gate a pack author runs in CI.
func TestEmbeddedContent(t *testing.T) {
	s, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() == 0 {
		t.Fatal("no embedded rules")
	}
	for _, r := range s.RunTests() {
		if !r.OK {
			t.Errorf("%s / %s: got %s want %s: %s", r.RuleID, r.Name, r.Got, r.Want, r.Detail)
		}
	}
	for _, is := range Lint(s) {
		if is.Level == LevelError {
			t.Errorf("lint: %s", is)
		} else {
			t.Logf("lint: %s", is)
		}
	}
}
