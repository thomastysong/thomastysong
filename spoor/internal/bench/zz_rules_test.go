package bench

import (
	"fmt"
	"os"
	"testing"

	"github.com/thomastysong/spoor/internal/rules"
)

func TestZZRules(t *testing.T) {
	if os.Getenv("ZZRULES") == "" {
		t.Skip()
	}
	s, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	n, bad := 0, 0
	for _, r := range s.RunTests() {
		n++
		if !r.OK {
			bad++
			fmt.Printf("FAIL %s / %s: got %s want %s: %s\n", r.RuleID, r.Name, r.Got, r.Want, r.Detail)
		}
	}
	for _, is := range rules.Lint(s) {
		fmt.Println("LINT", is)
	}
	fmt.Printf("rules %d tests %d failed %d\n", s.Count(), n, bad)
}
