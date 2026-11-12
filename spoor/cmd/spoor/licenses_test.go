package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestModuleLicensesMatchThirdPartyFile: `spoor licenses` prints the same
// license for every linked module as the INDEX of THIRD_PARTY_LICENSES, and
// knows exactly the modules listed there.
func TestModuleLicensesMatchThirdPartyFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "THIRD_PARTY_LICENSES"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	i := strings.Index(text, "\nINDEX\n")
	j := strings.Index(text, "\n=====")
	if i < 0 || j < i {
		t.Fatal("THIRD_PARTY_LICENSES has no INDEX section")
	}
	row := regexp.MustCompile(`^(\S+)\s+(v\S+)\s+(.+)$`)
	index := map[string]string{}
	for _, l := range strings.Split(text[i:j], "\n") {
		m := row.FindStringSubmatch(l)
		if m == nil || m[1] == "Module" {
			continue
		}
		// "BSD-3-Clause; SQLite itself is public domain; all release targets"
		index[m[1]] = strings.TrimSpace(strings.SplitN(m[3], ";", 2)[0])
	}
	if len(index) < 10 {
		t.Fatalf("parsed only %d INDEX rows", len(index))
	}
	known := moduleLicenses()
	for mod, lic := range index {
		got, ok := known[mod]
		if !ok {
			t.Errorf("%s is linked (THIRD_PARTY_LICENSES) but moduleLicenses does not know it", mod)
			continue
		}
		// moduleLicenses may add a remark in parentheses.
		if expr := strings.TrimSpace(strings.SplitN(got, " (", 2)[0]); expr != lic {
			t.Errorf("%s: moduleLicenses says %q, THIRD_PARTY_LICENSES says %q", mod, expr, lic)
		}
	}
	for mod := range known {
		if _, ok := index[mod]; !ok {
			t.Errorf("moduleLicenses lists %s, which THIRD_PARTY_LICENSES does not (no longer linked?)", mod)
		}
	}
}
