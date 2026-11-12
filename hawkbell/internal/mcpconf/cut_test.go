package mcpconf

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// cutPoint never leaves part of a marker in the head: at every offset
// across one, the head holds the whole marker or none of it.
func TestCutPointKeepsMarkersWhole(t *testing.T) {
	marker := outputMark("generic_secret", "hunter2hunter2")
	s := strings.Repeat("a", 40) + marker + " " + strings.Repeat("b", 40)
	start := strings.Index(s, marker)
	for n := -1; n <= len(s)+1; n++ {
		c := cutPoint(s, n)
		head := s[:c]
		if c > max(n, 0) {
			t.Fatalf("n=%d: cut at %d", n, c)
		}
		has := strings.Contains(head, marker)
		if k := strings.Index(head, "[REDACTED"); k >= 0 && !has {
			t.Fatalf("n=%d: partial marker %q", n, head[k:])
		}
		if n > start && n < start+len(marker) && c != start {
			t.Fatalf("n=%d: cut %d, want the marker start %d", n, c, start)
		}
		if n >= start+len(marker) && !has {
			t.Fatalf("n=%d: whole marker dropped", n)
		}
	}
	// The cut stays on a rune boundary.
	if c := cutPoint(strings.Repeat("é", 10), 5); c != 4 {
		t.Fatalf("cut inside a rune: %d", c)
	}
}

// Every capped output field keeps markers whole.
func TestCapStringKeepsMarkersWhole(t *testing.T) {
	marker := outputMark("generic_secret", "hunter2hunter2")
	for n := 0; n < 200; n++ {
		s := strings.Repeat("a", n) + marker + strings.Repeat("b", 200)
		got := capString(s, 128)
		if len(got) > 128 {
			t.Fatalf("n=%d: %d bytes", n, len(got))
		}
		if k := strings.Index(got, "[REDACTED"); k >= 0 && !strings.Contains(got, marker) {
			t.Fatalf("n=%d: partial marker %q", n, got[k:])
		}
	}
}

// Identity cuts are bounded, distinct, independent of input order and of
// the process (no keyed digest), and carry no digest of the value at all.
func TestStableCuts(t *testing.T) {
	head := strings.Repeat("n", 300)
	short := "short"
	// A literal value that is exactly what the first long value's cut form
	// would be: the cut must step past it rather than collide.
	squat := head[:256-12] + "~1"
	vals := []string{head + "-b", short, head + "-a", head + "-c", head + "-a", squat, strings.Repeat("m", 400)}
	got := stableCuts(vals, maxNameLen)
	for range 20 {
		shuffled := slices.Clone(vals)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again := stableCuts(shuffled, maxNameLen)
		for k, v := range got {
			if again[k] != v {
				t.Fatalf("cut of %.12q depends on input order: %q vs %q", k, v, again[k])
			}
		}
	}
	if _, ok := got[short]; ok {
		t.Fatal("a short value was cut")
	}
	if _, ok := got[squat]; ok {
		t.Fatal("a value at the cap was cut")
	}
	if len(got) != 4 {
		t.Fatalf("%d cut values, want 4", len(got))
	}
	seen := map[string]string{}
	for full, c := range got {
		if len(c) > maxNameLen || !strings.HasPrefix(full, c[:strings.LastIndexByte(c, '~')]) {
			t.Fatalf("cut %q of %.12q: over the cap or not a head", c, full)
		}
		if c == squat || c == short {
			t.Fatalf("cut %q collides with a literal value", c)
		}
		if prev, dup := seen[c]; dup {
			t.Fatalf("%.12q and %.12q share the cut %q", prev, full, c)
		}
		seen[c] = full
		if strings.Contains(c, fp8(full)) || strings.Contains(c, runFP8(full)) {
			t.Fatalf("cut %q carries a digest of the value", c)
		}
	}
	// Ranks follow the bytewise order of the full values; the squatted
	// first form is skipped.
	if got[head+"-a"] != head[:244]+"~2" || got[head+"-b"] != head[:244]+"~3" || got[head+"-c"] != head[:244]+"~4" {
		t.Fatalf("ranks: %q %q %q", got[head+"-a"][240:], got[head+"-b"][240:], got[head+"-c"][240:])
	}
	if stableCuts([]string{"a", "b"}, maxNameLen) != nil {
		t.Fatal("nothing to cut, yet a map")
	}
}

// Parse matches disabledMcpServers against the full declared name, before
// the name is cut: a long-named server listed there is disabled.
func TestLongNameDisabledInProject(t *testing.T) {
	name := strings.Repeat("d", 400)
	doc := `{"projects":{"/w/p":{"mcpServers":{"` + name + `":{"command":"x"}},"disabledMcpServers":["` + name + `"]}}}`
	ss := mustParse(t, "/home/a/.claude.json", doc, FormatClaudeJSON)
	if len(ss) != 1 || ss[0].Enabled == nil || *ss[0].Enabled {
		t.Fatalf("long-named server not disabled: %+v", ss)
	}
	if len(ss[0].Name) > maxNameLen {
		t.Fatalf("name not cut: %d bytes", len(ss[0].Name))
	}
}
