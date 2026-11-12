package bench

import (
	"math"
	"strings"
	"testing"
)

func TestWilson(t *testing.T) {
	for _, c := range []struct {
		k, n   int
		lo, hi float64
	}{
		// Reference values (Wilson score, z = 1.96).
		{0, 10, 0, 0.2775},
		{10, 10, 0.7225, 1},
		{5, 10, 0.2366, 0.7634},
		{1, 37, 0.0048, 0.1383},
		{0, 0, 0, 1},
		{-3, 10, 0, 0.2775}, // clamped
		{12, 10, 0.7225, 1}, // clamped
		{0, 30000, 0, 0.000128},
	} {
		lo, hi := Wilson(c.k, c.n, Z95)
		if math.Abs(lo-c.lo) > 0.0006 || math.Abs(hi-c.hi) > 0.0006 {
			t.Errorf("Wilson(%d,%d) = [%.4f, %.4f], want [%.4f, %.4f]", c.k, c.n, lo, hi, c.lo, c.hi)
		}
		if lo < 0 || hi > 1 || lo > hi {
			t.Errorf("Wilson(%d,%d) out of bounds: [%v, %v]", c.k, c.n, lo, hi)
		}
	}
}

func TestRate(t *testing.T) {
	r := NewRate(3, 20)
	if !r.Insufficient || r.P != 0.15 {
		t.Errorf("rate %+v", r)
	}
	if s := r.String(); !strings.Contains(s, "3/20") || !strings.Contains(s, "insufficient") {
		t.Errorf("string %q", s)
	}
	if NewRate(30, 30).Insufficient {
		t.Error("30 trials is a measurement")
	}
	if s := NewRate(0, 0).String(); !strings.Contains(s, "no trials") {
		t.Errorf("string %q", s)
	}
	if got := pct(NewRate(0, 0)); got != "n/a" {
		t.Errorf("pct of an empty rate %q", got)
	}
}
