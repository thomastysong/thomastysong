package bench

import (
	"fmt"
	"math"
)

// Z95 is the standard normal quantile for a two-sided 95% interval.
const Z95 = 1.959963984540054

// MinTrials is the smallest number of trials for which a rate is reported
// as a measurement; below it the cell is marked insufficient. With 10
// trials and 10 successes the Wilson lower bound is still 72%, which says
// almost nothing about a rule (redteam/detection-quality.md section 7).
const MinTrials = 30

// Wilson returns the Wilson score interval for k successes in n trials at
// normal quantile z. It is well behaved at k = 0 and k = n, unlike the
// normal approximation, which is why the bench uses it for small cells.
// n <= 0 yields [0, 1]; k is clamped to [0, n].
func Wilson(k, n int, z float64) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	if k < 0 {
		k = 0
	}
	if k > n {
		k = n
	}
	nf := float64(n)
	p := float64(k) / nf
	z2 := z * z
	den := 1 + z2/nf
	center := (p + z2/(2*nf)) / den
	half := z * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf)) / den
	lo, hi = center-half, center+half
	if lo < 0 || k == 0 {
		lo = 0
	}
	if hi > 1 || k == n {
		hi = 1
	}
	return lo, hi
}

// Rate is k of n with its Wilson 95% interval.
type Rate struct {
	K            int     `json:"k"`
	N            int     `json:"n"`
	P            float64 `json:"p"`
	Lo           float64 `json:"lo"`
	Hi           float64 `json:"hi"`
	Insufficient bool    `json:"insufficient,omitempty"`
}

// NewRate computes k of n.
func NewRate(k, n int) Rate {
	r := Rate{K: k, N: n}
	if n > 0 {
		r.P = float64(k) / float64(n)
	}
	r.Lo, r.Hi = Wilson(k, n, Z95)
	r.Insufficient = n < MinTrials
	return r
}

// String renders "k/n p% [lo, hi]" and marks small cells.
func (r Rate) String() string {
	if r.N == 0 {
		return "0/0 (no trials)"
	}
	s := fmt.Sprintf("%d/%d %.1f%% [%.1f, %.1f]", r.K, r.N, 100*r.P, 100*r.Lo, 100*r.Hi)
	if r.Insufficient {
		s += " insufficient"
	}
	return s
}
