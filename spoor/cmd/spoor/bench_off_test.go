//go:build !spoor_bench

package main

import (
	"strings"
	"testing"
)

func TestBenchNotInThisBuild(t *testing.T) {
	ta := newTestApp(t)
	ta.mustRun(t, exitError, "bench", "--scenarios", "x")
	if !strings.Contains(ta.errb.String(), "-tags spoor_bench") {
		t.Fatalf("stderr: %s", ta.errb.String())
	}
	ta.mustRun(t, exitOK, "bench", "--help")
}
