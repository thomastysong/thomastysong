//go:build !spoor_bench

package main

import "fmt"

// The benchmark runner is not linked into the default build: package
// initialisation of internal/bench costs about 2 ms per process (measured
// with GODEBUG=inittrace=1), and every `spoor hook` call starts two spoor
// processes. The benchmarks need the scenario corpus from the source tree
// anyway, so they are run from there.
func (a *app) cmdBench(args []string) int {
	for _, x := range args {
		if x == "-h" || x == "--help" || x == "-help" {
			fmt.Fprint(a.stdout, benchOffHelp)
			return exitOK
		}
	}
	fmt.Fprint(a.stderr, benchOffHelp)
	return exitError
}

const benchOffHelp = `usage: spoor bench [--scenarios dir] [--replay dir]... [--json] [--out dir]

This build of spoor does not include the benchmark runner (internal/bench):
it is left out of release builds to keep hook start-up fast. From a source
checkout, run either of:

  go run -tags spoor_bench ./cmd/spoor bench --scenarios bench/scenarios
  go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios
`
