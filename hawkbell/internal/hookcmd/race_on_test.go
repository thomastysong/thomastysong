//go:build race

package hookcmd

// raceSlowdown scales wall-clock bounds: race-instrumented workers run
// several times slower.
const raceSlowdown = 10
