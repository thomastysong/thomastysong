//go:build race

package transcript

// raceEnabled: the race detector slows the parser several times over, so
// wall-clock bounds are not checked under it.
const raceEnabled = true
