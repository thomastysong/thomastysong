//go:build !race

package rules

// raceEnabled reports a build with the race detector, under which wall-clock
// budgets are meaningless (it slows execution several times over).
const raceEnabled = false
