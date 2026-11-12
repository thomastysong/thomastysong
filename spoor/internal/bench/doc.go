// Package bench measures spoor's detection content instead of asserting
// it. It has two instruments, both driven by a Runner:
//
//   - Scenarios (RunScenarios): named attack and benign event sequences
//     from bench/scenarios/*.yaml, in the partial-event shape of inline
//     rule tests. Each attack is also run through semantics-preserving
//     mutations of its shell commands (quoting, $IFS, a wrapper shell,
//     variable assembly, an interpreter one-liner, a split across a written
//     script and its execution) and through surface ablations (hook only,
//     transcript only, OS plane only). The report gives per-rule and
//     per-technique true positives, false negatives and false positives
//     with Wilson 95% intervals, plain and robust recall, and the scores of
//     trivial oracles every rule set has to beat. Cells with fewer than 30
//     trials are marked "insufficient".
//   - Benign replay (Replay): real agent session logs (Claude Code
//     transcripts by default) parsed by internal/transcript and evaluated
//     in timestamp order, reporting per rule its hits, the agent threads it
//     hit, hits per 1,000 tool calls and sampled hits with their reviewed
//     label (false positive, red-team experiment, rule bug).
//
// # The evaluation seam
//
// Both instruments talk to the detection stack through Evaluator. Today
// RulesEvaluator runs internal/features and internal/rules directly;
// the daemon's pipeline (engine.Pipeline: Ingest, Tick and sinks) plugs in
// through PipelineFuncs and CaptureSink without changing the runner, so the
// same corpus can later measure correlation, hold timers and privacy
// routing too.
//
// # What the numbers cannot show
//
// Neither instrument measures prevalence or the alert rate of a real
// benign fleet. The scenario corpus is synthetic and was written by the
// same project that wrote the rules; the replay corpus is one workload
// (agents building and red-teaming this project on one machine). Reports
// say so in their text, next to the numbers.
//
// Inputs are hostile like everything else spoor reads: scenario files are
// parsed strictly (unknown keys, anchors and aliases are errors) and
// capped, transcripts are read through internal/transcript's no-follow,
// regular-file-only reader, and sampled replay hits are redacted before
// they are rendered.
package bench
