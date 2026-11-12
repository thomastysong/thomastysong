# `spoor hook` latency

Measured 2026-11-12 on the build VM (Linux 6.18 Firecracker guest, 4 vCPU,
shared with other builders: load average 2.3 to 4.8 during the runs, so
treat p99 and max as noisy). Every number is wall time from process start
to exit as the agent sees it: one process per hooked event, a real-shaped
Claude Code `PreToolUse` payload (`internal/hookio/testdata/claude/PreToolUse.json`,
540 bytes) on stdin, the spool on local ext4.

Method: a throwaway harness outside the repository (`hookbench`, a `main`
that calls `hookcmd.Run` exactly as `cmd/spoor` will, built `CGO_ENABLED=0`
like the release, 11.9 MB static) run 300 times per case after 10 discarded
warm-ups, all cases interleaved round-robin so background load hits each
equally. Shell launch paths run the command line hookinstall renders,
including its missing-binary guard:
`[ -x BIN ] || exit 0; exec BIN hook --agent claude-code --config CFG`.
"Unsupervised" runs the worker directly (`hook --worker ...`), i.e. what
the hook cost before the supervisor existed.

## Results (p50 / p90 / p99, ms, n = 300 each, 0 non-zero exits in 7,500 runs)

| case | direct | `sh -c` | `bash -lc` |
|---|---|---|---|
| empty hook (`/bin/true`) | 1.30 / 1.66 / 3.76 | 2.14 / 2.74 / 4.67 | 9.64 / 11.91 / 15.79 |
| empty Go program | 1.77 / 2.51 / 4.84 | | |
| spoor start + package init only (kill switch) | 5.40 / 6.60 / 11.95 | | |
| **observe, supervised** | **12.31 / 15.37 / 29.38** | **12.98 / 16.84 / 27.69** | **20.43 / 25.48 / 38.69** |
| observe, unsupervised | 6.43 / 8.36 / 15.77 | | |
| guard, supervised, rule cache fresh | 28.13 / 35.32 / 51.00 | 29.00 / 39.65 / 59.75 | 36.76 / 45.42 / 66.91 |
| guard, unsupervised, rule cache fresh | 21.79 / 28.92 / 38.79 | | |
| guard, supervised, rule cache stale | 43.52 / 56.16 / 87.45 | 44.56 / 58.43 / 86.08 | 52.74 / 66.88 / 90.13 |
| guard, unsupervised, rule cache stale | 36.98 / 49.04 / 70.45 | | |
| detect-in-hook, supervised, rule cache fresh | 38.39 / 49.44 / 77.14 | 39.22 / 51.29 / 110.64 | 47.22 / 59.01 / 81.68 |
| detect-in-hook, unsupervised, rule cache fresh | 32.72 / 41.71 / 59.16 | | |
| detect-in-hook, supervised, rule cache stale | 53.90 / 71.11 / 114.36 | 56.01 / 70.05 / 108.89 | 62.71 / 81.83 / 116.97 |
| detect-in-hook, unsupervised, rule cache stale | 47.88 / 62.36 / 86.03 | | |

The empty-hook rows reproduce the red team's baseline (1.7 / 2.5 / 8.5 ms
p50). Guard mode used the default `guard.deadline` (150 ms) and the
embedded rules (136 rules, 8 in the guard subset at the time). Its p99 stays
inside the deadline, but 2 of the 1,860 supervised guard runs (0.1 %, on
the loaded VM; the slowest guard runs took up to 206 ms including the shell)
hit it: the supervisor killed the worker,
appended a `hook_worker_timeout` health record and answered "ask" for a
benign `npm test`. On a loaded laptop a 150 ms deadline will occasionally
prompt for nothing; raise `guard.deadline` if that matters more than the
wait. "Rule cache stale" is the
repository as it was during the run: the content builder was still editing
`internal/rules/packs/*.yaml` and `packs/embedded.cache` predated the edits,
so every guard or detect hook parsed ~270 KB of YAML. "Fresh" is the same
code from a scratch copy after `go generate ./internal/rules`.

## Where the time goes

Supervised = two spoor process starts (supervisor and worker), each paying
the Go runtime start for an 11.9 MB binary and every linked package's init,
plus the work. Per process:

| step | cost | source |
|---|---|---|
| process start, empty Go program | ~1.8 ms | table above |
| package init of the hook binary | 2.4 to 3.9 ms | `GODEBUG=inittrace=1`, 5 runs |
| of which `internal/features` (9 case-insensitive regexes compiled at init) | 1.3 to 2.0 ms | same |
| of which `internal/shellx`, `rules`, `classify`, `yaml.v3` | ~0.2, ~0.15, ~0.15, ~0.1 ms | same |
| observe work in the worker (config, parse, host id, caller chain, keyed payload digest, one spool append) | ~1 ms | unsupervised minus kill-switch row |
| guard: `rules.LoadEmbedded` from a fresh cache (136 rules) | 9.5 to 14.7 ms | probe, fresh process |
| guard: `rules.LoadEmbedded` from YAML (stale cache) | ~21 ms | probe |
| guard: `NewEngine` on the guard subset / on the full set | ~0.7 to 1 ms / ~15 ms | probe |
| hookio parse + guard `Eval` of this payload | ~0.1 + ~0.2 ms | probe |

So the supervisor roughly doubles observe latency (6.4 to 12.3 ms p50
direct) because it is a second full spoor process. That is the price of
the crash-safety contract; nothing in `hookcmd` itself is a large share.

Measured remedies, outside this package:

- **Lazy regexes in `internal/features`** (`sync.OnceValue` around
  `autorunPatterns` and `mcpServersKey`, tried in a scratch copy only):
  package init drops to 1.2 to 1.9 ms and, interleaved against the current
  build (n = 300, load 2.3):

  | case | current | features regexes lazy |
  |---|---|---|
  | spoor start + init only | 4.92 / 5.90 / 8.12 | 3.51 / 4.38 / 9.40 |
  | observe supervised, direct | 11.39 / 14.03 / 20.99 | 8.98 / 11.01 / 21.41 |
  | observe supervised, `sh -c` | 12.29 / 14.50 / 20.00 | 9.60 / 11.86 / 22.11 |
  | observe supervised, `bash -lc` | 19.26 / 22.73 / 30.49 | 16.67 / 20.73 / 34.70 |
  | observe unsupervised, direct | 6.06 / 7.61 / 11.79 | 4.83 / 6.05 / 9.99 |

  The same treatment for the init work of `shellx`, `classify` and `rules`
  would save a further ~0.5 ms per process (twice when supervised).
- **A regenerated rule cache** before every release (`go generate
  ./internal/rules`): guard 43.5 to 28.1 ms p50 supervised in the table.
  Rule loading is still the largest guard cost (10 to 15 ms for 136
  rules), and `NewEngine` on the full set costs ~15 ms in detect-in-hook
  mode; both are the rules package's start-up budget (its target was 15 ms
  for LoadEmbedded + GuardSubset + NewEngine).
- **A slim launcher** (not built): the supervisor needs only `config`,
  `hookio`, `spool`, `platform` and `event`; none of `shellx`, `classify`,
  `features`, `rules` or `privacy`. A separate small binary that runs the
  supervisor and re-executes the full binary as the worker would start in
  about the empty-Go-program time, saving an estimated 1.5 to 3 ms per
  supervised call. It costs a second binary in packaging and in the hook
  command hookinstall writes, so it is the integrator's call.

## Against the spec budget (open)

Spec C1 asks observe mode to stay "within a few ms" of the empty-hook
figures (1.7 / 2.5 / 8.5 ms p50 direct, `sh -c`, `bash -lc`). Observe
supervised is about 10.5 to 12 ms over them (table above). The excess is
two process starts of the full binary, each paying the package init of
`internal/features`, `shellx`, `classify` and `rules`; nothing in this
package's own code is a measurable share (next section). Closing the gap
needs one of the remedies above, all outside `internal/hookcmd`: lazy
package init in those packages, or a slim launcher binary. Until one of
them lands, the observe budget is a deviation the lead has to accept or
fix there.

## After the reviewer fixes (2026-11-12)

The fixes (reply written before any spool access, framed worker replies,
bounded health and record appends, the session-state lock with optimistic
save, stdin size and digest past the cap) were measured against the
previous version of this package, both built into the same tree as test
binaries running in their hook role (`hook.test hook --agent claude-code`,
the worker re-executing the same binary), direct exec, the same 540-byte
payload, 300 runs each interleaved, load average 1.2 to 3.1:

| p50 / p90 / p99 ms | before | after |
|---|---|---|
| observe, supervised | 14.37 / 17.86 / 23.39 | 14.34 / 17.45 / 23.96 |
| guard, supervised (run 1) | 28.95 / 34.67 / 41.34 | 30.24 / 36.23 / 43.41 |
| guard, supervised (run 2) | 31.18 / 36.11 / 41.26 | 30.91 / 36.57 / 43.41 |

No measurable change. The test binaries are about 2.7 MB larger than the
`hookbench` binary above (the testing package and test code), so their
absolute figures are not comparable with the earlier tables.

## modernc.org/sqlite

`go list -deps ./internal/hookcmd` has 212 packages and none of them is
`modernc.org/*`, `database/sql` or `os/exec` (the supervisor uses
`os.StartProcess` on its own executable). Whether the `spoor hook` process
initialises sqlite is decided by what `cmd/spoor` links, because Go runs
every linked package's init before `main`. Measured with the bench binary
plus a blank `modernc.org/sqlite` import: +5.8 MB (11.9 to 17.6 MB) and
+0.27 ms of init per process (`modernc.org/libc` 0.15, `mathutil` 0.05,
`sqlite/lib` 0.06 ms), i.e. about +0.5 ms per supervised call plus page
faults for the larger image.

## Supervised versus unsupervised

| p50 ms, direct | unsupervised | supervised | added by the supervisor |
|---|---|---|---|
| observe | 6.43 | 12.31 | 5.9 |
| guard (fresh cache) | 21.79 | 28.13 | 6.3 |
| detect-in-hook (fresh cache) | 32.72 | 38.39 | 5.7 |

The red-team verifier measured 1.3 to 3.5 ms direct and 3.5 to 7.5 ms
supervised with a smaller prototype binary on the same VM; the difference
to the rows above is the size and package init of the real link set.

## What the guard answers mean per agent

Guard latency only matters where the answer is honoured. On Codex and
Gemini an "ask" (a rule with `response: ask`, `guard.max_response: ask`, a
guard timeout, or a crashed worker) is rendered as a non-blocking
`systemMessage` warning and the action proceeds; only a block with
`guard.max_response: block` stops the action there. On Claude Code,
Copilot and Cursor "ask" prompts the user. Every agent also treats its own
hook timeout as "proceed" (Claude Code unless `onFailure: block`).

## Not measured

macOS and Windows (the package cross-compiles; process start and the
Windows Toolhelp32 snapshot in the caller-chain capture are unmeasured),
cold page cache after install, and spools on network file systems.
