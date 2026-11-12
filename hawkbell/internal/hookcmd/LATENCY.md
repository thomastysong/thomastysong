# `hawkbell hook` latency

## Current figures: release build (2026-11-12)

Measured with `tools/hooklatency`, which is in the repository: one process
per hooked event, the 540-byte Claude Code `PreToolUse` payload
(`internal/hookio/testdata/claude/PreToolUse.json`) on stdin, wall time
from process start to exit as the agent sees it. 300 runs per case after 10
discarded warm-up rounds, all cases interleaved round-robin. The binary is
built like the release (`CGO_ENABLED=0 go build -trimpath -buildvcs=false
-ldflags '-s -w -buildid='`, 22.9 MB) with a fresh embedded rule cache
(`TestEmbeddedCacheFresh` passed). The spool is on local ext4. Same VM as
the earlier records (Linux 6.18 Firecracker guest, 4 vCPU). The machine was
quiet this time: nothing else was building, and the load average was 1.3
to 1.9.

```
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o /tmp/hb ./cmd/hawkbell
go run ./tools/hooklatency -bin /tmp/hb -dir "$(mktemp -d)" -hello <empty Go program> \
    -payload internal/hookio/testdata/claude/PreToolUse.json -n 300 [-alt <other build>]
```

p50 / p90 / p99, ms, n = 300 each. 0 non-zero exits in 9,000 runs, and no
`hook_worker_timeout` record in any guard spool:

| case | direct | `sh -c` | `bash -lc` |
|---|---|---|---|
| empty hook (`/bin/true`) | 1.33 / 1.62 / 1.91 | 2.19 / 2.80 / 3.43 | 9.61 / 10.88 / 11.98 |
| empty Go program | 1.55 / 1.78 / 3.08 | | |
| kill switch on (process start + package init + one stat) | 4.30 / 5.25 / 6.17 | | |
| **observe, supervised** | **10.42 / 12.07 / 18.24** | **10.97 / 12.76 / 14.20** | **18.74 / 21.17 / 24.45** |
| observe, unsupervised (worker alone) | 5.61 / 6.73 / 7.90 | | |
| guard, supervised | 16.64 / 19.30 / 23.05 | 18.04 / 20.98 / 23.37 | 25.78 / 29.79 / 33.31 |
| guard, unsupervised | 11.97 / 14.64 / 16.40 | | |
| detect-in-hook, supervised | 19.73 / 22.62 / 25.59 | 20.69 / 24.07 / 28.53 | 28.80 / 32.68 / 37.28 |
| detect-in-hook, unsupervised | 15.38 / 17.99 / 21.06 | | |

The shell columns run the command line hookinstall renders,
`[ -x BIN ] || exit 0; exec BIN hook --agent claude-code --config CFG`.
"Supervised" is what hookinstall registers. Before each run, the guard
case was checked to answer "ask" for `curl ... | sh` (HB-EXEC-001), and the
detect-in-hook case was checked to write a detection record.

### Two start-up changes

The commit that recorded these figures made two changes to process
start-up. Both were measured in the same rounds against the rename commit
`d261f98`, built the same way (p50 ms):

| case | `d261f98` | with the changes | change |
|---|---|---|---|
| kill switch (start + init) | 5.96 | 4.30 | -1.66 |
| observe, unsupervised, direct | 7.54 | 5.61 | -1.93 |
| observe, supervised, direct | 14.53 | 10.42 | -4.11 |
| observe, supervised, `bash -lc` | 23.05 | 18.74 | -4.31 |
| guard, supervised, direct | 20.59 | 16.64 | -3.95 |
| detect-in-hook, supervised, direct | 24.83 | 19.73 | -5.10 |

- **`go.opentelemetry.io/otel` v1.16.0 to v1.24.0** (`otel`, `otel/metric`
  and `otel/trace`; `go-logr/logr` moves from 1.2.4 to 1.4.1; no new
  modules). otel is linked only through `github.com/osquery/osquery-go`,
  which the osquery extension and `internal/osqexec` need. In v1.16.0,
  `otel/trace` compiles two regular expressions at package init, about
  1.0 ms per process. That was the largest single init cost, and a
  supervised hook paid it twice. v1.24.0 validates trace state without
  regular expressions. Checked afterwards: the extension registers and
  answers queries on all 9 of its tables in osquery 5.19 shell mode. That
  check ran as `nobody`, with every file under a scratch directory.
- **Lazy patterns.** The catalog's nine validation regular expressions
  (`internal/catalog/validate.go`) and the daemon's uid pattern
  (`internal/daemon/dirs.go`) now compile on first use, not at package
  init. Only catalog loading and the daemon use them. They cost about
  0.35 ms and 0.2 ms per process.

Package init per process (`GODEBUG=inittrace=1`, 7 runs) went from 2.9 to
4.6 ms down to 1.4 to 1.8 ms. The largest remaining items are
`klauspost/compress/internal/snapref` (0.19 ms, zstd for compressed
transcripts), `modernc.org/libc` (0.14 ms, the state database),
`BurntSushi/toml` (0.08 ms) and `yaml.v3` (0.05 ms).

The earlier full-binary record below (18.06 ms observe p50) was measured
with the load average at 2.8 to 3.3. To separate code from load, the code
of that record (`7e6441a`) was rebuilt the same way and measured in the
same rounds as `d261f98`. With the two files a clean checkout of
`7e6441a` lacks taken from `c384122`, observe supervised was 15.86 ms
against 14.62 ms. So between that record and the rename, the code got
about 1.2 ms faster. The rest of the gap from 18.06 ms was machine load.

### Against the spec budget (still open)

Observe supervised is now 9.1, 8.8 and 9.1 ms above the empty hook p50
(direct, `sh -c`, `bash -lc`). Before these changes the gap was about 13 ms.
The spec asks for "a few ms". Of what remains, a supervised call is two
starts of the 22.9 MB binary at about 4.3 ms each (the kill-switch row),
plus about 1.3 ms of observe work (the unsupervised row minus the
kill-switch row).
The way to close most of the rest is still the slim launcher described
below: a hook-only supervisor binary would start in about the empty Go
program time, saving an estimated 2.5 to 3 ms per call. That is a second
binary in packaging and in the hook command hookinstall writes, so it
remains the integrator's decision. Until then, observe latency is a
recorded deviation.

Guard mode stays far inside its 150 ms default deadline: p99 is 23 to
33 ms depending on the launch path, the slowest of this build's 1,200 guard runs took
40.6 ms, and none timed out. Rule loading and engine construction are the
difference between the guard and observe rows, about 6 ms. Detect-in-hook
builds the engine for the full rule set, which adds about 3 ms more.

## Earlier records

Recorded before the rename from the working name spoor to hawkbell: commands, paths and names below use the old name.

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

## The full `spoor` binary (cmd/spoor), measured 2026-11-12

Everything above was measured with a harness that links only
`hookcmd`. The released program is `cmd/spoor`, one binary that is also
the daemon, the osquery extension and the operator CLI, and Go runs the
init of every linked package before `main`. These rows measure that binary
as the agent runs it. Same VM and method as above: a throwaway harness
outside the repository runs each case 300 times after 10 discarded
warm-ups, all cases interleaved round-robin; payload
`internal/hookio/testdata/claude/PreToolUse.json`; both binaries built
`CGO_ENABLED=0 go build -trimpath` from the same tree at the same moment
(embedded rule cache fresh: `TestEmbeddedCacheFresh` passed); spool on
local ext4 in a pre-created per-user spool directory. Load average 2.8 at
the start and 3.3 at the end of the run (4 vCPU shared with other
builders), so p99 is still noisy.

p50 / p90 / p99, ms, n = 300 each, 0 non-zero exits in 3,000 runs:

| case | direct | `sh -c` | `bash -lc` |
|---|---|---|---|
| empty hook (`/bin/true`) | 1.35 / 1.92 / 3.43 | 2.65 / 3.65 / 5.93 | 10.36 / 12.93 / 16.05 |
| hook-only harness (12.9 MB), observe, supervised | 12.12 / 16.25 / 20.07 | 12.84 / 15.70 / 21.61 | |
| **`spoor` (31.2 MB), observe, supervised** | **18.06 / 22.68 / 28.39** | **18.89 / 23.95 / 28.46** | **27.16 / 33.87 / 39.49** |
| `spoor`, guard (default 150 ms deadline), supervised | 29.23 / 35.77 / 42.48 | | |
| `spoor`, kill switch on (start + init + one stat) | 7.27 / 9.62 / 11.85 | | |

The shell rows run the command line hookinstall renders,
`[ -x BIN ] || exit 0; exec BIN hook --agent claude-code --config CFG`.

So the one-binary design costs about 6 ms p50 per hooked event over a
hook-only binary (18.1 against 12.1 ms direct): the call starts two spoor
processes and each pays the larger init and the page faults of a binary
2.4 times the size. `GODEBUG=inittrace=1`, 5 runs each: package init is
3.8 to 6.3 ms per process for `spoor` against 1.7 to 2.3 ms for the
hook-only binary. The largest additions are
`go.opentelemetry.io/otel/trace` (~1.0 ms, linked through
`github.com/osquery/osquery-go`, which the osquery extension and
`internal/osqexec` need), `internal/catalog` (~0.34 ms),
`klauspost/compress/internal/snapref` (~0.18 ms), `modernc.org/libc`
plus `modernc.org/sqlite/lib` (~0.2 ms; the state database) and
`internal/daemon` (~0.11 ms); `internal/mcpconf` (~0.5 ms) and
`internal/rules` (~0.2 ms) are paid by both. Stripping symbols
(`-ldflags "-s -w"`, 22.1 MB) did not change latency (23.70 against 23.33
ms p50 in an earlier interleaved run, made while `internal/bench` was
still linked).

Two changes were made in `cmd/spoor` because of this measurement:

- `internal/bench` is not linked into the default build (build tag
  `spoor_bench`): its package init cost 1.9 to 3.3 ms per process, twice
  per hooked event, for a command that needs the source tree's scenario
  corpus anyway. Before that change the same comparison read 23.3 against
  14.0 ms p50.
- `cmd/spoor` itself has no package-level work left (its maps are built
  on demand); `main` no longer appears in the init trace.

The remaining gap is the link set of the daemon and the extension. The
"slim launcher" above is the way to remove it: a second, hook-only binary
(about the 12.9 MB harness) that hookinstall registers, re-executing
itself as the worker, would give the hook-only row. It costs a second
binary in packaging and in the hook command, so it is the integrator's
call. `modernc.org/sqlite` is in the full binary's init (the
import-graph test in BUILD-C was not written: one binary cannot keep it
out of the hook path; this measurement stands in for it).
