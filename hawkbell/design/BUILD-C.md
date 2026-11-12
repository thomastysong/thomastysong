> **Historical design record.** Build specification for group C (pipeline, daemon, CLI, detection content, Fleet and Fluent Bit content, packaging, documentation), with an addendum from the verification pass.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:53 UTC on the build machine; it has no date of its own).
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# spoor build spec, group C (integration, content, deployment)

Naming: the working name in code is **spoor** (repo `/home/user/thomastysong/spoor`, module `github.com/thomastysong/spoor`, binary `spoor`, env prefix `SPOOR_`, osquery table prefix `spoor_`, rule id prefix `SPR-`). The public name will be changed by the lead in one mechanical pass at the very end, so use "spoor" consistently everywhere now and never mix names.

Read first: `BUILD-A.md` section "Rules for every builder" (all rules apply), `BUILD-B.md` section "Decisions taken after the red-team review" and its Addendum, `design/DECISIONS.md` (the ledger: every design choice and why), then the actual code of the packages you call (group A and B are built; the code is the contract, the older spec text is not). `internal/event` and `internal/config` are the lead's contracts: do not change exported names; additive fields are allowed if you report them.

## C1. `internal/spool` and `internal/hookcmd` — the hook path

```go
package spool
// Dir resolves where a hook process running as uid may append, in order: $SPOOR_SPOOL; <dataDir>/spool/<uid>/ when it exists, is owned by the caller and has mode 0700; else the caller's own state dir (platform.UserDirs(home).Spool, created 0700). Never a shared world-writable directory.
func Dir(dataDir, uid, home string) (string, error)
type Writer struct{ /* ... */ }
func OpenWriter(dir string) (*Writer, error)
// Append writes one record as exactly one write(2) on a file opened O_APPEND|O_NOFOLLOW (no bufio). File name <stream>-<YYYYMMDD>.ndjson, mode 0600. It sets Event.Writer ("hook-<uid>") and Event.Seq from a per-stream counter file updated under an exclusive lock (flock / LockFileEx), and refuses to write when free space is under 64 MiB (ErrNoSpace).
func (w *Writer) Append(e *event.Event) error
// State files for guard mode: <dir>/state/<hex sha256(agent, session)[:32]>.json, 0600, 64 KiB cap, read and written with no-follow opens.
func (w *Writer) LoadState(agentID, sessionID string) ([]byte, bool)
func (w *Writer) SaveState(agentID, sessionID string, b []byte) error

type Root struct{ Dir, UID string; User event.User }
type ReaderOptions struct{ Roots func() []Root; Checkpoint string; MaxLine int; PerUIDPerSecond int /* default 200 */; Retain time.Duration }
type Problem struct{ Kind, Path, Detail string } // forged_kind | owner_mismatch | symlink_refused | not_regular | oversize_line | rate_limited | malformed
func NewReader(o ReaderOptions) *Reader
// Poll reads complete new lines from every spool root as a privileged process. Rules (red-team findings E1/PP-4/F4): open with no-follow + non-blocking, fstat must be a regular file owned by root.UID; ONLY Kind activity records are accepted (a spool can never inject detections, health, inventory or posture: such lines are counted and reported as forged_kind); User, Host, Integrity ("user"), and Writer are overwritten from the file owner and local host, never taken from the payload; per-uid token bucket; fully-read files older than Retain are deleted.
func (r *Reader) Poll(ctx context.Context) ([]*event.Event, []Problem, error)
```

```go
package hookcmd
type Env struct{ Getenv func(string) string; UID, User, Home string; PID, PPID int; Now func() time.Time }
// Run implements `spoor hook --agent <id> [--config <path>]`. Contract (each line is a red-team finding; test every one):
//  1. Exit code is ALWAYS 0. Decisions are expressed only in the agent's JSON reply. Exit 2 is never used, because the Go runtime also exits 2 on a fatal error and exit 2 means "block" to every agent.
//  2. A deferred recover and a watchdog (default 2 s) force exit 0 with an allow-shaped (empty) reply; no code path may deadlock or wait without a timeout.
//  3. stdin is read with a cap (config limits.max_hook_input_bytes); deeper nesting than 64 or a decode error produces a minimal "hook.payload_anomaly" activity record (size, sha256 of the raw bytes) instead of nothing.
//  4. Payloads are decoded into maps (case-sensitive keys), never into structs.
//  5. No path from the payload is ever opened.
//  6. Observe mode (guard off, in-hook detection off) loads no rules: normalize, stamp, append, exit.
//  7. Guard mode (config guard.mode advisory): load rules.GuardSubset, import session state, Eval with the configured deadline; on Timeout the reply is "ask", never allow; responses are capped by guard.max_response; save state.
//  8. In-hook detection (config sources.hooks.detect_in_hook, for daemonless/container/CI use): the full rule set is evaluated and detection records are appended too (integrity user).
//  9. Every record gets Host (platform.HostInfo), User (OS identity of the process, not the payload), Integrity (root only if euid 0), deterministic ID and Dedupe (event.StableID / event.DedupeKey over host, agent, session, tool use id or payload hash, type), and Process: the caller chain captured NOW (ppid, its start time, exe path, names of up to 8 ancestors) because the hook is a child of the agent, which makes this the one exact process-identity join key for EDR data.
func Run(stdin io.Reader, stdout, stderr io.Writer, args []string, env Env) int
```
Add `DetectInHook bool yaml:"detect_in_hook"` to `config.HookSource` (you may edit `internal/config` for this one field and its test).
Measure and report hook latency on this machine: direct exec, `sh -c`, and `bash -lc` launch paths, observe vs guard vs detect-in-hook, p50/p99 over 300 runs (the red team measured 1.7 / 2.5 / 8.5 ms p50 for an empty hook: yours must stay within a few ms of those in observe mode).
Tests: concurrency (20 processes appending 500 records each: every line parses, seq per stream is gapless and unique); forged spool lines rejected by Reader with identity overwritten; symlink, FIFO and foreign-owner files refused without hanging; hostile stdin fuzz asserting exit code 0 and bounded time; guard deny/ask rendering per dialect; watchdog; no-space behaviour.

## C2. `internal/engine` — the pipeline

```go
package engine
type Options struct {
    Config   *config.Config
    Catalog  *catalog.Catalog
    Rules    *rules.Set
    Policy   *privacy.Policy
    Outbox   sink.Sink        // shipped records (root-owned segments or stdout)
    Local    sink.Sink        // local ring for records that must not leave the host (may be nil)
    State    *state.Store     // may be nil (hook/detect/CI modes)
    Host     event.Host
    Mode     string           // daemon | scan | detect | hook
    Integrity event.Integrity
    Now      func() time.Time
    Hooked   func(agentID, user string) string // discovery's view of hook state for coverage logic: managed|user|missing|modified|shadowed|unsupported
    RootSaw  func(agentID, user string) bool    // true when the process monitor (root-observed) currently sees that agent running
}
func New(o Options) (*Pipeline, error)
func (p *Pipeline) Ingest(evs ...*event.Event) // safe for concurrent use; never blocks on I/O longer than a bounded queue (drops are counted, never silent)
func (p *Pipeline) Tick(now time.Time)         // grace timers, session summaries, heartbeat, state flush
func (p *Pipeline) Coverage() []event.Coverage
func (p *Pipeline) Close() error
```
Behaviour (each item traces to `DECISIONS.md`):
1. Exclusions first (`Policy.Excluded`): excluded sessions are counted in health and never processed further.
2. Identity: deterministic `ID`/`Dedupe` if the source did not set them; `Host` forced to Options.Host; `Integrity` defaulted from Options.
3. One activity record per action. Hook is primary. A transcript or OTel record whose `Dedupe` was already seen only adds its source to the session's surfaces. A transcript tool event with no hook counterpart is held 10 s, then processed as activity (so coverage is kept when hooks are absent). OTel `hook_execution_complete` counts are compared with hook records received.
4. Coverage per (agent, user) and per session: `covered` (hook + another surface), `partial`, `blind`, `absent`. A "hook bypass suspected" FINDING requires an independent root-observed surface (process monitor saw the agent, or the OTel receiver) together with at least 3 unmatched tool calls while `Hooked` says hooks should be there; with only self-reported surfaces it is a low-severity signal, rate-limited to one per session, never attributed across users. A root-observed agent process with a hook-free/persistence-free flag or with no hook and no transcript activity for 60 s is `blind`.
5. Features + rules: `features.Compute`, `rules.Engine.Eval`; engine sets session feature inputs (written-path set for write-then-run).
6. Secret flow (the precise replacement for the co-occurrence trifecta): when a tool result from a sensitive read (features `path.sensitive_read` or secret read classes in a shell event) carries content, remember up to 64 secret values per session in memory only (`classify.FindSecrets` hits, plus tokens of 20+ chars with entropy over 3.5 from secret-class files); on later shell, web and MCP events search command, URL and tool-input strings for each value and its base64, hex and URL-encoded forms; set features `flow.secret_egress` (bool) and `flow.secret_kinds` before rule evaluation. Values are never written anywhere.
7. First-seen baseline: a small persistent LRU (file under the checkpoint dir, 20k keys) of (user, egress host) and (user, MCP server definition hash); features `net.host_first_seen`, `mcp.server_first_seen`.
8. Rule classes: detections carry `Detection.Class` (signal | finding | alert; add the field to `internal/event` if the rules builder has not). Only classes at or above `config.Rules.MinClass` are written to the detection stream; signals still count into the session summary. Dedup/suppression per rule engine. Operator suppressions from config and bundle apply.
9. Context: a ring of the last `Privacy.ContextEvents` events per session; when a finding or alert is emitted, `Policy.Context` renders them into the detection stream labelled `context_for`.
10. Session summary (`event.Summary`): updated on every event, emitted at session end, after 15 min idle, and every 15 min while active (Final=false).
11. Volume: token bucket per session on activity (config.Limits); suppressed counts go to the summary and heartbeat.
12. Privacy: `Policy.Emit` decides outbox vs local ring. Records are written with `Writer` = this process's random id and `Seq` monotonic per (writer, stream).
13. State: inventory, posture, detections (aggregated rows), summaries, coverage, agent processes, health are applied in batches on Tick.
14. Heartbeat (`event.Health`): per-stream accounting `{emitted, dropped, truncated, first_seq, last_seq}` for the interval (put them in Counters with stable key names such as `stream.detection.emitted`), surface status with schema-drift flags, coverage list, rules count/hash/version, catalog version, bundle version, shipper lag when known. It is content-free.
Tests: table-driven scenario tests that feed synthetic event sequences from each surface and assert emitted records (hook+transcript duplicate collapses; transcript-only held then emitted; bypass finding only with RootSaw; forged cross-user attempt ignored; secret flow end to end with base64 variant; write-then-run; rate limit; minimal vs standard profile routing; summary content; heartbeat accounting sums match what the fake sinks received); race detector clean.

## C3. `internal/daemon` and `cmd/spoor` — the product surface

`internal/daemon`: `func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error` wires everything: privilege check and directory creation with explicit ownership/modes (outbox dir root:<group> 0750, files 0640; state dir 0700; per-user system spool dirs `<data>/spool/<uid>/` created 0700 and chowned for every discovered user; on Windows use explicit ACLs via `golang.org/x/sys/windows` (SYSTEM + Administrators full, the user modify on their own spool dir) and say in the summary what is unverified), sources (spool reader, transcript tailer with roots from catalog transcripts for every user plus config-home overrides reported by procmon, procmon, osqlog, otelrecv when enabled, adapters), scan scheduler (full scan on start, differential on interval, `discovery.ScanProject` on every new session cwd), bundle puller (verify, install, reload rules/lists/catalog overlay without restart, stamp versions), outbox pruning (by age; when `output.fluent_bit.tail_db` is set open Fluent Bit's tail DB read-only, compute per-segment shipped offsets, prune only fully read segments until the hard byte cap, and emit a `health.error` with reason `outbox.dropped_unshipped` and counts when the cap forces dropping unread data; export `shipper_lag_bytes`), optional shippers (`sink.NewShipper` over the outbox for forward/OTLP), heartbeat ticker, graceful shutdown that flushes. Linux/macOS: plain foreground process for systemd/launchd. Windows: `golang.org/x/sys/windows/svc` service wrapper.

`cmd/spoor` (standard library `flag`, no CLI framework; every command supports `--json` where it prints data; exit codes documented in `--help`):
- `run [--config]`, `hook --agent <id>`, `scan [--json|--ndjson] [--state] [--host-root]`, `detect [--format native|numbat] [--rules dir] [files|-]` (the engine over NDJSON for central re-evaluation, CI and benchmarks; prints detections and a summary; exit 3 when findings at or above `--fail-on` exist),
- `hooks install|uninstall|status [--scope managed|user] [--agents a,b] [--guard] [--dry-run]` (dry-run prints the plan and diffs),
- `rules list|test|lint [--dir]`, `bench [--scenarios dir] [--json]` (calls internal/bench if present, else says so),
- `doctor` (one screen: privilege, dirs and modes, host id and its source, hooks status per agent and user incl. `shadowed`, rules/bundle versions, last heartbeat, Fluent Bit checks: if `output.fluent_bit.api` is set query `/api/v1/storage` and config for the tail input and warn `shipper.unsafe_config` when the tail input is memory-buffered or retries are bounded; outbox readable by `--as-user`),
- `privacy show|tail|purge --user <u>` (show = Policy.Describe plus retention and destinations; tail = follow the caller's own emitted records),
- `export fleet|fluent-bit|kubernetes|atc [--out dir]` (writes the embedded deployment content from `deploy/` (embed it) with this host's paths substituted),
- `bundle keygen|create|verify|pull`, `catalog list|verify` (verify: HEAD/GET npm and PyPI registry endpoints for every `npm:`/`pip:` package in the catalog, report 404s and renames; network optional),
- `ci exec -- <cmd...>` (experimental: user-scope hooks into a temp config home via each agent's home env var where possible, detect-in-hook on, run the command, then print findings and exit non-zero per `--fail-on`),
- `version`, `licenses`.
- Invoked by osquery as an extension (argv contains `--socket`, or the executable name ends in `.ext` / `.ext.exe`): call `osqext.Run`.
An import-graph test asserts `cmd/spoor` hook path does not import `modernc.org/sqlite` transitively at init cost... if separating is impractical, measure `hook` latency with the full binary and report it instead.
End-to-end test (Linux, real processes, in `test/e2e`, run by `go test ./test/e2e -tags e2e`): build the binary, create a fake home with a fake Claude Code transcript and config, run `spoor hooks install --scope user`, pipe real-shaped hook payloads into `spoor hook`, run `spoor run` for a few seconds with a temp data dir, assert: outbox segments contain the expected detection for a `curl | sh` payload, activity stayed local in minimal profile, state DB has the detection and a fresh heartbeat, `spoor doctor --json` is sane.

## C4. Detection content: `internal/rules/packs/*.yaml`, `lists.yaml`, `internal/bench`, `bench/`

Rule packs: implement the detection catalogue in `research/threats.md` sections 3 and 4 (R01..R54, S1..S12) as far as the available features allow, organised as packs `execution`, `credential`, `exfiltration`, `persistence`, `defense-evasion`, `destructive`, `supply-chain`, `agent-integrity`, `process`, `offensive`, `sequence`, `posture` (inventory rules over asset risk flags), `coverage`. Every rule: id `SPR-<AREA>-<NNN>`, class (signal | finding | alert), severity, confidence, maturity, tags with ATT&CK v20 ids, ATLAS ids and OWASP ASI ids taken from `research/standards.md` (do not invent ids: omit when unsure), references to the incident or CVE in threats.md, falsepositives, remedy, at least one positive and two negative tests (benign look-alikes from threats.md section 6 and `redteam/detection-quality.md` "22 ordinary workflows").
Precision rules from the detection-quality red team (binding):
- Shell rules match parsed facts only; `|re` or `|contains` on `target.command` is a lint error (use features; if a feature is missing ask for it in your summary rather than regexing raw text).
- A rule may be class `alert` only if it is expected to stay silent on ordinary developer work; everything broad is `finding` or `signal`. Co-occurrence trifecta (untrusted input + secret read + egress) is a `signal`; the alert-class version requires `flow.secret_egress: true`.
- `untrusted_input` is not set by package registries, the org's own code hosts or documentation hosts (lists).
- Workspace-relative logic: `rm -rf` inside cwd/temp is never destructive; use the `shell.destructive` vocabulary.
- Guard responses: only a handful of near-zero-FP rules get `response: ask` (pipe-to-shell from a non-allowlisted host, agent writing its own managed hook/policy files, stopping the sensor or a security tool, secret-flow egress); nothing ships with `response: block`.
Then measure, do not assert: (1) `spoor rules test` and `lint` clean; (2) replay over the REAL agent sessions on this machine: `/root/.claude/projects/**/*.jsonl` (the transcripts of the agents that built this project: hundreds of sessions, thousands of tool calls; there is no attacker in them except red-team experiments) through the transcript parser and engine (`spoor detect` or a small harness), and report per rule: hits, sessions hit, hits per 1,000 tool calls, and whether each sampled hit is a true false positive, a red-team experiment (true positive, non-malicious) or a rule bug; tune rules and lists until alert-class rules have zero false positives on this corpus and finding-class rules are individually under 5 hits per 1,000 tool calls, and write the before/after table to `bench/results/benign-replay.md` with the corpus size, date and limits (one workload, n sessions, Wilson intervals).
`internal/bench` + `bench/scenarios/*.yaml`: scenario = named sequence of events (same partial-event shape as rule tests, with content) plus `expect: [rule ids]` / `expect_none: true`, labels `incident:` (threats.md table row), `technique`, `outcome` (attempted | succeeded). Corpus: at least 60 attack scenarios drawn from the 48 incident rows (author them from the incident mechanics, not from the rules) and at least 60 benign look-alikes; `mutations:` per attack (quoting, `$IFS`, wrapper, variable assembly, interpreter one-liner, split across two events) so the runner reports plain recall AND robust recall; ablations by surface (hook-only, transcript-only); trivial-oracle baselines (rule fires on tool name only). Runner output: per rule and per technique TP/FN/FP with Wilson 95% intervals, cells with n < 30 marked "insufficient", JSON and Markdown; `bench/results/scenarios.md` committed. State plainly in the result files what this corpus cannot show (prevalence, a real benign fleet).

## C5. `deploy/fleet` — Fleet content, verified on the live server

Produce and VERIFY against the running Fleet 4.94.1 (ENV.md; use `fleetctl gitops --dry-run` and real applies on a scratch fleet/labels that you remove afterwards; never leave the shared server changed): 
- `deploy/fleet/README.md` with the three tiers (no binary over fleetd built-ins; scan + ATC; daemon + extension) and exactly what Fleet Free vs Premium allows (research/fleet.md, redteam/fleet-operator.md).
- GitOps fragments under `deploy/fleet/lib/`: `agent-options.atc.yml` generated from `state.ATCConfig` for linux/darwin/windows (overrides are not merged: show the full blocks), labels (spoor installed, AI agents present, sensor unhealthy), policies (sensor heartbeat fresh; managed hooks effective for every detected hook-capable agent; no critical or high findings in 24 h; no agent in bypass mode; no unpinned or inline-secret MCP server; no autorun plant in a project; rules bundle current) each written fail-closed (every "no X" policy also requires a fresh `spoor_health.heartbeat`, because a missing DB reads as zero rows), reports (`spoor detections` differential with `automations_enabled`, packed inventory, coverage, and, as a clearly marked OPT-IN example only, an exec-events report joining `process_events` / `es_process_events` / `process_etw_events` to `spoor_agent_processes`, with a privacy warning: a Fleet-scheduled query over evented process tables sends raw command lines for the host to the Fleet server outside spoor's privacy profiles, which is why the daemon pulls those rows locally over the osquery socket instead), a `fleetd` profile that uses Fleet's own `ai_tools` tables where they exist and a `stock` profile for plain osquery.
- Install/uninstall scripts for Fleet scripts (sh and ps1, under 10,000 characters each, idempotent, verify a SHA-256 before install, create group and dirs, install the service unit, register the extension in osquery's default `extensions.load`, never `/opt/orbit/extensions.load`, restart orbit detached), and `*.package.yml` examples for Premium.
- A test script `deploy/fleet/verify.sh` that applies the ATC options to the live server, runs live queries against every `spoor_*` table through Fleet on the enrolled host with a real state DB produced by `spoor scan --state` and `spoor run`, evaluates each policy query on a healthy host, on a host with a planted finding and with the state DB removed (must fail, not pass), and restores the original agent options. Commit its captured output as `deploy/fleet/VERIFIED.md`.

## C6. `deploy/fluent-bit` — the transport contract, verified on the real image

- `deploy/fluent-bit/spoor.yaml`: tail input on the outbox with `storage.type: filesystem`, `db` + `db.compare_filename: true` + `db.locking: false`, `read_from_head`, `refresh_interval: 5`, `buffer_max_size` at least 4x the line cap, `skip_long_lines: on`, parser with the exact time format spoor emits, tag `spoor.<stream>` from the file name, `retry_limit: no_limits` and explicit `storage.total_limit_size` on every output; a catch-all output; parser-miss records routed to a visible stream.
- Output examples (each a small include): Splunk HEC, Elasticsearch/OpenSearch (with `id_key: id` so at-least-once replays are idempotent), Microsoft Sentinel (azure_logs_ingestion), Google Chronicle/SecOps, S3 archive for activity, Kafka (`message_key_field`), Loki, OTLP (`opentelemetry` output), plus routing detections+summary+health to the SIEM and activity to object storage.
- `osquery.yaml` (tail Fleet's local/server osquery result log with the verified `calendarTime` parser), `numbat.yaml` (tail numbat NDJSON), and `no-binary/` (agents' native OTel pinned by managed settings into the `opentelemetry` input, a Lua normalizer and a small lite rule set; say clearly what this rung cannot do; reuse the experiment in `redteam/alt-arch/`).
- `kubernetes.yaml` snippet for a Fluent Bit DaemonSet reading the node sensor's stdout.
- `test/e2e/fluentbit_test.go` (tag e2e, uses the local `fluent/fluent-bit:latest` image with `--network host`, unique ports): (1) every stream arrives with correct tag and event time through tail; (2) the kill test from the red team: output down, write 5,000 records, SIGKILL and also graceful stop, restart with output up, assert 5,000 of 5,000 with the shipped config (and document that the default memory config loses them); (3) prune safety with the tail DB awareness; (4) a 5 MB command becomes one truncated record under the cap; (5) forward and OTLP shippers deliver through `forward` and `opentelemetry` inputs with filesystem buffering; (6) `--dry-run` validation of every shipped YAML against the image. Commit captured results as `deploy/fluent-bit/VERIFIED.md`.

## C7. Containers, packaging, service units, CI

- `deploy/kubernetes/`: node sensor DaemonSet per the red team's "minimal honest container story" (`redteam/containers-k8s.md`): hostPID, non-root uid with file capabilities `cap_sys_ptrace,cap_dac_read_search` only, read-only root FS, no hostPath, events to stdout, health reports `procs_unreadable`; in-image hook mode docs (devcontainer Feature / Dockerfile snippet); the unsupported list. Test what can be tested here with docker (`--pid=host`, the two caps, a container with a fake agent home and a marker process): the sensor finds the in-container agent, attributes container id, refuses a planted symlink escape. Commit results.
- `Dockerfile` (multi-stage, distroless/static or scratch, non-root, `setcap` applied in the build stage), `.goreleaser.yaml` (linux/darwin/windows amd64+arm64, `-trimpath`, reproducible flags, nfpm deb/rpm with systemd unit and pre/post scripts, archives, checksums, SBOM and cosign hooks), `packaging/` (systemd unit with hardening directives that still allow reading user homes, launchd plist, Windows service install script, macOS `pkgbuild` script and WiX sketch marked untested), `Makefile` (build, test, lint, e2e, cross, package). Actually build the deb and rpm here (use `go run github.com/goreleaser/nfpm/v2/cmd/nfpm@latest` in a temp GOFLAGS=-mod=mod dir outside the module, or a hand-rolled `dpkg-deb` build if nfpm is unreachable), install the deb in a throwaway container if an image is available locally, and report.
- `.github/workflows/ci.yml` (kept under the project directory with a note that it must move to the repository root when the project gets its own repo): build + test on ubuntu, macos, windows; cross-compile matrix; rules test + lint + bench gate; Fluent Bit and osquery e2e on Linux.

## C8. Documentation (written last, from the code)

`README.md` (what it is in 5 lines, the honest positioning from DECISIONS.md, 10-minute quick starts for Fleet and for Fluent Bit, architecture diagram in Mermaid, coverage matrix by agent and surface with verified/unverified marks, comparison table with uber/ADR, numbat, Agent Beacon, Agentmetry, snyk/agent-scan, agent-bom, Fleet built-ins where every cell is backed by `research/*.md`), `docs/DESIGN.md`, `docs/ASSUMPTIONS.md` (the red-team ledger: assumption, attack, evidence, verdict, change; from DECISIONS.md and `redteam/*.md`), `docs/EVENTS.md` + `docs/schema/event.schema.json` (generated from `internal/event` and validated against golden events), `docs/RULES.md`, `docs/FLEET.md`, `docs/FLUENT-BIT.md`, `docs/PRIVACY.md` (profiles, what each record contains, retention, exclusions, transparency commands, DPIA/works-council notes, not legal advice), `docs/LIMITATIONS.md` (the non-goals list and the hardware test matrix for Windows/macOS from `redteam/platform-parity.md`), `docs/COMPARISON.md`, `SECURITY.md`, `CONTRIBUTING.md` (no CLA), `NOTICE` (uber/ADR, snyk/agent-scan, numbat, agentic-detector credits; third-party notices), `THIRD_PARTY_LICENSES`.
Docs rules: every claim about spoor must be true of the code in the repo (run the command before you document it and paste real output); every claim about another project must cite the research report section; measured numbers carry their conditions; no claim of Windows/macOS behaviour beyond "compiles and unit-tests pass" unless tested.


## Addendum (verification pass; applies to C1, C2, C3, C5, C7, C8)

- Exec route: the daemon gets exec ground truth from `procmon` (Linux process connector) and `internal/osqexec` (pull over the osquery extension socket). There is no results-log tailer and no default Fleet-scheduled exec report. Config key `sources.osquery_log` is renamed by the lead to `sources.osquery_exec` (fields `enabled`, `socket`, `interval`); use whatever `internal/config` says at the time you build.
- `--bare` is an attribute, not a hook-free signal (managed tool hooks still run on the Claude Code release tested). Session start is synthesized from the first event of an unseen session id; the SessionStart hook is not required.
- Evidence allowlist (privacy red team, "rule packs as covert content search"): `Policy.Evidence` may copy only fields from a fixed allowlist of non-content fields (redacted command, paths, hosts, classes, counts, ids). Prompt text and tool output can never be evidence in `minimal` or `standard`, whatever a rule asks for; in `full` they are redacted and capped. Rule and bundle versions are stamped on every finding so a content-searching rule is attributable.
- The 16 KiB cap is enforced on the ENCODED line (JSON escaping can inflate a value up to 6x), not on raw field lengths.
- Tenant HMAC key limits (document, do not oversell): the key is on every endpoint, so keyed digests protect against readers of the log store and cross-tenant linkage, not against someone with root on the endpoint; in daemonless mode the hook has no key and emits no digests.
- Transcript tailing starts at end of file for files that existed before first sight (no retroactive collection of pre-deployment activity); backfill is an explicit operator action.
- Windows: no file handles are held between polls on agent-owned files.
- Kill switch: `platform.Disabled()` (file `<config dir>/disabled`) makes `spoor hook` exit 0 immediately and the daemon idle its collectors; `doctor` shows it.
- Containers (C7): confine opens with openat2 RESOLVE_IN_ROOT AND require the file to be a regular file owned by the uid of the agent process being followed (a non-root agent must not be able to make the node sensor read root-owned files inside its own container); open non-blocking so a FIFO cannot stall the harvester; anchor a session on the agent ROOT process (tool children inherit the session env markers and exit within milliseconds; anchoring on one captured 14 of 60 lines in the verifier's test); checkpoints are keyed by container id + pid start time + in-container path (the same in-container path had the same device number in six successive containers); `procs_unreadable` counts only EACCES/EPERM on live user-space pids. In-image hook mode cannot use stdout (hook stdout is the agent's control channel): it appends to a spool in a writable dir such as `/dev/shm/spoor` that the node sensor harvests, or ships by OTLP. State all of this in the docs with the unsupported list (microVM runtimes, Docker Desktop/Colima/OrbStack VMs on macOS and Windows, NFS-backed homes, Fargate/Autopilot, Windows containers, vendor-hosted agents).
- Structural command redaction table must also cover: `curl --proxy-user`, `openssl -passin pass:X` / `-passout`, nested commands after `--` (`kubectl exec ... -- mysql -pX`), `aws configure set <key> <value>`, and literals piped into `--password-stdin`.

- Fluent Bit (C6), from the pipeline verification runs: (1) use a SEPARATE tail input per stream group (at least: detection+summary+health+posture+inventory, and activity) because with one tail input and the activity destination down, 0 of 10 detections reached a healthy SIEM sink (head-of-line blocking); (2) set `storage.keep.rejected: on` with a limit, because with filesystem buffering and `retry_limit: no_limits` a single HTTP 401, 400 or 413 still dropped the chunk after one request (a rotated SIEM token silently discards data), and have `spoor doctor` read Fluent Bit's `/api/v1/metrics` and warn on `dropped_records` > 0; (3) the tail DB must live on persistent storage (in Kubernetes a hostPath, not emptyDir): deleting it replayed 5,000 delivered records as 10,000; deterministic record ids make that survivable, document the dedupe; (4) add all four as e2e cases; (5) the YAML must also be valid when the operator merges it into an existing Fluent Bit config: ship it as an includable fragment plus a standalone file.
- Late events (C2/C6): laptops offline for days deliver records with old `ts`. `event.Event` has an `Emitted` time the pipeline sets when a record is written more than 60 s after its `ts`; document that SIEM rules with event-time lookback windows should use `emitted` for scheduling and `ts` for ordering.
- Fleet policies (C5): two windows. The dedicated "sensor heartbeat fresh" policy uses a short window (30 min) and is the one to alert on. Every "no X" policy embeds a LONG heartbeat guard (24 h) so a removed sensor or deleted DB fails within a day without turning every policy red after a laptop wakes from sleep. Say this trade-off out loud in the README. The ATC content is shipped as a fragment with explicit merge instructions and a warning that replacing agent options drops existing ATC tables, decorators and options.
