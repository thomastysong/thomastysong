# Assumptions ledger: how the design was attacked before it was built

Before any product code existed, the first design ("v0") was written down as 37 explicit, numbered assumptions and handed to ten hostile reviewers, each with a different persona. Every reviewer had to break assumptions with evidence: a cited primary source or, preferably, an experiment run against real software (Fleet 4.94.1 with an enrolled osquery 5.19 host, the Fluent Bit 5.2.0 image, Go prototypes). A second, independent reviewer then tried to refute each finding. This file records what was assumed, what broke, the evidence, and what changed. It is kept in the repository because the failures are more useful to a prospective user than the features.

Verdicts: **broken** (the claim was false or the design as written failed), **weakened** (true only with a stated restriction), **holds** (a serious attempt to break it failed).

Scope of the evidence: all experiments ran on one Linux x86-64 sandbox VM on 2026-11-11. Nothing here is a measurement on Windows or macOS hardware; see [LIMITATIONS.md](LIMITATIONS.md) for the hardware test matrix that follows from that.

## The reviewers

| Lens | Persona | Assumptions attacked |
|---|---|---|
| Evasion | attacker controlling the agent's context, or the developer hiding activity | A1 A3 A5 A6 A9 A11 A27 A28 |
| Detection quality | SOC detection engineer owning the alert queue for 10,000 developers | A8 A10 A12 A13 A26 A29 A35 |
| Fleet operator | Fleet admin with 20,000 hosts, mostly Fleet Free | A16 A17 A18 A19 A20 A30 A33 |
| Pipeline operator | logging engineer who runs Fluent Bit everywhere and pays the SIEM bill | A14 A15 A21 A22 A23 |
| Platform parity | Windows and macOS endpoint engineer | A2 A7 A20 A24 |
| Containers | Kubernetes platform engineer running dev workspaces and CI | A25 |
| Privacy and sensor security | privacy counsel plus an application security engineer | A26 A27 A28 A29 A32 A34 |
| Skeptical buyer | security architect who already runs Fleet and Fluent Bit | A19 A30 A31 A36 A37, the thesis |
| Alternative architectures | principal engineer arguing the top-level design is wrong | the thesis, A5 A8 A17 A21 A30 |

## What broke, with the evidence

### Transport: "NDJSON files plus Fluent Bit tail is at-least-once" (A14) — broken
- With Fluent Bit's default memory buffering, the tail input commits its file offset when it reads a line, not when an output delivers it. Test: 5,000 events, output unreachable, Fluent Bit restarted. Delivered after recovery: **0 of 5,000** with memory buffering (graceful stop or default retry), **5,000 of 5,000** with `storage.type: filesystem` and `retry_limit: no_limits` even after SIGKILL.
- Pruning segments by deletion while Fluent Bit lags lost data silently: **3,552 of 40,000** delivered. With inode reuse and default tail settings the first 1,000 of 3,000 records of the next segment were skipped; `db.compare_filename: true` fixed it.
- One 200 KB event line stopped the whole segment with default tail settings (32k buffer); with `skip_long_lines` the event vanished.
- Concurrent appenders did hold: 0 torn lines in 29,568 lines up to 1 MB from six processes using one `write(2)` per line on `O_APPEND`.

Changes: the shipped Fluent Bit configuration is part of the contract (filesystem buffering, unlimited retries, filename comparison, long-line skipping); every emitted line is capped at 16 KiB with truncation recorded; the sensor reads Fluent Bit's tail database and prunes only segments that were read, and emits a health error with counts when a hard cap forces dropping unshipped data; `doctor` flags an unsafe shipper configuration; the kill test runs in CI against the real image. The claim is now "at-least-once only with filesystem buffering".

### Integrity: "a user-writable spool is an acceptable trade-off" (A28) — broken
- Forgery, not deletion, is the real risk. Three lines were appended to a spool file as the user: one genuine, one forged detection marked "cleared, approved by security", one forged activity record attributed to a different user. Fluent Bit shipped all three verbatim.
- A root Fluent Bit tailing a user-owned directory shipped whatever file the user symlinked into it (confused deputy).

Changes: hooks write only to a per-user spool that nothing ships directly in the supported fleet mode. The root daemon ingests spools with no-follow, non-blocking opens and an owner check on the open descriptor, accepts **only activity claims** from them (a spool can never inject detections, health, inventory or posture), sets user and host from the file owner rather than the payload, stamps `integrity: user`, and re-runs detection itself. Fluent Bit tails only the root-owned outbox. Every record carries `integrity`, and Fleet policies depend only on root-integrity data. Daemonless operation still exists for containers, CI and evaluation and is labelled as such.

### Corroboration: "three independent surfaces" (thesis, A5, A6) — broken
- Hooks and transcripts are both written by the agent. The third surface, process polling, saw **7 of 120** short-lived child processes at a 1 s interval and none of the 100 shortest at 250 ms.
- osquery's audit-backed `process_events` captured **5 of 5** millisecond-lived processes with full command lines, and they reached the local results log within one 5 s interval. Its BPF publisher failed in the same VM while reporting `active=1`.
- Disagreement between surfaces can be driven to zero (hook-free plus transcript-free plus relocated config) or forged upward (write a transcript for tool calls that never ran).

Changes: the poller is described as what it is (agent presence, flags, long-lived children). Exec ground truth comes from the Linux process connector where available and from osquery evented tables by tailing osquery's local results log. A "hook bypass suspected" finding requires a root-observed surface; with only self-reported surfaces it is a low-severity, rate-limited signal that is never attributed across users.

### Hosting the daemon inside the osquery extension (A17) — broken
The extension process exited 3 s after osqueryd was killed, taking any hosted collector with it. The extension is tables only.

### Host identity equals osquery's `system_info.uuid` (A20) — broken
On a machine without SMBIOS data, four osquery databases produced four different random UUIDs, none related to `/etc/machine-id`; on hardware with DMI the Linux source is readable by root only. Changes: identity order is explicit configuration, then a file written by the extension (which asks osquery itself), then hardware identifiers, then machine-id; the source is reported in health. An exact join with Fleet requires the extension or explicit configuration.

### Fleet tables through ATC (A16) — weakened
- WAL mode: 0 torn reads of 75 while a writer committed every 50 ms. Rollback-journal mode: torn snapshots with no error (4 of 10 through Fleet).
- A missing database reads as zero rows with no warning, so every "no critical findings" style policy **passes** when the sensor is absent.
- No predicate pushdown: 10,000 rows cost 26 ms and 12 MB per query, 100,000 rows 270 ms and 107 MB, and one live query over 300,000 rows tripped the 200 MB watchdog while Fleet reported success.
- Replacing the database by rename replayed a stale WAL over the new file.

Changes: WAL only and never rename; row caps per table; every policy also requires a fresh heartbeat row so absence fails closed; the extension is the recommended path at scale; ATC remains the ten-minute start.

### Privacy: "metadata tier by default" (A26) — broken, critical
The proposed default shipped user name, working directory, file paths, command lines and web search queries for every tool call: identified behavioural monitoring. An unkeyed SHA-256 of prompts was reversed for 4 of 6 short sample prompts with a 1,600-entry dictionary built in 1 ms.

Changes: three emit profiles. `minimal` is the default: findings, inventory, posture, health and per-session summaries leave the host, activity stays in a local ring and travels only as context attached to a finding. `standard` ships activity with field-level redaction. `full` adds redacted content. Digests of content are HMAC with a tenant key or are not emitted. Exclusions by path, repository and user apply before any content is processed. `privacy show`, `privacy tail` and `privacy purge` exist for the people being monitored. Retention has stated defaults.

### Redaction by patterns and entropy (A29) — broken
8 of 17 invented secrets survived (hex tokens at the entropy threshold, values after unlisted flags); over-redaction removed hosts and an image digest. Changes: redaction is structural first (the parsed command says which argument is a credential for `mysql -p`, `curl -u`, `-H Authorization`, assignments to sensitive names, URL userinfo), patterns second; a canary corpus runs in CI and the measured leak and over-redaction rates are published rather than asserted.

### The sensor as attack surface (A27) — broken in several places
- A root reader followed a user-placed symlink; a FIFO named like a config blocked the reader indefinitely.
- Rule cost scales with input: 10 patterns over 1 MiB took 290 ms; compiling 300 regexes costs 77 ms per process.
- An unrecovered Go panic or runtime fatal error exits with status 2, and exit 2 means "block" in every agent's hook contract: a crashing observe-only hook would block tool calls.

Changes: no path taken from hook input is ever opened; all reads of user-controlled trees use no-follow, non-blocking opens and check type and owner on the descriptor; content scans are bounded to head and tail windows with a wall-clock deadline; the hook always exits 0 and expresses decisions only in JSON, with a recover handler and a watchdog; scan and collection packages may not import `os/exec`.

### Shell analysis as a robust basis for rules (A9) — broken against a motivated evader
A canonicalizer built on a real POSIX parser saw `curl ... | sh` but not `eval` of runtime-assembled strings, interpreter one-liners, heredocs built from character codes, decoded payloads fetched at runtime, or a script written by an earlier tool call and then executed. Changes: these constructs are surfaced as an explicit `opaque` feature that rules score, write-then-run is correlated across events, and the documentation lists what cannot be seen without a kernel sensor.

### Co-occurrence "lethal trifecta" as an alert (A10) — broken
Replayed over 37 real agent sessions with no attacker present: `untrusted_input` was set in 68% of sessions and `egress` in 65%, so the rule reduced to "a secret-class path was touched" and fired in 1 of 37 sessions. At 100,000 sessions a day that is thousands of alerts with a positive predictive value near zero. Regex-on-text rules produced dozens of false hits that parsed-fact rules did not, and flat predicates over arrays over-matched 3.3x to 3.6x because they cannot say "the same command".

Changes: rules have three classes (signal, finding, alert); co-occurrence is a signal; the alert-class rule requires data flow (a secret value the agent actually read later appears, raw or encoded, in an outbound command, URL or tool input); shell rules may match parsed facts only, enforced by lint; a bound quantifier (`any_command`) expresses "the same command"; first-seen baselines and operator suppressions are first-class; rule quality is measured by replay over real sessions, not asserted from inline tests.

### Guard mode as prevention (A12) — unsafe as a control
Hook timeouts fail open in almost every agent, so stalling the hook converts "block" into "allow". Guard mode is opt-in, labelled advisory, answers "ask" on deadline, and is never described as prevention.

### Managed hooks behave as documented everywhere (A1, A24) — broken in specifics
- Claude Code ignores a file-dropped managed hook when a higher-precedence managed source exists (MDM plist, HKLM value or server-managed policy; the default is first-wins).
- One hook command string cannot be valid in Git Bash, PowerShell, cmd and sh; Codex launches hooks through the user's login shell.
- POSIX permission bits do nothing on Windows; WSL2 agents are invisible to a Windows binary; a Go binary has no stable code identity on macOS without a signing identity.

Changes: the installer uses exec-form hooks where the agent supports them and per-shell strings elsewhere; `hooks status` reports `shadowed` and insecure permissions; coverage is driven by a per-session "hook loaded" signal rather than file presence; platform claims are limited to what was tested.

### Kubernetes: "hostPID DaemonSet sees agents in containers" (A25) — broken as stated
`hostPID` alone cannot read non-root agents' files or environment (it needs `SYS_PTRACE` and `DAC_READ_SEARCH`); reading through `/proc/<pid>/root` followed tenant-planted symlinks to host files; microVM sandboxes are opaque. Changes: a read-only node sensor with exactly those two capabilities for runc-class runtimes, opens confined with `openat2(RESOLVE_IN_ROOT)`, events on stdout, plus in-image hook mode; an explicit unsupported list.

### "No server of our own" (A30, A33) — weakened
Fleet answered `422 Scripts are disabled for this host` on the stock-osquery host: there is no Fleet channel that can deliver a rule pack or a suppression there, policies run hourly and webhooks daily. Changes: rules, lists, suppressions and catalog overlays are pulled as an ed25519-signed bundle from an operator-supplied static URL, with no downgrade and the installed version visible in every finding and in the health table; `detect` re-evaluates shipped events centrally; a session summary stream supports fleet-wide questions.

### The thesis itself — broken as first written
The first draft claimed that no open-source tool gives a real-time, vendor-neutral signal. Research found that perplexityai/numbat (hooks for 28 agents, on-endpoint rules, opt-in enforcement) and Agent Beacon (29 runtimes, signed packages) already exist, and that Fleet's own agent ships inventory tables. What survived a deliberate search for an equivalent: nobody proves the telemetry is complete, corroborates it with the OS, exposes findings and coverage as osquery tables, documents a tested Fluent Bit contract, or covers Kubernetes. The project is positioned as that assurance and integration layer, and it accepts numbat output as an input.

## What held

| Assumption | Why it held |
|---|---|
| Deterministic rules are a valid first tier (A8) | uber/ADR's own strongest production number is a regex-and-entropy pre-prompt hook (97.2% precision); a Fluent Bit Lua rule set missed 3 of 5 trivial variants that parsed-fact rules catch |
| Concurrent single-write appends (A14, part) | 0 torn lines in 29,568 |
| A CGO-free Go binary can also be an osquery extension (A17, part) | verified through a Fleet live query |
| Never execute discovered binaries or start MCP servers (A32) | every alternative executes user-controlled code as the sensor |
| Reuse of uber/ADR catalog data under Apache-2.0 (A34) | with attribution, and nothing from its vendored benchmark material |
| The assurance layer is unoccupied (A37) | no heartbeat, host identity, osquery or Fluent Bit content in the nearest open-source sensors' documentation |
| User namespaces and rootless containers do not hide processes from a node sensor | tested |

## Measurements quoted elsewhere in this repository

| Measurement | Value | Conditions |
|---|---|---|
| Hook process: start, parse, append, exit | p50 1.2 ms slim, 2.9 ms with SQLite and YAML linked, vs 0.9 ms for `/bin/true` | Linux sandbox, direct exec, empty rule set, 300 runs |
| Same through the launch paths agents really use | `sh -c` 2.5 ms, `bash -lc` 8.5 ms p50 | same sandbox; Windows not measured |
| Process polling capture rate | 1% of `/bin/true`, 7% of 100 ms processes at 1 s; 7 of 120 in a second test | `/proc` scanner, Linux |
| ATC query cost | 26 ms / 12 MB at 10k rows; 270 ms / 107 MB at 100k | osquery 5.19, WAL SQLite |
| Fluent Bit recovery | 0 of 5,000 (memory) vs 5,000 of 5,000 (filesystem) | Fluent Bit 5.2.0, output down across restart |
| Benign trigger rate of the co-occurrence trifecta | 1 of 37 sessions (Wilson 95% 0.5% to 13.8%) | real agent sessions from this project's own build, no attacker |

## Not verified

- Anything on Windows or macOS hardware (hook latency with Defender, ACLs, service behaviour, TCC and Full Disk Access, WSL, code signing).
- Whether Claude Code managed hooks load under `--bare`; whether Codex hooks fire identically under `codex exec`; all Cursor hook payload details (the vendor documentation was unreachable from the build environment).
- Commercial vendors' capabilities are taken from public material and treated as claims.
- The real-session replay corpus is one workload (agentic research and infrastructure work as root in a sandbox); intervals are wide.
