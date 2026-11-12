> **Historical design record.** The design lead's ledger after the red-team review: for each v0 assumption A1 to A37, the verdict, the evidence in one line and the decision. It is the source of the decision table in `docs/DESIGN.md` and of `docs/ASSUMPTIONS.md`; the evidence column summarises the red-team notes in `redteam/`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:25 UTC on the build machine; it has no date of its own and summarises the red-team notes of 2026-11-11).
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# spoor design decisions after red team (lead's ledger; source for docs/DESIGN.md and docs/ASSUMPTIONS.md)

Legend: verdict of the red team on each v0 assumption, the evidence in one line, and the decision. Full notes: `$S/redteam/*.md`. Structured results: workflow outputs.

## Thesis (restated)
spoor is the assurance and integration layer for AI-agent telemetry on Fleet + Fluent Bit: it proves coverage, corroborates what agents report with what the OS saw, detects on the endpoint, and delivers to the control planes teams already run. It works from its own hooks/transcript tailers and from other sensors' output. It is NOT a tamper-proof control against an adversary who controls the endpoint; detection of careless/unmodified abuse, worms and infostealers yes, targeted evader on their own machine no.
What nobody else ships (verified by research + skeptical-buyer SB-11): findings + sensor health + per-agent hook coverage as osquery tables with Fleet GitOps content; a tested Fluent Bit contract; OS-side corroboration; a Kubernetes story; an open benchmark with benign look-alikes.

## Ledger

| A# | Verdict | Evidence (who, what) | Decision |
|---|---|---|---|
| A1 managed hooks, one binary | weakened; PP-1 broken | Claude file-drop hooks silently ignored when plist/HKLM/server-managed policy exists (first-wins); Cursor unverified; Gemini system path env-overridable | `hooks status` detects higher-precedence managed sources and reports `shadowed`; per-session positive "hook loaded" signal (SessionStart hook event); effective coverage, not file presence, drives health |
| A2 hook overhead | weakened | 2.9 ms is direct exec on Linux; agents wrap in sh / `$SHELL -lc` (8.5 ms floor) / PowerShell; Windows unmeasured | exec form where the agent supports it (Claude `args`); publish measured numbers per launch path; Windows listed as unverified |
| A3 hooks in headless/CI | weakened | `--bare` skips hooks and is documented to become default for `-p`; Codex exec parity unverified | headless/bypass argv detected by process surface; missing hook signal for a session seen elsewhere = coverage finding; CI is its own mode (`spoor ci exec`, experimental) |
| A4 transcripts tail-able | holds with restriction | formats are internal and change; ADR/Fleet parsers exist | unknown-record counters -> `schema_drift` health; start at EOF for pre-existing files; backfill explicit |
| A5 polling monitor | weakened | 7 of 120 short processes at 1 s; cn_proc works unprivileged on kernel >= 6.6; osquery audit process_events caught 5/5 | poller = agent roots and long-lived children only; exec ground truth from cn_proc (Linux) and osquery results log; stated as optional tier |
| A6 cross-surface disagreement | broken as stated | all three v0 surfaces are user-writable; can be driven to zero or forged | disagreement is signal only when one side is root-observed (process/exec/OTel receiver); transcript-only or spool-only bypass findings are severity-capped, rate-limited, never cross-user |
| A7 attribution | broken (socket) | SO_PEERCRED Linux-only; parent check fails behind shells; session id self-reported | no socket; identity = owner uid of the spool file / transcript file, never payload fields; state keyed by (uid, agent, session) |
| A8 deterministic rules | holds as tier 0/1 | ADR's best production number is a regex+entropy hook (97.2% precision); Lua pipeline rules missed 3 of 5 evasions | keep; position honestly; `escalate` tag for an optional downstream judge |
| A9 shell canonicalizer | broken vs motivated evader | eval of assembled strings, interpreter one-liners, heredocs from char codes, write-then-run all hide content | `shell.opaque` feature (eval, inline code, heredoc to interpreter, dynamic command, decoded exec) scores/escalates instead of pretending to see inside; write-then-run correlated across events; documented "not covered" list |
| A10 trifecta FP | pending detection-quality lens | | severity tiers, dedup, suppression windows, first-seen, allowlists; trifecta ships experimental unless bench FP is low |
| A11 public rules on attacker endpoint | weakened to broken | rules readable; hook-free paths exist | trust boundary stated: endpoint rules are best-effort; authoritative copy can be re-evaluated centrally with `spoor detect` over shipped events |
| A12 guard mode | unsafe as a control | timeouts fail open (Copilot always); stalling converts block to allow | guard is opt-in, labelled advisory, deadline answers `ask` never `allow`; never marketed as prevention |
| A13 inline tests + bench | holds with conditions | ADR-Bench labels leak the server name (oracle 39/43 TP); n=1 for 7 of 17 techniques | own corpus from 48 incident classes, benign look-alikes, per-rule scores, held-out split, CI gate; ADR-Bench not claimed |
| A14 NDJSON + tail | broken as stated | 0 of 5000 survived restart with memory buffering; prune-by-delete lost 91% while Fluent Bit lagged; inode reuse skipped 1000 of 3000; 200 KB line stalled a segment | contract = tail + `storage.type filesystem` + `retry_limit no_limits` + `db.compare_filename true` + `skip_long_lines on`; 16 KiB line cap; prune only shipped segments by reading Fluent Bit's tail DB; `spool.dropped` health event; `spoor doctor` checks the shipper; CI kills Fluent Bit with output down |
| A15 Forward + OTLP in v1 | weakened | forward ack = accepted into memory buffer, 500 acked 0 delivered; tail -> opentelemetry output needs no sensor code | tail is the default and recommended path; Forward/OTLP are optional shippers that READ the segments with their own checkpoint, labelled experimental |
| A16 ATC | weakened | WAL: 0 torn of 75; rollback journal: torn reads; missing DB reads as 0 rows so "no X" policies fail open; O(table) per query, 300k rows trips the 200 MB watchdog; rename-replace replays old WAL | WAL only, never rename; row caps per table; every "no X" policy also requires a fresh `spoor_health` row; extension recommended at scale; TEXT columns documented |
| A17 daemon in extension | broken | extension exits 3 s after osqueryd dies | extension = tables only |
| A18 Fleet Free deploy | weakened | scripts disabled by default, software deploy/policy automation Premium | docs say exactly what each tier can do; bundle ships script + package variants |
| A19 tables beyond ai_tools | weakened | 5 of 8 duplicate fleetd; none exist on stock osquery | bundle has two profiles: `fleetd` (Fleet tables + spoor_detections/health/coverage/extensions/agent_processes) and `stock`; our inventory tables exist for stock osquery, containers and richer MCP facts |
| A20 host id = osquery uuid | broken | random per osquery DB on DMI-less hosts; root-only on Linux | order: explicit config/env, host_id file written by the extension (asks osquery), DMI/IOPlatformUUID/SMBIOS, machine-id; `host_id_source` reported; exact Fleet join needs the extension |
| A21 edge detection keeps cost flat | weakened | ~4.6M events/day for 10k devs is only 1.6-5 GB/day; detections scale with activity | argument is privacy and latency first, cost second; edge dedup with counts, session summary stream, differential inventory |
| A22 bounded volume | weakened | nothing bounded it | token bucket per session on activity (20/s, burst 200) + `activity.suppressed`; one activity record per action (hook primary, transcript only if unmatched); per-stream counters |
| A23 SQLite state | holds with restriction | per-hook transactions hit 67% BUSY | hooks never open SQLite; single root writer; busy_timeout |
| A24 one Go codebase, parity | weakened; several broken | POSIX perms do nothing on Windows; one hook string cannot serve Git Bash/PowerShell/cmd; WSL2 invisible; macOS TCC/FDA; no signing identity | parity is claimed only where tested; Linux tested here; macOS/Windows compile and unit-test, with a published hardware test matrix; exec-form hooks; per-shell command strings; WSL listed unsupported |
| A25 DaemonSet | broken as stated | hostPID alone is blind to non-root agents (needs SYS_PTRACE + DAC_READ_SEARCH); symlink confused deputy via /proc/<pid>/root; microVM runtimes opaque | v1: read-only node sensor for runc-class runtimes with exact caps, openat2 RESOLVE_IN_ROOT, events to pod stdout; in-image hook mode; `spoor ci exec` experimental; unsupported list published |
| A26 metadata default | broken (critical) | "metadata" tier was identified behavioural monitoring | emit profiles: `minimal` default ships verdicts not behaviour; exclusions; `spoor privacy show|tail|purge`; retention defaults; DPIA notes |
| A27 sensor as attack surface | broken in several places | root reader follows user symlinks; FIFO hangs; per-event cost scales with input; JSON differences | never open payload paths; no-follow + nonblock + owner check on fd; head/tail scan caps + deadline; strict YAML; decode into maps; no os/exec in scan path |
| A28 user-writable spool | broken | forged detections and cross-user activity shipped verbatim by Fluent Bit; root Fluent Bit tails any symlink | daemon accepts only activity claims from a spool, sets identity from file owner, stamps integrity=user, re-detects itself; Fluent Bit tails only the root-owned outbox; daemonless mode is for containers/CI/evaluation and says so |
| A29 redaction | broken | 8 of 17 invented secrets survived pattern+entropy | structural redaction from the shell AST first, patterns second; canary corpus in CI with published leak and over-redaction rates; no unkeyed digests |
| A30 no server | weakened | Fleet is an hourly state plane; scripts disabled on stock osquery; no rule push | signed bundle pulled from an operator static URL; rules_version in every detection and in health; session summary stream for fleet-wide hunting; `spoor detect` for central re-evaluation |
| A31 catalog | weakened | 158 stable releases of 4 agents in 90 days; ADR's month-old catalog already has a 404 npm name | catalog is data in the bundle with `verified_at`/sources; `spoor catalog verify` checks registries; two tiers (majors deep, others identity-only) |
| A32 never execute | holds | alternatives all execute user-controlled code | enforced by import-graph test |
| A33 signed packs | weakened | no file primitive on Fleet Free | bundle pull over HTTPS (ed25519), no downgrade, convergence visible in `spoor_health` |
| A34 ADR reuse | holds with conditions | Apache-2.0; keep notices; nothing from Detection/benchmark/agentdojo | NOTICE credit; skill hash reimplemented and described as compatible |
| A35 Sigma-style vs CEL | pending detection-quality lens | | |
| A36 own hook layer | broken as "5 beats 28" | numbat has the same five with hook+parser+enforce | keep native hooks for the five (the spool/integrity design needs them) AND ship a numbat NDJSON adapter; be explicit that numbat/Beacon cover more agents |
| A37 differentiators | holds for the assurance layer | SB-11: no open equivalent of coverage/health tables, K8s, tested Fluent Bit contract | build those first and best |

## Architecture after red team

- `spoor hook`: stdin -> normalize -> (guard only: evaluate response rules with per-session state file) -> append to per-user spool (single write per line, O_APPEND|O_NOFOLLOW, seq from a per-user counter under lock) -> exit. Observe mode loads no rules. Process identity of the caller chain (pid, start time, exe, ancestors) is captured at hook time.
- Spool location order: `$SPOOR_SPOOL`; system spool `<data>/spool/<uid>/` if it exists, is owned by the caller and is 0700; else the user's own state dir. Never a shared world-writable directory.
- `spoor run` (root daemon, the supported fleet mode): sources = spool ingest (50-200 ms poll, safe opens, identity from file owner), transcript tailers, process monitor (+cn_proc), osquery results log, OTLP receiver (experimental), periodic scan + session-start project scan; pipeline = normalize -> dedupe/correlate (deterministic ids, hook primary) -> features -> rules (stateful) -> privacy -> outbox (root-owned segments) + local ring + state DB; heartbeat every 5 min with per-stream accounting, coverage per agent/user, shipper lag.
- Outbox `<data>/outbox/<stream>-<date>-<n>.ndjson`, dir root:spoor 0750, files 0640: the only path Fluent Bit tails. Local ring `<data>/local/` (activity in minimal profile) is never tailed.
- Extension: tables only, reads state DB read-only, writes host_id file.
- `spoor scan`: one-shot inventory/posture -> state DB (when privileged) and/or stdout; `spoor detect`: engine over NDJSON (native or numbat) for central re-evaluation, CI and benchmarks; `spoor doctor`: checks hooks (effective), shipper config and lag, permissions, host id source.
- Deployment modes: (1) Fleet tables only over fleetd built-ins, no binary; (2) scan timer + ATC; (3) daemon + hooks + Fluent Bit (recommended); (4) Kubernetes node sensor / in-image hooks; (5) CI wrapper (experimental).

## Explicit non-goals / not covered (publish in docs/LIMITATIONS.md)
- Content hidden behind runtime assembly (eval, interpreter one-liners, write-then-run beyond one session), in-memory exfiltration with no child process, an agent run hook-free + transcript-free + renamed + env-scrubbed: need a kernel sensor (osquery evented tables, eBPF, ES, ETW).
- MCP-over-stdio payloads and model traffic (needs a gateway/proxy).
- microVM sandboxes (Docker Sandboxes, Apple container, WSL2, gVisor/Kata/Firecracker) from the host; vendor-hosted cloud agents.
- Windows and macOS behaviour is compiled and unit-tested but not hardware-tested in this release; hardware test matrix published.
- Guard mode is advisory.
- No tool-description scanning (we never start MCP servers).
- Unsigned binaries until a maintainer signing identity exists; reproducible build + checksum instructions provided.
