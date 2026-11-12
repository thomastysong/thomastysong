> **Historical design record.** Red-team review of design v0, pipeline-operator lens (A14, A15, A21, A22, A23): Fluent Bit 5.2.0 restarts with the output down, segment pruning, oversized lines, Forward acknowledgements, SQLite under hook-rate writes.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:19 UTC on the build machine; it says "Date 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (2 places).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: pipeline-operator lens (A14, A15, A21, A22, A23)

Date 2026-11-11. Persona: logging/SIEM platform engineer who runs Fluent Bit on every endpoint and cluster and pays the SIEM bill.
Target: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/design/v0.md`.
Work dir with every config, script and output: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/rtp/` (below: `$R`).
All runs: `docker run --network host -v <dir>:/work fluent/fluent-bit:latest -c /work/fb.yaml` (Fluent Bit v5.2.0), Linux, ext4, root. Nothing in the shared Fleet/osquery stack was touched. All `rtp-*` containers and sinks were removed afterwards.

Common parser in every run (the one the research report proposes to ship):
```yaml
parsers:
  - name: spoor_ndjson
    format: json
    time_key: ts
    time_format: '%Y-%m-%dT%H:%M:%S.%L%z'
    time_keep: on
```

## Summary of verdicts

| # | Assumption | Verdict | Severity | One line |
|---|---|---|---|---|
| F1 | A14 | broken | critical | `tail` + `db` is at-most-once with Fluent Bit's default memory buffering: 0 of 5000 events survived a graceful restart with the output down |
| F2 | A14 | broken | high | prune-by-deletion loses unread data silently (3,552 of 40,000 delivered) and inode reuse skips the head of the next segment (2,000 of 3,000) |
| F3 | A14 | broken | high | one 200 KB event stops the whole segment with default tail settings; with `skip_long_lines` that event vanishes; on container stdout it becomes 13 fragments |
| F4 | A21 + sec. 9 | broken | high | a per-host `seq` cannot detect gaps once streams are routed to different destinations; daemonless mode has no allocator and no heartbeat |
| F5 | A21 | weakened | high | central cost is not flat: detection volume scales with activity, escalation is a session property but routing is per event, inventory/heartbeat dominate if not differential |
| F6 | A15 | broken | medium | Forward acks are not durable (500 acked, 0 delivered) and tail to `opentelemetry` output already gives OTLP with zero sensor code |
| F7 | A14 | weakened | medium | restrictive spool files are read by root Fluent Bit only; cap-dropped root and non-root read 0 of 50 with no log line at all |
| F8 | A14 | weakened | medium | one 503 after commit duplicated a whole chunk (200 unique ids stored 400 times); random UUIDv7 ids cannot dedupe replays or hook+transcript doubles |
| F9 | A23 | weakened | medium | a per-hook SQLite transaction doubles hook latency and hits 67% SQLITE_BUSY without `busy_timeout`; a single daemon writer is fine |
| F10 | A22 | weakened | medium | nothing in the design bounds volume: no rate limit, no size cap, two surfaces report every action, transcript backfill is unspecified |
| F11 | A14/A21 | weakened | medium | Go's default time encoding fails the shipped parser when nsec is 0 (silent ingestion-time fallback); no schema-evolution contract |
| F12 | A14 | holds (with a restriction) | low | concurrent O_APPEND single-write appenders: 0 torn lines in 29,568 lines up to 1 MB; one torn line on a full disk |

---

## F1. `tail` + `db` is not at-least-once (A14)

Mechanism: in_tail commits the file offset to its SQLite DB when it READS a line, not when an output delivers it. With the default `storage.type: memory` the chunk exists only in RAM. A restart of Fluent Bit while the destination is unreachable (laptop off VPN, SIEM outage, package upgrade that restarts the service) loses everything read but not delivered, and the offset says it was shipped. Separately, the default `retry_limit` is 1.

Run (`$R/ea/{mem,fs,def}`): tail with `db`, `read_from_head: true`; http output to a closed port. 5000 events (2,563,890 bytes) in `activity-000001.ndjson`.

```
== mem: db state   [('/work/spool/activity-000001.ndjson', 2563890, 1025201)] filesize 2563890     <- offset at EOF, nothing delivered
== fs:  db state   [('/work/spool/activity-000001.ndjson', 2563890, 1025217)] filesize 2563890
== def: db state   [('/work/spool/activity-000001.ndjson', 2563890, 1025249)] filesize 2563890
```
Then: `mem` (memory buffering, `retry_limit: no_limits`) got `docker stop` (SIGTERM, graceful); `fs` (`storage.type: filesystem`, `retry_limit: no_limits`) got `docker kill -s KILL`; `def` (memory, default retry) was left running. Sinks were started, containers restarted, 12 s wait:
```
== mem received lines: 0 of 5000
== fs received lines: 5000 of 5000
== def received lines: 0 of 5000
[2026/11/11 17:07:05.996] [error] [engine] chunk '1-1794416818.300847912.flb' cannot be retried: task_id=0, input=tail.0 > output=http.0
[2026/11/11 17:07:09.991] [error] [engine] chunk '1-1794416818.318816719.flb' cannot be retried: task_id=1, input=tail.0 > output=http.0
```
The default-retry variant dropped both chunks 7 and 11 seconds after the first failure.

The research report's "run-verified at-least-once" test (`research/fluentbit.md` line 39) killed Fluent Bit with nothing in flight, so it never exercised this path.

Minimal change: the transport contract is "tail + `storage.type: filesystem` on the input + `retry_limit: no_limits` + an explicit `storage.total_limit_size` per output". Ship only that config; add `spoor doctor fluent-bit` that parses the active config (or `/api/v1/storage`) and emits a `health` event `shipper.unsafe_config` when the tail input is memory-buffered or retry is bounded; make "kill Fluent Bit with the output down, restart, count" a CI test against the real image. Word the claim as "at-least-once only with filesystem buffering".

## F2. Never-renamed segments pruned by deletion (A14)

### F2a. Sensor prunes while Fluent Bit lags (`$R/e3/c`)
tail with `mem_buf_limit: 1M`, http output down with `retry_limit: no_limits`; 40,000 events (11.8 MB) in segment 1.
```
db while paused: [('/work/spool/activity-000001.ndjson', 1046730)] filesize 11828890
[ warn] [input] tail.0 paused (mem buf overlimit - event of size 31968B exceeded limit 1000000 to 1022592B)
sensor pruned segment 1 (retention cap) while FB lagging        # rm of the segment, then 100 events to segment 2
... sink started, 45 s ...
E3b delivered: seg1 3552 of 40000 ; seg2 100 of 100
```
91% of the segment was lost. Fluent Bit logged nothing about unread data in a deleted file. The sensor cannot know either: the design has no feedback from the shipper.

### F2b. Inode reuse (`$R/e3/b_default`, `$R/e3/b_cmpname`)
Fluent Bit read segment 1 (1000 events, offset 293,890) and was stopped. Segment 1 was deleted and segment 2 created on the same inode (on ext4 that took only 43 to 54 filler creations in that directory), 3000 events written, Fluent Bit restarted:
```
== b_default phase1 delivered: 1000
   seg1 inode=1025667 size=293890 ; seg2 inode=1025667 size=883890
== b_default after restart: seg2 delivered 2000 of 3000; first seq delivered=1000; garbage records=0
== b_cmpname after restart: seg2 delivered 3000 of 3000; first seq delivered=0
[ info] [input:tail:tail.0] db: stale file deleted from database: id=1          # only with db.compare_filename: true
```
With default settings the first 293,890 bytes of the new segment were skipped silently. Without inode reuse (`$R/e3/a_*`) Fluent Bit's startup cleanup (`db: delete unmonitored stale inodes from the database: count=1`) handled it, so this needs Fluent Bit to be down across a prune + roll, which at 10,000 hosts happens somewhere every day. `db.compare_filename: true` is absent from the reference config in `research/fluentbit.md` section 5.

SIEM down for a day on a laptop with 1 GB free: volume is not the problem (F5: 0.2 to 8 MB per developer per day). The problem is that two components each drop silently: the sensor's retention prune (F2a) and Fluent Bit's `storage.total_limit_size` ("oldest chunk is discarded", `research/fluentbit.md` line 234).

Minimal change: ship `db.compare_filename: true` and `db.locking: false`; before pruning, the sensor reads Fluent Bit's tail DB read-only (I read it from outside while Fluent Bit was running in every run above; the report's reference config sets `db.locking: true`, which blocks that) and prunes only fully shipped segments until a hard cap; when the hard cap forces dropping unread data, write `health` event `spool.dropped{stream, seq_first, seq_last, events, bytes}` and count it in the heartbeat; separate caps per stream with `detection` pruned last.

## F3. Oversized event lines (A14)

`$R/e5/default` (no buffer options) and `$R/e5/skip` (`skip_long_lines: on`, default 32k buffers). Segment: seq 0..2 small, seq 3 = 200 KB command (marked `kind: detection`), seq 4..8 small, then seq 9..11 appended 5 s later.
```
== E5 default: file has 12 lines; delivered seqs: [0, 1, 2]
[error] [input:tail:tail.0] file=/work/spool/activity-000001.ndjson requires a larger buffer size, lines are too long. Skipping file.   (repeats every second)
== E5 skip: file has 12 lines; delivered seqs: [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11]
[ warn] [input:tail:tail.0] file=/work/spool/activity-000001.ndjson have long lines. Skipping long lines.
== E5 default after new segment: [0, 1, 2, 100, 101]
```
Default: everything after the long line in that segment is never shipped (8 events here, in production the rest of the hour). With `skip_long_lines`: exactly the oversized event disappears. The line length is attacker-controlled (a heredoc command, an MCP argument, a long URL), so this is a one-command way to blind the pipeline or to delete the one event that matters. The design states no size cap. Real data from 953 Bash tool calls in Claude Code transcripts on this machine: command p50 371 B, p99 3,854 B, max 7,936 B, so a 16 KB cap costs nothing in normal use; largest tool input of any kind was 44,149 B.

Kubernetes stdout path ("in-container mode: hook + stdout sink"): one 200 KB line through the container runtime's json-file log:
```
runtime log entries for ONE 200 KB event line: 13 sizes [16384 x12, 3421] ... entries ending in newline: 1
```
(containerd/CRI splits at the same 16 KB default with partial flags.)

Minimal change: hard cap per event in the sensor (default 16 KB, so an event is one runtime log entry; configurable up to 64 KB), truncate oversized fields to head + tail and add `sha256`, original length and `truncated: true`; shipped tail config uses `buffer_max_size` of at least 4x the cap and `skip_long_lines: on`; heartbeat counts truncations; CI case with a 5 MB command.

## F4. Gap detection versus stream routing (A21, section 9)

Design line 91: "Per-host monotonic `seq` and periodic `health` heartbeat with counters, so downstream can detect gaps." Design line 63: "detections to SIEM, activity to object storage". If `seq` is one counter per host, the SIEM sees detections with seq 17, 4032, 9911 and cannot tell whether a detection was dropped; the object store has holes wherever a detection was emitted. F2a shows drops that are invisible to both the sensor and Fluent Bit, so `seq` is the only way to notice them and it does not work per destination.
Daemonless mode (a headline deployment mode, design line 79): concurrent short-lived hook processes writing per-user spool files have no shared allocator, and there is no process to emit a heartbeat, so an idle host and a dead pipeline look the same (the same weakness the research found in ADR, `research/adr-sensor.md` line 95).

Minimal change: scope `seq` to (host.id, writer epoch, stream) and put the writer id in the envelope; route `health` to every destination (it is tiny) and make each heartbeat carry per-stream `{first_seq, last_seq, emitted, dropped, truncated}` for the interval so each destination can verify its own stream; in daemonless mode allocate seq from a per-user counter file under the same lock as the append and emit the heartbeat from a timer-run `spoor heartbeat` one-shot; document that gap detection needs that timer.

## F5. Cost math for 10,000 developers (A21)

Measured inputs:
- Event size, design section 4 envelope, compact JSON, `metadata` tier (script in notes work dir): tool.pre shell 990 B, tool.post shell 1069 B, file_edit 860 B, mcp 933 B, prompt.submit 842 B; mean 939 B. The per-session constant part (host + user + agent + session + repo) is 543 B = 58% of the mean event.
- Tool calls per session: 23 real Claude Code sessions on this machine (agent-heavy workflow sessions, not a representative sample): median 73 `tool_use`, busiest 80 to 110 within 8 to 36 minutes.
- Sessions per endpoint per day from Uber (`research/adr-paper.md` lines 33-34): paper 10,000+/day over 7,200 hosts = 1.4; slides 200,000+/day over 30k endpoints = 6.7.
- Events per tool call in the design: hook tool.pre + tool.post = 2, plus about 0.3 for prompt/turn/permission/session events = 2.3. If the transcript surface also emits the same actions (the design lists `source: hook|transcript` and never says they are merged): 4.3.

| Scenario | events/dev/day | MB/dev/day | events/day fleet | GB/day fleet |
|---|---|---|---|---|
| Low: 1.4 sessions, hooks only | 235 | 0.22 | 2.35 M | 2.2 |
| Mid: 6.7 sessions, both surfaces | 2,100 | 1.97 | 21.0 M | 19.7 |
| Heavy: 20 sessions x 100 calls, both surfaces | 8,600 | 8.1 | 86 M | 80.7 |

Other streams (my assumptions, stated): inventory as a full snapshot every hour at 150 records x 600 B per host = 21.6 GB/day fleet, more than the Mid activity stream and almost all unchanged; heartbeat every 60 s at 400 B = 5.8 GB/day, every 5 min = 1.15 GB/day.

Why "flat" does not hold as written:
1. Detection volume is a rate times activity. At Mid there are 4.9 M tool calls/day; a 0.5% rule hit rate is about 24,000 detections/day. Uber reports 49% false positives in production and that alert volume "quickly exceeded the capacity for manual review" (`research/adr-paper.md` lines 93, 115).
2. Coverage-correlator detections are per event. If an agent update breaks hooks fleet-wide, "transcript shows tool calls hooks never reported" fires once per tool call: 4.9 M detections/day into the SIEM on the worst possible day.
3. A detection without its session context cannot be triaged, and the context is in object storage that the S3 output fills with a delay (`upload_timeout: 5m` in the reference config). `escalate: true` is decided at the session level after the fact; the earlier events of that session were already shipped untagged to cold storage, and in the default `metadata` tier they contain no content for the "downstream LLM judge" at all.
4. Inventory and heartbeat volume are unspecified.

Minimal change: (a) aggregate detections at the edge: dedupe key (rule, session, target class), first hit plus count per window, a per-host budget with an overflow summary event; coverage findings are per session, and a fleet-wide hook break is a `health` condition; (b) flight recorder: keep the last N (200) events per session in the state store and, on the first detection at or above medium or on escalation, emit that bundle into the detection stream so the SIEM case is self-contained; (c) inventory is differential (added/removed/changed) with one full snapshot per day; heartbeat default 5 minutes; (d) publish this sizing table and ship `spoor estimate` that computes it from the local spool.

## F6. Forward client and OTLP exporter in v1 (A15)

Forward ack durability (`$R/ef`): forward input (memory buffered, the default), http output down, client sends 5 Forward-mode batches of 100 events with the `chunk` option:
```
forward client: sent 500 events in 5 batches with chunk option; ACKED by Fluent Bit: 500
FB stopped gracefully (SIGTERM) while output unreachable
delivered downstream after restart: 0 of 500 acked
```
The ack means "in Fluent Bit's RAM" (`research/fluentbit.md` line 54 says the same from source). With tail the bytes are at least still in the segment; with Forward the client has already discarded them. To be at-least-once the Forward client needs its own durable queue, which is the segment spool again plus a second checkpoint and a retry/handshake state machine. It also cannot run inside a short-lived hook process (connect + HELO/PING/PONG + ack per event), and on Windows it is loopback TCP with a `shared_key` that the user-level hook process must be able to read.

OTLP (`$R/eo2`): tail + the built-in `opentelemetry` output, no sensor code:
```
POST /v1/logs ct=application/x-protobuf len=27684 has_type=True has_session=True
```
Fluent Bit already turns the NDJSON into OTLP/HTTP. Sites without Fluent Bit can point the OpenTelemetry Collector `filelog` receiver at the same segments (not run here).

Minimal change: v1 ships tail only, plus tested configs for Fluent Bit `opentelemetry` output and an OTel Collector `filelog` receiver, behind an internal `Sink` interface. Forward and a native OTLP exporter move to "later, if a measured need appears", and if built they are second readers of the segment files with their own checkpoint, never a parallel in-memory path.

## F7. Spool file permissions (A14, daemonless mode and "root-owned event files")

`$R/e2/{root,rootnocap,nonroot}`: `home/alice/.local/state/spoor/activity-000001.ndjson`, owner uid 1001, directory 0700, file 0600, 50 events; tail path `/work/home/*/.local/state/spoor/*.ndjson`.
```
== E2 root:      delivered 50 of 50        (docker default capabilities)
== E2 rootnocap: delivered 0 of 50         (--cap-drop ALL, uid 0)     no warning or error in the log
== E2 nonroot:   delivered 0 of 50         (--user 2000:2000)          no warning or error in the log
```
A hardened Fluent Bit (non-root package user, or a DaemonSet with `capabilities.drop: [ALL]` / `runAsNonRoot`) ships nothing and says nothing. The same applies to "root-owned event files in daemon mode" if they are 0600.

Minimal change: spool lives in one system directory, not in home directories: `root:spoor-read` 0750, files 0640, per-user subdirectories for daemonless mode created by the installer; documented `supplementalGroups` (or `CAP_DAC_READ_SEARCH`) for DaemonSets; `spoor doctor --as-user <fluent-bit user>` readability check; a `shipper_lag` health value derived from the tail DB so "Fluent Bit reads nothing" is visible.

## F8. Duplicates and dedupe (A14)

`$R/eo2`: an HTTP sink that stores the batch and answers 503 once (a load balancer timeout after commit):
```
== flaky HTTP sink (stores then answers 503 once): stored records 400 unique ids 200 ids stored twice 200
[ warn] [engine] failed to flush chunk '1-1794417352.372801226.flb', retry in 10 seconds
[ info] [engine] flush chunk '1-1794417352.372801226.flb' succeeded at retry 1
```
Retry granularity is the chunk (up to about 2 MB), so one hiccup duplicates thousands of events. Replays keep the same `id`, so id-based dedupe works where the destination supports it: Elasticsearch/OpenSearch `id_key` (docs `pipeline/outputs/elasticsearch.md:33`, `opensearch.md:34`), Kafka `message_key_field` (`kafka.md:26`). Splunk HEC, S3 and Chronicle have no ingest-time dedupe in the docs clone, so the SIEM bill counts duplicates.
Two duplicate classes survive id dedupe because `id` is a random UUIDv7 per emit: (1) the transcript tailer re-reading after a crash with a lagging checkpoint emits the same action with a new id; (2) the hook and transcript surfaces both report the same tool call.

Minimal change: deterministic ids. `id` = UUIDv8(ts_ms prefix + truncated SHA-256 of host.id, session.id, tool.use_id or transcript byte offset, type, source); add `dedupe_key` = the same hash without `source` so hook and transcript versions of one action collapse; shipped configs set `id_key: id` (ES/OpenSearch) and `message_key_field: id` (Kafka) and the docs give the search-time dedupe for Splunk/Sentinel/Chronicle.

## F9. SQLite state store under hook-rate writes (A23)

`$R/sq/main.go` (modernc.org/sqlite v1.62.0, CGO off, WAL, synchronous NORMAL), `$R/sq/drive.py`. "hook" = one process per event: open, one transaction (upsert `spoor_sessions`, insert `spoor_detections`), commit, close.
```
spawn only (same binary, no DB work):                       p50=1.8ms p99=2.5ms
busy_timeout=5000ms concurrency=1  n=300 : p50=4.0ms  p95=6.1ms  p99=10.2ms  max=15.4ms  errors=0
busy_timeout=5000ms concurrency=8  n=800 : p50=7.7ms  p95=17.6ms p99=31.3ms  max=73.0ms  errors=0
busy_timeout=5000ms concurrency=32 n=1600: p50=33.8ms p95=73.6ms p99=111.7ms max=210.0ms errors=0
busy_timeout=0ms    concurrency=8  n=800 : errors=535 (database is locked (5) (SQLITE_BUSY))
ext4, busy_timeout=5000ms concurrency=8  : p50=8.6ms  p95=17.8ms p99=29.3ms
single long-lived writer: 5000 commits in 132 ms (26 us/event); 20000 events in batches of 100: 7 us/event; WAL high-water mark 4.1 MB
```
So: a daemon as the single writer holds. A hook that writes SQLite more than doubles the design's measured hook cost (2.9 ms p50 was measured with an append only) and loses 67% of writes without `busy_timeout`. That means in the "daemonless hooks" mode the Tier 1 tables `spoor_sessions` and `spoor_detections` and the Fleet policy "no critical detections in 24h" have no writer. Also, "retention caps" on a detections table are an eviction primitive: an agent that triggers many low-severity hits can push the critical row out before Fleet's hourly policy query reads it.

Minimal change: hooks never open SQLite. In daemonless mode a timer-run `spoor sync` (single writer) folds the spool into the state DB, and the docs say those tables lag by the timer interval. `busy_timeout` is mandatory on every connection. Detections are stored as aggregated rows (rule, session, count, first, last) with per-severity quotas.

## F10. Volume is not bounded by anything in the design (A22)

- No per-session or per-host rate limit: an agent loop or subagent fan-out sets the event rate. Busiest local sessions ran about 10 tool calls per minute each; a CI node with 50 concurrent agent jobs at that rate and 4.3 events per call is about 2.9 GB/day on one node.
- No event size cap (F3).
- Two surfaces report every action (F5).
- Transcript backfill is unspecified. ADR's sensor uses a 14-day lookback (`research/adr-sensor.md` line 18). The 23 local sessions are 1.5 to 2.5 MB of transcript each. A first run that reads existing transcripts from the head sends weeks of history from every host on rollout day with old timestamps.
- Write-path CPU is fine: 26 us per event for the state store (F9), and 160.8 MB of NDJSON was appended by 6 processes in 0.24 s (F12).

Minimal change: token bucket per session on `activity` only (for example 20 events/s, burst 200) with an `activity.suppressed{count, first_ts, last_ts}` summary; one emitted activity event per action (hook is primary, the transcript version is emitted only when no hook event matched); transcript tailers start at end of file for files that predate install, backfill is an explicit `spoor scan --backfill <days>` into its own stream; publish events/day and bytes/day per stream as health counters.

## F11. Timestamp encoding and schema evolution (A14, A21)

`$R/e4/gen/main.go` (Go 1.24.7) through the shipped parser; wall clock was 17:12:15Z:
```
A json.Marshal(time.Time) nsec=0   ts="2026-11-11T10:00:03Z"            -> FB time 17:12:15.430540Z  (parse failed, ingestion time)
B RFC3339Nano nsec=0               ts="2026-11-11T10:00:03Z"            -> FB time 17:12:15.430552Z  (failed)
C RFC3339Nano nsec=5e8             ts="2026-11-11T10:00:04.5Z"          -> 10:00:04.500000Z ok
D RFC3339                          ts="2026-11-11T10:00:04Z"            -> failed
E "2006-01-02T15:04:05.000000000Z07:00" nsec=0                          -> 10:00:03.000000Z ok
G same layout, local zone +05:30   ts="2026-11-11T15:30:05.123000000+05:30" -> 10:00:05.123000Z ok
H ".000Z" three digits                                                  -> ok
I unix millis as a JSON number                                          -> failed (ingestion time)
J three events with identical ts                                        -> all three kept, file order, no dedupe
[ warn] [parser:spoor_ndjson] invalid time format %Y-%m-%dT%H:%M:%S.%L%z for '2026-11-11T10:00:03Z'
```
The exact Go layout is `t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")` (zeros, not nines). `time.RFC3339Nano` and the default `encoding/json` encoding of `time.Time` both drop the fraction when nsec is 0. That is not a one-in-a-billion case: 5 of 4,059 timestamps in the local Claude Code transcripts end in `.000Z`, and second-resolution sources always do. The failure is silent downstream (event gets ingestion time, hours or days off for transcript-derived events). Output time precision was microseconds in `iso8601` output, so ordering among same-timestamp events needs `seq`.

Schema evolution: rollouts are staggered, so mixed sensor versions and a Fluent Bit config owned by another team coexist for weeks. The design has only `v`. Concrete breakages: a field whose JSON type differs between versions or OSes (`user.id` "501" versus a Windows SID) is a mapping conflict in Elasticsearch/OpenSearch and the bulk item is rejected; free-form `inventory{}`/`detection{}` objects grow the field count without bound; a new stream name in a newer sensor matches the tail glob but no output `match`, and Fluent Bit drops unmatched tags without a word.

Minimal change: a custom `MarshalJSON` for the timestamp type plus a unit test with nsec = 0 and a CI case through the real parser; a published JSON Schema with rules "additive only within v1, ids and enums are strings, bounded key sets"; a golden-event corpus per released version replayed through the shipped configs in CI; shipped configs end with a catch-all `match: 'spoor.*'` output to cold storage.

## F12. Concurrent appenders (A14): attack failed on a local filesystem

`$R/e1w.py`: 6 processes, O_APPEND, exactly one `write()` per line, line sizes 300 B / 5 KB / 70 KB / 200 KB / 1 MB shuffled, Fluent Bit tailing during the writes (`buffer_max_size: 4M`).
```
writers 6 lines 29568 short_writes 0                      (160,800,000 bytes in 0.24 s)
RAW FILE: lines 29568 unparseable 0 length-mismatch 0 unique(w,i) 29568
FLUENT BIT OUT: records 29568 garbage/unparsed 0 unique(w,i) 29568 missing 0 by size {300: 24000, 5000: 4800, 70000: 480, 200000: 240, 1000000: 48}
```
No torn or merged record at any size.

Full disk (`$R/e1b.py`, 3 MB tmpfs, three writers of 20 KB events and three of 300 B events):
```
short_writes 1 ENOSPC errors 2242
  torn/merged line: len 5728 head b'{"w": 1, "i": 50, "n": 20000, "pad": "xx' ...
lines 158 unparseable (torn or merged) 1
```
One partial write left a 5,728-byte fragment without a newline; the next successful append from any process is glued to it. Not tested: NFS/SMB home directories (open(2) documents that O_APPEND can corrupt files on NFS with multiple appenders), macOS, Windows.

Minimal change: keep the single-write rule as a tested invariant (no `bufio.Writer` on the spool); check free space before writing and stop below a reserve, counting the drop; state "local filesystems only" for the spool; parser-miss records (`{"log": ...}`) are routed to the health stream so a torn line is visible.

## Not run / limits
- Everything ran on Linux ext4 in one VM. macOS (stat polling, APFS) and Windows (NTFS, services) behaviour of tail is taken from the research report, not re-run.
- No Elasticsearch/Splunk instance was available, so mapping conflicts and SIEM-side dedupe are argued from the Fluent Bit docs clone, not observed.
- The cost table rests on 23 local sessions and Uber's published session counts; the hit rate of 0.5% and the inventory/heartbeat sizes are my assumptions and are labelled as such.
- The Windows glob for per-user spool paths (`tail_scan_win32.c` at v5.2.0 was fetched) was read only far enough to see it handles `*`; multi-level wildcard behaviour was not confirmed.
