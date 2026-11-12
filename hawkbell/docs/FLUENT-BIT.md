# Shipping hawkbell records with Fluent Bit

By default hawkbell does not talk to your SIEM. It writes newline-delimited
JSON files into a root-owned outbox and leaves delivery to Fluent Bit, which
already has outputs for almost every destination. (The daemon also has two
experimental shippers that send outbox segments themselves when configured:
`output.forward`, Fluent Forward protocol, and `output.otlp`, OTLP/HTTP
JSON logs; see `internal/config/config.go`. This page does not cover them.)
This page is the contract between hawkbell and Fluent Bit: what hawkbell
writes, the Fluent Bit settings that keep it from losing data, and how to
route each stream.

The fragments were checked against the `fluent/fluent-bit` image reporting
v5.2.0: `hawkbell.yaml` and every output fragment pass
`fluent-bit --dry-run`, and the inputs fragment
was run end to end (restart with the output down, head-of-line blocking,
HTTP 400, 401, 413 and 503 answers, a lost tail database, a tail
database held locked with `db.locking: true`, an oversized record). The commands and results are in
[`deploy/fluent-bit/VERIFIED.md`](../deploy/fluent-bit/VERIFIED.md).
Earlier Fluent Bit versions were not tested, including whether they
expand the `${VAR:-default}` property syntax the fragments use
(VERIFIED.md, "Not verified here").

## What hawkbell writes

```
<data_dir>/outbox/<stream>-<YYYYMMDD>-<HH>-<NNNN>.ndjson
```

The hour is UTC. `NNNN` is a roll counter that starts at `0001`: a writer
moves to the next number when the file reaches `output.max_segment_bytes`
(default 16 MiB). Files are never renamed, truncated or rewritten; pruning
deletes whole files.

`data_dir` is `/var/lib/hawkbell` on Linux, `/Library/Application Support/hawkbell`
on macOS and `C:\ProgramData\hawkbell` on Windows. On Linux and macOS the
daemon makes the outbox directory mode `2750` (set-group-id), owner root,
group `output.group` (default `hawkbell`), and the files `0640`. Fluent Bit
therefore runs as root or as a member of that group. The deb and rpm
packages create the group. The release builds (Makefile,
`.goreleaser.yaml`, Dockerfile) set `CGO_ENABLED=0`; on Linux such a build
looks the group up in `/etc/group` only (Go's resolver without cgo reads
that file): when it is not there (a group that exists only in LDAP, SSSD
or NIS), the daemon logs a warning and the outbox stays readable by root
only. A build with cgo (`go install` or `go build` on a host with a C
compiler, where Go enables cgo by default) resolves the group through the
system's NSS instead, which finds such groups. On macOS Go asks the
system's own `getgrnam_r` with or without cgo, which also answers for Open
Directory groups; that was not run on a Mac
(`internal/daemon/dirs_unix.go`). On Windows the outbox is readable by
SYSTEM and Administrators (compiled, not run on Windows). Only the daemon and
`hawkbell scan --outbox` write there; the per-user hook spools are a
different directory that Fluent Bit must never read (a user can write
anything into their own spool).

| Stream | One record per | Ships in profile |
|---|---|---|
| `detection` | finding or alert; signals are not written unless `rules.min_class: signal`, but their rule ids are counted in the session summary | all |
| `summary` | agent session: counts, surfaces, rule ids that fired; written at session end, after 15 min idle and every 15 min while active | all |
| `health` | heartbeat every 5 min (per-stream accounting, coverage, versions), and errors | all |
| `posture` | failing configuration check | all |
| `inventory` | agent, MCP server, extension or hook configuration: changes from the hourly scan, and a full snapshot every 24 h | all |
| `activity` | agent action (prompt, tool call, permission decision) | `standard` and `full` only |

In the default `minimal` privacy profile activity records are kept in a
local ring on the host and reach the outbox only as context attached to a
finding (the last 5 records of the session, as `detection.context` on the
detection stream); see [PRIVACY.md](PRIVACY.md).

Each line is one JSON object. `ts` is always
`YYYY-MM-DDTHH:MM:SS.ffffffZ` (six fraction digits, UTC). `id` is
deterministic, so a replayed record carries the same `id` as the original:
delivery is at least once, and destinations should deduplicate on `id`.
A record is capped at `output.max_line_bytes` (16 KiB by default, after
JSON encoding); fields cut to fit are listed in `truncated`. A record
written more than 60 s after its `ts` (a laptop that was offline) carries
`emitted`, which the pipeline sets when it writes the record: schedule
SIEM searches on `emitted` and order by `ts`.

The schema is in [EVENTS.md](EVENTS.md).

## Quick start

1. Copy `deploy/fluent-bit/hawkbell-inputs.yaml` and the output fragments you
   need from `deploy/fluent-bit/outputs/` to `/etc/fluent-bit/`, or run
   `hawkbell export fluent-bit --out <dir>`, which writes the same files
   with this host's outbox path as the default.
2. Include them from your configuration and set a storage path:

   ```yaml
   service:
     http_server: on            # the API hawkbell doctor reads (step 5)
     http_listen: 127.0.0.1
     http_port: 2020
     storage.metrics: on        # /api/v1/storage, also read by hawkbell doctor
     storage.path: /var/lib/fluent-bit/storage
     storage.keep.rejected: on
     storage.rejected.path: rejected
   includes:
     - hawkbell-inputs.yaml
     - outputs/splunk.yaml
     - outputs/s3.yaml
   ```

   Or start from the standalone `deploy/fluent-bit/hawkbell.yaml`, which
   contains the service section shown in full.
3. Set the variables the fragments read: `HAWKBELL_OUTBOX` (default
   `/var/lib/hawkbell/outbox`), `HAWKBELL_FLB_DB` (default
   `/var/lib/fluent-bit`, where the tail offset databases
   `hawkbell-findings.db` and `hawkbell-activity.db` live),
   `HAWKBELL_FLB_STATE` (default `/var/lib/fluent-bit`; `hawkbell.yaml`
   and `outputs/s3.yaml` keep their buffers under it) and the
   destination's own variables (for Splunk `SPLUNK_HEC_HOST`,
   `SPLUNK_HEC_TOKEN`, ...).
4. Check the configuration with `fluent-bit -c <file> --dry-run`.
5. Tell hawkbell where Fluent Bit keeps its offsets, in hawkbell's
   configuration (`/etc/hawkbell/hawkbell.yaml` on Linux):

   ```yaml
   output:
     fluent_bit:
       tail_db: /var/lib/fluent-bit/hawkbell-*.db   # comma-separated paths or globs
       api: http://127.0.0.1:2020                    # optional, for hawkbell doctor
   ```

   Without `tail_db` the daemon cannot see what Fluent Bit has read. It
   then prunes the outbox by age and size alone, and the size cap can
   delete records Fluent Bit has not shipped without reporting it (see
   [Operating it](#operating-it)). `api` needs the `http_server` and
   `storage.metrics` settings from step 2.

## Why each setting is there

Most settings in `hawkbell-inputs.yaml` and `hawkbell.yaml` answer a
failure that was reproduced against the real image, in the design review
([ASSUMPTIONS.md](ASSUMPTIONS.md), "Transport") or in the end-to-end
tests (`test/e2e/fluentbit_test.go`, results in
[`deploy/fluent-bit/VERIFIED.md`](../deploy/fluent-bit/VERIFIED.md)).

| Setting | Without it |
|---|---|
| `storage.type: filesystem` on the tail inputs | With the default memory buffering, tail commits its file offset when it reads a line. With the destination down, 5,000 records written and Fluent Bit restarted, 0 of 5,000 were delivered. With filesystem buffering: 5,000 of 5,000, after both SIGKILL and a graceful stop. |
| `retry_limit: no_limits` on every output | With the default retry limit, a destination that is down longer than the retry budget loses the chunks. `storage.total_limit_size` next to it bounds the disk each output's backlog may use. |
| `storage.keep.rejected: on` | A destination answering HTTP 400, 401 or 413 made Fluent Bit's `http` output give up on the chunk after one request, even with `retry_limit: no_limits` (`dropped_records` 10 of 10; a 503 was retried and delivered once the destination accepted). With this setting the chunk is kept under `storage.path/rejected`; the kept file held all 10 records. Other outputs were not tested. |
| Two tail inputs (findings, activity) | With one tail input for every stream, memory-buffered with `mem_buf_limit 5M`, 35 MB of activity for an unreachable archive paused the input, and 0 of 10 detections written 5 s later reached a healthy SIEM output within 45 s; with two such inputs, 10 of 10. With filesystem buffering (the shipped setting) one input delivered 10 of 10 as well, behind 3.5 MB and 35 MB of activity, and so did one memory-buffered input with `mem_buf_limit 5M` behind 3.5 MB. The split protects findings when an input is memory-buffered with a `mem_buf_limit` that the activity backlog exceeds (measured: 5M limit, 35 MB backlog). Memory buffering without `mem_buf_limit`, and filesystem buffering with `storage.pause_on_chunks_overlimit: on` (shipped: `off`), were not run. |
| `db.compare_filename: true` | After a segment was deleted and its inode reused, Fluent Bit skipped 1,000 of the 3,000 records in the new file (design review). |
| `db.locking: false` | The hawkbell daemon and `hawkbell doctor` open these databases read-only, when `output.fluent_bit.tail_db` names them, to measure shipper lag and to prune only segments Fluent Bit has read to the end. With `db.locking: true`, Fluent Bit 5.2.0 held each database locked (only a `-wal` file beside it, no `-shm`): a read in place failed with `database is locked` after SQLite's 2 s busy timeout, and a read of a copy of the database and its WAL found the rows (`TestFluentBitTailDBLocking`). The daemon then reads such a copy in its checkpoint directory, which can be behind. `hawkbell doctor` reads each database twice, both times with this fallback and a copy in a private temporary directory it removes: in its `fluent_bit` check and in the daemon status it embeds (`outboxStatus` in `internal/daemon/status.go`), so each locked database adds 4 s to the run (measured: 4.07 s with one, 8.10 s with both shipped databases locked, 0.04 s without `tail_db`; deploy/fluent-bit/VERIFIED.md, "Fixes added 2026-11-12, second pass"). |
| `skip_long_lines: on`, `buffer_max_size: 1M` | One over-long line stops the whole file (a 200 KB line with the default 32k buffer, design review). hawkbell's line cap (16 KiB by default, 64 KiB at most) keeps every record well inside the buffer. |
| Parser with `time_format '%Y-%m-%dT%H:%M:%S.%L%z'` | A timestamp the parser cannot read silently becomes ingestion time. |
| `rewrite_tag` to `hawkbell.parse_error` | A line that is not JSON arrives as `{"log": ...}` and mixes into your data; it gets its own tag instead. |

The tail databases must be on persistent storage. The inputs set
`read_from_head: true`, so a tail database that is lost makes Fluent Bit
read every retained segment again from its start and deliver those
records a second time: with 5,000 records delivered, the databases
deleted and Fluent Bit restarted, all 5,000 arrived again (10,000
received; with the databases kept, none). Deterministic ids make this
survivable at a destination that deduplicates.

## Routing

Tags are `hawkbell.<stream>`, plus `hawkbell.parse_error` for lines that
are not JSON. The Splunk, Sentinel and SecOps fragments send findings,
summaries, health, posture, inventory and parse errors
(`match_regex: '^hawkbell\.(detection|summary|health|posture|inventory|parse_error)$'`).
All the other fragments match `hawkbell.*`, activity included: use
`match_regex` there too if a destination should not get activity.

| Fragment | Destination | Notes |
|---|---|---|
| `outputs/splunk.yaml` | Splunk HEC | Deduplicate in searches: `\| dedup id`. TLS verification on. |
| `outputs/sentinel.yaml` | Microsoft Sentinel / Log Analytics (Logs Ingestion API) | Needs a DCR with a custom table. KQL: `summarize arg_max(TimeGenerated, *) by id`. |
| `outputs/chronicle.yaml` | Google SecOps | Needs a SecOps parser for the custom log type. |
| `outputs/elasticsearch.yaml`, `outputs/opensearch.yaml` | Elasticsearch, OpenSearch | `id_key: id`: a replayed record overwrites instead of duplicating. |
| `outputs/kafka.yaml` | Kafka | Message key is the record id, for compaction and consumer-side dedupe. |
| `outputs/s3.yaml` | S3 | Gzipped objects under `/hawkbell/<stream>/<YYYY>/<MM>/<DD>/<HH>/`; query with Athena, BigQuery or DuckDB. |
| `outputs/loki.yaml` | Grafana Loki | Labels are `job`, `stream` and `severity` only. |
| `outputs/otlp.yaml` | Any OTLP endpoint (logs) | |
| `outputs/http.yaml` | Any HTTPS JSON endpoint | Bearer token header. The records carry neither the tag nor the event time. For a receiver behind a private CA the file offers `tls.ca_file` as a comment; it was not tested. In the recorded run Fluent Bit trusted a private CA only when it was mounted as `<subject hash>.0` in `/etc/ssl/certs`; the CA placed in the image's bundle file failed verification ([REAL-AGENT.md](../test/e2e/REAL-AGENT.md), section 5). |
| `outputs/file.yaml` | Local files | For trying it out and for tests. |

`hawkbell.yaml` and the eleven output fragments pass
`fluent-bit --dry-run` with 5.2.0 (VERIFIED.md), which checks
that Fluent Bit accepts the properties, not that the destination accepts
the data. Only `outputs/http.yaml` delivered records end to end: over
TLS with the bearer header to a local receiver, in the real-agent run
([`test/e2e/REAL-AGENT.md`](../test/e2e/REAL-AGENT.md), section 5,
recorded before the rename). The end-to-end tests in
`test/e2e/fluentbit_test.go` use the shipped inputs with an `http` output
of their own. No other destination was tried.

## Other fragments

- **`osquery.yaml`** tails osquery result logs (Fleet reports and osquery
  schedules) and tags them `osquery.results`; reports whose name starts
  with `hawkbell` move to `osquery.hawkbell` (change the prefix in its
  `rewrite_tag` rule for your own reports). Event time is parsed from
  `calendarTime` because Fluent Bit does not honour the numeric `unixTime`
  as a time key. Tested on 11 real result lines from a Fleet 4.94.1 server:
  all 11 arrived on `osquery.hawkbell` with event time equal to `unixTime`.
- **`numbat.yaml`** tails perplexityai/numbat's NDJSON and routes each
  record type to `numbat.<record_type>`; a line that is not JSON stays on
  `numbat.raw`. For hawkbell's correlation, Fleet tables and rules over
  numbat records, point hawkbell at the same files instead
  (`sources.adapters`).
- **`no-binary/`** is for hosts where no daemon will be installed: the
  agents' own OpenTelemetry export, pinned by managed settings to a
  loopback `opentelemetry` input, normalised by a Lua script with four
  text-matching rules. It cannot decide anything before a tool runs, reads
  the attribute names of Claude Code, Codex and Gemini CLI only, depends on
  the agent's exporter for anything sent while Fluent Bit is down (not
  tested) and accepts posts from anything on the host. Its
  [README](../deploy/fluent-bit/no-binary/README.md) lists every limit.
- **`kubernetes.yaml`** reads the node sensor's container log in a Fluent
  Bit DaemonSet. Not yet tested on a cluster.

Defaults in these fragments avoid globs whose top directory may be missing
(`/Users/*/...` on Linux): Fluent Bit 5.2.0 logs an error on every refresh
for such a glob. Set the variable for your platform instead.

## Operating it

- Watch Fluent Bit's `/api/v1/metrics` for `dropped_records` and
  `retried_records` per output, and `/api/v1/storage` for chunks building
  up. With `storage.metrics: off`, 5.2.0 answers 404 on `/api/v1/storage`;
  with it on (set in `hawkbell.yaml`), and also when the setting was left
  out, it answered 404 for the first 4 to 5.5 s after start and 200 from
  then on.
- `hawkbell doctor` checks the shipper. The checks of Fluent Bit itself
  (the `fluent_bit` check: API, configuration file, tail databases) only
  warn, never fail (`cmd/hawkbell/fluentbit.go`):
  - with `output.fluent_bit.api` set it reads the API and warns when the
    API cannot be reached, when an output dropped records, when an output
    gave up retrying (`retries_failed`), when no `storage_backlog` input
    exists (no `storage.path`, so every input is memory-buffered) and when
    `/api/v1/storage` cannot be read. A 404 from `/api/v1/storage` means
    that `storage.metrics` is off or that Fluent Bit started seconds ago,
    and a 404 from `/api/v1/metrics` that it started less than a second
    ago; doctor says to rerun it in both cases. The API does not say how
    each input buffers;
  - with `--fluent-bit-config <file>` (YAML or classic, includes followed)
    it warns for each tail input that reads the outbox without
    `storage.type: filesystem` or without a `db`, when no tail input reads
    the outbox, when `storage.path` is not set, and for each output without
    `retry_limit: no_limits`;
  - with `output.fluent_bit.tail_db` set it expands the value as the
    daemon does (comma-separated paths and globs, `ExpandTailDB` in
    `internal/daemon/taildb.go`) and reads each database the way the
    daemon's pruner does (`CheckTailDB`): in place, and, when that fails
    (a database Fluent Bit holds locked with `db.locking: true`, a
    read-only mount), from a copy, which doctor makes in a temporary
    directory and removes. A locked database therefore adds SQLite's 2 s
    busy timeout to this check and is not reported; the daemon status
    that doctor also reads (the `daemon` section of `--json`) reads it the
    same way and adds another 2 s. It warns (`shipper.tail_db`) once for each
    database that is missing or cannot be read as a tail database either
    way, for each pattern that matches no file, and when more than 16
    databases are named (the daemon reads the first 16). Fluent Bit 5.2.0 creates both shipped databases
    when it starts, also when no activity segment exists yet, so the glob
    in step 5 matches both.

  `--as-user <account>` is part of the `outbox` check, and that check
  fails (doctor exits 4) when the account cannot read the outbox
  (`cmd/hawkbell/doctor.go`, `doctorOutbox`).
- The daemon prunes the outbox every 30 seconds. A segment counts as read
  when every consumer of its stream has read it to the end: the Fluent Bit
  tail databases named in `output.fluent_bit.tail_db` and the experimental
  `output.forward` and `output.otlp` shippers. Age (`retention.outbox`,
  default 7 days) removes read segments only, and segments of streams no
  consumer reads. The size cap (`retention.outbox_bytes`, default 512 MiB)
  removes read segments first, then segments of streams no consumer reads,
  then unread data, activity first and detections last. The newest segment
  of each stream is never removed. Unread data the cap removes is reported
  as a `health.error` with reason `outbox.dropped_unshipped`, with record
  and byte counts and the first and last sequence numbers lost per stream
  ([EVENTS.md](EVENTS.md#counters)). With no consumer configured, the
  daemon prunes by age and size alone and no such record is written; the
  heartbeat's `outbox.pruned_cap` counter still counts the segments the
  cap removed (`outbox.pruned_bytes` is the bytes removed by age and by
  the cap together).
- Every heartbeat carries per-stream counters for the interval since the
  previous one (`stream.<name>.emitted`, `.dropped`, `.truncated`,
  `.first_seq`, `.last_seq`), so a destination can detect gaps without
  trusting Fluent Bit ([EVENTS.md](EVENTS.md#per-stream-accounting)). The
  daemon also reports `shipper_lag_bytes` (bytes the slowest consumer of
  each stream has not read yet) and `outbox.lag.<consumer>` (bytes that
  consumer has not read) when a consumer is configured.
