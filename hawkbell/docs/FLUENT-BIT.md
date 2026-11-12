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
rejected chunks, an oversized record). The commands and results are in
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
packages create the group. The daemon looks the group up in `/etc/group`
only: when it is not there (a group that exists only in macOS Open
Directory or LDAP), the daemon logs a warning and the outbox stays
readable by root only. On Windows the outbox is readable by SYSTEM and
Administrators (compiled, not run on Windows). Only the daemon and
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
| `storage.keep.rejected: on` | A destination answering HTTP 401 made Fluent Bit give up on the chunk even with unlimited retries. With this setting the chunk is kept under `storage.path/rejected`. |
| Two tail inputs (findings, activity) | Records of all streams would share one input, so an unreachable activity destination could hold findings back. With two inputs, all 10 detections reached a healthy SIEM output while 20,000 activity records were stuck behind an unreachable archive. A one-input control is not part of the committed tests. |
| `db.compare_filename: true` | After a segment was deleted and its inode reused, Fluent Bit skipped 1,000 of the 3,000 records in the new file (design review). |
| `db.locking: false` | The hawkbell daemon and `hawkbell doctor` open these databases read-only, when `output.fluent_bit.tail_db` names them, to measure shipper lag and to prune only segments Fluent Bit has read to the end. With locking on, Fluent Bit holds the database locked and the daemon falls back to reading a copy in its checkpoint directory, which can be behind. |
| `skip_long_lines: on`, `buffer_max_size: 1M` | One over-long line stops the whole file (a 200 KB line with the default 32k buffer, design review). hawkbell's line cap (16 KiB by default, 64 KiB at most) keeps every record well inside the buffer. |
| Parser with `time_format '%Y-%m-%dT%H:%M:%S.%L%z'` | A timestamp the parser cannot read silently becomes ingestion time. |
| `rewrite_tag` to `hawkbell.parse_error` | A line that is not JSON arrives as `{"log": ...}` and mixes into your data; it gets its own tag instead. |

The tail databases must be on persistent storage. The inputs set
`read_from_head: true`, so a tail database that is lost makes Fluent Bit
read every retained segment again from its start and deliver those
records a second time. Deterministic ids make this survivable at a
destination that deduplicates.

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
  up. `/api/v1/storage` needs `storage.metrics: on` (set in
  `hawkbell.yaml`).
- `hawkbell doctor` checks the shipper. The checks of Fluent Bit itself
  (the `fluent_bit` check: API, configuration file, tail databases) only
  warn, never fail (`cmd/hawkbell/fluentbit.go`):
  - with `output.fluent_bit.api` set it reads the API and warns when the
    API cannot be reached, when an output dropped records, when an output
    gave up retrying (`retries_failed`), when no `storage_backlog` input
    exists (no `storage.path`, so every input is memory-buffered) and when
    storage metrics are unavailable. The API does not say how each input
    buffers;
  - with `--fluent-bit-config <file>` (YAML or classic, includes followed)
    it warns for each tail input that reads the outbox without
    `storage.type: filesystem` or without a `db`, when no tail input reads
    the outbox, when `storage.path` is not set, and for each output without
    `retry_limit: no_limits`;
  - with `output.fluent_bit.tail_db` set it warns (`shipper.tail_db`) when
    that path does not exist. It checks the value as written, without the
    comma and glob expansion the daemon applies, so a glob or a list such
    as the one in step 5 is reported even when the databases exist.

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
  daemon prunes by age and size alone and no such record is written.
- Every heartbeat carries per-stream counters for the interval since the
  previous one (`stream.<name>.emitted`, `.dropped`, `.truncated`,
  `.first_seq`, `.last_seq`), so a destination can detect gaps without
  trusting Fluent Bit ([EVENTS.md](EVENTS.md#per-stream-accounting)). The
  daemon also reports `shipper_lag_bytes` (bytes the slowest consumer of
  each stream has not read yet) and `outbox.lag.<consumer>` (bytes that
  consumer has not read) when a consumer is configured.
