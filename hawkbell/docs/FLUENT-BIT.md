# Shipping hawkbell records with Fluent Bit

hawkbell does not talk to your SIEM. It writes newline-delimited JSON files
into a root-owned outbox and leaves delivery to Fluent Bit, which already
has outputs for almost every destination. This page is the contract
between the two: what hawkbell writes, the Fluent Bit settings that keep it
from losing data, and how to route each stream.

Everything here was run against the `fluent/fluent-bit` image reporting
v5.2.0; the commands and results are in
[`deploy/fluent-bit/VERIFIED.md`](../deploy/fluent-bit/VERIFIED.md).
Version 5.0.6 or later is required for the `${VAR:-default}` syntax the
fragments use.

## What hawkbell writes

```
<data_dir>/outbox/<stream>-<YYYYMMDD>-<HH>-<n>.ndjson
```

`data_dir` is `/var/lib/hawkbell` on Linux, `/Library/Application Support/hawkbell`
on macOS and `C:\ProgramData\hawkbell` on Windows. The directory is
`root:hawkbell 0750` and the files `0640`, so Fluent Bit needs to run as root
or in the `hawkbell` group. Nothing else on the host can write there; the
per-user hook spools are a different directory that Fluent Bit must never
read (a user can write anything into their own spool).

| Stream | One record per | Ships in profile |
|---|---|---|
| `detection` | finding or alert (signals stay local unless `rules.min_class: signal`) | all |
| `summary` | agent session: counts, surfaces, top rules; emitted at session end, after 15 min idle and every 15 min while active | all |
| `health` | heartbeat every 5 min (per-stream accounting, coverage, versions), and errors | all |
| `posture` | failing configuration check | all |
| `inventory` | agent, MCP server, extension or hook configuration, on change | all |
| `activity` | agent action (prompt, tool call, permission decision) | `standard` and `full` only |

In the default `minimal` privacy profile activity records are kept in a
local ring on the host and never reach the outbox; see
[PRIVACY.md](PRIVACY.md).

Each line is one JSON object. `ts` is always
`YYYY-MM-DDTHH:MM:SS.ffffffZ` (six fraction digits, UTC). `id` is
deterministic, so a replayed record carries the same `id` as the original:
delivery is at least once, and destinations should deduplicate on `id`.
A record is capped at `output.max_line_bytes` (16 KiB by default, after
JSON encoding); fields cut to fit are listed in `truncated`. A record
written more than 60 s after its `ts` (a laptop that was offline) carries
`emitted`: schedule SIEM searches on `emitted` and order by `ts`.
<!-- VERIFY after C2: Emitted is set by the engine -->

The schema is in [EVENTS.md](EVENTS.md).

## Quick start

1. Copy `deploy/fluent-bit/hawkbell-inputs.yaml` and the output fragments you
   need from `deploy/fluent-bit/outputs/` to `/etc/fluent-bit/`.
2. Include them from your configuration and set a storage path:

   ```yaml
   service:
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
   `/var/lib/fluent-bit`, where the tail offset databases live) and the
   destination's own variables (for Splunk `SPLUNK_HEC_HOST`,
   `SPLUNK_HEC_TOKEN`, ...).
4. Check the configuration with `fluent-bit -c <file> --dry-run`.

## Why each setting is there

Each line of `hawkbell-inputs.yaml` answers a failure that was reproduced
against the real image during the design review
([ASSUMPTIONS.md](ASSUMPTIONS.md), "Transport").

| Setting | Without it |
|---|---|
| `storage.type: filesystem` on the tail inputs | With the default memory buffering, tail commits its file offset when it reads a line. With the destination down, 5,000 records written and Fluent Bit restarted, 0 of 5,000 were delivered. With filesystem buffering: 5,000 of 5,000, after both SIGKILL and a graceful stop. |
| `retry_limit: no_limits` and `storage.total_limit_size` on every output | A destination that is down longer than the retry budget loses the chunks. |
| `storage.keep.rejected: on` | A permanent HTTP error (401 after a token rotation, 400, 413) drops the chunk after one request even with unlimited retries. Kept chunks land under `storage.path/rejected`. |
| Two tail inputs (findings, activity) | With one input for every stream and the activity destination unreachable, 0 of 10 detections reached a healthy SIEM. With two: all 10 arrived while 20,000 activity records were stuck. |
| `db.compare_filename: true` | After a segment was deleted and its inode reused, Fluent Bit skipped 1,000 of the 3,000 records in the new file. |
| `db.locking: false` | Lets the hawkbell daemon read the offset databases to measure shipper lag and to prune only segments Fluent Bit has finished. <!-- VERIFY after C3 --> |
| `skip_long_lines: on`, `buffer_max_size: 1M` | One over-long line stops the whole file. hawkbell's 16 KiB cap keeps every record well inside the buffer. |
| Parser with `time_format '%Y-%m-%dT%H:%M:%S.%L%z'` | A timestamp the parser cannot read silently becomes ingestion time. |
| `rewrite_tag` to `hawkbell.parse_error` | A line that is not JSON arrives as `{"log": ...}` and mixes into your data; it gets its own tag instead. |

The tail databases must be on persistent storage. Deleting one replays
every retained segment: in testing 5,000 delivered records became 10,000.
Deterministic ids make this survivable at a destination that deduplicates.

## Routing

Tags are `hawkbell.<stream>`. The shipped output fragments send findings,
summaries, health, posture, inventory and parse errors to a SIEM
(`match_regex: '^hawkbell\.(detection|summary|health|posture|inventory|parse_error)$'`)
and everything, activity included, to cheap storage.

| Fragment | Destination | Notes |
|---|---|---|
| `outputs/splunk.yaml` | Splunk HEC | Deduplicate in searches: `\| dedup id`. TLS verification on. |
| `outputs/sentinel.yaml` | Microsoft Sentinel / Log Analytics (Logs Ingestion API) | Needs a DCR with a custom table. KQL: `summarize arg_max(TimeGenerated, *) by id`. |
| `outputs/chronicle.yaml` | Google SecOps | Needs a SecOps parser for the custom log type. |
| `outputs/elasticsearch.yaml`, `outputs/opensearch.yaml` | Elasticsearch, OpenSearch | `id_key: id`: a replayed record overwrites instead of duplicating. |
| `outputs/kafka.yaml` | Kafka | Message key is the record id, for compaction and consumer-side dedupe. |
| `outputs/s3.yaml` | S3 | Gzipped NDJSON per stream and hour; query with Athena, BigQuery or DuckDB. |
| `outputs/loki.yaml` | Grafana Loki | Labels are low-cardinality fields only. |
| `outputs/otlp.yaml` | Any OTLP endpoint (logs) | |
| `outputs/http.yaml` | Any HTTPS JSON endpoint | |
| `outputs/file.yaml` | Local files | For trying it out and for tests. |

Only the `http` and `file` outputs were exercised end to end here; the
others pass `--dry-run`, which checks that Fluent Bit accepts the
properties, not that the destination accepts the data.

## Other fragments

- **`osquery.yaml`** tails osquery result logs (Fleet reports and osquery
  schedules) and tags them `osquery.<name>`, with event time parsed from
  `calendarTime` because Fluent Bit does not honour the numeric `unixTime`
  as a time key. Tested on 11 real result lines from a Fleet 4.94.1 server:
  event time equalled `unixTime` for all 11.
- **`numbat.yaml`** tails perplexityai/numbat's NDJSON and routes each
  record type to `numbat.<record_type>`. For hawkbell's correlation, Fleet
  tables and rules over numbat records, point hawkbell at the same files
  instead (`sources.adapters`).
- **`no-binary/`** is for hosts where no daemon will be installed: the
  agents' own OpenTelemetry export, pinned by managed settings to a
  loopback `opentelemetry` input, normalised by a Lua script with four
  text-matching rules. It cannot decide anything before a tool runs, sees
  only three of the five major agents, is lost when Fluent Bit is down and
  accepts posts from anything on the host. Its README lists every limit.
- **`kubernetes.yaml`** reads the node sensor's container log in a Fluent
  Bit DaemonSet. Not yet tested on a cluster.

Defaults in these fragments avoid globs whose top directory may be missing
(`/Users/*/...` on Linux): Fluent Bit 5.2.0 logs an error on every refresh
for such a glob. Set the variable for your platform instead.

## Operating it

- Watch Fluent Bit's `/api/v1/metrics` for `dropped_records` and
  `retried_records`, and `/api/v1/storage` for chunks building up.
- `hawkbell doctor` reads Fluent Bit's API when `output.fluent_bit.api` is
  set and warns when the tail input is memory-buffered or retries are
  bounded. <!-- VERIFY after C3 -->
- The daemon prunes outbox segments by age and size, and only segments
  the tail database shows as fully read; when the hard size cap forces it
  to drop unread data it emits a `health.error` with reason
  `outbox.dropped_unshipped` and counts. <!-- VERIFY after C3 -->
- Every heartbeat carries per-stream counters (`stream.<name>.emitted`,
  `dropped`, `truncated`, first and last sequence numbers), so a
  destination can detect gaps without trusting Fluent Bit.
  <!-- VERIFY after C2 -->
