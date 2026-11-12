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
