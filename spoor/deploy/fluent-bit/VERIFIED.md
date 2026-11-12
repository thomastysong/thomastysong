# Verified against Fluent Bit 5.2.0

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
