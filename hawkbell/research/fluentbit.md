> **Historical design record.** Research report: Fluent Bit 5.2.0 integration surfaces (tail, the Forward protocol, the HTTP and OpenTelemetry inputs, configuration, buffering), partly run against the `fluent/fluent-bit` 5.2.0 image.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:57 UTC on the build machine; it cites a documentation clone at a commit of 2026-11-09 and runs of Fluent Bit 5.2.0).
> - Written before the project had a name. The text uses the placeholder `agentwatch` (for example the command `agentwatch fluent-bit print-config` and the tags `agentwatch.*`); it is a placeholder, not this project's name or a product the report describes. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Fluent Bit integration surfaces (v5.2.0) for an AI-agent detection sensor

## Executive summary

1. Default transport should be **NDJSON segment files + `tail` with a SQLite `db`**: it is the only path that works identically on Linux, macOS and Windows, needs no listener, no auth, survives either process dying, and is at-least-once (run-verified, including SIGKILL and restart).
2. Best optional transport is **Fluent Forward v1 with the `chunk`/ack option** (unix socket on Linux/macOS, loopback TCP on Windows): binary, nanosecond event time, per-event tags, and all four carrier modes plus acks and the `shared_key` handshake were run-verified from a 150-line hand-written MessagePack client.
3. `in_http` and `in_opentelemetry` work but are worse fits: `in_http` cannot carry an event timestamp and returned 200 while silently losing a `[ts,{...}]` payload; OTLP puts attributes/resource in metadata that the `file` output drops.
4. Fluent Bit ships **no osquery parser and no named-pipe input**; osquery result logs need a custom JSON parser keyed on `calendarTime` (numeric `unixTime` is not honoured as a time key; run-verified).
5. Conditional routing (`routes:`) in 5.2.0 has sharp edges (replaces tag matching, rewrites the tag to the route name, drops default-route records for an output listed in two routes); route by **sensor-chosen tags** instead.

Sources: docs clone `/home/user/fluent/fluent-bit-docs` (commit 75f6d7a, 2026-11-09), Fluent Bit source at tag `v5.2.0` fetched from raw.githubusercontent.com, and live runs of `fluent/fluent-bit:latest` (`Fluent Bit v5.2.0`, git e0149076ae). VERIFIED = read or run in this session. Note the docs still call 5.2 "upcoming" (`installation/downloads.md`) and list 5.1.3/5.1.5 as latest packages, while the Docker `latest` image is already 5.2.0.

## 1. Ways a local Go daemon can hand events to Fluent Bit

| Path | Delivery | Backpressure seen by sensor | Auth / TLS | Platforms | Notes |
|---|---|---|---|---|---|
| **tail** (NDJSON files) | At-least-once with `db` (tail.md:101-109) | None: Fluent Bit just reads later; sensor must bound its own disk | File permissions | Linux, macOS, Windows (`FLB_IN_TAIL Yes` in `cmake/windows-setup.cmake`) | inotify on Linux; stat polling every 250 ms plus rotation check every 2.5 s elsewhere (`plugins/in_tail/tail_fs_stat.c:193-203`; `inotify_watcher` option only exists under `FLB_HAVE_INOTIFY`, `tail.c:760`) |
| **forward** TCP / unix socket | At-least-once only if client sends `chunk` and retries un-acked | Paused input closes the connection without ack (run-verified) | `shared_key`, `security.users`, TLS, mTLS (`tls.verify_client_cert`) | TCP everywhere; `unix_path` needs `FLB_HAVE_UNIX_SOCKET` (compile check for `sys/un.h` + `unistd.h`, CMakeLists.txt:1228-1241), so no unix socket on MSVC Windows builds (INFERENCE from that check) | `workers` not allowed with `unix_path` |
| **http** (JSON) | Client retries on non-2xx or dropped connection | Paused listener accepts then immediately closes connections (backpressure.md) | TLS, mTLS, OAuth2 JWT via JWKS only; no static token | All (`FLB_IN_HTTP Yes` on Windows) | No event time; JSON parse cost |
| **opentelemetry** | Same HTTP listener; 503 / gRPC 14 when ingress queue full | Same as http | Same as http | All per CMake defaults (`FLB_IN_OPENTELEMETRY ON`, not overridden on Windows; not run on Windows) | OTLP/HTTP JSON + protobuf and gRPC on one port (4318) |
| **tcp** | At-most-once, no ack (run-verified: no reply) | TCP only | TLS/mTLS | All | `format json` (objects/arrays) or `none` + separator |
| **udp** | At-most-once datagrams | None | None | All per CMake defaults | Max message = `chunk_size`/`buffer_size` (KB) |
| **syslog** | At-most-once | None | TLS for tcp mode | `unix_udp`, `unix_tcp`, `tcp`, `udp`; default socket perm `0644` | Needs a parsers file |
| **exec** | At-most-once polling of a command through `popen` + shell | n/a | n/a | Compiled out of distroless container images (exec.md "Container support"); enabled on Windows | Could run `sensor scan --json` every N seconds |
| **stdin** | None; EOF makes Fluent Bit exit | Pipe blocks writer | n/a | Windows support since v5.0.7 | JSON object or `[ts,{..}]` |
| **in_unix_socket** | n/a | | | `FLB_IN_UNIX_SOCKET OFF` by default (`cmake/plugins_options.cmake:74`); absent from the 5.2.0 binary | Do not rely on it |
| **Windows named pipes** | n/a | | | No such input: zero hits for "named pipe" in the docs and nothing in the binary's input list | Use tail or loopback forward |

### tail specifics worth copying (tail.md)

- `buffer_chunk_size` and `buffer_max_size` both default to **32k**. A line longer than `buffer_max_size` makes Fluent Bit **stop monitoring the file** unless `skip_long_lines: on`. Run-verified: a 1.5 MB line was skipped with `file=... have long lines. Skipping long lines.` and following lines were still delivered.
- `db` stores `id, name, offset, inode, created` in table `in_tail_files`; `db.sync` default `normal`, `db.journal_mode` default `wal` (creates `-wal`/`-shm` files), `db.locking: true` blocks external readers, `db.compare_filename` adds filename to the inode match.
- `refresh_interval` default **60 s** (new-file discovery); `rotate_wait` default 5 s; `read_from_head` default false (startup files), `read_newly_discovered_files_from_head` default true.
- Rotation by rename is handled (`handle rotation(): events.ndjson => events.ndjson.1`, run-verified). copytruncate can lose data, and the `path` glob must not match rotated names or they are re-read (tail.md:495-506).
- Windows: files are opened with `FILE_SHARE_READ|WRITE|DELETE` and NTFS file index is used as inode (`plugins/in_tail/win32/io.c:47-82`, `win32/stat.c:288`), so the sensor can rotate/delete while Fluent Bit reads. `windows.path_encoding: utf8` (5.1+) is needed for non-ANSI paths and paths over `MAX_PATH`.
- Parser miss behaviour (run-verified): a non-JSON line is **not dropped**, it becomes `{"log":"not json at all"}`; a line whose time key is missing or unparsable is kept with ingestion time.
- `offset_key` was wrong after a skipped long line (reported 500358 for a record that sits past byte 1,500,000). Do not use it for dedupe.

Run-verified sequence (config in section 5, Linux container): 2 pre-existing lines read from head; appended line picked up immediately; rename rotation followed; new file picked up about 3 s later with `refresh_interval: 5`; `docker kill -s KILL`, one line appended while down, restart: exactly that one line was emitted, no duplicates, no loss.

## 2. Forward protocol v1, as implemented by Fluent Bit 5.2.0

Spec: https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1 (read in full). Server behaviour: `plugins/in_forward/fw_prot.c` at v5.2.0.

Every request is one MessagePack array; mode is detected from element 1 (`fw_prot.c:1637-1745`):

| Mode | Shape | Element 1 type |
|---|---|---|
| Message | `[tag, time, record, option?]` | positive int or ext (float or negative time is rejected) |
| Forward | `[tag, [[time, record], ...], option?]` | array |
| PackedForward | `[tag, <concatenated msgpack entries>, option?]` | `bin` or `str` |
| CompressedPackedForward | same, payload gzip (Fluent Bit also accepts `zstd`), option `{"compressed":"gzip"}` required | `bin` |

Options Fluent Bit reads: `chunk` (must be a msgpack **str**; echoed as ack), `compressed` (`gzip`|`zstd`, cross-checked against magic bytes), `size` (ignored), plus Fluent Bit extensions `fluent_signal` (logs/metrics/traces) and `metadata` (Message mode). Ack is written after the events are appended to the input buffer, in every mode (`send_ack`, `fw_prot.c:795`, call sites 1204/1669/1930): ack means "accepted into Fluent Bit's buffer", not "delivered downstream".

Byte-level examples (all sent to the 5.2.0 container and acked/printed):

```
Message mode, 49 bytes -> [0] agentwatch.msg: [[1794391200.123456789, {}], {"event"=>"message.mode","n"=>1}]
93                                              fixarray(3)
ae 61 67 65 6e 74 77 61 74 63 68 2e 6d 73 67    fixstr(14) "agentwatch.msg"
d7 00 6a f4 3c a0 07 5b cd 15                   fixext8, type 0: u32 BE sec=1794391200, u32 BE nsec=123456789
82 a5 65 76 65 6e 74 ac 6d 65 73 73 61 67 65 2e 6d 6f 64 65 a1 6e 01   {"event":"message.mode","n":1}

PackedForward with ack request (3 entries, 99-byte stream)
93 b1 "agentwatch.packed"  c4 63 <92 d7 00 <8 bytes> 82 ... x3>  82 a4 "size" 03 a5 "chunk" b8 <24 base64 chars>

Ack response (server -> client), 30 bytes
81 a3 61 63 6b b8 <same 24 base64 chars>        {"ack": "<chunk>"}
```

`chunk` is base64 of 16 random bytes. EventTime may also be `c7 08 00 <8 bytes>` (ext8). Plain integer seconds are accepted (verified: `[.., 1794391200, {...}]` gave `.000000000`).

Handshake (only when `shared_key` or `empty_shared_key` is set), observed bytes:

```
S->C HELO  92 a4 "HELO" 82 a5 "nonce" b0 <16 raw bytes> a4 "auth" b0 <16 raw bytes>
C->S PING  96 a4 "PING" <str client_hostname> <str shared_key_salt> d9 80 <128 hex> a0 a0
S->C PONG  95 a4 "PONG" c3 a0 a9 "flb.local" d9 80 <128 hex>
```

- `shared_key_hexdigest` (PING) = `sha512_hex(shared_key_salt + client_hostname + nonce + shared_key)`
- PONG digest = `sha512_hex(shared_key_salt + server_self_hostname + nonce + shared_key)`; verified it checks out.
- password = `sha512_hex(auth_salt + username + password)`, or `""` with `""` username when no users are configured.
- Fluent Bit quirks: nonce and auth salt are 16 **raw random bytes typed as msgpack `str`** (not UTF-8), `auth` is always non-empty, there is no `keepalive` key, every PING field must be `str` (a `bin` salt is rejected, `fw_prot.c:600`), PING must be a 6-element array, and `self_hostname` must differ between client and server (forward.md). Wrong key: server logs `shared_key mismatch` and closes; the client read 0 bytes (no PONG false was received).

Limits: `buffer_chunk_size` 1024000, `buffer_max_size` 6144000 (also caps decompressed size), `msgpack_memory_limit` default 16 x `buffer_max_size`. Unix socket: `unix_path` max 107 bytes on Linux, 103 on macOS; `unix_perm` must be plain octal such as `0660` (`-1` becomes `07777`); an existing socket is replaced.

Backpressure, run-verified with `mem_buf_limit: 20k` and a dead output: batches 0 and 1 (15.5 KB each) acked, then `paused (mem buf overlimit)`; batch 2 was written successfully by the client, got **no ack and the connection was closed**; a reconnect was accepted but the next batch timed out without ack. Without `chunk`, that data would have been lost silently.

## 3. in_opentelemetry

- Endpoints: `/v1/logs`, `/v1/metrics`, `/v1/traces` (HTTP), and gRPC export paths (the docs list `/opentelemetry.proto.collector.log.v1.LogService/Export` twice, probably a typo for the standard `logs.v1.LogsService`; gRPC was not run here), all on one port (default 4318). JSON and protobuf are both "Stable" for logs. gzip/zstd/snappy request bodies.
- Success code defaults to **201** (`successful_response_code`: 200/201/204). Limits in 5.2: `buffer_max_size` 64 MiB (413 above), `logs_max_size` 100M.
- Tag: explicit `tag` wins; otherwise `tag_from_uri: true` gives **`v1_logs`** (observed); `tag_key` can take a record accessor.
- Minimal payload accepted (201, observed): `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"x"}}]}]}]}`. Missing `timeUnixNano` falls back to `observedTimeUnixNano`, then ingestion time (`src/opentelemetry/flb_opentelemetry_logs.c:74-77`). Bad JSON gives 400 `invalid request: deserialisation error`; wrong path gives 404; `{"resourceLogs":[]}` returns 201 but logs an error.
- Mapping (observed with stdout): string body becomes `{"log":"..."}` (or `logs_body_key`); a `kvlistValue` body **becomes the record map itself**; log attributes, severity, `trace_id`, `span_id`, `event_name`, `observed_timestamp` go to record **metadata** under `otlp` (`logs_metadata_key`); resource and scope go to **group attributes** (`{"resource":{"attributes":{...}},"scope":{...}}`).
- Consequence (observed): `stdout` with `format: json_lines` prints them under `__internal__`, but the `file` output wrote only the body. Trace/span ids are raw bytes and came out mangled in JSON. Other non-OTLP outputs were not tested.
- `raw_traces: true` forwards JSON traces unvalidated as logs; irrelevant for a logs-only sensor.

## 4. in_http (run-verified matrix)

| Request | Result |
|---|---|
| `POST /agentwatch.inventory` `{...}` | 201 by default (200/201/204 configurable), tag `agentwatch.inventory` |
| `POST /agentwatch/runtime/tool` | tag `agentwatch_runtime_tool` (anything but alnum, `_`, `.` becomes `_`, `http_prot.c:152-163`) |
| `POST /` | tag `http.0` |
| JSON array of objects | one record per element |
| Several JSON objects separated by newlines in one body | one record each |
| `Content-Encoding: gzip` | accepted |
| invalid JSON / scalar | 400 `error: unable to process records` |
| no `Content-Type` / `text/plain` | 400 (only `application/json` and `application/x-www-form-urlencoded`) |
| GET | 400 `error: invalid HTTP method` |
| body over `buffer_max_size` (4M) | 413 |
| `[1762855200.5, {"event":"I"}]` | **200, then `Log event decoder error : -10` at flush and the record never appears** |

Event time is always ingestion time (`flb_time_get`, `http_prot.c:613`). `tag_key` overrides the tag from a record field. `enable_health_endpoint: true` adds `GET /health`.

## 5. Configuration

- YAML is "the standard configuration format as of Fluent Bit v3.2"; classic `.conf` "will be deprecated at the end of 2026" (`administration/configuring-fluent-bit.md`). Processors, conditional routing, `telemetry` and `extensions` are YAML-only. The container image's default config is still classic; official Windows builds include libyaml via vcpkg (`.github/workflows/call-build-windows.yaml`).
- Top-level sections: `env`, `includes`, `service`, `pipeline`, `parsers`, `multiline_parsers`, `plugins`, `upstream_servers`, `extensions` (5.1+: free-form nested map Fluent Bit ignores, ideal for our own metadata such as a config version).
- `includes` takes literal relative/absolute paths (no env expansion). `env` supports `${VAR}`, `${VAR:-default}` (5.0.6+), predefined `${HOSTNAME}`, and file-backed secrets with `uri: file://...` + `refresh_interval`; the file must exist or startup fails (observed).
- Filters are global and tag-matched and run on the main thread; processors attach to one input/output under `processors: logs:` and run in that plugin's thread. Record accessor: `$key`, `$a['b']['c']`.
- `fluent-bit --dry-run -c file` validates property names since 4.2. The image ships `/fluent-bit/etc/schema.json` (769 KB: every plugin and option for this build), usable to validate generated configs offline.
- Hot reload: SIGHUP or `PUT /api/v2/reload`, supported on all three OSes.
- Conditional routing (4.2+, logs only). Observed on 5.2.0: (a) the tag seen by outputs becomes the **route name**; (b) once an input has `routes`, an output using `match` gets nothing from it; (c) an output listed in both a conditional route and the default route received only the conditional records, the rest vanished. Each output in exactly one route worked.

Reference pipeline (passes `--dry-run` on 5.2.0; the tail + tag routing part was run with local outputs and delivered 3 records to archive and 1 to the detection sink):

```yaml
env:
  - name: AW_LOG_DIR
    value: /var/log/agentwatch
  - name: FLB_STATE
    value: /var/lib/fluent-bit
  - name: SPLUNK_HEC_TOKEN
    uri: file:///etc/fluent-bit/secrets/splunk_hec_token
    refresh_interval: 300
service:
  flush: 1
  grace: 10
  http_server: on
  http_listen: 127.0.0.1
  http_port: 2020
  health_check: on
  hot_reload: on
  storage.path: ${FLB_STATE}/storage
  storage.sync: normal
  storage.checksum: on
  storage.max_chunks_up: 64
  storage.backlog.mem_limit: 32M
  storage.metrics: on
  storage.delete_irrecoverable_chunks: on
  storage.keep.rejected: on
  storage.rejected.path: rejected
  storage.rejected.limit: 256M
  scheduler.base: 3
  scheduler.cap: 300
parsers:
  - name: agentwatch_ndjson
    format: json
    time_key: ts
    time_format: '%Y-%m-%dT%H:%M:%S.%L%z'
    time_keep: on
pipeline:
  inputs:
    - name: tail
      alias: agentwatch_tail
      path: ${AW_LOG_DIR}/*.ndjson          # <stream>-<seq>.ndjson
      exclude_path: '*.tmp,*.gz'
      tag: agentwatch.<stream>
      tag_regex: '(?<stream>[a-z_]+)-[0-9]+\.ndjson$'
      parser: agentwatch_ndjson
      db: ${FLB_STATE}/tail-agentwatch.db
      db.sync: normal
      db.locking: true
      read_from_head: true
      refresh_interval: 5
      rotate_wait: 15
      buffer_chunk_size: 64k
      buffer_max_size: 1M
      skip_long_lines: on
      skip_empty_lines: on
      storage.type: filesystem
      storage.pause_on_chunks_overlimit: off
      processors:
        logs:
          - name: content_modifier
            action: insert
            key: collector_host
            value: ${HOSTNAME}
  outputs:
    - name: s3
      alias: archive_s3
      match: 'agentwatch.*'
      bucket: example-agentwatch-archive
      region: us-east-1
      total_file_size: 50M
      upload_timeout: 5m
      compression: gzip
      s3_key_format: /agentwatch/$TAG[1]/%Y/%m/%d/%H/$UUID.ndjson.gz
      store_dir: ${FLB_STATE}/s3
      storage.total_limit_size: 2G
      retry_limit: no_limits
    - name: splunk
      alias: siem_splunk
      match: 'agentwatch.detection'
      host: splunk-hec.example.com
      port: 8088
      tls: on
      splunk_token: ${SPLUNK_HEC_TOKEN}
      event_sourcetype: agentwatch:detection
      storage.total_limit_size: 512M
      retry_limit: no_limits
    - name: opentelemetry
      alias: otlp_out
      match: 'agentwatch.*'
      host: otel-collector.example.com
      port: 4318
      tls: on
      logs_uri: /v1/logs
      throttle: on
      storage.total_limit_size: 512M
      retry_limit: 10
```

Time format findings (observed with this parser): `...00.123456789Z`, `...01.5+00:00` and `...02.000-0800` parse correctly; `2026-11-11T10:00:03Z` (no fraction) fails with `invalid time format` and falls back to ingestion time because `time_strict` defaults to true. The sensor must always emit a fractional part.

## 6. Buffering and reliability

- Chunks average 2 MB. `storage.type`: `memory` (default), `filesystem` (mmap file plus memory copy), `memrb` (ring buffer that drops oldest). Filesystem needs `service.storage.path`; `storage.inherit: on` + `storage.type` sets a default for all inputs.
- `mem_buf_limit` only applies to memory buffering: the input is paused, and "some input plugins are prone to data loss" (backpressure.md). With filesystem buffering, `storage.max_chunks_up` (default 128) caps chunks in memory and `storage.pause_on_chunks_overlimit` decides whether the input pauses or keeps writing to disk.
- Per-output `storage.total_limit_size`: when exceeded the **oldest chunk is discarded**. `retry_limit`: N (default 1), `no_limits`/`false`, `no_retries`. Retry wait is jittered between `scheduler.base` (5) and `min(base*2^n, scheduler.cap)` (2000).
- DLQ: `storage.keep.rejected: on` copies chunks that hit a permanent error or exhaust retries to `<storage.path>/rejected/<tag>_<status>_<output>_<id>.flb`; `storage.rejected.limit` caps it; files stay until removed by hand and are in the internal chunk format.
- 5.1+: per-input `rate_gate.*`; `flush.adaptive`. 5.2: per-output `throttle` honours 429 / `Retry-After` for http, es, opensearch, opentelemetry.
- `storage.sync: full` for stronger crash durability; `storage.checksum: on` for CRC32.
- Guarantee is at-least-once end to end; duplicates arise from tail offset lag after a crash, un-acked forward resends, and output retries. Elasticsearch/OpenSearch outputs have `id_key` and `generate_id` for idempotent writes.
- Monitoring (run-verified): `/api/v1/health` returned `ok`, `/api/v1/metrics` gave per-input `records`, `long_line_skipped`, `files_rotated` and per-output `proc_records`, `errors`, `retries`, `dropped_records`; `/api/v1/storage` gave chunk counts. Also `/api/v2/metrics/prometheus`.

## 7. Outputs in the 5.2.0 Linux binary (47 from `--help`, plus `lib` in schema.json)

- SIEM / log platforms: `splunk`, `es`, `opensearch`, `datadog`, `nrlogs`, `loki`, `logdna`, `gelf`, `chronicle`, `azure` (Log Analytics HTTP collector), `azure_logs_ingestion`, `azure_kusto`, `oracle_log_analytics`, `stackdriver`, `cloudwatch_logs`, `skywalking`, `arvancloud_cloudlogs`, `td`
- Object stores: `s3`, `gcs`, `azure_blob`
- Queues / streams: `kafka`, `kafka-rest`, `kinesis_streams`, `kinesis_firehose`, `nats`
- OTel / metrics: `opentelemetry`, `prometheus_exporter`, `prometheus_remote_write`, `vivo_exporter`, `influxdb`
- Databases / warehouses: `pgsql`, `bigquery`
- Generic: `http`, `forward`, `tcp`, `udp`, `syslog`, `websocket`, `file`, `stdout`, `slack`
- Test / internal: `null`, `exit`, `counter`, `flowcounter`, `plot`

Windows default set is narrower (`cmake/windows-setup.cmake`): `bigquery`, `nats`, `td`, `kafka-rest`, `plot` are off. Doc pages for dash0, dynatrace, observe, openobserve and parseable exist but there are no plugins by those names in the binary.

## 8. Packaging and extension

- Windows: NSIS `.exe` (silent `/S /D=C:\fluent-bit`), `.zip`, `.msi` for win32, win64, winarm64; service via `sc.exe create fluent-bit binpath= "...fluent-bit.exe -c ...conf"` or `New-Service`. Windows container tags `windows-2022-*`, `windows-2025-*`, `windows-nano-2025-*` (Nano cannot run `exec`).
- macOS: `.pkg` built with CPack `productbuild` on macos-14 arm64 and Intel runners; Homebrew formula exists but "isn't officially supported" (macos.md).
- Linux: apt/yum repos at packages.fluentbit.io, `install.sh`, systemd unit; Debian/Ubuntu upgrades restart the service since 5.1.
- Containers: distroless images for amd64/arm64/arm/v7, `-debug` variants with a shell; `cr.fluentbit.io/fluent/fluent-bit`.
- Kubernetes: DaemonSet through the official Helm chart (`helm repo add fluent https://fluent.github.io/helm-charts`; `helm upgrade --install fluent-bit fluent/fluent-bit`).
- Extension: Lua filter (LuaJIT, enabled on Windows), WASM filter and `exec_wasi` input (TinyGo `wasm32-wasi`, Rust `wasm32-unknown-unknown`; `exec_wasi` off on Windows), Go plugins as `c-shared` `.so` loaded with `-e` ("output plugins only" per the docs), Zig integration only if zig 0.14.0 is on the build host, and the new `fts` processor (Lua-based typed scripting, 5.2).

## 9. osquery

- The docs contain no mention of osquery; shipped parsers are apache, apache2, apache_error, nginx, k8s-nginx-ingress, json, logfmt, docker, docker-daemon, syslog-rfc5424, syslog-rfc3164(-local), mongodb, envoy, istio-envoy-proxy, cri, kube-custom, kmsg-netfilter-log.
- osquery's filesystem logger writes one JSON object per line to `osqueryd.results.log` / `osqueryd.snapshots.log` with `name`, `hostIdentifier`, `calendarTime`, `unixTime`, `epoch`, `counter`, `columns` or `snapshot`, `action` (osquery `docs/wiki/deployment/logging.md`). Fleet's healthcheck scripts place the host-side directory at `/opt/orbit/osquery_log` and `C:\Program Files\Orbit\osquery_log`, "only populated when logger_path/logger_plugin" selects the filesystem logger; the Fleet server's own `filesystem` result plugin defaults to `/tmp/osquery_result`.
- Run-verified parser: `time_key: unixTime` + `time_format: '%s'` is ignored because the value is a JSON number (record got ingestion time). This works:

```yaml
parsers:
  - name: osquery_result
    format: json
    time_key: calendarTime
    time_format: '%a %b %d %H:%M:%S %Y UTC'
    time_keep: on
```

It parsed both `Wed Nov 11 10:00:00 2026 UTC` and the space-padded `Thu Oct  1 00:37:30 2026 UTC`. Snapshot lines can be large, so raise `buffer_max_size` (for example 4M) and keep `skip_long_lines: on`.

## 10. Recommended design for our agent

1. **Default: spool files + tail.** The sensor writes append-only NDJSON segments `<spool>/<stream>-<seq>.ndjson` (streams such as `inventory`, `runtime`, `detection`, `health`), rolls by size (for example 16 MB) by starting a new sequence number, never renames, never truncates, and prunes oldest segments by total size/age. Ship the YAML above as `agentwatch fluent-bit print-config`, validated against `schema.json`.
2. **Optional: built-in Forward client** (no dependency: msgpack subset + SHA-512). PackedForward, `bin` payload, EventTime, always `chunk`, wait for ack with timeout, resend on close/timeout, bounded on-disk spool behind it. Unix socket with `unix_perm 0660` on Linux/macOS; `127.0.0.1` + `shared_key` on Windows. Optional gzip.
3. **Optional: OTLP/HTTP JSON exporter** for sites without Fluent Bit; put the full event in a `kvlistValue` body and duplicate nothing essential into attributes.
4. Skip `in_http` as a first-class path (no timestamps; 200-with-loss case).
5. **Tags**: `agentwatch.<stream>` set by the sensor (file name or forward tag). Route with `match`, not `routes`.
6. **Record shape**: one JSON object per line, UTF-8, no raw binary; `ts` RFC 3339 UTC with a fixed fractional part (always present); `event_id` (UUIDv7/ULID) and per-boot `seq` for downstream dedupe and gap detection; routing fields (`kind`, `event`, `severity`) at top level; nested maps are preserved through msgpack, but keep depth shallow; target under 64 KB per event and hard-cap below `buffer_max_size` (truncate large fields in the sensor and flag `truncated: true`).
7. **Pitfalls to document for users**: the defaults that bite are the 32k tail line limit, 60 s discovery interval, `retry_limit` of 1 and oldest-chunk discard at `storage.total_limit_size`.
