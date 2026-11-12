# Events

Everything spoor writes for other systems is one record format: a JSON object on one line (NDJSON), defined by the Go types in `internal/event`. This page describes the streams, every record type and field, what each privacy profile ships, how records are identified and deduplicated, how time works for late records, and the heartbeat that lets a consumer prove nothing was lost.

- Machine-readable schema: [`schema/event.schema.json`](schema/event.schema.json) (JSON Schema 2020-12), generated from `internal/event`.
- Real records: [`schema/examples/`](schema/examples/), written by the spoor binary itself (see [How the examples were made](#how-the-examples-were-made)).
- The field reference at the end of this page is generated from the same code. `go test ./internal/event` fails when the schema, this reference or the examples disagree with the code.

## Where records are written

| Where | What | Notes |
|---|---|---|
| `<data_dir>/outbox/<stream>-<YYYYMMDD>-<HH>-<NNNN>.ndjson` | every record that may leave the host | The file Fluent Bit tails. The hour is UTC; `NNNN` is a roll counter (`output.max_segment_bytes`, default 16 MiB). On Linux the daemon makes the directory mode 2750 (setgid) with group `output.group` (default `spoor`, when that group exists) and the files 0640, so only root and that group (the shipper) can read them. A file name never changes once the file exists. |
| `<data_dir>/local/` | activity that must not leave the host (the `minimal` profile) | The local ring: same file naming, files 0600, never tailed, bounded by `retention.local` / `retention.local_bytes`. |
| standard output | the outbox records too, when `output.stdout: true` | For containers (the Kubernetes node sensor). |
| `spoor detect --ndjson`, `spoor scan --ndjson` | findings, posture checks and session summaries (`detect`); inventory and posture records (`scan`) | Same format and the same privacy stage as the outbox. |

The stream is the record's `kind`, so the tag Fluent Bit gives a record (`spoor.<stream>`, see [FLUENT-BIT.md](FLUENT-BIT.md)) follows from its file name. With `output.format: ocsf` the outbox carries OCSF 1.9.0 events instead (`internal/format`), with the native record under `unmapped.spoor`; this page and the schema describe the native format only. The experimental OTLP shipper sends the native record as the log body.

## Kinds and streams

| `kind` (= stream) | Types | Written by | Shipped in |
|---|---|---|---|
| `activity` | `session.start`, `session.end`, `prompt.submit`, `tool.pre`, `tool.post`, `turn.end`, `subagent.start`, `subagent.stop`, `permission.decision`, `config.change`, `notification`, `context.compact`, `agent.process.start`, `agent.process.stop`, `process.exec`, `hook.payload_anomaly` | hooks (through the spool), transcript tailer, process monitor, osquery exec pull, OTel receiver, adapters | `standard`, `full`; in `minimal` only as detection context |
| `detection` | `detection.finding`, `detection.context` | the rules engine and the coverage logic (findings); the privacy stage (context) | every profile |
| `inventory` | `inventory.asset` | inventory scan | every profile |
| `posture` | `posture.check` | inventory rules over the scan | every profile |
| `health` | `health.heartbeat`, `health.error` | the pipeline (heartbeat), the daemon (errors) | every profile |
| `summary` | `session.summary` | the pipeline | every profile |

`output.streams` can restrict which streams are written; empty means the profile's default.

### Types

| Type | Kind | Meaning |
|---|---|---|
| `session.start` | activity | A session began. Claude Code's `SessionStart` hook, or synthesized by the pipeline from the first record of a session it has not seen (`fidelity: inferred`), so the SessionStart hook is not required. |
| `session.end` | activity | A session ended (`SessionEnd`). The final summary follows once no record of the session is still held. |
| `prompt.submit` | activity | The user submitted a prompt. Prompt text is never shipped outside `full`. |
| `tool.pre` | activity | A tool call is about to run. The only type, with `prompt.submit`, that guard mode can answer. |
| `tool.post` | activity | A tool call finished, successfully or not (`outcome`). |
| `turn.end` | activity | The agent finished a turn (`Stop`). |
| `subagent.start`, `subagent.stop` | activity | A subagent thread started or stopped. |
| `permission.decision` | activity | A permission prompt or decision was observed (`outcome.decision`, `outcome.decision_source`). |
| `config.change` | activity | The agent reported a configuration change. |
| `notification` | activity | Other agent lifecycle events (Claude Code `Notification`, `InstructionsLoaded`, `CwdChanged` and similar); `labels.hook_event` names the original. |
| `context.compact` | activity | The agent compacted its context. |
| `agent.process.start`, `agent.process.stop` | activity | The process monitor saw an agent process start or stop (`process`, flags such as `--dangerously-skip-permissions`). |
| `process.exec` | activity | A child process attributed to an agent session (process connector, osquery exec pull or polling). |
| `hook.payload_anomaly` | activity | A hook payload that could not be read as an agent event (empty, malformed, too large, too deep): its size and a digest instead of nothing. |
| `inventory.asset` | inventory | One asset: agent, app, extension, MCP server, hook, rules file, skill and so on (`asset`). |
| `posture.check` | posture | A failed configuration check: an inventory rule matched an asset (`check`). |
| `detection.finding` | detection | A rule matched (`detection`). |
| `detection.context` | detection | One of the session's records that preceded a finding, attached to it (labels `context_for` and others, below). |
| `health.heartbeat` | health | The sensor heartbeat (`health`). |
| `health.error` | health | A sensor error with a closed-vocabulary `health.reason`, for example `outbox.dropped_unshipped`. |
| `session.summary` | summary | The per-session rollup (`summary`). |

## What each profile ships

`privacy.profile` decides what is written for shipping; detection always runs on the full record in memory ([PRIVACY.md](PRIVACY.md)). Per kind: `detection`, `inventory`, `posture`, `health` and `summary` records are written to the outbox in every profile. `activity` records go to the outbox in `standard` and `full`; in `minimal` they go to the local ring, and the last `privacy.context_events` (default 5) records of a session travel with each finding as `detection.context` records. `minimal` and `standard` apply the same field policy to everything they write; `full` applies a wider one, except to detection context, which always gets the standard policy (`labels.context_policy`). Per field (from `internal/privacy`, `fields.go`):

<!-- BEGIN PROFILE FIELDS -->
| Field | `minimal` and `standard` | `full` |
|---|---|---|
| `prompt.text` | never | redacted, capped |
| `prompt.len` | rounded up to a power of four (`labels.len_bucketed`) | exact |
| `prompt.sha256` | keyed digest (HMAC with `privacy.hmac_key_file`) for prompts of at least 32 characters; absent without a key | same |
| `tool.input` | never | redacted (commands structurally), bounded in size and depth |
| `tool.output` | never | redacted, capped |
| `tool.input_keys` | argument names only; long names are redacted | same |
| `tool.input_sha256` | keyed digest or absent, as for `prompt.sha256` | same |
| `tool.output_sha256` | keyed digest or absent | same |
| `tool.output_len` | rounded up to a power of four | exact |
| `target.command` | structurally redacted, then by pattern | same |
| `target.url` | userinfo, query and fragment removed | userinfo removed; query and fragment kept, values of secret-named parameters replaced |
| `target.query` | never (a web search query is prompt-derived) | redacted |
| `session.transcript` | never | never |
| `session.cwd` | paths under the acting user's home become `~/...` | same |
| `target.path` | `~/...` under the home directory | same |
| `process.args` | redacted as an argument vector | same |
| `outcome.error` | redacted, at most 256 bytes | redacted, up to the field cap |
| `account.id` | keyed digest `a_<hex>`, or removed without a key | as reported, pattern-redacted |
| `user.name` | as is; with `privacy.pseudonymize_users`, a keyed pseudonym (removed when no key is configured), also in `user.id`, `process.user`, `asset.owner`, `check.owner` and coverage rows | same |
| `asset.sha256` | for MCP servers, hooks, rules files, subagents, commands and project configs (text a user wrote): keyed digest or removed; other assets keep the binary or package hash | same |
| `asset.mcp.command` | base name of the program | as declared |
| `asset.mcp.args` | redacted as an argument vector | same |
| `detection.evidence` | only allowlisted, non-content fields; a field a rule asks for but may not have reads `[WITHHELD]` | prompt text and tool output may appear, redacted and capped |
| `detection.dedup_key` | re-keyed with the tenant key, removed without one | same |
<!-- END PROFILE FIELDS -->

In every profile, every string field is then passed once more through pattern redaction, invalid UTF-8 is replaced (`labels.lossy: "true"`), each string is capped at 4 KiB and the encoded line at `output.max_line_bytes`. A detected secret's value, or an unkeyed fingerprint of it, is never written: classify's `[REDACTED:<kind>:<fingerprint>]` markers become `[REDACTED:<kind>:hmac=<8 hex digits of a keyed hash>]` with a tenant key and `[REDACTED:<kind>]` without one (as in the activity example below). When a keyed digest or pseudonym was written, `labels.key_id` carries `privacy.key_id`.

## Identity: `id`, `dedupe`, `seq`, `writer`

Delivery is at least once (a Fluent Bit replay, a tail database that was deleted, a shipper retry), and one action can be reported by several surfaces (the hook and the transcript of the same tool call). Records are therefore identified deterministically.

- **`id`** is UUID-shaped and starts with the record time in milliseconds, so ids sort by time. Version 7 ids (third group starts with `7`) are random, for records that have no natural key, such as inventory records made by a scan. Version 8 ids (`8`) are derived (`event.StableID`): the same input gives the same id. Deduplicate deliveries on `id` (the Elasticsearch output in [FLUENT-BIT.md](FLUENT-BIT.md) uses it as the document id).
  - activity: the id the source set is kept (the hook derives it from the tool-call id, or from a keyed digest of its payload; transcript ids come from the log's record ids or a keyed digest of the line), otherwise it is derived from the source, the type and a keyed digest of the record;
  - `detection.finding`: derived from the triggering record's time, the rule id and the triggering record's `dedupe`, so the same finding raised again from a replay, or from the transcript twin of a hook record, has the same id;
  - `detection.context`: derived from the finding's id and the copied record, so context never collides with the activity record itself or with another finding's context (`labels.context_event_id` is the copied record's id);
  - `session.summary` and `health.heartbeat`: derived from the writer and a sequence, so each one is distinct.
- **`dedupe`** (24 hex characters) is identical for every record that describes the same action, whichever surface reported it. For activity it is computed from host id, user id, agent, session id, the natural key and the type; the natural key is the agent's tool-call id for `tool.pre`/`tool.post`, a keyed digest of the prompt text plus its occurrence number in the session for `prompt.submit` (the same text submitted twice is two actions), and the session for `session.start`/`session.end`. The user id is part of it, so two accounts never collapse into one record. The pipeline uses it to write one activity record per action, hook first (a transcript record waits up to 10 s for its hook twin); downstream it groups records of one action.
- **Keys.** Everything in `dedupe` and `id` except content (host, user, agent, session, type, time) is visible in the record, so any part derived from content (the prompt text, the digest behind a derived id) is an HMAC-SHA256 under the pipeline's identity key; an unkeyed hash would let a reader of the logs confirm a guess about a prompt or about a redacted secret. The daemon keeps its key in `<data_dir>/checkpoints/identity.key` (32 random bytes, hex, mode 0600), created on first start, so ids hold across restarts (heartbeat counter `identity.key_stored: 1`). `spoor scan`, `spoor detect` and the hook use a random key per process: ids are deterministic within one run and differ between runs. Details: `go doc ./internal/engine` ("Identity keys").
- **`writer`** is `<mode>-<16 hex>`, random per process start (`daemon-…`, `detect-…`, `scan-…`). **`seq`** is monotonic per writer and stream, starting at 1. A gap in `seq` for one writer and stream is a lost record; a new writer value is a restart. The heartbeat states which sequence numbers it covers (below).
- **`sources`** lists the surfaces that corroborated an activity record before it was written (`["hook","transcript"]`). In the daemon the hook record is usually written within milliseconds and its transcript twin arrives a poll later; a record already handed to the sink is not rewritten, so that corroboration is counted instead: heartbeat `correlate.corroborated_after_write`, and on the session summary `summary.surfaces` plus the labels `corroborated` and `corroborated_after_write` (see the summary example below).

## Time: `ts` and `emitted`

Every time is RFC 3339 in UTC with exactly six fraction digits (`2026-11-12T09:02:56.460197Z`), the form Fluent Bit's strict parser needs; the shipped parser uses `ts` as the event time.

- **`ts`** is when the thing happened, as its source says: the hook's own clock for hook records, the log's timestamp for transcript records, the triggering record's `ts` for a finding, the write time for heartbeats and summaries.
- **`emitted`** is set only when the record was written more than 60 seconds after its `ts`: a laptop that was offline for days, a transcript read late, a replay through `spoor detect`. In [`detect-numbat.ndjson`](schema/examples/detect-numbat.ndjson) the finding has `"ts": "2026-07-24T15:20:00.000000Z"` and `"emitted": "2026-11-12T09:03:47.062120Z"`.

SIEM rules with an event-time lookback window miss late records if they schedule on `ts`: a record that arrives today with yesterday's `ts` falls outside today's window. Schedule and window on `emitted` when it is present (`coalesce(emitted, ts)`), order and correlate on `ts`.

## Integrity, source and fidelity

- **`integrity`**: `root` when a privileged process (the daemon's scan, process monitor) observed it; `user` when the monitored user could have written it. The pipeline forces `user` for every hook, transcript, OTel and adapter record whatever the record claims, and a finding carries the integrity of the record that triggered it. Fleet policies should depend on `root` records only. A spool line can only ever be an activity claim: the daemon refuses spool lines of any other kind and takes user and host from the file owner, not the payload ([ASSUMPTIONS.md](ASSUMPTIONS.md), "Integrity").
- **`source`** is the collection method. Findings, summaries, heartbeats and posture checks are `sensor`; a `detection.context` record keeps the source of the record it copies.
- **`fidelity`**: `observed`, or `inferred` for what the pipeline reconstructed (a synthesized `session.start`, a summary).

## Truncation and skeleton records

- The encoded line, newline included, is capped at `output.max_line_bytes` (default 16 KiB, accepted range 8 KiB to 64 KiB). The cap is on the encoded form because JSON escaping can turn one byte into six. Larger fields are cut, largest first; a cut value ends in a `[TRUNCATED:<n>B]` marker, and every cut field is named in `truncated`. When the sink cuts `target.command` it records the original length in `labels["target.command.len"]`. No hash of the full value is kept.
- If redaction fails, or a record cannot be brought under the cap, a content-free **skeleton** is written instead: the routing fields only, `truncated: ["*"]`, and (from the privacy stage) a label naming the reason, `privacy_error` or `line_cap`. A skeleton's string values may be clipped, so the schema checks only its marker and routing fields (`$defs/Skeleton`). Heartbeat counter `records.linecap_dropped` counts records that could not be written at all.

## Detection records

A `detection.finding` record is a copy of the triggering record (host, user, agent, session, tool, target, process, after the privacy stage) plus `detection`:

- `rule_id`, `title`, `class` (`signal` < `finding` < `alert`), `severity`, `confidence`, `maturity`, `category`, `tags` (ATT&CK, ATLAS and OWASP ids in Sigma style: `attack.t1059.004`, `atlas.aml.t0050`, `owasp.asi05`), `remedy`.
- `evidence`: the fields the rule names, copied from a fixed allowlist of non-content fields (list values as JSON arrays in a string).
- `event_ids`: the records that produced the match, oldest first; for a sequence rule, the chain.
- `response` is what the rule asks for in guard mode (`none`, `ask`, `block`); `enforced` is true only when spoor actually returned that answer to the agent. With guard mode off (the default) `enforced` is absent.
- `count`: how many matches the record stands for after deduplication (repeats inside `rules.suppress_for` are counted, not re-emitted); `dedup_key` groups repeats (written only with a tenant key, see the profile table); `escalate` marks findings worth a second look by a human or an LLM judge.
- Labels stamped on every finding so that a rule change is attributable: `rule_pack`, `rule_pack_version`, `rules_hash` (first 12 hex digits of the rule set's hash), `rules_version` (every loaded `pack@version`), and `bundle_version` when a signed bundle is installed.

Classes below `rules.min_class` (default `finding`) are not written, but still count into the session summary. Rules are documented in [RULES.md](RULES.md).

`detection.context` records carry `labels.context_for` (the finding's `id`), `context_kind`, `context_type` and `context_event_id` (what the copied record was) and `context_policy: standard`. They are routed to the detection stream, so a case is complete in `minimal` without the activity stream.

Inventory rules write `posture.check` records to the posture stream instead: `check.id` is the rule id, `status` is `fail`, `asset_id` names the asset and `actual` shows the facts that matched.

## Session summaries

One `session.summary` per session when it ends (once none of its records is still held for correlation), after 15 minutes of silence, and every 15 minutes while it is active (`final: false`). It carries counts, classes and identifiers, never content: tool calls by kind, distinct hosts contacted through tools, sensitive path classes touched, MCP servers, packages installed, rule ids that fired (signals included), the session flags rules set, the surfaces that reported the session and the resulting coverage. Labels on a final summary: `end_reason`, one of `session_end`, `idle` (no end was seen), `evicted` (the in-memory session table was full), `close` (the process stopped, for example `spoor detect` at the end of its input; on shutdown the daemon writes a non-final summary instead, since a restart does not end anyone's session) or `late_records` (records arrived after the final summary, and this one supersedes it). On any summary: `corroborated`, `corroborated_after_write`, and `activity_suppressed` when the activity rate limit dropped records.

## Heartbeat

The daemon writes a `health.heartbeat` every `heartbeat` (default 5 minutes, minimum 10 s). It is content-free: counters, surface states, per-agent coverage, rule and catalog versions.

- `health.mode` (`daemon` for the daemon), `sensor_version`, `uptime_s`, `rules_count`, `rules_hash` (full SHA-256 of the rule set), `catalog_version`.
- `health.surfaces`: per collector, `status` (`ok`, `degraded`, `failed`, `disabled`), `last_event` (the arrival time of its last record, not a time the record claims), `events`, `errors`, `schema_drift`, `reason`.
- `health.coverage`: per (agent, user), the hook and transcript state, running processes and `state`: `covered`, `partial`, `blind` or `absent`. Rows that do not fit the line are counted (`coverage.rows_omitted`, `truncated: ["health.coverage"]`); the state database gets every row.
- Labels: `profile`, `status` (`ok`, or `disabled` while the kill switch is on: then the surfaces read `disabled` with reason `kill_switch` and the heartbeat is not written to the state database, so Fleet's freshness policy fails), `rules_version`, `bundle_version` when a bundle is installed, `host_id_source`, `last_error`.

### Per-stream accounting

For every stream written since the previous heartbeat, the counters hold `stream.<stream>.emitted`, `.dropped`, `.truncated`, `.first_seq` and `.last_seq`. The interval restarts at each heartbeat, and a heartbeat's own record belongs to the next interval. A consumer checks completeness per writer and stream: every `seq` from `first_seq` to `last_seq` must have arrived, and `emitted` must equal their count. From [`standard.ndjson`](schema/examples/standard.ndjson) (one writer):

| Heartbeat `seq` | Stream counters it reports |
|---|---|
| 1 | none (nothing was written before it) |
| 2 | activity 9 emitted, seq 1-9; detection 17, seq 1-17; inventory 2, seq 1-2; posture 4, seq 1-4; health 1, seq 1-1 (heartbeat 1) |
| 3 | summary 1, seq 1-1; health 1, seq 2-2 |
| 4 | health 1, seq 3-3 |

### Counters

The other counters are totals since the process started, under stable names (dashboards and the state database read them). The groups written by the pipeline (`internal/engine`, `health.go`):

| Counters | Meaning |
|---|---|
| `events_in`, `events_out`, `dropped`, `detections`, `errors` | headline totals (the state database's health table reads these) |
| `ingest.processed`, `.excluded`, `.malformed`, `.queue_dropped`, `.disabled_dropped`, `.closed_dropped`, `.unknown_vocab` | records taken in, excluded by `privacy.exclude`, refused, or dropped (full queue, kill switch, shutdown) |
| `correlate.*` | cross-surface correlation: held, released, matched, duplicates, late hooks, corroborated, corroborated after write, OTel attribution |
| `coverage.*` | coverage rows by state, hook-bypass findings and signals, unknown agents, untrusted process records |
| `detections.below_min_class`, `detections.context` | findings not written because of `rules.min_class`; context records written |
| `records.late`, `.withheld`, `.emit_refused`, `.linecap_dropped`, `.secret_flow_scrubbed` | records that got `emitted`; evidence withheld; records refused by the privacy stage, too large to write, or reduced to a skeleton after secret flow |
| `outbox.write_errors`, `outbox.dropped`, `local.written`, `local.dropped`, `local.discarded`, `local.write_errors` | sink results |
| `state.applied`, `state.errors`, `baseline.*`, `identity.key_stored`, `identity.key_errors` | state database batches, first-seen baseline, identity key |
| `session.summaries`, `session.synthesized_start`, `activity.suppressed` | summaries written, inferred session starts, activity dropped by the rate limit |
| `engine.*`, `rules.*` | pipeline queues, panics and rule timeouts; the rules engine's own statistics (evaluations, matches, per-rule time in `rules.rule_ns.<id>`) |

The daemon adds its own gauges in the same map (in the examples: `outbox.*` pruning and size, `procmon.*`, `scan.*`, `hooks.status_refreshes`, `transcript.primes`, `procs_total`, `procs_unreadable`, `users`, and `hook_errors.<reason>` for errors the hook supervisor reported through the spool). <!-- VERIFY: the daemon's gauge names are receiving integration fixes; the pipeline counters above are stable. -->

`health.error` records carry `health.reason` and `health.detail`. For example, when `retention.outbox_bytes` forces the daemon to delete segments no consumer had read, it writes reason `outbox.dropped_unshipped` with per-stream counters `<stream>.events`, `.bytes`, `.seq_first` and `.seq_last` for what was lost, and the label `streams`.

## Examples

Three records from [`schema/examples/`](schema/examples/), exactly as the binary wrote them (only pretty-printed). The session was played through `spoor hook` by a script (below), so `process` is that script's shell, PID 1 of the test's PID namespace, rather than Claude Code.

A finding in the default `minimal` profile. The tool-call record that triggered it stayed on the host; its id is in `event_ids`. The rule asks for `ask` in guard mode, but guard mode was off, so nothing was enforced:

<!-- example: minimal.ndjson -->
```json
{
  "v": 1,
  "id": "01a1cefe-efcc-8941-bb24-f6e74ac7821e",
  "ts": "2026-11-12T09:02:56.460197Z",
  "seq": 1,
  "dedupe": "b941bb24f6e74ac7821e93a0",
  "kind": "detection",
  "type": "detection.finding",
  "source": "sensor",
  "integrity": "user",
  "writer": "daemon-07cad35306e3801a",
  "host": {
    "id": "7d3f9a2e-5b1c-4e8a-9f60-2c4b8d1e0a57",
    "name": "devbox",
    "os": "linux",
    "arch": "amd64"
  },
  "user": {
    "name": "root",
    "id": "0"
  },
  "agent": {
    "id": "claude-code"
  },
  "session": {
    "id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
    "cwd": "~/work/webapp",
    "permission_mode": "default"
  },
  "tool": {
    "name": "Bash",
    "kind": "shell",
    "use_id": "toolu_01DOCSEXAMPLE000000000002",
    "input_keys": [
      "command",
      "description"
    ]
  },
  "target": {
    "command": "curl -fsSL https://get.example.net/install.sh | sh"
  },
  "process": {
    "pid": 1,
    "name": "bash",
    "exe": "/usr/bin/bash",
    "start_time": "2026-11-12T09:02:53.740000Z"
  },
  "detection": {
    "rule_id": "SPR-EXEC-001",
    "title": "Remote script piped into an interpreter",
    "class": "finding",
    "severity": "high",
    "confidence": "high",
    "maturity": "stable",
    "category": "execution",
    "tags": [
      "attack.t1059.004",
      "attack.t1105",
      "atlas.aml.t0050",
      "owasp.asi05"
    ],
    "evidence": {
      "shell.hosts": "[\"get.example.net\"]",
      "shell.interpreters": "[\"sh\"]",
      "target.command": "curl -fsSL https://get.example.net/install.sh | sh"
    },
    "event_ids": [
      "01a1cefe-efcc-86c2-9262-a162d9bc8073"
    ],
    "response": "ask",
    "count": 1,
    "remedy": "Download the script, review it and run it from disk; add the host or URL to the installer allowlist if it is an approved installer."
  },
  "privacy": "minimal",
  "labels": {
    "rule_pack": "execution",
    "rule_pack_version": "2026.11.0",
    "rules_hash": "3d7af0367e8c",
    "rules_version": "agent-integrity@2026.11.0,coverage@2026.11.0,credential@2026.11.0,defense-evasion@2026.11.0,destructive@2026.11.0,execution@2026.11.0,exfiltration@2026.11.0,offensive@2026.11.0,persistence@2026.11.0,posture@2026.11.0,process@2026.11.0,sequence@2026.11.0,supply-chain@2026.11.0"
  }
}
```

An activity record in the `standard` profile. The hook received `curl -u deploy:<password> -T dist/app.tgz https://artifacts.example.net/upload/`; the password is replaced structurally (`-u` takes `user:password`), the description argument is reduced to its name in `input_keys`, and `first_seen` says the pipeline's baseline had not seen this host for this user before:

<!-- example: standard.ndjson -->
```json
{
  "v": 1,
  "id": "01a1ceff-5727-8084-b86a-028267aa6479",
  "ts": "2026-11-12T09:03:22.919278Z",
  "seq": 7,
  "dedupe": "ff6aba2facbf112073412840",
  "kind": "activity",
  "type": "tool.pre",
  "source": "hook",
  "fidelity": "observed",
  "integrity": "user",
  "writer": "daemon-bf0d954061cdfb6c",
  "host": {
    "id": "7d3f9a2e-5b1c-4e8a-9f60-2c4b8d1e0a57",
    "name": "devbox",
    "os": "linux",
    "arch": "amd64"
  },
  "user": {
    "name": "root",
    "id": "0"
  },
  "agent": {
    "id": "claude-code"
  },
  "session": {
    "id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
    "cwd": "~/work/webapp",
    "permission_mode": "default"
  },
  "tool": {
    "name": "Bash",
    "kind": "shell",
    "use_id": "toolu_01DOCSEXAMPLE000000000004",
    "input_keys": [
      "command",
      "description"
    ]
  },
  "target": {
    "command": "curl -u deploy:[REDACTED:password] -T dist/app.tgz https://artifacts.example.net/upload/"
  },
  "process": {
    "pid": 1,
    "name": "bash",
    "exe": "/usr/bin/bash",
    "start_time": "2026-11-12T09:03:20.170000Z"
  },
  "privacy": "standard",
  "labels": {
    "first_seen": "net.host",
    "hook_event": "PreToolUse",
    "hook_mode": "observe"
  }
}
```

The final summary of the same session in `minimal`. The hook and the transcript both reported it (`surfaces`); the three tool calls the transcript confirmed after their hook records were written are counted in the labels:

<!-- example: minimal.ndjson -->
```json
{
  "v": 1,
  "id": "01a1ceff-19e9-892f-9967-97b22b140655",
  "ts": "2026-11-12T09:03:07.241721Z",
  "seq": 1,
  "dedupe": "3842e62dd7bbcfde6cdb23af",
  "kind": "summary",
  "type": "session.summary",
  "source": "sensor",
  "fidelity": "inferred",
  "integrity": "user",
  "writer": "daemon-07cad35306e3801a",
  "host": {
    "id": "7d3f9a2e-5b1c-4e8a-9f60-2c4b8d1e0a57",
    "name": "devbox",
    "os": "linux",
    "arch": "amd64"
  },
  "user": {
    "name": "root",
    "id": "0"
  },
  "agent": {
    "id": "claude-code"
  },
  "session": {
    "id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
    "cwd": "~/work/webapp",
    "permission_mode": "default",
    "model": "claude-opus-5"
  },
  "summary": {
    "started": "2026-11-12T09:02:56.377587Z",
    "ended": "2026-11-12T09:02:56.515367Z",
    "final": true,
    "events": 9,
    "prompts": 1,
    "tool_calls": {
      "file_read": 1,
      "shell": 3
    },
    "hosts": [
      "get.example.net",
      "artifacts.example.net"
    ],
    "path_classes": [
      "cloud_credentials",
      "token_file"
    ],
    "detections": [
      "SPR-EXEC-001",
      "SPR-CRED-002",
      "SPR-EXFIL-005"
    ],
    "max_severity": "high",
    "flags": [
      "credential_source_read",
      "secret_read"
    ],
    "surfaces": [
      "hook",
      "transcript"
    ],
    "coverage": "covered"
  },
  "privacy": "minimal",
  "labels": {
    "corroborated": "3",
    "corroborated_after_write": "3",
    "end_reason": "session_end"
  }
}
```

The example files hold every other record of the same runs: the detection context of each finding, inventory and posture records from the scan, the heartbeats, and the `standard` run's activity stream.

### How the examples were made

[`schema/examples/regen.sh`](schema/examples/regen.sh) builds the binary and, for the `minimal` and `standard` profiles, starts `spoor run` with a temporary data directory, plays one Claude Code session (session start, a prompt, four tool calls, stop, session end) through `spoor hook` with the payload shapes Claude Code sends, writes that session's transcript, waits for a heartbeat and the final summary, stops the daemon and keeps every outbox line. It runs the daemon in private mount, PID and UTS namespaces with empty `/root` and `/home`, so the host's real agent sessions and processes cannot appear; the host name is `devbox` and `host_id` is set in the run's configuration. It also runs `spoor detect` over the numbat fixtures in `internal/adapter/testdata` (`detect-numbat.ndjson`). It needs Linux, root, Go, jq and unshare:

```
sudo docs/schema/examples/regen.sh
```

After regenerating, update the quoted examples above (the test requires each to be a line of the named file) and run `go test ./internal/event`.

## The schema

`docs/schema/event.schema.json` is generated from the Go types (field names, JSON tags, which fields are always written) and from the package's source (doc comments and the constants of every closed vocabulary):

```
go test ./internal/event -run TestSchema -update
```

What it enforces: JSON types; required fields (those the encoder always writes); `additionalProperties: false` on every object whose Go type is a struct (open maps are only `labels`, `asset.detail`, `detection.evidence`, `health.counters`, `summary.tool_calls` and `tool.input`); the closed vocabularies declared as constants in `internal/event` plus `detection.context` from `internal/privacy` (kind, type, source, fidelity, integrity, tool kind, asset kind, scope, change, detection class, severity); `v` equal to 1; the time format. Values described only in a field comment (for example `outcome.status`, `coverage.state`) are documented below but not enforced. The test also validates every example line, checks the validator rejects records with an unknown field, a value outside a vocabulary, a missing required field or a malformed time, and fails when the committed schema or the field reference below differs from what the code generates.

`v` is the schema version. It changes only on a breaking change; new optional fields are not breaking, so consumers should ignore fields they do not know rather than reject the record.

## Field reference

<!-- BEGIN GENERATED: field reference (go test ./internal/event -run TestSchema -update) -->

Generated from the Go types in `internal/event` and their doc comments. "always" fields are written on every record of that object (an empty string or zero when unset); the others are left out when empty.

### `Event` object

Event is the normalized record.

| Field | Type | Present | Description |
|---|---|---|---|
| `v` | integer | always | Schema version, 1 (SchemaVersion). Bumped only on breaking changes; adding optional fields is not breaking. |
| `id` | string | always |  |
| `ts` | [`Time`](#time-string) | always |  |
| `emitted` | [`Time`](#time-string) | when set | Emitted is when the record was written for shipping, set only when that is more than a minute after TS (a laptop that was offline, a backfilled transcript). Rules with event-time lookback windows can schedule on it. |
| `seq` | integer ≥ 0 | when set | monotonic per (Writer, stream), for gap detection downstream |
| `dedupe` | string | when set | Dedupe is identical for every record that describes the same action, whichever surface reported it (see DedupeKey). |
| `kind` | [`Kind`](#kind-values) | always |  |
| `type` | [`EventType`](#eventtype-values) | always |  |
| `source` | [`Source`](#source-values) | always |  |
| `fidelity` | [`Fidelity`](#fidelity-values) | when set |  |
| `sources` | array of [`Source`](#source-values) | when set | Sources lists every surface that corroborated this event after cross-surface correlation (for example ["hook","transcript"]). |
| `integrity` | [`Integrity`](#integrity-values) | when set |  |
| `writer` | string | when set | Writer identifies the process that wrote the record (random per process start). Seq is monotonic per Writer, and heartbeats report per-writer counts, so a consumer can prove that nothing was lost or removed. |
| `host` | [`Host`](#host-object) | when set |  |
| `user` | [`User`](#user-object) | when set |  |
| `agent` | [`Agent`](#agent-object) | when set |  |
| `account` | [`Account`](#account-object) | when set |  |
| `session` | [`Session`](#session-object) | when set |  |
| `tool` | [`Tool`](#tool-object) | when set |  |
| `target` | [`Target`](#target-object) | when set |  |
| `prompt` | [`Prompt`](#prompt-object) | when set |  |
| `outcome` | [`Outcome`](#outcome-object) | when set |  |
| `process` | [`Process`](#process-object) | when set |  |
| `container` | [`Container`](#container-object) | when set |  |
| `repo` | [`Repo`](#repo-object) | when set |  |
| `asset` | [`Asset`](#asset-object) | when set | Kind == inventory |
| `check` | [`Check`](#check-object) | when set | Kind == posture |
| `detection` | [`Detection`](#detection-object) | when set | Kind == detection |
| `health` | [`Health`](#health-object) | when set | Kind == health |
| `summary` | [`Summary`](#summary-object) | when set | Kind == summary |
| `privacy` | string | when set | Privacy is the tier that was applied when the record was emitted. |
| `truncated` | array of string | when set | Truncated names fields whose values were cut, so truncation is never silent; the cut value itself ends in an "[TRUNCATED:&lt;n&gt;B]" marker (when a sink cuts target.command to fit its line cap it records the full length in Labels["target.command.len"] instead). No hash of the full value is kept: an unkeyed one would let a reader confirm guesses about the missing text. |
| `labels` | object of string | when set |  |

### `Host` object

Host identifies the endpoint. ID should equal osquery's system_info.uuid so events join to Fleet hosts.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set |  |
| `name` | string | when set |  |
| `os` | string | when set | linux \| darwin \| windows |
| `arch` | string | when set | amd64 \| arm64 |

### `User` object

User is the OS account the agent runs as.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | when set |  |
| `id` | string | when set | uid on POSIX, SID on Windows |

### `Agent` object

Agent identifies the AI agent product.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | always | catalog id, e.g. "claude-code" |
| `name` | string | when set |  |
| `version` | string | when set |  |
| `pid` | integer | when set |  |
| `surface` | string | when set | Surface is how the agent was run: cli \| ide \| desktop \| sdk \| ci \| cloud. |

### `Account` object

Account is the identity the agent is signed in with, when a surface reports it (vendor OpenTelemetry does; hooks usually do not). It answers the first governance question: corporate tenant, personal account or a raw API key on a managed machine.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set | ID is the vendor account identifier; emitted as a keyed digest unless the privacy profile is full. |
| `org` | string | when set |  |
| `kind` | string | when set | Kind: organization \| personal \| api_key \| unknown. |

### `Session` object

Session identifies one agent conversation.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set |  |
| `parent_id` | string | when set | parent session for subagents |
| `turn_id` | string | when set |  |
| `cwd` | string | when set |  |
| `permission_mode` | string | when set | PermissionMode is the agent's own vocabulary, normalized to: default \| plan \| accept_edits \| auto \| dont_ask \| bypass. |
| `model` | string | when set |  |
| `transcript` | string | when set | path of the session log, when known |
| `subagent_id` | string | when set |  |
| `subagent_type` | string | when set |  |

### `Tool` object

Tool describes the tool call.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | when set | agent's own tool name, e.g. "Bash" |
| `kind` | [`ToolKind`](#toolkind-values) | when set |  |
| `use_id` | string | when set | agent's tool-call id; join key across surfaces |
| `mcp_server` | string | when set | for Kind == mcp |
| `mcp_tool` | string | when set |  |
| `input_sha256` | string | when set | InputSHA256 is the hash of the canonical JSON of the tool input, so identical calls correlate without shipping content. |
| `input_keys` | array of string | when set | InputKeys lists top-level argument names (metadata tier). |
| `input` | object (any JSON) | when set | Input is the redacted tool input; present only in tiers redacted/full. |
| `output` | string | when set | Output is the redacted, truncated tool output; tiers redacted/full only. |
| `output_sha256` | string | when set |  |
| `output_len` | integer | when set |  |

### `Target` object

Target is what the tool call acts on, extracted and normalized.

| Field | Type | Present | Description |
|---|---|---|---|
| `command` | string | when set | shell command line, secrets redacted |
| `path` | string | when set | primary file path |
| `paths` | array of string | when set | additional paths referenced |
| `url` | string | when set | userinfo, query and fragment stripped unless tier is full |
| `host` | string | when set | network host |
| `hosts` | array of string | when set |  |
| `query` | string | when set | web search query; tiers redacted/full only |

### `Prompt` object

Prompt summarizes a user prompt without necessarily carrying it.

| Field | Type | Present | Description |
|---|---|---|---|
| `len` | integer | always |  |
| `sha256` | string | when set | keyed hash when a tenant key is configured |
| `text` | string | when set | tiers redacted/full only |

### `Outcome` object

Outcome is the result of a tool call or turn.

| Field | Type | Present | Description |
|---|---|---|---|
| `status` | string | when set | Status: ok \| error \| denied \| interrupted \| unknown. |
| `error` | string | when set |  |
| `duration_ms` | integer | when set |  |
| `exit_code` | integer | when set |  |
| `decision` | string | when set | Decision: allow \| deny \| ask, when a permission decision was observed. |
| `decision_source` | string | when set | user \| policy \| hook \| spoor |

### `Process` object

Process describes an OS process.

| Field | Type | Present | Description |
|---|---|---|---|
| `pid` | integer | when set |  |
| `ppid` | integer | when set |  |
| `name` | string | when set |  |
| `exe` | string | when set |  |
| `args` | array of string | when set | secrets redacted |
| `start_time` | [`Time`](#time-string) | when set |  |
| `user` | string | when set |  |
| `ancestors` | array of string | when set | Ancestors is the chain of process names from parent to root. |
| `env_markers` | array of string | when set | EnvMarkers are agent marker variable NAMES found in the environment (values are never emitted except session ids copied into Session). |
| `flags` | array of string | when set | Flags are risky argv flags recognized by the catalog, e.g. "--dangerously-skip-permissions". |

### `Container` object

Container locates the workload when the agent runs in a container.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set |  |
| `runtime` | string | when set | docker \| containerd \| cri-o \| podman |
| `image` | string | when set |  |
| `name` | string | when set |  |
| `pod` | string | when set |  |
| `pod_uid` | string | when set |  |
| `namespace` | string | when set |  |
| `node` | string | when set |  |

### `Repo` object

Repo describes the source repository of the session's working directory.

| Field | Type | Present | Description |
|---|---|---|---|
| `root` | string | when set |  |
| `remote` | string | when set | credentials stripped |
| `branch` | string | when set |  |

### `Asset` object

Asset is one inventory record. ID is stable across scans for the same (host, kind, identity, owner, location) so downstream can upsert.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | always |  |
| `kind` | [`AssetKind`](#assetkind-values) | always |  |
| `name` | string | always |  |
| `vendor` | string | when set |  |
| `version` | string | when set |  |
| `catalog_id` | string | when set | CatalogID is the catalog entry that identified the asset ("" when unknown). |
| `parent` | string | when set | Parent is the catalog id of the agent that owns this item (an MCP server declared in Cursor's config has Parent "cursor"). |
| `path` | string | when set | install path or declaring file |
| `scope` | [`Scope`](#scope-values) | when set | for declared items |
| `owner` | string | when set | OS user the item belongs to |
| `running` | boolean | when set |  |
| `pid` | integer | when set |  |
| `sha256` | string | when set | SHA256 is the content hash: binary hash for agents, definition hash for MCP servers and hooks, folder hash for skills. |
| `evidence` | array of string | when set | Evidence lists how identity was established, e.g. "package:npm", "bundle_id", "path", "process", "signature". Two independent classes are required for Confidence "high". |
| `confidence` | string | when set | high \| medium \| low |
| `signer` | string | when set | Signer is the code-signing identity when verified (team id / publisher). |
| `first_seen` | [`Time`](#time-string) | when set |  |
| `last_seen` | [`Time`](#time-string) | when set |  |
| `change` | [`Change`](#change-values) | when set |  |
| `risk_flags` | array of string | when set | RiskFlags are closed-vocabulary posture hints computed at scan time. |
| `mcp` | [`MCP`](#mcp-object) | when set |  |
| `telemetry` | [`Telemetry`](#telemetry-object) | when set | Telemetry describes how well spoor can see this agent (agents only). |
| `detail` | object of string | when set |  |

### `MCP` object

MCP holds normalized launch facts for a declared MCP server, so a central team can hunt for a bad package or endpoint across the fleet.

| Field | Type | Present | Description |
|---|---|---|---|
| `transport` | string | when set | stdio \| http \| sse \| ws |
| `command` | string | when set | executable as declared (basename unless tier is full) |
| `args` | array of string | when set | secrets redacted |
| `runner` | string | when set | Runner is the package launcher when one is used: npx \| bunx \| uvx \| pipx \| pip \| docker \| podman \| node \| python \| deno \| binary. |
| `ecosystem` | string | when set | npm \| pypi \| oci \| "" |
| `package` | string | when set |  |
| `version` | string | when set |  |
| `pinned` | boolean | always | Pinned is true only for an exact version or an image digest. |
| `url_host` | string | when set |  |
| `url_path` | string | when set |  |
| `env_keys` | array of string | when set | names only, never values |
| `header_keys` | array of string | when set |  |
| `has_inline_secret` | boolean | when set |  |
| `auth_mode` | string | when set | none \| env \| header \| oauth \| inherited |
| `enabled` | boolean | when set |  |

### `Telemetry` object

Telemetry is per-agent coverage state: which surfaces spoor has.

| Field | Type | Present | Description |
|---|---|---|---|
| `hooks` | string | when set | Hooks: managed \| user \| missing \| modified \| unsupported \| disabled. |
| `transcript` | string | when set | Transcript: tailing \| found \| none \| relocated \| disabled. |
| `native_otel` | string | when set | NativeOTel: enabled \| disabled \| unsupported. |

### `Check` object

Check is one posture check result.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | always | rule id of the posture rule |
| `title` | string | when set |  |
| `status` | string | always | pass \| fail \| unknown |
| `severity` | [`Severity`](#severity-values) | when set |  |
| `agent_id` | string | when set |  |
| `asset_id` | string | when set |  |
| `scope` | [`Scope`](#scope-values) | when set |  |
| `subject` | string | when set | file path or setting key checked |
| `expected` | string | when set |  |
| `actual` | string | when set |  |
| `owner` | string | when set |  |
| `remedy` | string | when set |  |

### `Detection` object

Detection is a rule match.

| Field | Type | Present | Description |
|---|---|---|---|
| `rule_id` | string | always |  |
| `title` | string | always |  |
| `class` | [`DetectionClass`](#detectionclass-values) | when set | Class is how much attention the match deserves: "signal" (counted into the session summary, not shipped by default), "finding" (shipped, no page) or "alert" (expected to be silent on ordinary developer work). |
| `severity` | [`Severity`](#severity-values) | always |  |
| `confidence` | string | when set | low \| medium \| high |
| `maturity` | string | when set | experimental \| stable |
| `category` | string | when set |  |
| `tags` | array of string | when set | Tags carries framework mappings in Sigma tag style: attack.t1059.004, atlas.aml.t0051, owasp.asi05. |
| `evidence` | object of string | when set | Evidence is a small redacted map of the field values that matched. |
| `event_ids` | array of string | when set | EventIDs are the ids of the events that produced the match, oldest first; for sequence rules this is the chain. |
| `flags` | array of string | when set | Flags are the session flags that were required and present. |
| `response` | string | when set | Response is what the rule asks for (none \| ask \| block); Enforced says whether spoor actually returned that decision to the agent. |
| `enforced` | boolean | when set |  |
| `dedup_key` | string | when set | DedupKey groups repeats of the same finding; Count is how many matches this record stands for after suppression. |
| `count` | integer | when set |  |
| `escalate` | boolean | when set | Escalate marks findings that are suspicious but not conclusive and are good candidates for a downstream LLM or human judge. |
| `remedy` | string | when set |  |

### `Health` object

Health is the sensor heartbeat. It is deliberately content-free.

| Field | Type | Present | Description |
|---|---|---|---|
| `sensor_version` | string | always |  |
| `mode` | string | always | Mode: daemon \| extension \| hook \| scan. |
| `uptime_s` | integer | when set |  |
| `counters` | object of integer ≥ 0 | when set |  |
| `surfaces` | array of [`SurfaceStatus`](#surfacestatus-object) | when set |  |
| `coverage` | array of [`Coverage`](#coverage-object) | when set |  |
| `rules_count` | integer | when set |  |
| `rules_hash` | string | when set |  |
| `catalog_version` | string | when set |  |
| `last_scan` | [`Time`](#time-string) | when set |  |
| `reason` | string | when set | Reason is a closed-vocabulary code for health.error records. |
| `detail` | string | when set |  |

### `SurfaceStatus` object

SurfaceStatus reports one collector.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | always | hooks \| transcripts \| processes \| scan |
| `status` | string | always | Status: ok \| degraded \| failed \| disabled. |
| `last_event` | [`Time`](#time-string) | when set |  |
| `events` | integer ≥ 0 | when set |  |
| `errors` | integer ≥ 0 | when set |  |
| `schema_drift` | boolean | when set |  |
| `reason` | string | when set |  |

### `Coverage` object

Coverage is the per-agent, per-user visibility statement: which surfaces are actually delivering. "Not collected" must never read as "clean".

| Field | Type | Present | Description |
|---|---|---|---|
| `agent_id` | string | always |  |
| `user` | string | when set |  |
| `hooks` | string | when set | see Telemetry.Hooks |
| `transcript` | string | when set | see Telemetry.Transcript |
| `processes` | integer | when set | running agent processes seen |
| `state` | string | always | State: covered \| partial \| blind \| absent. |

### `Summary` object

Summary is the per-session rollup: enough to answer fleet-wide questions ("which hosts called MCP server X", "which sessions loaded skill hash Y") from a small indexed stream while raw activity stays local or in cold storage. It carries counts, classes and identifiers, never content.

| Field | Type | Present | Description |
|---|---|---|---|
| `started` | [`Time`](#time-string) | when set |  |
| `ended` | [`Time`](#time-string) | when set |  |
| `final` | boolean | when set | true when the session ended; false for periodic rollups |
| `events` | integer | always |  |
| `prompts` | integer | when set |  |
| `subagents` | integer | when set |  |
| `tool_calls` | object of integer | when set | ToolCalls counts tool calls by normalized kind. |
| `hosts` | array of string | when set | Hosts are distinct network hosts contacted through tools (capped). |
| `host_classes` | array of string | when set |  |
| `path_classes` | array of string | when set | PathClasses are the distinct sensitive path classes touched. |
| `mcp_servers` | array of string | when set |  |
| `installs` | array of string | when set | Installs are packages installed by the agent as "manager:name". |
| `detections` | array of string | when set | rule ids |
| `max_severity` | [`Severity`](#severity-values) | when set |  |
| `flags` | array of string | when set | session flags set by rules |
| `surfaces` | array of [`Source`](#source-values) | when set | Surfaces that reported this session and the resulting coverage state (covered \| partial \| blind). |
| `coverage` | string | when set |  |
| `denied` | integer | when set | tool calls denied by user, policy or guard |
| `blocked` | integer | when set | tool calls blocked by spoor guard mode |

### `Time` string

RFC 3339 in UTC with exactly six fraction digits, for example `2026-11-12T09:02:56.460197Z` (`TimeLayout`; Fluent Bit's strict parser needs the fraction). Optional time fields are left out when unset.

### `Kind` values

Kind is the top-level class of a record and selects the output stream.

| Value | Constant | Meaning |
|---|---|---|
| `activity` | `KindActivity` | something an agent did or was asked to do |
| `inventory` | `KindInventory` | an asset that exists on the endpoint |
| `posture` | `KindPosture` | the result of a configuration check |
| `detection` | `KindDetection` | a rule matched |
| `health` | `KindHealth` | sensor heartbeat, coverage and errors |
| `summary` | `KindSummary` | per-session rollup, small enough to index centrally |

### `EventType` values

Event.Type: the activity types (Kind activity) and the types of the other kinds. detection.context is declared in internal/privacy.

| Value | Constant | Meaning |
|---|---|---|
| `session.start` | `TypeSessionStart` |  |
| `session.end` | `TypeSessionEnd` |  |
| `prompt.submit` | `TypePromptSubmit` |  |
| `tool.pre` | `TypeToolPre` | before execution; the only type guard mode can block |
| `tool.post` | `TypeToolPost` | after execution, success or failure (see Outcome) |
| `turn.end` | `TypeTurnEnd` |  |
| `subagent.start` | `TypeSubagentStart` |  |
| `subagent.stop` | `TypeSubagentStop` |  |
| `permission.decision` | `TypePermissionDecision` |  |
| `config.change` | `TypeConfigChange` |  |
| `notification` | `TypeNotification` |  |
| `context.compact` | `TypeCompact` |  |
| `agent.process.start` | `TypeAgentProcessStart` |  |
| `agent.process.stop` | `TypeAgentProcessStop` |  |
| `process.exec` | `TypeProcessExec` | child process attributed to an agent session |
| `hook.payload_anomaly` | `TypePayloadAnomaly` | TypePayloadAnomaly is written by the hook when a payload could not be read as an agent event (empty, malformed, too large, too deep): size and a digest of the raw bytes instead of nothing, so padding a payload past the caps is visible rather than an evasion. |
| `inventory.asset` | `TypeInventoryAsset` |  |
| `posture.check` | `TypePostureCheck` |  |
| `detection.finding` | `TypeDetectionFinding` |  |
| `health.heartbeat` | `TypeHealthHeartbeat` |  |
| `health.error` | `TypeHealthError` |  |
| `session.summary` | `TypeSessionSummary` |  |
| `detection.context` | `privacy.TypeContext` |  |

### `Source` values

Source is the collection method that produced a record.

| Value | Constant | Meaning |
|---|---|---|
| `hook` | `SourceHook` | agent hook invoked spoor (real time, self-reported by the agent) |
| `transcript` | `SourceTranscript` | parsed from the agent's on-disk session log |
| `process` | `SourceProcess` | observed from the OS process table |
| `scan` | `SourceScan` | discovery / posture scan of files and packages |
| `otel` | `SourceOTel` | agent-native OpenTelemetry received locally |
| `osquery` | `SourceOsquery` | rows from osquery evented tables read from its local results log |
| `adapter` | `SourceAdapter` | records converted from another sensor's output |
| `sensor` | `SourceSensor` | produced by spoor itself (detections, health, correlation) |

### `Fidelity` values

Fidelity says whether the record was directly observed or reconstructed.

| Value | Constant | Meaning |
|---|---|---|
| `observed` | `FidelityObserved` |  |
| `inferred` | `FidelityInferred` |  |

### `Integrity` values

Integrity says who could have altered a record before it was written. Hooks run as the monitored user, so their records are advisory until a privileged collector corroborates them; anything a Fleet policy depends on must be root-integrity.

| Value | Constant | Meaning |
|---|---|---|
| `root` | `IntegrityRoot` | written by a privileged scan or daemon |
| `user` | `IntegrityUser` | written by an unprivileged process the monitored user controls |

### `ToolKind` values

ToolKind is the cross-agent normalized class of a tool call.

| Value | Constant | Meaning |
|---|---|---|
| `shell` | `ToolShell` |  |
| `file_read` | `ToolFileRead` |  |
| `file_write` | `ToolFileWrite` | create or overwrite |
| `file_edit` | `ToolFileEdit` | in-place modification |
| `file_list` | `ToolFileList` | glob, grep, ls style discovery |
| `web_fetch` | `ToolWebFetch` |  |
| `web_search` | `ToolWebSearch` |  |
| `mcp` | `ToolMCP` |  |
| `subagent` | `ToolSubagent` |  |
| `browser` | `ToolBrowser` |  |
| `other` | `ToolOther` |  |

### `AssetKind` values

AssetKind classifies an inventory record.

| Value | Constant | Meaning |
|---|---|---|
| `agent` | `AssetAgent` | CLI or headless coding agent |
| `app` | `AssetApp` | desktop AI app or AI IDE |
| `ide_extension` | `AssetIDEExtension` | VS Code / JetBrains AI extension |
| `ai_browser` | `AssetBrowser` | agentic browser |
| `browser_extension` | `AssetBrowserExtension` | AI browser extension |
| `model_runtime` | `AssetModelRuntime` | Ollama, LM Studio, llama.cpp ... |
| `mcp_server` | `AssetMCPServer` | declared in a client config |
| `skill` | `AssetSkill` |  |
| `plugin` | `AssetPlugin` |  |
| `hook` | `AssetHook` | hook definition in an agent config |
| `rules_file` | `AssetRulesFile` | CLAUDE.md, AGENTS.md, .cursor/rules ... |
| `subagent` | `AssetSubagent` |  |
| `command` | `AssetCommand` | slash command / prompt file |
| `ci_agent` | `AssetCIAgent` |  |
| `project_config` | `AssetProjectConfig` | AssetProjectConfig is a repository-local file that can make an agent or IDE run something when the folder is opened (settings with hooks, rules that always apply, auto-run tasks, .git/config exec keys). |

### `Scope` values

Scope is where a configuration item is declared.

| Value | Constant | Meaning |
|---|---|---|
| `managed` | `ScopeManaged` | admin-controlled tier (MDM, system policy path) |
| `system` | `ScopeSystem` | machine-wide but not policy |
| `user` | `ScopeUser` |  |
| `project` | `ScopeProject` |  |
| `plugin` | `ScopePlugin` | contributed by a plugin or extension |

### `Change` values

Change describes how an asset differs from the previous scan.

| Value | Constant | Meaning |
|---|---|---|
| `new` | `ChangeNew` |  |
| `changed` | `ChangeChanged` |  |
| `removed` | `ChangeRemoved` |  |
| `unchanged` | `ChangeUnchanged` |  |

### `Severity` values

Severity levels, lowest to highest (SeverityRank).

| Value | Constant | Meaning |
|---|---|---|
| `info` | `SevInfo` |  |
| `low` | `SevLow` |  |
| `medium` | `SevMedium` |  |
| `high` | `SevHigh` |  |
| `critical` | `SevCritical` |  |

### `DetectionClass` values

Detection classes, lowest to highest (ClassRank).

| Value | Constant | Meaning |
|---|---|---|
| `signal` | `ClassSignal` |  |
| `finding` | `ClassFinding` |  |
| `alert` | `ClassAlert` |  |

<!-- END GENERATED: field reference -->
