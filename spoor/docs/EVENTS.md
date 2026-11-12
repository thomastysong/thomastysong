# Events

Everything spoor writes for other systems is one record format: a JSON object on one line (NDJSON), defined by the Go types in `internal/event`. This page describes the streams, every record type and field, what each privacy profile ships, how records are identified and deduplicated, how time works for late records, and the heartbeat that lets a consumer prove nothing was lost.

- Machine-readable schema: [`schema/event.schema.json`](schema/event.schema.json) (JSON Schema 2020-12), generated from `internal/event`.
- Real records: [`schema/examples/`](schema/examples/), written by the spoor binary itself (see [How the examples were made](#how-the-examples-were-made)).
- The field reference at the end of this page is generated from the same code. `go test ./internal/event` fails when the schema, this reference or the examples disagree with the code.

## Where records are written

| Where | What | Notes |
|---|---|---|
| `<data_dir>/outbox/<stream>-<YYYYMMDD>-<HH>-<NNNN>.ndjson` | every record that may leave the host | The file Fluent Bit tails. The hour is UTC; `NNNN` is a roll counter (`output.max_segment_bytes`, default 16 MiB). On Linux the daemon makes the directory mode 2750 (setgid) with group `output.group` (default `spoor`, when that group exists) and the files 0640, so only root and that group (the shipper) can read them. <!-- VERIFY: directory ownership and modes are receiving integration fixes in internal/daemon. --> A file name never changes once the file exists. |
| `<data_dir>/local/` | activity that must not leave the host (the `minimal` profile) | The local ring: same file naming, files 0600, never tailed, bounded by `retention.local` / `retention.local_bytes`. |
| standard output | the outbox records too, when `output.stdout: true` | For containers (the Kubernetes node sensor). |
| `spoor detect --ndjson`, `spoor scan --ndjson` | findings, posture checks and session summaries (`detect`); inventory and posture records (`scan`) | Same format and the same privacy stage as the outbox. |

The stream is the record's `kind`, so the tag Fluent Bit gives a record (`spoor.<stream>`, see [FLUENT-BIT.md](FLUENT-BIT.md)) follows from its file name. With `output.format: ocsf` the outbox carries OCSF 1.9.0 events instead (`internal/format`), with the native record under `unmapped.spoor`; this page and the schema describe the native format only. The experimental OTLP shipper sends the native record as the log body.

## Kinds and streams

| `kind` (= stream) | Types | Written by | Shipped in |
|---|---|---|---|
| `activity` | `session.start`, `session.end`, `prompt.submit`, `tool.pre`, `tool.post`, `turn.end`, `subagent.start`, `subagent.stop`, `permission.decision`, `config.change`, `notification`, `context.compact`, `agent.process.start`, `agent.process.stop`, `process.exec`, `hook.payload_anomaly` | hooks (through the spool), transcript tailer, process monitor, osquery exec pull, OTel receiver, adapters | `standard`, `full`; in `minimal` only as detection context |
| `detection` | `detection.finding`, `detection.context` | the rules engine, the engine's hook-bypass check and relayed findings of other sensors ([RULES.md](RULES.md#detections-that-are-not-in-a-pack)); the privacy stage (context) | every profile |
| `inventory` | `inventory.asset` | inventory scan | every profile |
| `posture` | `posture.check` | inventory rules over the scan | every profile |
| `health` | `health.heartbeat`, `health.error` | the pipeline (heartbeat), the daemon (errors) | every profile |
| `summary` | `session.summary` | the pipeline | every profile |

`output.streams` can restrict which streams are shipped (empty means the profile's default); records of the other streams go to the local ring instead (heartbeat counter `records.withheld`).

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
- **`writer`** is `<mode>-<16 hex>`, random per process start (`daemon-…`, `detect-…`, `scan-…`); records in the local ring carry `<writer>.local` with their own sequence. **`seq`** is monotonic per writer and stream, starting at 1. A gap in `seq` for one writer and stream is a lost record; a new writer value is a restart. The heartbeat states which sequence numbers it covers (below).
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
- If redaction fails, or a record cannot be brought under the cap, a content-free **skeleton** is written instead: `truncated: ["*"]`, the routing and identity fields, a few identity fields of `host`, `user`, `agent`, `session`, `tool`, `detection`, `check`, `asset` and `health`, never content, and (from the privacy stage) a label naming the reason, `privacy_error` or `line_cap`. The schema's `$defs/Skeleton` admits exactly the fields the two functions that write skeletons set (`internal/sink` and `internal/privacy`; the generator reads them from their source), in closed objects. A skeleton's strings may be clipped to a byte budget, so there a vocabulary field holds a value of its vocabulary, a prefix of one (`detectio`), or nothing. Heartbeat counter `records.linecap_dropped` counts records that could not be written at all.

## Detection records

A `detection.finding` record is a copy of the triggering record (host, user, agent, session, tool, target, process, after the privacy stage) plus `detection`. Most come from rules; the engine's hook-bypass check (`SPR-COV-901`, `SPR-COV-902`) and findings relayed from numbat (`rule_id` `numbat:<id>`, `source: adapter`) are described in [RULES.md](RULES.md#detections-that-are-not-in-a-pack).

- `rule_id`, `title`, `class` (`signal` < `finding` < `alert`), `severity`, `confidence`, `maturity`, `category`, `tags` (ATT&CK, ATLAS and OWASP ids in Sigma style: `attack.t1059.004`, `atlas.aml.t0050`, `owasp.asi05`), `remedy`.
- `evidence`: the fields the rule names, copied from a fixed allowlist of non-content fields (list values as JSON arrays in a string).
- `event_ids`: the records that produced the match, oldest first; for a sequence rule, the chain.
- `response` is what the rule asks for in guard mode (`none`, `ask`, `block`); `enforced` is true only when spoor actually returned that answer to the agent. With guard mode off (the default) `enforced` is absent.
- `count`: how many matches the record stands for after deduplication (repeats inside `rules.suppress_for` are counted, not re-emitted); `dedup_key` groups repeats (written only with a tenant key, see the profile table); `escalate` marks findings worth a second look by a human or an LLM judge.
- Labels stamped on every rule's finding so that a rule change is attributable: `rule_pack`, `rule_pack_version`, `rules_hash` (first 12 hex digits of the rule set's hash), `rules_version` (every loaded `pack@version`), and `bundle_version` when a signed bundle is installed. The engine's own findings carry `rules_hash`, `rules_version` and `bundle_version` only; relayed findings carry none of them.

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

The other counters are totals since the process started (a few, such as `engine.sessions`, `engine.pending`, `baseline.keys` and the `coverage.<state>` row counts, are current values), under stable names that dashboards and the state database read. The groups written by the pipeline (`internal/engine`, `health.go`):

| Counters | Meaning |
|---|---|
| `events_in`, `events_out`, `dropped`, `detections`, `errors` | headline totals, copied into the state database's health row (the `spoor_health` table Fleet reads) |
| `ingest.processed`, `.excluded`, `.malformed`, `.queue_dropped`, `.disabled_dropped`, `.closed_dropped`, `.unknown_vocab` | records taken in; excluded by `privacy.exclude`; malformed; dropped (full queue, kill switch, shutdown); an unknown `tool.kind` rewritten to `other` |
| `correlate.*` | cross-surface correlation: held, released, matched, duplicates, late hooks, corroborated, corroborated after write, OTel attribution |
| `coverage.*` | coverage rows by state, hook-bypass findings and signals, unknown agents, untrusted process records |
| `detections.below_min_class`, `detections.context` | findings not written because of `rules.min_class`; context records written |
| `records.late`, `.withheld`, `.emit_refused`, `.linecap_dropped`, `.secret_flow_scrubbed` | records that got `emitted`; records kept local because `output.streams` excludes their stream; records the privacy stage refused; records too large to write; records reduced to a skeleton after secret flow |
| `outbox.write_errors`, `outbox.dropped`, `local.written`, `local.dropped`, `local.discarded`, `local.write_errors` | sink results |
| `state.applied`, `state.errors`, `baseline.*`, `identity.key_stored`, `identity.key_errors` | state database batches, first-seen baseline, identity key |
| `session.summaries`, `session.synthesized_start`, `activity.suppressed` | summaries written, inferred session starts, activity dropped by the rate limit |
| `engine.*`, `rules.*` | pipeline queues, panics and rule timeouts; the rules engine's own statistics (evaluations, matches, per-rule time in `rules.rule_ns.<id>`) |

The daemon adds its own gauges in the same map: in the examples `outbox.*` (pruning and size), `procmon.*`, `scan.*`, `hooks.status_refreshes`, `transcript.primes`, `procs_total`, `procs_unreadable` and `users`; when they occur, `spool.<problem>` for spool lines the daemon refused (`spool.forged_kind` for a line that claimed a kind other than activity, `spool.owner_mismatch`, `spool.symlink_refused`, `spool.not_regular`, `spool.oversize_line`, `spool.rate_limited`, `spool.malformed`) and `hook_errors.<reason>` for failures the hook supervisor reported through the spool (worker crash, timeout, bad reply). <!-- VERIFY: the daemon's gauge names are receiving integration fixes; the pipeline counters above are stable. -->

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

The final summary of the same session in `minimal`. The hook and the transcript both reported it (`surfaces`). The transcript confirmed three of the session's records after their hook records had been written: the prompt and the first tool call's `tool.pre` and `tool.post` (the transcript has those three lines). They are counted in the labels:

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
sudo env "PATH=$PATH" docs/schema/examples/regen.sh
```

After regenerating, update the quoted examples above (the test requires each to be a line of the named file) and run `go test ./internal/event`.

## The schema

`docs/schema/event.schema.json` is generated from the Go types (field names, JSON tags, which fields are always written) and from the package's source (doc comments and the constants of every closed vocabulary), plus three facts read from the source where they are produced: the `detection.context` type and the profile names (`internal/privacy`), and the fields a skeleton carries (the skeleton writers in `internal/sink` and `internal/privacy`). A change to any of them makes `go test ./internal/event` fail until the schema is regenerated:

```
go test ./internal/event -run TestSchema -update
```

What it enforces:

- JSON types; required fields: those the encoder always writes, and `privacy`, which the privacy stage stamps on every record it lets through (a record without it did not pass that stage).
- `additionalProperties: false` on every object whose Go type is a struct. The open maps are only `labels`, `asset.detail`, `detection.evidence`, `health.counters`, `summary.tool_calls` and `tool.input`.
- The closed vocabularies declared as constants in `internal/event`, plus `detection.context` and the profile names from `internal/privacy`: kind, type, source, fidelity, integrity, tool kind, asset kind, scope, change, detection class, severity, privacy. Values described only in a field comment (for example `outcome.status`, `coverage.state`) are documented below but not enforced.
- `v` equal to 1.
- The time format, with the range of every component checked, month and day together. A regular expression cannot know leap years, so the pattern admits February 29 in every year; the `Time` definition also says `format: date-time`, which this package's validator asserts (and so rejects 2026-02-29). A generic validator asserts it only when format assertion is switched on.
- What each profile never writes, from the [profile table](#what-each-profile-ships): in `minimal` and `standard` no `prompt.text`, `tool.input`, `tool.output`, `target.query` or `session.transcript`, in `full` no `session.transcript`. The test fails when the table and the schema disagree.
- A skeleton only as described [above](#truncation-and-skeleton-records): the marker `"*"` in `truncated` does not open the schema.

The test also validates every example line; checks that the validator rejects records with an unknown field, a value outside a vocabulary, a missing required field, a malformed or impossible time, a field the record's profile never writes, or a skeleton with anything its writers do not set; and fails when the committed schema or the field reference below differs from what the code generates, or when a field in that reference has no description.

To check other records against the schema (a live outbox, the local ring, a SIEM export as NDJSON), name files or directories in `SPOOR_SCHEMA_VALIDATE` (separated by `:`, or `;` on Windows):

```
$ SPOOR_SCHEMA_VALIDATE=<data_dir>/outbox:<data_dir>/local go test ./internal/event -run TestSchemaValidatesGivenFiles -v
```

It reports every line that does not validate and the count it checked, and fails when it found no record at all, so a mistyped or empty directory is not a pass. Over the binary's outputs collected while this page was written (four example runs, a `spoor scan` and three `spoor detect` runs, one of them over hostile input) it printed `validated 273 records in 16 files`.

`v` is the schema version. It changes only on a breaking change; new optional fields are not breaking, so consumers should ignore fields they do not know rather than reject the record.

## Field reference

<!-- BEGIN GENERATED: field reference (go test ./internal/event -run TestSchema -update) -->

Generated from the Go types in `internal/event` and their doc comments; a field without one is described by a note in `internal/event/schema_test.go` (`fieldNotes`) or by its type's comment. "always" fields are written on every record of that object (an empty string or zero when unset); the others are left out when empty.

### `Event` object

Event is the normalized record.

| Field | Type | Present | Description |
|---|---|---|---|
| `v` | integer | always | Schema version, 1 (SchemaVersion). Bumped only on breaking changes; adding optional fields is not breaking. |
| `id` | string | always | Record id: UUID-shaped and starting with the record time in milliseconds, so ids sort by time. Version 7 ids are random; version 8 ids are derived from the record's natural key (StableID), so a replayed delivery, or the twin of a record from another surface, has the same id. Deduplicate deliveries on it. |
| `ts` | [`Time`](#time-string) | always | When the thing happened, as its source says: the hook's clock, the log's timestamp, the triggering record's ts for a finding, the write time for heartbeats and summaries. |
| `emitted` | [`Time`](#time-string) | when set | Emitted is when the record was written for shipping, set only when that is more than a minute after TS (a laptop that was offline, a backfilled transcript). Rules with event-time lookback windows can schedule on it. |
| `seq` | integer ≥ 0 | when set | monotonic per (Writer, stream), for gap detection downstream |
| `dedupe` | string | when set | Dedupe is identical for every record that describes the same action, whichever surface reported it (see DedupeKey). |
| `kind` | [`Kind`](#kind-values) | always | Kind is the top-level class of a record and selects the output stream. |
| `type` | [`EventType`](#eventtype-values) | always | The record type within its kind. |
| `source` | [`Source`](#source-values) | always | Source is the collection method that produced a record. |
| `fidelity` | [`Fidelity`](#fidelity-values) | when set | Fidelity says whether the record was directly observed or reconstructed. |
| `sources` | array of [`Source`](#source-values) | when set | Sources lists every surface that corroborated this event after cross-surface correlation (for example ["hook","transcript"]). |
| `integrity` | [`Integrity`](#integrity-values) | when set | Integrity says who could have altered a record before it was written. Hooks run as the monitored user, so their records are advisory until a privileged collector corroborates them; anything a Fleet policy depends on must be root-integrity. |
| `writer` | string | when set | Writer identifies the process that wrote the record (random per process start). Seq is monotonic per Writer, and heartbeats report per-writer counts, so a consumer can prove that nothing was lost or removed. |
| `host` | [`Host`](#host-object) | when set | Host identifies the endpoint. ID should equal osquery's system_info.uuid so events join to Fleet hosts. |
| `user` | [`User`](#user-object) | when set | User is the OS account the agent runs as. |
| `agent` | [`Agent`](#agent-object) | when set | Agent identifies the AI agent product. |
| `account` | [`Account`](#account-object) | when set | The identity the agent is signed in with. No collector in this release sets it; the Claude Code OpenTelemetry receiver records the organization as labels.org_id instead. |
| `session` | [`Session`](#session-object) | when set | Session identifies one agent conversation. |
| `tool` | [`Tool`](#tool-object) | when set | Tool describes the tool call. |
| `target` | [`Target`](#target-object) | when set | Target is what the tool call acts on, extracted and normalized. |
| `prompt` | [`Prompt`](#prompt-object) | when set | Prompt summarizes a user prompt without necessarily carrying it. |
| `outcome` | [`Outcome`](#outcome-object) | when set | Outcome is the result of a tool call or turn. |
| `process` | [`Process`](#process-object) | when set | Process describes an OS process. |
| `container` | [`Container`](#container-object) | when set | Container locates the workload when the agent runs in a container. |
| `repo` | [`Repo`](#repo-object) | when set | Repo describes the source repository of the session's working directory. |
| `asset` | [`Asset`](#asset-object) | when set | Kind == inventory |
| `check` | [`Check`](#check-object) | when set | Kind == posture |
| `detection` | [`Detection`](#detection-object) | when set | Kind == detection |
| `health` | [`Health`](#health-object) | when set | Kind == health |
| `summary` | [`Summary`](#summary-object) | when set | Kind == summary |
| `privacy` | [`Profile`](#profile-values) | when set | Privacy is the tier that was applied when the record was emitted. |
| `truncated` | array of string | when set | Truncated names fields whose values were cut, so truncation is never silent; the cut value itself ends in an "[TRUNCATED:&lt;n&gt;B]" marker (when a sink cuts target.command to fit its line cap it records the full length in Labels["target.command.len"] instead). No hash of the full value is kept: an unkeyed one would let a reader confirm guesses about the missing text. |
| `labels` | object of string | when set | Facts that have no field of their own, as strings (hook_event, end_reason, rule_pack, context_for, first_seen and the others named in docs/EVENTS.md). Values pass the same redaction as every other string. |

### `Host` object

Host identifies the endpoint. ID should equal osquery's system_info.uuid so events join to Fleet hosts.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set | Host identifier, meant to equal osquery's system_info.uuid so that records join to Fleet hosts: host_id from the configuration, SPOOR_HOST_ID, the host_id file the osquery extension writes, or the hardware UUID (on Linux without one, machine-id). Empty when nothing is derivable; the heartbeat label host_id_source names the source. |
| `name` | string | when set | Host name: SPOOR_HOST_NAME when it is set to a plausible name (the Kubernetes node sensor sets it to the node's name), else the kernel's host name. |
| `os` | string | when set | linux \| darwin \| windows |
| `arch` | string | when set | amd64 \| arm64 |

### `User` object

User is the OS account the agent runs as.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | when set | Account name. With privacy.pseudonymize_users, a keyed pseudonym (removed when no key is configured). |
| `id` | string | when set | uid on POSIX, SID on Windows |

### `Agent` object

Agent identifies the AI agent product.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | always | catalog id, e.g. "claude-code" |
| `name` | string | when set | Product name from the catalog, on process-monitor and inventory records. |
| `version` | string | when set | Version as the surface or the scan reported it. |
| `pid` | integer | when set | Process id of the agent, on process-monitor records. |
| `surface` | string | when set | Surface is how the agent was run: cli \| ide \| desktop \| sdk \| ci \| cloud. |

### `Account` object

Account is the identity the agent is signed in with, when a surface reports it (vendor OpenTelemetry does; hooks usually do not). It answers the first governance question: corporate tenant, personal account or a raw API key on a managed machine.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set | ID is the vendor account identifier; emitted as a keyed digest unless the privacy profile is full. |
| `org` | string | when set | Organization the account belongs to. |
| `kind` | string | when set | Kind: organization \| personal \| api_key \| unknown. |

### `Session` object

Session identifies one agent conversation.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set | The agent's own session id. |
| `parent_id` | string | when set | parent session for subagents |
| `turn_id` | string | when set | Id of the current turn (a prompt and the work it caused), when the surface reports one. |
| `cwd` | string | when set | Working directory of the session; a path under the acting user's home is written as ~/... |
| `permission_mode` | string | when set | PermissionMode is the agent's own vocabulary, normalized to: default \| plan \| accept_edits \| auto \| dont_ask \| bypass. |
| `model` | string | when set | Model the session uses, as the agent reports it. |
| `transcript` | string | when set | path of the session log, when known |
| `subagent_id` | string | when set | Id of the subagent thread the record belongs to; absent on the main thread. |
| `subagent_type` | string | when set | Type or name of that subagent, as the agent reports it. |

### `Tool` object

Tool describes the tool call.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | when set | agent's own tool name, e.g. "Bash" |
| `kind` | [`ToolKind`](#toolkind-values) | when set | ToolKind is the cross-agent normalized class of a tool call. |
| `use_id` | string | when set | agent's tool-call id; join key across surfaces |
| `mcp_server` | string | when set | for Kind == mcp |
| `mcp_tool` | string | when set | Tool name on that MCP server, for kind mcp. |
| `input_sha256` | string | when set | InputSHA256 is the hash of the canonical JSON of the tool input, so identical calls correlate without shipping content. |
| `input_keys` | array of string | when set | InputKeys lists top-level argument names (metadata tier). |
| `input` | object (any JSON) | when set | Input is the redacted tool input; present only in tiers redacted/full. |
| `output` | string | when set | Output is the redacted, truncated tool output; tiers redacted/full only. |
| `output_sha256` | string | when set | Keyed digest of the tool output (HMAC with the tenant key); absent without a key. |
| `output_len` | integer | when set | Size of the tool output in bytes; rounded up to a power of four outside the full profile. |

### `Target` object

Target is what the tool call acts on, extracted and normalized.

| Field | Type | Present | Description |
|---|---|---|---|
| `command` | string | when set | shell command line, secrets redacted |
| `path` | string | when set | primary file path |
| `paths` | array of string | when set | additional paths referenced |
| `url` | string | when set | userinfo, query and fragment stripped unless tier is full |
| `host` | string | when set | network host |
| `hosts` | array of string | when set | Further distinct network hosts the call refers to; host holds the first. |
| `query` | string | when set | web search query; tiers redacted/full only |

### `Prompt` object

Prompt summarizes a user prompt without necessarily carrying it.

| Field | Type | Present | Description |
|---|---|---|---|
| `len` | integer | always | Length of the prompt in bytes; rounded up to a power of four outside the full profile (labels.len_bucketed). |
| `sha256` | string | when set | keyed hash when a tenant key is configured |
| `text` | string | when set | tiers redacted/full only |

### `Outcome` object

Outcome is the result of a tool call or turn.

| Field | Type | Present | Description |
|---|---|---|---|
| `status` | string | when set | Status: ok \| error \| denied \| interrupted \| unknown. |
| `error` | string | when set | Error text the agent reported, redacted; at most 256 bytes outside the full profile. |
| `duration_ms` | integer | when set | Duration of the call in milliseconds, when the surface reports it. |
| `exit_code` | integer | when set | Exit status of the command, when the surface reports it. |
| `decision` | string | when set | Decision: allow \| deny \| ask, when a permission decision was observed. |
| `decision_source` | string | when set | user \| policy \| hook \| spoor |

### `Process` object

Process describes an OS process.

| Field | Type | Present | Description |
|---|---|---|---|
| `pid` | integer | when set | Process id. On hook records, the process that invoked the hook (the agent, or a shell it started); on process-monitor and exec records, the process itself. |
| `ppid` | integer | when set | Parent process id. |
| `name` | string | when set | Process name as the kernel reports it, which the process can set itself. |
| `exe` | string | when set | Path of the executable. |
| `args` | array of string | when set | secrets redacted |
| `start_time` | [`Time`](#time-string) | when set | Start time of the process; with pid, the join key to EDR process telemetry. |
| `user` | string | when set | Account the process runs as. |
| `ancestors` | array of string | when set | Ancestors is the chain of process names from parent to root. |
| `env_markers` | array of string | when set | EnvMarkers are agent marker variable NAMES found in the environment (values are never emitted except session ids copied into Session). |
| `flags` | array of string | when set | Flags are risky argv flags recognized by the catalog, e.g. "--dangerously-skip-permissions". |

### `Container` object

Container locates the workload when the agent runs in a container.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | when set | Container id, from the process's cgroup (process monitor) or from the container a scan looks into. |
| `runtime` | string | when set | docker \| containerd \| cri-o \| podman |
| `image` | string | when set | Image of the container. Not set by the collectors in this release. |
| `name` | string | when set | Name of the container. Not set by the collectors in this release. |
| `pod` | string | when set | Kubernetes pod name. Not set by the collectors in this release. |
| `pod_uid` | string | when set | Kubernetes pod UID, from the cgroup path; absent outside Kubernetes. |
| `namespace` | string | when set | Kubernetes namespace. Not set by the collectors in this release. |
| `node` | string | when set | Kubernetes node name. Not set by the collectors in this release. |

### `Repo` object

Repo describes the source repository of the session's working directory.

| Field | Type | Present | Description |
|---|---|---|---|
| `root` | string | when set | Root directory of the repository. Not set by the collectors in this release. |
| `remote` | string | when set | credentials stripped |
| `branch` | string | when set | Branch, when a surface reports it (Claude Code OpenTelemetry, numbat records). |

### `Asset` object

Asset is one inventory record. ID is stable across scans for the same (host, kind, identity, owner, location) so downstream can upsert.

| Field | Type | Present | Description |
|---|---|---|---|
| `id` | string | always | Stable across scans for the same host, kind, identity, owner and location, so downstream can upsert on it. |
| `kind` | [`AssetKind`](#assetkind-values) | always | AssetKind classifies an inventory record. |
| `name` | string | always | Name of the asset: the product, the declared server, skill or plugin, or the file. |
| `vendor` | string | when set | Vendor or publisher, when known. |
| `version` | string | when set | Version, when known. |
| `catalog_id` | string | when set | CatalogID is the catalog entry that identified the asset ("" when unknown). |
| `parent` | string | when set | Parent is the catalog id of the agent that owns this item (an MCP server declared in Cursor's config has Parent "cursor"). |
| `path` | string | when set | install path or declaring file |
| `scope` | [`Scope`](#scope-values) | when set | for declared items |
| `owner` | string | when set | OS user the item belongs to |
| `running` | boolean | when set | True when the scan saw a process of the product running. |
| `pid` | integer | when set | The lowest pid of those processes. |
| `sha256` | string | when set | SHA256 is the content hash: binary hash for agents, definition hash for MCP servers and hooks, folder hash for skills. |
| `evidence` | array of string | when set | Evidence lists how identity was established, e.g. "package:npm", "bundle_id", "path", "process", "signature". Two independent classes are required for Confidence "high". |
| `confidence` | string | when set | high \| medium \| low |
| `signer` | string | when set | Signer is the code-signing identity when verified (team id / publisher). |
| `first_seen` | [`Time`](#time-string) | when set | Not set by the scanner in this release (last_seen and change are). |
| `last_seen` | [`Time`](#time-string) | when set | Time of the scan that saw the asset. |
| `change` | [`Change`](#change-values) | when set | How the asset differs from the previous scan: new (also when there is no previous state), changed, unchanged (written by a full scan only) or removed (gone since the previous scan, reported by a full scan). |
| `risk_flags` | array of string | when set | RiskFlags are closed-vocabulary posture hints computed at scan time. |
| `mcp` | [`MCP`](#mcp-object) | when set | MCP holds normalized launch facts for a declared MCP server, so a central team can hunt for a bad package or endpoint across the fleet. |
| `telemetry` | [`Telemetry`](#telemetry-object) | when set | Telemetry describes how well spoor can see this agent (agents only). |
| `detail` | object of string | when set | Other facts about this kind of asset, as strings: for example project, plugin, marketplace, pinned, enabled, status or hooks_shadowed_by. |

### `MCP` object

MCP holds normalized launch facts for a declared MCP server, so a central team can hunt for a bad package or endpoint across the fleet.

| Field | Type | Present | Description |
|---|---|---|---|
| `transport` | string | when set | stdio \| http \| sse \| ws |
| `command` | string | when set | executable as declared (basename unless tier is full) |
| `args` | array of string | when set | secrets redacted |
| `runner` | string | when set | Runner is the package launcher when one is used: npx \| bunx \| uvx \| pipx \| pip \| docker \| podman \| node \| python \| deno \| binary. |
| `ecosystem` | string | when set | npm \| pypi \| oci \| "" |
| `package` | string | when set | Package the runner launches (an npm or PyPI name, an image). |
| `version` | string | when set | Version or tag of that package, when the declaration names one. |
| `pinned` | boolean | always | Pinned is true only for an exact version or an image digest. |
| `url_host` | string | when set | Host of the endpoint the client connects to (a remote transport, or the endpoint a stdio bridge is given). |
| `url_path` | string | when set | Path of that endpoint, redacted. |
| `env_keys` | array of string | when set | names only, never values |
| `header_keys` | array of string | when set | Names of the HTTP headers the declaration sets, never their values. |
| `has_inline_secret` | boolean | when set | True when a credential-shaped literal is written into the declaration itself (command line, arguments, environment or header values, headers helper, OAuth client secret, or a token in the URL) rather than referenced. The value is never written. |
| `auth_mode` | string | when set | none \| env \| header \| oauth \| inherited |
| `enabled` | boolean | when set | Whether the client has the server switched on, when its configuration says (false for a server on its disabled list). |

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
| `title` | string | when set | Title of the rule or check. |
| `status` | string | always | pass \| fail \| unknown |
| `severity` | [`Severity`](#severity-values) | when set | Severity of the rule or check. |
| `agent_id` | string | when set | Catalog id of the agent the checked item belongs to. |
| `asset_id` | string | when set | asset.id of the inventory record that failed the check. |
| `scope` | [`Scope`](#scope-values) | when set | Scope is where a configuration item is declared. |
| `subject` | string | when set | file path or setting key checked |
| `expected` | string | when set | What the check requires, when it says (the scanner's file-owner check does). |
| `actual` | string | when set | What was found: for an inventory rule, the evidence fields as name=value pairs separated by "; " (at most 512 bytes). |
| `owner` | string | when set | Account the checked item belongs to. |
| `remedy` | string | when set | What to do about it. |

### `Detection` object

Detection is a rule match.

| Field | Type | Present | Description |
|---|---|---|---|
| `rule_id` | string | always | Id of the rule that matched: a rule from a pack, an id the engine itself writes (SPR-COV-901, SPR-COV-902) or a relayed one (numbat:&lt;id&gt;). See docs/RULES.md. |
| `title` | string | always | Title of the rule. |
| `class` | [`DetectionClass`](#detectionclass-values) | when set | Class is how much attention the match deserves: "signal" (counted into the session summary, not shipped by default), "finding" (shipped, no page) or "alert" (expected to be silent on ordinary developer work). |
| `severity` | [`Severity`](#severity-values) | always | Severity of the rule. |
| `confidence` | string | when set | low \| medium \| high |
| `maturity` | string | when set | experimental \| stable |
| `category` | string | when set | Category of the rule, for example execution. |
| `tags` | array of string | when set | Tags carries framework mappings in Sigma tag style: attack.t1059.004, atlas.aml.t0051, owasp.asi05. |
| `evidence` | object of string | when set | Evidence is a small redacted map of the field values that matched. |
| `event_ids` | array of string | when set | EventIDs are the ids of the events that produced the match, oldest first; for sequence rules this is the chain. |
| `flags` | array of string | when set | Flags are the session flags that were required and present. |
| `response` | string | when set | Response is what the rule asks for (none \| ask \| block); Enforced says whether spoor actually returned that decision to the agent. |
| `enforced` | boolean | when set | True only when spoor returned the response to the agent (guard mode); absent otherwise. |
| `dedup_key` | string | when set | DedupKey groups repeats of the same finding; Count is how many matches this record stands for after suppression. |
| `count` | integer | when set | How many matches this record stands for: repeats inside rules.suppress_for are counted and carried on the next emission instead of being written again. |
| `escalate` | boolean | when set | Escalate marks findings that are suspicious but not conclusive and are good candidates for a downstream LLM or human judge. |
| `remedy` | string | when set | What to do about it. |

### `Health` object

Health is the sensor heartbeat. It is deliberately content-free.

| Field | Type | Present | Description |
|---|---|---|---|
| `sensor_version` | string | always | Version of the spoor binary that wrote the record. |
| `mode` | string | always | Mode: daemon \| extension \| hook \| scan. |
| `uptime_s` | integer | when set | Seconds since the writing pipeline started. |
| `counters` | object of integer ≥ 0 | when set | Counters and gauges by name (see Counters in docs/EVENTS.md). |
| `surfaces` | array of [`SurfaceStatus`](#surfacestatus-object) | when set | SurfaceStatus reports one collector. |
| `coverage` | array of [`Coverage`](#coverage-object) | when set | Coverage is the per-agent, per-user visibility statement: which surfaces are actually delivering. "Not collected" must never read as "clean". |
| `rules_count` | integer | when set | Number of loaded rules. |
| `rules_hash` | string | when set | SHA-256 of the loaded rule set; findings carry its first 12 hex digits as labels.rules_hash. |
| `catalog_version` | string | when set | Version of the agent catalog. |
| `last_scan` | [`Time`](#time-string) | when set | Time of the last inventory scan. Not set by the heartbeat writer in this release. |
| `reason` | string | when set | Reason is a closed-vocabulary code for health.error records. |
| `detail` | string | when set | Free-text detail of a health.error. |

### `SurfaceStatus` object

SurfaceStatus reports one collector.

| Field | Type | Present | Description |
|---|---|---|---|
| `name` | string | always | hooks \| transcripts \| processes \| scan |
| `status` | string | always | Status: ok \| degraded \| failed \| disabled. |
| `last_event` | [`Time`](#time-string) | when set | When the collector last delivered, by the sensor's clock (the arrival of its last record; for the process monitor its last self-check, for the scan the scan's time), not a time a record claims. |
| `events` | integer ≥ 0 | when set | Records the collector delivered. |
| `errors` | integer ≥ 0 | when set | Errors the collector counted. |
| `schema_drift` | boolean | when set | True when the collector met input in a shape it does not know (an agent changed its log or telemetry format). |
| `reason` | string | when set | Why the status is not ok, as a code: for example config, kill_switch, checkpoint or procs_unreadable. |

### `Coverage` object

Coverage is the per-agent, per-user visibility statement: which surfaces are actually delivering. "Not collected" must never read as "clean".

| Field | Type | Present | Description |
|---|---|---|---|
| `agent_id` | string | always | Catalog id of the agent. |
| `user` | string | when set | Account the row is about: its name, or its uid or SID when the name is unknown. |
| `hooks` | string | when set | see Telemetry.Hooks |
| `transcript` | string | when set | see Telemetry.Transcript |
| `processes` | integer | when set | running agent processes seen |
| `state` | string | always | State: covered \| partial \| blind \| absent. |

### `Summary` object

Summary is the per-session rollup: enough to answer fleet-wide questions ("which hosts called MCP server X", "which sessions loaded skill hash Y") from a small indexed stream while raw activity stays local or in cold storage. It carries counts, classes and identifiers, never content.

| Field | Type | Present | Description |
|---|---|---|---|
| `started` | [`Time`](#time-string) | when set | ts of the session's earliest activity record. |
| `ended` | [`Time`](#time-string) | when set | ts of its latest activity record, on the final summary only. |
| `final` | boolean | when set | true when the session ended; false for periodic rollups |
| `events` | integer | always | Activity records counted into the summary. |
| `prompts` | integer | when set | prompt.submit records. |
| `subagents` | integer | when set | subagent.start records. |
| `tool_calls` | object of integer | when set | ToolCalls counts tool calls by normalized kind. |
| `hosts` | array of string | when set | Hosts are distinct network hosts contacted through tools (capped). |
| `host_classes` | array of string | when set | Distinct classes of the network hosts contacted. |
| `path_classes` | array of string | when set | PathClasses are the distinct sensitive path classes touched. |
| `mcp_servers` | array of string | when set | Distinct MCP servers called. |
| `installs` | array of string | when set | Installs are packages installed by the agent as "manager:name". |
| `detections` | array of string | when set | rule ids |
| `max_severity` | [`Severity`](#severity-values) | when set | Highest severity among detections, signals included. |
| `flags` | array of string | when set | session flags set by rules |
| `surfaces` | array of [`Source`](#source-values) | when set | Surfaces that reported this session and the resulting coverage state (covered \| partial \| blind). |
| `coverage` | string | when set | What the reporting surfaces amount to: covered (hooks and another surface), partial (hooks, or transcript or OpenTelemetry, alone) or blind (only the process monitor or osquery). |
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

Event.Type: the activity types (Kind activity) and the types of the other kinds. detection.context is declared in internal/privacy. The Types table in docs/EVENTS.md says what each one means.

| Value | Constant | Meaning |
|---|---|---|
| `session.start` | `TypeSessionStart` |  |
| `session.end` | `TypeSessionEnd` |  |
| `prompt.submit` | `TypePromptSubmit` | guard mode can block this and tool.pre |
| `tool.pre` | `TypeToolPre` | before execution; guard mode can block it (and prompt.submit) |
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
| `detection.context` | `privacy.TypeContext` | TypeContext is the Type of a detection-context record. |

### `Source` values

Source is the collection method that produced a record.

| Value | Constant | Meaning |
|---|---|---|
| `hook` | `SourceHook` | agent hook invoked spoor (real time, self-reported by the agent) |
| `transcript` | `SourceTranscript` | parsed from the agent's on-disk session log |
| `process` | `SourceProcess` | observed from the OS process table |
| `scan` | `SourceScan` | discovery / posture scan of files and packages |
| `otel` | `SourceOTel` | agent-native OpenTelemetry received locally |
| `osquery` | `SourceOsquery` | exec rows from osquery evented tables, pulled from osqueryd over its extension socket |
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

### `Profile` values

Profile names what leaves the endpoint.

| Value | Constant | Meaning |
|---|---|---|
| `minimal` | `privacy.ProfileMinimal` | ProfileMinimal (the default) ships detections, inventory, posture, health and session summaries. Activity stays in the local ring and is attached to a detection as redacted context. |
| `standard` | `privacy.ProfileStandard` | ProfileStandard also ships activity, with field-level redaction and no prompt text, tool input or tool output. |
| `full` | `privacy.ProfileFull` | ProfileFull adds prompt text, tool input and the head of tool output, all redacted. |

<!-- END GENERATED: field reference -->
