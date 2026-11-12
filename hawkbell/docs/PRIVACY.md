# Privacy

hawkbell watches what AI agents do on a developer's machine. That is also a record of what a person asked for, when, and in which project, so it is employee monitoring under most definitions. This page says exactly what is collected, what leaves the machine in each profile, how long it is kept, and what controls exist. It is engineering documentation, not legal advice: have your own counsel and, where one exists, your works council review a deployment.

The design choice behind everything below: **detection runs on the endpoint, on full content, so that content does not have to leave it.** Central LLM-based analysis needs the transcript; local rules do not.

## Emit profiles

`privacy.profile` in the config selects what is written for shipping. There are three profiles: `minimal` (the default), `standard` and `full` (`internal/privacy`, `internal/config`). The profile governs emission only: rules always evaluate the full event locally, in memory.

| | `minimal` (default) | `standard` | `full` |
|---|---|---|---|
| Findings (detection stream) | shipped | shipped | shipped |
| Inventory and posture | shipped | shipped | shipped |
| Health and coverage | shipped | shipped | shipped |
| Per-session summaries (counts, tool kinds, hosts contacted, path classes, rule ids) | shipped | shipped | shipped |
| Activity (records of each prompt, of each tool call before and after it runs (`tool.pre`, `tool.post`), of session and turn events, of agent process starts and stops, and of child processes; [EVENTS.md](EVENTS.md#types)) | kept in a local ring, not shipped; the last few events of a session travel with each finding as detection context | shipped, redacted | shipped, redacted |
| Command lines | redacted, in a finding's evidence and its detection context | redacted | redacted |
| File paths and working directories | in a finding's evidence and context, `session.cwd` on findings and summaries, inventory paths | yes | yes |
| Prompt text | never | never | redacted |
| Tool input and output | content never; a finding and its detection context carry names of input keys, sizes rounded up to a power of four and keyed digests (with a tenant key), as in `standard` | names of input keys, sizes rounded up to a power of four, keyed digests (with a tenant key) | redacted, truncated |
| Web search queries | never | never | redacted |

In `minimal`, a finding carries a small evidence map (the fields the rule names, from an allowlist that excludes prompt text and tool output) and up to `privacy.context_events` (default 5, at most 50) preceding events of the same session as `detection.context` records. Context follows findings and alerts, not signals, and always uses the `standard` field policy. A shipped command line includes any text the command writes into a file (a heredoc, `echo` or `printf`): credentials are removed from it by pattern and by position, and all of it is removed when the target is a credential file (`hawkbell privacy show` says so on the machine). In `minimal` and `standard` a failed tool's error message ships redacted and cut to 256 bytes.

The per-field rules are generated from the code into [EVENTS.md](EVENTS.md#what-each-profile-ships), and `go test ./internal/event` fails when that table, the JSON schema and the example records disagree. The examples are real outbox lines written by the binary for one played session in each profile ([docs/schema/examples/](schema/examples/)): in `minimal.ndjson` the heartbeat counts 9 activity records written to the local ring (`local.written: 9`) and no activity stream in the outbox; in `standard.ndjson` the same 9 records are shipped (`stream.activity.emitted: 9`, see [per-stream accounting](EVENTS.md#per-stream-accounting)).

## What every shipped record contains

- Host identifier and name, operating system and architecture.
- On records about an account's agents (in the examples, every record but health): the OS account name and numeric id (or keyed pseudonyms, see below) and the agent's catalog id. Health heartbeats name accounts in their per-agent coverage rows.
- On activity, findings, context and summaries: a session identifier and the session's working directory, with the home directory written as `~`.
- A timestamp.

A per-user, per-session, timestamped stream is personal data in every profile. `minimal` reduces it to exceptional events and aggregates; it does not make it anonymous.

## Redaction

- Command lines are redacted structurally first: the parsed command identifies which argument is a credential (`mysql -p`, `curl -u`, `-H "Authorization: ..."`, `--token`, assignments to sensitive variable names, URL userinfo, and similar), and those values are replaced. A pattern and entropy pass runs second.
- URLs lose userinfo in every profile. Query string and fragment are removed except in `full`, which keeps them with the values of secret-named parameters replaced.
- Paths under the acting user's home are written as `~/...`.
- MCP server declarations are inventoried with the names of environment variables and headers, never their values, and with their arguments redacted.
- A detected secret is reported by kind and location. Its value is never emitted, and neither is an unkeyed fingerprint of it: with a tenant key the marker carries an 8-hex-digit keyed hash, without one it carries none.
- Redaction is tested, not asserted. `go test ./internal/privacy` writes a canary corpus of synthetic credentials through every profile, each without a key, with a key and with key plus pseudonyms, both uncached and from the redaction memo, and fails on any leak (`TestCanaryCorpusAllProfiles` in `internal/privacy/canary_test.go`). On 2026-11-12 it wrote 179 canaries into 9,144 records with 0 leaks. `TestOverRedactionBenign` checks that benign values detection needs (hosts, digests, paths) survive the `standard` profile: 0 of 52 lost on the same day. Both counts are printed by `go test -v`; they are not published in `bench/results/`, and the CI workflow that would run them on every change has not run on GitHub yet. Pattern-based redaction alone leaked 8 of 17 synthetic credentials in the design review ([ASSUMPTIONS.md](ASSUMPTIONS.md)), which is why it is not the first line.
- Known gaps (`internal/privacy`, package documentation): free-text credentials are found by heuristics ("my password is x" is not found); text a command writes into an ordinary file is redacted by pattern only; a secret transformed by something the redactor cannot decode (compression, encryption) and never seen structurally cannot be found; Windows 8.3 short names of a home directory are not rewritten to `~`.

## Digests and pseudonyms

- Content-derived digests (of a prompt, tool input or output, a user-written asset definition, a finding's dedup key) are HMAC-SHA-256 with a tenant key (`privacy.hmac_key_file`), truncated to 96 bits. `labels.key_id` carries `privacy.key_id` when a keyed value was written. Without a key they are not emitted at all, and values shorter than 32 characters never get a digest (`DigestMinLen` in `internal/privacy/policy.go`). An unkeyed hash of a short prompt is reversible with a dictionary: 4 of 6 sample prompts were recovered that way in the design review.
- The key file must be a regular file, not a symbolic link, with no permission bits for group or others on POSIX systems (0600 or stricter), at most 4,096 bytes, and at least 16 bytes once trailing white space is removed (`internal/engine/options.go`, `ReadKeyFile`).
- `privacy.pseudonymize_users: true` replaces account names with keyed pseudonyms (`u_` and 16 hex digits of an HMAC of the name), also in `user.id`, `process.user`, asset and check owners and coverage rows. Re-identification then requires the key, which should be held by a different team than the one reading the logs. Pseudonymization covers identity fields and home directory paths, not free text that happens to contain a name. It requires `privacy.hmac_key_file`: a configuration that sets it without one is rejected (`internal/config/config.go`). The hook never reads the tenant key, so in findings and context it writes itself (in-hook detection, `sources.hooks.detect_in_hook`) those fields are removed instead of pseudonymized (`internal/hookcmd/worker.go`, `privacyPolicy`).
- Record ids and the `dedupe` field are keyed too. The parts derived from content (a prompt's text, the digest behind a derived id) are HMACs under the daemon's own identity key (`<data_dir>/checkpoints/identity.key`, 32 random bytes, mode 0600), which is separate from the tenant key. The hook keys its payload digests with a per-user secret kept in the user's spool state (`internal/hookcmd/records.go`); `hawkbell scan`, `hawkbell detect` and the detection pipeline inside the hook use a random key per process ([EVENTS.md](EVENTS.md#identity-id-dedupe-seq-writer), `internal/engine/identity.go`).
- Limits: the tenant key is present on every endpoint, so this protects against readers of the log store and against linkage across tenants, not against an administrator of the endpoint. In daemonless mode the hook has no key and emits no digests. On a single-user laptop the host identifier already identifies the person.

## Exclusions

```yaml
privacy:
  exclude:
    paths: ["~/personal/**", "/work/legal/**"]
    repos: ["github.com/alice/*"]
    users: ["contractor-*"]
```

`paths` match the session's working directory, the repository root and the paths of project-scoped inventory and posture records; `repos` match the repository remote; `users` the OS account. A path pattern names a directory tree; `**` matches any number of segments and a leading `~/` is the acting user's home (`internal/privacy/exclude.go`).

Exclusions are evaluated on identity fields only, before detection and redaction look at any content. An excluded session produces no activity, no findings and no summary. The hook drops an excluded event without writing anything; records the daemon drops are counted in the heartbeat counter `ingest.excluded`. Health records are never excluded.

Managed hooks fire for whichever account the agent is signed in with, including a personal subscription on a company laptop. Hooks do not report the account. If personal use is permitted, give people an excluded path.

## Transparency for the people monitored

- `hawkbell privacy show` prints, on that machine, what is collected, in which profile, where it is sent, how long it is kept and which exclusions apply.
- `hawkbell privacy tail` shows records written about the caller's own sessions: what was shipped (outbox) and what stayed on the machine (local ring). Both are written by the root daemon, so an ordinary account needs administrator rights (or membership of `output.group`, for the shipped records only). When it cannot read them it says so and exits 1, rather than reporting nothing.
- `hawkbell privacy purge --user <name>` (administrator) erases that account's rows from the local state database, its lines in the local ring, and its hook spool: every line of the account's own spool directories is overwritten in place and its guard-mode session state deleted. Records already shipped must be erased downstream. Append-only outbox segments are removed by retention, not rewritten; purge reports how many of the account's lines remain there. For a guaranteed purge, stop the daemon and the account's agents first (`hawkbell privacy purge --help`).

## Retention

| Store | What it holds | Default | Setting |
|---|---|---|---|
| Hook spool `<data_dir>/spool/<uid>/` (0700, owned by the user) | activity **with local content**: prompt text, tool input and output, file content the agent wrote | a fully read file is deleted once its last write is 72 hours old | `retention.spool` |
| Fallback hook spool in the user's home (`~/.local/state/hawkbell/spool` on Linux), used when the system spool cannot be reached | the same | never deleted by the daemon, which does not write into home directories; `privacy purge` overwrites it | none |
| Local activity ring | redacted activity that is not shipped | 72 hours or 256 MiB | `retention.local`, `retention.local_bytes` |
| Outbox segments | shipped records | a segment older than 7 days is deleted once every shipper whose read position the daemon tracks (Fluent Bit's tail database, the built-in forward and OTLP shippers) has read it, or when none of them reads its stream; older unread segments stay until the 512 MiB cap removes them, which writes an `outbox.dropped_unshipped` health record (`internal/daemon/outbox.go`, `prune`) | `retention.outbox`, `retention.outbox_bytes` |
| Findings in the local state database | | 30 days, at most 5,000 rows | `retention.detections` |
| Session rows in the local state database | | 7 days, at most 2,000 rows | `retention.sessions` |

The state database (0600) and the local ring are readable by root only, and the outbox by root and one named group for the shipper (`output.group`). The hook spool is readable by its user and root. Tables exposed to Fleet that derive from activity carry no commands, working directories or evidence text (`internal/state/tables.go`): `hawkbell_detections` and `hawkbell_sessions` hold identifiers, the account, rule ids, titles, severities and counts; `hawkbell_agent_processes`, from the process monitor, holds each agent root process's pid, start time, agent, account, executable path, the command-line flags the catalog marks as risky (no other arguments), session reference and container id.

Fleet keeps a second copy with its own lifetime. The shipped report `hawkbell - detections` reads `hawkbell_detections` every 15 minutes with `logging: differential_ignore_removals` (new rows go to Fleet's log destination) and `discard_data: false` (Fleet also stores the latest result per host). No stock report reads `hawkbell_sessions` or `hawkbell_agent_processes`; the bypass-mode policy checks both. The opt-in child-process reports join `hawkbell_agent_processes` to osquery's process events and send raw command lines to Fleet; they are the only reports that set `discard_data: true` ([deploy/fleet/lib/stock/reports.yml](../deploy/fleet/lib/stock/reports.yml), [deploy/fleet/lib/opt-in/exec-events.reports.yml](../deploy/fleet/lib/opt-in/exec-events.reports.yml)). Set `discard_data: true` on the detections report if Fleet should not keep it.

There is no retroactive collection: transcript files that existed before hawkbell first saw them are read from their end. Backfill is an explicit operator action (`sources.transcripts.backfill`).

## What hawkbell does not do

- It does not send anything to the project's authors. There is no telemetry and no cloud component. The daemon connects only where the operator configures it: a bundle URL (`bundle.url`) and the experimental `output.forward` and `output.otlp` shippers. `hawkbell catalog verify`, run by hand, asks the npm and PyPI registries about the catalog's own package names (`--offline` skips that); it sends nothing from the machine's activity.
- It does not capture screens, keystrokes, clipboard, or browser history.
- Files it reads: agents' own configuration and session directories, the project control files those agents load, and `/proc` entries of running processes (command lines and the agents' marker variables). Discovery refuses personal directories (Documents, Desktop, Pictures, Mail, Messages, browser profiles, `.ssh`, `.gnupg` and others) unless the catalog or an agent's project list points inside them, and then reads only control files (`internal/discovery/gate.go`).

## Risks to weigh

- Rule packs can search content. Anyone who can ship a rule (the holder of the bundle signing key, a committer to the rules repository, root on the endpoint through `rules.dirs`) can match on prompts and tool output locally and receive findings about named users. The evidence allowlist stops content leaving in `minimal` and `standard`, but a finding still reveals that a pattern matched. Treat rule changes like access changes: review them, and note that every finding carries the rule pack version, the hash of the loaded rule set and, when one is installed, the bundle version (labels `rule_pack_version`, `rules_version`, `rules_hash`, `bundle_version`; `internal/engine/doc.go`).
- `standard` and `full` are behavioural monitoring. Choose them deliberately.
- The hook spool holds full content on the endpoint for up to 72 hours after it was read, and the fallback spool in a home directory until it is purged.
- Guard mode shows the developer a reason when it asks or denies. Make sure that text is appropriate for the person reading it.

## Points for a works agreement or impact assessment

These are the questions the design review expected to be asked; the answers are yours to give.

1. Purpose: security monitoring of AI agents, not performance measurement. State that summaries and activity will not be used for performance evaluation.
2. Legal basis and proportionality: why `minimal` is or is not sufficient for your risk.
3. Notice: who is told, when, and how (`hawkbell privacy show` output is a starting point).
4. Access: who can read findings; who holds the pseudonym key; how re-identification is approved and logged.
5. Retention at every hop: endpoint, Fleet, the log pipeline, the SIEM, cold storage.
6. Personal use: permitted or not, and which paths are excluded.
7. Rule governance: who can add rules, and how changes are reviewed.
8. Data subject requests: how access and erasure are handled downstream.
