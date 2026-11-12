# Privacy

spoor watches what AI agents do on a developer's machine. That is also a record of what a person asked for, when, and in which project, so it is employee monitoring under most definitions. This page says exactly what is collected, what leaves the machine in each profile, how long it is kept, and what controls exist. It is engineering documentation, not legal advice: have your own counsel and, where one exists, your works council review a deployment.

The design choice behind everything below: **detection runs on the endpoint, on full content, so that content does not have to leave it.** Central LLM-based analysis needs the transcript; local rules do not.

## Emit profiles

`privacy.profile` in the config selects what is written for shipping. The profile governs emission only: rules always evaluate the full event locally, in memory.

| | `minimal` (default) | `standard` | `full` |
|---|---|---|---|
| Findings (detection stream) | shipped | shipped | shipped |
| Inventory and posture | shipped | shipped | shipped |
| Health and coverage | shipped | shipped | shipped |
| Per-session summaries (counts, classes, hosts, MCP servers, rule ids) | shipped | shipped | shipped |
| Activity (one record per prompt, tool call, session event) | kept in a local ring, not shipped | shipped, redacted | shipped, redacted |
| Command lines | only as redacted evidence on a finding | redacted | redacted |
| File paths | as evidence on a finding | yes | yes |
| Prompt text | never | never | redacted |
| Tool input and output | never | names of input keys and size buckets only | redacted, truncated |
| Web search queries | never | never | redacted |

In `minimal`, a finding carries a small evidence map (the fields the rule names, from an allowlist that excludes prompt text and tool output) and up to `privacy.context_events` preceding events of the same session in redacted form, so that a case can be understood without shipping everything else.

## What every shipped record contains

- Host identifier and name, operating system.
- The OS account name (or a keyed pseudonym, see below).
- Agent product and version, a session identifier.
- A timestamp.

A per-user, per-session, timestamped stream is personal data in every profile. `minimal` reduces it to exceptional events and aggregates; it does not make it anonymous.

## Redaction

- Command lines are redacted structurally first: the parsed command identifies which argument is a credential (`mysql -p`, `curl -u`, `-H "Authorization: ..."`, `--token`, assignments to sensitive variable names, URL userinfo, and similar), and those values are replaced. A pattern and entropy pass runs second.
- URLs lose userinfo, query string and fragment unless the profile is `full`.
- Paths under the acting user's home are written as `~/...`.
- MCP server declarations are inventoried with the names of environment variables and headers, never their values.
- A detected secret is reported by kind and location. Its value is never emitted, and no digest of it is emitted without a tenant key.
- Redaction is measured, not asserted: a corpus of synthetic secrets is pushed through every profile in CI, and the leak rate and over-redaction rate are published with each release in `bench/results/`. Pattern-based redaction alone leaked 8 of 17 synthetic credentials in the design review, which is why it is not the first line.

## Digests and pseudonyms

- Content-derived digests (for example of a prompt) are HMAC-SHA-256 with a tenant key (`privacy.hmac_key_file`), truncated, with a key id. Without a key they are not emitted at all, and values shorter than 32 characters get a size bucket instead of a digest. An unkeyed hash of a short prompt is reversible with a dictionary: 4 of 6 sample prompts were recovered that way in testing.
- `privacy.pseudonymize_users: true` replaces account names with keyed pseudonyms. Re-identification then requires the key, which should be held by a different team than the one reading the logs.
- Limits: the key is present on every endpoint, so this protects against readers of the log store and against linkage across tenants, not against an administrator of the endpoint. On a single-user laptop the host identifier already identifies the person.

## Exclusions

```yaml
privacy:
  exclude:
    paths: ["~/personal/**", "/work/legal/**"]
    repos: ["github.com/alice/*"]
    users: ["contractor-*"]
```

Exclusions are evaluated before any content is processed. An excluded session produces one counter in the health record and nothing else: no activity, no findings, no summary.

Managed hooks fire for whichever account the agent is signed in with, including a personal subscription on a company laptop. Hooks do not report the account. If personal use is permitted, give people an excluded path.

## Transparency for the people monitored

- `spoor privacy show` prints, on that machine, what is collected, in which profile, where it is sent, how long it is kept and which exclusions apply.
- `spoor privacy tail` shows the caller the records being emitted about their own sessions.
- `spoor privacy purge --user <name>` removes that user's rows from the local state database and local ring. Records already shipped must be erased downstream, and append-only outbox segments are removed by retention, not rewritten.

## Retention

| Store | Default | Setting |
|---|---|---|
| Per-user hook spool | 72 hours, deleted once ingested | `retention.spool` |
| Local activity ring | 72 hours or 256 MiB | `retention.local`, `retention.local_bytes` |
| Outbox segments | 7 days or 512 MiB | `retention.outbox`, `retention.outbox_bytes` |
| Findings in the local state database | 30 days | `retention.detections` |
| Session rows in the local state database | 7 days | `retention.sessions` |

The state database and outbox are readable by root (and the outbox by one named group for the shipper). Tables exposed to Fleet that derive from activity (`spoor_detections`, `spoor_sessions`) carry identifiers, rule ids, severities and counts, not commands, working directories or evidence text. Fleet keeps the latest result of each report per host: that is a second copy with its own lifetime, so the shipped reports over those tables set `discard_data`.

There is no retroactive collection: transcript files that existed before spoor first saw them are read from their end. Backfill is an explicit operator action.

## What spoor does not do

- It does not send anything to the project's authors or to any vendor. There is no telemetry and no cloud component.
- It does not capture screens, keystrokes, clipboard, or browser history.
- It does not read files outside agents' own configuration and session directories and the project control files those agents load. Documents, mail, photos and browser profiles are refused.

## Risks to weigh

- Rule packs can search content. Anyone who can ship a rule (the holder of the bundle signing key, a committer to the rules repository) can match on prompts and tool output locally and receive findings about named users. The evidence allowlist stops content leaving in `minimal` and `standard`, but a finding still reveals that a pattern matched. Treat rule changes like access changes: review them, and note that every finding carries the rule pack version.
- `standard` and `full` are behavioural monitoring. Choose them deliberately.
- Guard mode shows the developer a reason when it asks or denies. Make sure that text is appropriate for the person reading it.

## Points for a works agreement or impact assessment

These are the questions the design review expected to be asked; the answers are yours to give.

1. Purpose: security monitoring of AI agents, not performance measurement. State that summaries and activity will not be used for performance evaluation.
2. Legal basis and proportionality: why `minimal` is or is not sufficient for your risk.
3. Notice: who is told, when, and how (`spoor privacy show` output is a starting point).
4. Access: who can read findings; who holds the pseudonym key; how re-identification is approved and logged.
5. Retention at every hop: endpoint, Fleet, the log pipeline, the SIEM, cold storage.
6. Personal use: permitted or not, and which paths are excluded.
7. Rule governance: who can add rules, and how changes are reviewed.
8. Data subject requests: how access and erasure are handled downstream.
