# Rules

hawkbell's detections are rules in a small YAML language, evaluated on the endpoint over parsed facts about each record (the parsed shell command, path and host classes, session flags) rather than over raw text. This page covers the language, how to write, test and lint a rule, how rule content is signed and distributed, the catalogue of the packs that ship in the binary with links to their measured quality, and the few detections that are written by hawkbell's code rather than by a rule ([Detections that are not in a pack](#detections-that-are-not-in-a-pack)).

The authoritative reference for the language is the package comment of `internal/rules` (`go doc ./internal/rules`); this page follows it and the loader (`internal/rules/model.go`, `compile.go`). Records produced by rules are described in [EVENTS.md](EVENTS.md#detection-records).

## Where rules run

| Where | Which rules | Notes |
|---|---|---|
| `hawkbell run` (the daemon) | every enabled rule, on every record from every surface | The supported fleet mode. Findings, posture checks and summaries go through the privacy stage to the outbox and the state database. |
| `hawkbell hook` with `guard.mode: advisory` | the guard subset: rules with a `response`, plus the rules that set flags those rules require | Answers the agent `ask` (or `deny`, if a rule asks for `block` and `guard.max_response` allows it) on `tool.pre` and `prompt.submit`. Advisory: agents fail open on hook timeouts, and on Codex and Gemini CLI an `ask` is a non-blocking warning (the action proceeds). |
| `hawkbell hook` with `sources.hooks.detect_in_hook: true` | every rule | For daemonless use (containers, CI, evaluation); records are user-integrity. |
| `hawkbell detect` | every rule | Central re-evaluation of shipped records (with rules you do not publish), CI, benchmarks. |

Rule content is loaded in this order, and a later rule with the same id replaces an earlier one: the packs embedded in the binary (`internal/rules/packs/*.yaml` and `internal/rules/lists.yaml`), the installed signed bundle (`<data_dir>/bundle`, see [Signed bundles](#signed-bundles)), the directories in `rules.dirs` (root-owned and not group- or world-writable), and, for the CLI, `--dir`/`--rules` directories. `rules.disable` switches rule ids off. `--no-embedded` drops the embedded packs and `--no-host-rules` ignores the host's bundle and `rules.dirs`, so a command shows exactly the content you point it at.

Every finding is stamped with the content it came from (labels `rule_pack`, `rule_pack_version`, `rules_hash`, `rules_version`, `bundle_version`), and the heartbeat reports the rule count and hash, so a rule change is visible in every record it affects.

## Classes

Every rule has a class, chosen by how much attention a match deserves:

| Class | Meaning | Written by default |
|---|---|---|
| `signal` | Context: worth counting, not worth reading alone (a credential file was read; untrusted content entered the session). | no: counted into the session summary (`summary.detections`, `summary.flags`) |
| `finding` | Worth a look; may be legitimate. Broad rules are findings or signals. | yes |
| `alert` | Expected to be silent on ordinary developer work. Lint requires at least two negative tests, and the deduplication window is capped at 10 minutes and always includes the destination. | yes |

`rules.min_class` (default `finding`) is the lowest class written to the detection stream; `hawkbell detect --min-class` overrides it for one run. Repeats of one finding (same rule, session and `dedup` fields) inside `rules.suppress_for` (default 24 h in the configuration) are counted and carried on the next emission (`detection.count`) instead of being written again.

## The rule language

### Packs

A pack is one YAML document with `pack` (name), `version`, `description` and `rules`. Loading is strict: unknown keys, anchors, aliases, merge keys, custom tags, duplicate keys and a second document are errors; a pack is capped at 1 MiB and 500 rules, a YAML document at 64 levels of nesting; regular expressions are RE2, at most 1,000 characters. Two rules with the same id in one source are reported as a lint error (`duplicate_id`) and the later definition is used; across sources the later source wins silently, which is how a bundle overrides a shipped rule.

### Rule keys

| Key | Required | Values (default) | Meaning |
|---|---|---|---|
| `id` | yes | letters, digits, `.`, `_`, `-`; at most 64 | Shipped rules use `HB-<AREA>-<NNN>`. Use your own prefix. `HB-COV-9xx` and `HB-SCAN-*` are taken by ids hawkbell's code writes ([below](#detections-that-are-not-in-a-pack)); the loader does not stop a rule from using them, so do not. |
| `title`, `description` | | text | `title` becomes `detection.title`. |
| `kind` | | `activity` (default), `inventory` | Activity rules see activity records; inventory rules see `inventory.asset` records and produce `posture.check` records. |
| `class` | | `signal`, `finding` (default), `alert` | See [Classes](#classes). |
| `severity` | yes | `info`, `low`, `medium`, `high`, `critical` | |
| `confidence` | | `low`, `medium` (default), `high` | |
| `maturity` | | `stable`, `experimental` (default) | |
| `category`, `tags`, `references`, `falsepositives`, `remedy` | | text | `tags` carry framework ids in Sigma style: `attack.t1059.004`, `atlas.aml.t0050`, `owasp.asi05`, `owasp.mcp09`. |
| `when` | | predicate | Cheap prefilter. Its `type:` literals index the rule, so an event is only matched against rules that can apply to its type. |
| `match` | yes | predicate | The detection logic. |
| `allow` | | predicate | A match here vetoes the detection (allowlists). |
| `flags` | | `require`, `require_any`, `set` (lists of up to 32 names), `ttl` (`30m`), `scope` (`thread`, `session`) | Session state; this is how sequences are written (below). Names: lower-case letters, digits, `_ . : -`. `ttl` up to 30 days. |
| `threshold` | | `count` (1 to 256), `window` (0 to 30 days; 0 = no window), `by` (`session`, `user`, `host`) | Fire when `count` matches fall inside `window`, then restart the count. |
| `emit` | | `true` (default), `false` | `false`: the rule only maintains flags and writes nothing. |
| `escalate` | | `false` | Marks a finding worth a second opinion (`detection.escalate`). |
| `response` | | `none` (default), `ask`, `block` | What guard mode answers. Only `tool.pre` and `prompt.submit` can be answered. Lint refuses `block` in an embedded pack. |
| `dedup` | | field names (up to 32) | Added to the deduplication key (rule and session are always in it). |
| `evidence` | | field names (up to 32) | Fields copied into `detection.evidence`, through the privacy allowlist. |
| `novelty` | | `fields` (required), `raise` (`false`) | A first sighting of the field values adds the tag `hawkbell.first_seen` and, with `raise`, lifts the class one level. It can only add attention. |
| `tests` | yes | 1 to 64 tests | See [Tests](#tests). |

Evaluation per candidate rule: `when`, then `flags.require` / `require_any` against the session flags, then `match`, then `allow`, then `threshold`. A rule that fires sets its `flags.set` even when `emit` is false; flags set by an event take effect for later events only, so results never depend on rule order. Per-event evaluation has a deadline (150 ms by default, `guard.deadline` in the hook); when it expires with a guard rule still pending, the answer is at least `ask`.

### Predicates

`when`, `match` and `allow` are mappings. Several keys in one mapping are a conjunction; `all` and `any` take a list of mappings; `not` takes a mapping. A leaf is `field: value` (equality; a list value is any-of; on a list field, true when any element equals) or `field|modifier: value`:

| Modifiers | Meaning |
|---|---|
| `contains`, `icontains`, `startswith`, `endswith`, `re` | string tests (`re` is RE2; on a list field any element may match) |
| `in`, `contains_any`, `contains_all` | membership |
| `in_list`, `any_in_list` | membership in a named list from `lists.yaml`; `in_list` on a list field requires EVERY element to be listed, so one trusted host cannot vouch for another in the same command |
| `gt`, `gte`, `lt`, `lte`, `len_gt` | numbers and lengths |
| `exists` | presence (`exists: false` is the only test a missing field passes) |
| `cidr` | IP address in a network |
| `any_startswith`, `any_endswith`, `any_re`, `any_contains` | the string tests over the elements of a list field |

A missing field never matches; empty strings and empty lists count as missing. Incomplete lists fail closed: when a feature lost entries to a size cap it is named in `content.truncated_fields`, and `in_list` on it is false.

Two quantifiers bind several conditions to one item, which flat predicates over feature arrays cannot (measured: 3.3x to 3.6x over-matching on real sessions):

```yaml
any_command: {name|in: [rm], args|contains_any: ["-rf", "-fr"], args|any_startswith: ["/", "~"]}
any_install: {manager: npm, exec: true, packages|any_re: "^@evil/"}
```

`any_command` iterates the parsed commands (keys `name`, `path`, `args`, `origin`, `dynamic`); `any_install` iterates package installs (keys `manager`, `packages`, `global`, `exec`, `flags`).

### Fields

Rules see the record's own fields (`type`, `tool.kind`, `target.path`, `session.cwd`, `asset.telemetry.hooks` ...) and the features computed for it: `shell.*` facts from the parsed command (`shell.download_and_execute`, `shell.destructive`, `shell.hosts`, `shell.cred_access` ...), `path.*` and `net.*` classes, `mcp.*`, `write.*` (content being written), `content.*`, and the session state `session.*` (`session.flags`, `session.secret_flow`, `session.runs_written_file`). The list, with types and closed vocabularies, is the features registry in `internal/features/registry.go`; `hawkbell rules lint` rejects a field it does not know.

Path features hold one canonical spelling of each path (`internal/pathcanon`): `shell.reads`, `shell.writes`, `shell.deletes`, `shell.changes` (touch, mkdir, md, install -d, chmod and other changes that are not content writes, move sources, mount points), `shell.aliases` (what a new link or bind mount points at), `shell.executes_paths` and `path.targets` (the file tool's `target.path` and `target.paths`) are joined with a directory a `cd` on the same line set, have `.` and `..` resolved, duplicate separators collapsed and an unquoted one-character bracket glob (`[s]`) replaced by its character, and lose a `/proc/<id>/root` prefix (a pid, `self`, `$PID`, `$(...)`, `*`), which `shell.proc_root` and `path.proc_root` record. Windows paths also lose the trailing dots Win32 drops, and `\\localhost\C$\` becomes `C:\`. A rule that anchors a path regex matches these features, not `target.path` or the arguments in `shell.cmds`, which keep the operand as written. File-tool targets are joined with the session's working directory; shell paths are not, but the `shell.*_classes` features classify them with it. To match a location however it is spelled, including globs and paths relative to the session directory, use a path class: `sensor_self` is the sensor's own install locations, which HB-EVADE-002 matches beside its anchored list. Symlinks are not followed, except a link or bind mount made earlier on the same command line, through which an operand is recorded both as written and as the path it reaches.

The rule for the shipped packs, enforced by lint: shell rules match parsed facts, never the command text. `|re`, `|contains` and the other text modifiers on `target.command` are a lint error (`raw_command_match`); when a fact is missing, the feature is extended instead.

### Sequences

A sequence is two or more rules joined by flags. The first sets a flag (usually `class: signal`, often `emit: false`); a later rule requires it. Flags are kept per session thread: a flag set inside one subagent does not satisfy a requirement in another thread or in the parent, unless the setting rule has `flags.scope: session`. They expire after `ttl`. From the shipped `sequence` pack:

```yaml
  - id: HB-SEQ-001
    title: Untrusted input, credential read and egress in one thread
    class: signal
    when:
      type: [tool.pre, process.exec]
    flags:
      require: [untrusted_input, secret_read]
    match:
      any:
        - shell.exfil|exists: true
        - mcp.arg_hosts|exists: true
```

`untrusted_input` and `secret_read` are set by the flag-only rules HB-FLOW-001 and HB-FLOW-002. A finding of a sequence rule lists the flags it required (`detection.flags`) and the whole chain in `detection.event_ids`.

### Thresholds

From the shipped `destructive` pack, five destructive operations within two minutes in one session:

```yaml
    match:
      shell.destructive|contains_any: [rm_recursive_wildcard, find_delete, truncate_file, git_reset_hard, git_clean_force, kubectl_delete, kubectl_delete_namespace, cloud_delete, terraform_destroy, docker_prune_all, db_drop, db_truncate]
    threshold:
      count: 5
      window: 2m
```

Per-user and per-host counters (`by: user`, `by: host`) are bound to the identity the pipeline established (file owner, host), never to a name in the payload.

### Lists and suppressions

`lists.yaml` holds named lists (`{lists: {name: [entries]}}`) for `in_list` and `any_in_list`. Matching ignores case; `*.example.com` matches any subdomain of example.com (not example.com itself) and `prefix*` matches by prefix. A bundle replaces a list by name, so to extend a list ship the whole list.

Suppressions are operator exceptions, in the configuration (`rules.suppressions`) or in a bundle's `suppressions.yaml` (`{suppressions: [...]}`), with the same fields:

```yaml
rules:
  suppressions:
    - rule: HB-EXEC-001             # a rule id or a glob ("HB-NET-*", "*")
      match:
        shell.hosts: "get.example.net"   # field -> glob; every entry must match
      tags: [platform-eng]           # optional: only on hosts with one of these tags
      expires: "2027-01-31"          # RFC 3339 or YYYY-MM-DD; empty never expires
      reason: "vendor installer, reviewed in SEC-1234"
```

On a list field every element must match the glob, so an exception written for a trusted destination does not silence the same rule when an untrusted destination rides along; write the key as `field|any` to accept a list when any one element matches. A list named in `content.truncated_fields` never matches. Suppressed matches are counted (heartbeat `rules.suppressed_operator`).

### Tests

Every rule carries at least one inline test (at most 64). A test has a `name`, either one `event` or a list of `events` (up to 64, evaluated in order on one session, one second apart), and `expect: match` or `expect: no_match` for the last event. Optional: `content` (local-only material for the last event, such as tool input or file content being written), `feat` (feature values forced on the last event) and `flags` (session flags preset for the last event's thread). Events use the record's own field names in YAML flow style:

```yaml
    tests:
      - name: read, then delete
        events:
          - { type: tool.pre, tool: { kind: file_read, name: Read }, target: { path: /home/dev/.kube/prod-config } }
          - { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "kubectl delete deployment web" } }
        expect: match
```

`hawkbell rules test` runs each inline test on a fresh engine built from the whole set, so a test also sees the flags other rules set. Inline tests show that a rule does what it says; they are not a measure of its quality. That is what the benchmarks under `bench/` are for ([Measured quality](#measured-quality)).

## Writing, testing and linting a rule

Put your packs in a directory and point the commands at it. This pack (written for this page and run as shown) marks a thread that read the production kubeconfig and raises a finding on a later `kubectl delete`:

```yaml
pack: acme
version: "2026.11.1"
description: Example organisation rules.
rules:
  - id: ACME-KUBE-001
    title: Agent reads the production kubeconfig
    description: Marks the thread; ACME-KUBE-002 fires on a later delete.
    kind: activity
    class: signal
    severity: info
    category: discovery
    when:
      type: tool.pre
    match:
      target.path|endswith: /.kube/prod-config
    flags:
      set: [acme_prod_kubeconfig]
      ttl: 2h
    emit: false
    tests:
      - name: reads the file
        event: { type: tool.pre, tool: { kind: file_read, name: Read }, target: { path: /home/dev/.kube/prod-config } }
        expect: match
      - name: another kubeconfig
        event: { type: tool.pre, tool: { kind: file_read, name: Read }, target: { path: /home/dev/.kube/config } }
        expect: no_match

  - id: ACME-KUBE-002
    title: kubectl delete after the production kubeconfig was read
    description: >-
      A delete issued by an agent in a thread that read the production
      kubeconfig earlier.
    kind: activity
    class: finding
    severity: high
    confidence: medium
    category: impact
    tags: [attack.t1485]
    when:
      type: [tool.pre, process.exec]
    flags:
      require: [acme_prod_kubeconfig]
    match:
      any_command: { name: kubectl, args|contains: delete }
    evidence: [target.command]
    remedy: Ask the developer which cluster the delete was meant for.
    tests:
      - name: read, then delete
        events:
          - { type: tool.pre, tool: { kind: file_read, name: Read }, target: { path: /home/dev/.kube/prod-config } }
          - { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "kubectl delete deployment web" } }
        expect: match
      - name: delete without the read
        event: { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "kubectl delete deployment web" } }
        expect: no_match
      - name: the word delete in a commit message
        events:
          - { type: tool.pre, tool: { kind: file_read, name: Read }, target: { path: /home/dev/.kube/prod-config } }
          - { type: tool.pre, tool: { kind: shell, name: Bash }, target: { command: "git commit -m 'kubectl delete is gone'" } }
        expect: no_match
```

```
$ hawkbell rules test --no-host-rules --no-embedded --dir myrules
5 tests over 2 rules, 0 failed
$ hawkbell rules lint --no-host-rules --no-embedded --dir myrules
warning ACME-KUBE-001 [missing_field]: no framework tags
2 rules: 0 error(s), 1 warning(s)
$ hawkbell rules list --no-host-rules --dir myrules | grep -E '^(ID|ACME)'
ID              CLASS    SEVERITY  RESPONSE  PACK             ON   TITLE
ACME-KUBE-001   signal   info      none      acme             yes  Agent reads the production kubeconfig
ACME-KUBE-002   finding  high      none      acme             yes  kubectl delete after the production kubeconfig was read
```

Drop `--no-embedded` to test your rules together with the shipped ones (their flags interact). A rule that matches command text fails lint, and a test that does not hold fails the run; both exit 4:

```
$ hawkbell rules lint --no-host-rules --no-embedded --dir badrules
warning ACME-BAD-001 [missing_field]: description is empty
warning ACME-BAD-001 [missing_field]: category is empty
warning ACME-BAD-001 [missing_field]: no framework tags
warning ACME-BAD-001 [missing_field]: remedy is empty
error ACME-BAD-001 [raw_command_match]: match (line 12): |contains on target.command: match parsed facts (shell.*, any_command) instead of command text
1 rules: 1 error(s), 4 warning(s)
$ hawkbell rules test --no-host-rules --no-embedded --dir badrules
FAIL ACME-BAD-001 echo: got match, want no_match: when=true; match=true
2 tests over 1 rules, 1 failed
```

(`badrules/bad.yaml` matched `target.command|contains: terraform destroy`, so `echo terraform destroy` matched too.) Lint also reports unknown fields, literals outside a closed vocabulary, type mismatches, unknown lists, alert rules with fewer than two negative tests, responses on types that cannot be answered, `response: block` in an embedded pack, duplicate ids and rules with no effect; `--strict` fails on warnings too. All three commands take `--json`.

To try a rule on recorded activity, run `hawkbell detect --rules myrules <files>` over NDJSON (outbox or local-ring segments, hook spool files, numbat output). It exits 3 when a detection at or above `--fail-on` (default `high`) is found.

### Rules for the shipped packs

Contributions to `internal/rules/packs` follow the precision rules of the detection-quality review (see [ASSUMPTIONS.md](ASSUMPTIONS.md)):

- Shell rules match parsed facts only (enforced by lint). If a fact is missing, extend `internal/shellx` or `internal/features` rather than matching text.
- A rule may be class `alert` only if it is expected to stay silent on ordinary developer work, with at least two negative tests built from benign look-alikes. Co-occurrence (untrusted input, a secret read and egress in one thread) is a `signal`; the alert-class version requires the data flow itself (`session.secret_flow`).
- `untrusted_input` is not set by package registries, the organisation's own code hosts or documentation hosts (the lists).
- Deleting inside the working directory or a temp directory is never destructive; use the `shell.destructive` vocabulary.
- Only a handful of near-zero-false-positive rules get `response: ask` (seven today: HB-EXEC-001, HB-EXEC-008, HB-EVADE-001, HB-EVADE-002, HB-EVADE-003, HB-EVADE-009, HB-EXFIL-001); nothing ships with `response: block`.
- Give every rule framework tags from the standards research (omit an id when unsure; never invent one), references to the incident it comes from, false positives, a remedy, and at least one positive and two negative tests.
- Never put a credential in a provider's real format in a pack or test (see [CONTRIBUTING.md](../CONTRIBUTING.md#credential-literals)).

After editing anything under `internal/rules/packs` or `internal/rules/lists.yaml`, regenerate the pre-parsed copy that keeps guard-mode hook start-up fast, then run the package tests (they fail while the cache is stale, and check that every pack loads, passes its inline tests and lints without errors):

```
go generate ./internal/rules
go test ./internal/rules
```

`go run ./internal/rules/cmd/rulescache -dir internal/rules -check` reports a stale cache without writing anything (for CI). A stale cache is never wrong at run time, only slower: the binary parses the YAML instead. Then measure the change ([Measured quality](#measured-quality)) and regenerate the catalogue below.

## Signed bundles

Rules, lists, suppressions and catalog overlays reach hosts as an Ed25519-signed archive that each host verifies before installing it. There is no hawkbell server: the bundle and its detached signature are two static files at a URL you choose (`bundle.url`), or a file dropped on the host (air-gapped hosts, MDM). Versions only ever increase; hosts refuse a downgrade. The commands below were run as shown, with `hawkbell.yaml` holding `data_dir` and the printed `bundle.public_keys` entry; the key is the one that run made.

1. Make a signing key pair once, and keep the private key offline:

   ```
   $ hawkbell bundle keygen --out keys/acme-rules
   private key: keys/acme-rules.key (keep it offline)
   public key:  keys/acme-rules.pub
   key id:      f36c832922f644be

   bundle:
     public_keys:
       - 8kIRgxdY6cRWuk3ErQ+otIyhE4BrFN1tBcVFW/sFuDk=
   ```

   The private key file is written mode 0600; existing files are never replaced. Put the printed `bundle.public_keys` entry in every host's configuration.

2. Lay out the content (`rules/*.yaml`, `lists.yaml`, `suppressions.yaml`, `catalog/*.yaml`; all optional) and create the bundle. `SOURCE_DATE_EPOCH` (or `--created`) makes the archive reproducible:

   ```
   $ SOURCE_DATE_EPOCH=1794470400 hawkbell bundle create --src src --version 1 --key keys/acme-rules.key --out out/acme-rules-1.tar.gz --note "kubectl delete after prod kubeconfig"
   wrote out/acme-rules-1.tar.gz (956 bytes, 1 files, version 1) and out/acme-rules-1.tar.gz.sig
   ```

   `create` also proves that the archive passes the same verification every host runs.

3. Verify (the signature against the trusted keys, then the archive's structure and every file against the manifest). A changed byte or an untrusted key exits 4:

   ```
   $ hawkbell bundle verify --pub keys/acme-rules.pub out/acme-rules-1.tar.gz
   OK: version 1, created 2026-11-12T08:00:00Z, 1 files, digest c93ecb45ef7c
     rules/acme.yaml
   $ hawkbell bundle verify --pub keys/acme-rules.pub out/tampered.tar.gz     (one byte of the archive changed)
   INVALID: bundle: signature does not verify against any trusted key
   ```

4. Install: hosts with `bundle.url` set fetch `<url>` and `<url>.sig` every `bundle.interval` (default 1 h); `hawkbell bundle pull` does it now, and `--file` installs a local archive (its signature is `<file>.sig` unless `--sig` says otherwise). Pull verifies, checks that the rules and catalog overlays load, and installs under `<data_dir>/bundle` only when the version is newer than the installed one:

   ```
   $ hawkbell bundle pull --config hawkbell.yaml --file out/acme-rules-1.tar.gz
   installed bundle version 1 (1 files) under <data_dir>/bundle      (path shortened)
   $ hawkbell bundle pull --config hawkbell.yaml --file out/acme-rules-1.tar.gz
   bundle version 1 is current
   $ hawkbell rules list --config hawkbell.yaml | tail -1
   140 rules (140 enabled), content acme@2026.11.1,agent-integrity@2026.11.0,coverage@2026.11.0,credential@2026.11.0,defense-evasion@2026.11.0,destructive@…, hash 1be3db6b5bc2
   ```

   The running daemon picks the new content up without a restart, and the bundle version appears on every finding (`labels.bundle_version`) and in the heartbeat.

Treat the signing key like an access grant: whoever holds it decides what every host searches for. Rules can match on prompts and tool output locally; the evidence allowlist keeps that content out of `minimal` and `standard` output, but a finding still reveals that a pattern matched ([PRIVACY.md](PRIVACY.md), "Risks to weigh").

## Catalogue of the shipped packs

Generated from `hawkbell rules list --json` with the embedded packs only. Guard is the rule's `response` in guard mode; "flag only" rules (`emit: false`) write nothing and set session flags for other rules. Framework ids: ATT&CK techniques, MITRE ATLAS techniques, OWASP Top 10 for Agentic Applications (`ASI`) and OWASP MCP Top 10 (`MCP`). To regenerate, save this program as `catalogue.jq` and replace the generated block with its output:

```jq
def tags(p): [.Tags[]? | select(startswith(p)) | ltrimstr(p) | ascii_upcase] | join(", ");
.rules | group_by(.Pack)[] |
"### `\(.[0].Pack)` \(.[0].PackVersion) (\(length) rules)\n",
"| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |",
"|---|---|---|---|---|---|---|---|---|",
(.[] | "| \(.ID) | \(.Kind) | \(.Class)\(if .Emit then "" else ", flag only" end) | \(.Severity) | \(.Response) | \(.Title | gsub("[|]"; "\\|")) | \(tags("attack.")) | \(tags("atlas.")) | \(tags("owasp.")) |"),
""
```

```
go run ./cmd/hawkbell rules list --no-host-rules --json | jq -r -f catalogue.jq
```

<!-- BEGIN GENERATED: rule catalogue (hawkbell rules list --no-host-rules --json | jq -r -f catalogue.jq) -->

### `agent-integrity` 2026.11.0 (13 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-AGENT-001 | activity | finding | high | none | Agent writes a hook, auto-run task or always-applied rule | T1546 | AML.T0081 | ASI05 |
| HB-AGENT-002 | activity | finding | medium | none | Agent adds an MCP server to its configuration |  | AML.T0081, AML.T0110 | MCP09, ASI04 |
| HB-AGENT-003 | activity | finding | high | none | Agent widens its own permissions |  | AML.T0081 | ASI03, ASI05 |
| HB-AGENT-004 | activity | finding | high | none | Agent configuration points the model endpoint elsewhere |  | AML.T0083, AML.T0081 | ASI03 |
| HB-AGENT-005 | activity | signal | low | none | Model endpoint overridden on a command line |  | AML.T0083 |  |
| HB-AGENT-006 | activity | finding | high | none | Invisible Unicode written into an instruction, skill or configuration file | T1027.018 | AML.T0068, AML.T0080.000 | ASI06 |
| HB-AGENT-007 | activity | finding | high | none | Instruction-override text written into an instruction or skill file |  | AML.T0080.000, AML.T0051.001 | ASI06 |
| HB-AGENT-008 | activity | finding | medium | none | Agent CLI started with approvals disabled from inside a session |  | AML.T0053, AML.T0103 | ASI10 |
| HB-AGENT-009 | activity | finding | high | none | Git configuration written with a command-running key | T1574 | AML.T0081 | ASI05 |
| HB-AGENT-010 | activity | finding | medium | none | Session started in a downloads directory |  | AML.T0051.001, AML.T0100 | ASI01 |
| HB-AGENT-011 | activity | signal | low | none | Session running with approvals bypassed |  |  | ASI10 |
| HB-AGENT-012 | activity | signal | low | none | Another agent's session logs read |  | AML.T0085.002 | ASI03 |
| HB-AGENT-013 | activity | finding | medium | none | Instruction file read from a downloads directory |  | AML.T0051.001, AML.T0100 | ASI01 |

### `coverage` 2026.11.0 (7 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-COV-001 | inventory | finding | low | none | Installed agent without hawkbell's hooks |  | AML.T0138 |  |
| HB-COV-002 | inventory | finding | high | none | Agent hooks disabled or hawkbell's hook entry modified | T1685.007 |  | ASI10 |
| HB-COV-003 | inventory | signal | low | none | Agent session logs not where hawkbell reads them |  | AML.T0138 |  |
| HB-COV-004 | activity | finding | medium | none | Agent run with a flag that skips hook trust | T1685.007 |  | ASI10 |
| HB-COV-005 | activity | signal | low | none | Agent run without a session log |  | AML.T0138 |  |
| HB-COV-006 | inventory | finding | medium | none | Managed configuration path or state directory moved | T1685.007 |  | ASI10 |
| HB-COV-007 | inventory | signal | info | none | Managed policy missing or hooks not locked to managed |  |  | ASI10 |

### `credential` 2026.11.0 (13 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-CRED-001 | activity | finding | high | none | Credential file read after untrusted content | T1552.001 | AML.T0051.001, AML.T0098 | ASI01, ASI03 |
| HB-CRED-002 | activity | finding | medium | none | Private key or stored credential read by an agent tool | T1552.001, T1552.004 | AML.T0055 | ASI03 |
| HB-CRED-003 | activity | signal | low | none | Environment file, shell history or cluster credentials read | T1552.001, T1552.003 |  | ASI03 |
| HB-CRED-004 | activity | finding | high | none | Cloud instance metadata service contacted | T1552.005 | AML.T0055 | ASI03 |
| HB-CRED-005 | activity | signal | medium | none | Secret manager value or access token printed | T1528 | AML.T0098 | ASI03 |
| HB-CRED-006 | activity | finding | high | none | Environment variables dumped to a network destination | T1041 | AML.T0098, AML.T0086 | ASI03 |
| HB-CRED-007 | activity | finding | medium | none | Another process's environment read through /proc |  | AML.T0098 | ASI03 |
| HB-CRED-008 | activity | finding | high | none | AI agent credential store read | T1552.001 | AML.T0083 | ASI03 |
| HB-CRED-009 | activity | finding | high | none | Keychain, browser credential store or wallet accessed | T1555.001, T1555.003, T1539 |  | ASI03 |
| HB-CRED-010 | activity | finding | medium | none | Credential pasted into a prompt |  | AML.T0055 | ASI03 |
| HB-CRED-011 | activity | finding | medium | none | Credential written into an agent or MCP configuration file | T1552.001 | AML.T0083 | MCP01 |
| HB-CRED-012 | activity | signal | low | none | Credential literal on a command line | T1552.001 |  | ASI03 |
| HB-CRED-013 | activity | finding | medium | none | Kubernetes secrets listed across namespaces | T1552.007, T1119 |  | ASI03 |

### `defense-evasion` 2026.11.0 (12 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-EVADE-001 | activity | finding | high | ask | Security tool stopped or killed | T1685, T1685.007 |  | ASI10 |
| HB-EVADE-002 | activity | alert | critical | ask | Sensor files deleted or modified | T1685, T1685.007 | AML.T0138 | ASI10 |
| HB-EVADE-003 | activity | alert | critical | ask | Managed agent policy written or removed | T1685.007 | AML.T0081 | ASI10 |
| HB-EVADE-004 | activity | finding | medium | none | Agent hook configuration edited from the shell | T1685.007 | AML.T0081 | ASI10 |
| HB-EVADE-005 | activity | finding | high | none | Operating-system security control disabled | T1685, T1686 |  | ASI10 |
| HB-EVADE-006 | activity | finding | medium | none | Shell history or system logs cleared | T1070.003, T1690, T1685.006 | AML.T0138 |  |
| HB-EVADE-007 | activity | signal | medium | none | Sandbox switched off for a tool call | T1685.007 |  | ASI10 |
| HB-EVADE-008 | activity | finding | high | none | Agent configuration written to disable hooks or the sandbox | T1685.007 | AML.T0081 | ASI10 |
| HB-EVADE-009 | activity | alert | high | ask | Control file path spelled to evade matching |  | AML.T0081 | ASI05 |
| HB-EVADE-010 | activity | signal | low | none | Git hooks skipped |  |  | ASI02 |
| HB-EVADE-011 | activity | finding | high | none | Agent session log deleted or rewritten | T1070.004 | AML.T0138 | ASI10 |
| HB-EVADE-012 | activity | finding | high | none | Symbolic link planted to a sensitive file | T1098.004 |  | ASI05 |

### `destructive` 2026.11.0 (8 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-DESTR-001 | activity | alert | critical | none | Recursive delete of the filesystem root or a home directory | T1485 | AML.T0101 | ASI02 |
| HB-DESTR-002 | activity | alert | critical | none | Disk wiped, filesystem created or shadow copies deleted | T1485, T1490 | AML.T0101 | ASI02 |
| HB-DESTR-003 | activity | finding | high | none | Infrastructure or data store destroyed | T1485 | AML.T0101 | ASI02 |
| HB-DESTR-004 | activity | finding | medium | none | Shared git history force-pushed or rewritten | T1485 |  | ASI02 |
| HB-DESTR-005 | activity | finding | high | none | Burst of destructive commands | T1485 | AML.T0101 | ASI02 |
| HB-DESTR-006 | activity | finding | medium | none | Recursive delete in a system directory | T1485 |  | ASI02 |
| HB-DESTR-007 | activity | signal | low | none | Permissions opened recursively | T1222.002 |  |  |
| HB-DESTR-008 | activity | finding | high | none | Personal files deleted | T1485 | AML.T0101 | ASI02 |

### `execution` 2026.11.0 (9 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-EXEC-001 | activity | finding | high | ask | Remote script piped into an interpreter | T1059.004, T1105 | AML.T0050 | ASI05 |
| HB-EXEC-002 | activity | finding | high | none | Encoded payload decoded and executed | T1140, T1027, T1059 |  | ASI05 |
| HB-EXEC-003 | activity | finding | medium | none | Shell construct that defeats approval parsers | T1027, T1059.004 |  | ASI05 |
| HB-EXEC-004 | activity | finding | medium | none | Execution-sink environment variable set on a command | T1574.006, T1059.004 |  | ASI05 |
| HB-EXEC-005 | activity | finding | medium | none | Program option that runs an arbitrary command | T1059.004 |  | ASI05 |
| HB-EXEC-006 | activity | finding | high | none | Binary started through /proc/self/root or the dynamic loader | T1685.007 |  | ASI10 |
| HB-EXEC-007 | activity | signal | low | none | Command whose effect a static parse cannot see | T1027 |  | ASI05 |
| HB-EXEC-008 | activity | alert | critical | ask | Remote script from a throwaway or anonymous host piped into an interpreter | T1059.004, T1105 | AML.T0050 | ASI05 |
| HB-EXEC-009 | activity | finding | medium | none | Python run after a file named like a standard-library module was written | T1059.006 |  | ASI05 |

### `exfiltration` 2026.11.0 (13 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-EXFIL-001 | activity | alert | critical | ask | Credential read earlier in the session leaves in an outbound request | T1041, T1700 | AML.T0086 | ASI01, ASI02 |
| HB-EXFIL-002 | activity | finding | high | none | Data sent to a paste site, file share or request-capture host | T1567.003, T1567.004 | AML.T0086 | ASI02 |
| HB-EXFIL-003 | activity | signal | low | none | Exfiltration or tunnel host contacted | T1567.004, T1572 |  |  |
| HB-EXFIL-004 | activity | finding | high | none | DNS lookup with data in the hostname | T1048, T1071.004 | AML.T0086 |  |
| HB-EXFIL-005 | activity | finding | medium | none | Local file or stream uploaded to an unapproved host | T1041, T1048 | AML.T0086 | ASI02 |
| HB-EXFIL-006 | activity | signal | low | none | Copy to a remote host or bucket | T1048, T1567.002, T1537 |  |  |
| HB-EXFIL-007 | activity | finding | medium | none | Push to a git remote added in the same command or session | T1567.001, T1213.003 | AML.T0086 |  |
| HB-EXFIL-008 | activity | finding | medium | none | Repository or gist made public | T1567.001 | AML.T0086 | ASI02 |
| HB-EXFIL-009 | activity | signal | medium | none | Package published to a public registry | T1195.002 |  | ASI04 |
| HB-EXFIL-010 | activity | finding | medium | none | Tool result asks for a data-carrying image or link |  | AML.T0077, AML.T0051.001 | ASI01 |
| HB-EXFIL-011 | activity | finding | medium | none | Literal AI provider key sent to the provider's API | T1567 | AML.T0086 | ASI02 |
| HB-EXFIL-012 | activity | finding | medium | none | MCP tool call carries a credential |  | AML.T0086 | MCP01, ASI02 |
| HB-EXFIL-013 | activity | signal | low | none | Value from an earlier broad read leaves in an outbound request | T1041 | AML.T0086 |  |

### `offensive` 2026.11.0 (8 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-OFFSEC-001 | activity | finding | medium | none | Offensive security tool run from an agent session |  | AML.T0103 | ASI02 |
| HB-OFFSEC-002 | activity | alert | critical | none | Reverse shell | T1059.004 | AML.T0050 | ASI05 |
| HB-OFFSEC-003 | activity | signal | low | none | Local service exposed through a tunnel | T1572, T1090 |  |  |
| HB-OFFSEC-004 | activity | finding | medium | none | Pivoting relay or anonymiser started | T1572, T1090 |  |  |
| HB-OFFSEC-005 | activity | signal | low | none | Container started with host-level privileges | T1611, T1609 |  |  |
| HB-OFFSEC-006 | activity | finding | high | none | Host root or host PID namespace entered from a container command | T1611 |  | ASI03 |
| HB-OFFSEC-007 | activity | alert | critical | none | Credential dumping tool or LSASS dump |  | AML.T0055 | ASI03 |
| HB-OFFSEC-008 | activity | signal | low | none | Burst of reconnaissance commands | T1082, T1057 |  |  |

### `persistence` 2026.11.0 (7 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-PERS-001 | activity | finding | medium | none | Shell startup file modified | T1546.004 |  | ASI05 |
| HB-PERS-002 | activity | alert | high | none | SSH authorized_keys modified | T1098.004 |  | ASI03 |
| HB-PERS-003 | activity | finding | medium | none | Scheduled job, service or login item registered | T1053.003, T1053.005, T1543.001, T1543.002, T1547.001 |  | ASI05 |
| HB-PERS-004 | activity | signal | low | none | Git hook installed or removed |  |  | ASI05 |
| HB-PERS-005 | activity | finding | high | none | Python startup hook written |  |  | ASI05 |
| HB-PERS-006 | activity | finding | high | none | Sudoers, setuid or setgid change | T1548.003, T1548.001 |  | ASI03 |
| HB-PERS-007 | activity | finding | medium | none | Package manager pointed at a different registry | T1195.001 |  | ASI04 |

### `posture` 2026.11.0 (21 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-POST-001 | inventory | finding | high | none | Agent hook fetches or decodes code | T1546 | AML.T0081 | ASI05 |
| HB-POST-002 | inventory | finding | high | none | Project hook runs a script from the repository | T1546 | AML.T0081 | ASI04, ASI05 |
| HB-POST-003 | inventory | finding | high | none | Repository auto-run launcher | T1546 | AML.T0081 | ASI04 |
| HB-POST-004 | inventory | finding | high | none | Configuration escalates agent permissions |  | AML.T0081 | ASI03, ASI05 |
| HB-POST-005 | inventory | finding | high | none | Model endpoint overridden in configuration |  | AML.T0083 | ASI03 |
| HB-POST-006 | inventory | finding | medium | none | IDE executable path points into the workspace |  | AML.T0081 | ASI05 |
| HB-POST-007 | inventory | finding | high | none | Command-running key in a repository git config | T1574 | AML.T0081 | ASI05 |
| HB-POST-008 | inventory | finding | medium | none | MCP server launched from an untrusted location |  | AML.T0110 | MCP09, ASI04 |
| HB-POST-009 | inventory | finding | medium | none | Credential written inline in an MCP declaration | T1552.001 | AML.T0083 | MCP01 |
| HB-POST-010 | inventory | signal | low | none | MCP server fetched and run unpinned at every launch |  | AML.T0109 | MCP04, ASI04 |
| HB-POST-011 | inventory | finding | low | none | MCP server reached over plaintext HTTP |  |  | MCP07 |
| HB-POST-012 | inventory | finding | medium | none | MCP server container with host privileges | T1611 |  | MCP02 |
| HB-POST-013 | inventory | finding | critical | none | Managed agent policy writable by non-administrators | T1222.002 | AML.T0081 | ASI03 |
| HB-POST-014 | inventory | finding | high | none | Invisible Unicode in an instruction, skill or command file | T1027.018 | AML.T0068 | ASI06 |
| HB-POST-015 | inventory | finding | high | none | Instruction or skill file carries a dropper or injection text |  | AML.T0011.002, AML.T0110 | ASI04 |
| HB-POST-016 | inventory | finding | medium | none | Instruction file downloaded from the internet |  | AML.T0051.001, AML.T0100 | ASI01 |
| HB-POST-017 | inventory | finding | high | none | CI workflow runs an AI agent on untrusted triggers | T1677 | AML.T0051.001 | ASI03 |
| HB-POST-018 | inventory | finding | low | none | Approvals off by default in agent settings |  |  | ASI10 |
| HB-POST-019 | inventory | finding | high | none | Agent version with a known execution or exfiltration fix missing |  | AML.T0109 | ASI04 |
| HB-POST-020 | inventory | signal | low | none | MCP server or skill definition changed |  | AML.T0109 | MCP04 |
| HB-POST-021 | inventory | finding | medium | none | Agent service listens beyond loopback |  |  | MCP07 |

### `process` 2026.11.0 (6 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-PROC-001 | activity | alert | critical | none | Headless agent with approvals disabled launched by a package install script | T1195.002 | AML.T0053, AML.T0098 | ASI04 |
| HB-PROC-002 | activity | finding | high | none | Agent CLI launched by a package install script | T1195.002 | AML.T0053 | ASI04 |
| HB-PROC-003 | activity | signal | low | none | Agent running with approvals disabled |  |  | ASI10 |
| HB-PROC-004 | activity | finding | medium | none | Agent started by another agent with approvals disabled |  | AML.T0053, AML.T0103 | ASI10 |
| HB-PROC-005 | activity | alert | high | none | Agent launched by a browser or URL handler with inline configuration |  | AML.T0081 | ASI05 |
| HB-PROC-006 | activity | signal | low | none | Agent CLI started with inline settings JSON |  | AML.T0081 |  |

### `sequence` 2026.11.0 (15 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-FLOW-001 | activity | signal, flag only | info | none | Untrusted content entered the session | T1698 | AML.T0051.001 | ASI01 |
| HB-FLOW-002 | activity | signal, flag only | info | none | Credential material read | T1552.001 | AML.T0055 |  |
| HB-FLOW-003 | activity | signal, flag only | info | none | Tool call refused |  |  | ASI10 |
| HB-FLOW-004 | activity | signal, flag only | info | none | File named like a Python standard-library module written | T1059.006 |  |  |
| HB-FLOW-005 | activity | signal, flag only | info | none | Instruction-override text in a tool result | T1698 | AML.T0051.001 | ASI01 |
| HB-FLOW-006 | activity | signal, flag only | info | none | Several credential reads in a short window | T1119, T1552.001 |  |  |
| HB-FLOW-007 | activity | signal, flag only | info | none | Agent control file written outside the working directory |  | AML.T0081 |  |
| HB-FLOW-008 | activity | signal, flag only | info | none | Credential source read (for the data-flow alert) | T1552.001 | AML.T0055 |  |
| HB-SEQ-001 | activity | signal | medium | none | Untrusted input, credential read and egress in one thread | T1041 | AML.T0086 | ASI01 |
| HB-SEQ-002 | activity | finding | high | none | Auto-run configuration written after untrusted input | T1546 | AML.T0081, AML.T0051.001 | ASI05 |
| HB-SEQ-003 | activity | finding | high | none | Evasion attempt after a refused tool call | T1685.007 |  | ASI10 |
| HB-SEQ-004 | activity | finding | high | none | Bulk credential reads followed by egress | T1119, T1041 | AML.T0086 | ASI02 |
| HB-SEQ-005 | activity | finding | medium | none | Instruction or memory file written after untrusted input |  | AML.T0080.000 | ASI06 |
| HB-SEQ-006 | activity | finding | high | none | Sensitive action after instruction-override text in a tool result | T1698 | AML.T0051.001 | ASI01 |
| HB-SEQ-007 | activity | finding | high | none | Push after agent control files were written in another repository | T1195.002 | AML.T0081 | ASI04 |

### `supply-chain` 2026.11.0 (6 rules)

| ID | Kind | Class | Severity | Guard | Title | ATT&CK | ATLAS | OWASP |
|---|---|---|---|---|---|---|---|---|
| HB-SUPPLY-001 | activity | alert | critical | none | Worm indicator file written or run | T1195.002 | AML.T0010.005 | ASI04 |
| HB-SUPPLY-002 | activity | alert | critical | none | Package from an incident report installed | T1195.002, T1204.005 |  | ASI04 |
| HB-SUPPLY-003 | activity | finding | medium | none | Install from an unapproved registry or index | T1195.001 |  | ASI04 |
| HB-SUPPLY-004 | activity | signal | low | none | Package installed straight from a URL or git repository | T1195.001 |  | ASI04 |
| HB-SUPPLY-005 | activity | signal | info | none | Package fetched and run in one step | T1195.002 |  | ASI04 |
| HB-SUPPLY-006 | activity | finding | medium | none | Worm indicator named on a command line or inventory file written | T1195.002 | AML.T0010.005 | ASI04 |

<!-- END GENERATED: rule catalogue -->

## Detections that are not in a pack

Three ids are written by hawkbell's own code, not by a rule, so `hawkbell rules list`, `hawkbell rules test` and the catalogue above do not show them, and neither `rules.disable` nor suppressions apply to them. The `HB-COV-9xx` range is reserved for the engine (`internal/engine`, `coverage.go`) and `HB-SCAN-` for the inventory scanner (`internal/discovery`, `trust.go`).

| ID | Record | Class, severity | Written when |
|---|---|---|---|
| `HB-COV-901` | `detection.finding` | finding, high (confidence medium) | Hook bypass suspected. All three hold for one session: the process monitor (a root-observed surface, not one the user can write) currently sees the agent running for that account; hooks are expected for that agent and account; and at least 3 of the session's tool calls (distinct tool-call ids) reached hawkbell from the transcript or OpenTelemetry and had no hook record when their 10-second hold for a hook twin ran out, or the agent's OpenTelemetry reported at least 3 more tool-hook runs than hawkbell received hook records. A hook record that arrives later takes its call off the count. At most one per session. |
| `HB-COV-902` | `detection.finding` | signal, low (confidence low) | The same, but no root-observed process backs it (self-reported surfaces only). A signal: with the default `rules.min_class` it is not written, and it is counted in `summary.detections`. At most one per session. |
| `HB-SCAN-001` | `posture.check` | high when another account wrote the file, medium when only its permissions let other accounts write it | The scan refused to read an agent configuration file inside an account's home (the home itself or a project below it) because neither the account nor root owns it, someone else can write it, or it is a root-owned file with more than one link in another account's home. The file is reported as a `project_config` asset with the risk flag `untrusted_owner`, the check says what was expected (`owned by the account or root and writable by nobody else`) and what was found, and hawkbell does not read the file until it is fixed. Past 64 refused files in one directory or 256 for one account, one more check with the title "More agent configuration files written or writable by other accounts" counts the rest (high when any of them was written by another account). |

"Hooks are expected" means, in the daemon, that discovery's hook state for the agent and account (`asset.telemetry.hooks`) is `managed`, `user` or `modified`. Without discovery, as in `hawkbell detect`, hooks count as expected once they have delivered for that agent and account before, and a root-observed process is a root-integrity `agent.process.start` record from the process monitor or osquery in the input (an unprivileged pipeline keeps no record at root integrity, so it can only write the signal).

The two hook-bypass records carry:

- `detection`: the title (`Hook bypass suspected: a root-observed agent made tool calls its hooks did not report`, or `Agent tool calls without hook records (self-reported surfaces only)`), category `coverage`, maturity `experimental`, tags `attack.t1562.001` (Impair Defenses: Disable or Modify Tools) and `hawkbell.coverage`, `event_ids` with up to 16 of the unmatched tool calls, `count: 1`, and the remedy "Run `hawkbell hooks status` for this user and agent; check for a higher-precedence managed settings source, a removed or edited hook entry, or an agent started in a hook-free mode."
- labels `hooks_state` (the hook state discovery reported), `surfaces` (the surfaces that reported the session, comma-separated), `unmatched_tool_calls`, `otel_hook_mismatch` and `root_observed` (`true` or `false`), plus `rules_hash`, `rules_version` and `bundle_version` like any finding, but no `rule_pack` or `rule_pack_version`.
- `integrity`: the pipeline's own for `HB-COV-901` (`root` when it runs privileged, as the daemon does), `user` for `HB-COV-902`; `source: sensor`, `fidelity: inferred`. Like a rule's finding of class `finding` or above, `HB-COV-901` is followed by `detection.context` records (up to `privacy.context_events` of the session's last records).

Findings relayed from another sensor are not rules either: numbat findings read with `hawkbell detect --format numbat` (or a configured adapter) keep numbat's verdict, with `rule_id` `numbat:<numbat rule id>` (a `:` cannot occur in a hawkbell rule id), `source: adapter` and `class: finding`; hawkbell does not re-evaluate them.

## Measured quality

Inline tests prove a rule does what it says. How well the packs detect real attack mechanics, and how often they fire on ordinary work, is measured separately and committed under [`bench/results/`](../bench/results/). Per-rule figures are in those files; read them with their limits, which each file states.

- [`scenarios.md`](../bench/results/scenarios.md) ("Per rule", "Per technique"): a synthetic corpus written from the incident mechanics in the project's threat research, 100 attack scenarios covering 48 incident rows and 84 benign look-alikes, with mutations of every shell command (quoting, `$IFS`, `sh -c`, variable assembly, an interpreter one-liner, write-then-run). It reports plain recall 95/100 = 95.0% [88.8, 97.8], robust recall (detected under every applicable mutation) 94/100 = 94.0% [87.5, 97.2], benign look-alikes with an alert-class hit 0/84 = 0.0% [0.0, 4.4] and with a finding-class hit 5/84 = 6.0% [2.6, 13.2], each with a Wilson 95% interval. The corpus was written by the same project that wrote the rules (not blind), so its recall is an upper bound, and cells with fewer than 30 trials are marked insufficient.
- [`benign-replay.md`](../bench/results/benign-replay.md) ("Per rule", "Sampled hits", "Review of the numbers"): the rules replayed over real Claude Code sessions on one machine (94 transcript files of one root session, 5,337 tool calls, the agents that built and red-teamed this project), every sampled hit labelled false positive, red-team experiment or rule bug, with the before/after table of the tuning. After tuning, no false-positive alert in 5,337 tool calls (Wilson 95% upper bound 0.72 per 1,000) and every finding-class rule under 5 hits per 1,000 tool calls. One workload, one machine: it bounds benign rates for this workload only and says nothing about prevalence.
- [`live-benign-replay.md`](../bench/results/live-benign-replay.md): the same rules over a later snapshot (106 threads, 6,522 tool calls). It was not regenerated after the rename: it and `live-benign-replay.json` keep the old name and rule ids.

Reproduce the scenario numbers with `go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out <dir>` (or `make bench`, which also runs the benchmark's gate test); the replay command is at the end of `benign-replay.md`. The committed replays read session logs recorded before the rename from the working name spoor to hawkbell and add `-old-name` to that command; the committed reports were also checked against the reports made before the rename with `-renamed-from` (see the package comment of `internal/bench/cmd/benchrun`).
