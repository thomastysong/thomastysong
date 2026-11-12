> **Historical design record.** Red-team review of design v0, privacy and sensor-security lens (A26 to A29, A32, A34).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:15 UTC on the build machine; it says "Date: 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (1 place). Kept: the invented passwords and host names of the redaction test in E2 (`Sommer2026!`, `db.internal` and the like); none has a provider's credential format.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: privacy + sensor security (A26, A27, A28, A29, A32, A34)

Reviewer persona: privacy counsel + appsec engineer gating a rollout to 10,000 EU/US employee machines.
Date: 2026-11-11. Design attacked: `design/v0.md` (sections 3-9, 11).

## Scope note (read first)

The task asked for attack proofs of concept for at least two items (session_id file-name traversal, link-following root reader).
I did NOT write attack PoCs. A first attempt at this review was interrupted, so every experiment here is a defensive
conformance check or a measurement: harmless temp files, invented credentials, standard library only. The design facts the PoCs
were meant to establish are still established (E6 shows the unvalidated join leaves the state dir and that a plain open follows
a link while `os.Root`/`O_NOFOLLOW` refuse), but nothing here is a working exploit against a spoor binary, because no spoor
binary exists yet. Treat F4 and F5 as "mechanism shown at API level", not "exploit demonstrated".

Legal references (GDPR articles, BetrVG, US state statutes, EDPB guidance) are from reviewer knowledge and were not
re-verified against primary texts inside this sandbox. A real counsel must confirm them before the article cites them.

Working files: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/redteam/pss-work/`
(`py/privacy_checks.py`, `go/main.go`, `atc/conf.json`, `atc/state.db`).
Shared stack: untouched. osquery was used only as a private shell (`osqueryd -S --config_path=<mine>`), binary
`rt-fleetop/bin/osqueryd` (the `dl/osquery/...` path in ENV.md no longer exists).

---

## Experiments

### E1. Unkeyed prompt hash is a lookup key, not a pseudonym (A26, A29)

`python3 -I py/privacy_checks.py` (first half). A 1,600-entry dictionary (20 verbs x 20 objects x 4 casings) built in 1.0 ms:

```
emitted sha256=8a798890fe938171.. len=  3 -> recovered: 'yes'
emitted sha256=94e74ef526c8bcab.. len= 13 -> recovered: 'Fix the tests'
emitted sha256=e256ee8e7aff6957.. len=  8 -> recovered: 'continue'
emitted sha256=483ad913da58ee0d.. len= 13 -> recovered: None
emitted sha256=5a86c380f0428413.. len= 22 -> recovered: 'revert the last change'
emitted sha256=12a8466ecb66d900.. len= 73 -> recovered: None
dictionary: 1600 candidates built in 1.0 ms; recovered 4/6
with per-tenant HMAC key held off-endpoint: 0 recovered
single-core python rate: 2.74 M sha256/s (GPU rigs are ~1e9-1e10/s)
equality leak: same prompt on two hosts -> 8a798890fe938171 == 8a798890fe938171
```

Reading: design section 8 emits "hashes + lengths for prompts" in the default tier. The emitted length cuts the candidate
space further (a dictionary only needs entries of that exact length). Identical hashes across users and across tenants link
people who typed the same thing. With an HMAC key the same dictionary recovers nothing.

### E2. "Secret patterns + entropy" redaction on command lines (A29)

Strawman redactor = 9 common patterns (AWS, GitHub, sk-, Slack, JWT, PEM, `key=value`, Authorization header, `--password X`)
plus Shannon entropy >= 4.0 on tokens >= 20 chars. All secrets invented.

```
LEAK | mysql -u root -pSommer2026! -h db.internal prod
LEAK | curl -u alice:Winter2026 https://api.internal/v1/users
LEAK | sshpass -p 'Berlin#1989' ssh deploy@10.0.0.5
ok   | psql [REDACTED:entropy]
ok   | git clone [REDACTED:entropy]
LEAK | docker login -u ci -p Tr0ub4dor registry.internal
ok   | export PG[REDACTED]
LEAK | 7z a -pFamilyDog2019 backup.7z ~/Documents
LEAK | openssl enc -aes-256-cbc -k letmein -in a -out b
LEAK | curl -H 'X-Auth: 7f3a9c1e' https://svc.internal/
LEAK | redis-cli -a s3cr3t-cache ping
ok   | kubectl create secret generic db [REDACTED:entropy]
ok   | echo [REDACTED:entropy] | base64 -d
ok   | curl [REDACTED:entropy]
ok   | aws configure set aws_secret_access_key [REDACTED:entropy]
ok   | curl -H '[REDACTED] https://api.example.com
ok   | [REDACTED] ./run.sh
leaked 8/17 invented secrets
benign -> git checkout 3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e
benign -> docker pull [REDACTED:entropy]
benign -> cat [REDACTED:entropy]
```

Reading:
- Human-chosen passwords in short-flag, attached-flag and `user:pass` forms pass both the pattern and the entropy test (8/17).
- Hex strings top out at exactly 4.0 bits/char, so a 40-hex API token is not caught by an entropy threshold above ~3.9
  (the 40-hex git SHA line survived untouched; a token of the same shape would too).
- Where it did fire, it destroyed detection fields: the whole `git clone` URL (host gone), the whole `psql` DSN (host gone),
  a `@sha256:` image pin and a plain file path were replaced. Redaction and the host/path classifiers in design section 5
  fight each other unless redaction is structural.
- Caveat: this is my strawman, not spoor's redactor (none exists). The mechanism (entropy cannot see low-entropy secrets;
  generic patterns cannot see tool-specific flags) is independent of the strawman. uber/ADR's own flag-list scrubber has
  documented misses of the same class (`research/adr-discovery.md:157`).

### E3. encoding/json on agent-supplied JSON (A27)

`cd go && go run .`

```
nesting depth 9999   -> typed decode err=invalid character '[' exceeded max depth
nesting depth 10001  -> typed decode err=invalid character '[' exceeded max depth
nesting depth 200000 -> typed decode err=invalid character '[' exceeded max depth
keys command/Command/COMMAND -> struct sees "THIRD" (exact-case key was "ls")
duplicate key command -> struct sees "second"
64 MiB Write payload -> decode err=<nil> in 346ms, Go heap Sys 138 -> 202 MiB
```

Node 22.23.4 (the runtime family the agents use) on the same nesting:

```
node JSON.parse depth 10001 ok; re-stringify -> stringify: RangeError
node JSON.parse depth 50000 ok; re-stringify -> stringify: RangeError
node JSON.parse depth 200000 ok; re-stringify -> stringify: RangeError
python json depth 10001 RecursionError
```

Reading:
- Go's struct decoding matches keys case-insensitively and the last match wins. A payload object that carries both
  `command` and `Command` is read differently by a JS consumer (exact key) and by a Go struct. What spoor inspects can
  differ from what the agent acts on. Whether each agent's tool-input schema rejects extra keys was NOT tested (no agent
  binaries here); MCP tool arguments are free-form, so at least that path is open.
- Go rejects total depth above 10,000; Node parses 200,000. Node could not re-stringify that depth, so an agent that
  serialises the hook payload with `JSON.stringify` may itself fail first: the depth differential is real but its
  reachability through a specific agent is unverified.
- A 64 MiB payload costs at least its own size in heap, against the design's "< 50 MB RSS" (A22).

### E4. RE2 cost and limits (A27; YAML rule packs)

```
1 MiB payload x 10 patterns: 290ms  => 200 rules x same cost ~ 6s
8 MiB payload x 10 patterns: 2.275s  => 200 rules x same cost ~ 46s
compile (a{1000}){1000}: error parsing regexp: invalid repeat count: `{1000}`
compile a{1001}: error parsing regexp: invalid repeat count: `{1001}`
compile (a+)+$: <nil> (accepted; linear at match time)
compiling 300 medium rule regexes at process start: 77ms (paid on EVERY daemonless hook exec), heap Sys 203 MiB
```

Reading:
- Classic catastrophic backtracking does not exist in Go `regexp` (RE2 semantics); counted repeats above 1000 are
  refused at compile time. That part of A27 HOLDS.
- What remains: cost is linear in input size times pattern count. Ten ordinary patterns over 1 MiB took 290 ms on this
  box. The "200 rules" figures are a straight extrapolation (x20), not a measurement. A `Write` tool call carries the
  whole file in `tool_input.content`, so multi-megabyte hook stdin is normal traffic, not an attack.
- Compiling 300 mid-size regexes costs 77 ms per process start, which is 16x the design's quoted p99 of 4.7 ms for the
  daemonless hook (design section 7). The 203 MiB figure is cumulative for the whole test process, not for compilation alone.
- Hook timeouts fail open (`research/agent-surfaces-a.md:23-25`: Copilot 30 s and always fail-open; Claude fail-open
  unless `onFailure:"block"`), so an evaluation that overruns is an allow.

### E5. NDJSON framing (A27, log injection)

```
marshalled: {"command":"echo a\n{\"kind\":\"detection\",\"forged\":true}\r\n\u001b[2K  bad-utf8:��"}
raw newline bytes in output: 0, ESC bytes: 0, lines: 1
round-trip byte-identical to original command: false
```

Reading: with `encoding/json` a value cannot split a line or smuggle terminal escapes: newline, CR, ESC and U+2028 are all
escaped. Line injection HOLDS (provided no code path ever builds a line with `fmt`). Residual: invalid UTF-8 is silently
replaced with U+FFFD, so the emitted command is not the bytes that ran and any hash computed downstream will not match.

Related, from the evidence base rather than a rerun: Fluent Bit `tail` defaults `buffer_max_size` to 32k and "a line longer
than `buffer_max_size` makes Fluent Bit stop monitoring the file unless `skip_long_lines: on`" (`research/fluentbit.md:31`,
run-verified there with a 1.5 MB line). The metadata tier keeps full commands, so one long heredoc command produces such a line.

### E6. File-name confinement conformance (A27, A28)

Harmless temp dir; `state/` is the pretend per-session state dir, `elsewhere/marker.txt` is a file outside it.

```
id="0f9c2c0e-7a51-4f0c-9d5e-1b2c3d4e5f60"  unvalidated join stays inside state dir: true  | allow-list validator accepts: true
id="../elsewhere/marker"                   unvalidated join stays inside state dir: false | allow-list validator accepts: false
id="a/b"                                   unvalidated join stays inside state dir: true  | allow-list validator accepts: false
id="..\\x"                                 unvalidated join stays inside state dir: false | allow-list validator accepts: false
id=""                                      unvalidated join stays inside state dir: true  | allow-list validator accepts: false
id="CON"                                   unvalidated join stays inside state dir: true  | allow-list validator accepts: true
id="aaaa...(300)"                          unvalidated join stays inside state dir: true  | allow-list validator accepts: false
link inside state dir -> plain os.ReadFile err=<nil> (follows it)
os.Root.Open(link) err=openat link.json: path escapes from parent
os.Root.Open(../..) err=openat ../elsewhere/marker.txt: path escapes from parent
open(O_NOFOLLOW) err=too many levels of symbolic links
blocking open of a FIFO named like a transcript: still blocked after 1.5s (a tailer goroutine would hang)
O_NONBLOCK open returns at once; fstat regular file: false -> reject
```

Reading:
- `filepath.Join(stateDir, session_id + ".json")` leaves the directory for an id containing `../`. `session_id` arrives on
  hook stdin (`research/agent-surfaces-a.md:41-44`) and the design builds a "per-session state file" from it (section 7).
- Test artefact: the `..\x` row says "false" on Linux only because my prefix check is crude; on Linux that name stays
  inside the directory, on Windows the backslash is a separator and it would not.
- A character allow-list is not enough for a cross-platform binary: `CON` passes it and is a reserved device name on
  Windows; 300 characters exceeds NAME_MAX. Deriving the file name from a hash of the id avoids every case.
- A plain open follows a link placed in a directory the writer controls; Go 1.24 `os.Root` and `O_NOFOLLOW` refuse.
  `O_NOFOLLOW` only guards the last path component, `os.Root` guards all of them.
- A blocking open of a FIFO never returns, so a transcript tailer needs `O_NONBLOCK` plus an `fstat` regular-file check.

### E7. osquery ATC over a state DB whose writer is not trusted (A28, SQL injection)

Private osquery shell, my own config and DB:

```
state.db: table real_posture(check_id,status,detail) with rows
            ('hooks_intact','fail','managed hook file missing')
            ('note','info', "x'); drop table real_posture; -- \" ' ; select 1")
          view  spoor_posture = select 'hooks_intact','pass','synthetic row from a view'
conf.json: auto_table_construction.spoor_posture.query = "select check_id,status,detail from spoor_posture"

$ osqueryd -S --config_path=atc/conf.json --disable_extensions --disable_events --json "select * from spoor_posture; select * from real_posture; ..."
{"check_id":"hooks_intact","detail":"synthetic row from a view","path":".../atc/state.db","status":"pass"}
{"check_id":"hooks_intact","detail":"managed hook file missing","path":".../atc/state.db","status":"fail"}
{"check_id":"note","detail":"x'); drop table real_posture; -- \" ' ; select 1","path":".../atc/state.db","status":"info"}
{"n":"1"}
after query: (2,) [('table','real_posture'), ('view','spoor_posture')]
```

Reading:
- SQL injection through ATC data HOLDS: metacharacters come back as data and the table is intact. (Precondition on our
  side: spoor's own writes use bound parameters.)
- ATC does not care whether the name in its configured query is a table or a view. Whoever can write the DB file decides
  what Fleet policies see, and schema objects stored in that file are evaluated inside osqueryd, which runs as root.
- Observed on the shared stack, read-only: the prototype state DB is `644 root:root` in a `755` directory
  (`fleetstack/atc/state.db`, `-wal`, `-shm`). Fine for a prototype; the design text never states a mode.

### E8. Licence inventory (A34)

- uber/ADR: `LICENSE` is Apache-2.0; `Sensor/LICENSE` and `Detection/LICENSE` are byte-identical to it
  (sha256 `4584e0de...`); `Discovery/` has no LICENSE file of its own but `Discovery/pyproject.toml:7` says
  `license = { text = "Apache-2.0" }`. Appendix line: "Copyright 2024 ADR Project Contributors".
- `NOTICE.md` (Markdown, not a plain `NOTICE`) lists third-party material only under `Detection/`: AgentDojo (MIT),
  a YAML `!include` gist (MIT), a Stack Overflow snippet (CC BY-SA 3.0) in
  `Detection/benchmark/agentdojo/benchmarks/agentdojo/yaml_loader.py`, OpenAI type re-definitions (Apache-2.0),
  and two arXiv papers used as fixtures (CC BY 4.0).
- `Discovery/adr_discovery/catalog/catalog.json`: 37 entries, keys `fingerprints,id,kind,name,proofs,risk_factors,vendor`;
  no licence header or third-party provenance field inside the file.
- Planned Go dependencies, licence files read from the module cache / proxy:
  - `mvdan.cc/sh/v3 v3.14.1`: BSD-3-Clause, no NOTICE.
  - `modernc.org/sqlite v1.62.0`: BSD-3-Clause + `LICENSE-SQLITE` (public domain) + `LICENSE-SQLITE_VEC` +
    `LICENSE-3RD-PARTY.md`. That file states the only copyleft-adjacent licence in the graph is MPL-2.0
    (`hashicorp/golang-lru/v2`) and that it is "in the module graph, not compiled into anything".
  - `modernc.org/libc v1.80.1`: BSD-3-Clause, bundles musl (MIT) notices.
  - `github.com/osquery/osquery-go`: MIT; pulls `github.com/apache/thrift v0.23.0` (Apache-2.0, has a `NOTICE`).
  - `github.com/shirou/gopsutil/v4 v4.26.10`: BSD-3-Clause; pulls `ebitengine/purego` (Apache-2.0),
    `go-ole` (MIT), `yusufpapurcu/wmi` (MIT), `tklauser/go-sysconf` (BSD-3).
  - `gopkg.in/yaml.v3 v3.0.1`: MIT + Apache-2.0, has a `NOTICE`. Upstream README (fetched from
    raw.githubusercontent.com today) opens with "THIS PROJECT IS UNMAINTAINED". `go.yaml.in/yaml/v3 v3.0.5`
    (the maintained fork, same licences) is already in the module cache.
- Nothing in that list is incompatible with shipping under Apache-2.0. Obligations that follow: reproduce BSD/MIT
  notices with binary releases; carry the thrift and yaml NOTICE content (Apache-2.0 section 4(d)).

---

## Findings (most damaging first)

### F1. A26 BROKEN (critical): the "metadata" tier is identified behavioural monitoring, and the product has no controls a works council or DPIA will ask for

Mechanism. The default envelope (design section 4) carries `user{name,id}`, `host{name}`, `session{cwd}`, `repo{...}`,
`target{command,path,url,host,query}` and a fractional timestamp for every tool call. Section 8 confirms "commands and
paths kept". That is not metadata in any legal sense:
- `user.name` + `ts` on every action is a per-employee activity and working-time log.
- `cwd` and `path` embed the OS username and project or client names (the E2 path example).
- `command` is free text: commit messages, emails in `git config`, search terms in `grep`, inline scripts.
- `target.query` is the web-search query, i.e. prompt-derived content, shipped in the tier that claims "no prompt text".
- `target.url` carries query strings; `repo` remotes reveal personal repositories.
- "Detections carry a redacted evidence snippet": content leaves the endpoint in every tier.
- Section 8 says tiers "control what is EMITTED, not what detection sees locally". Local scanning of full prompts and
  tool output by an employer-installed root daemon is itself processing (GDPR Art. 4(2)), including whatever special
  category data people type into prompts.

Legal pressure points (unverified here, see scope note): GDPR Art. 5(1)(a)-(c),(e), Art. 6(1)(f) balancing (consent is
not usable in employment), Art. 13 notice, Art. 25, Art. 35 DPIA (systematic monitoring + employees + new technology);
Germany BetrVG s.87(1) no.6 (co-determination is triggered by a tool being objectively capable of monitoring behaviour
or performance; intent is irrelevant) and BDSG s.26; France Code du travail L1222-4 and L2312-38; Italy Statuto dei
Lavoratori Art. 4; ECtHR Barbulescu v. Romania (prior notice of nature and extent); US: New York Civil Rights Law
s.52-c, Connecticut Gen. Stat. s.31-48d, Delaware 19 Del. C. s.705 (written notice of electronic monitoring), CPRA
employee data rights (notice at collection, retention disclosure, access/deletion).

Missing product controls: an employee-facing transparency command, per-path/per-repo exclusion, handling of personal
accounts on a managed machine (managed-tier hooks fire for a personal subscription too), user pseudonymisation,
documented retention, a DPIA template.

Minimal change:
1. Add an egress profile `detections-only` and make it the default: only `detection`, `inventory`, `posture`, `health`
   leave the host; `activity` stays in a local ring buffer (default 24 h) and is attached to a detection as context.
   Full `activity` streaming becomes an explicit opt-in.
2. Field-level emit policy instead of three coarse tiers; in the default profile emit `argv0` + flag names + computed
   feature classes, not `command`; emit path class + basename hash, not `path`; never emit `target.query`.
3. `user.name` replaced by a keyed pseudonym by default (see F2), re-identification through a separately held key.
4. `exclude: {paths, repos, accounts}` evaluated before any content processing; excluded sessions produce one counter
   in `health`, nothing else.
5. `spoor privacy show` (what is collected on this machine, in which profile, where it goes, how long it is kept) and
   `spoor privacy tail` (the employee sees their own emitted events). Ship a DPIA and works-agreement template in docs.

### F2. A26/A29 BROKEN (high): unkeyed hashes are reversible for short prompts and link users across hosts and tenants

Evidence: E1 (4 of 6 sample prompts recovered from a 1,600-entry dictionary built in 1 ms; 0 with HMAC). Without a
secret kept apart from the data, this is not pseudonymisation in the GDPR Art. 4(5) sense, and since `user.name` sits in
the same event the record is plainly personal data anyway. The same applies to any hash of a secret found in an MCP
config: a hash of a low-entropy password is an offline guessing oracle.

Minimal change: every content-derived digest is `HMAC-SHA-256(tenant_key, value)` truncated to 96 bits, with `key_id` in
the event; key delivered through Fleet (agent options secret or a root-only file), rotated on a schedule. No digest at
all below 32 characters; emit a length bucket (`<16, <64, <256, ...`) instead of exact length. Never emit any digest of a
detected secret value: emit name, location and type only (ADR's "names, never values", `research/adr-discovery.md:134`).

### F3. A29 BROKEN (high): pattern + entropy redaction leaks ordinary credentials and wrecks detection fields

Evidence: E2 (8/17 invented secrets survive; hex tokens sit at or below the entropy threshold; over-redaction removed
hosts, an image digest and a path). ADR's flag-list scrubber misses the same class (`research/adr-discovery.md:157`).

Minimal change: redact structurally on the shell AST the design already plans to build (mvdan.cc/sh). Ship a per-tool
argument table (`mysql -p`, `curl -u/-H`, `sshpass -p`, `docker login -p`, `redis-cli -a`, `7z -p`, `openssl -k/-pass`,
URL userinfo, assignments to sensitive variable names) and make the default allow-list based: for a tool not in the
table emit `argv0` + flag names only. Keep pattern/entropy as a second pass. Add a canary corpus to CI and publish the
measured leak rate and over-redaction rate per release instead of the claim "good enough".

### F4. A27 BROKEN (high): a root daemon opens paths chosen by the users it monitors

Mechanism. Daemon mode is root-owned (section 7, 9) and (a) tails transcripts inside each home directory, (b) scans homes
and a "user-extensible drop-in dir" for catalog entries, (c) receives `transcript_path` on hook stdin
(`research/agent-surfaces-a.md:29,41-44`), (d) walks `/proc/<pid>/root` in the DaemonSet. Every one of those trees is
writable by the monitored user or container. E6: a plain open follows a link and a FIFO blocks the reader forever. A root
reader that follows a user-placed link and then emits hashes, lengths, "redacted evidence snippets" or posture findings
about what it read is a confused deputy: it moves root-only content into an event stream. A user-written catalog drop-in
that names paths to inspect has the same effect without any link.

Minimal change:
1. Never open a path taken from hook stdin. `transcript_path` is recorded as a claim only; the tailer derives locations
   from the catalog and the session's uid.
2. Per-user reads run in a worker that has dropped to that uid (setuid worker on Linux/macOS, impersonation on Windows),
   so the kernel does the access check.
3. Inside that worker: `os.Root` per home (or `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`; `RESOLVE_IN_ROOT`
   for `/proc/<pid>/root`), `O_NONBLOCK|O_NOFOLLOW`, then `fstat`: regular file, owner == session uid, size and
   line-length caps.
4. Catalog and rule drop-ins load only from root-owned, not group/world-writable directories, checked on the open fd
   (the rule Copilot applies to `policy.d`, `research/agent-surfaces-a.md:100`).

### F5. A28 BROKEN (high): in daemonless mode the monitored user owns the evidence, the state and the file names

Mechanism.
- Section 7: without a daemon the hook "evaluates rules in-process against a per-session state file and appends to a
  per-user spool file". Both are written with the user's own privileges, so the user can edit, truncate or pre-seed
  them. The trifecta flags (`untrusted_input`, `secret_read`) live in a file the subject can reset.
- "Fluent Bit ships within seconds" assumes Fluent Bit is running and caught up; nothing in the design detects otherwise
  for this mode, and a per-host monotonic `seq` cannot exist with one independent writer per user.
- The Fleet bundle's policies ("no critical detections in 24h", "hooks intact", "sensor healthy") read the state DB via
  ATC. E7: ATC serves a view as if it were the table and evaluates schema from the file inside root osqueryd. If any
  daemonless code path writes that DB as the user, those policies are self-attestation. If no such path exists, then
  `spoor_detections`/`spoor_sessions` are empty in this mode and section 7's table overstates what it gives.
- E6: the per-session file name comes from `session_id` on stdin; an unvalidated join leaves the directory, and a
  character allow-list still passes Windows reserved names.

Minimal change: (1) stamp every event with `integrity: user|root` and state in docs that `user` events are advisory;
(2) the ATC state DB is written only by root contexts (scan timer, daemon), mode 0600 in a 0700 directory, and Fleet
policies never depend on user-integrity data; (3) spool layout `/var/lib/spoor/spool/<uid>/` created by the installer,
0700, owned by that uid, files opened `O_APPEND|O_NOFOLLOW`; (4) `seq` and a `prev` hash per (host, writer) so
truncation and edits are visible downstream; (5) state file name = `hex(sha256(uid|agent|session_id))[:32]`, opened
through `os.Root`.

### F6. A27 BROKEN (high): per-event cost scales with attacker- and user-sized input; the quoted 4.7 ms is the empty-rule case

Evidence: E4 (290 ms for 10 patterns over 1 MiB; 2.3 s over 8 MiB; 77 ms just to compile 300 regexes per process), E3
(64 MiB payload adds 64 MiB of heap). Normal `Write` calls already carry megabytes. Timeouts fail open
(`research/agent-surfaces-a.md:23-25`), so oversize input is both a user-visible stall and, in guard mode, an allow.
RE2 removes exponential blow-up; it does not remove linear cost times rule count.

Minimal change: a hard input budget in `spoor hook`. Stream-decode with per-field caps; scan the first and last 64 KiB of
any field and stream-hash the rest; emit `truncated: true, size, digest`; a literal prefilter (Aho-Corasick over rule
literals) before any regex; a wall-clock deadline (default 150 ms) after which guard mode answers `ask`, never `allow`,
and a `hook.budget_exceeded` detection is emitted. Daemonless hook loads a precompiled rule cache keyed by pack hash
instead of compiling YAML. `spoor rules lint` enforces a per-rule cost budget (ns/KiB) in CI. Rule packs: size cap,
reject YAML aliases, `KnownFields(true)`.

### F7. A27 WEAKENED (high): Go's JSON decoder does not read the payload the way the agent does

Evidence: E3. Case-insensitive key matching with last-wins (`command`/`Command`/`COMMAND` -> "THIRD"), duplicate keys
last-wins, depth limit 10,000 vs Node parsing 200,000. A decode error in a fail-open hook means no event at all.
Restriction on this verdict: reachability through each agent's own schema validation and serialiser was not tested.

Minimal change: decode hook stdin with a case-sensitive, duplicate-rejecting tokenizer (`encoding/json/v2`+`jsontext`
when stable, or a small hand-rolled pass). Before full parsing, always emit a minimal record from raw bytes (size,
digest, peer uid/pid). Duplicate keys, case-variant keys and depth overflow each raise `hook.payload_anomaly`; guard
mode answers `ask`.

### F8. A27 WEAKENED (medium): the daemon socket check is neither authentication nor portable

Mechanism. "SO_PEERCRED ... verify the caller's parent is a known agent" (section 7): `SO_PEERCRED` is Linux-only (macOS
needs `LOCAL_PEERCRED`/`LOCAL_PEERTOKEN`; Windows AF_UNIX exposes no peer credentials, so a named pipe is required).
Parent lookup by pid is racy, and any local user can start the genuine agent or the genuine `spoor hook` with input of
their choosing, so the check proves nothing about content. The socket must be connectable by every user, so every local
account can submit unlimited events. If session state is keyed by `session_id` alone, one user's events can set or
consume flags in another user's session, since the id is just a string from stdin. Not tested live (no daemon exists).

Minimal change: key all state by (peer uid, agent, session_id). Record kernel-derived `peer{uid,pid,exe}` next to, not
instead of, the self-reported fields, and make no trust decision on the parent check. Per-uid token bucket, per-uid
spool quota, 16 MiB frame cap, read deadline, connection cap. Windows: named pipe with an explicit SDDL and client
impersonation. Drop "SO_PEERCRED" from the cross-platform contract in section 7.

### F9. A26 WEAKENED (medium): retention and access to the local stores and to Fleet's copy are undefined

Evidence. Section 6: segments are "pruned by age/size"; A23: "retention caps"; no defaults anywhere. The state DB holds
`spoor_sessions` (user, cwd) and `spoor_detections` (evidence). Prototype mode observed: 0644 in a 0755 directory (E7),
i.e. readable by every local account on a shared host. Through ATC the same rows are readable by any Fleet user allowed
to run queries, and Fleet keeps the latest result per host per report (`research/fleet.md:184`: `report_cap` default
1000, `discard_data` per report), which is a second personal-data store with its own lifetime. "No server of our own"
does not mean no central copy. GDPR Art. 5(1)(e) and Art. 30 need stated periods.

Minimal change: ship defaults and print them in `health`: spool 72 h or 256 MB; sessions 7 d; detections 30 d;
per-session state deleted at `session.end` or after 24 h. State DB 0600/0700 root. ATC tables expose ids, rule ids,
severities and counts only; no command, cwd or evidence columns. The Fleet bundle sets `discard_data: true` on every
report over sessions/detections. Add `spoor privacy purge --user <u>` for erasure requests.

### F10. A27 WEAKENED (medium): line and SQL injection hold; long lines and lossy text do not

Tried and failed to break: newline/ESC/U+2028 in a value (E5: escaped, one line); SQL metacharacters through ATC (E7:
returned as data, table intact). Both hold provided all emission goes through the JSON encoder and all writes use bound
parameters.
What remains: (1) one event line above Fluent Bit's 32k default makes `tail` drop the line or stop monitoring the file
(`research/fluentbit.md:31`); the default tier keeps unbounded commands, so this is reachable by typing a long command.
(2) Invalid UTF-8 is replaced silently (E5), so the emitted command is not what ran.

Minimal change: cap every emitted line (16 KiB), overflow fields become `{truncated, size, digest}`; shipped Fluent Bit
config sets `skip_long_lines: on` and `buffer_max_size` above the cap; `health` counts truncations. For non-UTF-8 input
emit `lossy: true` plus a digest of the raw bytes.

### F11. A34 WEAKENED (low): catalog reuse is clean only with three conditions, and it buys less than assumed

Evidence: E8. Apache-2.0 covers `Discovery/` and the catalog; no third-party notices attach to them. Conditions:
(1) keep the Apache-2.0 text, mark the converted YAML as modified, credit uber/ADR and record the upstream commit
(section 4(a)-(c)); (2) do not lift anything from `Detection/benchmark/agentdojo/` into the repo: it carries a
CC BY-SA 3.0 snippet and CC BY 4.0 fixtures, which matters if the benchmark corpus borrows ADR-Bench material;
(3) Apache-2.0 section 6 grants no trademark rights, so say "compatible with uber/ADR's skill folder hash", not a name
that implies endorsement. Reimplementing the hash algorithm is unproblematic. Usefulness: 37 entries with zero Windows
identifiers (`research/adr-discovery.md:6`) is under half of the 80-product goal.
Dependencies: all permissive and compatible (E8). Obligations: bundle third-party licence texts with every binary
(BSD-3 clause 2, MIT), carry thrift's and yaml's NOTICE. `gopkg.in/yaml.v3` is declared unmaintained upstream.

Minimal change: generate `THIRD_PARTY_LICENSES` in release CI (go-licenses) and embed it behind `spoor licenses`; add a
`NOTICE` with the ADR credit and the thrift/yaml notices; switch to `go.yaml.in/yaml/v3`; add a CI licence allow-list
(Apache-2.0, MIT, BSD-2/3, ISC, public domain) that fails on anything else entering the compiled graph.

### F12. A32 HOLDS (low): never executing discovered binaries is the right call for a root sensor; one restriction

What I tried: looked for a way the rule forces a worse security or privacy outcome. Found none. The alternatives all
execute user-controlled code: agent-bom `--introspect` spawns each stdio server (`research/agent-bom.md:58`); snyk
agent-scan needs per-server consent and a `--dangerously-run-mcp-servers` flag for CI (`research/snyk-agent-scan.md:122,166`).
A root daemon doing that across every home directory would turn any writable MCP config into code run by the sensor.
The cost is real (no tool-description scanning), and the reused ADR catalog contains `version_probe: ["--version"]`
fields (`research/adr-discovery.md:86,96`), which is execution by another name.
Restriction: the rule must be stated as "no exec of any discovered path, including version probes", enforced by a test
that fails the build if the scan/daemon packages import `os/exec`. Tool descriptions can be collected passively where
an agent already exposes them (hook payload `mcp_server{name,source}`, transcripts), never by starting a server.

---

## Not done / limits

- No attack PoCs (see scope note). F4, F5, F8 are argued from the design text plus API-level checks.
- No agent binaries in the sandbox: F7's reachability through real agent schema validation is open.
- Windows and macOS behaviour (named pipes, reserved names, ACLs) is from knowledge, not tested; this box is Linux.
- The E2 redactor is a strawman; the E4 "200 rules" numbers are extrapolations.
- Legal citations not verified against primary texts here.
