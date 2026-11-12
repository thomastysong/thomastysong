# Security policy

spoor is security software that runs as root on developers' machines and reads input an attacker can control (agent hook payloads, transcripts, configuration files, command lines). Reports of weaknesses in it are welcome.

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion for a vulnerability.

- **Where:** GitHub's private vulnerability reporting for this repository, at <https://github.com/thomastysong/spoor/security/advisories/new> (the repository's **Security** tab, **Report a vulnerability**). The report and its discussion are visible only to you and the maintainers until an advisory is published. It needs a GitHub account.
- **If you cannot use it:** open an issue that asks for a private contact and says nothing about the problem itself; a maintainer will answer with one.
<!-- VERIFY (maintainer): private vulnerability reporting has to be switched on in the repository settings (Code security, Private vulnerability reporting) for the link above to work; this could not be checked from the build environment. Add a security e-mail address above as well if you want one. -->

Please include the spoor version (`spoor version`), the operating system and architecture, the deployment mode (daemon, `spoor scan` with the state database, daemonless hook, container, CI), the privacy profile, and the smallest input that shows the problem. Do not send real credentials, real prompts or real transcripts: build synthetic ones (a high-entropy string in a `password=` or `token=` context is enough for anything about redaction). If the issue concerns another project spoor reads or ships to (an agent, osquery, Fleet, Fluent Bit), say so; we will coordinate with that project rather than publish a workaround alone.

What to expect: an acknowledgement, an assessment against the list below, a fix in the next release for anything in scope, and credit in the release notes unless you prefer otherwise. Response times are not promised while the project has a single maintainer.

## Supported versions

spoor is pre-1.0. Only the latest release receives security fixes; there are no backports to earlier releases. The record schema (`v: 1`, [docs/EVENTS.md](docs/EVENTS.md)) and the configuration format may still change between minor releases; breaking changes are called out in the release notes.

| Version | Security fixes |
|---|---|
| latest release | yes |
| anything older | no: upgrade |

Windows and macOS builds are cross-compiled from the same code, and the unit tests run on Linux. Behaviour on Windows and macOS hardware has not been verified ([docs/LIMITATIONS.md](docs/LIMITATIONS.md)); reports from those platforms are especially useful.

## Trust model

1. **spoor is not a tamper-proof control.** Someone who controls the endpoint can run an agent hook-free, transcript-free, renamed and with a scrubbed environment. spoor detects careless and unmodified abuse, supply-chain worms and commodity infostealers; it raises the cost for a targeted evader on their own machine and does not stop them.
2. **Everything a user-writable surface delivers is a claim.** Hooks, transcripts, vendor OpenTelemetry and other sensors' files are written by processes the monitored user controls; their records are stamped `integrity: user` whatever they say. The root daemon accepts only activity claims from a hook spool (never findings, health, inventory or posture), takes the user and host from the file owner rather than the payload, and runs detection itself.
3. **The root-owned outbox is the only thing that ships.** Fluent Bit tails the daemon's outbox (root-owned, readable by one group); the per-user hook spool and the local activity ring are never tailed. Only `integrity: root` records, from the daemon's own scan and process monitor, should back a Fleet policy.
4. **Guard mode is advisory.** Every agent's hook timeout fails open, and some agents treat "ask" as a non-blocking warning, so a stalled or killed hook means "allow". A crash or timeout of the hook's worker never blocks the agent: the supervisor answers with an allow-shaped reply in observe mode (or "ask" in guard mode) and exits 0. <!-- VERIFY: guard-mode exit code is receiving an integration fix (CLI fixer, CSI-7); re-check against internal/hookcmd before release. -->
5. **Rule content and keys carry authority.** Rules, lists and suppressions arrive as Ed25519-signed bundles with no downgrade, or from root-owned directories; whoever holds the signing key decides what every host looks for. The tenant HMAC key is present on every endpoint, so keyed digests protect against readers of the log store and against cross-tenant linkage, not against root on the endpoint.

The reasoning and the experiments behind each point are in [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).

## What we treat as a vulnerability

- A user-writable surface (hook spool, transcript, OTel receiver, adapter input, project file) gets a record accepted as `integrity: root`, as a kind other than activity, or attributed to another user or host.
- The sensor, running privileged, follows a symbolic link or opens a path out of the tree it was asked to read, blocks on a FIFO or other special file, opens a path taken from hook input, executes a discovered binary or starts an MCP server.
- A secret value, prompt text, tool input or tool output leaves the host in the `minimal` or `standard` profile, through any field, label, evidence entry, context record, id or digest; or an unkeyed digest of content is shipped in any profile. (Redaction of free text is heuristic and documented as such; a missed pattern in `full` output is a bug, not necessarily a vulnerability. Report it either way.)
- The hook blocks or stalls the agent: any non-zero exit, a wait beyond its deadline, or output on stderr, in any input condition other than an outside signal killing the supervisor.
- A rule bundle is installed without a valid signature from a trusted key, or an older bundle replaces a newer one.
- A record breaks the one-object-per-line format, exceeds the encoded line cap, or otherwise makes Fluent Bit stop reading or drop a segment; or the outbox is pruned of records a configured consumer had not read without the `health.error` that reports it.
- Hostile input (payload, transcript, configuration, rule pack) makes the sensor crash, hang, or use memory or CPU beyond the bounds the code documents.
- The osquery extension or the state database lets a non-root user change what Fleet sees, or Fleet's fail-closed policies pass on a host whose sensor is absent or stale.
- Any path by which an unprivileged user escalates privileges through spoor's files, directories, service units or packages.

## What is not a vulnerability

These are documented limits, not bugs. Detection misses and false positives are bugs: report them as ordinary issues, with a synthetic reproduction.

- Evasion by the person who controls the endpoint (point 1 above), and everything listed as not visible in [docs/LIMITATIONS.md](docs/LIMITATIONS.md): runtime-assembled commands, write-then-run across sessions, effects of code the agent wrote, MCP-over-stdio payloads and model traffic, microVM and remote agents.
- Guard mode failing open on an agent's hook timeout.
- A user forging activity claims about their own sessions (they are user-integrity by design); a user clearing their own state in daemonless mode, where the hook's session state lives in a file that user can write.
- Free-text credentials that are not recognisable ("my password is x"), and secrets transformed by something the redactor cannot decode, as listed under "Known gaps" in `go doc ./internal/privacy`.
- Someone with root on the endpoint reading the tenant key, the identity key or the local state.
