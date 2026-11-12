# Limitations

This file lists what spoor does not see, does not prevent, and has not been tested on. It exists because the nearest alternatives publish coverage matrices but not blind spots, and because a detection tool that overstates its reach is worse than none. Each item comes from the red-team review recorded in [ASSUMPTIONS.md](ASSUMPTIONS.md).

## What spoor is not

- **Not a tamper-proof control.** Hooks, transcripts and vendor OpenTelemetry are all written by the agent, which runs as the developer. Someone who controls the endpoint can run an agent hook-free, transcript-free, renamed and with a scrubbed environment. spoor detects careless and unmodified abuse, supply-chain worms and commodity infostealers; it raises the cost for a targeted evader on their own machine and does not stop them.
- **Not prevention.** Guard mode answers pre-tool hooks with "ask" or "deny", but every agent's hook timeout fails open (Copilot CLI always, others by default), so stalling the hook converts a block into an allow. Guard mode is advisory.
- **Not an EDR.** It has no kernel sensor of its own. Where the organisation runs osquery evented tables, or an EDR, spoor provides join keys (host, pid, process start time, ancestor chain) rather than replacing them.
- **Not an LLM judge.** Detection is deterministic. Whether an instruction file is manipulative, or whether the user actually asked for a deletion, needs a judge; findings that would benefit from one are tagged `escalate` and nothing more.

## Not visible from the surfaces spoor uses

| Blind spot | Why | What would see it |
|---|---|---|
| Commands assembled at runtime (`eval` of concatenated strings, interpreter one-liners, heredocs built from character codes, payloads fetched and decoded at runtime) | a static parse of the command line cannot recover text that only exists when the shell runs | syscall and network observation (osquery evented tables, eBPF, Endpoint Security, ETW). spoor flags the construct itself as opaque. |
| A script written in one session and executed in another | write-then-run is correlated within a session only | file integrity monitoring |
| Effects of code the agent wrote (what `python build.py` opened or connected to) | hooks report intent, not effect | exec, file and socket events from a kernel sensor |
| Exfiltration from inside a process with no child process | nothing is spawned | network monitoring |
| MCP-over-stdio payloads and model traffic | hooks carry tool names and arguments, not the protocol stream | an MCP or LLM gateway |
| Tool descriptions of MCP servers (tool poisoning, rug pulls of the tool list) | spoor never starts an MCP server or runs a discovered binary; it hashes the declaration, not the live tool list | a proxy, or a scanner that executes servers (with the risks that brings) |
| Short-lived child processes when no exec feed is available | a 1 s poll saw 7 of 120 short processes in testing | the Linux process connector (used when permitted) or osquery evented tables (used when the organisation has them on) |
| Agents running in vendor clouds (Claude Code cloud sessions, Codex cloud, Cursor background agents, Copilot coding agent) | they do not run on your endpoints | the vendor's own audit and compliance APIs |
| Agents inside microVM or user-space-kernel sandboxes (Docker Sandboxes, Apple `container`, gVisor, Kata, Firecracker), and inside WSL2 or Docker Desktop / Colima / OrbStack VMs on macOS and Windows | the host cannot see into the guest | an in-guest install |
| Remote development (SSH, Codespaces, devcontainers on another host) | the laptop runs an IDE, the agent runs elsewhere | an install where the agent runs |
| Which account an agent is signed in with (corporate, personal, raw API key) | hooks and transcripts do not report it; vendor OpenTelemetry does | enabling the agent's own telemetry |
| A managed hook that the agent silently ignores | Claude Code uses only the highest-ranked managed source by default, so a file drop is ignored when an MDM profile, a registry policy or a server-managed policy exists; server-managed policy cannot be seen from disk | spoor reports hooks as effective only after a real hook event arrives, and reports `shadowed` when it can see a higher-ranked source |

## Integrity limits

- Records produced by hooks are marked `integrity: user`. A process running as the developer can append arbitrary activity claims about its own sessions. It cannot inject findings, health or inventory, and it cannot attribute activity to another user, because the root daemon takes identity from file ownership and re-runs detection itself.
- In daemonless mode (containers, CI, evaluation) there is no root component: every record is user-integrity and nothing a Fleet policy depends on should be derived from it.
- A tenant HMAC key lives on every endpoint. Keyed digests protect against readers of the log store and against cross-tenant linkage, not against root on the endpoint.
- Sequence numbers and heartbeats detect loss between the sensor and the destination. They do not prove that a record's content is true.

## Delivery limits

- At-least-once delivery holds only with the shipped Fluent Bit configuration (filesystem buffering, unlimited retries). With Fluent Bit defaults, records read but not yet delivered are lost on restart. `spoor doctor` checks for this when it can reach the Fluent Bit API.
- Duplicates are possible. Record ids are deterministic so that destinations can deduplicate.
- A record is capped at 16 KiB after encoding. Larger fields are cut and listed in `truncated`.
- If the local hard cap forces dropping records the shipper has not read, a health record says how many.

## Platforms

Everything in this release was built and exercised on Linux x86-64. For macOS and Windows the code cross-compiles and its unit tests cover the platform-independent logic; **no behaviour has been verified on macOS or Windows hardware.** The following must be tested there before any parity claim, and are not claimed today:

Windows
1. Hook latency per agent and launch path (Claude exec form, Git Bash, PowerShell; Codex `pwsh -NoProfile -Command`; Gemini and Copilot PowerShell) with Defender real-time protection on, signed and unsigned.
2. The generated hook command for a path with spaces in each shell, with and without Git for Windows; Claude Code's behaviour when a shell-form hook fails and Git Bash is absent (documented to block).
3. Directory ACLs under `%ProgramData%`, including a standard user pre-creating the directory before install.
4. A LocalSystem service reading user profiles: logged-off users, redirected or roaming AppData, FSLogix containers, OneDrive placeholders.
5. Reading another process's environment (native x64, arm64, emulation, sandbox children) and how EDR products react to it.
6. That no file handle held by spoor blocks an agent's rename or compaction of its own files.
7. The SMBIOS-derived host id against osquery's `system_info.uuid` on physical and virtual machines.
8. WDAC, AppLocker and Smart App Control with an unsigned binary.
9. WSL2: agents inside WSL are not covered by a Windows install.

macOS
1. A root LaunchDaemon without Full Disk Access reading `~/.claude`, `~/.codex`, `~/Library/Application Support/{Cursor,Code,Claude}`, project files under `~/Documents` and `~/Desktop`, iCloud Drive and app containers.
2. A Privacy Preferences Policy Control profile for Full Disk Access against an unsigned or ad hoc signed binary (there is no stable code identity without a Developer ID).
3. Process environment visibility for agent binaries that are code-signing restricted.
4. launchd behaviour, fast user switching and multi-user attribution.
5. Hook behaviour of each agent's real binary, including managed preference domains versus files.

Unverified agent facts (vendor documentation was unreachable from the build environment, or only one release was tested): all Cursor hook payload details; whether Codex hooks fire identically under `codex exec` and the IDE extension; Claude Code managed hooks under `--bare` on releases other than the one tested.

## Kubernetes and containers

- The node sensor supports runc-class runtimes (containerd, CRI-O, Docker) on cgroup v1 and v2. It needs `hostPID` and the capabilities `SYS_PTRACE` and `DAC_READ_SEARCH`; those violate the Baseline Pod Security Standard and need an exception.
- Not supported: Fargate and Autopilot-style platforms without host namespaces, Windows containers, sandboxed runtimes (see above), homes on NFS or EFS with root squashing, jobs shorter than the sensor's discovery interval.
- Hooks inside images the platform team does not build are not installable by the node sensor; in-image hooks are telemetry, not a control.
- CI support (`spoor ci exec`) is experimental and does not cover agents that run inside a `uses:` action step.

## Detection quality

- Rule quality is measured by replaying rules over real agent sessions and a scenario corpus; the numbers and their limits are in `bench/results/`. The real-session corpus is one workload, so intervals are wide and the results do not transfer to a fleet without re-measuring there.
- Alert-class rules are tuned to be silent on that corpus. That is evidence of a low false-positive rate, not proof.
- Public rules evaluated on the endpoint can be read and avoided. Re-evaluating shipped events centrally with `spoor detect` and rules you do not publish is supported for that reason.
- There is no behavioural baseline beyond first-seen egress hosts and MCP servers.

## Operations

- Binaries are unsigned in this release. Reproducible build flags and checksums are provided; notarized macOS packages and Authenticode-signed MSIs need a maintainer signing identity.
- Fleet Free cannot push files or run scripts on hosts enrolled with plain osquery, and software deployment and policy automations are Fleet Premium features. The deployment guide says which path needs which tier.
- On hosts without SMBIOS data, osquery invents its own host UUID; an exact join between spoor's stream and Fleet hosts then requires the extension (which asks osquery) or explicit configuration.
- The product catalog goes stale quickly: four major agents shipped about 158 stable releases in 90 days during the research for this project, with several renames. `spoor catalog verify` checks package names against registries; treat anything not verified in the last 30 days as unverified.
