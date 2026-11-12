> **Historical design record.** Research report: OS-level ground truth for agent detection on Linux, macOS, Windows and in containers (process connector, `/proc` polling, osquery evented tables, ETW), with measurements taken on the build VM.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:12 UTC on the build machine; it has no date of its own; it reports measurements on the build VM's kernel 6.18).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# OS ground truth for agent detection (Linux, macOS, Windows, containers)

**Executive summary**
1. Claude Code and Codex stamp their child processes with env markers that carry the session id (`CLAUDE_CODE_SESSION_ID`; `CODEX_SESSION_ID`/`CODEX_THREAD_ID`/`CODEX_TOOL_CALL_ID`), and Gemini CLI and others at least mark children (`GEMINI_CLI=1`), so an OS-side process sensor can join to hook/transcript telemetry without trusting either side. This is the core of independent attribution and of hook-tamper detection ("OS saw session X run tools, hooks reported nothing").
2. A pure-Go, CGO-free, driverless sensor is feasible on all three OSes: Linux cn_proc + /proc (works unprivileged on kernel >= 6.6, verified by test), macOS sysctl/kqueue/`csops`, Windows Toolhelp + ETW (MIT, no-CGO library exists). Polling alone is not enough: at a 1 s poll I measured 1% capture of `/bin/true` and 7% of 100 ms processes.
3. osquery is a usable tier-2 kernel sensor but not a foundation: its BPF tables are deprecated (removal in 6.0.0), audit tables conflict with auditd, ES tables need Full Disk Access, and everything is off by default behind per-table flags.
4. Containers need a host-PID DaemonSet: cn_proc only exists in the init network namespace, bwrap/Seatbelt sandboxes keep children visible to the host, but microVM sandboxes (Docker Sandboxes, Apple `container`, WSL2) are opaque to host sensors and must be inventoried as assets with an in-guest sensor.
5. uber/ADR has no evented OS telemetry at all (its `exec_journal` provider is an unimplemented stub); Fluent Bit's kubernetes filter enriches by tag only, so our sensor must resolve pod metadata itself.

Legend: **[V]** primary source read or tested this session; **[U]** memory or search snippet.

**uber/ADR baseline** [V]: Discovery enumerates processes by snapshot only (`world/platform/linux.py` /proc, `darwin.py` `ps -axo pid=,ppid=,user=,comm=` with no argv or env, `windows.py` PowerShell `Get-CimInstance Win32_Process`); `exec_journal` returns "unavailable" on every platform (`world/platform/base.py:184`); Sensor is transcript parsing only.

## 1. Linux, ranked by deployability

| Option | Privilege | In unprivileged container | Notes |
|---|---|---|---|
| `/proc` polling | none (own uid full detail; others: stat/cmdline/exe link limited) | yes, sees only its own pid ns | [V] measured here (kernel 6.18, 101 procs, Python): full scan 1.1 ms (~11 us/proc). Capture rate of short-lived procs: poll 1 s: `/bin/true` 1%, 100 ms proc 7%, 500 ms proc 53%; poll 250 ms: 0% / 38% / 100%; poll 50 ms: 0% / 100% / 100%. |
| netlink proc connector (cn_proc) | < 6.6: `CAP_NET_ADMIN` in init userns. >= 6.6: none for the `CN_IDX_PROC` group | no | [V] `drivers/connector/connector.c` v6.6+: `cn_bind` "Allow non-root access for NETLINK_CONNECTOR family having CN_IDX_PROC", `NL_CFG_F_NONROOT_RECV`; v6.5/v6.1/v5.15 `cn_proc.c:365` require `CAP_NET_ADMIN`. Socket is created only in `init_net`; LISTEN is ignored unless caller is in init user ns and init pid ns (`cn_proc.c:409`). [V] tested: root in init ns works; `unshare --net` gives `ECONNREFUSED`; new pid ns only receives events if some other listener exists (filter passes when `sk_user_data` is NULL), so treat as unsupported. Events carry pid/tgid/ppid only: read `/proc/<pid>/*` immediately on `PROC_EVENT_EXEC` (race for sub-ms processes). 6.6+ adds per-socket event filter (`struct proc_input.event_type`). Overflow surfaces as `ENOBUFS` [U]: resync with a /proc scan. |
| fanotify | `CAP_SYS_ADMIN` for mount/filesystem marks | no | [U] `FAN_OPEN_EXEC` (5.0+) gives exec with pid; `FAN_CLOSE_WRITE`/`FAN_MODIFY` give file writes with pid (file attribution without eBPF). `unix.FanotifyInit` exists in x/sys [V]. |
| audit netlink | unicast: one owner (auditd or osquery); multicast `AUDIT_NLGRP_READLOG` needs `CAP_AUDIT_READ` [U] | no | [V] osquery docs: "auditd should not be running... it will conflict with osqueryd over access to the audit netlink socket". Read-only multicast tap via `elastic/go-libaudit/v2` (v2.6.2) only if auditd already has execve rules. |
| eBPF CO-RE (`cilium/ebpf` v0.22.0, MIT, pure Go) | `CAP_BPF`+`CAP_PERFMON` (5.8+), else `CAP_SYS_ADMIN` [U] | no (default seccomp blocks `bpf`) [U] | [V] cilium/ebpf README: Linux amd64/arm64, ">= 4.4 should work but EOL'ed versions are not supported"; bpf2go embeds `*_bpfel.o` via `go:embed`, `CGO_ENABLED=0` supported; CO-RE "relies on type information encoded in BTF to be shipped with the kernel"; `rlimit.RemoveMemlock` needed before 5.11. Attach `sched/sched_process_exec|fork|exit` tracepoints and `sock/inet_sock_set_state` or `tcp_connect` [U]; capture cgroup id in-kernel so short-lived container processes are attributed without a /proc race. |

Unprivileged on host: /proc for same uid, cn_proc on >= 6.6, inotify. Inside an unprivileged container: only /proc of that container (sidecar/in-image mode).

## 2. macOS without an Endpoint Security entitlement

- **sysctl polling, pure Go** [V]: `gopsutil/v4` (v4.26.10) has zero cgo on darwin; `kern.procargs2` for argv+env. XNU `bsd/kern/kern_sysctl.c` (`sysctl_procargsx`): caller must be same uid or root (else `EINVAL`), and env is omitted when the target is `cs_restricted` unless SIP is off or the caller holds an entitlement. Which agent binaries are `CS_RESTRICT` is [U]; shells and interpreters normally are not.
- **`csops` on a live pid** [V]: `CS_OPS_STATUS(0)`, `CS_OPS_CDHASH(5)`, `CS_OPS_IDENTITY(11)`, `CS_OPS_TEAMID(14)` are "not restricted to root" (`bsd/kern/kern_proc.c` `csops_internal`); `SYS_CSOPS=169` is in x/sys. Kernel-validated team id and cdhash, no file parsing, defeats renames.
- **kqueue `EVFILT_PROC`** [V]: `NOTE_TRACK|NOTE_TRACKERR|NOTE_CHILD` return `ENOTSUP` (`kern_event.c:1105`); `NOTE_EXITSTATUS` only for parent or tracer. So: register `NOTE_FORK|NOTE_EXEC|NOTE_EXIT` per known agent pid and rescan children on `NOTE_FORK`. A trigger, not a tracer.
- **eslogger** [V, man page dated 22 Feb 2022]: "must be run as super-user and requires the responsible process to have TCC Full Disk Access"; as a launch daemon FDA can be granted by MDM PPPC (`com.apple.TCC.configuration-profile-policy`, `SystemPolicyAllFiles`). "eslogger is NOT API in any sense. Do NOT rely on the structure or information emitted for ANY reason." JSON Lines modelled on `es_message_t`, with `schema_version`; notify events only; suppresses events from its own process group. Man-page field paths: `.process.audit_token.pid`, `.process.executable.path`, `.event.exec.target.executable.path`. Usage: `eslogger exec fork exit`. Availability macOS 13+ [U]. Treat as an optional, schema-pinned tier-1 source with a contract test per macOS release.
- **OpenBSM**: osquery docs list OpenBSM `process_events`/`socket_events` for "macOS (10.15 and older)" and call OpenBSM "now-deprecated" [V]. Do not build on it.
- **Unified log** [U for predicates]: Seatbelt denials are logged; `sandbox-runtime` README confirms it taps "the system's sandbox violation log store" on macOS [V]. Useful secondary signal for sandboxed agent commands.
- **Needs entitlement or system extension**: native ES client (`com.apple.developer.endpoint-security.client`), NetworkExtension filters. osquery's signed build carries the ES entitlement, so `es_process_events` is the no-entitlement route to real exec events.

## 3. Windows

- **ETW from pure Go**: [V] `github.com/secDre4mer/etw` (MIT, fork of bi-zone, "Building without CGO", uses `windows.NewCallback`, last commit 2026-09-25). `0xrawsec/golang-etw` (v1.6.2, 2022) and `tekert/goetw` (v0.9.12, 2026-10-29) are pure Go but GPL-3.0; `bi-zone/etw` and `Velocidex/etw` import "C". [V] osquery enables `Microsoft-Windows-Kernel-Process` with keyword `0x10` plus the classic kernel Process provider and merges both; its `CommandLine`/`UserSID` parsing is in the kernel-provider branch, so the manifest provider alone does not give a command line. Provider GUID `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` [V, Fluent Bit docs]. Session control needs admin, LocalSystem or Performance Log Users; NT Kernel Logger needs admin/LocalSystem [U, Microsoft docs via search]. Kernel-Network event ids [U].
- **Fluent Bit is itself an ETW sensor** [V, docs]: input `event_tracing_windows` with `provider_name: Microsoft-Windows-Kernel-Process` or `session_type: system` + `kernel_flags: process,thread,image_load,tcpip`. Presence in a given Windows build [U].
- **Sysmon if present** [U]: channel `Microsoft-Windows-Sysmon/Operational`, ids 1 (process, with CommandLine, hashes, ParentProcessGuid), 3 (network), 11 (file create), 22 (DNS). Best quality when installed; never install it ourselves.
- **Security 4688** [U]: needs "Audit Process Creation" and `ProcessCreationIncludeCmdLine_Enabled=1`; reading Security needs admin or Event Log Readers.
- **WMI `Win32_ProcessStartTrace`** [U]: admin, no command line; skip.
- **Polling** [V bindings in x/sys/windows]: `CreateToolhelp32Snapshot`, `NtQuerySystemInformation`, `NtQueryInformationProcess`, `ReadProcessMemory`, `QueryFullProcessImageName`, `GetProcessTimes`, `WinVerifyTrustEx`. gopsutil reads env on Windows without cgo [V]. Other users' processes need admin + SeDebug; protected processes stay opaque [U].

## 4. osquery as the kernel sensor

All evented tables require `--disable_events=false` [V]. Specs read from `osquery/osquery` master `specs/`.

| Table | OS | Flags [V] | Columns that matter [V] | Caveats |
|---|---|---|---|---|
| `process_events` | Linux (audit); macOS <= 10.15 | `--disable_audit=false --audit_allow_config=true --audit_allow_process_events=true` | pid, parent, path, cmdline, cwd, auid/uid/euid, `env` (hidden), syscall, time | conflicts with auditd; throttles past 4096 queued records and may lose events; mask `systemd-journald-audit.socket`; Fleet: "Audit has limited visibility inside containers" |
| `socket_events` | Linux (audit) | `--audit_allow_sockets` | action, pid, path, remote_address, remote_port, status | "can introduce considerable load" |
| `process_file_events` | Linux (audit) | `--audit_allow_fim_events=true` + `file_paths` | operation, pid, ppid, executable, path, dest_path | only paths existing before start (Fleet note) |
| `bpf_process_events`, `bpf_socket_events` | Linux >= 4.18 | `--enable_bpf_events=true` | tid, pid, parent, `cid` (cgroup id), path, cmdline, cwd, duration; sockets: remote_address/port | **Deprecated, "will be removed in osquery 6.0.0" (#8691)**; Fleet analysis: ebpfpub "drops events, high CPU usage... unmaintained" |
| `es_process_events` | macOS >= 10.15 | `--disable_endpointsecurity=false`, root, FDA for osqueryd (PPPC) | pid, `pidversion`, parent, `original_parent`, `responsible_pid`, cmdline, `env`, cwd, `signing_id`, `team_id`, `cdhash`, `platform_binary`, `codesigning_flags`, event_type, exit_code, child_pid | empty table and no prompt without FDA |
| `es_process_file_events` | macOS | plus `--disable_endpointsecurity_fim=false`; mute with `--es_fim_mute_path_prefix` | pid, parent, path, filename, dest_filename, event_type | high volume; changelog #8114 adds open events and "only triggering on `file_paths`" (Fleet's article still says paths can only be muted) |
| `process_etw_events` | Windows | `--enable_process_etw_events=true` | type, pid, ppid, path, cmdline, username, token_elevation_type, mandatory_label, `process_sequence_number` (hidden) | process only |
| `file_events` | Linux/macOS | `--enable_file_events=true` + `file_paths` | target_path, action, sha256 | no pid; watch directories, not files (replace-on-write) |
| `ntfs_journal_events` | Windows | `--enable_ntfs_event_publisher=true` + `file_paths` | action, path, old_path | no pid |
| `windows_events`, `powershell_events`, `dns_lookup_events` | Windows | `--enable_windows_events_publisher/subscriber`, `--windows_event_channels=...`, `--enable_powershell_events_subscriber`, `--enable_dns_lookup_events` | eventid, data; script_text; pid, name | bridge to Sysmon and 4688 |

Buffering [V]: events sit in RocksDB until queried; `--events_expiry=3600`, `--events_max=50000`; set query interval and `events_max` to the burst rate or events drop silently.

Extension querying osquery [V]: `osquery-go` `NewClient(socket, timeout)` then `QueryRowsContext(ctx, sql)`. Fleet does this in `orbit/pkg/table/mcp_listening_servers/mcp_listening_servers.go` (joins `listening_ports` and `processes`). Extensions must be root-owned, named `.ext`, loaded via `--extensions_autoload`. Draining an evented table from an extension competes with the scheduled-query cursor; prefer scheduled queries shipped by the osquery logger to Fluent Bit and joined downstream, or use a distinct `time >` constraint.

## 5. Process attribution

- **Identity key**: `(boot_id, pid, start_time)`. Linux: `/proc/<pid>/stat` field 22 + `/proc/sys/kernel/random/boot_id`. macOS: start timeval, or ES `pidversion`. Windows: `CreateTime` or ETW `process_sequence_number`.
- **Root finding**: walk ancestors until a process matches by (a) code signature (macOS `csops` team id; Windows `WinVerifyTrustEx` subject), (b) exe sha256, (c) argv pattern (`node .../cli.js`, `npx`/`bunx`/`uvx` package names), (d) open handles on agent state (`~/.claude/projects/*.jsonl`, `~/.codex/sessions`), which survives renames, or (e) the **marker boundary**: the nearest ancestor whose own env lacks the marker its children carry.
- **Env markers** (set at spawn, so `/proc/<pid>/environ`, `kern.procargs2`, PEB and ES exec events all see them):
  - Claude Code [V, code.claude.com env-vars]: `CLAUDECODE=1` (Bash/PowerShell tools, tmux, hooks, status line, stdio MCP servers; IDE terminals also set it), `CLAUDE_CODE_CHILD_SESSION=1` (tools/hooks only, not MCP, not IDE; v2.1.172+), `CLAUDE_CODE_SESSION_ID` (tools, hooks and stdio MCP servers; equals hook `session_id`), `CLAUDE_CODE_BRIDGE_SESSION_ID`, `CLAUDE_CODE_REMOTE=true`, `CLAUDE_CODE_REMOTE_SESSION_ID`.
  - Codex [V, openai/codex main `core/src/spawn.rs`, `core/src/exec_env.rs`, `protocol/src/shell_environment.rs`]: `CODEX_SESSION_ID`, `CODEX_THREAD_ID`, `CODEX_TOOL_CALL_ID`, `CODEX_VERSION`, `CODEX_PERMISSION_PROFILE`, `CODEX_SANDBOX` ("seatbelt"), `CODEX_SANDBOX_NETWORK_DISABLED=1`.
  - Gemini CLI [V, `shellExecutionService.ts`, `docs/tools/shell.md`]: `GEMINI_CLI=1`.
  - Third-party list [V, `vercel/vercel` `packages/detect-agent/src/index.ts`]: `AI_AGENT`, `CURSOR_TRACE_ID`, `CURSOR_AGENT`, `CURSOR_EXTENSION_HOST_ROLE=agent-exec`, `CODEX_CI`, `ANTIGRAVITY_AGENT`, `AUGMENT_AGENT`, `OPENCODE=1`, `OPENCODE_CLIENT`, `CLAUDE_CODE_IS_COWORK`, `REPL_ID`, `COPILOT_MODEL`, `COPILOT_ALLOW_ALL`, `COPILOT_GITHUB_TOKEN`. Cursor `CURSOR_SANDBOX`, `CURSOR_ORIG_UID`, `CURSOR_SANDBOX_LANDLOCK_STATUS` [U].
- **Reading another process's env**: Linux same uid and dumpable, else `CAP_SYS_PTRACE` [U]; macOS same uid or root, minus `cs_restricted` targets [V]; Windows `PROCESS_VM_READ` (same user and integrity, else admin+SeDebug) [U]. Emit names plus an allowlist of marker values only; never ship raw env (ADR Discovery also keeps names only, `world/platform/linux.py:62-70`).
- Reparented daemons keep env markers and cgroup; macOS ES adds `responsible_pid` and `original_parent` [V].

## 6. Containers and Kubernetes

- **pid to container id** [V, aquasecurity/tracee `pkg/datastores/container/containers.go:328-413`]: scan `/proc/<pid>/cgroup` path components for 64-hex ids: `docker-<id>.scope`, `cri-containerd-<id>.scope`, `...:cri-containerd:<id>`, `crio-<id>.scope` (skip `crio-conmon-`), `libpod-<id>.scope` (skip `libpod-conmon-`), `/docker/<id>`, `/actions_job/<id>` (GitHub Actions), `kubepods/<qos>/pod<uid>/<id>`. cgroup v1 has one line per controller, v2 a single `0::` line [U]. Inside a cgroup namespace the process sees `0::/`, so in-container self-identification falls back to `/proc/self/mountinfo`, `/.dockerenv`, `/run/.containerenv`, `HOSTNAME` [U].
- **Pod metadata without the API server**: `/var/log/containers/<pod>_<ns>_<container>-<64hex>.log` symlink names give container id to pod/namespace/container; this is exactly what Fluent Bit parses [V, regex in `pipeline/filters/kubernetes.md`]. Mount it read-only. Alternatives: kubelet `/pods` on 10250, CRI socket (root-equivalent, avoid), downward API for sidecar mode.
- **DaemonSet**: `hostPID: true`; `hostNetwork: true` only if using cn_proc; drop ALL caps, add `SYS_PTRACE` + `DAC_READ_SEARCH` (read `/proc/<pid>/environ` and `/proc/<pid>/root/...` of other uids), plus `BPF`+`PERFMON` for the eBPF tier, `NET_ADMIN` only for cn_proc on < 6.6; read-only hostPath `/var/log/containers`, `/sys/fs/cgroup`. Agent config and transcripts inside other containers are read through `/proc/<pid>/root/home/*/.claude/...` [U mechanism], so the transcript and config scanners need no in-container footprint.
- **Ephemeral workloads**: capture at exec, not at poll; cache container metadata past exit (Tracee keeps cgroup info 30 s after removal [V]); on agent-root exit, snapshot transcripts through `/proc/<pid>/root` before the container's init exits.
- **Environment markers** [U unless noted]: `CODESPACES=true`, `CODESPACE_NAME`; `REMOTE_CONTAINERS=true`; `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT`, `GITHUB_RUN_ID`; `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`, `JENKINS_URL`, `TF_BUILD`, `CI=true`; `KUBERNETES_SERVICE_HOST`; `CLAUDE_CODE_REMOTE=true` [V].
- **Fluent Bit composition** [V]: the kubernetes filter derives pod identity from the tag (`kube_tag_prefix`, `regex_parser`, `use_tag_for_meta`, `use_kubelet`), not from record fields. Our records therefore carry `k8s.namespace`, `k8s.pod`, `k8s.container`, `container.id` themselves; users wanting labels can `rewrite_tag` to `agent.<ns>.<pod>.<container>.<cid>` and run the filter with a custom `regex_parser` (composition inferred from docs, not tested). [V] The official `fluent/fluent-bit:latest` v5.2.0 image has no `exec` and no `ebpf` input (inputs include tail, forward, http, tcp, udp, syslog, stdin, opentelemetry, kubernetes_events, docker_events), so ship via JSONL file + `tail`, or `forward`/`http`/`opentelemetry`. `in_ebpf` is experimental, source-build only, and its `trace_exec` records only argv[0..2] + last, no cgroup or env.

## 7. Sandboxes and what the host sees

| Sandbox | Mechanism | Host view |
|---|---|---|
| Claude Code | [V] macOS Seatbelt; Linux/WSL2 `bubblewrap` + `socat`; "On native Windows, Claude Code runs commands unsandboxed". `sandbox-runtime` passes `--unshare-user --unshare-pid --unshare-net --proc --dev --disable-userns` | Children stay visible in host /proc with host pids under a `bwrap` parent (inferred from namespace semantics). Network egress leaves from the agent's proxy process, not the tool process, so socket-level attribution to a command is lost; use the tree plus proxy decisions. `excludedCommands` and the unsandboxed retry run outside. |
| Codex | [V] macOS `/usr/bin/sandbox-exec`; Linux bubblewrap (system or bundled `codex-resources/bwrap`) + seccomp, legacy Landlock, helper arg0 `codex-linux-sandbox`; Windows restricted-token backend or "elevated Windows sandbox" | Same as above; `CODEX_SANDBOX*` env marks sandboxed children. Windows token/user of children may differ [U]. |
| Cursor | [U] Seatbelt, Landlock+seccomp, WSL2 on Windows | Same pid space. |
| Docker Sandboxes (`sbx`) | [U] microVM per sandbox, own kernel and Docker engine, workspace shared | Host sees only the VM process; nothing inside. |
| Apple `container` | [V] "Linux containers as lightweight virtual machines", macOS 26, Apple silicon | Only `container-apiserver` and helpers. |
| WSL2, WSL containers (`wslc.exe`), Microsoft Execution Containers | [U, Fleet articles in local clone]: MXC GA 7 Oct 2026 with process, session (separate account), WSL and experimental MicroVM backends | Windows-side sensors see no Linux processes; session containers break same-user visibility. |

## 8. Evasion catalogue (no kernel driver needed)

| Evasion | Countermeasure |
|---|---|
| Renamed or copied binary | macOS `csops` team id/cdhash; Windows Authenticode subject; sha256 list; open-handle and marker-boundary identification |
| Run via `node`/`bun`/`python`/`npx`/`uvx` | argv + package-path patterns; child env markers; open transcript handles; API endpoint connections as weak corroboration |
| Portable or user-dir install | Process-first discovery (never rely on installed-software inventory; Fleet notes it misses global npm, Scoop and portable executables on Windows) |
| `CLAUDE_CONFIG_DIR` / `CODEX_HOME` relocation [V both exist] | Read the agent root's env and follow the override; alert on non-default values |
| Hooks disabled: `--settings '{"disableAllHooks": true}'`, `--bare`, `--safe-mode`/`CLAUDE_CODE_SAFE_MODE=1` [V] | Flag argv/env; deploy hooks in managed settings (`disableAllHooks` "can't disable managed hooks", safe mode keeps policy hooks, `allowManagedHooksOnly`) [V]; FIM + hash on `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`, `HKLM\SOFTWARE\Policies\ClaudeCode` [V]; reconcile OS-seen sessions against hook events |
| Transcripts suppressed or wiped (`CLAUDE_CODE_SKIP_PROMPT_HISTORY=1` [V]) | Flag env; stream-tail so deletion after shipping is harmless; emit delete/truncate events for watched dirs; "session seen, transcript absent" finding |
| Env scrubbed (`env -i`) | Tree + cgroup + macOS `responsible_pid` attribution; record at fork time |
| WSL2 hides Linux agents | Enumerate distros per user (`HKU\<sid>\...\Lxss` [U]); require the Linux sensor in-distro; report "distro without sensor"; managed settings reach WSL via `wslInheritsWindowsSettings` [V] |
| Remote dev over SSH, VMs, microVMs | Flag `ssh`/remote-server/hypervisor children of IDEs; sensor on the remote; coverage-gap finding rather than silence |
| Killing or blinding the sensor | Heartbeat with sequence numbers; per-source gap counters (netlink `ENOBUFS`, ETW `EventsLost`, osquery `osquery_events`); Fleet policy for sensor liveness |

## 9. Recommendation: tiered sensor

One Go binary, `CGO_ENABLED=0`, a capability probe at start, and every event stamped with `sensor.tier` and `source` so detections can state confidence.

| Tier | Linux | macOS | Windows |
|---|---|---|---|
| 0, no privilege | /proc scanner (direct reads or `prometheus/procfs` v0.23.0), adaptive 1 s idle / 50-100 ms while an agent root lives; cn_proc when kernel >= 6.6 (`mdlayher/netlink` v1.11.2 or raw `x/sys/unix`); `fsnotify` v1.10.1 | `kern.proc.all` + `kern.procargs2` (`gopsutil/v4`), `csops`, kqueue triggers, fsnotify | Toolhelp/`NtQuerySystemInformation` poll, PEB env for same user, `GetExtendedTcpTable` [U], `WinVerifyTrustEx` |
| 1, root/admin | cn_proc on any kernel, fanotify exec and file-write attribution, audit multicast tap, all-uid environ | `eslogger exec fork exit` child (schema-pinned, FDA by PPPC), unified-log sandbox denials | ETW session via `secDre4mer/etw`; subscribe to Sysmon and Security 4688 when present |
| 2, assisted | eBPF CO-RE via `cilium/ebpf` (kernel >= 5.8 + BTF); osquery `process_events`/`socket_events`/`process_file_events` | osquery `es_process_events`, `es_process_file_events` | osquery `process_etw_events`, `ntfs_journal_events`, `dns_lookup_events`; Fluent Bit `event_tracing_windows` |

Fallback order per OS: tier 2, then tier 1, then tier 0, always with a periodic full snapshot for resync. osquery integration is two-way: an `osquery-go` extension exposes our attributed tables to Fleet, and optionally consumes osquery evented rows as one more source.

Sources not reachable this session (allowlist): cursor.com, docs.docker.com, learn.microsoft.com; claims from them are marked [U].
