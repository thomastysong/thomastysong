> **Historical design record.** Red-team review of design v0, platform-parity lens (a Windows and macOS endpoint engineer; A2, A7, A20, A24). No Windows or macOS machine was available: experiments ran on the Linux build VM and by cross-compiling.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:22 UTC on the build machine; it says "Date 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (1 place). Kept: the `/etc/machine-id` value of the disposable build VM and the host UUIDs osquery and Fleet reported for it. Two of these values also appear in the repository: the machine-id (`internal/platform/hostid_linux_test.go`) and the Fleet host UUID of the enrolled test host (`deploy/fleet/VERIFIED.md`). The other three UUIDs come from three osquery runs on the same VM with an ephemeral database (E1) and appear nowhere else in the repository. Kept: statements in the persona's voice about past experience, such as "typical costs I have measured on managed Windows laptops in other projects" (the Windows start-up times in E4). The reviewer was a review session of this build given the persona named above; no measurement or data behind those statements is in this repository or was on the build machine, so treat those numbers as unverified estimates.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: platform parity (A2, A7, A20, A24) — design v0 "spoor"

Reviewer persona: Windows/macOS endpoint engineer. Date 2026-11-11.
Work dir (probes, downloads, outputs): `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/redteam/pp-work/`
Legend: [X] experiment run in this sandbox; [S] primary source read this session (file under `pp-work/dl/` or GOROOT / module cache); [U] unverified (experience / memory), must be tested on real hardware.

No Windows or macOS machine was available. Everything about runtime behaviour on those OSes is [S] or [U]; only API availability was proven by cross-compiling.

---

## Primary sources fetched (pp-work/dl/)

- `cc-hooks.md`, `cc-managed-settings.md`, `cc-settings-reference.md`, `cc-setup.md` (code.claude.com/docs/en/*.md)
- `osq-system.cpp` (osquery/osquery master `osquery/core/system.cpp`)
- `codex-command_runner.rs`, `codex-engine-mod.rs` (openai/codex main `codex-rs/hooks/src/engine/`)
- `copilot-hooks.md` (github/docs `content/copilot/reference/hooks-reference.md`)
- `gemini-hookRunner.ts`, `gemini-hooks-ref.md` (google-gemini/gemini-cli main)
- `xnu-kern_sysctl.c` (apple-oss-distributions/xnu main `bsd/kern/kern_sysctl.c`)
- `linux-dmi-id.c` (torvalds/linux master `drivers/firmware/dmi-id.c`)
- GOROOT `/usr/local/go1.24.7/src/syscall/syscall_windows.go`; module cache `golang.org/x/sys@v0.50.0`, `github.com/shirou/gopsutil/v4@v4.26.10`

---

## E1 [X] A20: osquery host UUID cannot be derived without osquery on this very host

```
$ ls /sys/class/dmi/id/product_uuid        -> No such file or directory   (Firecracker VM, no SMBIOS)
$ cat /etc/machine-id                      -> d165c2d88d894a4787be219662b439ad
$ osqueryd -S --json "select uuid, hardware_serial, hardware_vendor from system_info"   (3 runs, ephemeral DB)
  uuid b778c667-7a36-4010-8505-4bd7976e8175
  uuid 03b73bd1-9af1-4973-a05b-68ac7751b016
  uuid 9186ed3e-dc9f-466a-9311-56833aa1362c
$ fleetctl get hosts --json   -> {'hostname': 'vm', 'uuid': '5e8102a2-f0ef-46ef-a315-39f770849362', 'hardware_serial': ''}
$ go run ./hostid             -> gopsutil host.HostID(): d165c2d8-8d89-4a47-87be-219662b439ad   (= machine-id)
```

Fleet's `uuid` for the enrolled host (5e8102a2-...) is a random value osquery generated and stored in its RocksDB. Nothing outside osquery can compute it; three fresh osquery processes produce three different values; the obvious pure-Go library returns machine-id instead.

[S] `osq-system.cpp`:
- `getHardwareUUID()`: macOS `gethostuuid()` + `uuid_unparse` (line 133-136); Windows WMI `Select UUID from Win32_ComputerSystemProduct` (139-146); Linux `readFile("/sys/class/dmi/id/product_uuid")` (149).
- `getHostUUID()` (203-250): if hardware UUID is empty or in `kPlaceholderHardwareUUIDList` (4 known junk values, lines 90-95) it reads `host_uuid_v3` from the database, else `generateNewUUID()` (random) and stores it.
- [S] `linux-dmi-id.c:50`: `DEFINE_DMI_ATTR_WITH_SHOW(product_uuid, 0400, DMI_PRODUCT_UUID)`: root-only. A hook process running as the user (the "daemonless hooks" mode in design section 7) can never read it.
- [S] gopsutil v4.26.10: `host_windows.go:59-81` returns `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (not the SMBIOS UUID that WMI/osquery returns); `host_darwin.go:23-37` execs `ioreg` (a process spawn) and lower-cases the value; `host_linux.go` falls back product_uuid -> machine-id -> boot_id.
- [S] `GetSystemFirmwareTable` is not wrapped in x/sys/windows v0.50.0 (grep count 0): matching osquery on Windows needs a hand-rolled SMBIOS type-1 parse with the mixed-endian conversion WMI applies, or COM/WMI (too slow for a hook).
- [U] DMI-less classes: Firecracker/microVMs, WSL2, some arm64 boards and cloud arm64 instances; duplicate SMBIOS UUIDs on cloned VDI images (the reason osquery has a placeholder list at all); UUID letter case differs per OS (sysfs lower, WMI/`uuid_unparse` upper).

Verdict A20: broken.

## E2 [X] A7/A24: the hook socket peer-identity API in the design exists on one OS of three

```
$ GOOS=linux  go build ./peercred          -> OK
$ GOOS=darwin GOARCH=arm64 go build ./peercred
  peercred/main.go:11:17: undefined: unix.GetsockoptUcred
  peercred/main.go:11:58: undefined: unix.SO_PEERCRED
$ GOOS=windows go build ./peercred
  undefined: unix.GetsockoptUcred / unix.SOL_SOCKET / unix.SO_PEERCRED
$ GOOS=darwin GOARCH=arm64 go build ./darwinalt   -> OK
  (unix.GetsockoptXucred(SOL_LOCAL, LOCAL_PEERCRED) = uid+groups, no pid;
   unix.GetsockoptInt(SOL_LOCAL, LOCAL_PEERPID) = pid, separate call;
   unix.SYS_GETHOSTUUID, unix.SysctlRaw("kern.procargs2"), unix.SYS_CSOPS all compile CGO-free)
$ GOOS=windows GOARCH=amd64|arm64 go build ./winapi -> OK-amd64, OK-arm64
  (svc.Run, svc.IsWindowsService, net.Dial("unix"), windows.GetNamedPipeClientProcessId, os.OpenFile(...,0600))
```
x/sys/windows v0.50.0 symbol check (grep -l count): `GetNamedPipeClientProcessId` 2, `CreateNamedPipe` 3, `NtQueryInformationProcess` 4, `ReadProcessMemory` 3, `WTSQueryUserToken` 2, `SetNamedSecurityInfo` 3, `SetEntriesInAcl` 2, `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` 1, `LookupAccountSid` 2; **`SIO_AF_UNIX_GETPEERPID` 0, `ImpersonateNamedPipeClient` 0, `GetSystemFirmwareTable` 0**.

So: AF_UNIX on Windows compiles but has no peer-credential call in Go/x/sys (and the Win32 ioctl returns a pid only, no token). Named pipes have `GetNamedPipeClientProcessId`; `ImpersonateNamedPipeClient` must be bound by hand (advapi32) or via Microsoft/go-winio.

## E3 [X] A7: "verify the caller's parent is a known agent" fails behind a shell wrapper

```
agent pid 29019
direct exec (exec form)                -> hook ppid=29019 parent_exe=/usr/local/bin/python3.13
sh -c  (Claude shell form, unix)       -> hook ppid=29025 parent_exe=/usr/bin/dash        <- parent is the shell
sh -c  with && true                    -> hook ppid=29031 parent_exe=/usr/bin/dash
bash -lc (Codex default: $SHELL -lc)   -> hook ppid=29019 parent_exe=/usr/local/bin/python3.13   (bash exec-optimises a single command)
bash -lc with env prefix; true         -> hook ppid=29047 parent_exe=/usr/bin/bash
/bin/sh -> dash (Ubuntu)
```
The parent of the hook is the agent only when the wrapper shell happens to exec-replace itself. dash (Debian/Ubuntu `/bin/sh`) does not. On Windows no shell exec-replaces (bash.exe, cmd.exe and powershell.exe all stay as the parent) and the Win32 parent pid is an unvalidated number that survives parent exit and pid reuse [U].

## E4 [X] A2: the 2.9 ms claim measures a path most agents do not use

300 runs each, driver = python subprocess, this sandbox (Linux):
```
/bin/true              p50=  0.95 p99=  3.18
direct exec            p50=  1.69 p99=  3.08
sh -c                  p50=  2.50 p99=  6.23
bash -c                p50=  2.50 p99=  5.54
bash -lc (Codex)       p50=  8.45 p99= 14.86      <- root's near-empty profile; a floor
bash -lc with a profile that takes 0.3 s: elapsed_ms=307
```
How each agent actually launches a command hook [S]:
- Claude Code (`cc-hooks.md:462-464`): exec form only when `args` is set; otherwise "`sh -c` on macOS and Linux, Git Bash on Windows, or PowerShell when Git Bash isn't installed".
- Codex (`codex-command_runner.rs:450-470, 499-521`): `$SHELL -lc <command>` on unix (a LOGIN shell, fallback `/bin/sh`), `%COMSPEC% /C "<command>"` on Windows (fallback `cmd.exe`). No exec form found.
- Copilot (`copilot-hooks.md:160-170`): `bash` on unix, `powershell` on Windows; `exec` (no shell) "Only supported in Copilot CLI".
- Gemini (`gemini-hookRunner.ts:335-365`): `spawn(shellConfig.executable, [...argsPrefix, command])`, with a `powershell` branch (line 342).

So on Windows every hook is two process creations (shell + spoor.exe) for Codex, Gemini, Copilot-in-VS-Code and Claude shell form. [U] typical costs I have measured on managed Windows laptops in other projects: powershell.exe -NoProfile cold start 200-500 ms, Git Bash bash.exe 50-200 ms, CreateProcess of a 15-25 MB unsigned Go exe under Defender real-time protection 20-80 ms and a full rescan after each signature update. These Windows numbers are NOT measured here and must be measured on real hardware; the mechanism (mandatory shell wrapper) is [S].

## E5 [X] A24: hook command quoting

```
$ bash -c 'C:\Program Files\spoor\spoor.exe hook --agent claude'
bash: line 1: C:Program: command not found          exit=127
$ bash -c '"C:\Program Files\spoor\spoor.exe" hook --agent claude'
bash: line 1: C:\Program Files\spoor\spoor.exe: command not found   exit=127 (parsed correctly; file absent here)
$ sh -c "<dir>/bin/Program Files/spoor/spoor who"
sh: 1: <dir>/bin/Program: not found                 exit=127
$ sh -c "\"<dir>/bin/Program Files/spoor/spoor\" who"   -> runs, exit=0
```
The double-quoted form that works in bash is, in PowerShell, a string expression that is printed rather than executed: [S] `cc-hooks.md:1004-1010` "PowerShell started no program ... a `command` that is only quoted strings, such as `\"C:\\Tools\\guard.exe\"`".
Failure semantics differ by machine state [S] `cc-hooks.md:936, 984-998`: "On Windows without Git Bash, a shell-form PreToolUse or PermissionRequest command hook that fails with onFailure unset can instead block the tool call" ("blocking because Git Bash wasn't found, so only exit code 0 or 2 counts as this hook's verdict"). So the same wrong string is silently fail-open on a machine with Git for Windows and blocks every tool call on a machine without it. The design's "Fail-open by default" is not true on that configuration.

## E6 [X] Codex managed hook is launched through user-controlled `$SHELL` and the user's login profile (emulation of `build_command`, not real Codex)

```
normal:            hook runs, spool lines=2
SHELL=/bin/true:   hook exit=0 ; spool lines=2     <- hook never ran, "success"
SHELL=fakesh:      hook exit=0 ; spool lines=2
HOME with .bash_profile containing `sleep 0.3; exit 0`:
  profile ran ... exit=0 elapsed_ms=307 spool lines=2   <- profile ran first and exited; hook never ran
```
[S] `codex-command_runner.rs:499-521` picks the program from the `SHELL` (unix) / `COMSPEC` (Windows) entry of the session environment snapshot; 459 passes `-lc`. Not verified against a real Codex build: whether the snapshot can be influenced exactly as `SHELL=/bin/true codex` suggests must be tested, and whether `requirements.toml` can pin the hook shell (`CommandShell{program,args}` exists in `codex-engine-mod.rs:59`) is unknown.

## E7 [X] A27/A28/A7: a root Fluent Bit tailing a user-owned spool is a confused deputy

```
home-alice/spool (owner uid 1000):
  activity-000001.ndjson
  activity-000002.ndjson -> .../root-only/shadow      (symlink planted by uid 1000)
root-only/shadow  -rw------- root root
$ setpriv --reuid 1000 ... cat .../activity-000002.ndjson  -> Permission denied
$ docker run --rm --network host -v $F:$F:ro fluent/fluent-bit:latest /fluent-bit/bin/fluent-bit -q \
    -i tail -p "path=$F/home-alice/spool/*.ndjson" -p read_from_head=true -p refresh_interval=1 -o stdout -p format=json_lines -f 1
{"date":...,"log":"{\"kind\":\"activity\",\"type\":\"tool.pre\",\"user\":{\"name\":\"alice\"}}"}
{"date":...,"log":"root:$6$SECRETHASH$not-a-real-hash:19000:0:99999:7:::"}
```
Fluent Bit 5.2.0 followed the user-planted symlink and shipped a root-only file. The same works for another user's transcript (cross-user disclosure plus mis-attribution to alice's stream). [U] Windows equivalent: directory junctions need no privilege; file symlinks need Developer Mode or admin (developers commonly enable Developer Mode).

## E8 [X] A24: Go darwin binaries have no stable code identity

```
$ python3 machosig.py bin/hello-darwin-arm64-v1 bin/hello-darwin-arm64-v2 bin/hello-darwin-amd64
hello-darwin-arm64-v1: blobs=1 CMS-signature-blob=False
    CodeDirectory ident='a.out' flags=0x20002 (adhoc=True linker-signed=True runtime=False) team=None cdhash=705131a1...
hello-darwin-arm64-v2: ... ident='a.out' flags=0x20002 ... team=None cdhash=f1282e06...
hello-darwin-amd64: NO LC_CODE_SIGNATURE (unsigned)
```
A one-character source change gives a new cdhash; identifier is `a.out`; no Team ID; the amd64 build has no signature. A PPPC payload (`com.apple.TCC.configuration-profile-policy`, `SystemPolicyAllFiles`) needs an identifier plus a code requirement; for ad-hoc code the only requirement is the cdhash, so the profile breaks on every release and differs per architecture [U for exact MDM behaviour, mechanism is standard].

## E9 [S] A24: Go permission bits do nothing on Windows

`/usr/local/go1.24.7/src/syscall/syscall_windows.go`:
- `Mkdir` (623-629): `return CreateDirectory(pathp, nil)`; mode ignored, the directory inherits the parent DACL.
- `Chmod` (759-774): only toggles `FILE_ATTRIBUTE_READONLY` from the 0200 bit.
- `Open` (364-): `perm` only selects the read-only attribute; `O_APPEND` maps to `FILE_APPEND_DATA` (385-393), so concurrent appends are safe (this part of the design holds).
[U] default `C:\ProgramData` DACL lets BUILTIN\Users create subfolders and files and read what others create; must be confirmed with `icacls` on Windows 11 24H2/25H2.

## E10 [S] Claude Code managed-source precedence shadows a file drop

`cc-managed-settings.md`:
- 127: "`first-wins`, the default: Claude Code uses the highest-ranked source that delivers at least one policy key and ignores the rest rather than merging them ... Claude Code shows no warning for the sources it skips".
- 136-140 ranking: 1 server-managed, 2 "MDM or OS-level policies: the macOS plist or the HKLM registry key", 3 "Managed settings files, `managed-settings.d/*.json` and `managed-settings.json` merged together", 4 HKCU.
- 157-179 cross-source keys: sandbox locks, MCP allow/deny, `env`, `maxEffortLevel`, ... **`hooks` is not in the list**. Under `"merge"` (table at 204-210) `hooks` is a combined list.
- `cc-settings-reference.md:5674-5678`: `managedSourcesBehavior` is read only from the highest-ranked source, "so a lower source can't opt itself into combining with the source above it".
- 191: "If a machine has both an MDM policy and a managed settings file, use the MDM policy."
- 153: "On WSL, `/etc/claude-code` is user-writable as well".
- `cc-settings-reference.md:5851-5869`: `wslInheritsWindowsSettings` makes WSL Claude read the Windows policy chain (`HKLM`, `C:\Program Files\ClaudeCode\`), and then `/etc/claude-code` only when no Windows admin document is present.
- `cc-setup.md:109-114`: WSL 2 is a first-class install target and the only Windows option with sandboxing.

## E11 [S] macOS: env of restricted processes is hidden even from root

`xnu-kern_sysctl.c:1387-1405`: env is returned by `kern.procargs2` only if the target is the caller, or "target process is not cs_restricted", or SIP is off, or the caller has `com.apple.private.read-environment-variables`. Root is not an exception. Which agent binaries run `cs_restricted` (hardened-runtime notarized `claude`, `codex`, `node`, Cursor/Electron helpers) is [U] and decides whether `CLAUDE_CONFIG_DIR` / `CODEX_HOME` / session-id markers can be read on macOS at all.

---

## Findings (most damaging first)

| # | Assumption | Verdict | Severity | One-line |
|---|---|---|---|---|
| PP-1 | A1/A24 unstated | broken | critical | Claude file-drop hooks are silently ignored when an MDM plist, HKLM value or server-managed policy exists (default first-wins) |
| PP-2 | A20 | broken | high | osquery `system_info.uuid` is not derivable without osquery (proved on this host) |
| PP-3 | A24/A1 | broken | high | one hook command string cannot be valid across Git Bash, PowerShell, cmd, sh and WSL; wrong string fails open or blocks depending on machine |
| PP-4 | A28/A27/A7 | broken | high | root Fluent Bit tailing a user-owned spool ships any file the user symlinks (proved) |
| PP-5 | A24 | broken | high | POSIX permission vocabulary has no effect on Windows; no ACL design for spool, state DB, rules dir |
| PP-6 | A7 | broken | high | SO_PEERCRED is Linux-only; "parent is a known agent" fails behind shells; sessions keyed by self-reported id |
| PP-7 | A24 | broken | high | WSL2 agents are invisible to the Windows binary and inherit hook commands that cannot run |
| PP-8 | A2 | weakened | high | 2.9 ms is direct exec on Linux; real paths add a shell (and a login profile for Codex); Windows unmeasured |
| PP-9 | A24 | weakened | high | macOS: no stable signing identity, so no PPPC/FDA; root daemon blind in TCC-protected trees; env hidden for restricted processes |
| PP-10 | A1/A6 | weakened | medium | Codex managed hook runs via `$SHELL -lc` / `%COMSPEC% /C`: env or profile can swallow it with exit 0 |
| PP-11 | A7/A24 | weakened | medium | LocalSystem/root reading profiles: ProfileList, HKU hives, redirected AppData, cloud placeholders, container uid names, sudo/runas |
| PP-12 | A24 | holds | low | CGO-free API availability on windows/darwin (tried to break by cross-compiling; all needed calls exist or can be bound) |

Details and proposed minimal changes are in the structured result returned to the lead; the evidence for each is the experiment section referenced above (PP-1: E10; PP-2: E1; PP-3: E4, E5, E10; PP-4: E7; PP-5: E9, E2; PP-6: E2, E3; PP-7: E10; PP-8: E4; PP-9: E8, E11; PP-10: E6; PP-11: E9, E2; PP-12: E2, E9).

---

## Must be tested on real hardware before any parity claim

Windows 11 (24H2/25H2, Defender real-time on, standard user, Intune-managed; plus one multi-session AVD/RDS host):
1. Hook latency p50/p99 per agent and per launch path: Claude exec form vs Git Bash vs PowerShell; Codex `cmd /C`; Gemini and Copilot PowerShell; with signed and unsigned spoor.exe; before and after a Defender signature update.
2. Exact quoting of each generated hook command for a path with spaces, in each shell, with and without Git for Windows installed; confirm the fail-closed behaviour of Claude without Git Bash.
3. `icacls C:\ProgramData` defaults; pre-creation of `C:\ProgramData\spoor` by a standard user before install; whether the service refuses to start.
4. Named pipe hook transport: `GetNamedPipeClientProcessId` + impersonation give the right SID for runas, elevated and RDP sessions.
5. LocalSystem reading: `HKU\<SID>` when the user is logged off, roaming/redirected `%APPDATA%` on a UNC path, FSLogix profile containers, OneDrive Files On-Demand placeholders (no hydration).
6. `\\wsl$` / `\\wsl.localhost` from session 0; WSL distro enumeration; Claude in WSL with `wslInheritsWindowsSettings` and a Windows-path hook command.
7. Process env read (PEB) of agent processes: native x64, arm64, x64-on-arm64 emulation, Codex restricted-token sandbox children; EDR reaction to periodic `PROCESS_VM_READ` opens.
8. SMBIOS UUID computed by spoor equals `select uuid from system_info` on physical, Hyper-V, VMware and Azure VMs.
9. WDAC / AppLocker / Smart App Control with an unsigned binary.

macOS 15 and 26, Apple silicon and Intel, MDM-enrolled (Fleet), standard and admin users, two users with fast user switching:
1. Root LaunchDaemon without FDA reading `~/.claude`, `~/.codex`, `~/Library/Application Support/{Cursor,Code,Claude}`, `~/Documents/<repo>/.mcp.json`, `~/Desktop`, iCloud Drive, `~/Library/Containers/*`: which return EPERM.
2. PPPC FDA profile against an ad-hoc binary, a Developer ID binary, and the osquery-hosted extension (does spoor.ext inherit orbit/osqueryd FDA).
3. `kern.procargs2` env for `claude`, `codex`, `node`, Cursor helpers as root (cs_restricted or not), and for their child shells.
4. Background-item (BTM) prompt and Login Items toggle for an unsigned LaunchDaemon; service-management profile lock.
5. `gethostuuid` via raw syscall from Go on macOS 26; case of the value vs osquery.
6. Managed preferences domain `com.anthropic.claudecode` present plus `managed-settings.d/50-spoor.json`: confirm the file's hooks do not fire (first-wins) and do fire with `merge`.
7. Codex `zsh -lc` hook latency with a typical developer profile (brew shellenv, nvm, pyenv, conda).
8. LOCAL_PEERCRED/LOCAL_PEERPID on a daemon socket for hooks launched under each agent; two concurrent GUI users.
9. Dataless (FileProvider) files: scanner must not materialise them.

Linux: product_uuid as root on bare metal, KVM, arm64 cloud, WSL2; Codex real binary with `SHELL=/bin/true`.
