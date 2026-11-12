> **Historical design record.** Red-team review of design v0, containers and Kubernetes lens (A25, in-container mode, CI), with Docker experiments on the build VM.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:17 UTC on the build machine; it says "Date: 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none. Kept: the `/etc/machine-id` value of the disposable build VM (E3), which also appears in `internal/platform/hostid_linux_test.go`, and the pod UID `0a1b2c3d-1111-...` in E7, a placeholder the experiment passed as `--cgroup-parent`.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: containers / Kubernetes lens (A25, in-container daemonless mode, CI)

Reviewer persona: Kubernetes platform engineer running dev workspaces (devcontainers, Coder/Codespaces-style pods) and CI runners.
Date: 2026-11-11. Target: design/v0.md section 6 ("Containers / Kubernetes"), section 7 (DaemonSet row, daemonless hooks), A25, plus unstated assumptions.

Test bed: this VM, Docker (runc, overlayfs, cgroup v1, cgroupfs driver, seccomp only: no AppArmor/SELinux), kernel 6.18.44-fc (Firecracker). Image used for every container: mirror.gcr.io/library/redis:7 (Debian, has bash/setpriv/dd). Scripts: redteam/k8s-exp/probe.sh, poller.sh. All containers were named rtk8s-* and removed afterwards; nothing in the Fleet stack was touched.

Not testable here (stated, not hidden): cgroup v2, containerd CRI, AppArmor, SELinux, gVisor, Kata, user-namespaced pods via the kubelet. Where I argue about those I cite source code or docs fetched during this run.

## Setup (X1)

Workspace container rtk8s-ws: PID 1 `sleep infinity` as root; child A `CLAUDECODE=1 CLAUDE_CODE_SESSION_ID=s-root sleep 86401` as root (default docker caps); child B same markers as uid 999 with no caps (`setpriv --reuid 999 --regid 999`), HOME=/home/dev, `~/.claude` 0700, transcript 0600, `/root/.mcp.json`, `/etc/claude-code/`.

Host root view (works, as the design expects):
```
pid 5725 Uid 0   NSpid 5725 11  CapEff 00000000a80425fb  CLAUDE_CODE_SESSION_ID=s-root  mnt:[4026532269] pid:[4026532272] user:[4026531837]
pid 5726 Uid 999 NSpid 5726 12  CapEff 0000000000000000  CLAUDE_CODE_SESSION_ID=s-dev
8:pids:/docker/3c35c0c0d610365ffe62ef75480c2757ff2e20954a31af625459ae02d0beef9d
/proc/5726/root/home/dev/.claude/:  -rw------- 1 claude systemd-journal 24 .credentials.json   <- host passwd maps uid 999 to "claude"; inside the container it is "redis"
```

## E1. What a DaemonSet-style sensor can read (probe.sh; `docker run --rm --pid=host ...`)

| Variant | root agent: environ / root link | uid-999 agent: environ / root link / 0600 transcript |
|---|---|---|
| A hostPID, default docker caps, uid 0, not privileged | OK / OK | **EPERM / EPERM / EPERM** |
| B hostPID, cap-drop ALL, uid 0 | EPERM / EPERM | EPERM / EPERM / EPERM |
| C hostPID, only SYS_PTRACE | OK / OK | **environ EPERM** / root OK / transcript EPERM |
| D hostPID, SYS_PTRACE + DAC_READ_SEARCH | OK / OK | OK / OK / OK |
| E hostPID, --privileged | OK / OK | OK / OK / OK |
| F no hostPID, `-v /proc:/host/proc:ro`, default caps | OK / OK (122 host pids visible) | EPERM / EPERM / EPERM |
| G no hostPID, /proc hostPath ro, SYS_PTRACE + DAC_READ_SEARCH | OK / OK | OK / OK / OK |
| H hostPID, uid 999 (runAsNonRoot) | EPERM / EPERM | OK / OK / OK (same uid only) |
| I hostPID, uid 65534 with cap-add SYS_PTRACE,DAC_READ_SEARCH | EPERM | EPERM (CapEff=0: added caps are not effective for a non-root user) |

In every variant `cmdline` and `cgroup` were readable, so a sensor without the right caps still sees the process list and then silently finds zero env markers and zero transcripts.

Raw lines (variant A):
```
[uid999-proc pid=5726] cmdline='sleep 86402 ' environ='/proc/5726/environ: Permission denied' root='ls: cannot access '/proc/5726/root/': Permission denied' cgroup='8:pids:/docker/3c35...'
uid999 transcript 0600 (dir 0700): cat: /proc/5726/root/home/dev/.claude/projects/y/s.jsonl: Permission denied
```
Kernel reason: `/proc/<pid>/{environ,root}` need `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`: same uid/gid AND target caps a subset of the caller's, else CAP_SYS_PTRACE; plus DAC on the 0400 `environ` inode and on the 0700/0600 home files (CAP_DAC_READ_SEARCH).
Relevance: Claude Code's own devcontainer doc (code.claude.com/docs/en/devcontainer.md line 149): "the container runs Claude Code as a non-root user ... The CLI rejects this flag when launched as root, so confirm remoteUser is set to a non-root account."

Minimal working privilege set: hostPID (or a /proc hostPath, which is equivalent: variant F/G), effective CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH.

## E2. Write-through and "read-only" claims (W1-W4)

```
W1 hostPID + default caps (no privileged):  echo pwned-by-sensor > /proc/5725/root/etc/claude-code/managed-settings.json  -> WRITE_OK (verified inside the container)
W2 no hostPID, -v /proc:/host/proc:ro:      echo pwned-via-ro-proc > /host/proc/5725/root/tmp/w2                           -> WRITE_OK (the ro flag covers procfs only, not the mount reached through the magic link)
W3 uid 0, only SYS_PTRACE+DAC_READ_SEARCH:  echo w3 > /proc/5725/root/tmp/w3 -> WRITE_OK ; append to uid-999 0600 transcript -> Permission denied
W4 uid 65534 with ambient SYS_PTRACE+DAC_READ_SEARCH (capsh on host): reads environ, 0600 transcript, /root/.mcp.json: OK
W4b same identity: echo w4 > /proc/5725/root/etc/claude-code/managed-settings.json -> Permission denied
```
So a uid-0 sensor can modify root-owned files in any pod even with every write capability dropped; a non-zero uid with only the two read caps reads everything and writes nothing that is not world-writable.

## E3. Symlink confused deputy through /proc/<pid>/root (SYM)

Tenant container plants links in its fake transcript directory:
```
ln -s /etc/sensor-secret            ~/.claude/projects/x/leak1.jsonl
ln -s /proc/467/root/etc/machine-id ~/.claude/projects/x/leak4.jsonl    (467 = host dockerd)
ln -s /proc/467/environ             ~/.claude/projects/x/leak5.jsonl
```
Inside the tenant all three are dangling ("No such file or directory").
Sensor (hostPID, uid 0, only SYS_PTRACE+DAC_READ_SEARCH, no hostPath) reading `/proc/<tenant pid>/root/root/.claude/projects/x/*.jsonl`:
```
leak1.jsonl => vm                                   <- the SENSOR's own /etc/sensor-secret (bind-mounted for the test)
leak4 => d165c2d88d894a4787be219662b439ad           <- HOST /etc/machine-id (matches `cat /etc/machine-id` on the host)
leak5 => SHELL=/bin/bash IS_SANDBOX=1 COREPACK_ENABLE_AUTO_PIN=0 CLAU...   <- environment of the host dockerd
```
Same result with --privileged. Absolute symlink targets are resolved against the reader's root, and the reader's /proc is the host pid namespace. With the design's `--host-root /host` mount a link to `/host/...` needs no pid guess at all. (PID 1 of this sandbox is unreadable even to host root, a sandbox peculiarity; on a normal node PID 1 is systemd.)

## E4. User namespaces (U1): holds

`setpriv --reuid 999 unshare --user --map-root-user --mount --pid --fork env CLAUDECODE=1 CLAUDE_CODE_SESSION_ID=s-userns sleep 86403` (uid_map `0 999 1`, user:[4026532284], full caps inside the userns).
```
sensor default caps:                    /proc/9555/environ: Permission denied ; /proc/9555/root: Permission denied
sensor SYS_PTRACE + DAC_READ_SEARCH:    CLAUDE_CODE_SESSION_ID=s-userns ; ROOT_OK
```
An init-userns sensor with the two caps reads rootless/userns targets. Not tested: kubelet `hostUsers: false` with idmapped mounts.

## E5. Short-lived containers and the transcript tail (P1-P3, V1)

poller.sh emulates process poll + re-open of the transcript through /proc/<pid>/root; the job writes one line per 100 ms then exits (`docker run --rm`).
```
P1 1.2 s job, 2 s poll:    lines written 12 ; agent_process_found=0 transcript_lines_captured=0
P2 6 s job,   2 s poll:    lines written 60 ; agent_process_found=1 transcript_lines_captured=56
P3 6 s job,   0.25 s poll: lines written 60 ; agent_process_found=1 transcript_lines_captured=60
```
The last poll interval of every session is lost when the reader re-opens by path (the path dies with the pid; `--rm` / pod deletion removes the layer).

V1, held file descriptor on a pod volume (loop-mounted ext4 bind-mounted into a container, fd opened via /proc/<pid>/root/data/t.jsonl):
```
container removed
read through held fd after container is gone: {"n":1} {"n":2-late}
umount of the volume mountpoint: OK (exit 0)
backing device still attached after umount? -> '/dev/loop0: ... vol.img'
after sensor closes fd -> ''
```
Holding the fd fixes the tail loss but pins the volume's block device after the kubelet's unmount "succeeds" (think RBD unmap / EBS detach busy) until the sensor closes it.

## E6. In-container "hook + stdout sink" (O1-O4)

```
O1 uid 999 hook, PID 1 is root:   echo ... > /proc/1/fd/1 -> Permission denied   (/proc/1/fd/1 is l-wx------ root, pipe)
   root:                          line appears in `docker logs`
   `docker exec` session stdout:  {"spoor":"exec-own-stdout"} printed to the exec client only; `docker logs` shows only {"spoor":"from-root"}
O2 24 concurrent writers x 150 single write(2) calls of a 5998-byte line to the container stdout pipe:
   lines expected 3600 got 3600 ; well-formed 3598 ; malformed 2 (one 10093-byte merged line, one 1901-byte fragment)
O3 same writers, O_APPEND regular file: lines 3600 malformed 0
O4 --read-only rootfs, uid 999: mkdir $HOME/.spoor -> Read-only file system ; /var/spool, /tmp -> Read-only file system
```
Hook stdout is not the container's stdout at all: code.claude.com/docs/en/hooks.md lines 828-836: stdout "counts as JSON output only when you print one JSON object"; for `UserPromptSubmit, UserPromptExpansion, SessionStart, PostModelSwitch` "Claude Code adds plain-text stdout as context that Claude can see and act on"; otherwise it goes to the debug log. Two NDJSON lines on stdout are "plain text when no line is a JSON output object".

## E7. cgroup attribution (C1, C2)

```
C1 sensor with --cgroupns=private reading the workspace process:
   self:   8:pids:/
   target: 8:pids:/../3c35c0c0d610365ffe62ef75480c2757ff2e20954a31af625459ae02d0beef9d      (the "/docker/" prefix is gone)
C2 nested ids (--cgroup-parent=/kubepods/burstable/pod0a1b2c3d-.../aaaa...64):
   8:pids:/kubepods/burstable/pod0a1b2c3d-1111-2222-3333-444455556666/aaaaaaaa...(64)/26346b19b0b6...(64)   -> two 64-hex ids in one path
```
containerd gives every non-privileged container a private cgroup namespace on cgroup v2: release/1.7 pkg/cri/server/container_create_linux.go:784-789 ("cgroupns is not used when running in cgroup v1 mode or in privileged"; `if isUnifiedCgroupsMode() && !securityContext.GetPrivileged()`), same in main internal/cri/server/container_create.go:337-343. So the "privileged-ish" (non-privileged) DaemonSet on cgroup v2 sees `0::/../../..`-relative paths, and an in-container process sees its own cgroup as `/` (no container id). The container id is still recoverable in-container from /proc/self/mountinfo (`/var/lib/docker/containers/<id>/hostname /etc/hostname` observed here; kubelet pods expose `/var/lib/kubelet/pods/<uid>/etc-hosts`).
cgroup paths never contain namespace, pod name, labels or image.

## E8. Identity and lineage (I1, L1)

```
inside container: /etc/machine-id: No such file ; /sys/class/dmi/id/product_uuid: No such file (also absent on this Firecracker host) ; hostname = vm (host network)
L1: this shell has 58 CLAUDE* env vars (CLAUDECODE, CLAUDE_CODE_SESSION_ID, CLAUDE_CODE_REMOTE set); the container PID 1 it started has 0 of them, parent = containerd-shim
```
`docker run` / `kubectl exec` launched by an agent re-parents the work under the runtime shim: env markers and process lineage end there.

## Sources fetched this run

- kubernetes/website pod-security-standards.md: Baseline forbids `spec.hostPID` (line 82), HostPath volumes (lines 139-144), and adding capabilities beyond AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT (no SYS_PTRACE, no DAC_READ_SEARCH).
- containerd contrib/apparmor/template.go:98: `ptrace (trace,tracedby,read,readby) peer={{.Name}},` (ptrace read only toward peers under the same profile).
- code.claude.com/docs/en/devcontainer.md lines 115-122: managed settings are a `COPY` in the repo's Dockerfile; "anyone with write access can change or remove this step. For policy that engineers cannot bypass ... deliver managed settings through server-managed settings".
- fluent-bit-docs pipeline/filters/kubernetes.md:59,326 (metadata is derived from the tag `kube.var.log.containers.<pod>_<ns>_<container>-<id>.log`); pipeline/inputs/tail.md:18,48,66 (a line beyond `buffer_max_size` drops the file from monitoring unless `skip_long_lines`).
- research/small-oss.md:50,52 (Beacon ships `beacon ci exec`, cloud-sandbox hooks to GCS/S3, and a `--service none` supervised container mode); research/agent-surfaces-a.md:66 (headless runs hooks unless `--bare`); research/agent-surfaces-b.md:57 (Claude Desktop puts helper + Claude Code on the SSH remote; Cowork on Linux runs a QEMU/KVM VM); research/paid-vendors.md:7 (no vendor documents containers/CI/K8s).

## Findings summary (details in the structured result)

1. critical / broken: symlink confused deputy when reading tenant files via /proc/<pid>/root (E3).
2. critical / broken: "hostPID, privileged-ish" is blind to non-root agents and fails silently; real requirement is SYS_PTRACE + DAC_READ_SEARCH (E1).
3. critical / broken: in-container "hook + stdout sink" (E6).
4. high / broken: managed-tier hooks are not a control inside images the platform does not own; DaemonSet cannot install them without write access (E2 W1, devcontainer doc).
5. high / broken: short-lived pods and the transcript tail; held fds pin volumes (E5).
6. high / broken: gVisor/Kata/Firecracker and vendor-hosted sandboxes are invisible to hostPID (not testable here; this sandbox itself is a Firecracker agent VM).
7. high / broken: CI has no design at all; Beacon already ships `ci exec`.
8. high / broken: remote-SSH/Codespaces: laptop sensor sees an IDE and no agent.
9. high / weakened: security review of hostPID + hostPath (PSS, AppArmor, SELinux, write-through E2).
10. medium / weakened: cgroup attribution (E7).
11. medium / broken: host identity, per-host seq, user name and lineage inside containers (E8, X1).
12. low / holds: user namespaces / rootless targets (E4).

## Minimal honest container story for v1

Supported (v1):
- Node sensor DaemonSet for runc-class runtimes only (containerd, CRI-O, Docker; cgroup v1 and v2). Strictly read-only. Surfaces: process + transcript + inventory/posture inside containers. securityContext: hostPID true, non-zero uid with file caps cap_sys_ptrace,cap_dac_read_search (allowPrivilegeEscalation must stay true for file caps), drop ALL others, readOnlyRootFilesystem, no hostPath, AppArmor Unconfined / SELinux spc_t where enforced, namespace labelled PSA privileged. Events to the sensor pod's own stdout (existing kubelet log pipeline) or Forward/OTLP to a Service. Health event carries procs_total / procs_unreadable / sandboxed_runtime_shims so blindness is visible.
- In-image hook mode: static binary + managed hook config baked by a devcontainer Feature / Dockerfile snippet / init container; sink = O_APPEND spool in a declared writable dir that the node sensor harvests through /proc/<pid>/root, or direct OTLP/HTTP. Positioned as telemetry, not as a tamper-proof control.

Experimental (labelled):
- `spoor ci exec -- <cmd>` for GitHub-hosted and ARC runners (install, run, synchronous flush at exit).
- Codespaces / remote-SSH devcontainer Feature; laptop-side `remote_session` inventory record.
- gVisor / Kata pods (in-image mode only), guard mode in containers, pod metadata enrichment through a node-scoped API watch.

Not supported (say so): Fargate / Autopilot-style platforms without host namespaces, Windows containers, vendor-hosted agent sandboxes, jobs shorter than the process poll interval on the node surface.
