# deploy/kubernetes: verification record

Captured 2026-11-12 (re-run after the review fixes: the seccomp profile,
the hook selection on upgrade, the deb deconfigure and abort paths) from

```
SPOOR_E2E_CONTAINER=1 SPOOR_NFPM=<nfpm v2.49.0> go test -tags e2e ./test/e2e -run 'TestContainer|TestPackage' -v -count=1
...
--- PASS: TestContainerNodeSensor (18.88s)
    --- PASS: TestContainerNodeSensor/image (0.67s)
    --- PASS: TestContainerNodeSensor/refuses_to_start_without_both_capabilities (1.09s)
    --- PASS: TestContainerNodeSensor/capabilities_are_effective_for_the_non-root_sensor (0.00s)
    --- PASS: TestContainerNodeSensor/finds_the_in-container_agent_and_attributes_it (0.56s)
    --- PASS: TestContainerNodeSensor/container_scan_refuses_planted_symlink_escapes (0.25s)
    --- PASS: TestContainerNodeSensor/seccomp_profile_stops_ptrace-class_control_of_root_processes (0.94s)
    --- PASS: TestContainerNodeSensor/shipped_ConfigMap_configuration_runs (0.85s)
    --- PASS: TestContainerNodeSensor/no_new_privs_(observation) (0.46s)
--- PASS: TestContainerInImageHookMode (5.77s)
--- PASS: TestPackageDeb (16.99s)
--- PASS: TestPackageRPM (5.04s)
```

(The tests ran one at a time; the image build from the Dockerfile reused
BuildKit's cache, a cold build takes about 70 s more.) The deb and rpm
results are in `packaging/README.md`.

## Test bed and what it is not

Docker 29.9.2 (BuildKit, runc, overlayfs storage), cgroup v1 with the
cgroupfs driver, Linux 6.18 (a Firecracker VM), no AppArmor and no SELinux.
No kubelet, containerd CRI or CRI-O: the DaemonSet's pod spec was reproduced
with `docker run` flags that the test derives from `daemonset.yaml` itself
(`--pid=host`, `--user 65532:65532`, `--cap-drop ALL --cap-add SYS_PTRACE
--cap-add DAC_READ_SEARCH`, `--read-only`, a tmpfs for the emptyDir, the
ConfigMap's `spoor.yaml` mounted read-only at `/etc/spoor`, and the
`Localhost` seccomp profile as `--security-opt
seccomp=seccomp/node-sensor.json`). Every sensor run below is under that
profile; Docker's default profile was used only for the comparison in the
seccomp section. Not tested: cgroup v2 and private cgroup
namespaces (containerd's default for non-privileged pods on cgroup v2),
AppArmor/SELinux, user-namespaced pods, Kubernetes' own handling of
`allowPrivilegeEscalation` and capabilities.

The manifests were checked against the Kubernetes 1.31.0 API schemas (not
applied to a cluster):

```
kubeconform -strict -summary -kubernetes-version 1.31.0 namespace.yaml configmap.yaml daemonset.yaml
Summary: 4 resources found in 3 files - Valid: 4, Invalid: 0, Errors: 0, Skipped: 0
```

That run predates the change of `seccompProfile` from `RuntimeDefault` to
`Localhost` with `localhostProfile` (PodSecurityContext fields since
Kubernetes 1.19); it was not repeated because kubeconform is not installed
where the fixes were made.

The image was built by the test from the repository's `Dockerfile` with the
module vendored into a copy of the build context (no network in the build),
on `mirror.gcr.io/library/golang:1.26-bookworm` and
`gcr.io/distroless/static-debian12:nonroot`, both pinned by digest.

## Results

### File capabilities survive into the image (they do)

The question was whether `setcap`-style file capabilities written in the
build stage survive `COPY --from` into the final image. They do, with
BuildKit's COPY: the layer's tar entry for `usr/bin/spoor` carries the
attribute, and the running process has the capabilities.

```
EVIDENCE image layer usr/bin/spoor SCHILY.xattr.security.capability=0100000204000800000000000000000000000000 (want 0100000204000800000000000000000000000000: cap_dac_read_search,cap_sys_ptrace=ep)
EVIDENCE sensor process (host pid 23902): Uid="65532\t65532\t65532\t65532" CapPrm=0000000000080004 CapEff=0000000000080004 CapBnd=0000000000080004 CapAmb=0000000000000000 NoNewPrivs=0
```

`0x80004` is bit 2 (`CAP_DAC_READ_SEARCH`) and bit 19 (`CAP_SYS_PTRACE`)
and nothing else. The attribute value is byte for byte what `setcap
cap_dac_read_search,cap_sys_ptrace=ep` writes (libcap 2.66;
`packaging/container/filecap/filecap_test.go`). Not tested: other image
builders (kaniko, buildah, the legacy Docker builder) and registries that
re-pack layers; check `CapEff` of the running sensor after changing either.

### Without both capabilities the binary does not start

```
EVIDENCE docker run  <image> version -> err=exit status 255 output="exec /usr/bin/spoor: operation not permitted"
EVIDENCE docker run --cap-drop ALL --cap-add SYS_PTRACE <image> version -> err=exit status 255 output="exec /usr/bin/spoor: operation not permitted"
EVIDENCE docker run --cap-drop ALL --cap-add DAC_READ_SEARCH <image> version -> err=exit status 255 output="exec /usr/bin/spoor: operation not permitted"
```

The kernel refuses to execute a binary whose effective file capabilities it
cannot grant in full. Consequence: the image is only for the node sensor; in
other images use the bare binary (`--target binary` or the release
download).

### The sensor finds an agent in another container and attributes it

Workspace container (`mirror.gcr.io/library/redis:7`): account `dev` (uid
1000) with a 0700 home; a fake Claude Code (bash copied to
`~/.local/bin/claude`) running as uid 1000 with
`--dangerously-skip-permissions`, whose child carries `CLAUDECODE` and
`CLAUDE_CODE_SESSION_ID`. Sensor: the configuration from `configmap.yaml`
with `privacy.profile` switched to `standard` so that process activity is
shipped and can be inspected.

```
EVIDENCE agent.process.start: agent=claude-code pid=23749 user.id=1000 exe=/home/dev/.local/bin/claude flags=[--dangerously-skip-permissions] container=map[id:8ee32d1b0f59de327ccfd0dba628fe04836b35cfc0defa64f9c7f3c743f4e46d runtime:docker]
EVIDENCE process.exec of the agent's child: session.id=s-e2e-ed78e69afe51 env_markers=[CLAUDECODE CLAUDE_CODE_SESSION_ID] container.id=8ee32d1b0f59de327ccfd0dba628fe04836b35cfc0defa64f9c7f3c743f4e46d integrity=user
```

The container id is the workspace container's full id (from
`/proc/<pid>/cgroup`, cgroup v1 `docker/<id>`). The session id and markers
come from `/proc/<pid>/environ` of a uid-1000 process, which a uid-65532
process can read only with `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
Records are `integrity: user` because the daemon decides integrity by uid 0,
not by capabilities (see "Gaps").

### The seccomp profile takes away ptrace-class control of root processes

Review finding: with `hostPID` and an effective `CAP_SYS_PTRACE`, a
uid-65532 process can attach to any root process on the node under the
runtime's default seccomp profile, so "a non-root sensor cannot write
root-owned files" was not true of a compromised sensor. The test builds a
small static probe, gives it exactly the sensor's file capabilities with
`packaging/container/filecap`, and runs it with the sensor's docker flags
against the workspace container's main process (uid 0), once with Docker's
default profile and once with `seccomp/node-sensor.json`:

```
EVIDENCE probe with the sensor's uid and file capabilities, hostPID, Docker's default seccomp profile, against root pid 23687: Uid=65532 65532 65532 65532 CapEff=0000000000080004 environ_read=ok mem_open_write=EACCES mem_open_read=ok ptrace_attach=ok process_vm_writev=ok process_vm_readv=ok pidfd_getfd=ok kcmp=ok
EVIDENCE same probe under deploy/kubernetes/seccomp/node-sensor.json: Uid=65532 65532 65532 65532 CapEff=0000000000080004 environ_read=ok mem_open_write=EACCES mem_open_read=ok ptrace_attach=EPERM process_vm_writev=EPERM process_vm_readv=EPERM pidfd_getfd=EPERM kcmp=EPERM
```

Under the default profile the probe attached to the root process and read
its registers, and `process_vm_writev` and `pidfd_getfd` passed the kernel's
access check (zero-length calls: nothing was written or taken). Under the
profile all five calls fail with `EPERM`, while the reads the sensor relies
on still work (`environ`, `/proc/<pid>/mem` for reading). Opening
`/proc/<pid>/mem` for writing fails on file permissions under both
(`EACCES`). The sensor itself ran under the profile in every other test
here and attributed the in-container agent as before.

### A confined scan of the container root refuses planted escapes

`spoor scan --host-root /proc/<workspace pid>/root --json`, run inside the
sensor container as uid 65532. Planted in the workspace, all pointing at
files that exist only in the sensor container (`/etc/spoor/canary.json`,
`settings.json`, `mcp-config.json`, each declaring an MCP server named
`canary-<nonce>`):

| link | kind |
|---|---|
| `/etc/claude-code/managed-mcp.json -> /etc/spoor/canary.json` | absolute file link |
| `~/.cursor/mcp.json -> ../../../../../../etc/spoor/canary.json` | relative `..` escape |
| `~/proj/.mcp.json -> /proc/self/root/etc/spoor/canary.json` | magic link |
| `~/.gemini -> /etc/spoor` | directory link |
| `~/.copilot -> /proc/<sensor's host pid>/root/etc/spoor` | directory link through the sensor's own root |

```
EVIDENCE scan of /proc/<workspace pid>/root as uid 65532: files=3 denied=12 skipped=3 errors=0; canary-ed78e69afe51 absent from the output
EVIDENCE ledger: skipped (symbolic link not followed): /etc/claude-code/managed-mcp.json
EVIDENCE ledger: skipped (symbolic link not followed): /home/dev/.cursor/mcp.json
EVIDENCE ledger: skipped (symbolic link not followed): /home/dev/proj/.mcp.json
EVIDENCE ledger: paths refused below the directory links (denied, path resolves outside its root): map[.copilot:4 .gemini:7]
EVIDENCE positive control: mcp_server legit-ed78e69afe51 from ~/.claude.json user=map[id:1000 name:dev]; agent Claude Code at ~/.local/bin/claude; container stamped on the records: <nil>
EVIDENCE observation: a root-owned regular file inside the account's home (~/.factory/mcp.json) was read (mcp_server rootowned-ed78e69afe51); discovery does not require the file owner to equal the account
```

The positive control shows the scan really reads the container: a 0600
`~/.claude.json` in a 0700 home, as uid 65532. Two observations, not
failures of the test: the scan's records carry no `container` field, and a
root-owned file inside the account's home is read (an account cannot create
such a file itself; the Addendum's owner rule is about the transcript
harvester, which does not exist yet).

### The shipped ConfigMap configuration runs

Unmodified `configmap.yaml` configuration, `SPOOR_HOST_ID` set as the
downward API would set it:

```
EVIDENCE docker stop (SIGTERM): <nil> spoor-e2e-shipped-ed78e69afe51 exit code 0 after 200ms
EVIDENCE shipped config: 2 heartbeat(s), last at shutdown: host.id=node-e2e-ed78e69afe51 surfaces=map[hooks:ok/ outbox:ok/ processes:degraded/exec_source_poll scan:disabled/config transcripts:disabled/config]
```

No activity record was shipped (minimal profile). `processes` is
`degraded/exec_source_poll`: without the host network namespace the process
connector does not deliver, so the monitor polls.

### no_new_privs (observation only)

```
EVIDENCE with no-new-privileges (allowPrivilegeEscalation: false) under Docker: NoNewPrivs=1 CapPrm=0000000000080004 CapEff=0000000000080004
```

Docker's runc put the added capabilities in the process's permitted set
before exec, and no_new_privs limits exec to what the process already had,
so the sensor kept both. This is runtime behaviour, not something the
manifest relies on: it keeps `allowPrivilegeEscalation: true`. Not tested
with containerd's or CRI-O's runtime handling.

### In-image hook mode

```
EVIDENCE in-image hook "/usr/local/bin/spoor hook --agent claude-code": err=<nil> stdout="" stderr=""
EVIDENCE in-image detection on container stdout: type=detection.finding rule=SPR-EXEC-001 severity=high user=map[id:1000 name:dev] integrity=user
```

Layout of `in-image/Dockerfile.example` (managed hooks registered by root,
`/var/lib/spoor` owned by uid 1000, `spoor-entrypoint.sh` starting the
daemon as uid 1000), a `PreToolUse` payload with `curl ... | sh` piped
through the command the managed hook file registers. The hook printed
nothing; the detection appeared on the container's stdout (`docker logs`).

## Gaps found (reported to the integrator)

- `spoor run` decides "privileged" by uid 0, so the node sensor logs "not
  running privileged: only this account's agents are visible" and stamps
  `integrity: user`, although with the two capabilities it sees every
  account's agents (shown above).
- No harvester for transcripts inside containers, no `procs_unreadable`
  counter, no automatic container-root scans; `spoor scan --host-root
  /proc/<pid>/root` does not stamp `container` on its records.
- `host.name` is the pod's hostname.
