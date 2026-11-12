# hawkbell on Kubernetes and in containers

Two ways to watch AI coding agents that run in containers, and a list of
places where neither works. What is stated here as verified was run with
Docker 29.9.2 on a Linux 6.18 VM (runc, overlayfs, cgroup v1, no AppArmor or
SELinux); the captured results are in `VERIFIED.md` next to this file in the
source tree (`test/e2e/container_test.go`; last run after the rename: 4
tests and 8 subtests passed). Nothing here has run under a kubelet, on
containerd's or CRI-O's runtime, or on cgroup v2. The e2e test reproduces
the pod spec with `docker run` flags it reads from `daemonset.yaml`
(`--pid=host`, the user, the added capabilities, `--read-only`, the
seccomp profile). `packaging/packaging_test.go` checks the manifests
(`TestDaemonSet`, `TestSeccompProfile`) and loads the ConfigMap's
configuration with the daemon's own loader. An earlier version of the
manifests passed `kubeconform -strict` against the Kubernetes 1.31.0
schemas; that run predates the switch of `seccompProfile` to `Localhost`
and was not repeated. `appArmorProfile` needs Kubernetes 1.30 or later.

```
# on every Linux node first (section 1, "Seccomp profile"):
install -D -m 0644 seccomp/node-sensor.json /var/lib/kubelet/seccomp/hawkbell/node-sensor.json
kubectl apply -k .            # namespace.yaml, configmap.yaml, daemonset.yaml
```

`hawkbell export kubernetes --out DIR` writes these files from the binary
(all of this directory except `VERIFIED.md`). Build the image with `make
image` (`docker build`, this machine's platform, tagged
`hawkbell:<version>`) or `docker buildx build --platform
linux/amd64,linux/arm64 ...` (the Dockerfile's header), push it to your
registry and set it in the `images:` block of `kustomization.yaml`; no
image is published yet.

## 1. Node sensor (DaemonSet)

One pod per node runs `hawkbell run` read-only and writes one NDJSON record per
line to its stdout, which the cluster's log agent collects
(`deploy/fluent-bit/kubernetes.yaml`).

### What it sees

Every process on the node, through the host pid namespace: agent roots
(`agent.process.start`: agent id, pid, uid, executable, risky flags such as
`--dangerously-skip-permissions`), their children (`process.exec` with the
agent's session id and marker variables read from `/proc/<pid>/environ`),
and the container each one runs in (`container.id`, `container.runtime`, from
`/proc/<pid>/cgroup`). Rules run on these records; detections, sensor health
with per-agent coverage, and session summaries go to stdout. With the default
`minimal` privacy profile process activity stays in the pod's local ring;
`standard` ships it, redacted.

Verified (VERIFIED.md): a fake Claude Code running as uid 1000 inside another
container was reported with its container id, uid, risky flag, and the
session id and markers of its child, by a sensor running as uid 65532 with
only the two capabilities below.

### Why the pod spec looks like this

| Setting | Why |
|---|---|
| `hostPID: true` | the sensor must see other containers' processes. |
| `runAsUser: 65532`, `runAsNonRoot` | a uid-0 sensor owns every root-owned file it reaches through `/proc/<pid>/root` in other containers, so it can write them even with every capability dropped. A non-root sensor cannot pass file permission checks for writing (`CAP_DAC_READ_SEARCH` bypasses read and search checks only), so it cannot write root-owned files through the file system. That alone does not make it write-safe: see `seccompProfile`. |
| `seccompProfile: Localhost`, `hawkbell/node-sensor.json` | `CAP_SYS_PTRACE` with `hostPID` lets a process attach to any process on the node, root ones included, and rewrite its registers and memory (`ptrace`, `process_vm_writev`) or take its open files (`pidfd_getfd`); the runtime default profile allows those calls to a holder of the capability (Docker's, verified; containerd's default is built from the same list, UNVERIFIED here). Verified with Docker's default profile: a uid-65532 probe with exactly the sensor's capabilities attached to a root process in another container and read its registers. The sensor needs the capability only for the kernel's access checks on `/proc/<pid>/{environ,root,cwd}` reads, never those calls, so its profile is the default one without them (below). Verified: under it the same probe gets `EPERM` from `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` and `kcmp`, while reading the root process's `environ` still works and the sensor attributes the in-container agent as before. |
| capabilities `drop: [ALL]`, `add: [SYS_PTRACE, DAC_READ_SEARCH]` | reading another uid's `/proc/<pid>/environ` and `/proc/<pid>/root` needs `CAP_SYS_PTRACE`; reading 0700 homes and 0600 transcripts needs `CAP_DAC_READ_SEARCH`. hostPID alone gives other processes' `cmdline` and `cgroup`, not their `environ`, so the session ids and markers of every non-root agent would be missing. Verified: with the two capabilities a uid-65532 sensor read them from a uid-1000 agent's child. |
| file capabilities on the binary | for a non-root process, exec grants capabilities only from the binary's file capabilities (or the ambient set), so `add` alone leaves the effective set empty. The image's `/usr/bin/hawkbell` carries `cap_dac_read_search,cap_sys_ptrace=ep`, set in the Dockerfile's build stage (`packaging/container/filecap`). Verified: the attribute survives `COPY --from` into the final image, and the running sensor has CapPrm = CapEff = `0x80004` (exactly those two). |
| `allowPrivilegeEscalation: true` | `false` sets no_new_privs, which is meant to stop exec from granting file capabilities. Under Docker the sensor still got both (runc had put them in the permitted set before exec, and no_new_privs intersects with it); that is a runtime detail this deployment does not rely on. |
| both capabilities in the bounding set, or no start | with the effective bit set, the kernel refuses to execute a binary whose file capabilities it cannot grant in full. Verified: without them, or with only one, `exec /usr/bin/hawkbell: operation not permitted`. A misconfigured sensor crash-loops instead of running blind. |
| `readOnlyRootFilesystem`, `emptyDir` at `/var/lib/hawkbell` (`sizeLimit: 1Gi`) | the outbox, local ring and state database live as long as the pod; records leave through stdout. |
| no `hostPath`, `automountServiceAccountToken: false`, `hostNetwork: false` | nothing of the node's file system is mounted, the pod holds no API token, and nothing listens. Without the host network namespace the Linux process connector does not deliver, so the sensor polls `/proc` (200 ms while an agent runs, 2 s otherwise; heartbeat surface `processes: degraded/exec_source_poll`): processes shorter than the poll interval can be missed. |
| `appArmorProfile: Unconfined`, `seLinuxOptions.type: spc_t` | container default profiles allow ptrace-class reads only toward peers under the same profile, which would hide other containers' `environ` (containerd's AppArmor template). UNVERIFIED: the test node has neither AppArmor nor SELinux. |
| namespace labelled `pod-security.kubernetes.io/enforce: privileged` | hostPID and these two capabilities are outside the Pod Security Standards' baseline. Keep nothing else in the namespace. |
| `HAWKBELL_HOST_ID` and `HAWKBELL_HOST_NAME` from `spec.nodeName` | the container has no machine id of its own, and its kernel host name is the pod's name. With both set, `host.id` and `host.name` in records are the node's name (internal/platform/hostid.go); the log pipeline adds pod metadata. The container test set `HAWKBELL_HOST_ID` only (`host.id` verified); `HAWKBELL_HOST_NAME` is covered by unit tests. |

### What a compromised sensor can do

Read: every file and every process's memory on the node (`CAP_DAC_READ_SEARCH`
and `CAP_SYS_PTRACE` exist to read other users' files and `/proc` entries,
and `/proc/<pid>/mem` opens for reading with them). Treat the sensor's
image, configuration and namespace like any other node-level agent.

Write: with the seccomp profile, what uid and gid 65532 may write under the
kernel's file permission checks: world-writable files, and, through
`/proc/<pid>/root` and `/proc/<pid>/mem`, the files and the process memory
of any other workload on the node that runs as 65532 (`/proc/<pid>/mem` is
mode 0600 and owned by the process's uid; `CAP_SYS_PTRACE` passes the
ptrace access check; the profile allows `openat` and `pwrite64`), plus
files group-writable for gid 65532. Distroless `:nonroot` images, this
image's base included, run as 65532. Opening a root process's
`/proc/<pid>/mem` for writing fails on file permissions (verified:
`EACCES`, VERIFIED.md); the recorded probe used only a root target, so
other uids were not probed there. A uid and gid that no other workload on
the node uses would leave only world-writable files and the sensor's own;
only 65532 was run, and `packaging/packaging_test.go` holds the shipped
manifest to it. With `RuntimeDefault` instead, or `Unconfined`, a
compromised sensor is equivalent to root on the node.

### Seccomp profile

`seccomp/node-sensor.json` is the default profile Docker applies to a
container with exactly these two capabilities on amd64 and arm64
(moby/profiles `seccomp/v0.1.0`, `default.json`, Apache-2.0), without
`ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`,
`process_madvise` and `open_by_handle_at` (the last one opens files by
handle outside the mount namespace with `CAP_DAC_READ_SEARCH`; hawkbell does
not use it). It is written in the plain OCI form, without moby's
`includes`/`excludes` conditions: those are not part of the OCI format, and
a runtime that reads only the OCI fields would drop the conditions and allow
every capability-gated call (UNVERIFIED which runtimes do: only Docker ran
here). `packaging/packaging_test.go` checks the form and the removed calls.

Kubernetes reads `Localhost` profiles from the kubelet's seccomp directory
(`/var/lib/kubelet/seccomp` unless the kubelet's root directory moved), so
the file must be on every Linux node before the DaemonSet starts: put it in
the node image or the node bootstrap, or distribute it with the Security
Profiles Operator (a `SeccompProfile` with the same rules; then set
`localhostProfile` to the path the operator reports). Not run under a
kubelet here. A pod on a node without the file should stay in
`CreateContainerError` (Kubernetes' documented behaviour for a missing
`Localhost` profile, not observed here), which is the intended failure.
Switching to
`type: RuntimeDefault` works everywhere and makes a compromised sensor
root-equivalent on the node (above); do it only knowingly.

### What the node sensor does not do yet

Stated plainly, because a quiet gap would read as "clean":

- **Transcripts inside containers are not read.** The daemon's transcript
  tailer follows homes in its own file system, so the ConfigMap switches it
  off. A harvester that follows each agent root through
  `/proc/<pid>/root` (openat2 `RESOLVE_IN_ROOT`, owner of the file = the
  agent's uid, non-blocking opens, checkpoints keyed by container id, pid
  start time and in-container path) is not part of this release.
- **Inventory and posture inside containers are not scanned by the daemon**
  (`sources.scan` is off for the same reason). A one-off confined scan of a
  container works: `kubectl exec -n hawkbell <sensor pod> -- /usr/bin/hawkbell scan
  --host-root /proc/<pid>/root --json`, with `<pid>` a process of that
  container as the node sees it. Verified: it found the agent and a 0600 MCP
  declaration in a 0700 home as uid 65532, and refused five planted links
  (absolute, relative `..`, `/proc/self/root` magic link, and two directory
  links, one through the sensor's own `/proc/<pid>/root`); the canary
  behind them never appeared. Its records carry the container's id and
  runtime in `container` (cmd/hawkbell/scancontainer.go; seen in the run
  after the rename, VERIFIED.md).
- **A blinded sensor shows it only in counters.** A sensor that lacks the
  capabilities does not start at all (above). One blinded some other way
  (an LSM denying ptrace reads) reports agents without session ids and
  markers. The heartbeat counts the processes that refused it with EACCES
  or EPERM (`procs_unreadable`, next to `procs_total`;
  internal/daemon/daemon.go), but on the node sensor the processes surface
  already reads `degraded/exec_source_poll`, which takes precedence over
  the `procs_unreadable` reason, so watch the counter. Not tested here (no
  LSM on the test node).
- Hook spools written inside containers are not collected by the node
  sensor; use in-image hook mode (below), which runs its own daemon.

## 2. In-image hook mode

For images you build (devcontainers, agent images, CI images): the agents'
hooks are registered at build time and a hawkbell daemon inside the container
collects them.

- `in-image/Dockerfile.example`: bare binary (release download with
  `ADD --checksum`, or the Dockerfile's `binary` target; never the node
  sensor's binary, which does not start without the two capabilities),
  `hawkbell hooks install --scope managed` (root-owned policy files), a small
  configuration (`output.stdout: true`), a data directory owned by the
  workspace user, and `in-image/hawkbell-entrypoint.sh` as the entrypoint.
- `in-image/hawkbell-entrypoint.sh`: starts `hawkbell run` next to the image's
  command so the daemon's stdout is the container's log.
- `in-image/devcontainer-feature/`: the same as a devcontainer Feature
  (SKETCH, not run with the devcontainer CLI).

Hook stdout is the agent's control channel (Claude Code adds plain stdout to
the model's context for some events), so hooks never write records there:
they append to a spool under the daemon's data directory and the daemon
re-detects with the full rule set. Verified (VERIFIED.md): with the layout
above, running as uid 1000, a `curl ... | sh` tool call piped through the
exact command the managed hook file registers produced
`detection.finding` (HB-EXEC-001, high) on the container's stdout; the hook
printed nothing.

This is telemetry, not a tamper-proof control: anyone who runs commands in
the container as its user can stop the daemon or change what it reads, and
its records are `integrity: user`. Records of the last second can be lost
when the container's main command exits. With a read-only root file system,
mount a writable volume at `/var/lib/hawkbell` owned by the workspace user.
Experimental alternatives: `output.forward` / `output.otlp` shippers to a
collector Service (not run here); `hawkbell ci exec` for CI jobs.

## 3. Not supported

- microVM runtimes (Kata Containers, Firecracker, gVisor) and sandboxes such
  as Docker Sandboxes or Apple's container: the node sees the VM, not the
  agent. Use in-image hook mode inside them.
- Docker Desktop, Colima, OrbStack and other VM-backed engines on macOS and
  Windows: containers run in a VM the host sensor cannot see into.
- Fargate, GKE Autopilot and other platforms without host namespaces.
- Windows containers and Windows nodes.
- NFS- or other network-backed home directories (root squash, no
  `CAP_DAC_READ_SEARCH` across the mount): not tested.
- Vendor-hosted agents (cloud sandboxes run by the agent vendor).
- Jobs shorter than the poll interval, on the node surface.
- Remote-SSH and Codespaces: the laptop's sensor sees an editor, not the
  agent; put in-image hook mode in the remote image.
