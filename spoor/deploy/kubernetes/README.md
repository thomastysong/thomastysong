# spoor on Kubernetes and in containers

Two ways to watch AI coding agents that run in containers, and a list of
places where neither works. What is stated here was run with Docker 29 on a
Linux 6.18 node (runc, overlayfs, cgroup v1, no AppArmor or SELinux); the
captured results are in `VERIFIED.md` next to this file in the source tree
(`test/e2e/container_test.go`). Nothing here has run under a kubelet: the
manifests are checked for the properties below by `packaging/packaging_test.go`
and their pod spec is reproduced with `docker run` flags by the e2e test.

```
kubectl apply -k .            # namespace.yaml, configmap.yaml, daemonset.yaml
```

Build the image with `make image` (or `docker buildx build --platform
linux/amd64,linux/arm64 ...`) and set it in `kustomization.yaml`; no image
is published yet.

## 1. Node sensor (DaemonSet)

One pod per node runs `spoor run` read-only and writes one NDJSON record per
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
| `runAsUser: 65532`, `runAsNonRoot` | a uid-0 sensor can write root-owned files in any other container through `/proc/<pid>/root`, even with every write capability dropped (red team E2, W3). A non-root sensor writes nothing that is not world-writable. |
| capabilities `drop: [ALL]`, `add: [SYS_PTRACE, DAC_READ_SEARCH]` | reading another uid's `/proc/<pid>/environ` and `/proc/<pid>/root` needs `CAP_SYS_PTRACE`; reading 0700 homes and 0600 transcripts needs `CAP_DAC_READ_SEARCH`. hostPID alone reads only `cmdline` and `cgroup` and silently misses every non-root agent (red team E1). |
| file capabilities on the binary | a non-root container gets no effective capability from `add` (red team E1, variant I: CapEff 0). The image's `/usr/bin/spoor` carries `cap_dac_read_search,cap_sys_ptrace=ep`, set in the Dockerfile's build stage. Verified: the attribute survives `COPY --from` into the final image, and the running sensor has CapPrm = CapEff = `0x80004` (exactly those two). |
| `allowPrivilegeEscalation: true` | `false` sets no_new_privs, which is meant to stop exec from granting file capabilities. Under Docker the sensor still got both (runc had put them in the permitted set before exec, and no_new_privs intersects with it); that is a runtime detail this deployment does not rely on. |
| both capabilities in the bounding set, or no start | with the effective bit set, the kernel refuses to execute a binary whose file capabilities it cannot grant in full. Verified: without them, or with only one, `exec /usr/bin/spoor: operation not permitted`. A misconfigured sensor crash-loops instead of running blind. |
| `readOnlyRootFilesystem`, `emptyDir` at `/var/lib/spoor` | the outbox, local ring and state database live as long as the pod; records leave through stdout. |
| no `hostPath`, `automountServiceAccountToken: false`, `hostNetwork: false` | nothing of the node's file system is mounted, the pod holds no API token, and nothing listens. Without the host network namespace the Linux process connector does not deliver, so the sensor polls `/proc` (200 ms while an agent runs, 2 s otherwise; heartbeat surface `processes: degraded/exec_source_poll`): processes shorter than the poll interval can be missed. |
| `appArmorProfile: Unconfined`, `seLinuxOptions.type: spc_t` | container default profiles allow ptrace-class reads only toward peers under the same profile, which would hide other containers' `environ` (containerd's AppArmor template). UNVERIFIED: the test node has neither AppArmor nor SELinux. |
| namespace labelled `pod-security.kubernetes.io/enforce: privileged` | hostPID and these two capabilities are outside the Pod Security Standards' baseline. Keep nothing else in the namespace. |
| `SPOOR_HOST_ID` from `spec.nodeName` | the container has no machine id of its own. `host.name` in records is the pod's hostname; the log pipeline adds node and pod metadata. |

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
  container works: `kubectl exec -n spoor <sensor pod> -- /usr/bin/spoor scan
  --host-root /proc/<pid>/root --json`, with `<pid>` a process of that
  container as the node sees it. Verified: it found the agent and a 0600 MCP
  declaration in a 0700 home as uid 65532, and refused five planted links
  (absolute, relative `..`, `/proc/self/root` magic link, and two directory
  links, one through the sensor's own `/proc/<pid>/root`); the canary
  behind them never appeared. Its records carry no `container` field.
- **No `procs_unreadable` counter.** A sensor that lacks the capabilities
  does not start at all (above), but a sensor blinded some other way (an
  LSM denying ptrace reads) reports agents without session ids and markers
  and no health counter says so.
- Hook spools written inside containers are not collected by the node
  sensor; use in-image hook mode (below), which runs its own daemon.

## 2. In-image hook mode

For images you build (devcontainers, agent images, CI images): the agents'
hooks are registered at build time and a spoor daemon inside the container
collects them.

- `in-image/Dockerfile.example`: bare binary (release download with
  `ADD --checksum`, or the Dockerfile's `binary` target; never the node
  sensor's binary, which does not start without the two capabilities),
  `spoor hooks install --scope managed` (root-owned policy files), a small
  configuration (`output.stdout: true`), a data directory owned by the
  workspace user, and `in-image/spoor-entrypoint.sh` as the entrypoint.
- `in-image/spoor-entrypoint.sh`: starts `spoor run` next to the image's
  command so the daemon's stdout is the container's log.
- `in-image/devcontainer-feature/`: the same as a devcontainer Feature
  (SKETCH, not run with the devcontainer CLI).

Hook stdout is the agent's control channel (Claude Code adds plain stdout to
the model's context for some events), so hooks never write records there:
they append to a spool under the daemon's data directory and the daemon
re-detects with the full rule set. Verified (VERIFIED.md): with the layout
above, running as uid 1000, a `curl ... | sh` tool call piped through the
exact command the managed hook file registers produced
`detection.finding` (SPR-EXEC-001, high) on the container's stdout; the hook
printed nothing.

This is telemetry, not a tamper-proof control: anyone who runs commands in
the container as its user can stop the daemon or change what it reads, and
its records are `integrity: user`. Records of the last second can be lost
when the container's main command exits. With a read-only root file system,
mount a writable volume at `/var/lib/spoor` owned by the workspace user.
Experimental alternatives: `output.forward` / `output.otlp` shippers to a
collector Service (not run here); `spoor ci exec` for CI jobs.

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
