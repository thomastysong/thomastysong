# packaging

Service definitions and package build inputs for spoor. Install locations
are fixed, because the systemd unit, the launchd plist, the Fleet scripts
(`deploy/fleet/scripts`) and the Fleet policies depend on them:

| | binary | configuration | data |
|---|---|---|---|
| Linux (deb, rpm) | `/usr/bin/spoor` | `/etc/spoor/spoor.yaml` | `/var/lib/spoor` (root:spoor 0711) |
| macOS (pkg) | `/usr/local/bin/spoor` | `/Library/Application Support/spoor/spoor.yaml` | same directory; logs in `/Library/Logs/spoor` |
| Windows | `C:\Program Files\spoor\spoor.exe` | `C:\ProgramData\spoor\spoor.yaml` | `C:\ProgramData\spoor` |

| path | what | tested here |
|---|---|---|
| `systemd/spoor.service` | the Linux unit (hardening, `Group=spoor`, capability bounding set) | `systemd-analyze verify` (by the lead); installed by the packages below |
| `launchd/com.github.thomastysong.spoor.plist` | the macOS LaunchDaemon | no (no macOS host) |
| `windows/install-service.ps1` | Windows service install/update/uninstall | no (no Windows host, no pwsh) |
| `windows/spoor.wxs` | WiX v4 installer **sketch** | no: never compiled |
| `linux/nfpm.yaml`, `linux/*.sh` | deb/rpm configuration and maintainer scripts | yes: built and installed, see below |
| `macos/postinstall`, `macos/build-pkg.sh` | pkg post-install script, pkgbuild wrapper | `sh -n` only |
| `container/filecap` | sets file capabilities in the Dockerfile's build stage | unit tests against bytes setcap(8) wrote; used by every image build |

`packaging_test.go` keeps these consistent with each other, with
`.goreleaser.yaml`, the Dockerfile and `deploy/kubernetes` (paths, group,
data directory mode, extension paths, script syntax under sh/dash/bash,
the hook selection, the DaemonSet's security context, and the ConfigMap
loaded with the daemon's own configuration loader).

## Linux packages

Built by goreleaser for releases (`nfpms` in `.goreleaser.yaml`) or by
`make package` (nfpm and `linux/nfpm.yaml`, the same contents and scripts).
Contents: the binary, `/usr/lib/systemd/system/spoor.service`, the license.

Maintainer scripts (POSIX sh; deb and rpm call conventions both handled):

- **preinstall**: creates the system group `spoor` (groupadd, else
  addgroup). The unit runs with `Group=spoor` and does not start without it.
- **postinstall**: the group again; `/etc/spoor` (root 0755) and
  `/var/lib/spoor` (root:spoor 0711, as the unit's `StateDirectoryMode=`
  sets it at every start); `spoor.yaml` from `spoor export config` when there
  is none (never overwritten); when spoor is registered as an osquery
  extension (the line `register-extension.sh` adds to
  `/etc/osquery/extensions.load`) it refreshes the copy osquery runs and
  schedules a detached osquery restart; systemd: daemon-reload, enable and
  start on first install, `try-restart` on upgrade (a service the
  administrator disabled stays disabled); then it rewrites spoor's managed
  hook entries only where they are exactly what an earlier release wrote
  with install's default options (`spoor hooks status --scope managed
  --json` says "written by an earlier spoor release" in their detail; they
  report "modified" until `spoor hooks install` runs again). The rewrite
  uses the default options, so entries installed with `--guard
  --fail-closed`, a `--timeout` or edited by hand are left as they are and
  listed (`managed hooks of <agents> left as they are`): rewriting them
  would turn a fail-closed guard into a fail-open one. Agents never hooked
  are left alone. `abort-deconfigure` starts the daemon again when it is
  enabled; `abort-remove` enables and starts it and puts back the osquery
  extension line prerm noted.
- **preremove** (removal only; nothing on upgrade): stops and disables the
  service; removes spoor's line from `/etc/osquery/extensions.load` (other
  lines kept; written to a copy with the file's owner and mode and renamed
  over it, so a failure never truncates it), notes it in
  `/var/lib/spoor/.osquery-extension` for `abort-remove`, removes the
  extension copy and schedules an osquery restart; last, `spoor hooks
  uninstall --scope managed` while the binary still exists, so no agent
  keeps calling a missing binary (fail-closed guard entries would block the
  agent). Every step only warns, so dpkg never has to undo a half-done
  removal. On `deconfigure` (deb) it only stops the daemon: the files stay,
  and hooks and the extension keep pointing at them.
- **postremove**: daemon-reload; drops prerm's note. On deb purge also removes `/etc/spoor` and
  `/var/lib/spoor` (a `data_dir` configured elsewhere is reported, never
  deleted) and deletes the group only when it has no members and no file
  under the known directories belongs to it. rpm leaves the group.

The packages do **not** register the osquery extension: the tier (ATC or
extension) is the operator's choice, and Fleet runs
`deploy/fleet/scripts/register-extension.sh` as the post-install script of
the extension tier.

### Verified (test/e2e/container_test.go, 2026-11-12)

`TestPackageDeb` (Debian bookworm, `mirror.gcr.io/library/redis:7`) and
`TestPackageRPM` (`mirror.gcr.io/library/rockylinux:9`), nfpm v2.49.0, two
builds 0.1.0 and 0.1.1, no systemd in the containers (the scripts' systemd
branches did not run; they print where they would have acted):

- install: group created; `root:spoor 711 /var/lib/spoor`, `root:root 644
  /etc/spoor/spoor.yaml`, `root:root 644 /usr/lib/systemd/system/spoor.service`,
  `root:root 755 /usr/bin/spoor`; `spoor version` 0.1.0;
- `register-extension.sh` added `/usr/lib/spoor/spoor.ext` after an existing
  line without a final newline; managed hooks installed for claude-code with
  `--guard --fail-closed --timeout 30` and for gemini-cli with the defaults,
  then gemini-cli's command lines put back in an earlier release's form
  (status `modified`, detail `written by an earlier spoor release ...`);
- upgrade to 0.1.1: the extension copy refreshed (same SHA-256 as
  `/usr/bin/spoor`), `managed hooks rewritten for gemini-cli` (`managed`
  afterwards), `managed hooks of claude-code left as they are` with the
  file's SHA-256 unchanged (4 `"onFailure": "block"` entries, 15
  `"timeout": 30`), codex still `missing` (not hooked by the upgrade), the
  extension line kept;
- deb only, maintainer scripts called directly: `prerm deconfigure` left the
  extension line, its copy and the hook file as they were; `prerm remove`
  took the line out and noted it, `postinst abort-remove` restored the line
  after the other one and the copy (same SHA-256 as `/usr/bin/spoor`) and
  dropped the note;
- remove: binary and `/usr/lib/spoor` gone, spoor's extension line removed
  and the other kept, the managed hook files removed (backups remain beside
  them), group, configuration and data kept;
- deb purge with a member in the group: configuration and data removed,
  `group spoor kept: it has members (shipper)`; purge without members: the
  group is deleted.
- The two independent `go build` runs of 0.1.1 (deb test, rpm test) produced
  the same binary (SHA-256 `53d9a427...`): the build is reproducible on one
  machine and toolchain.

`goreleaser check` passes and `goreleaser release --snapshot --clean
--skip=sign,sbom,publish` (v2.20.1, on a scratch copy of the module) built
all six binaries, the darwin universal binary, the archives, deb and rpm for
amd64 and arm64, the raw `spoor_<os>_<arch>` binaries and `checksums.txt`.
Signing (cosign) and SBOMs (syft) were skipped: neither tool is installed
here.

## macOS and Windows

Written to match the Fleet scripts, not run: `macos/build-pkg.sh` needs
pkgbuild, and an unsigned, unnotarized package is blocked by Gatekeeper and
most MDM pipelines. Full Disk Access for `/usr/local/bin/spoor` must come
from an MDM PPPC profile. `windows/install-service.ps1` registers the
service through `New-Service`/CIM because Windows PowerShell 5.1 does not
escape the quotes embedded in `sc.exe binPath=` arguments (found by the Fleet
script builder); `windows/spoor.wxs` is a sketch for an MSI (well-formed XML,
checked by `packaging_test.go`; never compiled).

On Windows the configuration directory is the data directory
(`C:\ProgramData\spoor`). Both installers give SYSTEM and Administrators
full control of everything in it and give Users list and read on the
directory itself only (not inherited) plus read on `spoor.yaml`:
`spoor hook` runs as the developer, reads `spoor.yaml` (an unreadable file
silently means built-in defaults: no central guard mode, privacy profile or
exclusions) and checks the kill switch file, while `state.db` and what the
daemon writes later inherit SYSTEM and Administrators only. A tool that
replaces `spoor.yaml` with a new file instead of writing it in place drops
the Users grant; run the script again. The hook selection on update and the
osquery extension copy (refreshed on update, unregistered on `-Uninstall`)
follow the Linux scripts and the Fleet scripts.
