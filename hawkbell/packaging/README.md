# packaging

Service definitions and package build inputs for hawkbell. Install locations
are fixed, because the systemd unit, the launchd plist, the Fleet scripts
(`deploy/fleet/scripts`) and the Fleet policies depend on them:

| | binary | configuration | data |
|---|---|---|---|
| Linux (deb, rpm) | `/usr/bin/hawkbell` | `/etc/hawkbell/hawkbell.yaml` | `/var/lib/hawkbell` (root:hawkbell 0711) |
| macOS (pkg) | `/usr/local/bin/hawkbell` | `/Library/Application Support/hawkbell/hawkbell.yaml` | same directory; logs in `/Library/Logs/hawkbell` |
| Windows | `C:\Program Files\hawkbell\hawkbell.exe` | `C:\ProgramData\hawkbell\hawkbell.yaml` | `C:\ProgramData\hawkbell` |

| path | what | tested here |
|---|---|---|
| `systemd/hawkbell.service` | the Linux unit (hardening, `Group=hawkbell`, capability bounding set) | `systemd-analyze verify` (systemd 255): as shipped, on a host without the binary, its only message is `Command /usr/bin/hawkbell is not executable`; with `ExecStart` naming an existing binary it reports nothing (section "systemd-analyze verify (2026-11-12)" below). Installed by the packages below, never started under systemd ([docs/LIMITATIONS.md](../docs/LIMITATIONS.md)) |
| `launchd/com.github.thomastysong.hawkbell.plist` | the macOS LaunchDaemon | no (no macOS host) |
| `windows/install-service.ps1` | Windows service install/update/uninstall | no (no Windows host, no pwsh) |
| `windows/hawkbell.wxs` | WiX v4 installer **sketch** | no: never compiled |
| `linux/nfpm.yaml`, `linux/*.sh` | deb/rpm configuration and maintainer scripts | yes: built and installed, see below |
| `macos/postinstall`, `macos/build-pkg.sh` | pkg post-install script, pkgbuild wrapper | syntax only (`-n` under sh, dash and bash); the hook step of `postinstall` runs on Linux in `TestUpgradeKeepsHookOptions` |
| `container/filecap` | sets file capabilities in the Dockerfile's build stage | unit tests against bytes setcap(8) wrote; used by every image build |

`packaging_test.go` keeps these consistent with each other, with
`.goreleaser.yaml`, the Dockerfile and `deploy/kubernetes` (paths, group,
data directory mode, extension paths, script syntax under sh/dash/bash,
the hook selection, the DaemonSet's security context, and the ConfigMap
loaded with the daemon's own configuration loader). Some of its tests
build hawkbell or need root and are skipped otherwise.

## Linux packages

Built by goreleaser for releases (`nfpms` in `.goreleaser.yaml`) or by
`make package` (nfpm and `linux/nfpm.yaml`, the same contents and scripts;
it needs `nfpm` on the PATH). Contents: `/usr/bin/hawkbell`,
`/usr/lib/systemd/system/hawkbell.service`, and `LICENSE`, `NOTICE` and
`THIRD_PARTY_LICENSES` in `/usr/share/doc/hawkbell`.

Maintainer scripts (POSIX sh; deb and rpm call conventions both handled):

- **preinstall**: creates the system group `hawkbell` (groupadd, else
  addgroup). The unit runs with `Group=hawkbell` and does not start without it.
- **postinstall**: the group again; `/etc/hawkbell` (root 0755) and
  `/var/lib/hawkbell` (root:hawkbell 0711, as the unit's `StateDirectoryMode=`
  sets it at every start); `hawkbell.yaml` from `hawkbell export config` when there
  is none (never overwritten); when hawkbell is registered as an osquery
  extension (the line `register-extension.sh` adds to
  `/etc/osquery/extensions.load`) it refreshes the copy osquery runs and
  schedules a detached osquery restart; systemd: daemon-reload, enable and
  start on first install, `try-restart` on upgrade (a service the
  administrator disabled stays disabled); then `hawkbell hooks install
  --only-installed` for the managed scope and for Codex's system scope. It
  rewrites hawkbell's hook entries only in files that already hold them
  (entries an earlier release wrote report "modified" until install runs
  again), and keeps the options each file was installed with: `--guard
  --fail-closed` and `--timeout` are read back from the entries
  (cmd/hawkbell/hooks_reinstall.go), so an upgrade does not turn a
  fail-closed guard into a fail-open one. Entries that no install option
  reproduces (edited by hand) are left as they are and listed (`managed
  hooks of <agent> left as they are: ...`). Agents never hooked are left
  alone. `abort-deconfigure` starts the daemon again when it is enabled;
  `abort-remove` enables and starts it and puts back the osquery extension
  line prerm noted.
- **preremove** (removal only; nothing on upgrade): stops and disables the
  service; removes hawkbell's line from `/etc/osquery/extensions.load` (other
  lines kept; written to a copy with the file's owner and mode and renamed
  over it, so a failure never truncates it), notes it in
  `/var/lib/hawkbell/.osquery-extension` for `abort-remove`, removes the
  extension copy and schedules an osquery restart; last, `hawkbell hooks
  uninstall` for the managed and system scopes while the binary still
  exists, so no agent keeps calling a missing binary (fail-closed guard
  entries would block the agent). Every step only warns, so dpkg never has to undo a half-done
  removal. On `deconfigure` (deb) it only stops the daemon: the files stay,
  and hooks and the extension keep pointing at them.
- **postremove**: daemon-reload; drops prerm's note. On deb purge also removes `/etc/hawkbell` and
  `/var/lib/hawkbell` (a `data_dir` configured elsewhere is reported, never
  deleted) and deletes the group only when it has no members and no file
  under the known directories belongs to it. rpm leaves the group.

The packages do **not** register the osquery extension: the tier (ATC or
extension) is the operator's choice, and Fleet runs
`deploy/fleet/scripts/register-extension.sh` as the post-install script of
the extension tier.

### Verified (test/e2e/container_test.go, 2026-11-12)

Recorded before the rename from the working name spoor to hawkbell: commands, paths and names below use the old name.

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

### Rerun after the rename (2026-11-12)

This section was run after the rename, with the hawkbell code and the
renamed `packaging/` files; names below are the new ones. Same images and
nfpm v2.49.0 as above, two builds 0.1.0 and 0.1.1, no systemd in the
containers. The tree was the uncommitted rename on top of commit 253369f.

```
HAWKBELL_E2E_CONTAINER=1 HAWKBELL_NFPM=<nfpm v2.49.0> go test -tags e2e ./test/e2e -run 'TestContainer|TestPackage' -v -count=1
--- PASS: TestPackageDeb (10.18s)
--- PASS: TestPackageRPM (4.76s)
```

(The container tests of the same run are in
`deploy/kubernetes/VERIFIED.md`.) Both passed, with the same results as
above under the new names:

- install: group `hawkbell` created; `root:hawkbell 711 /var/lib/hawkbell`,
  `root:root 755 /etc/hawkbell`, `root:root 644 /etc/hawkbell/hawkbell.yaml`,
  `root:root 755 /usr/bin/hawkbell`, `root:root 644
  /usr/lib/systemd/system/hawkbell.service`; `hawkbell version` 0.1.0;
- `register-extension.sh` added `/usr/lib/hawkbell/hawkbell.ext` after
  `/opt/other/x.ext` (no final newline); managed hooks installed for
  claude-code with `--guard --fail-closed --timeout 30` and for gemini-cli
  with the defaults; gemini-cli's entries put back in an earlier release's
  form (status `modified`, detail `written by an earlier hawkbell release
  ...`);
- upgrade to 0.1.1: the extension copy refreshed (same SHA-256 as
  `/usr/bin/hawkbell`), `managed hooks rewritten for gemini-cli` (`managed`
  afterwards), `managed hooks of claude-code left as they are: already what
  install writes (--guard --fail-closed --timeout 30)` with the file's
  SHA-256 unchanged (4 `"onFailure": "block"` entries, 15 `"timeout": 30`),
  codex still `missing`, the extension line kept;
- deb only: `prerm deconfigure` left the extension line, its copy and the
  hook file as they were; `prerm remove` took the line out, `postinst
  abort-remove` restored it after the other line and restored the copy
  (same SHA-256 as `/usr/bin/hawkbell`);
- remove: binary and `/usr/lib/hawkbell` gone, the extension line removed
  and the other kept, the managed hook files removed (backups
  `*.hawkbell-<time>.bak` remain beside them), group, configuration and data
  kept;
- deb purge with a member in the group: configuration and data removed,
  `group hawkbell kept: it has members (shipper)`; purge without members:
  the group is deleted;
- the two builds of 0.1.1 (deb test, rpm test) produced the same binary
  (SHA-256 `5ea76d96...`).

`hooks status` reports claude-code's managed file as `modified` before and
after the upgrade (`ConfigChange differs, ...`: it compares with a default
install, and this one has guard mode and a 30 s timeout). That is not a
change from the rename: the binary built from commit 253369f (before the
rename) reports the same for the same install in the same container.

`go test -count=1 ./packaging/...`: 18 tests and subtests, all passed.
Not rerun: the goreleaser check and snapshot (goreleaser is not installed
here).

### systemd-analyze verify (2026-11-12)

Static check of `systemd/hawkbell.service` at commit 6d0d308 (the unit is
unchanged in the working tree), on the build host: systemd 255
(255.4-1ubuntu8.18), no `hawkbell` group, `/usr/bin/hawkbell` absent. `$S`
is a scratch directory holding a binary built with `go build ./cmd/hawkbell`.

```
$ systemd-analyze verify packaging/systemd/hawkbell.service; echo "exit $?"
hawkbell.service: Command /usr/bin/hawkbell is not executable: No such file or directory
exit 1
$ sed "s|^ExecStart=/usr/bin/hawkbell |ExecStart=$S/hawkbell |" packaging/systemd/hawkbell.service > $S/sa/hawkbell.service
$ systemd-analyze verify $S/sa/hawkbell.service; echo "exit $?"
exit 0
```

The second run printed nothing. `verify` loads and checks the unit; it
does not start it, so this says nothing about the hardening at run time:
the unit has still never been started under systemd (no systemd in the
package test containers, a fake `systemctl` in the Fleet script test).
`deploy/fleet/scripts/install-hawkbell.sh` embeds the same directives
(`TestEmbeddedServiceDefinitions`) and was not checked separately.

## macOS and Windows

Written to match the Fleet scripts, not run: `macos/build-pkg.sh` needs
pkgbuild (macOS only). It signs the package only when `HAWKBELL_PKG_SIGN`
names a "Developer ID Installer" identity, does not sign the binary and
does not notarize; Gatekeeper and MDM deployment expect all three. Full
Disk Access for `/usr/local/bin/hawkbell` must come from an MDM PPPC
profile. `windows/install-service.ps1` registers the
service through `New-Service`/CIM because Windows PowerShell 5.1 does not
escape the quotes embedded in `sc.exe binPath=` arguments
(`TestPowerShellNativeArguments` in internal/fleetgen models that argument
passing and reproduces the failure); `windows/hawkbell.wxs` is a sketch for
an MSI (well-formed XML, checked by `packaging_test.go`; never compiled).

On Windows the configuration directory is the data directory
(`C:\ProgramData\hawkbell`). Both installers (`install-service.ps1` and the
`hawkbell.wxs` sketch) give SYSTEM and Administrators
full control of everything in it and give Users list and read on the
directory itself only (not inherited) plus read on `hawkbell.yaml`:
`hawkbell hook` runs as the developer, reads `hawkbell.yaml` (an unreadable file
silently means built-in defaults: no central guard mode, privacy profile or
exclusions) and checks the kill switch file, while `state.db` inherits
SYSTEM and Administrators only. The daemon gives each directory it creates
(outbox, spools, rule bundle and the rest) a protected ACL of its own,
which the files in it inherit: SYSTEM and Administrators full control, plus
Users read on the rule bundle and modify for each account on its own spool
directory (internal/daemon/dirs_windows.go; compiled, not run on Windows).
A tool that replaces `hawkbell.yaml` with a new file instead of writing it
in place drops the Users grant; run the script again. The hook selection on update and the
osquery extension copy (refreshed on update, unregistered on `-Uninstall`)
follow the Linux scripts and the Fleet scripts.
