# deploy/fleet: verification record

Captured 2026-11-12, and re-run after the adversarial review's fixes (tier-3
examples, binary-only install policies, path and opt-in report changes,
verify.sh polling), against the live test stack of this repository's build
sandbox: **Fleet 4.94.1** (license tier Free), **fleetctl 4.94.1**, and one
enrolled host `vm` running **plain osquery 5.19.0** on Ubuntu (not fleetd).
Paths under the build scratchpad are shortened to `$S` below; nothing else in
the captured output is edited.

## Safety on a shared server

- `fleetctl gitops` was only ever run with `--dry-run`.
- The server's agent options were saved (`fleetctl get config --yaml` and
  `--json`) before spoor's ATC tables were applied, and restored afterwards.
  The run's last lines confirm the restored agent options are **identical**
  to the saved copy, and that **no** label, report or policy named
  `spoor-c5-*` was left. The extension probe below restored them again and
  re-checked (identical).
- Labels, policies and reports were applied one by one with
  `fleetctl apply -f` under the prefix `spoor-c5-` and deleted by name
  (`fleetctl delete -f` for labels and reports, the policy delete API for
  policies).
- For the extension tier the throwaway extension was appended to the host's
  `extensions.load`, osqueryd was restarted as ENV.md describes, and at the
  end the line was removed (the file is empty again) and osqueryd restarted.
  Afterwards (checked again after the re-run): host `vm` online,
  `osquery_extensions` lists only `core`, no `spoor_*` table registered.

## 1. Live run of verify.sh (ATC tier and extension tier)

Command (the extension was built outside the repository from a scratch
`main` that calls `osqext.Run` against the harness database):

```
FLEETCTL=$S/fleetfix/bin/fleetctl FLEET_HOST=vm WORK=$S/fleetfix/verify PREFIX=spoor-c5- \
EXT_LOAD=$S/fleetstack/osq/extensions.load EXT_BIN=$S/fleetfix/ext/spoor-fix.ext \
OSQUERY_RESTART=$S/fleetfix/bin/restart-osqueryd ./deploy/fleet/verify.sh
```

The state databases were written by the harness in `test/e2e/fleet_test.go`
through `state.Store.Apply`, `SetAgentProcesses`, `SetCoverage` and
`MarkScan`; the planted project files and MCP server went through
`discovery.ScanProject`. `SPOOR_BIN` was not used: `cmd/spoor` was not built
for this run. Each policy is checked twice: as a live query (a row means
pass) and as Fleet's own policy result after a host refetch.

A first attempt of this re-run stopped at the GitOps dry run, which is what
it is for: `label "spoor tables unavailable" description may not exceed 255
characters` (the description had been extended). It was shortened, and a
unit test now holds every label description to Fleet's 255 characters.

Result: **0 failed checks**; `default.yml` (now with the tier-3 agent
options `lib/agent-options.base.example.yml`) passes the dry run; every
spoor policy passes on the healthy database and fails with the planted
findings, with a 25-hour-old heartbeat and with the database removed; a
2-hour-old heartbeat fails only the sensor policy (the 30 min / 24 h
trade-off). The opt-in Linux report, now with the `processes` lookup for
depth 2, ran (0 rows: audit events are not enabled on this host; section 6
shows the lookup attributing a grandchild on this osquery); the macOS and
Windows opt-in reports fail here with "no such table" as expected on Linux.

```
[05:41:31] Fleet 4.94.1, host vm (id 1), work dir $S/fleetfix/verify
[05:41:36] osquery 5.19.0
[05:41:36] saved agent options (920 bytes) to $S/fleetfix/verify/agent-options.before.json
[05:41:36] fleetctl gitops --dry-run deploy/fleet/gitops/default.yml
  [+] would've created 4 labels
  [+] would've applied certificate authorities
  [+] would've applied 4 scripts
  [+] would've applied fleet config
  [+] would've applied MDM profiles
  [+] would've applied enroll secrets
  [+] would've applied 10 policies
  [+] would've applied 4 reports
  [!] gitops dry run succeeded
[05:41:37] harness wrote specs, merged agent options and expectations for DB $S/fleetfix/verify/data/state.db
  [+] applied fleet config
  [+] applied 4 reports
  [+] applied 4 labels
  [+] applied 10 policies
[05:41:37] == tier 2: ATC
[05:41:51] all 9 spoor tables registered through ATC
[05:41:51] == scenario healthy (ATC)
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             1 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                0 rows; columns: 
        spoor_detections             1 rows; columns: agent_id,category,confidence,count,dedup_key,enforced,event_id,host_display_name,host_host
        spoor_sessions               1 rows; columns: agent_id,coverage,detections,host_display_name,host_hostname,last_event,max_severity,path,
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,path,
        spoor_coverage               2 rows; columns: agent_id,hooks,host_display_name,host_hostname,path,processes,state,transcript,updated,use
        spoor_health                 1 rows; columns: bundle_version,catalog_version,detections,dropped,errors,events_in,events_out,heartbeat,ho
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:43:36] == scenario planted (ATC)
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:44:33] == scenario stale (ATC)
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:45:29] == scenario stale25h (ATC)
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:46:28] == scenario removed (ATC)
  state database removed: ls: cannot access '$S/fleetfix/verify/data/state.db': No such file or directory
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             not member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:47:27] == reports (stock profile and opt-in exec reports) as live queries on the healthy database
        spoor - detections                                             [darwin,linux,windows] 1 rows
        spoor - AI inventory (packed)                                  [darwin,linux,windows] 1 rows
        spoor - telemetry coverage                                     [darwin,linux,windows] 2 rows
        spoor - sensor health                                          [darwin,linux,windows] 1 rows
        spoor opt-in - agent child processes (Linux, audit)            [linux] 0 rows
        spoor opt-in - agent child processes (macOS, EndpointSecurity) [darwin] error: no such table: es_process_events
        spoor opt-in - agent child processes (Windows, ETW)            [windows] error: no such table: process_etw_events
[05:48:04] == tier 3: osquery extension $S/fleetfix/ext/spoor-fix.ext
  [+] applied fleet config
[05:48:17] ATC tables gone; registering the extension in $S/fleetstack/osq/extensions.load
  [{"host_display_name":"vm","host_hostname":"vm","name":"spoor","path":"/run/osqt/osquery.em.44150","type":"extension","version":"c5-verify"}]
[05:48:33] == scenario healthy (extension)
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             1 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                0 rows; columns: 
        spoor_detections             1 rows; columns: agent_id,category,confidence,count,dedup_key,enforced,event_id,host_display_name,host_host
        spoor_sessions               1 rows; columns: agent_id,coverage,detections,host_display_name,host_hostname,last_event,max_severity,permi
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,pid,r
        spoor_coverage               2 rows; columns: agent_id,hooks,host_display_name,host_hostname,processes,state,transcript,updated,user
        spoor_health                 1 rows; columns: bundle_version,catalog_version,detections,dropped,errors,events_in,events_out,heartbeat,ho
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:50:15] == scenario planted (extension)
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:51:15] == scenario removed (extension)
  state database removed: ls: cannot access '$S/fleetfix/verify/data/state.db': No such file or directory
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - inventory scan complete and recent                    fail
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 fail
  ok    spoor-c5-spoor - no AI agent running unobserved                        fail
  ok    spoor-c5-spoor - no auto-run file planted in a project                 fail
  ok    spoor-c5-spoor - no high or critical agent configuration failure       fail
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               fail
  ok    spoor-c5-spoor - rules bundle is current                               fail
  ok    spoor-c5-spoor - sensor is reporting                                   fail
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             not member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        member
  ok    spoor-c5-spoor tables unavailable                                      not member
[05:52:10] cleanup
[05:52:16] extension unregistered from $S/fleetstack/osq/extensions.load, osqueryd restarted
[05:52:16] agent options restored: identical to the saved copy
[05:52:16] objects named spoor-c5-* left on the server: labels 0, reports 0, policies []
[05:52:16] done: 0 failed checks
```

## 2. GitOps dry runs

`deploy/fleet/gitops/default.yml` (stock profile, scripts, tier-3 example
agent options) is in the run above: dry run succeeded. The other generated
files, through a scratch `default.yml` that names them (the fleetd profile
with the ATC example agent options, the builtin profile with the base
example), after the run above had removed its objects:

```
$ fleetctl gitops --dry-run -f default.yml   # labels/policies/reports from lib/fleetd + lib/opt-in, agent options lib/agent-options.example.yml
[+] would've created 4 labels
[+] would've applied certificate authorities
[+] would've applied 0 scripts
[+] would've applied fleet config
[+] would've applied MDM profiles
[+] would've applied enroll secrets
[+] would've applied 10 policies
[+] would've applied 7 reports
[!] gitops dry run succeeded
exit 0
$ fleetctl gitops --dry-run -f default.yml   # labels/policies/reports from lib/builtin + lib/opt-in, agent options lib/agent-options.base.example.yml
[+] would've created 1 label
[+] would've applied certificate authorities
[+] would've applied 0 scripts
[+] would've applied fleet config
[+] would've applied MDM profiles
[+] would've applied enroll secrets
[+] would've applied 2 policies
[+] would've applied 4 reports
[!] gitops dry run succeeded
exit 0
$ fleetctl gitops --dry-run -f deploy/fleet/gitops/default.yml -f deploy/fleet/gitops/fleets/workstations.yml   # Premium example
Error: 3 errors occurred:
	* failed to parse policy install_software "spoor installed (Linux deb)": install_software.package_path URL https://downloads.example.com/spoor/0.1.0/spoor_0.1.0_linux_amd64.deb not found on team: ../../software/spoor-deb.package.yml
	* failed to parse policy install_software "spoor installed (Linux rpm)": install_software.package_path URL https://downloads.example.com/spoor/0.1.0/spoor_0.1.0_linux_amd64.rpm not found on team: ../../software/spoor-rpm.package.yml
	* failed to parse policy install_software "spoor installed (macOS)": install_software.package_path URL https://downloads.example.com/spoor/0.1.0/spoor_0.1.0_darwin_universal.pkg not found on team: ../../software/spoor-pkg.package.yml


exit 1
```

The Premium example still fails on this Free server, and only where Fleet
Premium is required: fleetctl 4.94.1 parses the `software` section only with
a Premium license (`pkg/spec/gitops.go`, `if appConfig != nil &&
appConfig.License.IsPremium()`), so the install-on-failure policies cannot
find their packages. Without the `install_software` and `software` keys,
fleetctl skips a fleet file entirely on Free, so the fleet's own labels
(Debian-family and Red Hat-family Linux) and its policies were checked only
by the unit tests:

```
$ fleetctl gitops --dry-run -f default.yml -f fleets/workstations.yml   # Premium example without install_software and software
[!] skipping team config fleets/workstations.yml since teams are only supported for premium Fleet users
[+] would've created 4 labels
[+] would've applied certificate authorities
[+] would've applied 4 scripts
[+] would've applied fleet config
[+] would've applied MDM profiles
[+] would've applied enroll secrets
[+] would've applied 10 policies
[+] would've applied 4 reports
[!] gitops dry run succeeded
exit 0
```

## 3. ATC and the extension together

ATC agent options applied first, then the extension registered in
`extensions.load`: osquery keeps the ATC tables and refuses the extension,
which restarts every few seconds. The README and the ATC fragment say so.

```
== case A: ATC applied first, then the extension is loaded
[+] applied fleet config
ATC tables registered: 9
osquery_extensions: []
registry spoor_health: [{"active":"1","host_display_name":"vm","host_hostname":"vm","internal":"1","name":"spoor_health","owner_uuid":"0"}]
spoor_health columns: ["bundle_version","catalog_version","detections","dropped","errors","events_in","events_out","heartbeat","host_display_name","host_hostname","host_id","host_id_source","last_scan","mode","path","profile","rules_count","rules_hash","rules_version","scan_complete","sensor_version","started"]
osqueryd.log (extension lines):
W1112 04:31:12.510463  2019 watcher.cpp:739] Extension respawning too quickly: $S/fleet-c5/ext/spoor-c5.ext
I1112 04:31:12.721879  2810 interface.cpp:137] Registering extension (spoor, 14586, version=c5-verify, sdk=)
E1112 04:31:12.721957  2810 interface.cpp:143] Could not add extension spoor: Registry item spoor_agent_processes conflicts with another item of the same name.
spoor-c5 extension: osqext: status 1 registering extension: Failed adding registry: Registry item spoor_agent_processes conflicts with another item of the same name.
W1112 04:31:15.511519  2019 watcher.cpp:739] Extension respawning too quickly: $S/fleet-c5/ext/spoor-c5.ext
I1112 04:31:15.723018  2941 interface.cpp:137] Registering extension (spoor, 7908, version=c5-verify, sdk=)
E1112 04:31:15.723088  2941 interface.cpp:143] Could not add extension spoor: Registry item spoor_agent_processes conflicts with another item of the same name.
spoor-c5 extension: osqext: status 1 registering extension: Failed adding registry: Registry item spoor_agent_processes conflicts with another item of the same name.
agent options restored: identical
extensions.load now: []
```

## 4. Install scripts (container)

`TestFleetInstallScripts` runs the shell scripts in a throwaway Debian 12
container (`mirror.gcr.io/library/redis:7`) with fake `systemctl` and
`spoor` binaries under a `SPOOR_ROOT` prefix: wrong SHA-256 installs
nothing; with orbit's `/opt/orbit/extensions.load` in use (non-empty) the
extension tier and `register-extension.sh` refuse with the reason and change
nothing; with orbit's file empty, install writes binary, extension, unit,
the `Group=spoor` drop-in, data dir 0750 and the default `extensions.load`,
keeping an existing last line that has no newline (it was glued to spoor's
path before the fix), and schedules a detached osquery restart; a second run
changes nothing and only starts the service; with orbit present orbit is
what restarts, and the atc tier works while orbit's file is in use and
unregisters spoor; `register-extension.sh` is idempotent; uninstall twice
keeps data and other autoload lines and removes the drop-in; orbit's
`extensions.load` is never written.

```
$ SPOOR_E2E_FLEET=1 go test -tags e2e ./test/e2e -run FleetInstallScripts -v
    fleet_test.go:641: install:
        spoor install: osquery (osqueryd) restarts in 10 s to load /work/root/usr/lib/spoor/spoor.ext
        spoor install: spoor-fake-1 installed at /work/root/usr/bin/spoor (tier extension)
--- PASS: TestFleetInstallScripts (1.44s)
PASS
ok  	github.com/thomastysong/spoor/test/e2e	1.448s
```

Script sizes (Fleet's limit is 10,000 characters): install-spoor.sh 9,405,
install-spoor.ps1 7,279, uninstall-spoor.sh 2,528, uninstall-spoor.ps1
1,950, register-extension.sh 2,441, register-extension.ps1 2,175.

## 5. Unit tests (no network, every OS)

`go test ./internal/fleetgen` emulates osquery with SQLite: the spoor tables
as views over a database written by `state.Store` (once with every column
TEXT plus a `path` column, as ATC does; once typed, as the extension does)
and the osquery tables the content reads as stubs. It covers every policy
against 23 scenarios in both flavours and both spoor profiles, the labels
(including a POSIX path on Windows not counting as installed), every report,
the opt-in reports' depth-1/depth-2 attribution (also when the depth-1
parent's exec event was in an earlier run, through `processes`, and not for
a reused pid), the catalog flag classification, a real project scan
producing every auto-run flag, the agent options merge, the golden files,
Fleet's 255-character label description limit, the Premium install
policies (fail with only the state database present) and family labels,
one tier per GitOps example, path validation (glob characters, unclean
paths), and the scripts: the exact `extensions.load` registration blocks
run by `sh` against existing files with and without a final newline, the
orbit refusal blocks, `verify.sh`'s polling with a fake fleetctl that first
answers nothing, and every `sc.exe`/`icacls.exe` call of the PowerShell
scripts through a model of Windows PowerShell 5.1's native argument passing
(which reproduces the old `binPath=` failure). Worst-case packed report
sizes with maximum-length values full of characters JSON must escape
(Fleet drops host results of 512 KiB or more):

```
    semantics_test.go:464: stock/spoor - AI inventory (packed): 369492 bytes
    semantics_test.go:464: fleetd/spoor - AI inventory (packed, with ai_tools): 223264 bytes
    semantics_test.go:464: builtin/AI tools (packed): 124326 bytes
```

## 6. osquery path handling and the opt-in lookup (local osquery 5.19.0)

Why custom state database paths must be clean and pattern-free: ATC resolves
its `path` as a glob (`?`, `[...]` and, with brace expansion, `{A,B}`) and
reports the canonical path, while the `file` table that the "spoor
installed" label reads reports a path exactly as written. Run with
`osqueryd -S --config_path=cfg.json` over three one-row databases
`$W/db/spoorA`, `spoorB`, `spoorC` (`$W` is a scratch directory). The last probe shows `processes.start_time`
is in Unix seconds, like the event tables' `time`, which the opt-in reports
compare.

```
$ ATC path $W/db/spoor?/state.db
[{"v":"A","path":"$W/db/spoorA/state.db"},{"v":"B","path":"$W/db/spoorB/state.db"},{"v":"C","path":"$W/db/spoorC/state.db"}]
$ ATC path $W/db/spoor[AB]/state.db
[{"v":"A","path":"$W/db/spoorA/state.db"},{"v":"B","path":"$W/db/spoorB/state.db"}]
$ ATC path $W/db/spoor{A,B}/state.db
[{"v":"A","path":"$W/db/spoorA/state.db"},{"v":"B","path":"$W/db/spoorB/state.db"}]
$ ATC path $W/db//spoorA/state.db
[{"v":"A","path":"$W/db/spoorA/state.db"}]
$ osqueryd -S "SELECT path FROM file WHERE path = '$W/db//spoorA/state.db'"
[{"path":"$W/db//spoorA/state.db"}]
$ osqueryd -S "SELECT pid, parent, start_time FROM processes WHERE pid = 1"; date +%s
[{"parent":"0","pid":"1","start_time":"1794454940"}]
1794462130
```

The opt-in Linux report's new depth-2 lookup, on the same osquery: the
generated query with its two inputs that need audit and spoor replaced by
stand-ins, and a real process as the depth-1 parent whose exec event is
not in the batch (as when it started in an earlier scheduled run):

```
$ sleep 300 &   # pid 12164, child of shell 12162: stand-ins for an agent's depth-1 shell (exec event in an earlier run) and the agent root
$ osqueryd -S "<the generated Linux opt-in query, with spoor_agent_processes replaced by (12162, claude-code, sess-1) and process_events by one exec of pid 999999 whose parent is 12164>"
{"pid":"999999","parent":"12164","depth":"2","agent_id":"claude-code","session_ref":"sess-1"}
```

## Not verified here

- **fleetd profile and builtin profile**: the enrolled host runs plain
  osquery 5.19, which has no `ai_tools` table, so these were validated only
  by `fleetctl gitops --dry-run` (above) and the unit-test emulator with an
  `ai_tools` stub built from Fleet's schema (`schema/tables/ai_tools.yml`).
- **macOS and Windows**: no such hosts. Untested: the darwin and windows ATC
  blocks on a real host, `es_process_events` / `process_etw_events` (columns
  from Fleet's osquery schema JSON), the `osquery_info.build_platform` values
  `darwin` and `windows` used by the "installed" label (only `linux` was
  observed), the PowerShell scripts (no PowerShell here: checked statically
  and through the PowerShell 5.1 argument-passing model; `New-Service`,
  `Win32_Service.Change` and the `sc.exe` exit codes were not run), and the
  macOS branch of the shell scripts (`dseditgroup`, `launchctl`).
- **fleetd/orbit**: the detached orbit restart, and orbit's handling of its
  own `extensions.load` (an `--extensions_autoload` flag only while the file
  is non-empty, `orbit/cmd/orbit/orbit.go` 1586-1603), were read from code,
  not run; the scripts' refusal on a non-empty orbit file ran in the
  container (section 4).
- **systemd**: the container has a fake `systemctl`, so the `Group=spoor`
  drop-in was checked as a file, not on a running systemd; the re-owning of
  `StateDirectory=` it counters is systemd's documented behaviour, not
  observed here.
- **Fleet Premium**: package YAMLs, install-on-failure policies, per-fleet
  files and fleet labels (dry run refused or skipped on a Free server, see
  section 2), and the rollback of a package whose post-install script
  fails (from Fleet's REST API documentation).
- **A real sensor**: the state databases came from the harness, not from
  `spoor scan --state` / `spoor run` (cmd/spoor is not built yet); verify.sh
  switches to them when `SPOOR_BIN` is set. The scripts ran with a fake
  `spoor` binary, so `spoor export config` and `spoor version` were not
  exercised for real.
- Fleet's scheduled policy interval (hourly) was not waited for: results
  were forced with a host refetch.
