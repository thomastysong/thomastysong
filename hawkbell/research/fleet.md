> **Historical design record.** Research report: Fleet integration surfaces (custom extensions, ATC, scripts, GitOps, logging, the AI tables fleetd ships).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:55 UTC on the build machine; its title names fleetdm/fleet at 27178c8c, 2026-11-11).
> - Written before the project had a name. The text uses the placeholder `aiguard` (for example the table `aiguard_findings`, the extension `aiguard.ext` and the package `aiguard`); it is a placeholder, not this project's name or a product the report describes. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none. Kept: GitHub account names and editor extension ids that are part of a cited repository, package or extension location, because a reader needs them to check the source (`karmine05/agentic-detector`, the upstream of fleetd's `ai_tools` table).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# FleetDM integration surfaces (fleetdm/fleet @ 27178c8c, 2026-11-11; Fleet 4.94.1, fleetd 1.63.0)

**Executive summary**
1. Fleet already ships AI-agent tables inside fleetd: `ai_tools` (fleetd 1.59.0+), `mcp_listening_servers`, and on main `ai_agent_sessions` / `ai_agent_session_messages` ("needs fleetd 1.64.0", unreleased). Inventory alone is no longer a differentiator on Fleet hosts; event-time telemetry, detections and streaming are.
2. Lowest-friction path needs no extension: our agent writes (a) an NDJSON event log for Fluent Bit and (b) a SQLite state DB that osquery exposes through `agent_options.config.auto_table_construction`. Policies, labels and reports then work unchanged.
3. fleetd starts osquery with `--logger_plugin=tls,filesystem --logger_path=<root>/osquery_log`, so every scheduled result is already on the endpoint's disk for Fluent Bit to tail, as well as at the Fleet server's log destination.
4. Fleet reports are not an event store: 1,000 results per report (or host count), 512 KiB per host result, latest result only. Events must go out via logs.
5. Extensions: the TUF `extensions` key needs Premium plus a self-hosted TUF repo for all fleetd components; the simple path is package + osquery's default `extensions.load`. Software deploy and policy "install software / run script" automations are Premium; scripts, global policies, reports, labels, log destinations and most webhooks are not marked Premium.

Legend: **V** = read in primary source this session, **U** = memory/inference. Paths are relative to `/home/user/fleetdm/fleet` unless a URL is given.

## 0. Terminology and layout (changed 2025-2026) — V
- "Teams" are now **fleets**; "queries" are **reports**; "No team" is **Unassigned**. GitOps: `default.yml` + `fleets/<name>.yml` + `fleets/unassigned.yml`; per-fleet settings key is `settings:` (`it-and-security/fleets/workstations.yml:1-2`). One doc example still says `team_settings:` (`docs/Configuration/yaml-files.md:1476`) and `no_team.yml` is still mentioned (`:425`).
- API paths: `/api/v1/fleet/reports`, `/api/v1/fleet/fleets/:id/policies`; some responses still carry `team_id`, `query` (`docs/API/rest-api.md:13335-13420`).
- `fleetctl new` scaffolds a repo using `platforms/` and `labels/` folders (raw.githubusercontent.com/fleetdm/fleet/main/cmd/fleetctl/fleetctl/templates/new/fleets/workstations.template.yml); Fleet's own repo uses `lib/`. Both are conventions.

## 1. Custom osquery extensions
**A. TUF-managed `extensions` (agent options)** — V, `docs/Configuration/agent-configuration.md:90-203`
- "requires a custom TUF auto-update server (available in Fleet Premium)"; with a self-hosted TUF "you must also manage all of Fleetd's versions, including osquery, Fleet Desktop and osquery extensions".
```yaml
agent_options:
  extensions:               # requires fleetd
    aiguard_macos:   {channel: stable, platform: macos}
    aiguard_linux:   {channel: stable, platform: linux}
    aiguard_linux_arm64:   {channel: stable, platform: linux-arm64}
    aiguard_windows: {channel: stable, platform: windows, labels: [AI agents present]}  # labels: Premium, ALL must match
    aiguard_windows_arm64: {channel: stable, platform: windows-arm64}
```
- File name = `<key>.ext` (macOS/Linux) or `<key>.ext.exe` (Windows); TUF target `extensions/<key>`; push with `fleetctl updates add --target ... --name extensions/<key> --platform <p> --version <v>`. Platforms: `macos|linux|linux-arm64|windows|windows-arm64`.
- Mechanism (V, orbit `update/flag_runner.go` on main; `orbit/cmd/orbit/orbit.go:1568-1605`): orbit downloads to `<root>/bin/extensions/<name>/<platform>/<channel>/<name>.ext`, writes `<root>/extensions.load`, and passes `--extensions_autoload` only when that file is non-empty.

**B. Simpler path: package + autoload file** — V, `articles/deploying-custom-osquery-extensions-in-fleet-a-step-by-step-guide.md` (2026-03-06)
- Ship the binary in a pkg/msi/deb, post-install appends its path to an `extensions.load`, restart orbit detached ~10 s later (`launchctl kickstart -k system/com.fleetdm.orbit`, `systemctl restart orbit`, `Restart-Service 'Fleet osquery'`); a policy plus install-software automation rolls it out.
- **Conflict found:** the guide writes `/opt/orbit/extensions.load`, but orbit's `ExtensionRunner.Run` truncates that file and restarts orbit whenever the server sends no `extensions` config and the file is non-empty (V code, U runtime behaviour — not executed). Fleet's own dogfood instead uses osquery's default path: `/var/osquery/extensions.load` → `/var/fleet/extensions/santa.ext` (`it-and-security/lib/macos/policies/install-santa-extension.yml:2`) and `C:\Program Files\osquery\extensions.load` (`articles/detect-and-mitigate-yellowkey-bitlocker-bypass-with-fleet.md:48`).
- osquery defaults (V, osquery `default_paths.h`, `extensions.cpp`): `/etc/osquery/extensions.load` (Linux), `/var/osquery/extensions.load` (macOS), `\Program Files\osquery\extensions.load` (Windows); suffix `.ext` (Windows also `.exe`); `safePermissions()` on file and parent dir (log string `unsafe permissions`); `--extensions_timeout=3`, `--extensions_interval=3`.
- Since Fleet 4.93.0 `extensions_autoload` may be set in `command_line_flags`, but not together with `extensions` (`agent-configuration.md:58`, `articles/fleet-4.93.0.md:116`). `command_line_flags` is not supported in platform `overrides` (`:256`), so one path per fleet.
- Loaded check: `SELECT 1 FROM osquery_extensions WHERE name = '<registered name>';` or `osquery_registry`. Local test: `sudo orbit shell -- --extension /path/x.ext`.
- orbit's own extension socket: `<root>/orbit-osquery.em`, Windows `\\.\pipe\orbit-osquery-extension` (`orbit/pkg/osquery/osquery.go:185-200`). Registering from our own daemon over that socket without autoload is plausible but **U**.

## 2. Zero-extension paths
**ATC** — V (osquery `plugins/config/parsers/auto_constructed_tables.cpp`, osquery `docs/wiki/deployment/configuration.md`; Fleet struct `server/fleet/agent_options.go:271-276`)
```yaml
agent_options:
  config:
    auto_table_construction:
      aiguard_findings:
        query: "SELECT id, ts, severity, rule_id, agent, session_id, summary FROM findings"
        path: "/opt/aiguard/state.db"       # % wildcards allowed, e.g. /Users/%/...
        columns: [id, ts, severity, rule_id, agent, session_id, summary]
        platform: "posix"                    # optional
```
- So yes: a SQLite file written by our agent becomes a table with no extension. Limits: every column is TEXT; an implicit `path` column is added and `path` is reserved; core table names cannot be overridden; `query`, `path`, `columns` are mandatory; journal mode is probed and WAL keeps locking; errors only reach the osquery status log.
- Fleet's docs show ATC only inside `overrides.platforms.darwin`, but the validator struct accepts it at `config` level. Overrides are **not merged** with base config (`agent-configuration.md:252-272`), and one table name maps to one path, so Windows needs either a duplicate full override block or a different table name.

**Other no-extension surfaces** (platforms from `schema/osquery_fleet_schema.json`, V)
- All OS: `file`, `hash`, `processes`, `process_open_sockets`, `listening_ports`, `npm_packages`, `python_packages`, `vscode_extensions` (`vscode_edition` distinguishes Cursor), `jetbrains_plugins`, `chrome_extensions`, `firefox_addons`, `startup_items`, `curl`, `osquery_extensions`, `osquery_registry`, `osquery_schedule`, SQLite `json_extract`/`json_each`.
- macOS: `apps`, `plist`, `launchd`, `safari_extensions`, `signature`; macOS+Linux: `homebrew_packages`, `augeas`, `crontab`, `process_envs`, `process_open_files`, `docker_*`; Linux: `deb_packages`, `rpm_packages`, `systemd_units`; Windows: `programs`, `registry`, `services`, `scheduled_tasks`, `authenticode`.
- fleetd-only helpers (not vanilla osquery): `file_lines`, `file_contents`, `parse_json`, `parse_jsonl`, `parse_xml`, `parse_ini`, `yaml_to_json`, `go_binaries` (`orbit/pkg/table/extension.go:156-215`). `parse_json(l)` requires a `path` constraint, `%` globs become `*` (`dataflattentable/tables.go:86-100`).
- Evented tables and flags (V: `articles/osquery-evented-tables-overview.md`; Fleet's dogfood flags `it-and-security/fleets/workstations.yml:52-74`):

| Table | OS | Flags (`command_line_flags`, all need `disable_events: false`) |
|---|---|---|
| `process_events`, `socket_events` | Linux | `disable_audit: false`, `audit_allow_process_events: true`, `audit_allow_sockets: true`, `audit_persist: true` |
| `bpf_process_events`, `bpf_socket_events` | Linux (kernel > 4.18) | `enable_bpf_events: true` |
| `es_process_events` / `es_process_file_events` | macOS (needs Full Disk Access) | `disable_endpointsecurity: false` / `disable_endpointsecurity_fim: false` |
| `process_etw_events` | Windows | `enable_process_etw_events: true` |
| `file_events` | macOS, Linux | `enable_file_events: true` + `config.file_paths` |
| `process_file_events` | Linux | `disable_audit: false`, `audit_allow_fim_events: true` |
| `ntfs_journal_events` | Windows | `enable_ntfs_event_publisher: true` |
| `windows_events`, `powershell_events`, `dns_lookup_events` | Windows | `enable_windows_events_publisher`, `enable_powershell_events_subscriber`, `enable_dns_lookup_events` |
- Buffers: `events_max` 50,000 rows per table, `events_expiry`, `events_optimize`. Fleet raises `watchdog_memory_limit: 350`, `watchdog_utilization_limit: 130` for evented workloads.

## 3. What Fleet already has for AI agents — V
- `ai_tools` (`orbit/pkg/table/ai_tools/`, vendored from karmine05/agentic-detector v0.3.0, MIT): `type` in `mcp_server|ide_plugins|agents|apps|sockets|agent_instruction|browser_extension`; columns `type,name,identifier,category,location,source,version,path,endpoint,running,pid,port,risk_flags,sha256,confidence,evidence,uid,username,detail`. Risk flags: `remote_fetch_exec, unpinned_dependency, mcp_shell_exec, mcp_fs_write, plaintext_secret, world_readable_config, cleartext_endpoint, bypass_permissions, auto_accept_edits, skip_permissions_runtime, injection_markers, hidden_unicode, world_writable, broad_host_permissions, sideloaded_unverified` (`schema/tables/ai_tools.yml`).
- `ai_agent_sessions` (21 columns: agent, session_id, account_identifier, project_path, git_repository, model, token counts, tool_calls...) and `ai_agent_session_messages` (per content block; `action` in `read|write|execute|search|network|mcp|other`, `decision` in `allowed|denied|error`), parsed from `~/.claude/projects`, `~/.codex/sessions`, `~/.copilot/session-state`, `~/.cursor/projects/*/agent-transcripts`, `~/.gemini/tmp/*/chats`. Caps: 30-day default window, ~1 MiB per result, 8 KB per block, 4 GiB read per query, 5,000 sessions per agent per home.
- `mcp_listening_servers`: probes local listening ports for HTTP MCP.
- Content: `articles/shadow-ai-is-already-on-your-fleet.md`, `articles/agentic-security-needs-ground-truth.md`, "Get MCP client configurations" in `docs/queries.yml:3115`, three AI reports in `it-and-security/lib/all/reports/dex-queries.yml:775-840`. Roadmap (`articles/roadmap-preview-october-2026.md:14,36`): AI tools and skills in software inventory, sessions per host, AI governance dashboards.
- Hardening rules worth copying (`ai_tools/README.md`): never execute discovered binaries, regular files only, no symlink following, no DNS for untrusted hostnames, OS-attested uid, panic recovery at `Generate`, constraint pushdown on `type`, 10 s shared-input cache because osquery calls generate once per `IN` value.

## 4. Software deployment — V (`articles/deploy-software-packages.md`, `yaml-files.md:667-872`)
- "_Available in Fleet Premium_". Types: `.pkg .msi .exe .deb .rpm .ipa .tar.gz .sh .py .ps1`. Needs fleetd with `--enable-scripts` (automatic with macOS MDM) and, self-hosted, an S3 bucket. Software is per fleet or Unassigned, never "All fleets".
- Package YAML: `url`, `hash_sha256`, `always_download`, `pre_install_query.path`, `install_script.path`, `post_install_script.path`, `uninstall_script.path`, `self_service`, `setup_experience`, `labels_include_any|include_all|exclude_any`, `categories`, `icon.path`, `display_name`. Up to 10 packages per title (arch split, staged rollout).
- Metadata must be extractable (pkg bundle id, msi product code, deb/rpm name); `.exe` and `.tar.gz` need explicit install and uninstall scripts; `$INSTALLER_PATH`, `$PACKAGE_ID`, `$UPGRADE_CODE` placeholders. Failed post-install triggers uninstall. Installs retry 3 times.
- Script-only packages: file content is the install script; no policy-triggered auto-install; support `$FLEET_SECRET_*`.

## 5. Scripts — V (`articles/scripts.md`, `rest-api.md:14241-14260`, `agent-configuration.md:305-314`)
- `.sh`/`.py` on macOS and Linux (root, `/bin/sh` unless shebang), `.ps1` on Windows. Disabled unless fleetd was packaged with `--enable-scripts` or macOS MDM is on.
- Timeout 300 s default, `agent_options.script_execution_timeout` up to 18000. Ad hoc `script_contents` under 10,000 characters; saved scripts via `script_id`. Runs at next check-in, queued behind other activities. `POST /api/v1/fleet/scripts/run`, batch run, `fleetctl run-script`.
- Not marked Premium (manual runs). Built-in `$FLEET_VAR_*` variables are Premium.

## 6. GitOps YAML (assembled from documented keys; not run through `fleetctl gitops --dry-run`)
```yaml
# default.yml
org_settings:
  server_settings: {server_url: $FLEET_URL}
  org_info: {org_name: Acme}
  secrets: [{secret: $FLEET_GLOBAL_ENROLL_SECRET}]
agent_options: {path: ./lib/agent-options.yml}
controls:
labels:
  - name: AI agents present
    label_membership_type: dynamic
    query: SELECT 1 FROM ai_tools WHERE type IN ('agents','mcp_server') LIMIT 1;
policies:
  - name: AI agents - no permission bypass
    description: No agent runs with approvals disabled.
    resolution: Remove bypassPermissions / --dangerously-skip-permissions.
    platform: darwin,linux,windows
    critical: false
    query: SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM ai_tools WHERE type='agents' AND (risk_flags LIKE '%bypass_permissions%' OR risk_flags LIKE '%skip_permissions_runtime%'));
reports:
  - name: AI tools per host (packed)
    query: SELECT COUNT(*) AS tool_count, json_group_array(json_object('type',type,'name',name,'risk_flags',risk_flags,'path',path)) AS tools FROM ai_tools;
    interval: 3600
    platform: darwin,linux,windows
    automations_enabled: true      # forward to log destination
    logging: snapshot              # or differential | differential_ignore_removals
    discard_data: false
```
```yaml
# fleets/workstations.yml  (Premium)
name: Workstations
settings:
  secrets: [{secret: $FLEET_WORKSTATIONS_ENROLL_SECRET}]
agent_options: {path: ../lib/agent-options.yml}
controls:
  scripts: [{path: ../lib/scripts/install-aiguard.sh}]
policies:
  - name: aiguard installed
    platform: linux
    query: SELECT 1 FROM deb_packages WHERE name = 'aiguard';
    install_software: {package_path: ../lib/software/aiguard-deb.package.yml}   # or run_script: {path: ...}
reports:
software:
  packages:
    - path: ../lib/software/aiguard-deb.package.yml
      labels_include_any: [AI agents present]
```
```yaml
# lib/software/aiguard-deb.package.yml
- url: https://example.com/aiguard_1.0.0_amd64.deb
  hash_sha256: <sha256>
  post_install_script: {path: ../scripts/aiguard-post-install.sh}
```
- Fleet's own files keep every top-level key present even when empty (`it-and-security/fleets/servers.yml`). Anything omitted is reset or deleted (`yaml-files.md:1736`); omitting `custom_host_vitals` deletes all vitals. Labels referenced anywhere must be declared. `path:` single file, `paths:` glob. `install_software`/`run_script` only in a fleet or Unassigned file, with the script/package in the same file.

## 7. Labels, variables, vitals — V
- Labels: `dynamic` (SQL, optional `platform`), `manual` (`hosts` by id/serial/uuid), `host_vitals` (`criteria.vital`: `end_user_idp_group`, `end_user_idp_department`, `custom_host_vital` + `custom_host_vital_id`). Label queries refresh hourly (`osquery_label_update_interval`). Fleet-scoped labels and label targeting of reports/policies are Premium.
- Custom variables `$FLEET_SECRET_NAME`: global, same value for all hosts, usable in scripts, script-only packages, profiles; uploaded by GitOps from CI env.
- Custom host vitals: per-host values, `PUT /api/v1/fleet/hosts/:host_id/custom_host_vitals/:id {"value": "..."}`, referenced as `$FLEET_HOST_VITAL_<id>` and in host-vitals labels. An external service can therefore push an "AI risk" value per host and drive labels.

## 8. Logs
**Server side** — V (`docs/Configuration/fleet-server-configuration.md:1242-1270,1553-1590,1714-2700`, `articles/log-destinations.md`)
- `osquery.result_log_plugin`, `osquery.status_log_plugin` (`FLEET_OSQUERY_RESULT_LOG_PLUGIN`, `..._STATUS_LOG_PLUGIN`): `filesystem` (default), `firehose`, `kinesis`, `lambda`, `pubsub`, `kafkarest`, `nats`, `splunk`, `stdout`; `webhook` for results only (`webhook.result_url`).
- Keys: `filesystem.{status_log_file=/tmp/osquery_status, result_log_file=/tmp/osquery_result, audit_log_file=/tmp/audit, enable_log_rotation, max_size=500, max_age=28, max_backups=3}`; `firehose|kinesis.{region, status_stream, result_stream, audit_stream}`; `lambda.{status_function, result_function, audit_function}`; `pubsub.{project, result_topic, status_topic, audit_topic, add_attributes}`; `kafkarest.{proxyhost, result_topic, status_topic, audit_topic}`; `nats.{server, result_subject, status_subject, audit_subject, jetstream}` with expr templates such as `results.{log.decorations.hostname}`; `splunk.{url, token, index, source, source_type}`.
- Audit: `activity.enable_audit_log`, `activity.audit_log_plugin` (Premium, up to 5 min delay). Activities webhook (`org_settings.webhook_settings.activities_webhook`) carries `timestamp, actor_full_name, actor_id, actor_email, type, details`.
- Only reports with `automations_enabled` are forwarded; results for Fleet-known queries not on the host's schedule are dropped; unknown query names pass through (V, `server/service/osquery.go` `SubmitResultLogs`). One plugin for all reports. Filesystem/stdout output is split across load-balanced servers. Size drops: Splunk 1 MB, Lambda 6 MB, Pub/Sub 10 MB.

**Result line shapes** — V (comment block in `server/service/osquery.go`, osquery `docs/wiki/deployment/logging.md`)
```json
{"snapshot":[{"type":"agents","name":"claude-code"}],"action":"snapshot","name":"pack/Global/AI tools per host (packed)","hostIdentifier":"F5B2...","calendarTime":"Wed Jan 29 22:17:17 2025 UTC","unixTime":1738189037,"epoch":0,"counter":0,"numerics":false,"decorations":{"host_uuid":"F5B2...","hostname":"foobar.local"}}
{"name":"pack/team-3/agent events","hostIdentifier":"F5B2...","calendarTime":"Wed Jan 29 12:32:54 2025 UTC","unixTime":1738153974,"epoch":0,"counter":4,"numerics":false,"decorations":{"host_uuid":"F5B2...","hostname":"foobar.local"},"columns":{"rule":"curl-pipe-sh","severity":"high"},"action":"added"}
```
- `name` = `pack<delim>Global<delim><report name>` or `pack<delim>team-<fleet id><delim><name>`; delimiter is `pack_delimiter` (`/`). Differential actions `added|removed`; batch mode (`logger_event_type=false`) uses `diffResults.{added,removed}`. Column values are strings unless `logger_numerics`. `decorations` are nested unless `decorations_top_level`.

**Endpoint side** — V
- orbit flags: `--logger_plugin=tls,filesystem`, `--logger_tls_endpoint=/api/v1/osquery/log` (`orbit/pkg/osquery/flags.go:27`), `--logger_path=<root>/osquery_log` (`orbit/cmd/orbit/orbit.go:1113-1117`): `/opt/orbit/osquery_log` on macOS/Linux, `C:\Program Files\Orbit\osquery_log` on Windows. Files `osqueryd.results.log` and `osqueryd.snapshots.log` (names from osquery docs; U on a live fleetd host). `logger_path`, `logger_plugin`, `logger_rotate`, `logger_rotate_size`, `logger_rotate_max_files`, `logger_snapshot_event_type` are accepted `command_line_flags`. Plain osquery enrolled to Fleet uses `--logger_plugin=tls` only.
- Tested here with Fluent Bit 5.2.0: `tail` + JSON parser reads both shapes. `time_key: unixTime` with `%s` is ignored because the value is a JSON number; this works:
```yaml
parsers:
  - name: osquery_json
    format: json
    time_key: calendarTime
    time_format: "%a %b %d %H:%M:%S %Y UTC"
    time_keep: on
```

## 9. Webhooks and automations — V (`yaml-files.md:1440-1545`, `articles/automations.md`)
- `org_settings.webhook_settings`: `interval` (default `24h`) plus `failing_policies_webhook {enable_failing_policies_webhook, destination_url, policy_ids, host_batch_size}` (also per fleet under `settings`), `vulnerabilities_webhook`, `host_status_webhook`, `activities_webhook`; `host_activities_webhook` is Premium.
- Policies run hourly (`osquery_policy_update_interval`); webhooks and tickets fire only for newly failing hosts and are evaluated once per `interval`. Install-software, run-script and resend-profile automations are Premium and fleet-level, 3 attempts, `continuous_automations_enabled` to retry on every failure; live policy runs do not trigger automations.

## 10. Live reports, storage limits, performance — V
- `POST /api/v1/fleet/reports/:id/run`, `POST /api/v1/fleet/hosts/:id/query` (sync, waits `FLEET_LIVE_QUERY_REST_PERIOD`, default 25 s), `POST /api/v1/fleet/queries/run` + WebSocket for campaigns. Only online hosts answer; each campaign holds a Redis connection; docs ask clients to rate-limit.
- Stored results: `server_settings.report_cap` default 1000 (or host count if larger); host result over 512 KiB is not stored (`maxQueryReportSnapshotBytes`); only the latest result per host; `discard_data` per report, `discard_reports_data` globally. Fleet's own workaround is one packed row per host via `json_group_array(json_object(...))`.
- Schedule: `interval` seconds (0 = never), aligned to clock with `schedule_splay_percent` 10%; pauses while a laptop sleeps. `logger_tls_max_linesize` 1 MiB per result line, 1024 lines per period.
- Watchdog defaults: 200 MB, 10% CPU for 12 s, `watchdog_delay` 60 s; autoloaded extensions are monitored for liveness, and for CPU/memory only with `enable_extensions_watchdog` (osquery `cli-flags.md`). Denylisted distributed queries appear as a server warning (`articles/fleet-4.74.0.md:76`). `osquery_schedule` shows per-query cost.

## 11. Recommended integration
**Tier 0, minutes, no binary:** a GitOps bundle (labels, policies, packed reports) over `ai_tools`, `mcp_listening_servers` and core tables for hosts on fleetd 1.59+; tail `/opt/orbit/osquery_log/osqueryd.*.log` with Fluent Bit or use the server log destination.

**Tier 1, "works with Fleet in 10 minutes":** one static Go agent that
1. writes NDJSON events to a fixed path (primary stream, Fluent Bit `tail`, independent of Fleet);
2. keeps a small SQLite state DB (`inventory`, `findings`, `status` heartbeat) exposed through ATC;
3. ships a generated bundle: ATC snippet, health policy (`SELECT 1 FROM aiguard_status WHERE CAST(heartbeat AS INTEGER) > strftime('%s','now') - 900`), finding policies, packed reports, package YAML and install scripts for Free tier;
4. stamps events with the same `host_uuid` Fleet decorates results with (orbit default `--host-identifier uuid`).

**Tier 2, richer:** an osquery-go extension (`aiguard.ext`) with typed columns and constraint pushdown, installed by the same package into osquery's default `extensions.load`; TUF `extensions` only for orgs that already run their own TUF.

**Pitfalls**
- Do not write `/opt/orbit/extensions.load`; if TUF `extensions` is in use orbit overrides the default autoload path, so those orgs must publish our extension through TUF.
- Never restart orbit synchronously from a Fleet script or installer; detach and delay.
- ATC columns are TEXT, per-OS paths need duplicate overrides, and behaviour on a missing file or a busy WAL DB is untested here.
- Snapshot logging re-emits the full set every interval; use `differential_ignore_removals` for event-like tables and `discard_data: true` for volume.
- Local osquery result files are root-only and unrotated unless `logger_rotate` is set.
- `command_line_flags: {}` clears host flags; any `command_line_flags` change makes orbit restart itself and osquery (`triggerOrbitRestart("osquery flags updated")`, V).
- ATC `platform` is a substring match (`darwin`, `linux`, `windows`, `posix`, `any`; V osquery `core/system.cpp`).
- Report names can contain spaces and emoji; route on a stable prefix in the `name` field.
- `mcp_listening_servers` port probing triggers EDR alerts (schema note); avoid active probing by default.
- Session-message content can contain secrets (schema note); ship redacted metadata by default.
