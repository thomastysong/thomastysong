> **Historical design record.** Red-team review of design v0, Fleet-operator lens (A16 to A20, A30, A33), run against Fleet 4.94.1 and osquery 5.19.0 on the build VM.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:22 UTC on the build machine; its title is dated 2026-11-11).
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (1 place). Kept: the `/etc/machine-id` value of the disposable build VM and the host UUIDs osquery and Fleet reported for it. Two of these values also appear in the repository: the machine-id (`internal/platform/hostid_linux_test.go`) and the Fleet host UUID of the enrolled test host (`deploy/fleet/VERIFIED.md`). The other three UUIDs come from two separate osquery runs and a second osqueryd instance the reviewer enrolled in the same Fleet (section 3), and appear nowhere else in the repository.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: lens "fleet-operator" (2026-11-11)

Persona: FleetDM admin, 20,000 hosts (macOS/Windows/Linux), GitOps, mostly Fleet Free plus one Premium fleet.
Assigned: A16, A17, A18, A19, A20, A30, A33. Design under attack: `design/v0.md`.

All experiments ran in this sandbox against Fleet 4.94.1 (license tier `free`) and osquery 5.19.0.
Work dir: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/rt-fleetop` (`$W`).

## 0. Setup and housekeeping

- `$S/dl` (osqueryd, fleet, fleetctl binaries named in ENV.md) had been deleted by the time I started; the server and the
  enrolled osqueryd were still running from deleted inodes. I recovered osqueryd with `cp /proc/24720/exe $W/bin/osqueryd`
  (still there, 274 MB, for anyone who needs it). fleetctl was not recoverable, so I used the Fleet REST API with curl/python
  (`--noproxy '*'`). Consequence: I could NOT run `fleetctl gitops --dry-run`; GitOps findings rest on Fleet docs, not a run.
- To avoid touching shared agent options I did NOT change Fleet config. I started a second, private osqueryd:
  `unshare --uts sh -c "hostname rtfo-fleetop; exec osqueryd --flagfile=$W/osq.flags"` with
  `--config_plugin=filesystem` (my ATC + schedule), `--distributed_plugin=tls` (Fleet live queries),
  `--host_identifier=specified --specified_identifier=rtfo-fleetop`, own RocksDB, socket `/run/rtfo/osq.em`,
  watchdog ENABLED with defaults (the shared host runs `--disable_watchdog=true`, so it cannot answer watchdog questions).
  It enrolled as Fleet host id 2.
- Restored afterwards: host 2 deleted (`DELETE /hosts/2` 200), 5 temporary global policies deleted, my osqueryd and extension
  killed, `/run/rtfo` removed. `GET /hosts` shows only `vm` again; `GET /global/policies` is empty. Shared host flagfile and
  agent options never modified.

Test DBs (`$W/scripts/mkdb.py`): table `detections(id INTEGER PK, ts, severity, rule_id, agent, session_id, summary(120 chars), batch)`
and `health(k,v)`. 10k rows = 1.97 MB, 100k rows = 19.6 MB, 300k rows = 58.7 MB. One copy in WAL mode, one in rollback (`delete`) mode.
Writer (`$W/scripts/writer.py`): one `BEGIN IMMEDIATE ... COMMIT` every 50 ms that sets `batch=k` on ALL rows, so a consistent
snapshot always has exactly ONE distinct `batch` value. A reader that sees 2 distinct values got a torn (non-atomic) view.

## 1. ATC over SQLite (A16)

### 1.1 Concurrent writer, 50 ms commits

Shell mode (`osqueryd -S --config_path=$W/atc.conf "select count(*), count(distinct batch) from <t>"`, one process per read):

```
== rt_wal10k kind=all:   25 x "10000|1"                         writer: commits=238 errs=0 max_txn_s=0.018
== rt_rb10k  kind=all:   22 x "10000|1",  3 x "10000|2"         writer: commits=221 errs=0 max_txn_s=0.031
== rt_wal10k kind=small: 40 x consistent
== rt_rb10k  kind=small: 35 x consistent, 5 x 2 distinct batches
```

Through Fleet (`POST /api/v1/fleet/hosts/2/query`, 10 live queries each, writer running):

```
 6 rb  None [{'c': '10000', 'nb': '1'}]
 4 rb  None [{'c': '10000', 'nb': '2'}]      <- torn snapshot, error=None, no warning in osquery log
10 wal None [{'c': '10000', 'nb': '1'}]
writer done commits=635 errs=0 (rb) / commits=684 errs=0 (wal)
```

Result: WAL holds (0 torn of 75 reads, writer never blocked, no errors). Rollback-journal mode is silently wrong
(8 of 65 shell reads, 4 of 10 Fleet reads torn; no error, no warning). Mechanism: osquery probes the journal mode and only keeps
SQLite locking for WAL; for other modes it opens with the no-lock VFS (fleet.md section 2, "journal mode is probed and WAL keeps locking").

### 1.2 Missing / empty / skewed / wrong-platform file

Shell mode:

```
missing file            -> [{"c":"0"}]            (NO warning at all)
0-byte file             -> [{"c":"0"}]  + W "ATC Table: Error Code: 1 Could not generate data: Could not prepare database"
query names column the DB lacks (rt_newcol) -> [{"c":"0"}] + same W (status log only)
"SELECT * FROM detections" with declared columns [id,severity,newcol] -> rows returned, newcol = ""   (skew tolerant)
table declared platform=windows, queried on linux -> "Error: no such table: rt_winonly"
typeof(id), typeof(batch) -> text, text
```

Through Fleet:

```
6 missing file:  {"status":"online","error":null,"nrows":1,"first":[{"c":"0"}]}
7 newcol skew:   {"status":"online","error":null,"nrows":1,"first":[{"c":"0"}]}
8 winonly table: {"error":"no such table: rt_winonly","nrows":0}
9 text compare:  [{"int_cmp":"2000","text_cmp":"1115"}]     <- "WHERE id < 2000" on a TEXT column is lexicographic
```

### 1.3 Fleet policy semantics over those tables (temporary global policies 1..5, then deleted)

```
host 2 (my host; state DB for rt_missing does not exist; wal-10k.db has 200 'critical' rows)
1 'pass' | no critical detections (db missing)          SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM rt_missing WHERE severity='critical')
2 'fail' | sensor healthy (db missing)                  SELECT 1 FROM rt_missing LIMIT 1
3 'pass' | no critical detections (unknown column)      ... NOT EXISTS (SELECT 1 FROM rt_newcol WHERE severity='critical')   <- same DB as policy 5
4 ''     | table absent on this platform                ... FROM rt_winonly ...   (query error -> no response, neither pass nor fail)
5 'fail' | control: critical rows exist in 10k db       ... NOT EXISTS (SELECT 1 FROM rt_wal10k WHERE severity='critical')
host 1 (shared `vm`, none of the tables exist): all five '' (no response)
```

So every "no X" policy the design lists (no critical detections in 24h, no bypass mode, no unpinned MCP) is fail-open:
sensor never installed with ATC present, DB deleted, DB empty, or bundle one schema version ahead of the binary -> green.
A host where the table is not defined (wrong platform, ATC not delivered) shows no response, which Fleet counts as neither.

### 1.4 Atomic replace by rename

```
old swap.db: WAL mode, writer SIGKILLed, 5000 'OLD' rows only in swap.db-wal (1.18 MB), swap.db itself 4096 bytes
ATC: 5000|OLD|OLD
new 7-row 'NEW' DB built in swap.db.tmp, os.rename() over swap.db; stale -wal/-shm remain
ATC detections: 5000|OLD|OLD     health: gen|OLD        <- new generation invisible, old WAL replayed over it
repeat with the new generation created in WAL mode and closed cleanly: still 5000|OLD|OLD
python sqlite3 (rw) on the same path: [(5000,'OLD','OLD')], integrity_check ok   (old frames now checkpointed INTO the new file)
```

Rename-over is not safe whenever a `-wal` sidecar survives (daemon crash, OOM kill, watchdog kill, power loss).

### 1.5 Cost with 10k / 100k / 300k rows (private osqueryd, default watchdog, `osquery_schedule` read through Fleet)

```
name               | interval | executions | last_wall_time_ms | last_memory (bytes) | average_memory
atc10k_count       | 10 | 12 |   26 |  12,103,680 |  13,210,963     SELECT count(*) FROM rt_wal10k
atc100k_count      | 10 | 11 |  269 | 107,397,120 | 113,397,758     SELECT count(*) FROM rt_wal100k
atc100k_policy     | 10 | 11 |  272 | 123,686,912 | 123,902,136     SELECT 1 FROM rt_wal100k WHERE severity='critical' AND ts>'2026-11-10' LIMIT 1
atc100k_notexists  | 10 | 12 |  285 | 123,682,816 | 117,516,625     SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM rt_wal100k WHERE severity='nope')
atc100k_packed     | 10 | 10 |  422 | 150,441,984 | 154,276,247     json_group_array(json_object(...)) over 100k rows
atc10k_join_procs  | 10 | 10 | 2315 |  16,949,248 |  19,160,841     processes p JOIN rt_wal10k d ON d.id = p.pid
ext_table          | 10 | 10 |    0 |           0 |               (osquery-go extension table)
```

- No pushdown: `LIMIT 1` and `NOT EXISTS` cost the same as a full scan; every query materialises the whole ATC result
  (about 1.1 to 1.5 KB of worker RSS per 200-byte row).
- Live query `select id, severity, rule_id, session_id from rt_wal100k` through Fleet: `"error": "timeout waiting for results"` after 25.02 s.
- Join: the ATC file is re-read once per outer row. Shell timings:
  `processes JOIN rt_wal10k ON d.id=p.pid` 2.64 s; `WITH d AS MATERIALIZED (SELECT id FROM rt_wal10k) ... JOIN d` 0.19 s; `select 1` 0.04 s.
- 300k rows (58.7 MB DB), ONE live query `select count(*) c from rt_rb100k` through Fleet:
  `W watcher.cpp:425] osqueryd worker (19691) stopping: Memory limits exceeded: 216985600 bytes (limit is 200MB)`.
  Repeated: killed on attempt 1 of 2 in the first series and attempt 6 of 6 in the second
  (`worker (21264) stopping: Memory limits exceeded: 356659200 bytes`). The kill is sampling-dependent (watcher checks every ~3 s).
  The Fleet client still got `c=300000` each time, so the operator sees success while the agent is being shot.
- Packed report size: `json_group_array(json_object(7 fields))` over 2,000 of these rows = 526,551 bytes, above Fleet's 512 KiB
  per-host result cap (articles/reports.md:55: such a host "returned no data").

## 2. Watchdog and extensions (A17)

Probe extension `$W/ext/main.go` (osquery-go, CGO-free): registers table `rtfo_ext` AND runs three "daemon" goroutines
(heartbeat log every 250 ms; CPU burn while `/run/rtfo/burn` exists; +16 MiB per 250 ms up to 480 MiB while `/run/rtfo/balloon` exists).

Process facts: watcher 19687, worker 19691, extension 19692 with ppid = watcher; all three `NI 10` (extension inherits osquery's
background priority; my hosted "daemon" logged `nice=10` at start).

Default flags (`enable_extensions_watchdog=false`, watchdog level 0 = 200 MB / 10% for 12 s, `watchdog_delay=60`):

```
extension at 100% of one core and RSS 501 MB:  still alive at uptime 121 s, no watcher message       -> NOT limited
17:13:08.854 W watcher.cpp:425] osqueryd worker (19691) stopping: Memory limits exceeded: 216985600 bytes (limit is 200MB)
17:13:08.857 pid=19692 RUN-RETURNED err=<nil>          <- extension (and every goroutine in it) torn down 2-3 ms later
17:13:09.862 pid=21265 START ...                       <- respawned by the watcher 1.0 s later, all in-memory state gone
```

"Survive" variant (extension keeps running after `srv.Run()` returns):

```
17:15:00.884 W osqueryd worker (21264) stopping: Memory limits exceeded: 356659200 bytes (limit is 200MB)
17:15:00.885 pid=21265 survive mode: staying alive after osquery went away
live query "select * from rtfo_ext"           -> "no such table: rtfo_ext"
select uuid,name,type from osquery_extensions -> only "core"
heartbeat goroutine still logging at 17:15:31; watcher does not respawn (process is alive) and nothing re-registers.
```

`--enable_extensions_watchdog=true` (same limits applied to extensions):

```
burn ON 17:16:53 (ext uptime 67 s)
17:17:03.713 W watcher.cpp:380] osquery extension .../rtfo.ext (25049) stopping: Maximum sustainable CPU utilization limit 1200ms exceeded for 12 seconds
17:17:06.917 pid=26987 START      17:17:18.918 pid=26987 SIGNAL terminated     <- respawn killed 12 s after start (no 60 s grace)
17:17:22.122 pid=27622 START      17:17:28.120 W ... (27622) stopping: Memory limits exceeded: 386772992 bytes (limit is 200MB)
17:17:29.799 E scheduler.cpp:128] Error executing scheduled query ext_table: Extension socket not available
17:17:31.325 pid=27903 START      (kill loop, about one restart every 9-12 s while load persists)
```

1200 ms per 3 s check on this 4-core VM = 40% of one core sustained for 12 s.

What holds: one Go binary works as an osquery extension and its goroutines run fine for minutes under default flags.
What does not: making that process the daemon.

## 3. Host identity (A20)

```
osqueryd -S "select uuid from system_info"   run 1: 333a275a-d824-4f16-bfb3-dd3b423be9d2
                                             run 2: 70806a8d-c097-4b34-b6ca-67d5b0cfc89d
shared enrolled host `vm` (Fleet host 1 uuid):      5e8102a2-f0ef-46ef-a315-39f770849362
my private osqueryd (Fleet host 2 uuid):            9b03b3eb-32ad-4d9a-ad27-8fb721e36df3
/etc/machine-id:                                    d165c2d88d894a4787be219662b439ad   (0644, readable as `nobody`)
/sys/class/dmi/id/product_uuid:                     No such file or directory (no /sys/class/dmi, no /sys/firmware/dmi/tables)
hardware_serial / vendor / model:                   all empty
```

Four osquery databases, four different UUIDs, none related to machine-id: with no SMBIOS, osquery invents a random UUID and
persists it in its own RocksDB. A process outside osquery cannot derive it. On hardware that has DMI, the Linux source is
`/sys/class/dmi/id/product_uuid`, which the kernel exposes mode 0400 root (not checkable here: no DMI), so the user-level
`spoor hook` in daemonless mode cannot read it either. Fleet deployments may also run `--host_identifier=instance|hostname`,
so `hostIdentifier` in result logs is not always the hardware UUID.

## 4. Fleet tiers, caps, cadence (A18, A30, A33): documentary evidence (fleetdm/fleet clone)

- This server: `license.tier = free`, `update_interval.osquery_policy = 1h`, `webhook_settings.interval = 24h`, `report_cap = 0` (default).
- Scripts (articles/scripts.md:14-28): "Script execution is disabled by default"; needs fleetd built with `fleetctl package --enable-scripts`
  or macOS MDM; for already-deployed fleetd "This requires a third-party tool (ex. Chef)". Plain osquery hosts (like the one enrolled here) cannot run scripts.
- docs/API/rest-api.md:14249-14259: script runs time out after 5 minutes by default (max 18000 s via `script_execution_timeout`),
  ad hoc `script_contents` "must be less than 10,000 characters", scripts queue behind other host activities.
- Batch run exists (`POST /api/v1/fleet/scripts/run/batch`, `filters.label_id`) and is not marked Premium; it needs a saved script and a caller.
- articles/automations.md:29,55,64: policy automations "install software" and "run script" are "Available in Fleet Premium, fleet-level policies only".
  :43 "Policies run every 1 hour"; :76-78 webhooks/tickets "only triggered when a policy is newly failing" and checked "once per day by default".
- Software packages are Premium and self-hosted needs S3 (fleet.md section 4). TUF `extensions` needs Premium plus a self-run TUF (fleet.md section 1A).
- articles/reports.md:49-55: "Fleet limits each report to as many results as you have hosts"; "When the report is full, Fleet keeps updating hosts
  already in the report ... but doesn't add results from other hosts"; "Fleet also doesn't store a host's result if it exceeds 512 KB".
- GitOps: docs/Configuration/yaml-files.md:1736 "Any settings not defined in your YAML files will be reset to the default values or deleted";
  :53 "Omitting the `labels` key also deletes that file's existing labels"; :17 omitting `custom_host_vitals` "deletes every existing custom host vital".
  docs/Configuration/agent-configuration.md:252-272: overrides "are NOT merged with the top level configuration"; `command_line_flags` unsupported in overrides.
- Fleet built-ins (schema/tables): `ai_tools` (19 columns incl. `risk_flags`, `running`, `pid`, `sha256`), `mcp_listening_servers`,
  `ai_agent_sessions` (21 columns incl. tool_calls and token counts), `ai_agent_session_messages` (per block: `tool_name, action, target, decision, cwd, timestamp`).
  No table for detections, sensor health, hook installation/coverage. The enrolled test host is plain osquery, so none of these exist on it.

Not verified here: saved-script size limit; whether orbit truncates `/opt/orbit/extensions.load` at runtime; any Windows or macOS behaviour
(all experiments are Linux x86-64); `fleetctl gitops --dry-run` of a bundle (binary unavailable).

## 5. Verdict summary

| Assumption | Verdict | One-line reason |
|---|---|---|
| A16 ATC robust at scale | weakened, with one broken consequence | WAL reads are consistent, but policies fail open, cost is O(table) per query, rename-replace and non-WAL are silently wrong |
| A17 extension hosts daemon | broken (hosting); holds (same binary as extension) | daemon dies with every worker kill, or loses its tables; ext watchdog either absent or a kill loop |
| A18 Free deploys with scripts + ATC | weakened | scripts off by default, no automation, no artifact hosting, global agent options |
| A19 tables add value | weakened | 5 of 8 tables duplicate fleetd built-ins; the unique ones are detections, health, coverage |
| A20 host id = system_info.uuid | broken | random per osquery DB on DMI-less hosts; root-only source on Linux |
| A30 no server is a feature | weakened | Fleet is an hourly state plane with result caps; rollout and rule push need an external scheduler |
| A33 packs via Fleet files/scripts | weakened | no file primitive on Free; skew between bundle and binary is silent |
