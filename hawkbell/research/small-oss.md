> **Historical design record.** Research report: small open-source and free comparables (claud3/agentshield, Agentmetry, Agent Beacon, numbat, Fleet's AI tables and others), cited by `docs/COMPARISON.md`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:01 UTC on the build machine; its title says "as of 2026-11-11").
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none. Kept: GitHub account and organisation names that are part of a cited repository, package or image location, because a reader needs them to check the source.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Small OSS and free comparables: endpoint AI-agent discovery, telemetry, detection (as of 2026-11-11)

## Executive summary (5 lines)

1. The "small OSS" field is no longer small: three Go/Python sensors now overlap most of our plan — **Agent Beacon** (MIT, Go, 29 runtimes, pkg/deb/rpm/MSI), **Perplexity numbat** (Apache-2.0, single CGO-free Go binary, 28 agents, CEL + sequence rules, opt-in blocking) and **Agentmetry** (Apache-2.0, Python, 14 sequence rules, hash-chained trail, 6 SIEM sinks). The brief's list missed the first two.
2. **Fleet already ships native AI tables in fleetd**: `ai_tools` (orbit 1.59.0, Aug 2026, vendored from karmine05/agentic-detector), `mcp_listening_servers`, and `ai_agent_sessions` / `ai_agent_session_messages` on main. "Fleet integration" must complement these, not re-implement inventory.
3. Every runtime sensor is hook/OTLP/transcript-based and says so; none does kernel/process corroboration except AgentSight (Linux eBPF, observability only, no rules, no fleet). None has a Kubernetes story.
4. Nobody ships osquery tables for *findings/telemetry health*, Fleet GitOps content, or a Fluent Bit integration (Beacon bundles Vector; Agentmetry has bespoke sinks). Fleet rollout, central policy, signing and consoles sit behind paid/closed tiers in both Beacon and Agentmetry.
5. claud3/agentshield is a 3.6k-LOC config scanner with verified correctness bugs and a secret-leaking JSON payload; Golf Scanner is a v0.1.0 MCP posture CLI. Both are easy to surpass; the bar is set by Beacon + numbat + Agentmetry + Fleet's tables combined.

Verification legend: **V** = primary source read this session (local clone or raw.githubusercontent.com / pypi / proxy.golang.org); **U** = search snippet only. `docs.golf.dev` is outside the session allowlist, so Golf Inventory claims are U.

---

## 1. claud3/agentshield (read fully; V)

Local clone `/home/user/claud3/agentshield`, HEAD `d212a7e` (2026-02-25, tag v0.3.0 per Go proxy). MIT, Go 1.24, deps: BurntSushi/toml, yaml.v3, x/term. 3,622 lines including tests.

- **Mechanism**: one-shot static config scan, `agentshield-scan [--json] [--configs DIR] [--report-url URL] [--api-key KEY]`: path scan → regex/entropy secrets → "MCP Security Benchmark" → output. `--report-url` POSTs the whole result with `X-API-Key` and expects HTTP 201 from a closed "AgentShield Console". `cmd/agentshield/main.go` is a 28-line stub that prints a command list.
- **Output schema**: `{scanner_version, scan_result{hostname, platform, username, tool_configs[], mcp_servers[], managed_configs[]}, findings[], benchmark{checks[], score, maturity_level, maturity_name, summary}}`. Exit 2 on critical credential.
- **Benchmark check IDs worth reusing**: `CS-01` creds in args, `CS-02` env, `CS-03` headers, `CS-04` private key, `CS-06` high entropy, `TS-01` remote HTTPS, `TS-02` `--allow-http`, `TS-03` TLS bypass, `TS-04` `ws://`, `AA-01` stdio-proxy-to-remote without auth, `AA-02` token in URL query, `SC-01` unpinned `npx/uvx/pipx`, `SC-04` third-party proxy domain, `GP-01` managed policy present, `GP-04` config world-readable, `OH-01` duplicate servers, `OH-02` debug flags, `OH-03` >15 servers. Score = 100 − (10 critical / 5 high / 2 medium / 1 low). Maturity 1 Visible → 4 Governed; "Level 5 requires the full AgentShield platform".
- **Managed paths list** (copy): macOS `/Library/Application Support/ClaudeCode/managed-{settings,mcp}.json`; Linux `/etc/claude-code/managed-{settings,mcp}.json`; Windows `C:\Program Files\ClaudeCode\…` and `C:\ProgramData\ClaudeCode\…`; Codex `/etc/codex/{requirements,managed_config}.toml`.

**Verified gaps/bugs**
1. **JSON output leaks the secrets it finds.** `MCPServer` serialises `env`, `headers`, `args`, `raw_config` verbatim (`scanner.go:26-38`); only `Finding.Match` is redacted. `--json` and `--report-url` therefore ship plaintext tokens.
2. **Dead benchmark mappings.** `compliance.go:166-182` switches on `f.Type == "private_key_header" | "allow_http_flag" | "allow_insecure_host"`, but the detector sets `Type` from the pattern's *type* (`"private_key"`, `"insecure_transport"`; `secrets.go:157-167`). CS-04/TS-02/TS-03 cannot fire in a real run; the unit test passes only because it fabricates the type (`compliance_test.go:329`).
3. **README overclaims.** It lists 10 tools; embedded defaults (`paths.go:74-261`) cover 8 on macOS and 7 on Linux/Windows. Zed, JetBrains, `.claude/settings.local.json` and user-level VS Code settings exist only in `configs/paths.yaml`, loaded only from `--configs` or `./configs` relative to CWD. The JetBrains entry is a glob (`IntelliJIdea*`) that `expandPath` never expands, and XML is not parsed.
4. **Parser misses real formats.** JSON extraction reads only top-level `mcpServers` and `projects.*.mcpServers` (`scanner.go:191-210`): no VS Code `servers` / `mcp.servers`, no Zed `context_servers`.
5. **Single user, CWD-relative.** `os.UserHomeDir()` plus relative paths like `.mcp.json`; run by MDM as root it scans root's home and whatever the working directory is. No all-users enumeration, no repo discovery.
6. No Claude Desktop on Windows/Linux, no skills/hooks/plugins/extensions/process inventory, no runtime telemetry, no SIEM sink, no Windows arm64 build, no signing. YAML-only pattern `[a-f0-9]{32}` ("datadog") matches any hex digest.

## 2. Agentmetry (blitzcrieg1/agentmetry; V from raw `master` + PyPI)

Apache-2.0 + CLA, Python ≥3.11, solo maintainer, "public alpha". PyPI 0.11.0 (2026-11-08), 23 releases since 0.4.0 (2026-08-07). Windows and Linux required in CI; macOS: "No hook has been exercised against a live agent on a Mac".

- **Mechanism**: cooperative agent hooks (`agentmetry hooks install`) → local orchestrator (SQLite index + hash-chained JSONL); stdio MCP proxy (`agentmetry mcp-proxy -- <cmd>`, fingerprints `tools/list`, flags rug-pull as `mcp_schema.status: changed`); loopback OTLP/HTTP receiver for Claude Code (`agentmetry otel`); static `scan` (MCP configs, skills, AGENTS.md/CLAUDE.md, typosquats) and `posture` (bypass modes).
- **Agents**: Claude Code, Cursor, Codex, Copilot CLI/VS Code, Qwen, Kimi, Qoder, CodeBuddy, Antigravity (Windows script only). Gemini CLI "possible, not built".
- **Output**: file, webhook (canonical / `batch` / CloudEvents), Elastic ECS, Splunk HEC, Google SecOps UDM, Sentinel ("not yet run against a live workspace"). No OTLP export ("That direction is not built"). Sigma pack (23 rules); Tenzir package maps to OCSF 1.9.0.
- **Detection**: 14 published ordered sequence rules per `correlation_id` (`credential-exfil`, `credential-read-then-cloud-api`, `dotfile-read-then-git-push`, `remote-staging-then-execute`, `approval-denied-then-executed`, `encoded-command-download`, `pr-merged-without-review`, `untrusted-input-then-risky-action`, `destructive-delete-burst`, `discovery-then-collect`, `session-tool-burst`, `subagent-swarm-burst`, `host-subagent-swarm-burst`, opt-in `off-hours-activity`). `agentmetry benchmark`: 57 cases (26 attack / 31 benign), 0 missed / 0 FP on its own corpus. ATT&CK tag per tool call; ATLAS ids pinned to a content release (2026.07).
- **Schema 1.2.0 essentials**: `event_id, seq, session_id, correlation_id, timestamp_utc, host_id, fleet_id, source{tier,app,adapter}, initiator{actor_type,trigger,operator_id,operator_source}, actor, action{type,outcome,reason}, agent, tool{name,qualified,input_hash,input_redaction,mitre,atlas}, model, dlp, tool_policy, detection{rule_id,severity,event_ids,…}, mcp_schema, account{domain,source,organization_id}`. Detections are events: `action.type=detection`, `action.outcome=<severity>`. Trail line wrapper: `{"trail":{"v","seq","prev_sha256","record_sha256"},"event":{…}}`.
- **Health idea worth copying**: heartbeat every 300 s listing hooked agents; `action.outcome: degraded` when an installed agent is unhooked; `hooks_silent` for configured-but-no-events in 7 days.
- **Sizing (one developer, their caveat)**: 1,119 events/active dev/day median (199–2,542), 1.1 KB median / 2.2 KB p90, ~60 MB/dev/month.
- **Fleet**: "Fleet questions are answered in the SIEM you forward to." No central policy or triage. Enterprise (ELv2, private repo): MSI, Intune scripts, Splunk TA, per-host Ed25519 signing, hosted console, Sigma import, mTLS. Won't-build list: "Full Rust/Go rewrite before paid fleet demand (≥500 seats)".
- **Self-declared limits**: not a process/file monitor; HTTP MCP unseen; approvals mostly inferred; tool outputs not logged; any API-token holder can inject events stamped as that host.

## 3. Agent Beacon (asymptote-labs/agent-beacon; V from raw `main`)

MIT, Go multi-module (`cli/beacon`, `cli/beacon-hooks`, `collector-builder`, `pkg/asymptoteobserve`); docs reference releases after 1.3.57. README headline is now "Self-improving memory for coding agents"; `AGENTS.md` still says "local-only endpoint telemetry agent for AI runtimes".

- **Mechanism**: strongest surface per harness — native hooks, managed plugins, local OTLP into a bundled OTel Collector distribution (`127.0.0.1:4317/4318`, `beaconjson` exporter), or polling the runtime's session store. Also: MV3 browser extension (claude.ai, ChatGPT), `beacon ci exec`, cloud-sandbox hooks → GCS/S3, JS SDK. Inventory job every 6 h writes `inventory.heartbeat` and (on digest change) `inventory.snapshot` to `inventory_state.jsonl` (agents, MCP servers, skills, hook configs; metadata/hash only unless `--contents`).
- **Agents**: 29 local runtimes in the README matrix (Claude Code, Cowork, Codex CLI/Desktop, Cursor, Copilot CLI, Gemini CLI, VS Code, Cline, OpenCode, Kiro, Devin, Droid, goose, OpenHands, Pi, Qwen, Kimi, Hermes, OpenClaw…).
- **OS/packaging**: signed+notarized macOS `.pkg` and brew; `.deb`/`.rpm` with signed apt repo and build-provenance attestation; Windows x64 MSI + Windows service, **not Authenticode-signed**, no self-update. Containers: only `--service none` supervised mode.
- **Output**: `runtime.jsonl` (user `~/.beacon/endpoint/logs/`, system `/var/log/beacon-agent/`; rotate 10 MiB × 5). Direct collector export only to Splunk HEC and Falcon LogScale; everything else is "read the JSONL" via bundled **Vector 0.56.0** or content packs (Sentinel, Rapid7, Sumo, Wazuh, Datadog, Elastic, CloudWatch, S3, GCS).
- **Schema ideas worth copying**: provenance on every event — `harness.collection_method` (`hook|otlp|plugin|poll|gateway`) and `event.fidelity` (`observed|inferred`); `prompt.id` normalising each runtime's turn id; OTel GenAI attributes preserved under `gen_ai`.
- **Detection**: "Threat Rules v1.2": YAML + CEL over the event (`e.event.action`, `e.file.path`, `e.command.command`), `correlation{scope: session, window, order: sequence|any, steps[]}`, mandatory embedded `tests[]` fixtures, RE2 only, cel-go cost cap 5,000,000. Six embedded baseline rules; corpus managed with `beacon rules`. Evaluation is `beacon scan` over the log (offline batch).
- **Fleet**: settings read from `/etc/default/beacon`, macOS profile domain `com.beacon.endpoint`, `HKLM\SOFTWARE\Policies\Beacon\Endpoint`; restricted log ACL + `beacon-log` group; per-person attribution from OS peer credentials. Plans table lists **"Fleet rollout (Jamf, Intune, Fleet)" and "Block or require approval for risky actions" as Enterprise-only**; cross-machine timeline is Beacon Cloud SaaS (free tier: 50 findings lifetime); interactive setup preselects Beacon Cloud.
- **Self-declared scope boundary**: "does not do kernel or process monitoring, shell history collection, cloud audit ingestion…". System-mode scheduled inventory covers only the active console user's home, and only user-level config (project-scoped files are not in the job).

## 4. numbat (perplexityai/numbat; V from raw `main` + Go proxy)

Apache-2.0, Go 1.26.10, CGO-free single binary for macOS/Linux/Windows amd64+arm64. v0.3.0 (2026-10-19). Record `schema_version` 0.5.0.

- **Mechanism**: no daemon. `numbat hook install --agent X [--managed] [--enforce]` writes hook/plugin config that launches a short-lived `numbat hook` per event; `numbat collect` (OTLP/HTTP logs); `numbat scan` / `timeline` parse on-disk session artifacts with no prior instrumentation; `numbat agents` inventory; `numbat ship` tails the output file for async HTTP delivery.
- **Agents**: 28 in the matrix with exact artifact and hook paths, plus managed-policy targets, e.g. Claude Code `/Library/Application Support/ClaudeCode/managed-settings.d/numbat.json`, `/etc/claude-code/managed-settings.d/numbat.json`, `C:\Program Files\ClaudeCode\managed-settings.d\numbat.json`; Copilot `/etc/github-copilot/policy.d/numbat.json`.
- **Detection**: CEL single-event rules and ordered sequence rules (2–8 steps); shell-aware fields from a real parser (mvdan.cc/sh; dialects `posix|powershell|cmd`; argv, redirects, wrappers, pipelines); rule tests; `enforce: true` opt-in, all shipped rules monitor-only.
- **Output**: NDJSON `record_type` = `event | finding | enforcement | indicator | scan summary`; stdout, file, HTTP (bearer or HMAC). "Direct HTTP is not a disk queue."
- **Fleet**: "The endpoint platform remains responsible for binary distribution, choosing the target users and agents, rerunning the idempotent install after upgrades, injecting sink credentials… and supervising any `ship` process." Discovery must run in user context.
- **Gaps**: no MCP/skill/extension posture inventory comparable to Fleet `ai_tools`; no OS packages or service; no SIEM-specific mappings (inference: only generic HTTP documented); no process/kernel signal; no osquery/Fluent Bit content; no central anything.

## 5. Fleet-native tables (V, local clone `/home/user/fleetdm/fleet` at `27178c8`, 2026-11-11)

- **`ai_tools`** — `orbit/pkg/table/ai_tools/`, added orbit **1.59.0 (2026-08-13)**, tuned in 1.62.0 "so it can run hourly on every host". Vendored from `karmine05/agentic-detector` v0.3.0 (MIT). `type` ∈ `mcp_server | ide_plugins | agents | apps | sockets | agent_instruction | browser_extension`. Columns: `type, name, identifier, category, location, source, version, path, endpoint, running, pid, port, risk_flags, sha256, confidence, evidence, uid, username, detail`. Enumerates all homes (`/Users/*`, `/home/*`, `/root`, `C:\Users\*`).
  `risk_flags` (copy): `remote_fetch_exec, unpinned_dependency, mcp_shell_exec, mcp_fs_write, plaintext_secret, world_readable_config, cleartext_endpoint, bypass_permissions, auto_accept_edits, skip_permissions_runtime, injection_markers, hidden_unicode, world_writable, broad_host_permissions, sideloaded_unverified`.
- **`ai_agent_sessions` / `ai_agent_session_messages`** — `orbit/pkg/table/ai_agent_sessions/`, registered in `extension.go` on main but absent from `orbit/CHANGELOG.md` through 1.63.0 (2026-10-30), so treat as unreleased. Transcript parsers for `claude_code, copilot_cli, cursor, codex_cli, gemini_cli`; per-session tokens, model, `account_identifier`, tool-call counts; messages table gives `action` (`read|write|execute|search|network|mcp|other`), `target`, `decision` (`allowed|denied|error`). Limits: 30-day default window, 4 GiB read per query, 5,000 sessions/agent/home, ~1 MiB per result, content 8 KB; relocated homes (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`…) not found; content table "don't schedule it unconstrained".
- **`mcp_listening_servers`** (orbit 1.49.1, 2025-10-27): probes listening ports for MCP over HTTP.
- **Gaps we can fill**: all three are `evented: false` snapshots; no detection or sequence logic; no rows for skills, hooks or plugins (skills only count as `workspace_shape` evidence; no hook handling in non-test code); requires fleetd, not stock osquery.
- Also V (changelog only): Elastic Osquery Manager 1.33.0 added "Shadow AI Discovery" osquery packs (15 Windows / 17 macOS / 16 Linux queries); the queries themselves were not read.

## 6. Other tools (short)

| Tool | Status | Notes |
|---|---|---|
| **Golf Scanner** (golf-mcp/golf-scanner) | V README; Apache-2.0; Go, 3 deps; only tag v0.1.0 (2026-03-04) | Discovers MCP configs in 7 IDEs (Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Kiro, Antigravity); 20 checks (9 offline, 11 online: OSV, GitHub, npm, PyPI, OCI, MCP Registry, cosign); 0–100 score, caps 30 (critical) / 59 (high); `--fail-on`, `--json`. One machine, point-in-time; fleet = paid Golf Inventory (U). |
| **AgentSight** (eunomia-bpf) | V README; MIT; Rust + eBPF | uprobes on TLS read/write + process tracer; `sudo agentsight record -- claude`; SQLite per run; OTLP/HTTP GenAI span export. Root + Linux for eBPF; macOS/Windows only read session files. Statically linked BoringSSL (Claude/Bun) and Node OpenSSL need per-binary offsets; Electron IDEs "Not through eBPF". No rules, no fleet. <3% CPU is self-reported. |
| **Prempti** (falcosecurity) | V README; Apache-2.0; "Experimental Preview"; v0.2.1 stable, 0.3.0-rc5 | Hook interceptor → Unix socket → Falco (nodriver) plugin → allow/deny/ask. Claude Code on 3 OS; Codex experimental on Linux. Per-user install, unsigned binaries. Proves Falco rule syntax is acceptable to this audience. |
| **Sage** (gendigitalinc) | V README; Apache-2.0; Node ≥18 | Pre-tool hooks/plugins for Claude Code, Cursor/VS Code/Copilot CLI, OpenClaw, OpenCode, pi; 300+ YAML heuristics, cloud URL reputation, PI classifier, AMSI on Windows, JSONL audit log. Consumer-style; no fleet/SIEM path documented in README. |
| **Cisco mcp-scanner** | V; Apache-2.0; Python 3.11; PyPI 4.8.7 (2026-10-20) | Scans MCP servers/tools (YARA, LLM judge, Cisco API, pip-audit, VirusTotal). Not an endpoint sensor. |
| **Lasso mcp-gateway** | V; MIT; last PyPI 1.2.1 (2026-01-22) | stdio MCP proxy with masking plugins; stale. |
| **ToolHive** (Stacklok) | V; Apache-2.0; v0.64.0 (2026-11-10) | Runs MCP servers in containers, K8s operator, OTel. Governance by replacement, not discovery. **CodeGate is deprecated** (V). |
| **StrongDM Leash** | V; Apache-2.0; v1.1.7 | Wraps agents in containers, Cedar policy, syscall monitoring. Opt-in wrapper. |
| **agentsh** (canyonroad) | V; v0.20.5 | Exec gateway with file/net/process enforcement; macOS ESF alpha; Windows minifilter unsigned. |
| **ggshield** | V | `ggshield install` AI hooks block secrets; `ai discover` inventory (U). |
| **claude-code-otel** | V; MIT | Grafana/Prometheus/Loki stack for Claude Code OTel: cost/usage, not security. |
| Exabeam Agent Sensor, 1Password/Kolide AI Insights, GitGuardian inventory | U; closed | Hook installers / inventory behind paid products. |
| agentgateway (LF), NVIDIA OpenShell (CNCF) | V | Network proxy and sandbox runtime; complementary, not sensors. No official Tetragon AI-agent policy library found (U). Lists to mine (U): scadastrangelove/awesome-ai-security-tools, ProjectRecon/awesome-ai-agents-security, efij/awesome-claude-code-security. |

## 7. Comparison

| | Mechanism | Agents | OS | Transport | Fleet story | Detection | Licence / maturity | Decisive gap |
|---|---|---|---|---|---|---|---|---|
| uber/ADR | on-disk log/transcript parsing (library) + discovery + LLM detector | 11 log parsers | mac/Linux/Win | library output | none shipped | two-tier LLM, ADR-Bench | Python; `adr-sensor` 1.0.0, single PyPI release (2026-07-31) | no prevention, no live capture, no fleet/SIEM plumbing |
| agentshield | config scan | 8 effective | 3 (no Win arm64) | stdout, POST to closed console | "deploy via MDM" | 18 posture checks | MIT; dormant since Feb 2026 | bugs, leaks secrets, single user |
| Golf Scanner | config scan + registry lookups | 7 IDEs | mac/Linux (Win build exists) | table/JSON | paid | 20 posture checks | Apache-2.0; v0.1.0 | no runtime, no fleet |
| Fleet `ai_tools` + sessions | osquery tables in fleetd | catalog + heuristics; 5 transcript parsers | 3 | osquery results | native | risk flags only | MIT upstream; shipping | snapshot only, no rules, no skills/hooks |
| Agentmetry | hooks + MCP stdio proxy + OTLP in | 9 | Win/Linux; macOS untested live | JSONL chain, webhook, ECS, HEC, UDM, Sentinel | SIEM only; rest ELv2 | 14 sequence rules, Sigma | Apache-2.0 + CLA; alpha; Python | Python runtime, no packages, no process signal |
| Agent Beacon | hooks + plugins + OTLP collector + poll + browser ext | 29 | 3, packaged | JSONL, Vector, HEC | settings via MDM; rollout/enforcement Enterprise; SaaS console | CEL rules, batch `scan` | MIT; active | SaaS funnel, batch detection, no kernel, no osquery/Fluent Bit |
| numbat | hooks + OTLP in + artifact forensics | 28 | 3, single binary | NDJSON, HTTP | DIY | CEL + sequences + shell parser, opt-in block | Apache-2.0; v0.3.0 | no posture inventory, no packaging, no SIEM maps |
| AgentSight | eBPF TLS + process | any Linux process | Linux | SQLite, OTLP | none | none | MIT; research-grade | root, Linux, no rules |
| Prempti | hook → Falco | Claude Code (+Codex exp.) | 3 | Falco outputs | none | Falco rules, verdicts | Apache-2.0; preview | two agents, per-user |
| Sage | hooks/plugins | 6 hosts | 3 (Node) | JSONL | none | 300+ heuristics + cloud | Apache-2.0 | cloud lookups, no fleet |

## 8. The bar an OSS newcomer must clear

To be clearly better than all of the above *combined*, ship every row below in the free build:

1. **One static Go binary plus signed packages** (pkg, deb/rpm, MSI incl. arm64) **and a container image / DaemonSet**. No one covers Kubernetes; Beacon's MSI is unsigned; numbat ships no packages; Agentmetry needs Python.
2. **Multi-source capture with explicit provenance**: hooks + OTLP receiver + transcript tailing (works with zero agent config, like numbat `scan` and Fleet's parsers) + OS process/network corroboration (Linux eBPF or `/proc`, ESF/ETW later). Stamp `collection_method` and `fidelity` on every event; correlate so a hook-less session is still visible and a hook event without a matching process is suspicious.
3. **Inventory superset of Fleet `ai_tools`**: add skills, hooks, plugins/marketplaces, managed-policy state, permission posture; parse every MCP dialect (`mcpServers`, VS Code `servers`, Zed `context_servers`, Codex TOML, Continue YAML); all users' homes; project scope via repo discovery; never emit secret values.
4. **Streaming detection on the endpoint** with a documented open format (CEL + ordered/unordered session windows + embedded fixtures, shell-aware fields), Sigma export, and a **public replayable benchmark corpus with CI gate** (Agentmetry has 57 cases; nobody else has ADR-Bench-like coverage).
5. **Fleet-native content nobody ships**: an osquery extension (or ATC/log-backed tables) exposing *findings, sensor health and hook coverage*, plus GitOps YAML (reports, policies, labels) that joins with fleetd's `ai_tools`. Works on stock osquery too.
6. **Fluent Bit as a first-class, tested path**: stable JSONL with rotation contract, shipped parser/tail/forward/OTLP configs, and CI against the real image. Nobody documents Fluent Bit today.
7. **Coverage honesty as telemetry**: heartbeat, per-agent states (hooked / unhooked / silent / unmanaged), hash chain, and per-host signing in the free tier.
8. **Privacy defaults**: metadata + keyed hashes by default, opt-in content, local redaction before any sink.
9. **No SaaS preselect, no CLA, no feature held back for a console.**

## Sources

- Local (V): `/home/user/claud3/agentshield/**`; `/home/user/fleetdm/fleet/orbit/pkg/table/{ai_tools,ai_agent_sessions,mcp_listening_servers}`, `schema/tables/ai_*.yml`, `orbit/CHANGELOG.md`; `/home/user/uber/adr/{README.md,Sensor/README.md}`.
- Raw GitHub (V), `https://raw.githubusercontent.com/<repo>/<branch>/…`: blitzcrieg1/agentmetry (master: README, docs/agentmetry-event-schema.md, docs/detection-rules.md, docs/integrations/fleet-via-siem.md, docs/commercial/open-core-split.md); asymptote-labs/agent-beacon (main: README, CLAUDE.md, spec/threat-rules/SPEC.md, docs/architecture/architecture.mdx, docs/platforms/fleet-deployment.mdx, docs/platforms/windows.mdx, docs/deployment/plans.mdx, docs/cli/endpoint-inventory.mdx); perplexityai/numbat (main: README, docs/agent-coverage.md, docs/deployment.md, docs/rules.md); READMEs of golf-mcp/golf-scanner, eunomia-bpf/agentsight, falcosecurity/prempti, gendigitalinc/sage, karmine05/agentic-detector, cisco-ai-defense/mcp-scanner, strongdm/leash, canyonroad/agentsh, stacklok/toolhive, stacklok/codegate, lasso-security/mcp-gateway, NVIDIA/OpenShell, GitGuardian/ggshield, ColeMurray/claude-code-otel; elastic/integrations `packages/osquery_manager/changelog.yml`.
- Registries (V): pypi.org JSON API and proxy.golang.org `@latest` for versions and dates.
- Search only (U): docs.golf.dev (not on the session allowlist), Agent Beacon launch date, Exabeam, 1Password/Kolide, Sysdig/CNCF Prempti posts, star counts.
