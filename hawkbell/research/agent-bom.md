> **Historical design record.** Research report on agent-bom (a local clone at 0.81.1 and upstream 0.114.0), cited by `docs/COMPARISON.md`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:51 UTC on the build machine; its title is dated 2026-11-11).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the name of the individual copyright holder in section 9 (1 place). Kept: GitHub account and organisation names that are part of a cited repository, package or image location, because a reader needs them to check the source. This includes the maintainer's account names (`msaad00`, `msaad02`) in the version table of section 0, the `CODEOWNERS` line and the repository moves in section 10, and the image name in section 11, item 9; they belong to the individual whose written-out name is redacted, so the redaction keeps the personal name out of the text but does not make the maintainer anonymous.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# agent-bom research report (2026-11-11)

## Executive summary (5 lines)

1. agent-bom is a 144k-LOC Python (>=3.11) "AI supply-chain BOM" scanner plus FastAPI/Next.js control plane; its core is static config discovery for 29 MCP clients and a CVE "blast radius" graph (CVE -> package -> MCP server -> agent -> credentials -> tools), not runtime detection.
2. Our local clone (`github.com/agent-bom/agent-bom`, v0.81.1, one commit dated 2026-04-23) is a STALE location: the live project is `koda-ai-studio/agent-bom` at v0.114.0 (PyPI upload 2026-11-08), 181 PyPI releases since 2026-02-19. Treat it as very active, single-maintainer-led.
3. Fleet mode is "cron runs the Python CLI on the laptop and POSTs JSON to `/v1/fleet/sync`"; upstream docs still say "this is not a managed endpoint agent or EDR". No osquery, FleetDM or Fluent Bit integration exists anywhere (zero hits in clone, upstream README and CHANGELOG).
4. Runtime coverage is an MCP stdio/SSE proxy + HTTP gateway (JSON-RPC interception, 7 inline detectors, policy blocking). Native agent tools (Bash/Edit/Write) are invisible to it; upstream later added an offline `agent-bom activity` transcript reviewer and a PreToolUse package-install guard, neither streamed to the control plane.
5. Worth copying: per-OS config path table, deterministic UUIDv5 IDs, credential-name-only redaction, CWE-aware reach, MCPObservation record. Worth beating: Python runtime on endpoints, launching MCP servers during scheduled scans, per-event SIEM POSTs, scope sprawl, no benchmark.

Verification legend: VERIFIED = read in primary source this session (local clone path, or upstream raw file / PyPI JSON). UNVERIFIED = not read.

## 0. Version caveat (read first)

| Source | Version | Evidence |
|---|---|---|
| Local clone `/home/user/agent-bom/agent-bom` | 0.81.1, 1 commit `b8fe01f` 2026-04-23 | `pyproject.toml`, `git log` VERIFIED |
| `raw.githubusercontent.com/agent-bom/agent-bom/main/pyproject.toml` | 0.81.1 | VERIFIED (stale org copy) |
| `raw.githubusercontent.com/koda-ai-studio/agent-bom/main/pyproject.toml` (also `msaad00/`) | 0.114.0 | VERIFIED |
| PyPI `agent-bom` | 0.114.0 uploaded 2026-11-08; project URLs point to `koda-ai-studio/agent-bom` | VERIFIED `pypi.org/pypi/agent-bom/json` |

Sections below describe 0.81.1 code unless marked "upstream 0.114" (read from upstream raw files). Any article we publish must compare against upstream main, not the clone.

## 1. What it inventories and how

Discovery is static file parsing; entry point `discover_all()` in `src/agent_bom/discovery/__init__.py:1144`.

**Clients (29 `AgentType` values + `custom`)**, `models.py:36-66`: claude-desktop, claude-code, cursor, windsurf, cline, vscode-copilot, cortex-code, codex-cli, gemini-cli, goose, snowflake-cli, continue, zed, openclaw, roo-code, amazon-q, docker-mcp, jetbrains-ai, junie, copilot-cli, tabnine, sourcegraph-cody, aider, replit-agent, void, aide, trae, pieces, mcp-cli.

**Exact paths** (`CONFIG_LOCATIONS`, `discovery/__init__.py:38-245`, VERIFIED). Keys are `platform.system()` values `Darwin|Linux|Windows`; `~` expanded for the invoking user only.

| Client | macOS | Linux | Windows |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `~/AppData/Roaming/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` (incl. per-project `projects.*.mcpServers`) | same | same |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` | `~/.windsurf/mcp.json` | `~/.windsurf/mcp.json` |
| Cline | `<CodeUser>/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | same under `~/.config/Code/User` | same under `~/AppData/Roaming/Code/User` |
| Roo Code | `<CodeUser>/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json` | same | same |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` | `~/AppData/Roaming/Code/User/mcp.json` |
| Codex CLI | `~/.codex/config.toml` (`[mcp_servers.*]`) | same | same |
| Gemini CLI | `~/.gemini/settings.json` | same | same |
| Copilot CLI | `~/.copilot/mcp-config.json` | same | same |
| Goose | `~/.config/goose/config.yaml` | same | `~/AppData/Roaming/Block/goose/config/config.yaml` |
| Continue | `~/.continue/config.json`, `<CodeUser>/globalStorage/continue.continue/config.json` | same | same |
| Zed | `~/.config/zed/settings.json` (`context_servers`) | same | `~/AppData/Roaming/Zed/settings.json` |
| JetBrains AI | `~/Library/Application Support/JetBrains/*/mcp.json`, `~/.config/github-copilot/intellij/mcp.json` | `~/.config/JetBrains/*/mcp.json` | `~/AppData/Roaming/JetBrains/*/mcp.json` |
| Junie / Tabnine / Cody / Amazon Q | `~/.junie/mcp/mcp.json`; `~/.tabnine/mcp_servers.json`; `~/.cody/mcp.json` + `sourcegraph.cody-ai/mcp.json`; `amazonwebservices.amazon-q-vscode/mcp.json` | same | same |
| Cortex Code | `~/.snowflake/cortex/{mcp,settings,permissions,hooks}.json` | same | same |
| Docker MCP Toolkit | `~/.docker/mcp/registry.yaml` + `~/.docker/mcp/catalogs/docker-mcp.yaml` | same | same |

Project-level (`PROJECT_CONFIG_FILES`, line 268): `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.openclaw/openclaw.json`, `.codex/config.toml`, `.gemini/settings.json`, `.junie/mcp/mcp.json`; compose files with images prefixed `mcp/`, `ghcr.io/modelcontextprotocol/`, `modelcontextprotocol/`.

**Installed-but-unconfigured**: `shutil.which()` on 16 binary names (`AGENT_BINARIES`, line 248: claude, codex, gemini, cursor, windsurf, goose, aider, zed, ...) plus `~/.local/bin`, `/usr/local/bin`, `~/.cargo/bin`.

**Opt-in layers**: running processes via `psutil` matching cmdline substrings `mcp-server`, `@modelcontextprotocol/`, `mcp_server`, `mcpserver`, `uvx mcp`, `npx mcp`, `python -m mcp` (line 664); Docker via `docker ps` + `docker inspect`; Kubernetes via `kubectl get pods -o json` and CRD `mcpservers` (labels `mcp.server`, `mcp-server`, `mcp.io/server`; image patterns `mcp-server`, `/mcp:`; env prefix `MCP_`); offline disk snapshots via `discover_filesystem_mcps(root)` over `home/*`, `root`, `Users/*`; "dynamic" content sniffing for top-level keys `mcpServers|mcp_servers|servers|context_servers` (`discovery/dynamic.py`).

**MCP tools/resources**: only with `--introspect`, which spawns each stdio server (`mcp_introspect.py:311-322`, `stdio_client(StdioServerParameters(command=server.command...))`) and calls `initialize`, `tools/list`, `resources/list`.

**Skills/instructions** (`parsers/skills.py:28-40`): project-relative only: `CLAUDE.md`, `.claude/CLAUDE.md`, `.cursorrules`, `.cursor/rules`, `skill.md`, `skills/*.md`, `.github/copilot-instructions.md`, `.windsurfrules`, `AGENTS.md`, `.cortex/skills`, `.snowflake/cortex/skills`. No grep hit for `~/.claude/skills`, `~/.claude/plugins`, `.claude/agents` or `.claude/commands` in 0.81.1 (VERIFIED absence). Skill audit (`parsers/skill_audit.py`, 1531 lines) does regex + Python `ast` + JS call-name analysis for eval/exec/subprocess/file mutation, typosquat and registry verification.

**Packages**: derived from server commands (`npx`/`uvx` args), lockfiles/manifests, container images; resolved against npm/PyPI/Go proxy/deps.dev. **Models**: weight files (pickle flags), HuggingFace/Ollama/MLflow/W&B provenance, dataset cards. Also in scope: cloud CSPM (AWS/Azure/GCP/Snowflake/Databricks CIS), IaC, SAST, GPU infra, browser extensions.

Upstream 0.114 additions (VERIFIED from raw files): `discovery/agent_permission_posture.py` reads Claude Code `managed-settings.json` (`/Library/Application Support/ClaudeCode`, `/etc/claude-code`, plus `managed-settings.d/*.json`); `scan --preset workstation` collects installed applications, processes, services, listeners, containers, images as names/counts only.

## 2. Data model / BOM schema

Canonical model is Python dataclasses (`models.py`), serialized to a custom JSON document; CycloneDX and SPDX are export projections.

- `Agent` (line 618): `name, agent_type, config_path, mcp_servers[], version, source, status(configured|installed-not-configured), parent_agent, metadata, automation_settings`.
- `MCPServer` (509): `name, command, args[], env{}, transport(stdio|sse|streamable-http|unknown), url, tools[], resources[], packages[], config_path, working_dir, mcp_version, registry_verified, registry_id, permission_profile, security_blocked, security_warnings[], surface`. Derived: `auth_mode` in `env-credentials | url-embedded-credentials | network-no-auth-observed | local-stdio`; `credential_names`; `fingerprint`.
- `MCPTool`: `name, description, input_schema, schema_findings[], schema_rule_findings[]`. `PermissionProfile`: `runs_as_root, container_privileged, tool_permissions{}, capabilities[], network_access, filesystem_write, shell_access, security_opt[]`.
- `Package`: `name, version, ecosystem, purl, is_direct, dependency_depth, is_malicious, license, scorecard_score, integrity_verified, provenance_attested, occurrences[]`...
- `BlastRadius` (663): `vulnerability, package, affected_servers[], affected_agents[], exposed_credentials[], exposed_tools[], risk_score, impact_category, hop_depth, delegation_chain[], transitive_*`, plus 14 framework tag lists.
- IDs: `stable_id = uuid5(NS 7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7, "agent:{type}:{name}")`; server uses `registry_id` or `name:command`; package uses purl. Note: no host component in any ID.

Native JSON (`output/json_fmt.py:467`): `document_type: "AI-BOM"`, `spec_version: "1.0"`, `scan_id`, `ai_bom_version`, `generated_at`, `scan_sources`, `summary`, `inventory_snapshot`, `agents[]`, `blast_radius[]`, `threat_framework_summary`, `remediation_plan`, `posture_scorecard`, `credential_risk_ranking`. Published JSON Schema `config/schemas/inventory.schema.json` (`$id https://agent-bom.github.io/schemas/inventory/v1`) covers only `agents[] -> mcp_servers[] -> tools[]/packages[]` and its `agent_type` enum lists just 6 values (stale vs 30 in code).

CycloneDX 1.6 (`output/cyclonedx_fmt.py:260`): agent = component `type: application`, `bom-ref: agent-<uuid>`, properties `agent-bom:type=ai-agent`, `agent-bom:config-path`, `agent-bom:status`; MCP server = `application` with `agent-bom:type=mcp-server`, `agent-bom:command`, `agent-bom:transport`, `agent-bom:has-credentials`, `agent-bom:tool-count`, `agent-bom:mcp-tool`, tools also under `services[]`; packages = `library` with purl; models = `machine-learning-model` + `modelCard`; `dependencies[]` agent -> server -> package; `vulnerabilities[]` with VEX `analysis.state`. SPDX 3.0 JSON-LD (`output/spdx_fmt.py`): agents as AI-profile elements, `VulnAssessmentRelationship`.

Doc/code drift: `docs/DATA_MODEL.md` lists enum members absent from `models.py` (`KIRO`, `WEBSOCKET`, `ServerSurface.LOCAL/IN_CLUSTER`, `MCPTool.dangerous`). VERIFIED by comparison.

## 3. Vulnerability and risk checks

- Sources: OSV primary (API or bundled SQLite `vulns/affected/epss_scores/kev_entries`), GHSA, NVD, EPSS, CISA KEV, NVIDIA CSAF, deps.dev, OpenSSF Scorecard, OSV `MAL-` malicious packages, npm/PyPI integrity + provenance (SLSA, PEP 740, sumdb).
- Blast radius score (`models.py:703`, weights in `config.py:75-109`, all env-overridable): base 8/6/4/2 by severity + min(0.5*agents, 2.0) + min(0.3*creds, 1.5) + min(0.1*tools, 1.0) + AI boost 0.5 + KEV 1.0 + EPSS 0.5 + low-Scorecard 0.25-0.75, capped at 10.
- CWE-aware reach (`cwe_impact.py`): CWE -> `code-execution | credential-access | file-access | injection | ssrf | data-leak | availability | client-side`; a DoS CWE does not "expose" env credentials.
- Multi-hop (`scanners/blast_radius.py`): BFS over agents sharing a server name, factors 1.0/0.7/0.5/0.35/0.25, max depth 5.
- Credentials: env var NAME substring match against `SENSITIVE_PATTERNS` (`constants.py:183`: key, token, secret, password, credential, api_key, auth, private, connection, database_url, ...); values replaced with `***REDACTED***`.
- Tool capability classes (`risk_analyzer.py`): READ/WRITE/DELETE/EXECUTE/NETWORK/AUTH/ADMIN weighted; toxic combos (`toxic_combos.py`): `credential_blast, lateral_chain, execute_exploit, multi_agent_cve, kev_with_credentials, transitive_critical, cache_poison, cross_agent_poison`.
- Tool poisoning (`enforcement.py`): injection regex over tool descriptions and `inputSchema` after stripping zero-width characters; description-hash drift.
- Bundled MCP registry `src/agent_bom/mcp_registry.json`: 427 entries with `risk_level, verified, tools[], credential_env_vars[], command_patterns[]`.
- Config posture: `enableAllProjectMcpServers`, non-Anthropic `ANTHROPIC_BASE_URL`, Claude Desktop `scheduledTasksEnabled/webSearchEnabled`, Cortex hooks.

## 4. Self-hosted API, UI, fleet sync

- API: FastAPI, 124 route decorators under `src/agent_bom/api/routes/` (VERIFIED count). UI: Next.js 16 / React 19 / `@xyflow/react` (`ui/package.json`), separate image `agentbom/agent-bom-ui`.
- Stores: Protocol + InMemory + SQLite + Postgres (RLS via `app.tenant_id`), optional ClickHouse (analytics) and Snowflake.
- Auth: API keys (hashed, roles admin/analyst/viewer), OIDC, SAML (assertion -> short-lived API key), trusted-proxy headers `X-Agent-Bom-Tenant-ID`/`X-Agent-Bom-Role`; HMAC-chained audit log, `GET /v1/audit/export`.
- Fleet sync (0.81.1): endpoint runs `agent-bom agents --preset enterprise --introspect --push-url .../v1/fleet/sync` from a user systemd timer (`OnUnitActiveSec=30m`) or launchd (`StartInterval 1800`); Jamf/Kandji/Intune wrappers just copy an installer that does `uv tool install` / `pipx install agent-bom`. Payload `PushPayload{source_id, idempotency_key, agents[], blast_radii[], warnings[]}`; `source_id = sha256(hostname)[:12]` (`push.py:23`); 3 retries with backoff.
- Fleet record `FleetAgent` (`api/fleet_store.py:29`): `agent_id, name, agent_type, lifecycle_state(discovered|pending_review|approved|quarantined|decommissioned), owner, environment, tags, trust_score, server_count, package_count, credential_count, vuln_count, tenant_id, last_discovery`. No host/device field.
- `MCPObservation` (`api/mcp_observation_store.py:17`) is the best schema to copy: `server_stable_id, server_fingerprint, server_name, agent_name, transport, url, auth_mode, command, args, config_path, credential_env_vars, observed_via[], observed_scopes[], configured_locally, fleet_present, gateway_registered, runtime_observed, first_seen, last_seen, last_synced`.
- Scale: sizing doc states it "does not promise fixed throughput numbers the repo has not published"; planning bands are ~250, 250-2,000 and 2,000+ endpoints; k6 scripts only hit `GET /health`, `/v1/fleet`, `/v1/fleet/stats`, `POST /v1/proxy/audit`. Upstream 0.114 adds p95 targets (for example fleet read < 200 ms) but still says "publish your own benchmark numbers".

## 5. Runtime monitoring / enforcement

- `agent-bom proxy -- <server cmd>`: stdio JSON-RPC man-in-the-middle; `proxy-configure --apply` rewrites client configs to `"command": "agent-bom", "args": ["proxy","--",...]`. Audit JSONL record: `{ts, type:"tools/call", tool, agent_id, tenant_id, args(truncated), policy:"allowed|blocked", reason, payload_sha256, message_id}` plus `proxy_summary` and `response_hmac` records. Blocks with JSON-RPC error `-32600`. Pulls policy from and pushes audit to the control plane; cached policy is Ed25519-signed.
- Seven detectors (`runtime/detectors.py`): tool drift, argument regex, credential leak, rate limit (50 calls/60 s default), sequence analysis, response inspection (cloaking, invisible Unicode, SVG), vector-DB injection; plus cross-agent correlator. Sequence rules are name-substring pairs, for example `["read", "http|fetch|request|curl|post"]` -> `data_exfiltration` (`runtime/patterns.py:322`).
- `agent-bom gateway serve`: shared HTTP/SSE relay with tenant policy and rate limits. `Shield` SDK for in-process checks. Helm mutating webhook injects the proxy sidecar (opt-in label `agent-bom.io/proxy=true`).
- The "monitor" DaemonSet (`deploy/k8s/daemonset.yaml`) runs `agent-bom protect --mode http --port 8423`: a passive HTTP service (`/tool-call`, `/tool-response`, `/drift-check`, `runtime/server.py:263`) with no hostPID/hostPath; it observes nothing unless something POSTs to it. No eBPF/Falco/Tetragon (VERIFIED absence).
- Upstream 0.114: `agent-bom activity` parses `~/.claude/projects/**/*.jsonl` and `~/.codex/sessions` for tool calls, classifies `pipe_to_shell`, `destructive_command`, `secret_file_read`, writes outside project (`runtime/agent_sessions/risk.py`); changelog states the control-plane pull route rejects these providers, so it is local-only. `agent-bom-guard` Claude Code plugin adds a `PreToolUse` check for malicious/typosquatted package installs.

## 6. Integrations

- SIEM (`siem/__init__.py`): Splunk HEC, Datadog Logs, Elasticsearch/OpenSearch, RFC 5424 syslog over TCP/TLS; formats `raw` or `ocsf`. Inbound `POST /v1/ocsf/ingest`.
- OTel: `--otel-endpoint` pushes scan metrics over OTLP/HTTP; `POST /v1/traces` ingests OTLP JSON tool-call spans; Prometheus text + Pushgateway; Grafana dashboards.
- Ticketing/GRC: Jira, ServiceNow, Slack, Vanta, Drata. CI: GitHub Action with SARIF. MCP server mode ("36 security tools" per README).
- MDM: Jamf/Kandji/Intune install wrappers only. K8s: Helm chart (API, UI, gateway, HPA, PDB, NetworkPolicy, Istio, Kyverno, ExternalSecrets, backup CronJob), reference EKS installer, Terraform baseline.
- osquery / FleetDM / Fluent Bit / Fluentd: none (VERIFIED zero matches in clone excluding lockfiles; zero matches in upstream README and CHANGELOG).

## 7. Output formats

JSON, SARIF, CycloneDX 1.6, SPDX 3.0, HTML, PDF, CSV, Markdown, JUnit XML, Mermaid, SVG, GraphML, Neo4j Cypher, Graph JSON/HTML, Prometheus, badge, Attack Flow, compliance evidence ZIP. OCSF only for SIEM events.

## 8. Platforms, deps, install

Python >=3.11 wheel (`pip`/`pipx`/`uvx`), core deps click, rich, httpx, pydantic, cyclonedx-python-lib, pyyaml, jsonschema, plus transitive pins for flask/werkzeug/tornado/requests; extras for api, postgres, otel, runtime (psutil), mcp-server, cloud SDKs. Docker image on `python:3.14.3-alpine3.23`. Path tables cover macOS/Linux/Windows; shipped scheduler templates are systemd and launchd only (no Windows Scheduled Task in 0.81.1; Intune script only installs). No single static binary.

## 9. License

Apache-2.0 (`LICENSE`, `pyproject.toml`). `NOTICE`: copyright [redacted: name of an individual], and "agent-bom" is claimed as a trademark; forks need permission or clear differentiation. We may reuse path tables and ideas with attribution; do not use the name.

## 10. Project health

- VERIFIED: 181 PyPI releases in under 9 months (39 in Feb, 61 in Mar, 21 in Apr, then 4-18 per month); latest 2026-11-08. `CODEOWNERS` lists only `@msaad00`; upstream changelog mentions new `GOVERNANCE.md`/`MAINTAINERS.md`. 347 test files, 29 GitHub workflows (CodeQL, Scorecard, gitleaks, ClusterFuzzLite, release signing). Classifier "Development Status :: 4 - Beta".
- Repo home has moved at least twice (msaad00 -> agent-bom org -> koda-ai-studio); stale copies exist. Upstream says "Managed agent-bom Cloud is not shipped".
- Stars, contributors, issue counts: UNVERIFIED (not fetched).

## 11. Weaknesses and opportunities

Verified in code (0.81.1 unless noted):
1. Endpoint collector is a Python CLI needing uv/pipx and a Python runtime on every laptop, run from a per-user timer; no daemon, no command channel ("no MDM or quarantine control channel today", still in upstream doc).
2. Scheduled fleet sync passes `--introspect`, which launches every configured stdio MCP server every 30 minutes (still in upstream `deploy/endpoints/agent-bom-fleet-sync.sh`), while README line 331 says it "never executes MCP servers". Inventory must not execute discovered commands.
3. Fleet identity: 0.81.1 `sync_fleet` keys agents by `agent.name` per tenant (`api/routes/fleet.py:206`), and the name is the agent type, so two laptops with Cursor collapse into one row. Upstream 0.114 now keys by canonical identity + `source_id` (fixed), but `source_id` is still `sha256(hostname)[:12]` unless `AGENT_BOM_PUSH_SOURCE_ID` is set.
4. Discovery expands `~` for the invoking user only; no multi-user enumeration when run as root/SYSTEM (inference from `expand_path`, line 284).
5. SIEM: one HTTP POST (or one new TCP+TLS connection) per event (`send_batch` loops `send_event`, still true upstream); CLI SIEM push only fires when CVE blast radii exist (`cli/agents/_post.py:203`), so pure inventory never reaches the SIEM. Two inconsistent OCSF mappings (class 2004 in `siem/ocsf.py`, class 2001 in `output/ocsf.py`).
6. Claude Code hook audit uses the wrong schema: `for hook in data.get("hooks", [])` with `matcher == "SessionStart"` (`enforcement.py:435`, unchanged upstream) versus the documented `hooks: {Event: [{matcher, hooks:[{type, command}]}]}` (code.claude.com/docs/en/hooks.md). By code reading it cannot match a real settings file; not executed.
7. Runtime visibility limited to MCP traffic that is explicitly wrapped; built-in tools (Bash/Edit/Write/WebFetch) unseen. Upstream `activity` covers Claude Code and Codex transcripts only, offline, not fleet-streamed.
8. Skills discovery is project-relative; user-level skills/plugins/subagents directories not scanned in 0.81.1.
9. K8s "monitor" DaemonSet observes nothing by itself; `deploy/k8s/cronjob.yaml` uses a different image name (`msaad02/agent-bom:latest`) and writes to an `emptyDir`.
10. No published throughput numbers; in-memory/SQLite defaults; no detection benchmark comparable to ADR-Bench.
11. Scope sprawl (CSPM, IaC, GPU, compliance, FinOps) and docs drifting from code.

Ideas worth adopting: the per-OS path table and `agent-bom paths`/dry-run transparency; deterministic UUIDv5 IDs (add host scope); name-only credential evidence; `auth_mode` classification; `installed-not-configured` state; the MCPObservation `observed_via`/first_seen/last_seen record; CWE-aware reach; collector status values `complete|partial|unsupported|unavailable|permission_denied|skipped` (upstream) so "not collected" never reads as "clean"; signed policy cache; symlink-escape guard on config reads; bundled MCP registry with risk levels.
