> **Historical design record.** Research report on snyk/agent-scan (formerly Invariant mcp-scan), cited by `docs/COMPARISON.md`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:52 UTC on the build machine; it reads a shallow clone at 59def8c of 2026-11-09).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# snyk/agent-scan (ex Invariant mcp-scan): research report

**Executive summary**
1. At HEAD (`59def8c`, 2026-11-09, v0.6.11) agent-scan is a thin Python *discovery + upload* client: it finds 14 agents' MCP configs and skills, optionally launches/contacts MCP servers to pull tool lists, and POSTs everything to `api.snyk.io`. **Zero detection logic runs locally**; all 14 risk verdicts come back from a closed Snyk API.
2. A Snyk credential (`SNYK_TOKEN` or enterprise push key) is mandatory for `scan`; there is no offline mode, the free tier is daily-rate-limited, and full skill file contents, tool descriptions, absolute paths, hostname and usernames leave the machine.
3. Local tool pinning / rug-pull detection, the `proxy` gateway, guardrails, whitelist and `--local-only` existed in mcp-scan 0.1-0.3.x (`--opt-out` survived to at least 0.5.0) and are all **gone**; `--storage-file` is now a dead flag.
4. Runtime coverage is "Agent Guard": shell/PowerShell hook forwarders for Claude Code, Cursor, Codex and Copilot that synchronously POST every hook payload to Snyk's `agent-monitor` and fail open. Policy is server-side, tenant-gated.
5. Fleet mode exists only as "run the CLI from your MDM with a push key and results appear in Snyk Evo": no daemon, no scheduler, no local event stream, no SIEM/osquery/Fluent Bit output, and the repo is closed to contributions. Its discovery code, however, is the best public path catalogue available and worth mining.

Legend: **[V]** = verified by reading the primary source in this session; **[U]** = unverified (search snippet, inference or memory). Local paths are relative to `/home/user/snyk/agent-scan`. Legacy facts were read from `raw.githubusercontent.com/snyk/agent-scan/<tag>/...`.

---

## 0. Provenance
- Clone is shallow (1 commit): `59def8c 2026-11-09 feat(guard): e2e guard install for copilot...` [V]. `pyproject.toml`: `name = "snyk-agent-scan"`, `version = "0.6.11"`, Apache-2.0, `requires-python >=3.10` [V]. PyPI latest = 0.6.11 uploaded 2026-11-06; wheel ~220 KB; 45 releases; `mcp-scan` on PyPI is a redirect stub (0.4.3) [V].
- README still says "CLI output is experimental and subject to change", for both the v0.5.x issue-code line (2025-09-02 API, "planned for deprecation") and the v0.6 risk line (2026-07-10 API) [V `README.md:14-24`].

## 1. What it discovers

Two phases, merged per `(client name, username)` [V `src/agent_scan/pipelines.py:114-147`]:

**Phase A: static table** `src/agent_scan/well_known_clients.py` (`CandidateClient{name, client_exists_paths, mcp_config_paths, skills_dir_paths, mcp_config_globs, skills_dir_globs, max_glob_depth=6}`) [V]. `<UD>` = macOS `~/Library/Application Support`, Linux `~/.config`, Windows `~/AppData/Roaming`.

| name | exists if | MCP config files | skills dirs |
|---|---|---|---|
| `windsurf` | `~/.codeium` | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills` |
| `cursor` | `~/.cursor` | `~/.cursor/mcp.json` | `~/.cursor/skills` |
| `vscode` | `~/.vscode` (+ `<UD>/Code` on Linux/Win) | `<UD>/Code/User/settings.json`, `~/.vscode/mcp.json`, `<UD>/Code/User/mcp.json`, `~/.copilot/mcp-config.json` | `~/.copilot/skills` |
| `github copilot` | `~/.copilot` | `~/.copilot/mcp-config.json` | `~/.copilot/skills` |
| `claude desktop` | `<UD>/Claude` | `<UD>/Claude/claude_desktop_config.json` | none |
| `claude code` | `~/.claude` | `~/.claude.json`, glob `~/.claude/plugins/cache/**/.mcp.json` | `~/.claude/skills`, glob `~/.claude/plugins/cache/**/skills` |
| `gemini cli` | `~/.gemini` | `~/.gemini/settings.json` | `~/.gemini/skills` |
| `openclaw` | `~/.clawdbot`, `~/.openclaw` | none | `~/.clawdbot/skills`, `~/.openclaw/skills`, `~/.openclaw/workspace/skills`, `.openclaw/skills` |
| `amp` | `~/.config/agents`, `.amp` | none | `~/.config/agents/skills`, `.amp/skills` |
| `kiro` | `~/.kiro` | `~/.kiro/settings/mcp.json` | none |
| `opencode` | `~/.config/opencode` | none | none |
| `antigravity` | `~/.gemini/antigravity` | `~/.gemini/antigravity/mcp_config.json` | none |
| `codex` (mac/Linux lists only) | `~/.codex` | none | `~/.codex/skills` |
| `amazon_q` (mac/Linux lists only) | `~/.aws/amazonq` | `~/.aws/amazonq/agents/default.json`, `agents/mcp.json`, `mcp.json` | none |

On Windows the Linux list is merged in so WSL homes (`\\wsl.localhost\<distro>\home\<user>`, fallback `\\wsl$`) are probed [V `well_known_clients.py:330-354`, `utils.py:402-444`].

**Phase B: 10 per-agent discoverer classes** (`src/agent_scan/agents/`, registry `DISCOVERERS` in `agents/__init__.py`): claude code, claude desktop, vscode, cursor, windsurf, kiro, antigravity, codex, github copilot, opencode [V]. Gemini CLI, OpenClaw, Amp and Amazon Q have **no** discoverer class, hence user scope only [V; README matrix lines 194-213 agrees]. Additional sources per class:

- **Claude Code** (`agents/claude_code.py`): `CLAUDE_CONFIG_DIR`; top-level `mcpServers` and `projects.<path>.mcpServers` in `~/.claude.json`; `<project and every ancestor>/.mcp.json`; skills `<base>/skills`, `<project+ancestors>/{.claude/skills,.agents/skills}`; plugins under `<base>/plugins/{cache,repos,synced}` walked to depth 10 for `.mcp.json`, `skills/`, `{.claude-plugin,.codex-plugin,.cursor-plugin}/plugin.json` (inline `mcpServers`, `skills[]`); `installed_plugins.json` -> `plugins.*[].installPath`; env `CLAUDE_CODE_PLUGIN_CACHE_DIR`, `CLAUDE_CODE_PLUGIN_SEED_DIR`; managed `managed-mcp.json` at `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `%ProgramW6432%\ClaudeCode\` [V lines 511-530]. Managed *skills* explicitly not scanned (ADS-365) [V line 104].
- **Claude Desktop** (`agents/claude_desktop.py`): `mcpServers` in `claude_desktop_config.json`; plugins listed in `local-agent-mode-sessions/*/*/rpm/manifest.json` (`plugins[].id`), macOS/Linux only; for Guard only, cloud connectors from `{claude-code-sessions,local-agent-mode-sessions}/*/*/local_*.json` key `remoteMcpServersConfig`, allowlisted fields `("uuid","name","url","tools","instructions")` [V].
- **VS Code family** (`agents/vscode/base.py` + subclasses): userdata dirs `Code`, `Code - Insiders`, `Cursor`, `Windsurf`, `Kiro`, `Antigravity`, `Antigravity IDE`; `User/mcp.json`; `User/settings.json` with nested or dotted `mcp.servers`; `User/profiles/<id>/{mcp.json,settings.json}`; opened workspaces from `User/workspaceStorage/<hash>/workspace.json` (`folder` / `workspace` URIs) plus ancestors; workspace files `.vscode/mcp.json`, `.cursor/mcp.json`, `.windsurf/mcp.json`, `.kiro/settings/mcp.json`, `.mcp.json`; `.devcontainer/devcontainer.json` and `.code-workspace` (VS Code only); extension trees (`~/.vscode/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, `~/.kiro/extensions`, `~/.kiro/powers/installed`, `~/.gemini/config/plugins`, `~/.gemini/extensions`, plus app-bundled `.../resources/app/extensions`); VS Code only: static JS extraction of `new vscode.McpStdioServerDefinition(...)` / `McpHttpServerDefinition(...)` gated on `contributes.mcpServerDefinitionProviders` (`agents/vscode/extension_mcp.py`) [V]. Cursor extras: `~/.cursor/skills-cursor`, `~/.cursor/plugins/{cache,local}`. Windsurf system skills: `/Library/Application Support/Windsurf/skills`, `/etc/windsurf/skills`, `C:\ProgramData\Windsurf\skills`. Kiro: inline `mcpServers` in `~/.kiro/agents/*.json`, `.kiro/agents`. Antigravity: `~/.gemini/config/mcp_config.json`, projects from `~/.gemini/config/projects/*.json` (`projectResources.resources[].folderUri`) [V]. Several Kiro/Antigravity/Windows paths are tagged `inferred - verify` in source [V].
- **Codex** (`agents/codex.py`): TOML `[mcp_servers.<name>]` in `<CODEX_HOME or ~/.codex>/config.toml`, profile overlays `*.config.toml`, system `/etc/codex/config.toml` or `%ProgramData%\OpenAI\Codex\config.toml`, projects from the `[projects]` table (`.codex/config.toml`, `.agents/skills`; `trust_level` ignored), plugins `<home>/plugins`, skills `<home>/skills`, `<home>/skills/.system`, `~/.agents/skills`, `/etc/codex/skills`. Not covered: `requirements.toml`, `/Library/Managed Preferences/com.openai.codex.plist` (`config_toml_base64`, TODO ADS-422) [V lines 67-77].
- **GitHub Copilot** (`agents/github_copilot.py`): `COPILOT_HOME`; `mcp-config.json`; projects from `permissions-config.json` (`locations`), `config.json` (`trusted_folders`/`trustedFolders`), `session-state/*/workspace.yaml` (`cwd`, `git_root`); project `.mcp.json`, `.github/mcp.json`, skills `.github/skills`, `.claude/skills`, `.agents/skills`; plugins `installed-plugins` with manifests `.plugin/plugin.json`, `plugin.json`, `.github/plugin/plugin.json`, `.claude-plugin/plugin.json` [V].
- **OpenCode** (`agents/opencode.py`): `opencode.{json,jsonc}` (`mcp` block, `type: local|remote`) in `~/.config/opencode`, `~/.opencode`, project root and `.opencode/`; managed `/Library/Application Support/opencode`, `/etc/opencode`, `%ProgramData%\opencode`; env `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `XDG_*`; projects from SQLite `~/.local/share/opencode/opencode*.db` (`project.worktree`); skills `{skills,skill}`, `skills.paths`, URL-pulled cache `~/.cache/opencode/skills/<hash>/` [V].

**Skills**: a skill = a directory containing `SKILL.md` (case-insensitive); every file is read (`skill_client.py:155-201`); `md/py/js/ts/sh` must be UTF-8, other non-UTF-8 files become `"Binary file. Hash: <sha256>"` [V]. **Not scanned** [V by grep over `src/`]: Claude subagents (`~/.claude/agents`), slash commands (`inspect_commands_dir` is dead code since 0.5.11), rules/memory files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules`, copilot-instructions), hook definitions, permission/auto-approve settings, running processes, agent binary versions.

Config parsing: JSON5 (`pyjson5`); VS Code family format union tried in order `ClaudeConfigFile{mcpServers}` -> `VSCodeConfigFile{mcp:{servers}}` -> `VSCodeMCPConfig{servers,inputs}` -> `PluginMCPConfigFile` (flat map), with `OpenCodeConfigFile` for opencode and TOML for Codex; server models `StdioServer{command,args,type,env,binary_identifier}` and `RemoteServer{url|serverUrl|httpUrl, type: sse|http, headers}` (`models/mcp.py`) [V]. A `type: "ws"` server fails validation and sinks its whole config file into `CouldNotParseMCPConfig` (TODO ADS-384) [V `models/mcp.py:88-97`].

## 2. Local vs cloud

Pipeline (`pipelines.py`, `cli.py:1163-1270`): discover -> consent -> inspect (MCP handshake) -> redact -> POST to Snyk -> render [V].

**Local only**: file discovery; JSON/TOML parsing; MCP `initialize` + `list_prompts/list_resources/list_resource_templates/list_tools` (`mcp_client.py:213-287`); macOS-only `codesign --verify --strict` + `codesign -dvvv` to derive `binary_identifier` when the chain includes "Apple Root CA" and the binary is not a code launcher (`signed_binary.py`); secret redaction with `detect-secrets` (`redact.py`). No prompt-injection, Unicode, shadowing or toxic-flow check exists in `src/` [V by grep]; the README's "local checks" claim (line 290) is not backed by code at HEAD.

**Cloud** (`verify_api.py`) [V]:
- Sync: `POST https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10`; with `SNYK_TOKEN` the path is rewritten to `/hidden/mcp-scan/cli/analysis-machine` and `Authorization: token <SNYK_TOKEN>` is sent; with a push key the header is `X-Push-Key`. Timeout 180 s, 3 retries.
- Async (push-key default when tenant enables it): `GET /hidden/agent-scan/config` (`{"async_analysis_enabled": bool}`) then gzip `POST /hidden/agent-scan/async/analysis`, expects `202`, **no results returned locally** unless `--show-analysis-results`/`--ci`.
- Other headers: `X-Environment`, `X-Push: skip`, `X-Scan-User-Id`.
- No token, no push key and no Snyk CLI proxy (`SNYK_CLI_USE=true`) -> `SnykTokenError`, exit 1 (lines 584-589). HTTP 429 -> "Daily usage limit reached for the public version of Agent-Scan" (line 616). README line 421: large-scale use of the standard API "is considered abuse and will result in your account being blocked".

**Payload** (`models/api/v20260710.py`):
```
ScanRequest{ scan_path_requests[]{ client, path(home-relative),
    servers[]{ name, config_path(absolute), server{command,args,env|url,headers,type,binary_identifier},
               signature{metadata, prompts[], resources[], resource_templates[], tools[]}, error },
    skills[]{ name, installation_path(absolute), files[]{path, content}, error }, error },
  scan_user_info{ hostname, username[], identifier, ip_address:null, anonymous_identifier:null },
  scan_metadata{ cli_version } }
```
Redaction before send: all env values and header values -> `**REDACTED**`, URL query values redacted, args and skill text run through detect-secrets (`**REDACTED_SECRET_<PLUGIN>**`), tracebacks dropped [V `redact.py:748-773`, `v20260710.py:19-46`]. Still sent: full tool descriptions and schemas, **full text of every skill file**, absolute config/skill paths, hostname, OS usernames [V].

**Opt-outs**: `--no-skills`; decline per-server consent; `inspect` (no upload, no verdicts). `--local-only` (last seen in the v0.2.1 README) and `--opt-out` (still in the v0.5.0 README) no longer exist in `cli.py` [V].

**Side effects of scanning**: attended scans launch every stdio MCP server after a y/N prompt; unattended push-key scans skip stdio but **auto-connect to every remote MCP URL using the user's configured headers** (`mcp_client.py:150-168`, matrix `cli.py:751-787`). SSRF guard blocks only `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200`; redirects off; DNS-rebinding window acknowledged [V].

## 3. Codes

**v0.6 risks** (`risk_indexes` keys; score 0-1000, levels 100 low / 300 medium / 600 high / 1000 critical) [V `docs/risks.md`, `v20260710.py:143-206`]
- MCP server: `prompt_injection_tool_desc`, `untrusted_content`, `private_data`, `destructive_capabilities`.
- Skill: `prompt_injection_skill_instructions`, `suspicious_download_url` (+`malicious_urls`), `malicious_code`, `insecure_credential_handling`, `secret_detection`, `direct_money_access`, `third_party_content_exposure`, `unverifiable_dependencies` (+`unverifiable_urls`), `modifying_system_services`, `missing_skill_md`.

**v0.5.x issue codes** [V `docs/issue-codes.md`]: E001 prompt injection in tool description (critical); E002 cross-server tool reference / shadowing (high); W015/W016 untrusted content (medium/low); W017 sensitive data exposure; W018 workspace data exposure; W019 destructive capabilities; W020 local destructive; E004 prompt injection in skill; E005 suspicious download URL; E006 malicious code; W007 insecure credential handling; W008 hardcoded secrets; W009 direct financial execution; W011 untrusted third-party content; W012 unverifiable external dependency; W013 system service modification; W014 missing SKILL.md; W021 hidden Unicode (Cf/Cc, decodes tag chars U+E0000-E007F; high when >= 3 types or a decoded message).

**Older codes, now removed** [V docs at tag v0.4.3]: E003 tool description hijacks agent; W001 suspicious words; W002 > 100 entities; W003 could not identify server (earlier: "entity has changed"); W004 server not in registry; W005 tool not in registry (rug-pull hint); W006 could not run server; TF001 data-leak toxic flow; TF002 destructive toxic flow; X002 whitelisted.

**Operational** [V `models/errors.py:23-33`]: X001 `server_startup`, X002 `skill_scan_error`, X003 `file_not_found` (not a failure), X004 `unknown_config` (not a failure), X005 `parse_error`, X006 `server_http_error`, X007 `analysis_error`, X008 uncategorized, X009 `user_declined`.

v0.6 therefore dropped shadowing (E002), hidden Unicode (W021) and the composite toxic-flow verdicts from the public risk list; CHANGELOG 0.6.4 also "Remove[s] the Dangerous Words risk" [V].

## 4. Runtime: Agent Guard (hooks); proxy is gone

`snyk-agent-scan guard install {claude,cursor,codex,github-copilot,all}` (`guard.py`, 2069 lines) [V]:
- Writes hook entries into user config (`~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.codex/hooks.json`, `~/.copilot/hooks/snyk-agent-guard.json`) or `--managed` config: macOS `/Library/Application Support/ClaudeCode/managed-settings.json`, `/Library/Application Support/Cursor/hooks.json`, `/etc/codex/requirements.toml`, `/etc/github-copilot/policy.d/snyk-agent-guard.json`; Linux `/etc/claude-code/managed-settings.json`, `/etc/cursor/hooks.json`, same Codex/Copilot; Windows `C:/Program Files/ClaudeCode/managed-settings.json`, `C:/ProgramData/Cursor/hooks.json`, `C:/ProgramData/OpenAI/Codex/requirements.toml`, `C:/ProgramData/GitHub/Copilot/policy.d/snyk-agent-guard.json` (lines 69-92).
- Events hooked: Claude `PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, Stop, SessionStart, SessionEnd, SubagentStart, SubagentStop`; Codex `PreToolUse, PermissionRequest, PostToolUse, UserPromptSubmit, Stop, SessionStart, SubagentStart`; Cursor 17 events (`beforeSubmitPrompt, beforeShellExecution, afterShellExecution, beforeMCPExecution, afterMCPExecution, beforeReadFile, afterFileEdit, afterAgentResponse, afterAgentThought, stop, preToolUse, postToolUse, postToolUseFailure, sessionStart, sessionEnd, subagentStart, subagentStop`); Copilot 10 (`SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse, PostToolUseFailure, PreCompact, SubagentStart, SubagentStop, Stop`) (lines 94-148).
- Hook command: `PUSH_KEY='<key>' REMOTE_HOOKS_BASE_URL=... TENANT_ID=... MACHINE_ID=... bash <hooks>/snyk-agent-guard.sh --client <c>`; the push key sits in plaintext in the agent config (lines 1803-1819).
- Forwarder (`hooks/snyk-agent-guard.sh`, 251 lines; `.ps1`, 204 lines): reads the entire hook JSON from stdin, sends `base64:<b64>` to `POST {base}/hidden/agent-monitor/hooks/{claude-code|cursor|codex|github-copilot}?version=2025-11-11` with headers `X-Client-Id: <push key>`, `X-User: {"hostname","username","identifier","cli_version"}`, optional `X-Agent-Surface` (from `AI_AGENT`/`COPILOT_CLI`); prints the response body as the hook decision; `--max-time 60`; on timeout/transport/HTTP>=400 **fails open** (exit 0, `{"systemMessage": ...}` only for Claude/Codex). Needs bash+curl+base64, or PowerShell 5.1.
- Session-start discovery hook (via `snyk-agent-guard-discover.sh`, only when `AGENT_SCAN_COMMAND` resolves) runs `<agent-scan> guard discover --client <c> --scope servers`, async on Claude/Codex, sending `sessionStartServerDiscovery` with the same server inventory as `scan` plus `claudeLoggedMcpServers`.
- Install emits `hooksConfigured` with `first_install`, `push_key_changed`, hook diff (`added/modified/removed`) and script sha256 (`current_checksum`/`new_checksum`) for tamper detection; preserves foreign hooks; refuses if `GET /hidden/tenants/{id}/agent-monitor/guard-enabled` says the tenant is not entitled (`pushkeys.py`).
- Hook payloads include prompts and tool inputs/outputs, so the README statement "does not store or log ... contents and results of your MCP tool calls" can only describe `scan`, not Guard [V mechanism; server-side handling U].

No proxy/gateway at HEAD. `mcp-scan proxy` (Invariant Gateway injected into MCP configs, `~/.mcp-scan/guardrails_config.yml`) existed 0.2.1 through 0.3.x and is absent from the v0.4.3 README onward [V READMEs at tags]. There is no long-running process, file watcher or timer anywhere in `src/` [V grep].

## 5. Fleet / MDM / central reporting
- "Background Mode (MDM) ... To set this up, please contact us" (`README.md:262`) is the whole public story. The mechanism is the same CLI with `--push-key KEY --machine-id ID [--scan-all-users] [--config-file agent-scan.yaml]`, scheduled by the customer's MDM [V docs/cli-reference.md; scheduling itself U]. `guard.py` refers to a separate, unpublished "ADS Installer" that is expected to supply `MACHINE_ID` and `AGENT_SCAN_COMMAND` (lines 238-245, 594-598) [V reference; installer U].
- `--scan-all-users`: POSIX `pwd.getpwall()` with uid >= 500 (mac) / 1000 (Linux); Windows shells out to `powershell Get-CimInstance Win32_UserProfile` (10 s cap) plus WSL (`utils.py:277-363`) [V].
- Central reporting = Snyk Evo only. `--control-server URL` is documented as an "upload destination", but at HEAD `ControlServer.url` is never dereferenced: the code only extracts `x-client-id` and the identifier from the block, and the single outbound POST goes to the analysis URL [V grep of `cli.py`, `pipelines.py`, `verify_api.py`]. A self-hosted collector therefore receives nothing.
- Push keys: `POST/DELETE {base}/hidden/tenants/{tenant}/mcp-scan/push-key?version=2025-08-28` (`pushkeys.py`) [V].
- Snyk CLI wrapper `snyk agent-scan --experimental` (Go extension, separate repo) downloads a pinned binary [V docs; extension code not read].

## 6. Output formats
- Rich terminal text, or `--json` (single JSON document on stdout). No SARIF, NDJSON, syslog, OTLP, CSV [V `cli.py:1391-1430`].
- `scan --json` (v0.6): `{"scan_path_responses":[{client, path, server_risks:[{name, entities:[{name,type: tool|prompt|resource|resource_template}], risk_indexes:{<risk>:{score, evidence, affected_tools:[idx]}}, error}], skill_risks:[{name, files:[{name,type: instruction|script|asset}], risk_indexes:{<risk>:{score, evidence, locations:[{start:{path,line,offset},end}], malicious_urls|unverifiable_urls}}, error}], error}]}`; nulls omitted.
- `inspect --json`: map keyed by absolute path -> `InspectedPath{client, path, servers[{name, config_path, server, signature, error}], skills[{name, installation_path, files[{path,content}], error}], error}`.
- `ScanError{message, exception, traceback, is_failure, category, server_output}`.
- Exit codes: 0 clean, 1 risks/failures (only with `--ci`, which also requires `--dangerously-run-mcp-servers`), 2 usage.
- No stable IDs, timestamps, host identity or event type in the output; findings reference entities by array index.

## 7. Platforms, runtime, install
- `uvx snyk-agent-scan@latest` (needs uv + Python >= 3.10) or PyInstaller `--onefile` binaries: Linux x86_64/arm64 (Ubuntu 22.04, Debian 12, AL2023, Fedora 40), Windows x86_64 (10), macOS arm64/x86_64 (15) [V README 132-136, Makefile]. No Windows arm64, no container image, no Kubernetes story.
- 14 direct deps (`rich, pyjson5, pydantic, lark, psutil, pyyaml, aiohttp, rapidfuzz, truststore, mcp[cli]==1.30.0, regex, detect-secrets, certifi, tomli`), 76 packages in `uv.lock`; 9 transitive CVE overrides pinned in `[tool.uv]` [V].
- Releases: GPG-signed `sha256sums.txt.asc`, SBOM, macOS codesign, Authenticode on `.ps1` hooks [V README/CHANGELOG 0.6.11].

## 8. License, telemetry, governance
- Code Apache-2.0 (`LICENSE`); use of the service is under `TERMS.md` (content licence grant to the company, feedback assignment, 100 USD liability cap) [V].
- No separate telemetry channel, but the product *is* the upload: every scan sends inventory + hostname + usernames. Legacy mcp-scan assigned "a unique, persistent, and anonymous ID" with `--opt-out`; both gone, replaced by a mandatory "non-anonymous" `--machine-id` for fleet use [V].
- `CONTRIBUTING.md`: "agent-scan is closed to contributions" [V].

## 9. Tool pinning / rug-pull detection
- **HEAD: none.** `--storage-file` (default `~/.mcp-scan`) is parsed but never read (`cli.py:469-475`; no other reference in `src/`) [V]. `demoserver/server.py` still ships a rug-pull demo the client can no longer detect locally [V].
- **Legacy mechanism** (tag v0.3.20, `src/mcp_scan/Storage.py`, `models.py`) [V]: `hash_entity = md5(entity.description or "no description available")`; stored in `~/.mcp-scan/scanned_entities.json` keyed `"<server_name>.<entity_type>.<entity_name>"` -> `ScannedEntity{hash, type, timestamp, description}`; mismatch emitted `W003 "Entity has changed"` with the previous description; `whitelist.json` mapped `"<type>.<name>" -> hash`, matched by hash value (`X002`), managed by `mcp-scan whitelist TYPE NAME HASH`.
- Flaws in that design: MD5; description only (a changed `inputSchema`, parameter descriptions, annotations, tool name, server command or binary went unnoticed); per-user local state with no fleet baseline; requires launching the server.

## 10. Weaknesses we can beat
All [V] unless marked.
1. No local detection, no offline or air-gapped mode; verdict logic is closed and unversioned.
2. Mandatory Snyk account; daily limit on free tier; ToS forbids scale use of the public API.
3. Uploads full skill contents, tool schemas, absolute paths, hostname, usernames.
4. No pinning/drift detection, no baseline, no "what changed since last scan".
5. No continuous monitoring: one-shot CLI, no daemon, watcher or scheduler; cadence is someone else's problem.
6. No runtime/process visibility, no agent version inventory, no permissions/auto-approve, hooks, rules-file or subagent auditing.
7. Results only reach Snyk Evo; no SIEM stream; `--control-server` URL is ignored; JSON is an index-referenced blob without timestamps or stable IDs.
8. Guard: cloud round trip (up to 60 s) on every hook event, fail-open, 4 agents, tenant-gated, plaintext push key in user-writable config, forwards whole payloads.
9. Scanning executes untrusted stdio servers (attended) and silently calls remote MCP servers with user credentials (fleet).
10. Python/PyInstaller footprint; Windows relies on PowerShell/CIM subprocess; binary identity is macOS-only; no containers/Kubernetes.
11. Coverage holes admitted in source: Gemini CLI project/extension scope, Amp project scope, Windows Claude Desktop plugins, Codex MDM plist, `ws` transport sinking a whole file, env-relocated homes of other users.
12. Experimental, twice-rewritten output contract (issue codes -> risks) within a year; closed to contributions.

## 11. Ideas worth adopting (with refs)
- **Path catalogue and scope model** (system / user / project / extension-plugin): `well_known_clients.py`, `agents/*.py`, README matrix 194-213.
- **Project enumeration from each agent's own state** + ancestor walk: `claude_code.py:151-159`, `vscode/base.py` workspaceStorage, `codex.py` `[projects]`, `github_copilot.py` session-state, `opencode.py` SQLite, `antigravity.py` projects registry; `base.py:708-737`.
- **Hardened walkers**: 20 MiB config cap, depth cap 10, symlink-cycle detection by `(st_dev, st_ino)`, plugin path-escape rejection (`base.py:66-74, 226-239`; `skill_client.py:126-152`), own-home gating of env overrides (`base.py:306-339`), per-source exception isolation.
- **Format-union parser** with JSON5 tolerance and transport normalisation (`local`->stdio, `streamable-http`->http): `models/mcp.py`.
- **Server identity**: code-launcher regex list (`signed_binary.py:16-27`) + signer identity; extend to Authenticode and ELF hashes.
- **VS Code extension static extraction**: `agents/vscode/extension_mcp.py`.
- **Toxic flow analysis**: per-tool labels `untrusted_content`, `private_data`, `is_public_sink`, `destructive` (`ScalarToolLabels`, legacy `models.py`), composed across all servers of one agent into TF001 (untrusted + private + public sink) and TF002 (untrusted + destructive); legacy `docs/issue-codes.md@v0.4.3` lines 137-172.
- **Hidden-Unicode rule** W021 (`docs/issue-codes.md:169-177`) and cross-server shadowing E002: cheap, deterministic, local.
- **Operational vs security separation**: X-codes with `is_failure` (`models/errors.py`).
- **Redaction policy**: env/header values always, URL query values, allowlist-not-passthrough for connector fields (`redact.py:748-773`, `claude_desktop.py:28-29`).
- **Consent matrix / never start stdio servers unattended** (`cli.py:751-787`) and SSRF blocklist (`mcp_client.py:44-47`).
- **Hook installer mechanics**: managed paths, foreign-hook preservation, event diff, script checksum, Copilot `policy.d` permission hardening, per-client fail-open semantics (`guard.py`, `hooks/snyk-agent-guard.sh:50-75`), surface detection via `AI_AGENT`.
- **Canary specs** that drive the real agent binary and assert the scanner still finds what it wrote: `tests/canary_specs/canary_test_supported_agents/`.

## 12. Not verified
- Snyk docs/marketing on Evo, Agent Guard blocking behaviour and MDM packaging (docs.snyk.io unreachable from this session; search snippets only) [U].
- Server-side analysis method (LLM vs rules), retention, and the meaning of `X-Push: skip` [U].
- Release binary sizes and start-up time [U].

Sources: local clone at `/home/user/snyk/agent-scan`; https://raw.githubusercontent.com/snyk/agent-scan/v0.3.20/src/mcp_scan/Storage.py ; https://raw.githubusercontent.com/snyk/agent-scan/v0.3.20/src/mcp_scan/models.py ; https://raw.githubusercontent.com/snyk/agent-scan/v0.4.3/docs/issue-codes.md ; READMEs at tags v0.2.1, v0.3.20, v0.3.39, v0.4.3, v0.5.0 ; https://pypi.org/pypi/snyk-agent-scan/json ; https://pypi.org/pypi/mcp-scan/json
