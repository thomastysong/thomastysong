> **Historical design record.** Research report: hook, transcript, OpenTelemetry and process surfaces of Claude Code, Codex, Copilot, Gemini CLI and Cursor.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:55 UTC on the build machine; its title says "as of 2026-11-11").
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Agent telemetry and control surfaces (Claude Code, Codex, Cursor, Copilot, Gemini CLI) as of 2026-11-11

## Executive summary

1. Four of five agents (Claude Code, Codex, Copilot CLI/VS Code "Copilot harness", Gemini CLI) now ship a stdin-JSON command-hook system with an admin-managed tier at fixed OS paths; Claude, Codex and Copilot share almost the same wire contract (`hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`, exit 2 = block). Cursor has hooks too, but its vendor docs were unreachable here, so Cursor facts are code-level cross-checks or UNVERIFIED.
2. Managed hooks are the only tamper-resistant real-time surface: Claude (`allowManagedHooksOnly`, managed hooks survive `disableAllHooks` and `--safe-mode`), Copilot (policy.d hooks ignore `disableAllHooks` and folder trust), Codex (`requirements.toml` `[hooks]` + `allow_managed_hooks_only`), Gemini (system `settings.json`, weaker). All are delivered by file/plist/registry, which FleetDM can push and osquery can audit.
3. Hooks fail open by default almost everywhere (timeouts especially), and each agent has a hook-free path (`claude --bare`, Codex `--dangerously-bypass-hook-trust` and untrusted projects, Copilot timeouts, Gemini `hooksConfig.enabled=false`). Detection must therefore triangulate three surfaces: hooks, transcript tail, native OTel.
4. Native OTel is uneven: Claude = logs/events + metrics (+ beta traces) with rich security events; Codex = logs + traces + metrics via `[otel]` TOML; Gemini = logs/metrics/traces, prompts logged by default; Copilot = traces + metrics only (GenAI semconv), with a JSON-lines file exporter; Cursor = none found.
5. uber/ADR Sensor is transcript-only batch parsing (14-day lookback, 1,000-char truncation, hard-coded `~/.claude/projects`); it uses no hooks, no OTel ingest and no config/posture state, which is the gap to beat.

Verification flags: VERIFIED = primary source read this session (path/URL given). UNVERIFIED = search snippet, third-party code, or memory. `developers.openai.com` and `cursor.com` did not resolve from this sandbox.

Sources read: `https://code.claude.com/docs/en/{hooks,settings,managed-settings,monitoring-usage,mcp,permission-modes,sandboxing,cli-reference,env-vars,claude-directory,sessions,headless,setup,network-config}.md`; `raw.githubusercontent.com/openai/codex/main/codex-rs/{core/config.schema.json,hooks/schema/generated/*.json,hooks/src/engine/*.rs,hooks/src/events/pre_tool_use.rs,config/src/loader/{README.md,mod.rs,macos.rs},config/src/config_requirements.rs,rollout/src/*.rs,otel/README.md,otel/src/events/session_telemetry.rs,utils/cli/src/shared_options.rs,core/src/{spawn,exec_env}.rs,login/src/auth/default_client.rs}` and `docs/config.md`; `raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/{hooks/reference.md,hooks/index.md,reference/configuration.md,cli/telemetry.md,cli/session-management.md,cli/skills.md,reference/policy-engine.md,tools/shell.md,cli/headless.md}`; `raw.githubusercontent.com/github/docs/main/content/copilot/reference/{hooks-reference.md,copilot-cli-reference/cli-config-dir-reference.md,copilot-cli-reference/cli-command-reference.md,enterprise-administrators/opentelemetry-reference.md}`; `raw.githubusercontent.com/microsoft/vscode-docs/main/docs/{agent-customization/hooks.md,enterprise/manage-ai-settings.md,enterprise/policies.md,agents/guides/monitoring-agents.md}`; local `/home/user/uber/adr/Sensor/adr_sensor/parsers/*.py`, `/home/user/snyk/agent-scan/src/agent_scan/guard.py`.

---

## 1. Cross-agent matrix

| | Claude Code | Codex CLI | Copilot CLI / VS Code Copilot harness | Gemini CLI | Cursor |
|---|---|---|---|---|---|
| Hook events | 33 | 14 | 14 | 11 | ~17-20 (UNVERIFIED) |
| Hook handler types | command, http, mcp_tool, prompt, agent | command, mcp_tool (prompt/agent in schema) | command, http, prompt | command only | command, prompt (UNVERIFIED) |
| Default hook timeout | 600 s (30 s UserPromptSubmit) | 600 s | 30 s | 60,000 ms | unknown |
| Block signal | exit 2 or JSON | exit 2 or JSON | exit 2 (preToolUse/permissionRequest) or JSON | exit 2 or `decision:"deny"` | exit 2 or `permission:"deny"` (UNVERIFIED) |
| Hook timeout on pre-tool | fail-open unless `onFailure:"block"` (v2.1.295+) | fail-open (inferred) | always fail-open, even policy hooks | warning, continues | fail-open unless `failClosed:true` (UNVERIFIED) |
| Managed hook location | managed-settings (file, plist, HKLM, server) | `requirements.toml` `[hooks]` | `policy.d/*.json`, HKLM | system `settings.json` | enterprise `hooks.json` |
| Users can disable managed hooks | No | No (with `allow_managed_hooks_only`) | No | Partly (env path override) | unknown |
| `permission_mode` in hook payload | Yes | Yes (Claude enum) | No | No | No (UNVERIFIED) |
| `transcript_path` in payload | Yes | Yes (nullable) | No | Yes | UNVERIFIED |
| Transcript | JSONL | JSONL (+ `.jsonl.zst`) | JSONL | JSON + JSONL journal | SQLite `state.vscdb` |
| Native OTel signals | logs, metrics, traces (beta) | logs, traces, metrics | traces, metrics (file exporter) | logs, metrics, traces | none found |

All Claude/Codex/Copilot/Gemini cells VERIFIED unless marked.

---

## 2. Claude Code (VERIFIED, code.claude.com docs)

**Hooks.** Events: `SessionStart, Setup, InstructionsLoaded, UserPromptSubmit, UserPromptExpansion, MessageDisplay, PreToolUse, PermissionRequest, PermissionDenied, PostToolUse, PostToolUseFailure, PostToolBatch, Notification, SubagentStart, SubagentStop, TaskCreated, TaskCompleted, Stop, StopFailure, TeammateIdle, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreCompact, PostCompact, PreModelSwitch, PostModelSwitch, Elicitation, ElicitationResult, SessionEnd`.

Common stdin fields: `session_id, prompt_id, transcript_path, cwd, scratchpad_dir, permission_mode ("default"|"plan"|"acceptEdits"|"auto"|"dontAsk"|"bypassPermissions"), effort.level, hook_event_name`, plus `agent_id, agent_type` inside subagents. Example (verbatim):

```json
{"session_id":"abc123","prompt_id":"550e8400-...","transcript_path":"/home/user/.claude/projects/.../transcript.jsonl",
 "cwd":"/home/user/my-project","permission_mode":"default","hook_event_name":"PreToolUse",
 "tool_name":"Bash","tool_input":{"command":"npm test","description":"Run test suite","timeout":120000,"run_in_background":false},
 "tool_use_id":"toolu_01ABC123..."}
```

Per-event extras: PostToolUse adds `tool_response, duration_ms`; PostToolUseFailure `error, is_interrupt, duration_ms`; MCP tools add `mcp_server:{name,source}` (v2.1.274+; "base trust decisions on `source`"); UserPromptSubmit `prompt`; SessionStart `source (startup|resume|clear|compact|fork), model`; SessionEnd `reason`; SubagentStop `agent_transcript_path, last_assistant_message`; Stop `last_assistant_message, background_tasks[], session_crons[]`; ConfigChange `source (user_settings|project_settings|local_settings|policy_settings|skills), file_path`; InstructionsLoaded `file_path, memory_type, load_reason`; PermissionDenied `reason`; Elicitation `mcp_server_name, message, requested_schema`.

Control: exit 0 = success (stdout JSON applied), exit 2 = block (stderr is the reason), other = non-blocking error. JSON: `continue, stopReason, systemMessage`, top-level `decision:"block"`, and for PreToolUse `hookSpecificOutput.{permissionDecision: allow|deny|ask|defer, permissionDecisionReason, updatedInput, additionalContext}`; precedence `deny > defer > ask > allow`. PostToolUse can rewrite with `updatedToolOutput`. Matcher: exact name, `|`/`,` list, or unanchored JS regex (`mcp__server__.*`); handler-level `if: "Bash(git *)"`. Timeouts: 600 s for command/http/mcp_tool, 30 s on UserPromptSubmit, SessionEnd shares a 1.5 s budget. A timed-out PreToolUse hook does not block unless `onFailure:"block"`. `async:true` runs in background (ideal for pure telemetry).

Config locations and precedence (highest first): managed, `--settings`, `.claude/settings.local.json`, `.claude/settings.json`, `~/.claude/settings.json`; also plugin `hooks/hooks.json`, skill/agent frontmatter. Hooks merge across levels. Managed tier, ranked: (1) server-managed (claude.ai admin console), (2) MDM: macOS managed preferences domain `com.anthropic.claudecode`; Windows `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings` (REG_SZ JSON), (3) files `managed-settings.json` + `managed-settings.d/*.json` + `managed-mcp.json` in `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\`, (4) `HKCU\SOFTWARE\Policies\ClaudeCode` (user-writable, lowest). Default `managedSourcesBehavior:"first-wins"`: only the highest source with a policy key applies, so a server-managed policy silently shadows a Fleet-deployed file unless `"merge"` is set. `allowManagedHooksOnly:true` blocks user/project/plugin hooks; user `disableAllHooks` cannot disable managed hooks; `--safe-mode` still runs policy hooks. HTTP hooks are gated by `allowedHttpHookUrls`. Interactive sessions hold all hooks until workspace trust; `-p`/SDK sessions treat the folder as trusted.

**Transcripts.** `~/.claude/projects/<cwd with non-alphanumerics replaced by ->/<session-id>.jsonl`; subagents at `<session>/subagents/agent-<agentId>.jsonl`; large outputs spill to `<session>/tool-results/`; `~/.claude/history.jsonl` holds typed prompts. Relocated by `CLAUDE_CONFIG_DIR`; retention `cleanupPeriodDays` (default 30); writes suppressed by `CLAUDE_CODE_SKIP_PROMPT_HISTORY` or `--no-session-persistence`. Docs state the entry format is internal and changes between versions. Line fields seen in ADR's parser: `type, uuid, sessionId, agentId, cwd, timestamp, message.{model,content[]}`, content blocks `text|tool_use|tool_result|thinking`, `toolUseResult`, and a `permission-mode` record type.

**OTel.** `CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_LOGS_EXPORTER=otlp`, `OTEL_METRICS_EXPORTER`, `OTEL_EXPORTER_OTLP_{PROTOCOL,ENDPOINT,HEADERS}`. Content gates (all default off): `OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_ASSISTANT_RESPONSES`, `OTEL_LOG_TOOL_DETAILS` (Bash commands, MCP server/tool names, `tool_input`), `OTEL_LOG_TOOL_CONTENT`, `OTEL_LOG_RAW_API_BODIES`, `OTEL_LOG_MANAGED_SETTINGS`. Events: `claude_code.user_prompt, assistant_response, tool_result, tool_decision, api_request, api_error, api_refusal, permission_mode_changed (from_mode,to_mode,trigger), auth, mcp_server_connection, plugin_installed, plugin_loaded, skill_activated, hook_registered, hook_execution_start/complete, subagent_completed, compaction, retention_sweep, managed_settings_resolved`. `tool_result` attributes: `tool_name, tool_use_id, success, duration_ms, decision_source, mcp_server_scope, tool_parameters{bash_command,full_command,dangerouslyDisableSandbox,mcp_server_name,mcp_tool_name}`. Standard attributes: `session.id, user.email, user.account_uuid, organization.id, app.entrypoint (cli|sdk-cli|sdk-ts|sdk-py|claude-vscode|claude-desktop|remote), terminal.type`; events add `prompt.id, agent_id, parent_agent_id`. `tool_use_id` joins OTel to hooks. Project settings cannot set OTEL variables; managed settings pin the destination; `OTEL_*` is not passed to subprocesses.

**MCP and extensions.** User and local scope in `~/.claude.json` (`mcpServers`, `projects.<path>.mcpServers`); project `.mcp.json`; managed `managed-mcp.json`, `managedMcpServers`, `allowedMcpServers`/`deniedMcpServers`, `allowManagedMcpServersOnly`. Under `.claude/` and `~/.claude/`: `skills/<name>/SKILL.md, commands/*.md, agents/*.md, rules/*.md, workflows/*.js, output-styles/*.md`; `CLAUDE.md`. Side-load flags `--plugin-dir, --plugin-url, --agents, --mcp-config` (blockable with `disableSideloadFlags`).

**Dangerous state.** argv: `--dangerously-skip-permissions`, `--permission-mode bypassPermissions|auto|dontAsk|acceptEdits`, `--allow-dangerously-skip-permissions`, `--bare` (skips hook discovery; sets `CLAUDE_CODE_SIMPLE`), `--settings '{"disableAllHooks":true}'`, `--dangerously-load-development-channels`. Settings: `permissions.defaultMode`, `skipDangerousModePermissionPrompt:true` in `~/.claude/settings.json` (written when the user accepts the bypass warning), `disableAllHooks`, `sandbox.enabled:false`, `sandbox.allowUnsandboxedCommands`. Runtime: hook `permission_mode`, OTel `permission_mode_changed` and `tool_decision.permission_mode`, Bash `tool_input.dangerouslyDisableSandbox`. Lock: `permissions.disableBypassPermissionsMode:"disable"`.

**Process identity.** Native launcher `~/.local/bin/claude` symlinked into `~/.local/share/claude/versions/`; Homebrew cask `claude-code`; WinGet `Anthropic.ClaudeCode`; apt/dnf/apk package `claude-code`. Children get `CLAUDECODE=1`, `CLAUDE_CODE_CHILD_SESSION=1` (not MCP servers), `CLAUDE_CODE_SESSION_ID`, `CLAUDE_PROJECT_DIR`; cloud sets `CLAUDE_CODE_REMOTE=true`. Hosts: `api.anthropic.com, claude.ai, platform.claude.com, mcp-proxy.anthropic.com, downloads.claude.ai`. npm package name `@anthropic-ai/claude-code`: UNVERIFIED.

**Headless.** `claude -p`, Agent SDK (TS/Python) and Actions run the same hooks and write transcripts unless `--bare`/`--no-session-persistence`. Agent SDK sessions load managed settings even when `settingSources` excludes user/project.

---

## 3. OpenAI Codex CLI (VERIFIED from openai/codex `main` source; vendor docs site unreachable)

**Hooks.** `HooksToml` keys (`codex-rs/core/config.schema.json`): `PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, SessionStart, SessionEnd, UserPromptSubmit, Stop, SubagentStart, SubagentStop, Interrupt, PreModelRequest, PostModelRequest`, plus `state.<key>.{enabled,trusted_hash,trusted_content_hash}`. Handler: `{type:"command", command, commandWindows, timeout, async, statusMessage, additionalContextLimit}` or `{type:"mcp_tool", server, tool, input}`. PreToolUse stdin (required fields, `hooks/schema/generated/pre-tool-use.command.input.schema.json`): `cwd, hook_event_name, model, permission_mode (default|acceptEdits|plan|dontAsk|bypassPermissions), session_id, tool_input, tool_name, tool_use_id, transcript_path (nullable), turn_id`, optional `agent_id, agent_type`. PostToolUse adds `tool_response`; UserPromptSubmit `prompt`; Stop `last_assistant_message, stop_hook_active`; SessionStart `source (startup|resume|clear|compact|fork)`. Output wire matches Claude (`continue, stopReason, systemMessage, decision, reason, hookSpecificOutput.permissionDecision/updatedInput/additionalContext`), but `permissionDecision:"ask"`, bare `"allow"` and legacy `decision:"approve"` are unsupported and fail open (`pre_tool_use.rs` tests lines 463-629). Exit 2 blocks. Default timeout 600 s (`discovery.rs:968`). Plugin hooks get `PLUGIN_ROOT` and `CLAUDE_PLUGIN_ROOT`.

Locations: `[hooks]` in any config layer and `hooks.json` beside each `config.toml` (`discovery.rs:390-394`): `$CODEX_HOME` (default `~/.codex`), `<repo>/.codex/` (ignored when untrusted), system. Managed hooks come from `requirements.toml` `[hooks]`; `allow_managed_hooks_only = true` is honoured only in `requirements.toml` (`docs/config.md`). Non-managed hooks need persisted trust unless `--dangerously-bypass-hook-trust`.

Config layers (`config/src/loader/mod.rs:81-135`, `macos.rs:27-29`): system `/etc/codex/config.toml` or `%ProgramData%\OpenAI\Codex\config.toml`; user `$CODEX_HOME/config.toml`; project `.codex/config.toml`; requirements `/etc/codex/requirements.toml` or `%ProgramData%\OpenAI\Codex\requirements.toml`; macOS MDM domain `com.openai.codex` keys `config_toml_base64`, `requirements_toml_base64`; legacy `/etc/codex/managed_config.toml`; cloud "EnterpriseManaged" bundles. Requirements keys include `allowed_approval_policies, allowed_sandbox_modes, allow_managed_hooks_only, hooks, mcp_servers, plugins, otel, rules, network`.

**Transcripts.** `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<timestamp>-<thread-uuid>.jsonl`, `archived_sessions/`; a background worker zstd-compresses rollouts to `.jsonl.zst` (`MIN_ROLLOUT_AGE` 7 days, `rollout/src/compression.rs`). Line `type`: `session_meta` (payload `id, parent_thread_id, forked_from_id, cwd, originator, cli_version, source, agent_role, agent_path`), `turn_context` (`turn_id, cwd, approval_policy, permission_profile, model`), `response_item` (`message, reasoning, function_call, function_call_output, custom_tool_call, local_shell_call`), `event_msg`. Also `$CODEX_HOME/history.jsonl` and `state_*.sqlite` catalogs.

**OTel.** `[otel]`: `exporter`/`trace_exporter`/`metrics_exporter` = `"none"|"statsig"|{otlp-http={endpoint,protocol,headers,tls}}|{otlp-grpc=...}`; `log_user_prompt`, `log_agent_responses`, `environment`. Events: `codex.conversation_starts` (carries `approval_policy`, `sandbox_policy`, `mcp_servers`), `codex.user_prompt`, `codex.tool_decision` (`tool_name, call_id, decision, source`), `codex.sandbox_outcome`, `codex.api_request`, `codex.sse_event`, `codex.skill_invocation`, `codex.agent_response`, `codex.guardian_assessment`.

**MCP/extensions.** `[mcp_servers.<name>]` in `config.toml` (`command,args,env,url,bearer_token_env_var,enabled_tools,disabled_tools`), `[plugins]`, `[marketplaces]`, `[skills]`; `AGENTS.md` plus `project_doc_fallback_filenames`.

**Dangerous state.** argv `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`), `--sandbox danger-full-access`, `--ask-for-approval never`, `--dangerously-bypass-hook-trust`, `--approve-for-me` (alias `--not-so-yolo`). Config `approval_policy="never"`, `sandbox_mode="danger-full-access"`, `projects."<path>".trust_level="trusted"`. `--full-auto` no longer appears in `shared_options.rs`, `exec/src/cli.rs`, `tui/src/cli.rs` or `cli/src/main.rs`.

**Process identity.** Rust binary `codex` (npm `@openai/codex`, brew cask `codex`). Child env: `CODEX_THREAD_ID, CODEX_SESSION_ID, CODEX_TOOL_CALL_ID, CODEX_VERSION, CODEX_PERMISSION_PROFILE, CODEX_SANDBOX, CODEX_SANDBOX_NETWORK_DISABLED`. Default `originator` header `codex_cli_rs`. Headless `codex exec` (`--json`, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`); whether hooks fire identically in `exec` and the IDE extension is UNVERIFIED.

---

## 4. GitHub Copilot CLI and VS Code (VERIFIED, github/docs + microsoft/vscode-docs)

**Hooks.** Events: `sessionStart, sessionEnd, userPromptSubmitted, userPromptTransformed, preToolUse, postToolUse, postToolUseFailure, agentStop, subagentStart, subagentStop, errorOccurred, preCompact, permissionRequest, notification`. Configuring the PascalCase name (`PreToolUse`) switches the payload to snake_case and Claude tool names (`Bash`, `Read`, `Write`, `Edit`). File format:

```json
{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"...","powershell":"...","cwd":".","env":{},"timeoutSec":30}]}}
```

camelCase payload: `{sessionId, timestamp (ms), cwd, toolName, toolArgs}`; postToolUse adds `toolResult:{resultType,textResultForLlm}`; subagents add `agentId, agentType, parentAgentId`. There is no transcript path and no permission mode in the payload. Output: `permissionDecision allow|deny|ask`, `permissionDecisionReason`, `modifiedArgs`; permissionRequest `behavior allow|deny, message, interrupt`. preToolUse command hooks fail closed on crash or non-zero exit, but timeouts always fail open, including for policy hooks. HTTP hooks require `https://` (localhost only with `COPILOT_HOOK_ALLOW_LOCALHOST=1`).

Locations: policy `/etc/github-copilot/policy.d/*.json` (root-owned, not group/world-writable), `C:\ProgramData\GitHub\Copilot\policy.d\*.json`, registry `HKLM\Software\Policies\GitHub\Copilot` (subkeys with `Policy` REG_SZ JSON); repo `.github/hooks/*.json`; user `~/.copilot/hooks/*.json` (`$COPILOT_HOME`); inline `hooks` in `.github/copilot/settings.json`, `settings.local.json`, `~/.copilot/settings.json`; repo `.claude/settings.json` is also read; plugin `hooks.json`. Policy hooks ignore `disableAllHooks`, run regardless of folder trust and outside the sandbox. Managed settings: plist `com.github.copilot`, `/Library/Application Support/GitHubCopilot/managed-settings.json`, `HKLM\SOFTWARE\Policies\GitHubCopilot`, `%ProgramFiles%\GitHubCopilot\managed-settings.json`, `/etc/github-copilot/managed-settings.json`; keys include `permissions.disableBypassPermissionsMode`, `permissions.{deny,ask,allow,limitTo}`, `allowedMcpServers`, `deniedMcpServers`, `sandbox`, `telemetry`, `strictKnownMarketplaces`. They apply in interactive, `-p`, `--acp` and `--server` modes.

VS Code: the Copilot harness shares the CLI runtime and hook format; Claude and Codex harnesses use their own hook systems and are disabled when Copilot enterprise-managed settings exist. The legacy Local harness uses `chat.useHooks`/policy `ChatHooks`. Auto-approve policies: `ChatToolsAutoApprove` (`chat.tools.global.autoApprove`, "YOLO"), `ChatToolsTerminalEnableAutoApprove`, `chat.mcp.access`.

**Transcripts.** `~/.copilot/session-state/<session-id>/events.jsonl` (+ `workspace.yaml`), `session-store.db`, `logs/`. Event `type` values per ADR's parser: `session.start, user.message, assistant.message, tool.execution_start, tool.execution_complete, permission.requested, permission.completed, subagent.started, hook.start, hook.end, session.mode_changed`.

**OTel.** Enabled by `COPILOT_OTEL_ENABLED` or `OTEL_EXPORTER_OTLP_ENDPOINT`; traces and metrics only. Spans `invoke_agent > chat | execute_tool` with `gen_ai.conversation.id, gen_ai.tool.name, gen_ai.tool.call.id`; `gen_ai.tool.call.arguments/result` only with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT`. `COPILOT_OTEL_FILE_EXPORTER_PATH` writes all signals as JSON-lines. VS Code emits `copilot_chat.*` including hook spans (`copilot_chat.hook_type, hook_input, hook_output`).

**MCP/dangerous.** `~/.copilot/mcp-config.json`, `--additional-mcp-config`. Flags `--allow-all`, `--yolo`, `--allow-all-tools` (env `COPILOT_ALLOW_ALL`), `--allow-all-paths`, `--allow-all-urls`, `--autopilot`, `--no-ask-user`; saved approvals in `~/.copilot/permissions-config.json`. Binary name and API hosts: UNVERIFIED.

---

## 5. Gemini CLI (VERIFIED, google-gemini/gemini-cli docs)

**Hooks.** Events: `BeforeTool, AfterTool, BeforeAgent, AfterAgent, BeforeModel, AfterModel, BeforeToolSelection, SessionStart, SessionEnd, Notification, PreCompress`. Base stdin: `{session_id, transcript_path, cwd, hook_event_name, timestamp}`; BeforeTool adds `tool_name, tool_input, mcp_context, original_request_name`; AfterTool `tool_response{llmContent,returnDisplay,error}`; BeforeAgent `prompt`; AfterAgent `prompt, prompt_response`; BeforeModel/AfterModel `llm_request, llm_response`. Exit 0 parses stdout JSON, 2 blocks, other is a warning. Output `decision:"allow"|"deny"`, `reason`, `continue`, `hookSpecificOutput.tool_input`. Only `type:"command"`, `timeout` in ms (default 60000); matcher is a regex for tools (`mcp_<server>_<tool>`). Hook env: `GEMINI_PROJECT_DIR, GEMINI_SESSION_ID, GEMINI_CWD, CLAUDE_PROJECT_DIR`. Configured under `hooks` in `settings.json`; `hooksConfig.enabled`/`hooksConfig.disabled`; project hooks are fingerprinted.

Settings precedence (low to high): system-defaults, user `~/.gemini/settings.json`, project `.gemini/settings.json`, system `settings.json`, env, argv. System paths: `/etc/gemini-cli/`, `C:\ProgramData\gemini-cli\`, `/Library/Application Support/GeminiCli/`, overridable by `GEMINI_CLI_SYSTEM_SETTINGS_PATH`. No plist or registry policy.

**Transcripts.** `~/.gemini/tmp/<project_hash>/chats/` (`.json` legacy, `.jsonl` journals with `$set`/`$rewindTo`, message `type: user|gemini`, `toolCalls[]`); `GEMINI_CLI_HOME`; `general.sessionRetention.maxAge`.

**OTel.** `telemetry.{enabled,target,otlpEndpoint,otlpProtocol,outfile,logPrompts}` / `GEMINI_TELEMETRY_*`; `logPrompts` defaults to true. Events: `gemini_cli.config` (`approval_mode, sandbox_enabled, mcp_servers, extensions`), `gemini_cli.user_prompt`, `gemini_cli.tool_call` (`function_name, function_args, decision, tool_type native|mcp, mcp_server_name`), `gemini_cli.hook_call`, `approval_mode_switch`.

**MCP/extensions.** `mcpServers` in `settings.json`; `mcp.allowed/excluded`; `admin.mcp.*`. Skills `~/.gemini/skills`, `~/.agents/skills`, `.gemini/skills`, `.agents/skills`; commands `~/.gemini/commands/*.toml`; agents `.gemini/agents/*.md`; `GEMINI.md`; policies `~/.gemini/policies/*.toml`, `/etc/gemini-cli/policies`.

**Dangerous/process.** `--yolo`, `--approval-mode=yolo|auto_edit` (YOLO is argv-only); locks `security.disableYoloMode`, `admin.secureModeEnabled`. Shell children get `GEMINI_CLI=1`. User-Agent `GeminiCLI/<ver>/<model> (os; arch; surface)`. Headless: `-p` or non-TTY, `--output-format json|stream-json`; hooks still run.

---

## 6. Cursor (mostly UNVERIFIED: cursor.com unreachable)

- Hook files (VERIFIED only as code in snyk `guard.py:70-90`): `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json`, enterprise `/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json`; dashboard-distributed team hooks.
- Events (snyk `guard.py:117-135`): `beforeSubmitPrompt, beforeShellExecution, afterShellExecution, beforeMCPExecution, afterMCPExecution, beforeReadFile, afterFileEdit, afterAgentResponse, afterAgentThought, stop, preToolUse, postToolUse, postToolUseFailure, sessionStart, sessionEnd, subagentStart, subagentStop`.
- Semantics (search snippets): exit 2 blocks; other failures fail open unless `failClosed:true`; hook env `CURSOR_VERSION, CURSOR_PROJECT_DIR, CLAUDE_PROJECT_DIR`; `sessionStart` is fire-and-forget and does not run for cloud agents.
- Transcript (VERIFIED as code, ADR `cursor_parser.py:29,105,164`): SQLite `<userdata>/Cursor/User/globalStorage/state.vscdb`, table `cursorDiskKV`, keys `composerData:%`, `bubbleId:%`, tools in `toolFormerData`.
- MCP `~/.cursor/mcp.json`, `.cursor/mcp.json`; skills `~/.cursor/skills`, `.cursor/skills`; rules `.cursor/rules/*.mdc`.
- CLI (`agent`/`cursor-agent`): `--force`/`--yolo`, `~/.cursor/cli-config.json` `permissions.allow/deny`. Native OTel: none found.

---

## 7. uber/ADR Sensor cross-check (VERIFIED, local clone)

Python transcript parsers per agent (`Sensor/adr_sensor/parsers/`), batch-polled; 14-day lookback by mtime; tool args/results truncated at 1,000 chars; spilled tool outputs not imported (`Sensor/README.md`). `claude_parser.py:77` hard-codes `Path.home()/".claude/projects"`, ignoring `CLAUDE_CONFIG_DIR`, while the Codex, Copilot and Gemini parsers honour `CODEX_HOME`, `COPILOT_HOME`, `GEMINI_CLI_HOME`. No hook receiver, no OTel ingest, no settings/posture collection; `permission-mode` records are classed as bookkeeping metadata (`claude_parser.py:44`). Schema is session-level `AgentEvent{timestamp, source, session_id, chat_history[ChatMessage{role, content, tools[ToolUsage{tool_name, tool_type, server_name, arguments, result, status, error}]}], project_path, model, hostname, username, raw_log_path, session_context, token_usage}`.

---

## 8. Recommended normalised event model

Common event types that all five can populate (via hook, transcript or OTel):

| Event | Claude | Codex | Copilot | Gemini | Cursor |
|---|---|---|---|---|---|
| `session.start` / `session.end` | SessionStart/End | SessionStart/End | sessionStart/End | SessionStart/End | sessionStart/End |
| `prompt.submit` | UserPromptSubmit | UserPromptSubmit | userPromptSubmitted | BeforeAgent | beforeSubmitPrompt |
| `tool.pre` | PreToolUse | PreToolUse | preToolUse | BeforeTool | preToolUse, beforeShell/MCP |
| `tool.post` (ok/fail) | PostToolUse(+Failure) | PostToolUse | postToolUse(+Failure) | AfterTool | postToolUse(+Failure) |
| `turn.end` | Stop | Stop | agentStop | AfterAgent | stop |
| `subagent.start/stop` | yes | yes | yes | OTel `gemini_cli.agent.start/finish`, transcript | yes |
| `permission.decision` | PermissionRequest/Denied, OTel | PermissionRequest, OTel | permissionRequest | OTel `tool_call.decision` | n/a |
| `config.posture` (scheduled) | files, plist, registry | TOML | JSON, registry | JSON | JSON, SQLite |

Minimal common fields: `event_id, ts, host{id,os,user}, agent{name,version,surface}, source (hook|transcript|otel|config|process), session_id, turn_id?, cwd, repo?, event_type, tool{name, class (shell|file_read|file_write|web|mcp|subagent|other), call_id?, input, input_sha256, truncated, mcp_server?, mcp_tool?}, outcome{status, error, duration_ms}, decision{value, source}, prompt{text?, length, sha256}, raw_ref{path, offset}`.

Agent-specific extension namespace: `permission_mode` (Claude, Codex), `approval_policy`/`sandbox_policy` (Codex), `approval_mode` (Gemini), `agent_id/agent_type/parent_agent_id`, `transcript_path`, `mcp_server.source` (Claude), `model`, `effort`, `tool_use_id` (join key to OTel for Claude), `toolResult.resultType` (Copilot), LLM request/response hooks (Gemini, Codex).

---

## 9. Gaps and design implications

Blind spots to detect rather than assume away (all VERIFIED unless marked):

- Hook-free execution paths: `claude --bare` (whether managed hooks still load under `--bare` was not confirmed), Claude `-p` in an untrusted repo runs that repo's hooks, Codex `--dangerously-bypass-hook-trust`, Gemini `hooksConfig.enabled:false`, Copilot hook timeouts.
- Transcript suppression: `CLAUDE_CODE_SKIP_PROMPT_HISTORY`, `--no-session-persistence`, Codex `codex exec --ephemeral` ("Run without persisting session files to disk", `exec/src/cli.rs:45`) and `history.persistence="none"` (prompt history only), relocation via `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `GEMINI_CLI_HOME`.
- Policy shadowing: Claude `managedSourcesBehavior` defaults to first-wins, so server-managed settings hide a device file; Gemini's system settings path is overridable by an environment variable (inference: a user can repoint it).
- Content gating: OTel prompts and tool inputs are off by default in Claude, Codex and Copilot, and on by default in Gemini.

Recommendations:

1. Ship one static Go binary as the hook handler for all agents (`sensor hook --agent claude|codex|copilot|gemini|cursor`): read stdin JSON, normalise, append to a local spool that Fluent Bit tails, always exit 0 in observe mode. Budget well under 30 s (Copilot default) and use Claude's `async:true` where no decision is needed.
2. Install only in managed tiers, with Fleet delivering the files/profiles: Claude `managed-settings.d/50-sensor.json`, Codex `requirements.toml` `[hooks]`, Copilot `policy.d/sensor.json`, Gemini system `settings.json`, Cursor enterprise `hooks.json`.
3. Expose posture as osquery tables: effective managed config per agent, hook inventory by source, MCP servers by scope, dangerous settings (`skipDangerousModePermissionPrompt`, `approval_policy="never"`, `sandbox_mode="danger-full-access"`, `COPILOT_ALLOW_ALL`), and live processes whose argv carries a bypass flag.
4. Tail transcripts incrementally with offset checkpoints as the fallback and integrity cross-check; handle Codex `.jsonl.zst`, Claude `subagents/` and `tool-results/`, Cursor SQLite.
5. Accept native OTel by pointing agents at a local Fluent Bit OTLP input (Claude logs, Codex logs, Gemini logs) and Copilot's JSON-lines file exporter; join on `tool_use_id`/`call_id`/`session_id`.
6. Emit a `coverage` heartbeat per session stating which of hook, transcript and OTel were seen, so a missing surface becomes a detection.
