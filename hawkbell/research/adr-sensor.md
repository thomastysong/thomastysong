> **Historical design record.** Research report on uber/ADR Sensor (the batch transcript parser), cited by `docs/COMPARISON.md`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:51 UTC on the build machine; it reads a local clone at commit 6b33dff (2026-10-16)).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none. Kept: GitHub account names and editor extension ids that are part of a cited repository, package or extension location, because a reader needs them to check the source (the Cline extension id `saoudrizwan.claude-dev`, in a transcript path).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# uber/ADR Sensor: teardown (research key: adr-sensor)

**Executive summary**
1. ADR Sensor (PyPI `adr-sensor` 1.0.0, Python >=3.9) is a one-shot batch parser of at-rest agent transcripts. It installs no hooks, runs no daemon, ingests no agent OTel. The premise "hooks vs tailing" resolves to: 100% offline file/SQLite parsing.
2. Unit of telemetry is a whole-session snapshot (`AgentEvent` with full `chat_history`), re-sent in full whenever the session changes. No per-event stream, no per-message timestamps, no tool-call IDs.
3. Only remote transport is OTLP/HTTP logs via the Python OTel SDK; no persistent queue, at-least-once, hash-only delivery checkpoint. Local output is timestamped JSON/JSONL dumps or pretty-printed per-session files.
4. No redaction, no tamper resistance, no packaging or scheduler units, no multi-user or container awareness; evidence of production use is macOS only (paper: hourly schedule, 0.182 s/run).
5. Strengths worth copying: 11 format parsers (DSH and Gemini pinned to upstream commits), content-free health schema with closed reason codes, torn-tail handling, OTLP partial-success validation, atomic snapshot writes.

Provenance: local clone `/home/user/uber/adr` at commit `6b33dff` (2026-10-16). Everything below is VERIFIED by reading the cited file in this session unless marked UNVERIFIED or INFERENCE. I could not execute the sensor (execution of the external code was denied), so there are no measured numbers of my own.

---

## 1. Collection mechanism per agent

**Global facts (VERIFIED).** `grep -i hook` over `Sensor/adr_sensor` finds only a passive `ClaudeHook` dataclass, Copilot `hook.start/hook.end` event passthrough, and a `requests` response hook. There is no hook installer, no hook config snippet, no settings.json writer, no OTLP receiver, no LevelDB reader. The paper (`docs/adr-paper.pdf` §3.1) says the sensor "parses local data stores ... from their SQLite databases and JSONL caches" and that hooks are used only for a separate, unreleased prevention layer (§6.2: regex + entropy pre-prompt hook for Cursor and Claude Code; README: "Prevention ... not included").

Every parser: reads only the current user's home (`Path.home()`), applies a 14-day lookback (by file mtime or DB timestamp; `--all-history` sets 10000 days), re-reads the full source each run, emits one `AgentEvent` per session.

| Source key | Mechanism and exact location | Captured | Not captured / caveats |
|---|---|---|---|
| `claude` (`parsers/claude_parser.py`) | JSONL, `~/.claude/projects/**/*.jsonl` (same on Windows via `%USERPROFILE%`); subagents at `<project>/<sessionId>/subagents/agent-<agentId>.jsonl` | user text, assistant text, `tool_use` name+input, `tool_result` text (prefers `toolUseResult.result`), `cwd`, model, subagent as separate event with `parent_session_id`, `agent_id` | `thinking`/`redacted_thinking` dropped (only `type=="text"` extracted, l.322-326); images/documents; `is_error` ignored (status is `success` if result else `unknown`, l.401); no MCP attribution (`tool_type` always `tool_use`, l.417, even for `mcp__srv__tool`); no token usage, permission mode, version, git branch; ignores `CLAUDE_CONFIG_DIR` (l.79) |
| `cursor` (`cursor_parser.py`) | SQLite `state.vscdb`, table `cursorDiskKV`, keys `composerData:<id>` and `bubbleId:<id>:<bubble>`. macOS `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`; Linux `~/.config/Cursor/...`; Windows `%APPDATA%\Cursor\...` | user text (bubble type 1), assistant text (type 2, `text`/`richText`), `toolFormerData` {name, params/rawArgs, status, error, result} | opened with plain `sqlite3.connect()` (l.69), not read-only; no model, project path, thinking, MCP server, per-bubble time; ordering sorts on `_bubble_id` (l.213), a key the sensor never populates, so unless Cursor's own JSON carries it the order is DB row order (INFERENCE); Cursor CLI and cloud agents absent |
| `claude_desktop` | JSONL `audit.jsonl` + sibling metadata `local_<uuid>.json`. macOS `~/Library/Application Support/Claude/local-agent-mode-sessions/<user>/<org>/local_<uuid>/`; Windows `%APPDATA%\Claude\local-agent-mode-sessions\...`; Dispatch under `<org>/agent/local_ditto_<uuid>/` | user string prompts, assistant text, tool_use, tool_result; `session_context.init` {tools, mcp_servers, permission_mode, model, claude_code_version, plugins, skills}, title, `is_dispatch`, `cli_session_id`, memory/skills/plugins flags, slash commands | thinking skipped (l.537); user messages whose content is a list of text blocks become empty; no Linux; ordinary (non-agent-mode) chats not covered |
| `codex` | JSONL rollouts `$CODEX_HOME/sessions/**/*.jsonl` (default `~/.codex`), plus `state_*.sqlite` `threads(id, rollout_path, updated_at[_ms])` opened `mode=ro`, `timeout=0` | `session_meta` (id, cwd), `turn_context.model`, `response_item` message/function_call/custom_tool_call + outputs, `reasoning` summary text as `[Reasoning]`, `token_count`; MCP via `mcp__<server>__<tool>` or namespace | only `model` is read from `turn_context` (sandbox/approval policy ignored); every other `response_item` type and every `event_msg` except `token_count` is dropped without a diagnostic; raw reasoning content not read |
| `copilot` (CLI only) | JSONL `$COPILOT_HOME/session-state/<id>/events.jsonl` (default `~/.copilot`), plus `workspace.yaml`, `vscode.metadata.json` | richest event set: `session.start/resume`, `user.message` (+`transformedContent`), `assistant.message.toolRequests`, `tool.execution_start/complete`, `permission.requested/completed`, `session.model_change`, `skill.invoked`, `subagent.started`, `hook.start/end`, `session.mode_changed`, `workspace_file_changed`, `plan_changed` | no MCP server attribution; VS Code Copilot Chat explicitly out of scope |
| `dsh` (DeepSeek Harness) | JSONL or Zstandard, `$DSH_HOME/sessions/**/session.v3.jsonl[.zstd]` (default `~/.dsh`); v3 only | user/assistant messages, reasoning blocks, `tool/call`, `tool/result`, PTC sub-dispatch, approvals, sandbox mode, permission preset, tokens | text blocks cut to 1000 chars but raw `content_parts` kept unbounded in `session_context` |
| `opencode` | SQLite `opencode.db` / `opencode-<channel>.db` (`mode=ro`) in `$XDG_DATA_HOME/opencode` or `~/.local/share/opencode`; legacy `storage/` JSON tree; `OPENCODE_DB` | text, reasoning, subtask prompts, file refs, tool input/output/status | README lists macOS/Linux only (no `%APPDATA%`/`%LOCALAPPDATA%` candidate); MCP guessed as "non-builtin name containing `_`" |
| `gemini` | JSONL journals `~/.gemini/tmp/<project>/chats/**/*.jsonl` + legacy `chats/*.json`; macOS also `~/.cache/.gemini/tmp`; `GEMINI_CLI_HOME` | messages, `toolCalls` args/result/status, `awaiting_approval`, tokens, model, subagents, thoughts in `message_metadata` | no truncation at all |
| `antigravity` | JSONL `~/.gemini/antigravity-{cli,2,ide}/brain/<conv>/.system_generated/logs/transcript[_full].jsonl` + 4 legacy roots; `ANTIGRAVITY_HOME`/`AGY_HOME` | `USER_INPUT`, `PLANNER_RESPONSE`, `thinking` as `[Thinking]`, tool calls | tool results never captured (`ToolUsage` built without `result`) |
| `cline` | JSON `<Editor>/User/globalStorage/saoudrizwan.claude-dev/tasks/<id>/api_conversation_history.json` for Code, Cursor, Code - Insiders, VSCodium, Windsurf (macOS `~/Library/Application Support`, Linux `~/.config`, Windows `%APPDATA%`) | text; only `<use_mcp_tool>` XML becomes `ToolUsage` (regex) | built-in tools (execute_command, write_to_file) stay as unstructured text; no forks (Roo, Kilo) |
| `warp` | SQLite `warp.sqlite` tables `agent_conversations`, `ai_queries`, optional `ai_blocks`; macOS group container or `~/Library/Application Support/dev.warp.Warp-Stable/`; Windows `%LOCALAPPDATA%\warp\Warp\data\` | query text, command, output, exit code | no Linux path; plain `sqlite3.connect()` (l.83) |

Absent from `AgentObserver.SOURCES` (`observer.py:61-73`): VS Code Copilot Chat, Windsurf Cascade, JetBrains assistants, Amazon Q/Kiro, Aider, Continue, Goose, Zed, Cursor CLI.

## 2. Unified schema (copy of `schemas/agent_event_schema.py`)

```python
ToolUsage:   tool_name: str
             tool_type: str            # free-form
             server_name: Optional[str] = None
             arguments: Dict[str, Any] = {}
             result: Optional[str] = None
             status: Optional[str] = None
             error: Optional[str] = None
ChatMessage: role: str                 # 'user' | 'assistant' (codex/opencode pass raw role through)
             content: str
             tools: List[ToolUsage] = []
             sequence_id: Optional[str] = None
AgentEvent:  timestamp: datetime       # session start (or last-updated for cursor/opencode/claude_desktop/warp/cline)
             source: str               # claude|cursor|cline|warp|codex|copilot|dsh|claude_desktop|opencode|gemini|antigravity
             session_id: str           # "<source>_<native id>"
             chat_history: List[ChatMessage] = []
             user_id, project_path, model, hostname, username, raw_log_path: Optional[str]
             session_context: Optional[Dict[str, Any]]   # untyped per-parser bag
             is_chunked: bool = False; total_chunks, chunk_sequence: Optional[int]; is_truncated: bool = False
             token_usage: Optional[Dict[str, Any]]       # {last_turn, cumulative, model_context_window}
             host_os: Optional[str]    # platform.system(): Darwin|Linux|Windows
             uuid: str                 # sha256("|".join([hostname, username, ts.isoformat(), "llm_interaction",
                                       #   source, session_id, len(chat), tool_count, first 100 chars of each msg]))
```

Observed `tool_type` values (no enum is enforced): `tool_use`, `tool_call`, `mcp_tool`, `function_call`, `custom_tool_call`, `tool_request`, `tool_execution`, `terminal_command`, `warp_tool`. Observed `status`: `success`, `error`, `unknown`, `pending`, `running`, `permission_requested`, `approved`, plus raw agent strings. Token keys: `input_tokens`, `cached_input_tokens`, `cache_write_input_tokens`, `output_tokens`, `reasoning_output_tokens`, `total_tokens` (+ `tool_tokens` for Gemini).

Schema gaps (VERIFIED): no per-message or per-tool timestamp, no tool-call ID, no duration, no exit code, no per-call cwd, no pid, no agent version, no stable device ID (only `socket.gethostname()`), no account identity. Chunking fields are declared and never set by any code. `SystemConfiguration` (MCP configs, pip/npm/brew, Docker, Cursor rules, Claude skills/plugins/hooks) is fully defined but `ingest_all()` always returns `system_config_data = []` (`observer.py:190`); no collector ships, although the paper lists environmental context as a captured dimension.

Health schema (worth copying): `{"schema_version":1,"event":"adr.sensor.health","timestamp","sensor_version","source","stage":parse|save|save_session|export|startup,"status":ok|empty|no_input|partial|failed,"suspected_schema_drift":bool,"counts":{events_returned,events_emitted,events_filtered,attempted,succeeded,failed},"reasons":{...}}`. Closed reason vocabulary: `input_missing, file_age_skipped, incomplete_record, file_read_error, file_stat_error, record_decode_error, record_shape_error, unsupported_record_type, unsupported_schema, unsupported_content_block, invalid_timestamp, session_build_error, database_error, parser_error, write_error, export_error, startup_error, checkpoint_read_error, checkpoint_write_error`.

## 3. Exporters

- **Files.** Default: `./output/agent_event_logs_<YYYYmmdd_HHMMSS>.json` = `{"timestamp","total_entries","entries":[...]}` or `.jsonl`; a new file per run containing every session in the window. `--save-sessions`: `adr.<session_id>.<YYYYmmdd_HHMMSS>.json`, `indent=2`, in `--output-dir` or `$XDG_CACHE_HOME/adr_sensor` (default `~/.cache/adr_sensor` on all OSes).
- **OTLP/HTTP logs only** (`exporters/opentelemetry.py`): `opentelemetry-exporter-otlp-proto-http` pinned 1.41.x, `BatchLogRecordProcessor(max_queue_size=512, max_export_batch_size=512)`, forced flush every 512 records. No gRPC, syslog, Kafka, S3, or Fluent forward. Config keys: `endpoint`, `service_name`, `headers`, `timeout_seconds` (10), `flush_timeout_seconds` (30), `certificate_file`, `gen_ai_attributes`.
- Record: `event_name=adr.agent.session`, body = entire `AgentEvent` dict; attributes `adr.event.type=agent_session`, `adr.event.uuid`, `adr.schema.version="1"`, `adr.source`, `adr.session.id`, `adr.model`, optional `gen_ai.agent.name`, `gen_ai.conversation.id`. Resource: `service.name`, `service.version`, `host.name`, `os.type`. Health: `adr.sensor.health` with `adr.event.type=sensor_health`, `adr.sensor.stage`, `adr.sensor.status`, WARN when degraded.
- **Retry / buffering.** No persistent payload queue (README says so). A failed export is retried only if the source transcript still exists and is inside the window on the next run. Checkpoint `.adr-otel-delivery.<sha256(destination)>.json` maps `sha256([source, session_id, hostname, username])` to `sha256(payload)`, written atomically after flush and shutdown, used only with `--save-sessions`. Without it every run re-exports all sessions. At-least-once. Good detail: a `requests` response hook parses `ExportLogsServiceResponse` and fails on `partial_success.rejected_log_records != 0`.

## 4. Install, runtime, fleet story

`pip install "adr-sensor[otel]"`; console script `adr-sensor`. Dependencies: `tabulate`, `zstandard` (C extension), and with the extra the OTel SDK, `requests`, `protobuf` (37 entries in `uv.lock` including dev tools). No pkg/msi/deb/rpm, no launchd/systemd/Task Scheduler unit, no MDM profile, no Fleet or osquery integration, no config file beyond the OTLP JSON. README: "Schedule runs and monitor last-seen health externally." Paper: hourly schedule on Uber MacBooks. Runs unprivileged as the logged-in user; run as root/SYSTEM it sees only that account's home (no user enumeration). INFERENCE from code: with no `--output-dir`, `AgentObserver.__init__` does `Path("output").mkdir()` relative to CWD, so a scheduler launching from a non-writable CWD fails at startup.

## 5. Reliability

- No offsets: every run re-parses every file modified in 14 days and holds all events in memory before export.
- Dedupe: per-session content comparison for 6 "content-aware" sources (`claude, codex, copilot, dsh, gemini, antigravity`) using `session_context.last_event_at` + `event_count` as a revision; timestamp-second comparison for the other 5.
- Crash safety of its own state is good: temp file, fsync, `os.replace`, directory fsync (skipped on Windows), per-session lock (`flock` / `msvcrt.locking`, 30 s timeout), stale-revision guard.
- Torn tails: Claude parser distinguishes `incomplete_record` from corruption and decodes concatenated objects/NUL padding; DSH discards non-LF-terminated tail and recovers torn zstd frames. Other parsers count a live partial line as `record_decode_error`, which flips status to `partial`.
- No backpressure concept beyond the 512-record flush. No GC of the session cache or `./output` dumps (only superseded snapshots of content-aware sources are unlinked), so sensitive plaintext accumulates.
- Loss windows: transcript deleted before the next run; endpoint offline or sensor broken for more than 14 days; collector down longer than the transcript survives.

## 6. Privacy

No redaction anywhere. README: "The OpenTelemetry exporter applies no redaction or field projection, so prompts, responses, tool arguments, tool results, usernames, hostnames, and local paths can be transmitted." The only minimisation is `truncate_middle` (keep first 400 + last 400 chars when over 1000), applied inconsistently: Claude, Claude Desktop, Cursor, Codex, Copilot, opencode yes; Gemini, Antigravity, Cline no. No allow/deny by repo or path, no content-off mode, no hashing option. Snapshot files are created with mode `0o666` minus umask (`observer.py:621`), so with a common 022 umask they are readable by other local users unless a parent directory blocks it (INFERENCE). The paper says secrets are redacted "where possible" in the backend; that code is not released. Health records are deliberately content-free; `--log-file-content-free` and `--log-identity` exist for runtime logs.

## 7. Tamper resistance

None. Inputs are user-writable files; there is no hash chain, signature, inode/size regression check, or heartbeat (health records are emitted only when a run happens; README admits a missing summary "cannot distinguish an idle endpoint from a sensor that never ran"). Concrete evasions, each INFERENCE from verified code plus verified vendor docs:
- Claude Code documents `CLAUDE_CODE_SKIP_PROMPT_HISTORY`, `claude -p --no-session-persistence`, `claude purge`, and `cleanupPeriodDays` (default 30, minimum 1) at code.claude.com/docs/en/claude-directory and settings-reference. Any of these leaves nothing to parse.
- Launching with `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `GEMINI_CLI_HOME`, or `DSH_HOME` set in the agent's shell relocates transcripts; the sensor reads those variables from its own (scheduler) environment, and never reads `CLAUDE_CONFIG_DIR`.
- Back-dating a transcript's mtime beyond 14 days makes it `file_age_skipped`.
- Padding a command past 1000 chars hides its middle from the exported record.
- The agent's own shell tool can edit or delete the transcript, the session cache, and the checkpoint between hourly runs.

## 8. Platform parity and containers

Windows-specific paths exist for Cursor, Cline, Claude Desktop, Warp and Antigravity; home-relative sources work unchanged; opencode is documented as macOS/Linux only; Linux is missing for Claude Desktop and Warp. Windows username comes from `os.getlogin()` (`host_identity.py:28`). `--resource` is Unix-only. CI runs the full Sensor suite on `ubuntu-latest` only; just `test_dsh_parser.py` and `test_gemini_parser.py` run on macOS and Windows (`.github/workflows/sensor-dsh.yml`, `sensor-gemini.yml`). The paper's deployment section covers "corporate MacBook endpoints (Intel and ARM)" only. No container, Kubernetes, devcontainer, Codespaces or remote-SSH handling; the sole mention is README: "WSL/container sessions belong to their own filesystem and home."

## 9. Performance

There is no per-hook cost because there are no hooks. Per-run cost is Python start, imports (OTel SDK when exporting), a full re-parse of the 14-day window, and two or more full JSON serialisations per session (checkpoint fingerprint, snapshot compare, export). Cost scales with total transcript bytes in the window, not with new activity. The paper reports 0.182 s average per run (§3.1); UNVERIFIED by me. Optional `--resource` appends `{duration_seconds, cpu_user_seconds, cpu_system_seconds, max_rss_bytes}` to `resource.log`. Detection latency is bounded below by the schedule interval (hourly at Uber), so nothing is real-time.

## 10. Opportunities to surpass

1. Event stream instead of session snapshots: stable event IDs, per-event timestamps, tool-call IDs, byte-offset checkpoints, so volume is O(new bytes) and records are small enough for any Fluent Bit output.
2. Dual-path collection: managed hooks/native OTel where the agent offers them (real time, exists even when persistence is off) plus transcript tailing as reconciliation; emit a gap event when the two disagree.
3. Tamper and coverage signals as first-class events: heartbeat, hook/telemetry config drift, transcript truncation or inode change, persistence-disabled flags, relocated config dirs found via process environment.
4. Single static Go binary with pkg/msi/deb/rpm and service units; system-level run that enumerates all users; container and K8s modes.
5. Redaction and minimisation at the edge with a metadata-only mode; never truncate security-relevant fields silently (hash the full value, flag truncation).
6. Stable host identity (hardware UUID / osquery `host_uuid`) for joining with Fleet.
7. Ship the inventory collector ADR left as an empty schema, exposed as osquery tables.
8. Read-only/immutable SQLite opens everywhere; typed enums for `tool_type` and `status`; uniform MCP attribution.
9. Durable on-disk spool with backpressure (or delegate to Fluent Bit filesystem buffering) instead of "re-derive from source next hour".
