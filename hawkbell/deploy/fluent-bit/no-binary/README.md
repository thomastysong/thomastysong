# The "no binary" rung: agents' native OpenTelemetry into Fluent Bit

Some hosts will never get a root daemon approved. On those, an agent that
exports its own OpenTelemetry logs can still report what it does, pinned by
managed settings to a Fluent Bit `opentelemetry` input on loopback.
`otel.yaml` receives it, `normalize.lua` turns each record into a
hawkbell-shaped `activity` record, and a handful of lite rules mark the
most obvious abuse. `normalize.lua` reads the attribute names of Claude
Code, Codex and Gemini CLI, the same three agents for which hawkbell's own
installer writes native OpenTelemetry settings
(`internal/hookinstall/notes.go`).

What this rung cannot do (from `normalize.lua` and `otel.yaml`, and where
cited, from the design review in `docs/ASSUMPTIONS.md` or hawkbell's code):

- No pre-execution decision: Fluent Bit only receives the export and
  nothing answers the agent. The tool record (`tool_result`) is logged
  after the tool ran.
- Cursor and Copilot CLI: UNVERIFIED whether they export OpenTelemetry
  logs at all; this rung was not tried with either.
- Claude Code cuts each `tool_input` value at 512 characters (as recorded
  in `internal/otelrecv/claude.go`, `claudeTool`); `normalize.lua` reads
  the command from `tool_parameters.full_command` instead.
- The Lua rules match text, not a parsed command: in the design review a
  Fluent Bit Lua rule set missed 3 of 5 trivial variants that hawkbell's
  parsed-fact rules catch (`docs/ASSUMPTIONS.md`, the table row on
  deterministic rules). They search the whole lower-cased command string,
  so a command inside a comment or a quoted string matches too.
- A record gets at most one finding: the first rule that matched.
- No session state, no correlation, no coverage proof, no inventory.
- Records sent while Fluent Bit is down: what the agent's exporter then
  does (retry, buffer or drop) is UNVERIFIED; it was not tested. Once
  received, the input buffers on disk (`storage.type: filesystem`).
- The receiver is unauthenticated loopback: anything on the host can post
  events. Treat this stream as advisory.

Tested on Fluent Bit 5.2.0 with seven records shaped like Claude Code's
`tool_result` and `permission_mode_changed` events, posted to the input
(not sent by a running Claude Code): six examples (five commands and a
switch to `bypassPermissions`) each produced one finding, with no
duplicates (HB-LITE-001 and HB-LITE-003 on two
examples each, HB-LITE-002 and HB-LITE-004 on one), and `go test ./...`
stayed an activity record (`deploy/fluent-bit/VERIFIED.md`, "Fragment
smoke tests" in the rerun after the rename). Codex and Gemini CLI records
were not tried.

Use it as a first step, not as the sensor.

## Agent settings (pin them in the managed tier)

Claude Code, `managed-settings.d/60-otel.json` (Linux `/etc/claude-code/`,
macOS `/Library/Application Support/ClaudeCode/`, Windows
`C:\Program Files\ClaudeCode\`). Managed settings lock the destination;
`OTEL_LOGS_EXPORTER` is pinned too so a developer cannot set it to `none`.
`OTEL_LOG_TOOL_DETAILS=1` adds commands and tool arguments to the events:
that is personal data, decide deliberately. Only one OTLP endpoint per
signal is allowed: if your organisation already collects Claude Code
telemetry, fan out from that collector instead of replacing it.

The block uses the per-signal log variables, the ones hawkbell's installer
writes (`internal/hookinstall/otel.go`, `claudeOTel`, checked against
Claude Code's monitoring documentation on 2026-11-11). The generic
`OTEL_EXPORTER_OTLP_ENDPOINT`, set in managed settings, makes Claude Code
drop every endpoint a developer set, for all signals, so it would take over
metrics and traces too. Not tested against a running Claude Code.

```json
{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://127.0.0.1:4318/v1/logs",
    "OTEL_LOG_TOOL_DETAILS": "1"
  }
}
```

Codex (`requirements.toml` or `config.toml`; key names from the Codex
source, UNVERIFIED against a running Codex):

```toml
[otel]
exporter = { otlp-http = { endpoint = "http://127.0.0.1:4318/v1/logs", protocol = "json" } }
log_user_prompt = false
```

Gemini CLI (system `settings.json`; UNVERIFIED against a running Gemini CLI):

```json
{ "telemetry": { "enabled": true, "otlpEndpoint": "http://127.0.0.1:4318", "otlpProtocol": "http", "logPrompts": false } }
```
