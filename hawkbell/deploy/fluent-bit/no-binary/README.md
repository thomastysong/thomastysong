# The "no binary" rung: agents' native OpenTelemetry into Fluent Bit

Some hosts will never get a root daemon approved. On those, three of the
five major agents can still report what they do through their own
OpenTelemetry export, pinned by managed settings to a Fluent Bit
`opentelemetry` input on loopback. `otel.yaml` receives it, `normalize.lua`
turns each record into a hawkbell-shaped `activity` record, and a handful of
lite rules mark the most obvious abuse.

What this rung cannot do (measured in the design review, see
`docs/ASSUMPTIONS.md`):

- No pre-execution decision: `tool_result` is logged after the tool ran.
- Cursor has no native OpenTelemetry; Copilot CLI exports traces and
  metrics, not logs.
- `tool_input` values over 512 characters are truncated by the agent;
  detection reads `tool_parameters.full_command` instead.
- The Lua rules match text, not a parsed command: in testing they missed 3
  of 5 trivial variants (quoting, variables, encoding) that hawkbell's parsed
  rules catch, and matched a command inside a comment.
- No session state, no correlation, no coverage proof, no inventory.
- The agent's OTel exporter batches in memory (default 5 s) with no disk
  queue: records are lost if Fluent Bit is down.
- The receiver is unauthenticated loopback: anything on the host can post
  events. Treat this stream as advisory.

Use it as a first step, not as the sensor.

## Agent settings (pin them in the managed tier)

Claude Code, `managed-settings.d/60-otel.json` (Linux `/etc/claude-code/`,
macOS `/Library/Application Support/ClaudeCode/`, Windows
`C:\Program Files\ClaudeCode\`). Managed settings lock the destination; the
exporter selectors are pinned too so a developer cannot set them to `none`.
`OTEL_LOG_TOOL_DETAILS=1` adds commands and tool arguments to the events:
that is personal data, decide deliberately. Only one OTLP endpoint per
signal is allowed: if your organisation already collects Claude Code
telemetry, fan out from that collector instead of replacing it.

```json
{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_METRICS_EXPORTER": "none",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
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
