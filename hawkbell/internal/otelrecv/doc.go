// Package otelrecv receives the OpenTelemetry logs that AI coding agents
// export natively and converts them into hawkbell events with Source "otel".
// It is an optional, experimental input: the third surface next to hooks and
// transcripts, useful because the agent emits it from its own process and a
// user cannot switch it off when managed settings pin the destination.
//
// # Wire format
//
// OTLP over HTTP with JSON encoding, POST /v1/logs, optionally gzip
// compressed. Protobuf bodies are rejected with 415 and a message that names
// the setting to change; gRPC is not served. This is deliberate: the module
// carries no protobuf dependency, and every supported agent can be pinned to
// JSON where its telemetry is configured:
//
//	Claude Code   OTEL_EXPORTER_OTLP_PROTOCOL=http/json (managed settings "env"),
//	              OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:4319/v1/logs
//	Codex         [otel] exporter = { otlp-http = { endpoint =
//	              "http://127.0.0.1:4319/v1/logs", protocol = "json" } }
//	Gemini CLI    telemetry.otlpProtocol "http", telemetry.otlpEndpoint
//	              "http://127.0.0.1:4319" (the CLI appends v1/logs)
//
// POST /v1/metrics and /v1/traces are acknowledged and discarded, so an agent
// given one base endpoint for all signals does not retry forever.
//
// # Trust model
//
// The receiver binds a loopback address only (Run refuses anything else) and
// has no authentication: OTLP exporters can send static headers, but a
// shared secret in an agent's settings is readable by the user it would be
// meant to keep out. Any local process can therefore post records, and
// loopback TCP carries no portable peer identity. Consequences:
//
//   - Events carry Integrity "user". They corroborate hook and transcript
//     records and feed the coverage logic; nothing a Fleet policy depends on
//     may rest on them alone.
//   - Requests carrying Origin or Sec-Fetch-Site, or a Host that is not a
//     loopback literal or "localhost", are refused, which closes the
//     browser-to-localhost and DNS-rebinding routes for a web page to forge
//     telemetry. Content-Type must be application/json for the same reason.
//   - Bodies are capped (Options.MaxBody, before and after decompression),
//     as are records per request, attributes per record, nesting, concurrent
//     requests and connections. Nothing in a record is executed or opened.
//
// # What is converted
//
// One log record becomes zero, one or two activity events. Unknown event
// names are counted (Result.Unknown, Stats.UnknownNames) and surfaced as
// schema drift; known names that are deliberately not converted (API
// accounting, model output, UI internals) are counted as ignored.
//
//	Claude Code (claude_code.*)
//	  tool_result                tool.post
//	  tool_decision              permission.decision
//	  user_prompt                prompt.submit
//	  permission_mode_changed    config.change
//	  plugin_installed           config.change
//	  managed_settings_resolved  config.change
//	  mcp_server_connection      notification
//	  plugin_loaded              notification
//	  skill_activated            notification
//	  hook_registered            notification
//	  hook_execution_start       notification
//	  hook_execution_complete    notification   (see IsHookRun)
//	  auth                       notification
//	  subagent_completed         subagent.stop
//	  compaction                 context.compact
//	Codex (codex.*)
//	  conversation_starts        session.start
//	  user_prompt                prompt.submit
//	  tool_decision              permission.decision
//	  tool_result                tool.post
//	  sandbox_outcome            notification
//	  skill_invocation           notification
//	Gemini CLI (gemini_cli.*)
//	  config                     session.start
//	  user_prompt                prompt.submit
//	  tool_call                  permission.decision and/or tool.post
//	  plan.approval_mode_switch  config.change
//	  hook_call                  notification   (see IsHookRun)
//	  agent.start / agent.finish subagent.start / subagent.stop
//
// # Field conventions
//
//   - Labels["otel_event"] is the agent's event name with its vendor prefix.
//   - Tool.UseID is tool_use_id (Claude Code) or call_id (Codex), the same id
//     the agent passes to its hooks, so the engine can pair the surfaces.
//     Gemini CLI's telemetry has no call id.
//   - Dedupe is left empty: the engine derives it for every surface from
//     host, agent, session, tool-call id and type.
//   - Ids are deterministic for a given record within one sensor process,
//     so an exporter retry does not create new events. They derive from a
//     hash of the whole record keyed with a per-process secret, because the
//     record may hold prompt, argument, error or output text and an id is
//     serialized: an unkeyed hash would confirm guesses about that text.
//   - Prompt text, tool arguments, tool output and error messages go to
//     Event.Content only, which is never serialized. Agents export them only
//     when their content flags are set (OTEL_LOG_USER_PROMPTS,
//     OTEL_LOG_TOOL_DETAILS, otel.log_user_prompt; on by default in Gemini
//     CLI). Without those flags an event still proves that a call with a
//     given id happened, which is what cross-surface coverage needs.
//   - Label values and Outcome.Error never carry free text, nor a hash of
//     it: values are reduced to a fixed alphabet, and errors to the agent's
//     error category or, without one, to hookio.ErrorSummary's
//     closed-vocabulary class ("tool error class:timeout"), the summary
//     the hook surface gives for the same text. No exact length either:
//     the privacy stage rounds lengths up outside the full profile, and
//     would pass one inside Outcome.Error through unrounded.
//   - Account e-mail addresses are never kept; only the domain is, as
//     Labels["account_domain"].
//
// # Unsupported
//
//   - OTLP protobuf and gRPC (rejected, see above).
//   - Metrics and traces (acknowledged and dropped). Copilot CLI exports
//     traces and metrics only, and Cursor exports nothing, so neither agent
//     is covered by this package.
//   - Sender authentication and TLS: loopback only, by design.
//
// Facts about each agent's telemetry are cited next to the code that relies
// on them; anything not confirmed from a primary source is marked UNVERIFIED.
package otelrecv
