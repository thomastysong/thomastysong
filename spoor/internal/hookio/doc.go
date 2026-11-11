// Package hookio translates between the hook wire formats of AI coding agents
// and spoor's normalized event model. Each agent has a Dialect that parses one
// hook invocation (the JSON an agent writes to the hook's stdin) into events,
// and renders a spoor Decision back into the reply that agent understands.
//
// The package is pure: no file, network or process access, no clock other
// than event.New. That keeps the hook entrypoint fast (it runs once per tool
// call) and makes every dialect testable from recorded payloads.
//
// # Threat model
//
// Hook stdin is attacker-influenced: tool arguments, prompts, tool output and
// file content come from the model or from whatever the model was fed, and
// anyone on the machine can invoke the hook binary with a forged payload. So:
//
//   - Input is capped at MaxInput bytes and MaxDepth nesting levels before it
//     reaches encoding/json. Oversized or over-nested input still yields a
//     best-effort event (built from a non-recursive scan of the top-level
//     string fields) together with ErrTooLarge / ErrTooDeep, because a payload
//     the sensor silently drops is an evasion primitive: pad a write past the
//     cap and the pre-tool hook would otherwise see nothing.
//   - Wrong types never panic; a field of the wrong type reads as absent.
//     Every exported entry point also recovers and reports ErrInternal.
//   - Identifier-like fields (session ids, tool names, model names) are
//     stripped of control characters and cut at fixed lengths; a cut is
//     recorded in Event.Truncated. Paths, commands, URLs and queries are kept
//     verbatim, because detection must see what the agent will act on.
//   - Label values and Outcome.Error never carry free text from the payload.
//     Tool error text can quote file content or credentials, so only a
//     normalized summary ("exit code 1", "tool error fp:1a2b3c4d") is emitted
//     and the raw text stays in Content.ToolOutput.
//
// # Events are pre-redaction
//
// Events returned by Parse hold raw values in Target (command line, URL with
// userinfo and query, search query) and in Content. They are input for local
// detection and MUST pass through the redaction stage before any sink.
//
// # Field conventions
//
//   - Source is "hook", Fidelity is "observed", Kind is "activity".
//   - Labels["hook_event"] is the agent's own event name. An event name the
//     dialect does not know maps to type "notification" with
//     Labels["hook_unmapped"]="1" so schema drift is visible, never dropped.
//   - Tool.InputSHA256 is the SHA-256 of encoding/json.Marshal of the tool
//     input as decoded into map[string]any (sorted keys, default escaping).
//     Tool.OutputSHA256 and Tool.OutputLen describe Content.ToolOutput.
//   - For turn.end and subagent.stop, Content.ToolOutput holds the agent's
//     final message when the hook provides one.
//   - Prompt.Len is the byte length of the prompt; Prompt.SHA256 is left for
//     the redaction stage, which owns the tenant key.
//   - Other labels (closed vocabulary values only): session_source,
//     end_reason, notification_type, config_source, compact_trigger,
//     compact_phase, mcp_source, mcp_tool_prefix, memory_type, load_reason,
//     model_from, prompt_kind, expansion_type, command_source, setup_trigger,
//     file_event, directory_source, elicitation_mode, elicitation_action,
//     mcp_server, error_context, stop_reason, stop_status, hook_scope,
//     hook_inferred, hook_error, sandbox_bypass, project_dir,
//     parent_agent_id, original_request, failure_type.
//
// # Unsupported behaviour (explicit, by agent)
//
//   - Codex cannot ask and rejects a bare allow on PreToolUse. Respond turns
//     "ask" into a non-blocking systemMessage warning and "allow" into no
//     output. A block is exit code 2 with the reason on stderr.
//   - Gemini CLI has no ask decision: "ask" becomes a systemMessage warning.
//   - Copilot CLI drops the output of userPromptSubmitted command hooks, so
//     prompts cannot be blocked there (Request.Blocking is false).
//   - Copilot's camelCase payloads carry no event name. Register the
//     PascalCase names returned by Events (self-describing payloads), or pass
//     the name in the EnvHookEvent variable; otherwise the name is inferred
//     from the payload shape and Labels["hook_inferred"]="1" is set.
//   - No dialect rewrites tool input or tool output (updatedInput,
//     modifiedArgs, updatedToolOutput): spoor observes and gates, it does not
//     edit what the agent does.
//   - WorktreeCreate (Claude Code) reads the hook's stdout as a path. It is
//     parsed if received but must never be registered for spoor.
//
// Facts about each wire format are cited next to the code that relies on
// them; anything not confirmed from a primary source is marked UNVERIFIED.
package hookio
