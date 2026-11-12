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
//     recorded in Event.Truncated. Commands are kept whole and paths, URLs
//     and queries as written (up to toolmap's length bounds), because
//     detection must see what the agent will act on, not a tidied version.
//   - Labels and Outcome.Error are serialized at every privacy tier, so they
//     never carry free text from the payload. Labels taken from the agents'
//     enum fields keep only word-shaped values (anything else becomes
//     "other"); identifier labels are reduced to a fixed alphabet. Tool error
//     text can quote file content or credentials, so only a normalized
//     summary ("exit code 1", "tool error class:not_found len:57") is
//     emitted and the raw text stays in Content.ToolOutput.
//   - No serialized field holds an unkeyed hash of free text (prompt, tool
//     output, error or denial text). Such a hash is a guessing oracle for
//     short values, and these events reach the local spool before the
//     privacy stage, which owns the tenant key and derives the keyed
//     digests. Error and denial text is summarized by a closed-vocabulary
//     class (ErrorClass) and its byte length instead.
//
// # Events are pre-redaction
//
// Events returned by Parse hold raw values in Target (the full command line,
// paths, URLs with their query string, search queries) and in Content. They
// are input for local detection and MUST pass through the redaction stage
// before any sink. The one thing already removed is URL userinfo, which
// toolmap drops when it builds a Target.
//
// # Field conventions
//
//   - Source is "hook", Fidelity is "observed", Kind is "activity".
//   - Labels["hook_event"] is the agent's own event name. An event name the
//     dialect does not know maps to type "notification" with
//     Labels["hook_unmapped"]="1" so schema drift is visible, never dropped.
//   - Tool.Kind, Tool.InputKeys, Tool.InputSHA256 and Target come from
//     package toolmap (KindWithInput, InputKeys, InputHash, Target), the
//     same functions the transcript parsers use, so both surfaces describe
//     one call identically. A hook that names the action itself (Cursor's
//     beforeShellExecution, Gemini's mcp_context) overrides the kind.
//     Tool.InputSHA256 is unkeyed because it is the cross-surface join key
//     toolmap defines; the privacy stage keys it before anything ships.
//   - Tool.OutputLen is the byte length of Content.ToolOutput. Tool.OutputSHA256
//     is left empty: the privacy stage derives it, keyed, from the content.
//   - Tool arguments sent as a JSON-encoded string (Copilot toolArgs, Cursor
//     MCP tool_input) are decoded first; a string that is not a JSON object
//     is kept as {"_raw": "<string>"}.
//   - For turn.end and subagent.stop, Content.ToolOutput holds the agent's
//     final message when the hook provides one.
//   - Prompt.Len is the byte length of the prompt; Prompt.SHA256 is left for
//     the redaction stage, which owns the tenant key.
//   - Outcome.Error of a failed tool call is "exit code N" when the text
//     starts with Claude Code's "Exit code N" line, else
//     "tool error class:<class> len:<bytes>" (ErrorSummary). A PermissionDenied
//     reason is the classifier's bracketed rule label, "no_verdict",
//     "classifier_unavailable", or "denied class:other len:<bytes>".
//   - Other labels. Enum-valued: session_source, end_reason,
//     notification_type, config_source, compact_trigger, compact_phase,
//     mcp_source, memory_type, load_reason, prompt_kind, expansion_type,
//     command_source, setup_trigger, file_event, directory_source,
//     elicitation_mode, elicitation_action, error_context, stop_reason,
//     stop_status, failure_type, hook_scope, hook_inferred, hook_error,
//     sandbox_bypass. Identifier-valued: mcp_tool_prefix, model_from,
//     parent_agent_id, original_request. Path-valued: project_dir.
//   - An MCP elicitation (Claude Code) is a notification whose Tool carries
//     only Kind "mcp" and MCPServer, so one query over tool.mcp_server finds
//     tool calls and elicitations alike.
//
// # Replies
//
// Respond returns empty stdout, empty stderr and exit 0 for Action "none", for
// an unknown action, for a nil request and for every event the agent does
// not gate (Request.Blocking false); all five agents read that as "proceed".
// Otherwise:
//
//	agent    event                      deny                                   ask                     allow
//	claude   PreToolUse                 hookSpecificOutput.permissionDecision  same, "ask"             same, "allow"
//	claude   PermissionRequest          hookSpecificOutput.decision.behavior   (nothing)               behavior "allow"
//	claude   UserPromptSubmit/Expansion decision "block" + reason              systemMessage warning   (nothing)
//	claude   ConfigChange               decision "block" + reason              (nothing)               (nothing)
//	codex    PreToolUse                 hookSpecificOutput.permissionDecision  systemMessage warning   (nothing)
//	codex    UserPromptSubmit           decision "block" + reason              systemMessage warning   (nothing)
//	codex    PermissionRequest          hookSpecificOutput.decision.behavior   (nothing)               behavior "allow"
//	copilot  preToolUse / PreToolUse    permissionDecision + reason            same, "ask"             same, "allow"
//	copilot  permissionRequest          behavior "deny" + message              (nothing)               behavior "allow"
//	gemini   BeforeTool                 decision "deny" + reason               systemMessage warning   decision "allow"
//	gemini   BeforeAgent                decision "deny" + reason               systemMessage warning   (nothing)
//	cursor   beforeShell/MCPExecution   permission "deny" + messages           permission "ask"        permission "allow"
//	cursor   beforeReadFile             permission "deny" + messages           (nothing)               permission "allow"
//	cursor   preToolUse                 permission + decision "deny"           permission "ask"        permission + decision "allow"
//	cursor   beforeSubmitPrompt         continue false + user_message          (nothing)               (nothing)
//
// Every reply is one line of JSON on stdout with exit 0 and nothing on
// stderr, Codex's blocks included. The one exception is Respond's own panic
// fallback: if rendering a deny on a gateable event panics, it answers exit
// 2 with a fixed reason on stderr, the closest thing to a universal block.
// The reason is always non-empty, single-line, at most about 1 KiB, prefixed
// "spoor: " and suffixed with the rule id in brackets.
//
// # Unsupported behaviour (explicit, by agent)
//
//   - Codex cannot ask and rejects a bare allow on PreToolUse. Respond turns
//     "ask" into a non-blocking systemMessage warning (nothing on
//     PermissionRequest, where the user is about to be asked anyway) and
//     "allow" into no output except on PermissionRequest. A block is the
//     JSON form Codex honours on exit 0 (table above; openai/codex main,
//     codex-rs/hooks/src/engine/output_parser.rs, read 2026-11-12), not
//     exit code 2, which the Go runtime also uses for a fatal error.
//     UNVERIFIED: the first Codex release that parses these JSON forms; a
//     Codex too old to parse them fails open on a spoor block.
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
