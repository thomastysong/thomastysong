// Package hookcmd is `spoor hook`, the entrypoint AI coding agents run on
// every hooked event (tool call, prompt, session start and end). It sits in
// the path of every tool call of every developer, so its first duty is to
// never break the agent, its second to be fast, and only its third to see
// and gate.
//
// # Contract
//
//   - Run returns 0 in every case: on success, on every crash, hang or
//     timeout of the worker that does the work, and for a guard block on
//     every agent including Codex (whose block is sent as JSON, see below).
//     Decisions are expressed only in the agent's JSON reply. Exit 2 means
//     "block" to every supported agent and is also what the Go runtime
//     exits with on a fatal error, so no code path uses it. Not covered: a
//     signal from outside killing the supervisor itself (the agent's own
//     hook timeout, the OOM killer, SIGPIPE when the agent has already
//     closed the reply pipe); the supervisor's own code is kept small for
//     that reason (no recursion, no shared maps, every goroutine recovers).
//   - The hook never writes to stderr: agents show it to the user or the
//     model, and Codex and Gemini read stderr as the block reason.
//   - stdin is read with a cap (limits.max_hook_input_bytes, at most
//     hookio.MaxInput) and a time bound. A payload that cannot be decoded
//     (empty, malformed, over the cap, nested deeper than 64 levels, from an
//     unknown agent) produces a TypePayloadAnomaly activity record with its
//     size and digest instead of nothing; hookio's salvage events for
//     oversized and over-nested payloads are kept as well.
//   - Payloads are decoded into maps by hookio, never into structs, and no
//     path from a payload is ever opened.
//   - Every record carries Host (platform.HostInfo), User (the OS identity
//     of the hook process, never a payload field), Integrity ("root" only
//     when the hook runs as root, else "user"), Process (the caller chain
//     captured at invocation: the caller's pid, parent pid, start time, exe
//     and up to eight ancestor names; the hook is a child of the agent, so
//     this is the exact process-identity join key for EDR data), and a
//     deterministic ID and Dedupe (below).
//
// # Record identity
//
//	natural = "tool:" + tool use id, else "p:" + hex(HMAC-SHA-256(per-user secret, raw payload)[:16])
//	Dedupe  = event.DedupeKey(host.id, agent.id, session.id, natural, type)
//	ID      = event.StableID(ts, host.id, agent.id, session.id, natural, type)
//
// A transcript record of the same tool call reproduces Dedupe from the tool
// use id. The payload digest is keyed with a secret kept in the user's
// spool state, because Dedupe ships at every privacy tier and an unkeyed
// digest of a prompt payload would let a reader of the log store confirm
// guessed prompts; it still collapses duplicate registrations (managed and
// user settings both running spoor for one event). Without the secret
// there is no payload key and the id is unique per record.
//
// # Supervisor and worker
//
// An in-process recover() cannot keep the first promise: a panic in another
// goroutine, a stack overflow, concurrent map writes and a deadlock all end
// a Go program with status 2. So Run is a supervisor. It checks the kill
// switch, reads the config and stdin, and re-executes its own binary as a
// worker (`spoor hook --worker ...`, stdin piped, stdout piped, stderr on
// the null device) under a hard deadline: guard.deadline in guard mode
// (floor MinGuardDeadline, cap 10 s), ObserveDeadline (2 s) otherwise. It
// forwards the worker's stdout only when it is empty after a clean exit or
// exactly one complete JSON object of at most MaxReply bytes; in every other
// case (worker missing, killed, crashed, hung, partial or oversized output)
// it answers with the dialect's allow-shaped reply (empty stdout) in observe
// mode or the dialect's "ask" in guard mode, appends a health.error record
// (Reason* constants) to the spool when it can, and exits 0. The worker
// writes its reply before appending records, so a decision survives a
// failure in the spool write.
//
// The supervisor re-executes only itself (/proc/self/exe on Linux,
// os.Executable elsewhere) with os.StartProcess; nothing found on disk or in
// the payload is executed. Its failure path does not run the dialect parser
// that may have crashed the worker: it reads the event name with a
// non-recursive top-level scan.
//
// # Modes
//
//   - Observe (guard.mode off, sources.hooks.detect_in_hook off; the
//     default): no rules are loaded. Parse, stamp, append, exit. The reply
//     is empty.
//   - Guard (guard.mode advisory): the guard subset of the rules
//     (rules.Set.GuardSubset of embedded + installed bundle + rules.dirs,
//     minus rules.disable) is evaluated with session state carried through
//     the spool's state files (ImportSession, Eval, ExportSession). The
//     strongest response is the answer, capped by guard.max_response. An
//     evaluation that times out, rule content that cannot be loaded, and a
//     payload too large or too deep to inspect answer "ask" on an event the
//     agent gates. Findings are not spooled in this mode (the daemon
//     re-detects from the activity); the activity records what the agent was
//     told (labels guard_reply, guard_rule; Outcome.Decision with
//     DecisionSource "spoor" when the reply carried the decision).
//   - In-hook detection (sources.hooks.detect_in_hook, for daemonless,
//     container and CI use): the full rule set is evaluated and its findings
//     (and privacy.Policy.ContextFor records when privacy.context_events >
//     0) are appended to the spool after privacy.Policy.Emit, without local
//     content, with integrity "user". A daemon reading the spool refuses
//     them (only activity is accepted from a user spool); they are for
//     consumers of a daemonless spool. Combined with guard, the full set
//     also answers the agent.
//
// Novelty blocks are inert in the hook: a one-shot process has no baseline,
// so every sighting would look like a first one. Detection.Enforced is set
// only on a finding whose rule produced the decision and only when the
// rendered reply actually carries that decision.
//
// # What "ask" and "block" mean per agent (honestly)
//
//	agent        deny/block                     ask                               guard timeout or crash
//	claude-code  permissionDecision deny        permissionDecision ask (prompts)  ask (prompts)
//	codex        JSON deny (see below)          systemMessage warning; PROCEEDS   warning; PROCEEDS
//	copilot-cli  permissionDecision deny        permissionDecision ask            ask
//	gemini-cli   decision deny                  systemMessage warning; PROCEEDS   warning; PROCEEDS
//	cursor       permission deny                permission ask                    ask
//
// So on Codex and Gemini a guard "ask" (including the answer to a timeout
// or a crashed worker) is a non-blocking warning and the action goes
// ahead; guard mode there blocks only on rules with response block and
// guard.max_response block. On events an agent does not gate, every
// decision is a no-op. Guard is advisory: agents also fail open on their own
// hook timeouts.
//
// Codex blocks: hookio renders a Codex block as exit 2 with the reason on
// stderr. This package never exits 2; it re-renders a Codex block as the
// JSON form Codex also accepts on exit 0 (PreToolUse:
// hookSpecificOutput.permissionDecision "deny" with a reason;
// UserPromptSubmit: decision "block" with a reason; PermissionRequest:
// hookSpecificOutput.decision.behavior "deny"), verified against
// openai/codex main (codex-rs/hooks/src/events/pre_tool_use.rs,
// user_prompt_submit.rs, permission_request.rs, engine/output_parser.rs)
// on 2026-11-12. UNVERIFIED: which Codex release first accepted the JSON
// form; a Codex too old to parse it would fail open on a spoor block.
//
// # Kill switch
//
// platform.Disabled (<system config dir>/disabled) or a "disabled" file
// next to the config file the hook was pointed at makes `spoor hook` exit 0
// at once with an empty reply, before reading anything. A per-user location
// is deliberately not honoured: it would let the monitored user switch off
// a managed hook. sources.hooks.enabled: false has the same effect.
//
// # Spool records and their consumers
//
// Activity records (and payload anomalies) are appended with their local
// content, as the spool contract requires, for the daemon to re-detect.
// Health records from the supervisor and findings from in-hook detection
// are also appended, but the daemon's spool reader accepts only activity
// from a user-writable spool and counts the rest as forged_kind; they are
// meant for daemonless consumers (Fluent Bit on the spool, `spoor ci`).
// A daemonless shipper must not ship activity-*.ndjson from the spool: those
// lines are pre-redaction and carry local content.
//
// # Known gaps
//
//   - Copilot's camelCase payloads carry no event name; when the worker
//     fails, the supervisor can render a guard "ask" only if the name came
//     from --event or SPOOR_HOOK_EVENT (Copilot treats its own hook
//     timeouts as allow, so this matches the agent's behaviour).
//   - Session state of a hook lives in the user's spool: code running as
//     that user can clear its own flags (see the rules package).
//   - An agent that never closes stdin costs one stdin wait (half the hard
//     deadline) per call.
//   - On Windows the worker is not tied to its supervisor by a job object;
//     its own watchdog ends it at most one second after the hard deadline.
//
// Measured latency is in LATENCY.md next to this file.
package hookcmd
