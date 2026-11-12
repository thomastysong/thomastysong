// Package engine is spoor's detection pipeline: every record a collector
// produces (hook spool, transcript tailer, process monitor, osquery exec
// pull, OTel receiver, adapters, scans) goes through one Pipeline, which
// writes what may leave the host to the outbox, keeps the rest in the
// local ring and feeds the state database that osquery and Fleet read.
//
// # Stages (BUILD-C section C2; the reasons are in design/DECISIONS.md)
//
//  1. Exclusions first: privacy.Policy.Excluded on identity fields only,
//     before any content is looked at. An excluded session stays excluded
//     for its later records. Counted as ingest.excluded.
//  2. Identity: an OTel record (no account: loopback carries no peer
//     identity) is attributed to the one live session with its host, agent
//     and session id, or waits HoldFor for one (attribution.go). The
//     account is a correlation key only: what folds into a twin or feeds
//     the hook-run comparison uses it; anything else is processed without
//     an account, since any local user can post OTel.
//     Host forced to Options.Host (when set), Integrity "user" for every
//     user-writable surface (hook, transcript, OTel, adapter) whatever the
//     record claims, otherwise defaulted from Options and never above the
//     pipeline's own integrity. Emitted and Sources are cleared (only the
//     pipeline sets them; detect mode keeps Sources); an unknown Tool.Kind
//     becomes "other". Dedupe is derived for every surface from (host, user
//     id, agent, session, tool-call id or keyed prompt digest and
//     occurrence, type), replacing what a source set, so hook and transcript
//     records of one call share it and two accounts never do; ID is derived
//     when absent, from a keyed digest of the record (see Identity keys).
//  3. One activity record per action, hook primary (correlate.go). A
//     transcript or OTel tool or prompt record waits HoldFor (10 s) for its
//     hook twin; unmatched, it is processed itself. The same prompt text
//     submitted twice is two actions: each surface numbers its records of
//     one text, and the k-th hook record pairs with the k-th transcript
//     record. OTel tool and prompt records without a natural key only
//     corroborate in a session with hook or transcript records. OTel
//     hook-run counts (claude_code.hook_execution_complete,
//     gemini_cli.hook_call) are compared with the hook records received. A
//     session's first record synthesizes its session.start (Fidelity
//     inferred), so the SessionStart hook is not required. A twin from
//     another surface goes into the Sources of the activity record that is
//     written when that record is still to be written (held, or buffered in
//     the same processing round); a twin that arrives after the record was
//     written (the usual hook-first case: the transcript tailer polls) is
//     counted instead: correlate.corroborated_after_write, and per session
//     the summary labels corroborated and corroborated_after_write.
//     correlate.corroborated counts every corroborated record.
//  4. Coverage per (agent, account) and per session, and the hook-bypass
//     finding (coverage.go). The finding needs the process monitor
//     (root-observed) to see the agent for the same account; with only
//     self-reported surfaces it is a low-severity signal, one per session.
//     Only root-integrity process records from the process monitor or
//     osquery change the process table. OTel records attributed through the
//     session id never count as calls the hook missed.
//  5. Features and rules: features.Compute with the acting account's home,
//     the first-seen features net.host_first_seen and mcp.server_first_seen
//     from the persistent Baseline (firstseen.go), then rules.Engine.Eval.
//     The rules engine keeps the per-session state (flags, thresholds,
//     dedup, written paths, secret fingerprints). A record that triggered
//     secret flow is reduced to its skeleton (flow.go) before anything,
//     the session summary included, is built from it.
//  6. Class floor: detections below config rules.min_class are not written,
//     but still count into the session summary. Rule-set and bundle
//     versions are stamped on every finding (labels rules_version,
//     bundle_version, next to rule_pack, rule_pack_version and rules_hash
//     from the rules engine). Evidence is rebuilt through
//     privacy.Policy.Evidence (fixed allowlist: prompt text and tool output
//     are never evidence outside the full profile, and a refused field
//     stays visible as [WITHHELD]).
//  7. Context: the last privacy.context_events records of the session go
//     with each finding or alert into the detection stream
//     (privacy.Policy.ContextFor), so a case is self-contained in minimal.
//  8. Session summary on session end (once none of the session's records is
//     held and HoldFor has passed since the end, so the other surfaces'
//     copies of the last records are in it; Close writes it at once), after
//     SessionIdle (15 min) of silence, and every SummaryEvery (15 min) while
//     active (Final=false). A record processed after the final summary (a late
//     collector) produces one more final summary at idle, labelled
//     end_reason=late_records, which supersedes it.
//  9. Activity token buckets (limits.go, config limits): per session, or
//     per account and agent for records without a session id, and per
//     account over all of its sessions (eight times the session bucket);
//     detection runs on every record, only writing is limited. Suppressed
//     counts go to the summary (label activity_suppressed) and the
//     heartbeat.
//  10. Privacy and output (output.go): privacy.Policy.Emit decides outbox or
//     local ring. The writer sets Writer (random per process), Seq (monotonic
//     per writer and stream), Emitted (written more than LateAfter = 60 s after
//     ts: a laptop that was offline, a transcript read late), checks the
//     ENCODED line against output.max_line_bytes, and accounts per stream.
//  11. State: inventory, posture, detections, summaries, coverage, agent
//     processes and the heartbeat are applied to the state database in
//     batches on Tick, after the same privacy pass as the outbox.
//  12. Heartbeat (health.go): per-stream {emitted, dropped, truncated,
//     first_seq, last_seq} for the interval (stream.<name>.<field>), totals,
//     surface status with schema drift (Options.Surfaces; last_event is the
//     arrival time), coverage, rules count/hash/version, catalog and bundle
//     versions, extra gauges such as shipper lag (Options.Gauges).
//     Content-free. It is built to fit the line cap, so the version and
//     status labels Fleet reads always survive: coverage rows are taken
//     account by account up to the budget and the rest are counted
//     (coverage.rows_omitted); the state database gets every row.
//
// # Identity keys
//
// Everything that goes into Dedupe and ID except content (host, account,
// agent, session, type, time) is visible in the shipped record, so an
// unkeyed digest of content would let any reader of the logs confirm a
// guess about a prompt, or about a secret the privacy stage redacted from a
// command (identity is derived before redaction), by recomputing it. Every
// identifier derived from content is therefore an HMAC-SHA256 under the
// pipeline's identity key (identity.go): the prompt digest that pairs a
// hook prompt with its transcript twin, and the digest of the record
// (command, path, URL, query, tool input hash, prompt, process, asset,
// check) behind the ID of a record that came without one. Tool-call ids
// and session ids are random values the agent generates, not content; they
// stay the natural keys of tool and session records, as they are, because
// they are also what joins spoor records to the agent's own telemetry. An
// ID the source set is kept (hookcmd keys its own payload digest;
// transcript ids come from the log's record ids, or from a line digest
// under the transcript tailer's own kept key).
//
// The first-seen baseline (BaselineFile under the checkpoint directory)
// stores digests of what the pipeline saw: which account contacted which
// egress host or called which MCP server definition. It
// outlives the records it was built from, so its keys are HMACs under the
// same identity key, in their own domain; the header carries a keyed
// fingerprint of the key, and a file in the old unkeyed format or under
// another key is discarded and overwritten (baseline.go).
//
// Options.IdentityKey is the key. In daemon mode with a data directory and
// no IdentityKey, New loads the key kept at IdentityKeyPath:
// <data_dir>/checkpoints/identity.key, IdentityKeyLen (32) random bytes
// written hex-encoded on one line, mode 0600 in the 0700 checkpoint
// directory, created on first start by LoadOrCreateIdentityKey and read
// back on every later one, so identities, the Dedupe values downstream
// deduplicates on, and the baseline hold across restarts (heartbeat
// identity.key_stored = 1). A key file that cannot be trusted (a symlink,
// not a regular file, readable by group or others, not hex) is never
// replaced: the pipeline runs with the per-process key and counts it
// (identity.key_errors), and identities then hold for this run only. In
// scan, detect and hook modes, and without a data directory, the pipeline
// uses a random key drawn once per process: identities are deterministic
// within the run, which is what deduplication, the hook/transcript pairing
// and the HoldFor wait need, and differ between runs. Losing or replacing
// the key changes identities from then on and empties the baseline (every
// host looks new once); it never merges records that were distinct. The key
// sits beside the baseline and the other checkpoints, so keying protects
// the shipped records and a copy of the state that travels without the key
// (a backup, a support bundle), not against an administrator of the host.
//
// # Satisfied by wiring, not implemented here
//
//   - Write-then-run (C2 item 5) and secret flow (item 6) are the rules
//     engine's session state: session.runs_written_file /
//     session.written_exec_path, and session.secret_flow /
//     session.secret_flow_kinds (the spec's flow.secret_egress and
//     flow.secret_kinds; the values are HMAC fingerprints, never stored).
//     They are computed inside rules.Engine.Eval, so the engine cannot set
//     them under the spec's names before evaluation. The pipeline keeps
//     that state alive by keeping one rules engine per process and carrying
//     sessions across SetRules. What the pipeline adds: a record that
//     triggered secret flow is reduced to its skeleton before it is written
//     (flow.go), because a value in base64 or hex is not something the
//     redactor can recognise on its own.
//   - First-seen (item 7): the engine sets net.host_first_seen and
//     mcp.server_first_seen from the persistent Baseline (BaselineFile under
//     the checkpoint directory, BaselineKeys keys, LRU), labels the record
//     first_seen and counts it (firstseen.go). The same Baseline backs the
//     rules novelty block (a first sighting adds the tag spoor.first_seen
//     and, with raise, one class). The rule linter knows a field from the
//     features registry, so a pack rule that names the two features is
//     matched at run time but needs them registered to lint clean.
//   - Dedup and suppression windows are the rules engine's; operator
//     suppressions from config (rules.suppressions) and from the bundle's
//     suppressions.yaml apply there. config rules.disable is applied to a
//     copy of the set.
//
// # Modes and concurrency
//
// In daemon mode Ingest only appends to a bounded queue (QueueSize; full
// means dropped and counted) and a worker processes it; Tick drains the
// queue first, so everything ingested before a Tick is processed by it.
// In scan, detect and hook modes Ingest processes synchronously. Ingest,
// Tick, Coverage, Stats, SetRules and Close are safe for concurrent use.
// The kill switch (platform.Disabled, or Options.Disabled) makes Ingest
// drop input (ingest.disabled_dropped), the worker and Tick drop what was
// queued before the switch was pulled (read fresh, not cached, so the
// outcome does not depend on which of them runs first), and Tick write only
// a heartbeat labelled status=disabled, which is not applied to the state
// database so that Fleet's freshness policy fails while nothing is
// collected. An Ingest that races Close is counted as ingest.closed_dropped
// if Close has already drained the queue for the last time.
//
// # Limits
//
//   - A hook record that arrives more than HoldFor after its transcript twin
//     was processed corroborates only; it does not replace the record.
//   - OTel records without a tool-call id (Gemini CLI) or prompt text (the
//     agents' default) cannot be paired; in a session with hook or
//     transcript records they only corroborate, otherwise they are
//     processed as they are.
//   - An OTel record is attributed only through a live session; when two
//     accounts claim one session id it is dropped
//     (correlate.otel_ambiguous); when none does within HoldFor it is
//     processed without an account (correlate.otel_unattributed), and so is
//     an attributed record that does not fold into a twin
//     (correlate.otel_unmatched). An OTel record of an excluded session is
//     excluded. Attributed records do add the OTel surface to the
//     account's session and coverage.
//   - The secret-flow skeleton keeps host names except labels shaped like
//     an encoding; a credential that is itself a plain lower-case word used
//     as a host label is kept.
//   - Hold, idle and summary timers run on the arrival time of records
//     (wall clock); the token bucket runs on the arrival time in daemon and
//     hook modes and on record time in detect and scan modes (replays).
//   - Coverage reads "blind" for an agent process that has produced no hook
//     or transcript record since it started, after BlindAfter; an agent
//     that sits idle at its prompt for a minute after start is therefore
//     reported blind until its first record.
//   - Sessions live in memory: after a daemon restart a session's next
//     record starts it again (a second synthesized session.start, a fresh
//     summary series with the same session id; the state database folds
//     summaries by session).
//   - Without Options.Hooked, hooks count as expected for an agent and
//     account once they have delivered before; Hooked is what makes a
//     never-delivering managed hook visible.
package engine
