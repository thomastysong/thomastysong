// Package transcript reads AI agent session logs incrementally and turns
// their records into normalized events.
//
// It is the second collection surface next to hooks: it works when hooks are
// missing, disabled or bypassed, and it lets the engine cross-check what an
// agent reported through a hook against what it wrote to disk.
//
// # Formats
//
//	claude-jsonl    Claude Code   <config>/projects/<slug>/<session>.jsonl and
//	                              <session>/subagents/agent-<id>.jsonl
//	codex-rollout   Codex CLI     $CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl,
//	                              archived_sessions/, and .jsonl.zst archives
//	copilot-events  Copilot CLI   $COPILOT_HOME/session-state/<id>/events.jsonl
//	gemini-chats    Gemini CLI    <home>/tmp/<project>/chats/session-*.jsonl,
//	                              chats/<parent>/<id>.jsonl (subagents) and the
//	                              legacy single-document session-*.json
//
// Cursor keeps its history in SQLite (state.vscdb), not in a line log, and is
// out of scope for this package.
//
// # Trust model
//
// Session logs are written by the agent and live in a directory the user
// (and anything running as the user, including the agent's own shell tool)
// can rewrite. Every byte is treated as hostile:
//
//   - files are opened without following symlinks beneath the root's base
//     (the fixed prefix of its glob, or Root.Base), by walking the path with
//     openat, and must be regular files; a FIFO or device planted at a log
//     path can neither block nor feed the reader;
//   - when a root names its user's id, a file owned by anyone else is
//     refused, judged on the open descriptor;
//   - only complete, LF-terminated lines are parsed; a line longer than
//     MaxLine is skipped without being buffered;
//   - each line is decoded once with bounded bookkeeping, a parser never
//     panics, and unknown record types are counted, not guessed at;
//   - truncation, replacement, in-place rewriting and deletion of a log that
//     was being followed are reported as Problems, because an agent erasing
//     its own tracks is itself a signal.
//
// # Delivery
//
// Poll returns the events of every newly completed line and advances the
// checkpoints. By default the checkpoint store is written at the end of
// each Poll, which is at-most-once if the caller dies before handing the
// events on. With TailerOptions.DeferCommit the store is written only by
// Commit, giving at-least-once: after a crash the same lines are read again
// and produce the same event ids. Events of one file are in file order;
// across files they are not merged by time.
//
// The checkpoint store keeps, per file, the offset, the file identity, a
// fingerprint of the bytes before the offset and the parser state needed to
// continue (session identity, pending call names and classes, seen ids). It
// never holds prompts, tool inputs or tool outputs, so a tool result that
// arrives after a restart is paired with its call's name and class but not
// with its input or target.
//
// # What the events carry
//
// Events have Source "transcript" and Fidelity "observed", the record's own
// timestamp, Session.Transcript, and Tool.UseID (the agent's tool-call id) so
// the engine can pair them with hook events. Raw prompts, tool inputs and
// tool outputs are placed only in Event.Content, which is never serialized.
// Target fields are copied from the tool input as written (URL userinfo is
// dropped); secret redaction and privacy-tier stripping are the redaction
// stage's job. Outcome.Error is a closed-vocabulary code, never tool text.
//
// Event ids are deterministic: a UUIDv7-shaped value built from the record
// timestamp and a hash of the line. Re-reading a file after a crash, a
// replacement, a move or a Codex archive pass therefore yields the same ids,
// and downstream can drop duplicates.
//
// # Unsupported
//
//   - Incremental tailing of compressed (.zst) rollouts: they are archives
//     and are read whole, once.
//   - Claude Code tool outputs spilled to <session>/tool-results/ are not
//     followed; the transcript line holds the truncated text.
//   - Gemini CLI's logs.json prompt history is not read.
//   - subagent.stop is not emitted for Claude Code, Codex or Gemini CLI: their
//     logs record the parent's tool result, not a distinct stop record.
//   - On platforms other than Linux, macOS, the BSDs and Windows there is no
//     file identity and no ownership check; symlinks are still refused.
//   - On Windows a file moved to another path is not recognized as the same
//     file (its identity is only known once opened), so a move reads as a
//     new file; ids stay stable, so the repeats are deduplicable.
package transcript
