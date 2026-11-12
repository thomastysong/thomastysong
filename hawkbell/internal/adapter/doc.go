// Package adapter converts the output of other sensors into hawkbell events,
// so a site that has already deployed one keeps its hooks and still gets
// hawkbell's correlation, Fleet tables and Fluent Bit content. It is an
// optional, experimental input.
//
// Two things live here: Numbat, a converter for the NDJSON records of
// perplexityai/numbat (Apache-2.0), and Detect, which tells a hawkbell line, a
// numbat line and an osquery result line apart so a tailer or the detect
// command can pick the right reader.
//
// # numbat
//
// The record shapes come from numbat's own documentation, read 2026-11-11
// at raw.githubusercontent.com/perplexityai/numbat/main: README.md,
// docs/event-model.md, docs/rules.md ("Event fields", "Event-type fields"),
// docs/cli.md ("The record stream") and the JSON Schemas under
// docs/schema/v0.5.0/ (event-, finding-, enforcement-, indicator-,
// scan-summary- and diagnostic-record.schema.json). Only schema_version
// 0.5.x is converted; other versions return ErrVersion.
//
// Records and what they become (Source is "adapter" on all of them):
//
//	event        activity, by event_type:
//	               session.start, session.end   session.start, session.end
//	               prompt.user                  prompt.submit
//	               tool.call                    tool.pre  (kind from the tool name)
//	               command.exec                 tool.pre  (shell)
//	               file.read                    tool.pre  (file_read)
//	               file.write                   tool.pre  (file_write, or file_edit by tool name)
//	               file.delete                  tool.pre  (file_edit, Labels file_op=delete)
//	               network.indicator            tool.pre  (web_fetch, or mcp when mcp_server is set)
//	               tool.result, command.result  tool.post
//	               permission.requested         permission.decision  ask
//	               permission.approved          permission.decision  allow
//	               permission.denied            permission.decision  deny
//	               config.agent, config.mcp     config.change
//	               message.assistant, message.reasoning   not converted
//	               anything else                notification, Labels adapter_unmapped=1
//	finding      detection.finding with RuleID "numbat:<rule_id>"
//	enforcement  permission.decision (deny, source hook) or notification (no_override)
//	indicator    notification with the indicator in Target
//	scan_summary, diagnostic   not converted
//
// Field conventions:
//
//   - Ids are derived from numbat's ids alone (see numbatID), so a finding's
//     cited events and an enforcement record's findings resolve to the ids
//     of the converted records. The originals are kept in
//     Labels numbat_event_id, numbat_finding_id and numbat_decision_id.
//   - No id or label is an unkeyed hash of record content. A record
//     without a numbat id, the oversize stand-in and every indicator are
//     identified by HMAC-SHA-256 under a random key drawn once per process
//     and never stored (runkey.go): stable within one run, different in the
//     next, so a log reader cannot confirm guesses about a prompt, a
//     command, an e-mail address or a URL query by recomputing an id.
//     numbat's project_path_hash (an unsalted SHA-256 of the path, by
//     numbat's own documentation) is relayed under the same key, so it
//     still joins findings and indicators within a run; diff_sha256 is not
//     relayed (diff_bytes is), and the stand-in keeps the line's size only.
//   - Tool.UseID is numbat's tool_call_id, the agent's own call id. Dedupe
//     is left empty (indicators excepted) so the engine pairs a converted
//     record with a native hook or transcript record of the same call.
//   - Integrity is "user": numbat runs as the monitored user and its record
//     file is writable by that user.
//   - Fidelity follows numbat's confidence: high is observed, medium and low
//     are inferred.
//   - Host.Name, Host.OS, Host.Arch and User come from the record's endpoint
//     object. endpoint.device_id is kept as a label, not as Host.ID.
//   - Prompt text, tool arguments and tool results go to Event.Content only.
//     Without --content full numbat exports a 200 code point preview and
//     the normalized command, file_path and url, which is what Target and a
//     rebuilt Content.ToolInput carry.
//   - Events are pre-redaction, like the events of every other source. Target
//     fields and, on findings, Detection.Evidence["command"|"file_path"|
//     "url"] hold text as numbat masked it (numbat redacts credentials in
//     event and finding fields before it writes them); such findings carry
//     Labels evidence_redaction=numbat. They MUST pass through the privacy
//     stage before any sink, and that stage must treat the evidence values
//     of an adapter finding as unredacted input. The observed content
//     preview of a finding is never copied.
//
// What a numbat stream cannot give hawkbell, compared with its own hook: guard
// mode (the decision was numbat's), the caller process chain, and root
// integrity for anything.
//
// UNVERIFIED (not confirmed from a primary source, or not exercised against
// a live numbat):
//
//   - No numbat binary was run. The fixtures are the examples in numbat's
//     README and docs/cli.md; record types without a complete example there
//     (session, prompt, file, command.result, permission, config) are tested
//     against records written from the schema.
//   - That numbat's session_id equals the session id the agent gives its
//     own hooks, which is what cross-surface pairing by session assumes.
//   - The meaning of approval_decision next to decision on permission
//     records; decision wins and approval_decision is the fallback.
//   - The id format with an embedded run timestamp (used only for sort
//     order).
//
// # Hostile input
//
// A record file is attacker-influenced twice over: its values come from
// model output, and the file is writable by the user. Lines are capped
// (MaxNumbatLine; a longer line yields a stand-in event plus ErrTooLarge
// rather than nothing), members of the wrong type read as absent, embedded
// JSON is depth-checked before decoding, identifiers are stripped of control
// characters and cut, labels are reduced to a fixed alphabet, and no path
// or URL from a record is ever opened or fetched.
package adapter
