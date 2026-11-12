// Package rules is spoor's detection engine: a strict YAML rule language
// over the field view of internal/features, compiled into a Set, and an
// Engine that evaluates events with bounded per-session state.
//
// # Packs
//
// A pack is one YAML document:
//
//	pack: core
//	version: "2026.11.0"
//	rules:
//	  - id: SPR-EXEC-001
//	    title, description, kind (activity|inventory), class (signal|finding|alert),
//	    severity, confidence, maturity, category, tags, references, falsepositives,
//	    when, match, allow, flags {require, require_any, set, ttl, scope},
//	    threshold {count, window, by}, emit, escalate, response (none|ask|block),
//	    dedup, evidence, remedy, novelty {fields, raise}, tests
//
// Loading is strict: unknown keys, anchors, aliases, merge keys, custom
// tags, duplicate keys and second documents are errors; a pack is capped
// at 1 MiB and 500 rules; regular expressions are RE2, at most 1,000
// characters, and compile on first use; every rule needs at least one
// test. lists.yaml holds named lists ({lists: {name: [entries]}});
// suppressions.yaml holds operator exceptions ({suppressions: [{rule,
// match, expires, reason, tags}]}).
//
// The embedded packs are also shipped pre-parsed in packs/embedded.cache,
// because a guard-mode hook is a fresh process per tool call and YAML
// scanning was two thirds of its start-up (18 ms for 300 rules against a
// 15 ms budget; 6 ms from the cache). The cache is regenerated with
// `go generate ./internal/rules` after any change to packs/ or lists.yaml;
// it records a SHA-256 of the YAML it was made from, LoadEmbedded uses it
// only on a match and parses the YAML otherwise, and the package tests fail
// while it is stale. It is embedded rather than written to a user cache
// directory, which the guarded agent itself could write.
//
// # Predicates
//
// when, match and allow are predicate mappings. Several keys in one
// mapping are a conjunction; "all" and "any" take a list of mappings; "not"
// takes a mapping. A leaf is "field: value" (equality; a list value is
// any-of; on a list field, true when any element equals) or
// "field|modifier: value" with the modifiers contains, icontains,
// startswith, endswith, re (a list value is any-of; on a list field any
// element may match), in, contains_any, contains_all, in_list (every
// element of a list field must be listed, so one trusted host cannot vouch
// for another in the same command), any_in_list, gt, gte, lt, lte, exists,
// len_gt, cidr, any_startswith, any_endswith, any_re and any_contains. A
// missing field never matches, except "|exists: false"; empty strings and
// empty lists count as missing.
//
// Two quantifiers bind several conditions to ONE item, which flat
// predicates over feature arrays cannot (measured: 3.3x to 3.6x
// over-matching on real sessions):
//
//	any_command: {name|in: [rm], args|contains_any: ["-rf", "-fr"], args|any_startswith: ["/", "~"]}
//	any_install: {manager: npm, exec: true, packages|any_re: "^@evil/"}
//
// any_command iterates shell.cmds (keys name, path, args, origin,
// dynamic); any_install iterates shell.install_entries (keys manager,
// packages, global, exec, flags).
//
// # Evaluation
//
// Rules are indexed by the event types their when block names, so an
// event is only matched against rules that can apply to it; activity rules
// see activity events, inventory rules inventory events. For each
// candidate: when, then flags.require / require_any against the session
// flags, then match, then allow (a hit vetoes the detection), then the
// threshold. A rule that fires sets its flags.set (with ttl, default 30m)
// even when emit is false; flags set by an event take effect for later
// events only, so results never depend on rule order.
//
// Flags are kept per (session, subagent thread): a flag set inside one
// subagent does not satisfy a requirement in another thread or in the
// parent, because subagents of one orchestrated session share a session
// id and one thread's untrusted input must not taint every other thread.
// A rule with flags.scope: session sets its flags session-wide and checks
// requirements against every thread.
//
// threshold {count, window, by} fires when count matches fall inside the
// window (0 = no window), counted per session, user or host, and then
// restarts the count. Detections are deduplicated per (rule, session,
// dedup fields): repeats inside Options.SuppressFor (default 1h) are
// counted, and the next emission carries the count. For class alert the
// window is capped at 10 minutes and the key always includes the
// destination (hosts and paths), so suppressing one alert cannot silence
// the same rule against a different target. A novelty block may only add
// attention: a first sighting adds the tag spoor.first_seen and, with
// raise, lifts the class one level; a repeat never lowers anything.
//
// Result.Response is the strongest of none < ask < block among fired rules
// on tool.pre and prompt.submit (the only blockable types). When the
// per-event deadline (default 150 ms) expires with a guard rule still
// pending, the response is at least ask: a stalled evaluation is never an
// implicit allow. Eval never panics; an internal failure answers ask for
// an event a guard rule could have decided.
//
// Inventory rules (kind: inventory) produce posture.check failures instead
// of detections.
//
// # Session state and identity
//
// SessionKey hashes (Event.User.ID, Event.Agent.ID, Event.Session.ID). The
// user id must be what the caller established (the owner of the spool or
// transcript file), never a name from the payload. Per session the engine
// keeps flags, counters, dedup memory, the last 200 paths written by file
// tools, shell redirections and writing MCP tools (session.runs_written_file
// is set when a later command executes one of them), and keyed
// fingerprints of credential values read from credential-class paths
// (session.secret_flow is set when one of those values, raw, URL-encoded,
// base64 or hex, appears in a later outbound command, URL or MCP argument).
// ExportSession and ImportSession move this state through a one-shot hook
// process; imported state is validated as hostile input and capped at
// 64 KiB.
//
// # Known gaps
//
//   - The data-flow rule follows secret VALUES read from secret-class
//     paths. Private data read through an approved MCP tool and written to
//     a public sink through MCP touches no secret path and is only covered
//     by a signal-class co-occurrence rule.
//   - Session state of a daemonless hook lives in a file the monitored user
//     can write; code running as that user can clear its own flags.
//   - Content hidden behind runtime assembly (eval of built strings,
//     interpreter one-liners, write-then-run across sessions) is scored by
//     shell.opaque and session.runs_written_file, not seen through.
//   - Novelty baselines are in memory unless Options.Baseline is set, so in
//     a one-shot hook process every sighting is a first sighting.
//
// # Linting
//
// Lint reports what the loader accepts but review must not: unknown field
// names (validated against features.Registry), literals outside a closed
// vocabulary, type mismatches, unknown lists, text matching
// (re/contains/icontains/startswith/endswith) on target.command, alert
// rules with fewer than two negative tests, responses on non-blockable
// types, response: block in an embedded pack, duplicate ids and rules with
// no effect.
package rules
