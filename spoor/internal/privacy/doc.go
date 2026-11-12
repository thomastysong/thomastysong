// Package privacy decides what leaves the endpoint. Detection always runs
// locally on full content; this package only governs what is written for
// shipping (the outbox) and what is kept in the local ring.
//
// # Profiles
//
//	minimal   (default) detection, inventory, posture, health and summary
//	          records ship; activity goes to the local ring only and is
//	          attached to findings as redacted context (Policy.Context).
//	standard  activity ships too, with field-level redaction: target.command
//	          structurally redacted, target.query dropped, URLs without query
//	          or userinfo, no prompt text, no tool input or output (only
//	          input_keys, lengths rounded up to a power of four, keyed
//	          digests of values of at least 32 characters), process.args
//	          through classify.RedactArgs.
//	full      adds prompt text, web search queries, tool input (via
//	          classify.RedactMap) and the head of tool output, all redacted.
//
// In every profile: paths under the acting user's home become "~/...";
// session.transcript is dropped; invalid UTF-8 is replaced and
// labels.lossy=true is set; the encoded line is forced under MaxLine by
// cutting the largest fields first and naming them in "truncated"; and a
// detected secret's value or its unkeyed fingerprint never appears. The
// Privacy field carries the profile name on every record, detection
// context included; context, which always uses the standard field policy,
// also says so in labels.context_policy.
//
// # Detection context
//
// Context renders the events that preceded a finding so that a case is
// self-contained even in minimal. The records are routed to the detection
// stream (sinks route by kind): Kind "detection", Type TypeContext, with
// labels context_for (the finding's id), context_kind, context_type and
// context_event_id (what the record was), context_policy ("standard"),
// and a new deterministic id, so they never collide with the activity
// record itself or with the context of another finding. Seq and Writer are
// left for the writer to set. Every context record carries context_for:
// Context finds the finding in the slice it is given and ContextFor takes
// its id; without one they return nil (the engine calls ContextFor with
// its per-session ring).
//
// # Structural redaction
//
// Commands are redacted from their structure first and by pattern second
// (see command.go): argument vectors from a word lexer, from
// shellx.Analyze (which also sees inside bash -c, cmd /c, eval, $( ) and
// decoded payloads), from every quoted value, heredoc and comment, and
// from a syntax-blind split go through classify.RedactArgs plus this
// package's own flag table (argrules.go: sshpass -pPW, keytool -storepass,
// sqlcmd -P, ssh-keygen -N, lftp -u user,pw, smbclient -U user%pw,
// schtasks /rp, sqlplus user/pw@db, any --*pass/--*password flag).
// Multi-word rules are handled here: literals piped or here-stringed into
// a consumer that reads a credential from stdin (--password-stdin and its
// kin, sudo -S, passwd, chpasswd, kinit, openssl -pass stdin, vault login
// -), text written into a credential-class file (heredoc, echo, printf,
// tee and Set-Content into .netrc, .pgpass, .env, cloud and package
// credentials, keys), printf arguments a format labels as a password
// ("password=%s"), PowerShell assignments and environment setters
// ($env:X=, Set-Item env:X, [Environment]::SetEnvironmentVariable),
// ConvertTo-SecureString -AsPlainText, net user, setx and htpasswd -b.
// Every recovered secret is then searched for in plain, reversed and
// encoded (base64, hex, escapes, UTF-16LE) form; a secret that cannot be
// located reduces the command to program and flag names.
//
// Every emitted byte of a command has been seen by every view: at most
// 64 KiB is analysed, and where a view stops early (shellx's command and
// work budgets, the lexer's token cap) the command is cut there and only
// its head is emitted, with a truncation marker. The searches are budgeted
// (secrets x text length): a line with more recovered secrets than the
// budget allows is reduced to the skeleton rather than costing seconds per
// event. The tests push a canary corpus of synthetic credentials through
// every profile and require zero leaks, and report the over-redaction rate
// on a benign corpus.
//
// The redaction of a command line is a pure function of its text and
// dialect hint, and the same text recurs (the hook's pre and post records
// and the transcript twin of one call, detection context, evidence, the
// same build and test commands all session), so results are remembered in
// a bounded LRU keyed by SHA-256 of hint and text (memo.go); it holds no
// raw command text. Within one line, the views hand identical argument
// vectors to the flag rules once. Features' shellx parse is not reused:
// Event.Feat lacks the inline and decoded payload texts the redactor
// re-lexes and does not say which text it was computed from. The canary
// corpus runs both uncached and from the memo and requires identical
// output.
//
// # Secret markers and digests
//
// classify marks a secret as "[REDACTED:<kind>:<fp>]" with an unkeyed
// SHA-256 fingerprint, and producers reduce free text they will not emit
// to "fp:<8 hex>" summaries (hookio's "tool error fp:..." and "denied
// fp:...", otelrecv's error summary). Before anything leaves, both are
// replaced by "hmac=" plus a keyed hash (same value, same digest, within a
// tenant) or removed when there is no key: an unkeyed hash of a short
// password or error message is a dictionary oracle. Likewise every content-derived digest (prompt, tool
// input and output, user-authored asset definitions, the engine's dedup
// key) is HMAC-SHA-256 with the tenant key, truncated to 96 bits, or is
// not emitted. Keys shorter than MinKeyLen bytes are ignored.
//
// Limits of the key, stated plainly: it is present on every endpoint of
// the tenant, so keyed digests and pseudonyms protect against readers of
// the log store and against linkage across tenants, not against someone
// with root on an endpoint. In daemonless mode the hook has no key and
// emits no digests. Pseudonymization covers identity fields and home
// directory paths, not free text that happens to contain a name.
//
// # Exclusions and evidence
//
// Exclusions (path, repository and account globs) are evaluated on
// identity fields only, before any content is processed; Emit drops
// excluded records and Excluded lets callers count them. Detection
// evidence is copied only from a fixed allowlist of non-content fields;
// prompt text and tool output are never evidence outside the full
// profile, whatever a rule asks for (a rule pack must not become a covert
// content search). A field outside the allowlist passes only as a bare
// boolean or number, and only when the rule registry (features) types it
// so: a value that merely parses as a number (an OTP, a card number) is
// content. A field that is asked for but not allowed is reported as
// Withheld, so the request stays visible; stamping rule and bundle
// versions on findings (so such a request is attributable) is the rule
// engine's job, and Emit passes those labels through. Labels are free text
// capped at 256 bytes, except rules_version and rules_hash when their
// value is in the version vocabulary (pack@version list, hex digest):
// those get their own bound (1 KiB, 128 bytes; versionlabel.go), so a
// finding stays attributable at any realistic number of rule packs.
//
// # Known gaps
//
// Free-text credential detection is heuristic ("my password is x" is not
// found). Text a shell command writes into an ordinary file (not a
// credential file) is redacted by pattern only, so a password in a
// project config file written by heredoc is found only when it is
// labelled ("password=x") or recognisable. A secret that is transformed by something the redactor cannot
// decode (compression, encryption, arithmetic) and was never seen
// structurally cannot be found. Windows 8.3 short names of a home
// directory are not rewritten to "~".
package privacy
