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
// Privacy field carries the profile name ("standard" for detection
// context, which always uses the standard field policy).
//
// # Structural redaction
//
// Commands are redacted from their structure first and by pattern second
// (see command.go): argument vectors from a word lexer and from
// shellx.Analyze (which also sees inside bash -c, cmd /c, eval, $( ) and
// decoded payloads) go through classify.RedactArgs; literals fed to
// --password-stdin style consumers, PowerShell assignments,
// ConvertTo-SecureString -AsPlainText, net user, setx and htpasswd -b are
// handled here; every recovered secret is then searched for in plain,
// reversed and encoded (base64, hex, escapes, UTF-16LE) form; a secret that
// cannot be located reduces the command to program and flag names. The
// tests push a canary corpus of synthetic credentials through every
// profile and require zero leaks, and report the over-redaction rate on a
// benign corpus.
//
// # Secret markers and digests
//
// classify marks a secret as "[REDACTED:<kind>:<fp>]" with an unkeyed
// SHA-256 fingerprint. Before anything leaves, that fingerprint is replaced
// by "hmac=" plus a keyed hash (same secret, same marker, within a tenant)
// or removed when there is no key: an unkeyed hash of a short password is
// a dictionary oracle. Likewise every content-derived digest (prompt, tool
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
// content search).
//
// # Known gaps
//
// Free-text credential detection is heuristic ("my password is x" is not
// found). A secret that is transformed by something the redactor cannot
// decode (compression, encryption, arithmetic) and was never seen
// structurally cannot be found. Windows 8.3 short names of a home
// directory are not rewritten to "~".
package privacy
