// Package osqexec turns a running osqueryd into an exec-event provider.
//
// Organisations that already run osquery with its evented process tables
// switched on (Linux audit process_events, macOS EndpointSecurity
// es_process_events, Windows ETW process_etw_events) have a kernel-backed
// record of every exec on the host. A Source pulls those rows straight from
// osqueryd over its extension-manager socket and hands back only the ones
// the caller attributes to an AI agent.
//
// # Why pull over the socket
//
// The obvious alternative, a Fleet-scheduled "SELECT ... FROM process_events"
// report, sends every command line of every process on the host to the Fleet
// server through osquery's logger, outside spoor's privacy profiles and
// without redaction; and a stock osquery enrolled in Fleet has no local
// results file to tail in the first place. Here nothing is scheduled, nothing
// is written to osquery's logs, and a row that is not an agent descendant is
// dropped in memory. The environment column is never selected.
//
// # What was verified, and on what
//
// Against a private osqueryd 5.19.0 with the Linux audit publisher
// (2026-11-11, kernel 6.18):
//
//   - Ad hoc SELECTs on process_events through the extension socket do return
//     rows. Rows become visible 2 to 15 s after the exec: osquery drains the
//     audit socket and writes subscriber batches on its own cadence. An
//     earlier observation that such a query "returns nothing" was that delay.
//   - The time column is the second osquery handled the record (2 to 4 s
//     after the exec in the test), not the exec itself. Event timestamps
//     therefore carry that error; eid is the reliable order.
//   - A reader that puts a constraint on time does not disturb scheduled
//     queries over the same table: with --events_expiry=1 and a 20 s
//     scheduled query, five marker execs were read ad hoc eight times and
//     were still all logged by the scheduled query afterwards. Every query
//     this package sends to an evented table is time-constrained, which is
//     also what the osquery documentation names as switching the scheduler's
//     cursor optimisation off for that query.
//   - A subscriber can say active=1 while its publisher is dead
//     (bpf_process_events on a host where the BPF publisher failed to start),
//     so availability needs the subscriber AND its publisher active AND at
//     least one row in a recent window.
//
// Not verified: the macOS and Windows tables (column lists are from the
// osquery table specs, the event_type/type spellings are marked UNVERIFIED in
// the code), and osquery releases older than 5.0. For those old releases the
// package refuses to read unless events_expiry is at least ten minutes,
// because their documentation says any SELECT expires buffered events.
//
// # Limits
//
//   - Rows carry a parent pid but osquery records execs, not every fork. A
//     chain agent -> shell -> command is followed inside the row stream (the
//     shell's own exec row is attributed first, the command's row then names
//     the shell as parent), but a subshell that forks without exec breaks the
//     chain unless the caller's Attribute function still knows the process.
//   - osquery joins argv with single spaces, so an argument containing a
//     space cannot be told from two arguments. Process.Args is that string
//     split on white space, redacted.
//   - Linux audit rows have no user name and no environment; the session id
//     of an event is whatever Attribute returned.
//   - Audit has limited visibility into containers and cannot coexist with
//     auditd; that is osquery's constraint and shows up here as "unavailable".
//
// # Trust
//
// The rows become root-integrity events, so the socket must be the real
// osqueryd. On Unix the socket and its directory must be owned by root (or by
// the caller when the caller is not root) and the directory must not be
// writable by anyone else. On Windows the pipe's owner must be SYSTEM or the
// Administrators group; that check is compiled and vetted but was not
// executed where this package was built. Row values are attacker-influenced
// text (a command line is whatever a process chose to exec): they are
// size-bounded, redacted with classify.RedactArgs, and never used to open or
// run anything.
package osqexec
