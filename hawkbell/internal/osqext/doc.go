// Package osqext is hawkbell's osquery extension: it exposes the local state
// database (internal/state) as osquery tables, one per state.Tables entry,
// named hawkbell_<name>, so Fleet policies, labels and reports can use them.
//
// # Tables only
//
// The extension serves tables and nothing else. It hosts no collector, no
// scanner and no detection: osquery tears an extension down within seconds
// of its own worker restarting (measured: 3 s after a watchdog kill), so
// anything stateful placed here would lose its state whenever osquery does.
// The daemon writes the state database; this process only reads it.
//
// # Compared with auto table construction
//
// The same tables can be had with no extension through
// state.ATCConfig. The extension adds typed columns (numbers compare as
// numbers), constraint pushdown for equality and time ranges, and reads that
// cost what the query needs instead of materialising the table. Queries
// written for ATC (CAST around numbers, text comparison of timestamps) work
// unchanged against the extension.
//
// # Behaviour worth knowing
//
//   - The database is opened read-only (SQLite mode=ro) and never created. It
//     is reopened when the file at the path is a different file than before.
//   - A missing database yields zero rows, not an error, exactly like ATC: a
//     sensor that is not installed must make "is the sensor healthy" policies
//     fail rather than leave the host without a policy result. Policies must
//     therefore include the heartbeat guard (state.PolicySQL).
//   - Any other failure (unreadable or unsafe file, damaged database) is
//     returned as a query error, which osquery logs and Fleet shows.
//   - A database written by an older or newer hawkbell is served as far as it
//     goes: unknown columns read as empty.
//   - Once per start the extension asks osquery for system_info.uuid and
//     writes it to the host id file (mode 0644), so every hawkbell process
//     stamps events with the host id Fleet knows. On hosts without firmware
//     ids osquery invents that id and keeps it in its own database; no other
//     process can derive it.
//   - Generate never panics into osquery-go: panics become query errors.
package osqext
