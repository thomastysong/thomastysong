// Package state is hawkbell's local state database: a small SQLite file that
// holds what is true on this endpoint right now (inventory, posture failures,
// recent detections, session rollups, agent processes, coverage and sensor
// health) so that osquery, and through it Fleet, can read it as tables.
//
// The same table definitions (Tables) drive both ways osquery can read the
// file: auto table construction (ATCConfig, no binary inside osquery) and the
// osquery extension in internal/osqext (typed columns, constraint pushdown).
//
// # Rules the file format follows, and why
//
// These come from experiments against osquery 5.19 and Fleet 4.94 (see
// design/DECISIONS.md, A16 and A23):
//
//   - WAL always. osquery's ATC reader keeps SQLite locking only for WAL
//     databases; a rollback-journal file is read with no locking and yields
//     torn snapshots with no error. Open refuses to run when WAL cannot be
//     enabled.
//   - The file is never replaced by rename. A surviving -wal sidecar is
//     replayed over the new file. All changes are ordinary transactions.
//   - Row caps on every table (RowCaps). ATC materialises the whole table for
//     every query, whatever the WHERE clause: about 12 MB of osquery memory
//     per 10,000 rows, and the watchdog kills the worker near 300,000. The
//     oldest rows are evicted in the transaction that would exceed a cap.
//   - Timestamps are fixed-width RFC 3339 UTC strings (TimeFormat), because
//     every ATC column is TEXT and only fixed-width strings compare
//     correctly as text. An unset time is the empty string.
//   - Numeric columns are INTEGER in the extension but TEXT under ATC. A
//     query that must work in both compares them through
//     CAST(col AS INTEGER).
//   - The column name "path" is reserved by ATC (osquery adds its own and
//     logs a warning per row when a table declares one), so asset locations
//     are install_path and source_path.
//   - A missing database reads as zero rows under ATC with no error, and so
//     does the extension. A policy of the form "no bad row exists" would
//     therefore pass on a host where the sensor is not running. Every such
//     policy must also require a fresh health.heartbeat: use PolicySQL.
//
// # What is stored
//
// Identifiers, classes, counts and timestamps only. Command lines, working
// directories, prompt text, tool input and output, and detection evidence
// values are never written: Apply copies a fixed list of fields and nothing
// else. MCP servers keep the launcher's base name, not its arguments or its
// directory. A session is identified by SessionRef, a truncated SHA-256 of
// (user id, agent id, session id), never by the agent's own session id.
// Text is cleaned (valid UTF-8, no control or bidirectional-override
// characters) and clipped before it is stored, because asset names and paths
// originate in files the monitored user controls.
//
// # Who writes
//
// One privileged process (the daemon, or a one-shot scan). Hooks never open
// the database: per-hook transactions measured 67% SQLITE_BUSY. Open creates
// the directory 0700 and the file 0600 and, when running as root on a POSIX
// system, refuses a directory that another user could write, since that user
// could then substitute the file Fleet policies are evaluated against. On
// Windows the mode bits mean nothing; the installer or daemon must restrict
// the directory ACL to SYSTEM and Administrators.
//
// # Scans, removal and drift
//
// A complete scan ends with MarkScan(started, finished, seen): every asset
// whose id is not in seen is marked removed, and Removed returns those as
// inventory events for the output stream. seen must list every asset the
// scan observed, including unchanged ones that a differential scan did not
// re-emit. A partial scan (deadline hit) must pass a zero finished time,
// which records the attempt without removing anything. Snapshot returns
// asset id to content hash for the next differential scan.
//
// Posture rows are failures only: a passing check deletes its row, and a
// failure that is not re-observed in two consecutive complete scans is
// pruned, so the scanner must re-emit failing checks on every scan.
//
// # Health mapping
//
// Apply turns a health.heartbeat event into the single health row. Fields
// that event.Health does not carry are read from the event: Host.ID,
// Privacy (the profile), Writer, and the labels LabelProfile,
// LabelRulesVersion, LabelBundleVersion and LabelHostIDSource. Counters named
// CounterEventsIn, CounterEventsOut, CounterDropped, CounterDetections and
// CounterErrors are taken as totals since the writer started. When one is
// absent, per-interval stream counters ("stream.<name>.emitted",
// "stream.<name>.dropped") are accumulated for as long as the Writer stays
// the same. SetHealth writes the row directly for callers that prefer not to
// rely on that mapping.
//
// # Unsupported
//
// Network filesystems without shared-memory support cannot run WAL; Open
// returns ErrNoWAL there rather than fall back to a mode ATC reads torn.
package state
