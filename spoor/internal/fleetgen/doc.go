// Package fleetgen generates spoor's Fleet content: the files committed under
// deploy/fleet/lib and written by `spoor export fleet`. Generate returns them
// as a map from path (relative to deploy/fleet/lib) to bytes; nothing here
// touches a Fleet server.
//
// Everything is derived, not hand-written, so that the content cannot drift
// from the sensor:
//
//   - table names, columns and the ATC queries come from state.Tables and
//     state.ATCConfig, one complete block per operating system;
//   - every policy is built with state.PolicySQLWithin, so the heartbeat
//     guard is the same expression the state package documents;
//   - names of agents that support hooks, of command-line switches that turn
//     approvals off and of settings that do the same come from the embedded
//     catalog (internal/catalog), classified by tables in vocab.go that a test
//     holds against the catalog, so a new catalog flag forces a decision;
//   - MCP risk flags come from internal/mcpconf, project auto-run flags from
//     internal/discovery (checked by running a project scan in a test).
//
// # Profiles
//
// Three alternative content sets are produced; an organization deploys one:
//
//   - stock: plain osquery (any distribution of osquery 5) reading the spoor
//     tables through ATC or the spoor extension;
//   - fleetd: hosts running Fleet's agent, which adds the ai_tools table.
//     Inventory questions (agents present, MCP declarations, permission
//     bypass flags) also consult ai_tools; spoor contributes what fleetd does
//     not have (detections, hook coverage, sensor health, project auto-run
//     files, agent processes);
//   - builtin: no spoor binary at all, ai_tools only (tier 1).
//
// # Fail-closed policies and the two heartbeat windows
//
// A missing state database reads as zero rows, under ATC and under the
// extension alike, so a policy of the form "no bad row exists" would pass on
// a host where the sensor was never installed or its database was deleted.
// Every spoor policy therefore requires a fresh spoor_health.heartbeat. Two
// windows are used (BUILD-C addendum, C5):
//
//   - the dedicated "sensor is reporting" policy uses AlertWindow (default 30
//     minutes) and is the one to alert on;
//   - every other spoor policy embeds GuardWindow (default 24 hours), so that
//     a removed sensor or a deleted database fails within a day without
//     turning every policy red each time a laptop wakes from sleep.
//
// The builtin profile has no heartbeat to check: its policies read Fleet's
// own ai_tools table, which errors (no response, neither pass nor fail) where
// it does not exist.
//
// # ATC is a fragment
//
// agent-options.atc.yml is a fragment to merge into existing agent options,
// never a replacement: Fleet replaces the whole agent options document, and
// does not merge platform overrides with the base config, so applying the
// fragment as it stands drops existing ATC tables, decorators and options.
// agent-options.example.yml shows the merged result on top of Fleet's
// documented default options, for review and for `fleetctl gitops
// --dry-run`.
//
// # Unsupported
//
// DBPaths with an osquery path wildcard (%) are rejected: the "spoor
// installed" label compares paths exactly. Platforms other than linux,
// darwin and windows have no spoor build and get no ATC block.
package fleetgen
