// Package fleetgen generates hawkbell's Fleet content: the files committed under
// deploy/fleet/lib and written by `hawkbell export fleet`. Generate returns them
// as a map from path (relative to deploy/fleet/lib) to bytes; nothing here
// touches a Fleet server.
//
// Everything is derived, not hand-written, so that the content cannot drift
// from the sensor:
//
//   - table names, columns and the ATC queries come from state.Tables and
//     state.ATCConfig, one complete block per operating system;
//   - every hawkbell policy is built with state.PolicySQLWithin, so the
//     heartbeat guard is the expression the state package documents, and
//     three policies reuse the violation SQL of state.Policies;
//   - names of agents that support hooks, of command-line switches that turn
//     approvals off and of settings that do the same come from the embedded
//     catalog (internal/catalog), classified by tables in vocab.go that a test
//     holds against the catalog, so a new catalog flag forces a decision;
//   - MCP risk flags come from internal/mcpconf, project auto-run flags from
//     internal/discovery (checked by running a project scan in a test).
//
// A golden test fails when deploy/fleet/lib differs from Generate's output;
// `go test ./internal/fleetgen -run TestGolden -update` rewrites it.
//
// # Profiles
//
// Three alternative content sets are produced; an organization deploys one:
//
//   - stock: plain osquery (any distribution of osquery 5) reading the hawkbell
//     tables through ATC or the hawkbell extension;
//   - fleetd: hosts running Fleet's agent, which adds the ai_tools table.
//     The "AI agents present" label and the bypass and MCP policies also
//     consult ai_tools; hawkbell contributes what fleetd does not have
//     (detections, hook coverage, sensor health, project auto-run files,
//     agent processes);
//   - builtin: no hawkbell binary at all, ai_tools only (tier 1).
//
// Plus opt-in exec-event reports (OptInWarning explains why they are not
// part of any profile).
//
// # Fail-closed policies and the two heartbeat windows
//
// A missing state database reads as zero rows, under ATC and under the
// extension alike, so a policy of the form "no bad row exists" would pass on
// a host where the sensor was never installed or its database was deleted.
// Every hawkbell policy therefore requires a fresh hawkbell_health.heartbeat. Two
// windows are used (design/BUILD-C.md section C5 and Addendum):
//
//   - the dedicated "sensor is reporting" policy uses AlertWindow (default 30
//     minutes) and is the one to alert on; the "hawkbell sensor unhealthy" label
//     uses the same window;
//   - every other hawkbell policy embeds GuardWindow (default 24 hours), so that
//     a removed sensor or a deleted database fails within a day without
//     turning every policy red each time a laptop wakes from sleep.
//
// A host whose hawkbell tables are not registered cannot run any of these
// queries (Fleet shows no response); the "hawkbell tables unavailable" label
// finds those hosts with osquery's own osquery_registry and file tables.
// The builtin profile has no heartbeat to check: its policies read Fleet's
// own ai_tools table, which is computed when queried.
//
// # Agent options
//
// agent-options.atc.yml is a fragment to merge into existing agent options,
// never a replacement: Fleet replaces the whole agent options document, and
// does not merge platform overrides with the base config, so applying the
// fragment as it stands drops existing ATC tables, decorators and options.
// Content.MergeAgentOptions performs the merge (verify.sh uses it against
// the live server's options) and StripAgentOptions undoes it;
// agent-options.example.yml shows the merged result on a typical base, and
// agent-options.base.example.yml the same base without hawkbell's tables: the
// agent options of the extension tier, which must not carry them (osquery
// refuses the extension when ATC already provides the hawkbell_* tables).
// ApplySpecs renders a profile as prefixed `fleetctl apply` documents for
// verification on a shared server, where `fleetctl gitops` (which resets
// everything a file omits) must not be used.
//
// # Unsupported
//
// Paths with an osquery wildcard or glob character (% * ? [ ] { }), control
// or formatting characters, or that are not absolute and clean for their OS
// (no empty, "." or ".." element, no trailing separator; backslashes only on
// Windows) are rejected: ATC expands patterns and reports canonical paths,
// while the "hawkbell installed" label compares paths exactly. Platforms other than linux,
// darwin and windows have no hawkbell build and get no ATC block. The macOS
// and Windows queries (es_process_events, process_etw_events, build_platform
// values) are checked against osquery's schema, not on those systems.
package fleetgen
