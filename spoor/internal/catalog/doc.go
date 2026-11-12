// Package catalog holds the product fingerprints spoor uses to recognise AI
// agents, AI IDEs, desktop AI apps, model runtimes, editor and browser
// extensions, and CI agents. Adding a product is a data change: every
// fingerprint lives in the YAML files under data/, embedded at build time.
//
// # Trust model
//
// The embedded data is trusted. Everything a caller passes in is not: process
// names, executable paths and command lines come from machines where the
// attacker controls agent output, and the environment map given to Expand is
// usually the environment of an agent process. Those inputs are bounded,
// never executed, never used to touch the filesystem, and never allowed to
// panic out of the package.
//
// Overlay files (LoadOverlay) are administrator configuration. They are read
// as regular files only (symlinks and world-writable files are refused), are
// size-bounded, and are validated with the same rules as the embedded data
// before they replace anything. An overlay that fails validation leaves the
// catalog exactly as it was.
//
// # Adding a product
//
// Add an entry to the data file for its category (agents, ides, desktop,
// runtimes, extensions, browsers). The keys are the YAML spellings of the
// Product fields. Path lists take the same paths for every OS as a plain
// list, or a mapping keyed by all, posix, linux, darwin and windows. Paths
// may use ~, $VAR, %VAR% and ${VAR:-default}; the last form is how a
// relocatable state directory is written
// ("${CODEX_HOME:-~/.codex}/sessions/..."). List where each fact came from
// in sources and name every field you could not check in unverified. Load
// (and the package tests) reject unknown keys, generic binary names,
// fingerprints shared without mutual aliases and paths that are not rooted.
//
// A site can add or override products without rebuilding by dropping YAML
// files of the same shape into a directory given to LoadOverlay.
//
// # Cost
//
// The first Load in a process parses the embedded YAML, which takes about
// 12 ms; later calls share the parsed data and cost nothing. The hook entry
// point runs once per agent event and should not load the catalog.
//
// # Identity needs two kinds of evidence for short names
//
// A process called goose, amp, q, agent or gemini is very often not an AI
// agent (a database migration tool, a text editor, a DNS client). MatchProcess
// therefore refuses to identify a process from an ambiguous name alone; it
// needs a second, independent class of evidence: an install path specific to
// the product, a package directory in the executable or script path, or a
// command-line pattern. A path never identifies a process on its own, with
// one exception: the main executable of a catalogued macOS app bundle, whose
// file name is arbitrary (Visual Studio Code runs as "Electron"). All path
// evidence is lexical; checking a code signature against Product.Signers is
// the caller's job. The list of ambiguous names is data
// (ambiguous_names in the YAML files); names of one or two characters are
// always ambiguous.
//
// # Shared fingerprints must be declared
//
// Load rejects a catalog in which two products claim the same fingerprint
// (binary or process name, package, bundle id, extension id, state directory
// and so on) unless both products list each other's id in Aliases. The rule
// keeps accidental collisions out and makes the real ones (ChatGPT.app and
// the Codex CLI share ~/.codex; the Kiro IDE and Kiro CLI share ~/.kiro)
// visible to whoever consumes a lookup result.
//
// # Unverified facts
//
// Product.Unverified names the fields whose values could not be checked
// against a primary source when the entry was written. Consumers that would
// act on a wrong value (signature pinning, writing hook files) should call
// Product.IsUnverified first and degrade to reporting.
//
// # Not supported
//
//   - The catalog never executes a discovered binary and has no version
//     probes; versions come from package metadata read by the scanner.
//   - Hooks.Dialect is limited to the five dialects spoor implements (claude,
//     codex, copilot, gemini, cursor). Other agents that have a hook system
//     are recorded with an empty dialect: their hook files are inventoried
//     and watched, but spoor does not install into them.
//   - Glob patterns support *, ? and ** only; character classes are matched
//     literally.
//   - Windows registry and macOS managed-preference probes are described in
//     Settings (formats "registry" and "plist") but reading them is the
//     platform layer's job, not this package's.
package catalog
