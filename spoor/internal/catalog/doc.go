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
// # Identity needs two kinds of evidence for short names
//
// A process called goose, amp, q, agent or gemini is very often not an AI
// agent (a database migration tool, a text editor, a DNS client). MatchProcess
// therefore refuses to identify a process from an ambiguous name alone; it
// needs a second, independent class of evidence: an install path specific to
// the product, a package directory in the executable or script path, or a
// command-line pattern. The list of ambiguous names is data
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
