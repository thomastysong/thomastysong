// Package hookinstall plans, applies, removes and audits the hook
// registrations that make an AI coding agent invoke `spoor hook --agent <id>`.
//
// It never runs an agent or the hook binary and imports no os/exec: every
// decision is taken from the catalog (where an agent keeps its hook files),
// from internal/hookio (which events to register) and from the bytes already
// on disk.
//
// # What gets written
//
// Field names were re-read from the vendor sources on 2026-11-11; the source
// of each one is cited next to the code that emits it.
//
//   - Claude Code, managed: the drop-in managed-settings.d/50-spoor.json,
//     holding only {"hooks": {...}} (plus "env" when native OTel is opted
//     in). Handlers use the exec form ("command" + "args"), so no shell and
//     no quoting is involved on any OS. User scope merges into
//     ~/.claude/settings.json.
//   - Codex: the managed tier is a block of [[hooks.<Event>]] tables between
//     "# BEGIN spoor" and "# END spoor" in requirements.toml. Scope system
//     writes hooks.json beside the system config.toml, scope user writes
//     $CODEX_HOME/hooks.json. hooks.managed_dir and windows_managed_dir are
//     never written.
//   - Copilot CLI: policy.d/spoor.json (managed) or ~/.copilot/hooks/spoor.json
//     in the {"version":1,"hooks":{...}} format with one command per shell
//     field ("bash", "powershell").
//   - Gemini CLI: the hooks key of the system or user settings.json.
//   - Cursor: the enterprise or user hooks.json. UNVERIFIED: cursor.com was
//     not reachable; the format follows two independent code bases.
//
// Every registered handler carries an explicit timeout, the session-start
// event is always registered, and every spoor entry is recognisable because
// its command line contains " hook --agent ". Install, uninstall and Status
// only ever touch entries that carry that marker.
//
// # Editing other people's files
//
// JSON files are patched as text: the file is parsed into a tree that keeps
// byte offsets and the new entries are spliced in, so unknown keys, key
// order, number spelling and formatting outside the touched arrays survive
// byte for byte, and removing what was added gives the original bytes back.
// A file with comments or trailing commas (JSONC) is reported as unsupported
// unless Options.Force is set; with Force the same splice keeps the comments.
// A file that is not valid JSON or TOML is never rewritten.
//
// # Trust model
//
// Managed files are policy for every user of the machine, and user files
// belong to the person the sensor watches. Apply therefore refuses to write
// through a symbolic link, pins the parent directory with an os.Root before
// it compares and replaces the file (so a directory swapped for a link after
// the check cannot redirect the write), refuses to traverse a link that the
// monitored user planted when it runs as root, and re-checks that the file
// still holds the bytes the plan was computed from. Managed files and their
// directories are left root/admin-owned and not group- or world-writable;
// Status reports insecure_permissions when they are not.
//
// # Not supported (reported, never silently skipped)
//
//   - Agents without a hookio dialect, and agents whose catalog entry has no
//     hook path for the requested OS and scope: Action "unsupported".
//   - Fail-closed hooks exist only for Claude Code (onFailure) and Cursor
//     (failClosed); other agents get a Note. Copilot timeouts always fail
//     open, even for policy hooks.
//   - Native OTel settings are written only when Options.OTel is set, only
//     for Claude Code, Codex and Gemini CLI, and are refused when a telemetry
//     destination is already configured.
//   - Higher-ranked policy sources that are not files (Claude Code
//     server-managed settings, Codex cloud requirements, MDM payloads on
//     another OS) cannot be seen from disk. Status says what it checked.
//   - Windows 8.3 short names are not normalised when paths are compared.
//   - The Windows DACL and registry code is compiled and vetted for windows
//     but was not executed in the build environment (UNVERIFIED).
package hookinstall
