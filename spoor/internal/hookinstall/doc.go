// Package hookinstall plans, applies, removes and audits the hook
// registrations that make an AI coding agent invoke `spoor hook --agent <id>`.
//
// The API is PlanInstall / PlanUninstall (compute changes, write nothing),
// Apply (carry them out) and Status (audit what is on disk). The package
// never runs an agent or the hook binary and imports no os/exec: every
// decision is taken from the catalog (where an agent keeps its hook files),
// from internal/hookio (which events to register) and from the bytes
// already on disk.
//
// # What gets written
//
// Field names were re-read from the vendor sources on 2026-11-12; the
// source of each one is cited next to the code that emits it.
//
//   - Claude Code, managed: the drop-in managed-settings.d/50-spoor.json,
//     holding only {"hooks": {...}} (plus "env" when native OTel is opted
//     in). Handlers use the exec form ("command" + "args"), so no shell and
//     no quoting is involved on any OS. User scope merges into
//     ~/.claude/settings.json (or $CLAUDE_CONFIG_DIR/settings.json).
//   - Codex: the managed tier is a block of [[hooks.<Event>]] tables between
//     "# BEGIN spoor" and "# END spoor" in requirements.toml. Scope system
//     writes hooks.json beside the system config.toml (a managed layer that
//     needs no trust), scope user writes $CODEX_HOME/hooks.json (which Codex
//     runs only after the user trusts it in /hooks). hooks.managed_dir and
//     windows_managed_dir are never written.
//   - Copilot CLI: policy.d/spoor.json (managed) or ~/.copilot/hooks/spoor.json
//     in the {"version":1,"hooks":{...}} format with one command per shell
//     field ("bash", "powershell").
//   - Gemini CLI: the hooks key of the system or user settings.json.
//   - Cursor: the enterprise or user hooks.json, shared by the Cursor IDE
//     and CLI (one registration, --agent cursor). UNVERIFIED: cursor.com was
//     not reachable; the format follows two independent code bases.
//
// Shell strings: POSIX fields are single-quoted, which sh, bash, dash, zsh,
// ksh and fish all read the same way for a path without backslashes (the
// tests execute them through every POSIX shell installed, sh, bash and dash
// in the build environment, with a path holding spaces, '&' and an
// apostrophe); PowerShell fields use the call operator with a verbatim
// string; Windows fields that may also meet cmd.exe (Codex commandWindows,
// Cursor) are written bare when the path needs no quoting. A Windows install
// path without spaces is therefore the most portable choice.
//
// Every tool, prompt and session hook is registered synchronously with an
// explicit timeout (Options.Timeout, default 10 s): a background hook is
// killed when the session ends right after the event and its record is
// lost. Only notification-type events (PostCompact) may run in the
// background. The session-start event is always registered. Every spoor
// entry is recognisable because its command line contains " hook --agent ";
// install, uninstall and Status only ever touch entries that carry it.
//
// # Editing other people's files
//
// JSON files are patched as text: the file is parsed into a tree that keeps
// byte offsets and the new entries are spliced in, so unknown keys, key
// order, number spelling and formatting outside the touched arrays survive
// byte for byte, and removing what was added gives the original bytes back
// (property-tested and fuzzed). A file with comments or trailing commas
// (JSONC) is reported as unsupported unless Options.Force is set; with
// Force the same splice keeps the comments. A file that is not valid JSON or
// TOML is never rewritten. Known limit: an empty "hooks" object or event
// array that existed before install cannot be told apart from one spoor
// created, and uninstall removes it (which means the same to every agent).
//
// Uninstall deletes a file only when spoor's entries were all it held: an
// own drop-in, or a file left in exactly the state spoor creates it in. The
// Plan action for that is "remove", in addition to the spec'd create, merge,
// append, unchanged and unsupported.
//
// # Trust model
//
// Managed files are policy for every user of the machine, and user files
// belong to the person the sensor watches. Apply therefore refuses to write
// through a symbolic link; walks every directory from the file-system root
// (or Options.Root) one handle at a time, following a link only when root
// (or, for an unprivileged caller, the caller itself) made it and never
// below a host root; pins the final directory with an os.Root; and re-checks
// that the file still holds the bytes the plan was computed from (ErrChanged
// otherwise). When root edits a user's file it keeps the user as owner and
// refuses a file owned by a third uid. Each write is a temporary file plus a
// rename, the previous bytes are kept as <name>.spoor-<UTC time>.bak, new
// files get mode 0644 and new directories 0755, and an existing file keeps
// its mode (a settings file may hold credentials). Managed files and the
// directories between the system anchor (/etc, /Library/Application Support,
// ProgramData, Program Files) and the file are made root/Administrators
// owned and not group- or world-writable, repairing a directory a standard
// user pre-created; Status reports insecure_permissions otherwise, and a
// reinstall rewrites the file to repair it.
//
// # Status
//
// managed / user mean the file holds exactly what PlanInstall would write.
// That is not proof that the agent runs it. Status reports shadowed when a
// higher-ranked source makes the agent ignore the file (Claude Code MDM
// profile or HKLM policy under the default managedSourcesBehavior
// "first-wins"; allowManagedHooksOnly or allow_managed_hooks_only against
// user hooks), and Detail says what was checked and what cannot be seen from
// disk (server-managed settings, Codex cloud requirements, per-user trust).
//
// # Not supported (reported, never silently skipped)
//
//   - Agents without a hookio dialect, and agents whose catalog entry has no
//     hook path for the requested OS and scope: Action "unsupported".
//   - Another sensor's handler (numbat, Agent Beacon, Snyk Agent Guard) in
//     any of the agent's hook files: nothing is written unless
//     Options.Coexist is set.
//   - Fail-closed hooks exist only for Claude Code (onFailure) and Cursor
//     (failClosed, UNVERIFIED) and only with Guard; other agents get a Note.
//     Copilot timeouts always fail open, even for policy hooks, while a
//     preToolUse hook that cannot start denies the tool call.
//   - Native OTel settings are written only when Options.OTel is set, only
//     for Claude Code, Codex and Gemini CLI, and are refused (a separate
//     unsupported Plan) when a telemetry destination is already configured.
//   - A binary path containing '$' or '`' (agents substitute placeholders
//     before any shell sees the command), or a backslash on unix.
//   - Higher-ranked policy sources that are not files (Claude Code
//     server-managed settings, Codex cloud requirements, MDM payloads on
//     another OS) cannot be seen from disk. Status says what it checked.
//   - Windows 8.3 short names are not normalised when paths are compared.
//   - The Windows DACL, registry and os.Root rename code is compiled and
//     vetted for windows but was not executed in the build environment
//     (UNVERIFIED).
package hookinstall
