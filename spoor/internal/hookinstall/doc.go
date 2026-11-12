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
// string. Every shell command first checks that the binary is there:
//
//	[ -x '<bin>' ] || exit 0; exec '<bin>' hook --agent <id>
//	if (Test-Path -LiteralPath '<bin>' -PathType Leaf) { & '<bin>' hook --agent <id>; exit $LASTEXITCODE } else { exit 0 }
//
// A shell that cannot find the program exits 126 or 127. Copilot CLI
// denies a preToolUse call on any such exit and Gemini CLI reads it, with
// the shell's message on stderr, as a deny, so a removed, half-replaced or
// quarantined binary would block every tool call; Codex and Claude Code
// would show an error on every event. With the binary present the check is
// invisible: exec hands the process to spoor, so stdin, stdout, signals and
// the exit status are spoor's own, and PowerShell exits with $LASTEXITCODE
// (with -Command it otherwise turns any native exit code but 0 and 1 into
// 1). spoor hook itself exits 0 in every case and sends every decision, a
// Codex block included, as JSON (internal/hookcmd), so keeping the status
// matters only for one spoor does not choose, such as a kill. The check is
// a shell builtin and starts no process; the tests measure the whole
// invocation.
//
// Three kinds of field carry no check. Claude Code uses the exec form: no
// shell, and a binary that is not there is a spawn failure, which Claude
// Code treats as a non-blocking error unless onFailure is "block". A
// handler that asks the agent to block when it fails (Cursor failClosed)
// is written as exec '<bin>' hook --agent <id> (on Windows & '<bin>' hook
// --agent <id>, or bare), so a missing binary still blocks, as the
// operator asked. Windows fields that may also meet cmd.exe
// (Codex commandWindows, Cursor) are written bare when the path needs no
// quoting, which both shells run: no line was found that does the check
// and is valid in cmd.exe, Windows PowerShell 5.1 and PowerShell 7 alike
// (5.1 has no && or ||, and each parser rejects the other's if). The
// check is all the bare line lacks: spoor's replies, blocks included, are
// JSON on exit 0 (internal/hookcmd), so no exit code of spoor's is lost.
// With the binary missing,
// Codex shows a hook error on every event and does not block (it blocks
// only on exit 2). A path that needs quoting gets the PowerShell form,
// which has the check but which cmd.exe cannot run. Neither choice is
// right for both shells, and a plan for Codex on Windows says which one it
// made.
//
// Entries written by releases before the check are still spoor's: install
// replaces them, uninstall removes them, and Status reports them as
// modified with a Detail that names them as an earlier release's and says
// whether a command the agent runs on this OS lacks the check. It does not
// for Codex on Windows with a bare commandWindows: Codex runs only that
// field there, and both releases write it the same way.
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
// (property-tested and fuzzed). Removal parses the file once and applies
// every removal to a model of the containers involved, so its cost is
// linear in the file whatever number of entries it holds. A file with
// comments or trailing commas (JSONC) is reported as unsupported unless
// Options.Force is set; with Force the same splice keeps the comments,
// including a comment that is all an object or array holds (such a
// container is kept, emptied, on uninstall). A repeated key is resolved the
// way the agents resolve it, last one wins: spoor entries under an earlier
// "PreToolUse" that a later one hides do not count as installed, and
// install and uninstall remove them. A file that is not valid JSON or TOML
// is never rewritten. TOML is refused before it reaches the decoder when it
// is larger than 128 KiB or nested more than 16 levels (brackets, dotted
// keys and table headers together): the decoder's cost grows with both.
// Known limit: an empty "hooks" object or event array that existed before
// install cannot be told apart from one spoor created, and uninstall
// removes it (which means the same to every agent).
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
// otherwise). Every file read, the target and the files consulted beside it
// (managed settings, drop-in siblings, requirements, MDM profiles), goes
// through the same walk, so a link inside a container or a user's
// directory never makes this process read another tree; every directory on
// the way must be readable by the caller.
//
// When root edits a user's file it keeps the user as owner and refuses a
// file owned by a third uid or with more than one hard link (a link the
// user made to any other file; such a file is not read into the plan
// either). The user owns the directory and can swap any name in it for a
// hard link, which os.Root does not stop, so mode and owner of the new
// file and of the backup are set on the open descriptor, never by name.
// Each write is a temporary file plus a rename, the previous bytes are kept
// as <name>.spoor-<UTC time>.bak, new files get mode 0644 and new
// directories 0755, and an existing file keeps its mode (a settings file
// may hold credentials).
//
// Managed files and the directories between the system anchor (/etc,
// /Library/Application Support, ProgramData, Program Files) and the file
// are made root/Administrators owned and not group- or world-writable,
// repairing a directory a standard user pre-created. So are the other files
// the agent loads from those directories (Codex hooks.json, config.toml and
// requirements.toml beside each other, Claude Code managed-settings.json,
// managed-settings.d/*.json, managed-mcp.json and CLAUDE.md, Copilot
// policy.d/*.json, Gemini CLI system-defaults.json), because a standard
// user who pre-created the directory may have planted one: the plan names
// each such file (its content was written by a non-admin and needs review),
// and one that is a link or has several hard links is reported, not
// touched. Every change is made through a handle checked against what was
// examined: on unix an O_NOFOLLOW descriptor compared with lstat; on
// Windows a handle opened relative to the pinned directory with
// FILE_OPEN_REPARSE_POINT and OBJ_DONT_REPARSE, and SetKernelObjectSecurity
// on it, which resolves no path again and propagates nothing to existing
// children. Status reports insecure_permissions while any of these can be
// changed by a non-admin, and a reinstall rewrites the file to repair it.
//
// # Status
//
// managed / user mean the file holds exactly what PlanInstall would write.
// That is not proof that the agent runs it. Status reports shadowed when a
// higher-ranked source makes the agent ignore the file (Claude Code MDM
// profile or HKLM policy under the default managedSourcesBehavior
// "first-wins"; allowManagedHooksOnly or allow_managed_hooks_only against
// user hooks) or a switch turns every hook off (Claude Code disableAllHooks
// in the managed settings, the only level that reaches managed hooks, or in
// the user's own file for user hooks; Gemini CLI hooksConfig.enabled false,
// the system settings outranking the user's). Detail says what was checked
// and what cannot be seen from disk (server-managed settings, Codex cloud
// requirements, project settings, per-user trust). On macOS the Codex MDM
// profile (com.openai.codex under /Library/Managed Preferences) is looked
// for and its presence reported; its content is not parsed.
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
//     preToolUse hook that crashes or exits non-zero denies the tool call
//     (the missing-binary check keeps a missing binary from doing so).
//   - The missing-binary check is the shell's -x (PowerShell: a file
//     exists). In a POSIX shell a path that passes it but cannot run still
//     fails at exec: a directory, a truncated copy (dash even runs a
//     non-ELF file as a script, whose syntax error exits 2, a deny), or a
//     binary that Gatekeeper or an antivirus kills at exec. Replace the
//     binary by rename, never in place. fish before 3.0 has no ||. The
//     PowerShell lines are checked for shape by the tests but were not
//     executed in the build environment (UNVERIFIED by execution).
//   - A missing binary is now silent at the agent: Status audits the hook
//     files, not the binary they name, so the missing record of an active
//     agent (the coverage signal) is what shows it.
//   - Native OTel settings are written only when Options.OTel is set, only
//     for Claude Code, Codex and Gemini CLI, and are refused (a separate
//     unsupported Plan) when a telemetry destination is already configured:
//     in the file, in the managed settings, or for Codex user scope in the
//     system requirements.toml or config.toml. So that uninstall removes
//     only what install added, every member spoor writes must be absent
//     beforehand, except the owner's choices of Claude Code
//     OTEL_LOG_TOOL_DETAILS and Gemini logPrompts (kept as they are) and
//     the shared switch CLAUDE_CODE_ENABLE_TELEMETRY. Uninstall leaves that
//     switch in place while another OTEL_*_EXPORTER in env still needs it.
//     Known limit: a switch the user had set before install with nothing
//     using it, or OTEL_LOG_TOOL_DETAILS "1" / logPrompts false set before
//     install, is indistinguishable from spoor's and is removed too.
//   - A binary path containing '$' or '`' (agents substitute placeholders
//     before any shell sees the command), a backslash on unix, or bytes
//     that are not valid UTF-8 (JSON and TOML would carry U+FFFD instead).
//   - Higher-ranked policy sources that are not files (Claude Code
//     server-managed settings, Codex cloud requirements, MDM payloads on
//     another OS) cannot be seen from disk. Status says what it checked.
//   - Windows 8.3 short names are not normalised when paths are compared.
//   - The Windows DACL, registry and os.Root rename code is compiled and
//     vetted for windows but was not executed in the build environment
//     (UNVERIFIED).
package hookinstall
