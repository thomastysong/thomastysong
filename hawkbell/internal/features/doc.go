// Package features turns one normalized event into the flat set of facts
// detection rules match on. Compute fills Event.Feat (local only, never
// serialized); Fields returns the view a rule sees: every emitted event
// field by its JSON path plus every feature. Registry lists every name with
// its type and, where the values are a closed vocabulary, the vocabulary;
// the rule linter rejects a rule that names anything else.
//
// Rule packs depend on the exact names below. Adding a feature is
// compatible; renaming one silently disables every rule that uses it, so
// renames go through the linter's unknown-field error first.
//
// # Value types
//
// Every value is a string, bool, float64 or []string, except shell.cmds and
// shell.install_entries, which are []map[string]any and are read only by
// the any_command / any_install quantifiers of the rule language. Lists are
// de-duplicated, keep first-seen order (class lists are sorted) and hold at
// most 512 entries (shell.argv 4096, shell.cmds 4096 commands of up to 1024
// arguments). A field that does not apply to an event is absent, not
// empty: an empty list or string is never stored. Booleans of a family are
// all present (true or false) whenever the family applies, so a rule can
// say "shell.sudo: false" for a shell event.
//
// # Truncation is never silent
//
// Every cap is at least the cap of the analyzer feeding it, so a list is
// cut here only when several analyses were merged or an analyzer already
// stopped. A cut keeps the first and the last half of the entries (a
// payload appended after padding sits at the end), and every feature whose
// value is incomplete for any reason (a cut here, an analyzer that stopped
// early, a command line or argument walk seen only in part) is named in
// content.truncated_fields; an incomplete shell feature also sets
// shell.truncated. The rule engine fails closed on them: in_list ("every
// element is listed") does not hold on an incomplete list, and an operator
// suppression does not match one.
//
// # Shell (target.command of any tool that carries one, process.exec argv)
//
// From shellx.Analyze: shell.parse_ok, shell.dialect, shell.truncated (the
// analyzer or a shell list hit a cap: rules should treat it as a signal in
// itself), shell.commands ([]string of names), shell.argv (every literal
// argument), shell.cmds ({name, path, args, origin, dynamic} per command), shell.urls, shell.hosts, shell.host_classes, shell.reads,
// shell.writes, shell.deletes, shell.changes (paths changed other than by
// a content write or delete: touch, mkdir, md and install -d operands,
// chmod, chown, chattr, setfacl, setcap, icacls and Set-Acl targets, a
// non-zero truncate, the source of a move or rename, a mount point),
// shell.aliases (the existing path a new link or bind mount makes
// reachable under another name: ln's target, mount --bind's source,
// mklink's and New-Item's link target), shell.read_classes,
// shell.write_classes, shell.delete_classes, shell.change_classes
// (classify.PathClasses with the session cwd), shell.proc_root (read,
// write, delete, change, alias, execute: kinds of path operand named
// through a process's root directory, /proc/<id>/root or /proc/self/root),
// shell.interpreters, shell.inline_langs, shell.downloads,
// shell.pipe_to_interpreter, shell.download_and_execute, shell.eval,
// shell.sudo, shell.background, shell.heredoc, shell.dynamic (any command
// with an unresolvable expansion), shell.obfuscation, shell.opaque (eval,
// inline_code, heredoc_interpreter, dynamic_command, decoded_exec,
// process_substitution_exec, deep_nesting: constructs a static parse cannot
// see into, so rules score the opacity itself), shell.executes_paths
// (./x.sh, sh x.sh, python x.py, chmod +x targets), shell.destructive,
// shell.persistence, shell.defense_evasion, shell.cred_access, shell.exfil,
// shell.net_tools, shell.recon, shell.privilege, shell.git_ops (closed
// vocabularies from shellx.Vocabulary), shell.installs ("manager:package"),
// shell.install_entries ({manager, packages, global, exec, flags}),
// shell.install_managers, shell.install_exec (npx/uvx/bunx/pipx run style),
// shell.install_sources (registry and index URLs, URL and git package
// specs), shell.env_assign, shell.decoded, shell.has_secret and
// shell.secret_kinds (classify.FindSecrets over the command line).
//
// Every path list (shell.reads, shell.writes, shell.deletes,
// shell.changes, shell.aliases, shell.executes_paths, path.targets) holds
// canonical paths (internal/pathcanon): joined with the directory a cd,
// pushd or Set-Location earlier on the same command line set (file-tool
// paths with the session directory; shell paths stay relative to it, and
// the *_classes features classify them with it), "." and ".." resolved,
// duplicate separators collapsed, the trailing separator dropped, an
// unquoted one-character bracket glob ("[s]") replaced by its character,
// /proc/<id>/root (any id: a pid, self, $PID, $(...)) stripped (recorded in
// shell.proc_root and path.proc_root), \\?\ and \\.\ prefixes folded,
// Windows drive paths written with backslashes and an upper-case drive
// letter, and a home anchor followed by ".." resolved against the known
// home. Case is kept. So an anchored regex over these lists sees one
// spelling of a location. The operand as written stays in target.command,
// in shell.cmds and shell.argv, and in target.path and target.paths.
//
// # Paths (file_read, file_write, file_edit, file_list tools)
//
// path.classes (union over target.path and target.paths, classified in
// canonical form), path.targets (target.path and target.paths in canonical
// form, relative ones joined with the session directory), path.proc_root
// (a target went through a process's root directory), path.sensitive_read
// (a read or list tool and a credential class), path.sensitive_write (a
// write or edit tool and a persistence or control class), path.outside_cwd,
// path.control_file (agent_*, mcp_config, vcs_*, startup_item), path.ext
// (".json"), path.normalization_evasion (the path names an agent control
// file only after case folding, trailing dot/space or ADS removal, or 8.3
// expansion; always false on Linux, where those are different files).
//
// # Network (web tools, URLs in shell commands and MCP arguments)
//
// net.host ([]string: every host, lower-case), net.host_classes,
// net.scheme ([]string), net.is_ip, net.url_has_secret, net.query_len (the
// longest query string).
//
// # Content (local only)
//
// prompt.secret_kinds, prompt.hidden_unicode, prompt.markers (prompt.submit);
// write.secret_kinds, write.hidden_unicode, write.markers, write.autorun
// (content written to a control file that makes an agent or IDE run
// something or widens permissions), write.autorun_kinds (hook_command,
// always_apply, folder_open_task, mcp_server, permission_escalation,
// base_url_override, hooks_disabled, sandbox_disabled; mcp_server comes
// from decoding the file with internal/mcpconf, which knows every agent's
// server key, and needs at least one entry that declares something to
// launch), write.exec_keys (git exec-sink keys written to a git config:
// core.fsmonitor, core.sshcommand, core.askpass, alias.shell, filter.clean,
// credential.helper (an absolute program) ...); output.markers, output.hidden_unicode,
// output.secret_kinds, output.untrusted (the result of a web fetch or
// search, an MCP or browser tool, a read under node_modules, vendor,
// Downloads or tmp, `gh issue|pr view`, `gh api`, or a shell download) and
// output.untrusted_source. Every web fetch sets output.untrusted, package
// registries and CDNs included (they serve whatever their publishers
// upload); rules discount trusted hosts visibly, through net.host,
// net.host_classes or a list. content.truncated_scan is set when a value
// over 128 KiB was scanned head 64 KiB + tail 64 KiB only;
// content.analyzer_error when an analyzer failed (the features are then
// incomplete, never wrong); content.truncated_fields names incomplete
// features (see above).
//
// # MCP calls
//
// mcp.server, mcp.tool, and from a walk of the tool input (depth 8, 4096
// strings, 1 MiB): mcp.arg_paths, mcp.arg_path_classes, mcp.arg_hosts,
// mcp.arg_host_classes, mcp.arg_secret_kinds.
//
// # Scripts written, then run (WrittenScripts, AnalyzeScript, Inherit)
//
// A command written into a script by a file tool and run in a second event
// ("sh /tmp/x.sh") would hide every shell fact from single-event rules.
// WrittenScripts takes a file_write or file_edit event (Write, Edit,
// MultiEdit, Copilot create/str_replace/insert, Gemini replace, Codex
// apply_patch split per file) and, for each file whose content is a
// script, returns ScriptFacts: the shell.* and net.* features a shell event
// carrying that content would get. A script is content with a #! line
// naming a known interpreter, a file with a script extension (.sh .bash
// .zsh .ksh .csh .tcsh .fish .command .ps1 .psm1 .bat .cmd .py .pyw .js
// .mjs .cjs .ts .mts .cts .rb .pl .pm .php .lua), or a file with no
// extension (or one that is not a document, data or compiled-language
// source format) whose content parses as POSIX shell. Shell content (csh,
// tcsh and fish read as POSIX shell), PowerShell and cmd content is
// analysed in its dialect; Python, JavaScript, Ruby, Perl, PHP and Lua
// content as the program an interpreter reads from a quoted heredoc, in
// pieces of at most 30 KiB (what shellx sees through: shell commands handed
// to exec-style calls, URLs, decoded payloads, reads), minus what the
// synthetic wrapper itself contributes, plus a POSIX analysis when the text
// parses as shell ("bash x.py"). Only a patch tool's input that starts with
// "*** Begin Patch" is read as an apply_patch envelope; the content of a
// write is always that file's.
//
// The analysis runs inside the event's time budget (ScriptOptions.Stop):
// the first piece of text and the last 8 KiB are always analysed, the rest
// while the budget lasts, and what is skipped is recorded as incomplete
// (Cut, shell.truncated). The credential scan of a written file reuses the
// one Compute made of the same content.
//
// ScriptFacts are bounded (3 KiB of strings, 96 commands of 32 arguments,
// 64 entries per list) and validated as hostile input when they come back
// from a session state file. What the bounds shed is ordered by value
// (ScriptOptions.Keep, which the rule engine fills from its rules):
// duplicate and inert commands first, then commands and list values no
// rule matches, and only then, head and tail kept, the ones a rule
// matches; every cut is recorded. So a script padded with hundreds of
// ordinary lines keeps the line a rule needs, unless the rule-matched
// commands alone exceed the bounds. Credentials are redacted in every
// argument, path and value ("[REDACTED:<kind>]", no fingerprint); their
// kinds stay in shell.secret_kinds.
//
// An edit sends only its new text, which can be harmless alone and
// dangerous in the line it lands in ("| cat" replaced by "| sh"). When the
// engine holds the file's text (WrittenScript.Keep: the whole text of a
// script of at most 8 KiB with no credential in it, kept in session state)
// the edit is applied to it as the tool applies it (old/new replacement,
// insert, patch hunks) and the whole result is analysed (InContext).
// Otherwise the new text is analysed on its own and its facts are a
// Fragment; an event that inherits them carries shell.inherited_kinds =
// edit_fragment and shell.cmds is recorded as incomplete.
//
// The rule engine keeps the facts per normalized path and, when a later
// shell command or process.exec runs that path, calls Inherit: the
// script's facts are merged into the executing event's features (lists
// unioned, booleans ORed, commands appended to shell.cmds),
// shell.inherited_kinds is set to written_script, and output.untrusted is
// recomputed for a shell result. The parsed-fact rules then fire on the
// execution event as on the content, within the bounds above. No file is
// ever opened: the content is what the tool call carried, so a script
// changed outside the agent's file tools (a shell redirect, an editor, a
// download) is known only by the facts of the last tool write.
//
// # Filled by the rule engine
//
// session.flags, session.tool_calls, session.prompts, session.age_s,
// session.first_event, session.runs_written_file and
// session.written_exec_path (write-then-run across events),
// shell.inherited_kinds (the event's shell facts include a written
// script's: written_script, edit_fragment; see above),
// session.secret_flow and session.secret_flow_kinds (a value read from a
// credential-class path leaves in a later command, URL or MCP argument),
// session.secret_flow_truncated (that outbound data was too large to scan
// whole), and host.tags. They are in the registry so rules referencing them lint clean.
//
// # Limits
//
// Everything here is lexical: no file is opened, no name resolved, nothing
// executed. Symlinks are not resolved, so a harmless-looking path can still
// point at a sensitive file; a link or bind mount created on the same
// command line is followed (an operand through it is recorded both as
// named and as the path it reaches; shell.aliases holds what it points
// at), one created by an earlier tool call is not. A cd to a directory the analysis cannot
// resolve ("cd $X") leaves later relative paths as written. 8.3 short
// names are matched by their generated prefix only. Content features see what the source captured: tool output
// truncated by the agent is scanned as truncated.
//
// # Start-up cost
//
// Linking this package costs almost no package init work: only the two
// exported 5-entry maps CommandKeys and InstallKeys, which other packages
// index directly (about a microsecond). `hawkbell hook` starts two
// processes per agent event and Go runs every linked package's init before
// main, so compiled regexps, map literals and computed tables here would be
// paid by processes that never compute a feature (the hook supervisor, an
// observe-mode worker). The autorun regexps compile on the first Autorun
// call, the field registry and its vocabularies are built on the first
// Registry or Lookup call, the event field plan on the first Fields call,
// and fixed membership sets are switch statements. Keep it that way: a
// package-level var whose initializer calls a function or is a map literal
// shows up in GODEBUG=inittrace=1 output for every hawkbell process.
package features
