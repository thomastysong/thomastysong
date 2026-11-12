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
// most 64 entries. A field that does not apply to an event is absent, not
// empty: an empty list or string is never stored. Booleans of a family are
// all present (true or false) whenever the family applies, so a rule can
// say "shell.sudo: false" for a shell event.
//
// # Shell (target.command of any tool that carries one, process.exec argv)
//
// From shellx.Analyze: shell.parse_ok, shell.dialect, shell.truncated (the
// analyzer hit a cap: rules should treat it as a signal in itself),
// shell.commands ([]string of names), shell.argv (every literal argument,
// capped at 256 x 1 KiB), shell.cmds ({name, path, args, origin, dynamic}
// per command), shell.urls, shell.hosts, shell.host_classes, shell.reads,
// shell.writes, shell.deletes, shell.read_classes, shell.write_classes,
// shell.delete_classes (classify.PathClasses with the session cwd),
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
// # Paths (file_read, file_write, file_edit, file_list tools)
//
// path.classes (union over target.path and target.paths), path.sensitive_read
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
// base_url_override, hooks_disabled, sandbox_disabled), write.exec_keys (git
// exec-sink keys written to a git config: core.fsmonitor, core.sshcommand,
// alias.shell, filter.clean ...); output.markers, output.hidden_unicode,
// output.secret_kinds, output.untrusted (the result of a web fetch or
// search, an MCP or browser tool, a read under node_modules, vendor,
// Downloads or tmp, `gh issue|pr view`, `gh api`, or a shell download) and
// output.untrusted_source. Package-registry fetches do not set
// output.untrusted. content.truncated_scan is set when a value over 128 KiB
// was scanned head 64 KiB + tail 64 KiB only; content.analyzer_error when an
// analyzer failed (the features are then incomplete, never wrong).
//
// # MCP calls
//
// mcp.server, mcp.tool, and from a walk of the tool input (depth 8, 4096
// strings, 1 MiB): mcp.arg_paths, mcp.arg_path_classes, mcp.arg_hosts,
// mcp.arg_host_classes, mcp.arg_secret_kinds.
//
// # Filled by the rule engine
//
// session.flags, session.tool_calls, session.prompts, session.age_s,
// session.first_event, session.runs_written_file and
// session.written_exec_path (write-then-run across events),
// session.secret_flow and session.secret_flow_kinds (a value read from a
// credential-class path leaves in a later command, URL or MCP argument), and
// host.tags. They are in the registry so rules referencing them lint clean.
//
// # Limits
//
// Everything here is lexical: no file is opened, no name resolved, nothing
// executed. Symlinks are not resolved, so a harmless-looking path can still
// point at a sensitive file; 8.3 short names are matched by their generated
// prefix only. Content features see what the source captured: tool output
// truncated by the agent is scanned as truncated.
package features
