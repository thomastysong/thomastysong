// Package discovery inventories AI agents and everything that configures
// them, and reports posture facts about both. Every record is an inventory
// event (Kind inventory, Type inventory.asset, Source scan) with an Asset,
// User set to the owner and Host and Container stamped; Integrity is left
// to the caller, which knows whether it ran privileged.
//
// # What is found
//
//   - Agents, desktop apps, AI IDEs, model runtimes (catalog fingerprints):
//     catalogued install paths, binaries in well-known bin directories
//     (looked up by name, links read but not followed), npm global
//     package.json files (system prefixes, nvm, fnm, volta, bun, pnpm, yarn),
//     pipx venvs and uv tools, Homebrew Cellar and Caskroom, macOS
//     /Applications and ~/Applications Info.plist (XML and binary plists),
//     Linux .desktop files, Windows Uninstall registry keys, state
//     directories and, from Options.Processes, running processes. Each
//     source is an evidence class (Asset.Evidence); classes fall into four
//     channels (installer metadata, filesystem, state, runtime) and
//     Confidence is "high" only with two channels. An ambiguous binary name
//     (goose, q, amp ...) or a state directory several products share does
//     not identify anything alone. Versions come from metadata files only.
//   - Editor extensions: every VS Code-family extensions directory of the
//     catalogued editors (package.json publisher.name) and JetBrains plugin
//     directories (META-INF/plugin.xml, read from the plugin jar's zip
//     directory).
//   - Per agent and user, Asset.Telemetry: hooks managed | user | missing |
//     modified | unsupported | disabled (is spoor's own hook entry present in
//     the managed file or the user file, does it name another agent, is the
//     managed file writable by non-administrators, is a hooks kill switch
//     set); transcript found | none | relocated; native OTel enabled |
//     disabled | unsupported. A hook entry is spoor's only when every
//     command of the handler runs a spoor binary (spoor, spoor.exe) with
//     exactly "hook --agent <id>", in the exec form or one of the quoted
//     shapes hookinstall writes; the words alone prove nothing. For Claude
//     Code, spoor's entry in the managed-settings.d drop-in is reported
//     "modified" (Detail hooks_shadowed_by=mdm_policy) when an MDM policy
//     is present: with the default managedSourcesBehavior first-wins the
//     agent then ignores the file tier. A macOS profile that sets
//     managedSourcesBehavior to merge is honoured; the Windows policy value
//     is not read, and server-managed policy cannot be seen from disk.
//   - Settings posture: the catalog's Setting probes on managed, user and
//     project settings files, macOS managed preferences and Windows policy
//     keys. Hits add their flag to the agent's RiskFlags; hits in a project
//     file are added as "project:<flag>" (and to the project_config asset),
//     because a repository, not the user, chose them. Discovery adds
//     managed_policy_missing and managed_policy_world_writable (a managed
//     file, or the directory holding it, is not owned by root or is group or
//     world writable; a sticky bit does not excuse a drop-in directory).
//   - Files in an account's home that the owner rule refuses (see Safety):
//     a project_config asset each, risk flag untrusted_owner, with the
//     reason in Detail["untrusted_owner"] and no hash (never read).
//   - MCP servers from every catalogued config (user, managed, system,
//     project, plugin), parsed with mcpconf: Asset.MCP, the definition hash
//     as SHA256, mcpconf risk flags plus untrusted_location.
//   - Hooks declared in agent configs, one asset per handler, with the
//     definition hash, the command text in Event.Content (local only), shell
//     analyzer flags (hook_remote_fetch_exec, hook_encoded,
//     hook_runs_repo_script, hook_network_tool) and Detail["spoor"]="true"
//     on spoor's own entries. hook_runs_repo_script needs the analyzer to
//     see a repository file executed (./x.sh, "$CLAUDE_PROJECT_DIR"/x.sh,
//     %CLAUDE_PROJECT_DIR%\x.cmd); merely naming the project directory is
//     not enough.
//   - Skills (folder hash byte-compatible with uber/ADR), plugins (Claude
//     Code marketplace, version, commit pin and enabled state), subagents,
//     commands and rules/instruction files, with hidden_unicode,
//     injection_markers, dropper_text and quarantined flags.
//   - Project control files (kind project_config) and CI agents in GitHub
//     workflows (ci_untrusted_trigger), for projects enumerated from the
//     agents' own state: ~/.claude.json and transcript cwds, Codex
//     [projects] and rollout cwds, VS Code-family workspaceStorage,
//     Copilot session-state, the Gemini project registry. The disk is never
//     crawled. MaxProjects keeps the most recently used projects, ranked by
//     per-project evidence only (newest transcript or rollout, the
//     workspace's state database, the Gemini marker); a registry key has no
//     time of its own, since the agent rewrites the whole file. The home
//     (or a directory above it) is never scanned as a project, by Scan or
//     ScanProject: its files are the user's own configuration.
//
// # Differential inventory
//
// With Options.Prev (asset id -> SHA256 from the state store) records carry
// Change new or changed; unchanged assets are returned only with
// Options.Full. Assets of Prev that a complete scan did not see are
// returned with Change removed (only the id is known, so Asset.Kind is
// empty: downstream joins on the id). A scan is complete only when the
// ledger shows no error, refusal or skip and it was not truncated: a
// deadline or exhausted budget, an unreadable home, a parse error, a
// config or item directory that became a symbolic link (dotfile and skill
// managers), a path that resolves outside its root, a file over its cap,
// another user's file, and every cap that cut an enumeration short
// (MaxProjects, the transcript and rollout samples, truncated listings and
// globs) all count. Prev holds ids only, so a gap cannot be matched to the
// assets it declared last time: any gap suppresses every removal, and the
// ledger says why. Absence that proves nothing is never reported as
// removal; on hosts that always have a gap (a symlinked config, more than
// MaxProjects projects), downstream reconciles from the Options.Full
// snapshot instead. SHA256 is the content or definition hash of
// declared items; for catalogued products it is a digest of the
// observation (version, path, evidence, risk flags, telemetry): binaries
// are not hashed.
//
// # Safety
//
// Every file access goes through one gate. On Linux opens use openat2 with
// RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS below a home or project root and
// RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS inside Options.HostRoot, so a link
// planted in a container never makes the node sensor read a node file; on
// other unix systems and on kernels without openat2 paths are walked one
// component at a time with O_NOFOLLOW; elsewhere os.Root confines them. On
// Windows a file confined by os.Root is then opened with FILE_SHARE_DELETE
// (platform.OpenNoFollow) and the handle's final path is checked against the
// root's: Go's own open shares only read and write, which would make an
// agent's rename-over of its own config fail while the scanner reads it.
// The final component is never followed, opens are non-blocking (a FIFO
// named like a config cannot hang the scan), only regular files are read,
// config files are capped at 20 MiB. Inside an account's home (the home and
// projects below it) a file is read only when the account or root owns it
// and nobody else can write it (not world-writable; group-writable only
// with a group private to the owner, the umask 002 user-private-group
// setup), and a root-owned file there must have a single link (it may
// otherwise be a hard link the account made to a root file); this holds
// privileged or not, since the node sensor runs as an ordinary uid with
// read capabilities. A refused file is checked on the open descriptor, so
// none of its content is read, and is reported as a project_config asset
// with risk flag untrusted_owner (scope user, Parent the agent whose
// location holds it; scope project in a project). Outside the home (a
// project elsewhere), when privileged, a file must belong to the account.
// When privileged a directory must belong to the account before it is
// listed (checked on the open descriptor): another user's skill, plugin or
// extension names are not this user's assets. A skill is reported only
// after its SKILL.md was opened through that check. Personal directories
// (Documents, Desktop, Pictures, Mail, Messages, browser profiles, .ssh
// ...) are refused unless the catalog or an agent's project list points
// inside them (a project under ~/Documents is common; only its control
// files are read).
// Directory listings, ** walks, hashed bytes and the whole scan
// (Options.Deadline) are bounded; the listing and hashing budgets belong to
// each scope (the machine-wide pass, each home, each project), so one
// hostile home cannot starve the users scanned after it, and decoding
// Claude Code project names shares one cache of system listings and has a
// per-user listing budget. Decoders are measured before they run: TOML by
// a scanner that follows TOML's string and comment rules (nesting depth,
// dotted-key parts, value count: the TOML decoder recurses without a limit
// and its memory is quadratic in key parts), JSON on its comment-free text,
// YAML after parsing by its size, height and scalar bytes once aliases are
// followed (anchors are ordinary YAML and are read, expansion is bounded),
// binary plists by the string bytes each reference decodes to (shared
// objects are decoded once). Everything refused or skipped is counted in
// the Ledger. Names, versions and paths read from files are sanitized
// and credential-shaped text is redacted before it is emitted; config
// values are never emitted, only key names. Nothing found is ever executed:
// the package does not import os/exec (an import-graph test enforces it).
// Files are opened, read and closed in one step, so an agent's own rename or
// delete of a file is never blocked on Windows.
//
// # Not supported (reported as such, never guessed)
//
//   - Binary hashing and code-signature verification (Asset.Signer stays
//     empty).
//   - Browser extensions: browser profiles are personal directories.
//   - "env" settings probes: they describe a running process and belong to
//     the process monitor.
//   - POSIX ACLs (setfacl) that let another account write a file are not
//     read: the owner rule sees mode bits only.
//   - Windows: file ownership is not checked (ACLs, not uids), the
//     registry is read for Uninstall entries and policy-key existence only,
//     and the Windows code paths were compiled but not executed here.
//   - Options.HostRoot on Windows uses os.Root confinement (no openat2) and
//     plain os.Root opens (no FILE_SHARE_DELETE); Zone.Identifier is not
//     checked there.
//   - Download provenance (quarantined): the macOS quarantine xattr is read
//     on the gate's descriptor; the Windows Zone.Identifier stream is probed
//     by path (attributes only, sharing delete); Linux has no equivalent.
//   - Git worktrees whose .git is a file: their config is not followed.
//   - Codex hooks declared inside a project's config.toml are read; their
//     trust state (persisted per hook) is not.
//
// Data provenance: the skill folder hash and the negative-control and
// canary test methods follow uber/ADR (Apache-2.0); the CI agent action
// list is the catalog's (gha: packages), derived from uber/ADR's workflow
// extractor. No code was copied.
package discovery
