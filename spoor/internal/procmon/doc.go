// Package procmon is spoor's OS-side view of AI agents: which agent
// processes run, under what flags and parents, and which processes they
// start. It corroborates what hooks and transcripts (both written by the
// agent, as the user) report, and it sees agents that have neither.
//
// # Model
//
// The monitor keeps a table of every visible process with a handful of
// fields (pid, parent, start time, name, executable, uid, the agent marker
// variables in its environment). An agent root is a process the catalog
// identifies as a product of kind "agent" (catalog.MatchProcessDetail: name,
// install path, package path or command-line evidence). Every process below
// a root belongs to the nearest root above it; the decision is made when
// the process is first seen and kept when the process is re-parented to
// init, because a daemon an agent started is still the agent's doing.
// Process identity is (pid, start time): a recycled pid is a new process.
//
// Nesting rules: a process of the same agent directly under a root is that
// root's helper or relaunch (Gemini CLI re-executes itself); the payload of
// a launcher root (npx, uvx, bunx naming the package) is the same agent;
// any other agent below an agent is a nested agent with its own root
// (AgentProc.ParentAgent, rule R47).
//
// IDEs and desktop apps (catalog kinds other than "agent") are not roots:
// most of what runs under an editor was started by a person. Their agent
// runs are attributed through the marker variables the catalog lists
// (CURSOR_AGENT, CLAUDE_CODE_IS_COWORK, ...). Markers come in two
// strengths. A verified marker (an agent's session variable, or an
// EnvMarkers entry the catalog does not mark unverified) is set by the
// product itself: a process carrying one is reported as process.exec with
// labels.attribution=env_marker. A weak marker (an unverified name, or a
// switch a user can export for a whole shell, such as COPILOT_MODEL) is in
// every process of that shell, so it only answers Attribute, with Evidence
// "env_marker_weak", and never produces an event; today every app marker
// in the catalog is weak. Marker attribution also covers agents the
// catalog cannot identify (a renamed or rebuilt binary): when a process
// carries a strong marker (a verified marker of an agent) and its parent
// does not, the parent is the agent and becomes a root with Evidence
// "env_marker". This is the marker-boundary technique from the OS
// telemetry research; it fails against an agent whose children's
// environment is scrubbed.
//
// # Exec providers
//
// In order of preference:
//
//  1. cn_proc, the Linux netlink process connector (Options.ExecEvents).
//     Fork, exec and exit events for every process on the host; on exec the
//     monitor reads /proc/<pid> at once, in the reader goroutine, before a
//     short-lived process is gone. A netlink overrun (ENOBUFS) marks the
//     table for a rescan; overruns come in storms (a parallel build), so
//     the marks are coalesced into one full scan no sooner than Idle (or
//     twenty times the last scan's duration) after the previous one. A
//     full rescan runs every 30 s regardless. Messages
//     not sent by the kernel (netlink port id 0) are dropped. Needs root,
//     or kernel 6.6+, and the initial user and pid namespaces (the kernel
//     ignores LISTEN from elsewhere without an answer; the monitor waits
//     one second for the acknowledgement and falls back).
//  2. osquery (internal/osqexec): exec rows from a running osqueryd's
//     evented process table over its extension socket, attributed through
//     the same table (exited processes stay answerable as tombstones for
//     two minutes, because rows arrive 2 to 15 s after the exec). Rows are
//     rate-capped on their own event time, not on arrival, so a delivery
//     batch is not mistaken for a burst. The connection is closed when Run
//     returns and while the kill switch is on.
//  3. poll: the process table is listed every Idle interval (2 s), and the
//     descendants of live roots every Active interval (200 ms) through
//     /proc/<pid>/task/<tid>/children. Polling sees agent roots and
//     long-lived children; it misses most processes shorter than the
//     interval (measured: 7 of 120 short processes at 1 s), so it is not
//     exec ground truth and ExecHealthy is always false under it.
//
// A scan notices an exec it was not told about by a changed kernel name.
// npm, yarn, pnpm and every setproctitle(3) user rename themselves after
// exec, so a changed name counts as an exec only when the executable
// changed too, or when the name went back to the one the kernel gives on
// exec (the program's or the interpreted script's base name). Otherwise
// the process is re-read without a process.exec, and an agent root that
// renames itself stays the root it was.
//
// Polling runs under every provider: it finds agents that were running
// before the monitor started and repairs the table after overruns. A scan
// never takes more than about 5% of a core: its interval stretches to
// twenty times its own duration on hosts with very many processes.
//
// # Exec self-test
//
// A provider can report itself active while delivering nothing. Every five
// minutes the monitor runs /usr/bin/true (cmd.exe /c rem on Windows) with a
// random nonce argument, directly with os.StartProcess (this package does
// not import os/exec), and checks that the active provider reported that
// exec within 5 s (cn_proc) or 90 s (osquery). ExecHealthy reports the
// result. The canary itself is never emitted. A process is taken for the
// canary (and so not ingested) only while a test is pending, only when its
// parent is this process and its arguments carry the nonce, and, once
// StartProcess has returned, only with the canary's pid; nonce and pid are
// forgotten as soon as the test settles. Any local user can read the
// nonce while the canary runs, but cannot make a process the monitor's
// child. On Unix the program must be one only root can have put there:
// os.StartProcess resolves the path again, so every name on the way is
// checked, each directory root-owned and not group or world writable (a
// sticky directory is accepted, as only root can replace root's entries in
// it) and each link root-owned. Directory links such as /bin -> usr/bin are
// followed under that rule; the program may be one link (busybox's
// /bin/true) whose target is a regular file. Without such a program
// ExecHealthy stays false. With HostRoot the canary's pids are not the
// ones the host-side providers report, so the self-test does not pass
// there.
//
// # Events
//
// agent.process.start (TS = process start, deterministic id so a sensor
// restart re-reports an agent with the same id), agent.process.stop
// (Outcome carries the exit status when the connector saw the exit), and
// process.exec for every process an agent root (or a verified marker) owns.
// All carry
// Source process (osquery rows keep Source osquery), Fidelity observed,
// Integrity root when the monitor runs privileged. AgentProc attributes
// without a contract field are labels: headless, bare, hook_free,
// persistence_free, lifecycle_parent, config_home, parent_agent, evidence.
// A process.exec of a process that is itself an agent (a nested agent, a
// relaunch, the payload of an npx-style launcher) carries its risky flags
// in Process.Flags. A launcher root's AgentProc absorbs its payload's
// flags and modes (the launcher's own command line is the package runner's,
// or an npm process title that has swallowed the arguments); the start
// event has gone out by then, so Agents, Attribute and the stop event show
// the merged view.
// process.exec events are capped at 20 per second per agent root (500 per
// second overall); the number dropped is attached as labels.exec_dropped to
// the next event of that root and counted in Stats.RateDropped.
//
// # What is read and what is emitted
//
// Command lines go through classify.RedactArgs first and are bounded
// after (64 arguments, 1 KiB each, 8 KiB in all): bounding first would cut
// a value inside long inline JSON (claude --mcp-config, --settings) before
// its closing quote, and the head of the secret would no longer be
// recognised. A cut argument ends in a "[TRUNCATED:<n>B]" marker (a cut
// never splits a "[REDACTED:...]" marker), dropped arguments are replaced
// by one final "[TRUNCATED:<n>B]" placeholder counting their bytes, and an
// argument cut by the 256 KiB command-line read limit is never emitted;
// every cut is listed in Truncated. The process.exec id covers pid, start
// time, executable and the emitted arguments, the arguments through a
// domain-separated HMAC with the redaction fingerprints left out: the
// privacy stage may redact more than the monitor does, and an unkeyed
// digest of the monitor's form would let a reader of the shipped record
// test guesses for what privacy removed. The key is Options.IDKey (the
// daemon passes its persisted identity key, so the id of a live process a
// restarted sensor reports again is the id it had, and downstream
// deduplication collapses the two) or, without one, 32 random bytes drawn
// once per process (ids then hold for one run). The id's time is the
// process's start, so the connector's record of an exec and a rescan's
// record of the process agree. Process names get the same redaction (split on
// white space) wherever they are kept or emitted (Process.Name, Ancestors,
// AgentProc.Name): a Node process title or setproctitle(3) writes the
// whole command line over argv[0], and the name refined from it, or the
// kernel's first 15 bytes of it, carries that command line. What the
// redaction cannot see in 15 bytes (the start of a vendor token whose
// pattern needs more) can remain in a kernel name.
// Environments are read (at most 256 KiB) to find marker variable NAMES;
// the only values kept are session ids (only when they look like plain
// identifiers) and HomeEnv overrides such as CLAUDE_CONFIG_DIR. npm's
// lifecycle variables and VS Code's VSCODE_CRASH_REPORTER_PROCESS_TYPE (of
// the agent, and of Electron utility processes above it) are read to decide
// LifecycleParent and then dropped. npm_lifecycle_event=npx, which
// everything npm exec / npx runs inherits, is not a lifecycle parent (a
// person or program chose to run the agent); the ancestors decide, so a
// package script that ran npx is still found above it. A Node process
// title that replaced the whole argv ("npm exec @openai/codex --yolo") is
// split on white space for flag detection; what is emitted is the redacted
// title. Nothing read from a process is ever executed or opened as a path.
//
// # Kill switch
//
// While platform.Disabled() is true the monitor stops every provider and
// emits nothing; Stats.Disabled says so, and Source stays within cn_proc |
// osquery | poll (poll: nothing better runs). Attribute then answers from
// the table as it stood, without reading /proc or queueing events. When
// the file goes away the monitor rescans and carries on.
//
// # Platforms and limits
//
//   - Linux: procfs is read directly for the cheap identity pass (one stat
//     read per process) and children lists; full records come from
//     internal/platform so start times match every other spoor component.
//     With Options.HostRoot (a sensor container that has the host's /proc
//     mounted at <HostRoot>/proc instead of sharing the host pid namespace)
//     everything is read from that mount, user names from
//     <HostRoot>/etc/passwd. cn_proc is unavailable in that layout (it
//     needs the initial pid namespace).
//   - macOS and Windows: every scan is platform.Processes; there is no
//     children shortcut, so the Active interval stretches with scan cost.
//     cn_proc does not exist; osquery (es_process_events,
//     process_etw_events) is the only exec provider. These code paths are
//     compiled and vetted but were not executed where this package was
//     built. macOS withholds the environment of hardened processes even
//     from root, which blinds marker attribution there.
//   - Reading another user's environment needs root (or CAP_SYS_PTRACE);
//     unprivileged, only the monitor's own user's processes have markers,
//     session ids and config homes. Stats.ProcsTotal and
//     Stats.ProcsUnreadable (the daemon's heartbeat counters procs_total
//     and procs_unreadable) count, at every full scan, the live user-space
//     processes (kernel threads left out) and those that refused the
//     monitor with EACCES or EPERM, so a sensor that is missing the
//     privilege shows it. A process refuses either its environment (the
//     common case) or, with /proc mounted hidepid=1 (noaccess), every file
//     under /proc/<pid> including stat: such a pid is still counted, in
//     both and in Stats.ProcsHidden (procs_hidden), kernel threads
//     included because nothing tells them apart there. With hidepid=2
//     (invisible) other accounts' pids are not even listed and cannot be
//     counted. Stats.ProcsProtected (procs_protected) is the part of
//     ProcsUnreadable that refused a monitor holding the read privilege
//     and runs as the system account (uid 0; on Windows LocalSystem, LOCAL
//     SERVICE, NETWORK SERVICE or an unreadable owner): Windows protected
//     processes, a sandbox's init (the build environment's pid 1 refuses
//     root). No privilege the sensor can be given opens those, so the
//     daemon does not degrade the processes surface for them alone.
//     macOS and Windows counts are UNVERIFIED (not executed).
//   - spoor's own hook processes (`spoor hook`, `spoor hook --worker`,
//     recognised by argv[1] and the running image, see self.go: on Linux
//     the file identity of /proc/<pid>/exe, on macOS and Windows the
//     kernel's name of the image, which must be one of spoor's trusted
//     paths, and the identity of the file there) are kept in the table but
//     never reported; other spoor commands an agent runs are reported like
//     any program. A spoor binary path is trusted only when only root (or
//     the sensor's account) can change what it names
//     (platform.TrustedPath), so hooks are reported where spoor is
//     installed in a directory another account can write to (on Intel
//     Macs with Homebrew, /usr/local/bin belongs to the Homebrew user).
//   - cn_proc reports exec after it happened; a process that exits within
//     microseconds can be gone before /proc is read (Stats.ReadMisses).
//   - HookFree cannot see Gemini CLI's hooksConfig.enabled=false: it is a
//     settings-file key, reported by discovery as the hooks_disabled risk
//     flag, not visible on the command line or in the environment.
//   - The headless, bare, hook-free and persistence-free tables in
//     traits.go cover claude-code, codex, gemini-cli, copilot-cli,
//     cursor-agent and kiro-cli; entries not checked against a primary
//     source are marked UNVERIFIED there, as are the URL handler list and
//     the macOS "Helper (Plugin)" rule in lifecycle.go. The VS Code
//     extension-host test (environment, not command line: the terminal's
//     pty host has the same command line) was checked against VS Code's
//     source; an extension host whose environment cannot be read (another
//     user's process while unprivileged, hardened processes on macOS) is
//     only recognised through the agent's inherited environment.
//   - osquery rows are attributed by pid; a pid reused within the seconds
//     before a row arrives can be attributed to the wrong process (the same
//     limit internal/osqexec documents).
package procmon
