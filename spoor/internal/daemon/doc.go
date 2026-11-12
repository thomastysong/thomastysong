// Package daemon is `spoor run`: the long-running, privileged sensor that
// wires every collector to the detection pipeline and keeps the local stores
// (outbox, local ring, state database, checkpoints) within their limits.
//
// # Contract
//
// Run blocks until its context is cancelled, then stops the collectors,
// closes the pipeline (which processes what is queued, releases held records
// and writes a last heartbeat), flushes and closes the sinks and the state
// database, and returns. Status reads the same installation from disk for
// `spoor doctor` without talking to a running daemon.
//
// # What runs
//
//   - Hook spool: spool.Reader over every user's system spool directory
//     <data>/spool/<uid>/ (created 0700, owned by the user) and over the
//     user's own fallback spool (platform.UserDirs(home).Spool), which hooks
//     use when they cannot reach the system one. Identity comes from the file
//     owner; reader problems are counted per kind, hook supervisor failures
//     as hook_errors.<reason> for hookcmd's own reasons and hook_errors.other
//     for anything else a spool claims (its user can write any code there).
//   - Transcripts: transcript.Tailer with transcript.HomeRoots for every user
//     plus transcript.ConfigRoots for configuration homes the process monitor
//     sees in agents' environments (CLAUDE_CONFIG_DIR, CODEX_HOME, ...).
//     Files that exist when a root is first seen are started at their end:
//     no retroactive collection of what happened before spoor was deployed
//     (sources.transcripts.backfill opts into reading back). Only the new
//     root is primed: files created since in roots already followed are read
//     from their first line. A root is "first seen" once per data directory:
//     the admitted roots are remembered in the checkpoint directory, also
//     while they are not listed (a configuration home is listed again only
//     once the process monitor sees an agent using it after a restart), and
//     forgotten after seven days unlisted, so a restart does not skip what
//     was written while the daemon was down.
//   - Processes: procmon (Linux process connector, then osquery's evented
//     tables through internal/osqexec when sources.osquery_exec is enabled,
//     then polling). The monitor's agent table answers the pipeline's RootSaw
//     and supplies configuration-home overrides and project directories.
//     spoor's own hook processes are recognised by the running image
//     (procmon self.go) against the running binary and the installed
//     copies (/usr/bin/spoor, /usr/local/bin/spoor,
//     %ProgramFiles%\spoor\spoor.exe), each used only when only root can
//     change what its path names (platform.TrustedPath), and not reported.
//     The daemon's identity key (engine.IdentityKeyPath) also keys the
//     monitor's process.exec ids, so a restarted sensor gives the live
//     processes it reports again the ids they had (procmon.stable_ids).
//     The heartbeat counts procs_total and procs_unreadable (live
//     user-space processes, and those that refused the monitor with EACCES
//     or EPERM), procs_hidden (of those, pids /proc mounted hidepid=1 lets
//     it list but not read) and procs_protected (of those, system-account
//     processes that refuse a fully privileged sensor: Windows protected
//     processes, a sandbox's init). A sensor short of privilege shows it
//     there, and the processes surface is degraded (procs_unreadable)
//     whenever an unreadable process is not a protected one.
//   - OTel: the loopback otelrecv receiver when sources.otlp.enabled.
//   - Adapters: numbat NDJSON files from sources.adapters, with the file
//     owner as the user. As for transcripts, files that exist when their
//     pattern is first looked at start at their end; files that appear later
//     (rotation, the other sensor starting after spoor, a file written while
//     the daemon was down) are read from their first line, and a renamed
//     file continues from its checkpoint. One pass reads at most 16 MiB of a
//     file, partial lines included.
//   - Scans: a full discovery.Scan at start and every scan.full_every,
//     differential scans every scan.interval (state.Snapshot as the previous
//     view), state.MarkScan after every complete scan, and discovery.ScanProject
//     for each new session working directory (from hook and transcript
//     records and from agent processes; at most once per directory in six
//     hours and 60 per account per hour; privacy exclusions honoured; only a
//     real directory owned by the session's account, whose files discovery
//     again refuses when another account owns them). The working directory
//     of an agent process is scanned only when the path means the same in
//     the sensor's file system view: the same mount namespace, or else the
//     path, resolved here, is the directory the process is in (device and
//     inode of /proc/<pid>/cwd). A shared root is not enough: systemd's
//     private namespace over the host's root keeps home directories but
//     gives the daemon its own /tmp under PrivateTmp=. In node
//     mode (the host's pid namespace, host_root empty) an agent in another
//     container names a path in its own namespace, which in the sensor's
//     names one of the sensor's directories; it is skipped and counted
//     (scan.project_foreign_ns).
//   - Hook state: hookinstall.Status per user, refreshed with the scans,
//     answers the pipeline's Hooked.
//   - Bundle: the installed signed bundle is loaded at start (embedded packs,
//     then the bundle, then rules.dirs, the same order the hook uses);
//     bundle.Pull runs every bundle.interval when bundle.url is set; any
//     change of the current bundle (a pull here, or `spoor bundle pull` from
//     the command line) is audited and hot-loaded: Pipeline.SetRules for rules
//     and lists, Catalog.LoadOverlay for catalog overlays.
//   - Outbox: sink.Files segments (dir root:<output.group> 0750 with the
//     set-group-id bit, files 0640) and optionally stdout (a failing stdout
//     is counted as output.stdout_errors, never as outbox loss). The daemon
//     prunes the outbox itself (the sink's own pruning is off): segments are
//     consumed when Fluent Bit's tail database(s) (output.fluent_bit.tail_db,
//     comma-separated paths or globs, read without writing anything beside
//     them: see readTailDB) and every configured shipper's checkpoint show
//     them read to the end. Read segments are pruned
//     by age; the hard byte cap removes read segments first, then segments of
//     streams no consumer reads, then unread data (activity first, detections
//     last), and every unread byte dropped is reported as a health.error with
//     reason outbox.dropped_unshipped and counted. The newest segment of a
//     stream is never removed. shipper_lag_bytes is the unread total.
//   - Shippers: sink.NewShipper over the outbox for output.forward and
//     output.otlp (experimental), checkpoints under the checkpoint directory.
//   - Local ring: sink.Files under <data>/local (0700, files 0600), pruned by
//     retention.local and retention.local_bytes. It is never tailed.
//   - State: state.Store at <data>/state.db; the pipeline applies records;
//     the daemon runs Prune on the heartbeat interval and MarkScan.
//   - Pipeline: engine.New in daemon mode, Tick about every second.
//
// # Privilege
//
// platform.IsPrivileged (root, or on Linux both CAP_DAC_READ_SEARCH and
// CAP_SYS_PTRACE effective) decides what is read: every account's homes,
// spools and processes, and records stamped integrity root. Without it only
// the daemon's own account is followed. platform.IsAdmin (root) decides
// what is written for others: the per-account spool directories and the
// chown and chgrp of the layout. The Kubernetes node sensor (uid 65532 with
// the two capabilities) reads everything and makes a spool directory for
// its own account only.
//
// # Host identity
//
// platform.HostInfo, with config host_id over SPOOR_HOST_ID for the id.
// SPOOR_HOST_NAME overrides the host name: in a pod the kernel's host name
// is the pod's, and the DaemonSet sets both variables from spec.nodeName.
//
// # Files the daemon writes
//
// Only under the data directory (the systemd unit allows /var/lib/spoor and
// /run/spoor and nothing else). <data> itself is made traversable (0711) so
// that unprivileged hooks can reach their spool and read the bundle;
// <data>/bundle is 0755 with 0644 files (signed public content);
// <data>/spool is 0711, each <data>/spool/<uid> 0700 owned by that user;
// <data>/outbox 2750 root:<output.group>; <data>/local, <data>/checkpoints
// 0700; state.db 0600. An existing directory with a wrong mode or owner is
// repaired, a symbolic link where a directory belongs is refused.
//
// On Windows mode bits mean nothing: the daemon sets explicit protected DACLs
// through golang.org/x/sys/windows (SYSTEM and Administrators full control on
// every directory; Users read and execute on the bundle; the user modify on
// their own spool directory). The data directory itself keeps the ACL the
// installer gave it, because the hook reads its configuration there.
// UNVERIFIED: the Windows code is compiled and vetted only; it has not run
// on Windows hardware.
//
// # Kill switch
//
// While platform.Disabled() is true the collectors idle (no spool, transcript
// or adapter reads, no scans; the process monitor idles itself) and the
// pipeline writes only a heartbeat labelled status=disabled. When the switch
// is released transcripts and adapter files restart from their current end,
// so nothing written while the sensor was off is collected afterwards, and
// collectors hand records over again two seconds later: the pipeline caches
// its view of the switch for up to a second and would drop them.
//
// # Windows service
//
// When the process was started by the service control manager
// (svc.IsWindowsService), Run runs under svc.Run and stops on the SCM's stop
// and shutdown requests as well as on its context. On Linux and macOS the
// daemon is a plain foreground process for systemd and launchd.
//
// # Limits
//
//   - With host_root set (a containerised node sensor) user spools and
//     transcripts are not followed: user homes are not enumerated inside
//     another root. Processes and scans honour host_root.
//   - A catalog overlay is layered on the running catalog; an entry that a
//     later bundle removes stays until the daemon restarts, and the process
//     monitor's marker tables are built at start.
//   - Fluent Bit's tail database is matched by segment base name and inode,
//     so Fluent Bit may see the outbox under another path (a container).
//     A tail database reads the streams it has ever listed a segment of: a
//     stream that no tail database has ever listed is treated as having no
//     consumer, and a readable database that lists nothing (the activity
//     input under the minimal profile) reads nothing. Only a database that
//     cannot be read and has never listed anything holds everything back.
//   - Hook spools written under $SPOOR_SPOOL (containers, CI) are not known
//     to the daemon.
package daemon
