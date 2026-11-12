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
//     as hook_errors.<reason>.
//   - Transcripts: transcript.Tailer with transcript.HomeRoots for every user
//     plus transcript.ConfigRoots for configuration homes the process monitor
//     sees in agents' environments (CLAUDE_CONFIG_DIR, CODEX_HOME, ...).
//     Files that exist when a root is first seen are started at their end:
//     no retroactive collection of what happened before spoor was deployed
//     (sources.transcripts.backfill opts into reading back). A root is "first
//     seen" once per data directory: the admitted roots are remembered in the
//     checkpoint directory, so a restart does not skip what was written while
//     the daemon was down.
//   - Processes: procmon (Linux process connector, then osquery's evented
//     tables through internal/osqexec when sources.osquery_exec is enabled,
//     then polling). The monitor's agent table answers the pipeline's RootSaw
//     and supplies configuration-home overrides and project directories.
//   - OTel: the loopback otelrecv receiver when sources.otlp.enabled.
//   - Adapters: numbat NDJSON files from sources.adapters, tailed from their
//     end like transcripts, with the file owner as the user.
//   - Scans: a full discovery.Scan at start and every scan.full_every,
//     differential scans every scan.interval (state.Snapshot as the previous
//     view), state.MarkScan after every complete scan, and discovery.ScanProject
//     for each new session working directory (rate limited, privacy
//     exclusions honoured, files not owned by the session's user refused by
//     discovery itself).
//   - Hook state: hookinstall.Status per user, refreshed with the scans,
//     answers the pipeline's Hooked.
//   - Bundle: the installed signed bundle is loaded at start (embedded packs,
//     then the bundle, then rules.dirs, the same order the hook uses);
//     bundle.Pull runs every bundle.interval when bundle.url is set; any
//     change of the current bundle (a pull here, or `spoor bundle pull` from
//     the command line) is audited and hot-loaded: Pipeline.SetRules for rules
//     and lists, Catalog.LoadOverlay for catalog overlays.
//   - Outbox: sink.Files segments (dir root:<output.group> 0750 with the
//     set-group-id bit, files 0640) and optionally stdout. The daemon prunes
//     the outbox itself (the sink's own pruning is off): segments are
//     consumed when Fluent Bit's tail database(s) (output.fluent_bit.tail_db,
//     comma-separated paths or globs, opened read-only) and every configured
//     shipper's checkpoint show them read to the end. Read segments are pruned
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
// so nothing written while the sensor was off is collected afterwards.
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
//     A stream that no tail database has ever listed is treated as having
//     no consumer.
//   - Hook spools written under $SPOOR_SPOOL (containers, CI) are not known
//     to the daemon.
package daemon
