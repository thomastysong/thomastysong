// Package platform is spoor's operating-system layer: host identity, user
// homes, the process table, well-known directories, and file helpers that are
// safe for a root process to use on trees a user (or an agent acting as that
// user) controls.
//
// Everything is pure Go (CGO_ENABLED=0) and builds for linux, darwin and
// windows on amd64 and arm64; other GOOS values compile against stubs that
// return ErrUnsupported or empty results.
//
// # Trust model
//
// The sensor runs on machines where the attacker controls agent output, the
// agent's environment and everything under the user's home. So:
//
//   - every read is size-bounded and every list is count-bounded;
//   - nothing discovered on disk is ever executed. The only child process this
//     package can start is /usr/sbin/ioreg on macOS, by absolute path, with a
//     5 s timeout, and only when the gethostuuid system call fails;
//   - exported functions recover from panics and report them as errors (or as
//     an empty result where the signature has no error);
//   - process names, arguments and environments are attacker-chosen bytes.
//     They are returned as they were read (possibly invalid UTF-8). Exe is the
//     only field the kernel vouches for.
//
// ProcEnv returns values because detection needs a few of them (session ids,
// config-dir overrides). Callers must never emit environment values: names
// only, plus an allowlist of marker values. Proc.Args is equally raw and can
// carry tokens passed on a command line; it goes through redaction before it
// leaves the machine.
//
// HostInfo in an unprivileged process is only as trustworthy as that
// process's environment: SPOOR_HOST_ID and the per-user host_id file are the
// user's to set. A privileged daemon should stamp host identity itself
// rather than accept it from a hook client.
//
// # What each OS provides
//
//	                 linux                  darwin                      windows
//	HostInfo id      DMI product_uuid,      gethostuuid(2), then        SMBIOS type 1 UUID,
//	                 then /etc/machine-id   ioreg IOPlatformUUID        then MachineGuid
//	Processes        /proc                  kern.proc.all,              Toolhelp32 snapshot,
//	                                        kern.procargs2, proc_info   NtQueryInformationProcess
//	ProcEnv          /proc/<pid>/environ    kern.procargs2              PEB read
//	ProcCWD          /proc/<pid>/cwd        proc_info (vnode path)      PEB read
//	PeerCred         SO_PEERCRED            LOCAL_PEERCRED/PEERPID      ErrUnsupported
//	ContainerOf      cgroup, mountinfo      "", ""                      "", ""
//
// # Known limits (returned as empty fields or ErrUnsupported, never guessed)
//
//   - Linux: another user's exe, cwd and environ need root or CAP_SYS_PTRACE;
//     without it those fields are empty and ProcEnv/ProcCWD return a
//     permission error. /proc/<pid>/environ is the environment at exec time.
//   - macOS: kern.procargs2 answers only for the caller's own processes unless
//     the caller is root, and the kernel withholds the environment of
//     restricted (hardened, SIP-protected) binaries: ProcEnv then returns an
//     empty map without error. The macOS and Windows code paths were compiled
//     and vetted but not executed in the environment this package was built
//     in; parsers for their wire formats are unit-tested with fixtures.
//   - Windows: other users' processes need an elevated token (the package
//     enables SeDebugPrivilege once when elevated); protected processes stay
//     opaque. OwnerUID has no answer from an os.FileInfo (use PathOwner).
//     PeerCred is unsupported.
//   - Host id: when no hardware id is readable (unprivileged Linux process,
//     container without DMI) the id falls back to /etc/machine-id, which
//     osquery does not use. The osquery extension should write the value of
//     system_info.uuid to <config dir>/host_id with WriteHostIDFile so every
//     spoor process on the host reports the id Fleet knows.
//   - Containers: a process inside a private cgroup namespace sees "0::/".
//     ContainerOf then falls back to the bind mounts of /etc/hostname,
//     /etc/hosts and /etc/resolv.conf, which identify Docker and Podman
//     containers. Under Kubernetes those mounts name the pod sandbox, not the
//     container, so only PodOf answers from inside a pod.
//   - Symlinks: OpenNoFollow guards the final path component only. Use
//     OpenBeneath to also refuse escapes through intermediate components.
package platform
