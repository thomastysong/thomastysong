package platform

import (
	"bytes"
	"strconv"
)

// Linux capability numbers (include/uapi/linux/capability.h). Together the
// two make a process that is not uid 0 able to read what spoor reads as
// root: CAP_DAC_READ_SEARCH bypasses file read and directory search
// permission checks (every account's home, agent logs and settings), and
// CAP_SYS_PTRACE passes the ptrace access check the kernel applies to
// /proc/<pid>/{environ,exe,cwd,root} of other accounts' processes. The
// Kubernetes node sensor runs as uid 65532 with exactly these two as file
// capabilities (deploy/kubernetes/daemonset.yaml), and sees every account's
// agents.
const (
	capDACReadSearch = 2
	capSysPtrace     = 19

	// readerCaps is the effective set IsPrivileged accepts in place of
	// uid 0 on Linux.
	readerCaps uint64 = 1<<capDACReadSearch | 1<<capSysPtrace

	// maxStatusRead bounds the read of /proc/self/status (a few KiB on
	// every kernel; the capability lines are in the first half).
	maxStatusRead = 16 << 10
)

// parseCapEff returns the effective capability set from the text of
// /proc/<pid>/status ("CapEff:\t0000000000080004", 64 bits in hex). Only
// the effective set counts: a permitted capability that is not effective
// does not pass the kernel's checks until the process raises it, which
// spoor never does. ok is false when the line is missing or malformed.
func parseCapEff(status []byte) (eff uint64, ok bool) {
	for len(status) > 0 {
		line := status
		if i := bytes.IndexByte(status, '\n'); i >= 0 {
			line, status = status[:i], status[i+1:]
		} else {
			status = nil
		}
		rest, found := bytes.CutPrefix(line, []byte("CapEff:"))
		if !found {
			continue
		}
		f := bytes.TrimSpace(rest)
		if len(f) == 0 || len(f) > 16 {
			return 0, false
		}
		v, err := strconv.ParseUint(string(f), 16, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// readerCapsIn reports whether a status text names an effective set that
// holds both reader capabilities.
func readerCapsIn(status []byte) bool {
	eff, ok := parseCapEff(status)
	return ok && eff&readerCaps == readerCaps
}
