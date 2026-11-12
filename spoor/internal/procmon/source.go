package procmon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

// ident is the cheap identity of one process: enough to notice that a pid
// now names a different process (key changed) or ran exec without the
// monitor seeing it (comm changed).
type ident struct {
	pid, ppid int
	// key is the start-time identity: clock ticks since boot (plus one) on
	// Linux procfs, Unix nanoseconds elsewhere. 0 means unknown.
	key  uint64
	comm string
}

// source is a process-table backend. Implementations must be safe for
// concurrent use: the netlink reader and the scan loop call them at the
// same time.
type source interface {
	kind() string
	// list returns every visible live process. recs is non-nil when the
	// backend had to read full records anyway (it then saves a second read).
	list() (ids []ident, recs map[int]*platform.Proc, err error)
	// identOf re-reads the cheap identity of one process.
	identOf(pid int) (ident, bool)
	// read returns the full record of a process and the identity it was read
	// under; ok is false when the process is gone or changed mid-read.
	read(pid int) (platform.Proc, ident, bool)
	// env returns the variables of the process environment whose names are
	// in keep (all of them when keep is nil). Filtering while parsing keeps
	// the rest of the environment, which can hold any secret, from being
	// copied at all.
	env(pid int, keep map[string]bool) (map[string]string, error)
	// children lists the direct children of pid; ok is false when the
	// backend cannot enumerate children without a full listing.
	children(pid int) (kids []int, ok bool)
	cwd(pid int) string
	workload(pid int) (id, runtime, pod string)
}

// newSource picks the backend. On Linux the Monitor reads procfs itself for
// the cheap identity pass (one stat read per process instead of four files)
// and for children lists; full records still come from internal/platform so
// that start times are identical to the ones every other spoor component
// computes. With a HostRoot (a sensor in a container that sees the host's
// /proc mounted at <HostRoot>/proc) every read is relative to that mount.
// Other systems use platform.Processes for every pass.
func newSource(hostRoot string) (source, error) {
	if runtime.GOOS != "linux" {
		if hostRoot != "" && hostRoot != "/" {
			return nil, fmt.Errorf("procmon: HostRoot is supported on Linux only")
		}
		return platformSource{}, nil
	}
	if hostRoot == "" || filepath.Clean(hostRoot) == "/" {
		return &procfsSource{dir: "/proc", viaPlatform: true}, nil
	}
	dir := filepath.Join(hostRoot, "proc")
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("procmon: host root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("procmon: host root: %s is not a directory", dir)
	}
	return newProcfsSource(dir, filepath.Join(hostRoot, "etc", "passwd")), nil
}

// platformSource answers everything through internal/platform.
type platformSource struct{}

func (platformSource) kind() string { return "platform" }

func (platformSource) list() ([]ident, map[int]*platform.Proc, error) {
	procs, err := platform.Processes()
	if err != nil {
		return nil, nil, err
	}
	ids := make([]ident, 0, len(procs))
	recs := make(map[int]*platform.Proc, len(procs))
	for i := range procs {
		p := &procs[i]
		ids = append(ids, identFromProc(p))
		recs[p.PID] = p
	}
	return ids, recs, nil
}

func identFromProc(p *platform.Proc) ident {
	return ident{pid: p.PID, ppid: p.PPID, key: timeKey(p.Start), comm: p.Name}
}

// timeKey turns a start time into an identity key; 0 stays "unknown".
func timeKey(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	k := uint64(t.UnixNano())
	if k == 0 {
		k = 1
	}
	return k
}

func (platformSource) identOf(pid int) (ident, bool) {
	p, err := platform.ProcessByPID(pid)
	if err != nil {
		return ident{}, false
	}
	return identFromProc(&p), true
}

func (platformSource) read(pid int) (platform.Proc, ident, bool) {
	p, err := platform.ProcessByPID(pid)
	if err != nil {
		return platform.Proc{}, ident{}, false
	}
	return p, identFromProc(&p), true
}

func (platformSource) env(pid int, keep map[string]bool) (map[string]string, error) {
	env, err := platform.ProcEnv(pid)
	if err != nil || keep == nil {
		return env, err
	}
	for k := range env {
		if !keep[k] {
			delete(env, k)
		}
	}
	return env, nil
}

func (platformSource) children(int) ([]int, bool) { return nil, false }

func (platformSource) cwd(pid int) string {
	c, err := platform.ProcCWD(pid)
	if err != nil {
		return ""
	}
	return cleanPath(c)
}

func (platformSource) workload(pid int) (string, string, string) {
	id, rt := platform.ContainerOf(pid)
	return id, rt, platform.PodOf(pid)
}
