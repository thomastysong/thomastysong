//go:build linux

package platform

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// procRoot is a variable so tests can run the readers against a fixture tree.
var procRoot = "/proc"

// commMax is TASK_COMM_LEN-1: the longest name the kernel keeps.
const commMax = 15

type linuxClock struct {
	boot  int64 // seconds since the epoch
	ticks int64 // clock ticks per second
}

var (
	linuxClockOnce sync.Once
	linuxClockVal  linuxClock
)

// clock is read once per sensor process: btime follows wall-clock steps, so
// re-reading it would make the same process appear to change its start time,
// and Start is part of the process identity callers key on.
func clock() linuxClock {
	linuxClockOnce.Do(func() { linuxClockVal = readClock(procRoot) })
	return linuxClockVal
}

func readClock(root string) linuxClock {
	c := linuxClock{ticks: 100} // USER_HZ, fixed at 100 by the Linux ABI on every architecture Go supports
	if b, err := readFileLimit(filepath.Join(root, "self", "auxv"), maxSmallFile); err == nil {
		if t, ok := parseAuxvClockTicks(b, int(unsafe.Sizeof(uintptr(0))), binary.NativeEndian); ok {
			c.ticks = t
		}
	}
	if b, err := readFileLimit(filepath.Join(root, "stat"), 1<<20); err == nil {
		if bt, ok := parseBootTime(b); ok {
			c.boot = bt
		}
	}
	return c
}

func (c linuxClock) startTime(ticks uint64) time.Time {
	if c.boot == 0 || c.ticks <= 0 {
		return time.Time{}
	}
	t := int64(ticks)
	if t < 0 {
		return time.Time{}
	}
	// Split before scaling: ticks*1e9 overflows int64 after ~3 years of uptime.
	return time.Unix(c.boot+t/c.ticks, (t%c.ticks)*int64(time.Second)/c.ticks)
}

// Processes lists every process this caller can see in /proc. A process that
// exits mid-scan is skipped; a field the caller may not read is left empty.
func Processes() (procs []Proc, err error) {
	defer guard(&err)
	d, err := os.Open(procRoot)
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	defer d.Close()
	c := clock()
	names := newUserNames()
	for len(procs) < maxProcs {
		batch, rerr := d.Readdirnames(1024)
		for _, n := range batch {
			pid, ok := parsePID(n)
			if !ok {
				continue
			}
			if p, ok := readProc(pid, c, names); ok {
				procs = append(procs, p)
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && len(procs) == 0 {
				return nil, fmt.Errorf("platform: %w", rerr)
			}
			break
		}
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// ProcessByPID returns one process, or an error wrapping os.ErrNotExist when
// it is gone.
func ProcessByPID(pid int) (p Proc, err error) {
	defer guard(&err)
	if pid <= 0 {
		return Proc{}, fmt.Errorf("platform: invalid pid %d", pid)
	}
	p, ok := readProc(pid, clock(), newUserNames())
	if !ok {
		return Proc{}, fmt.Errorf("platform: pid %d: %w", pid, os.ErrNotExist)
	}
	return p, nil
}

// readProc reads one /proc/<pid>. Every file is opened relative to a single
// handle on the directory: pids are recycled, and reading stat from one
// process and cmdline from its successor would attribute one program's
// arguments to another. After the process dies the handle's reads fail.
func readProc(pid int, c linuxClock, names *userNames) (Proc, bool) {
	root, err := os.OpenRoot(filepath.Join(procRoot, strconv.Itoa(pid)))
	if err != nil {
		return Proc{}, false
	}
	defer root.Close()
	stat, err := readRootFile(root, "stat", 4096)
	if err != nil {
		return Proc{}, false
	}
	comm, ppid, ticks, ok := parseLinuxStat(stat)
	if !ok {
		return Proc{}, false
	}
	p := Proc{PID: pid, PPID: ppid, Name: comm, Start: c.startTime(ticks)}
	if b, err := readRootFile(root, "cmdline", maxCmdlineBytes); err == nil {
		p.Args = splitArgs(b)
	}
	// The link text is the path inside the process's own mount namespace.
	if exe, err := root.Readlink("exe"); err == nil {
		p.Exe = trimDeleted(exe)
	}
	if b, err := readRootFile(root, "status", 8192); err == nil {
		if uid, ok := parseLinuxStatusUID(b); ok {
			p.UID = uid
			p.User = names.lookup(uid)
		}
	}
	p.Name = refineName(comm, p.Args, commMax)
	return p, true
}

func readRootFile(root *os.Root, name string, max int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// ProcEnv returns the environment the process was started with. Reading
// another user's environment needs root or CAP_SYS_PTRACE; the error then
// satisfies errors.Is(err, os.ErrPermission). A process that rewrote its own
// environment area can make this lie; child processes still inherit the
// truth, which is why callers look at the children of an agent.
func ProcEnv(pid int) (env map[string]string, err error) {
	defer guard(&err)
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	b, err := readFileLimit(filepath.Join(procRoot, strconv.Itoa(pid), "environ"), maxEnvBytes+1)
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	truncated := len(b) > maxEnvBytes
	if truncated {
		b = b[:maxEnvBytes]
	}
	return parseEnviron(b, truncated), nil
}

// ProcCWD returns the working directory of the process, as a path inside the
// process's own mount namespace.
func ProcCWD(pid int) (cwd string, err error) {
	defer guard(&err)
	if pid <= 0 {
		return "", fmt.Errorf("platform: invalid pid %d", pid)
	}
	cwd, err = os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "cwd"))
	if err != nil {
		return "", fmt.Errorf("platform: %w", err)
	}
	return trimDeleted(cwd), nil
}
