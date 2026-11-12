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

	"golang.org/x/sys/unix"
)

// procRoot is a variable so tests can run the readers against a fixture tree.
var procRoot = "/proc"

// commMax is TASK_COMM_LEN-1: the longest name the kernel keeps.
const commMax = 15

type linuxClock struct {
	boot  int64 // seconds since the epoch
	ticks int64 // clock ticks per second
}

// clockStepThreshold is how far the wall clock must jump before process
// start times are recomputed.
const clockStepThreshold = 2 * time.Second

var clockState struct {
	sync.Mutex
	loaded bool
	val    linuxClock
	ref    time.Duration // wall clock minus boot clock when val was read
	refOK  bool
}

// wallMinusBoot measures the offset between the wall clock and the
// time-since-boot clock. It is constant while the wall clock is only slewed
// and jumps when the wall clock is stepped. A variable so tests can step it.
var wallMinusBoot = func() (time.Duration, bool) {
	var wall, boot unix.Timespec
	if unix.ClockGettime(unix.CLOCK_REALTIME, &wall) != nil || unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil {
		return 0, false
	}
	return time.Duration(wall.Nano() - boot.Nano()), true
}

// clock returns the boot time used to turn /proc/<pid>/stat start ticks into
// wall-clock times.
//
// Start is how callers tell a process from a later one that reuses its pid,
// so it must not wobble: the boot time is therefore read once and kept, and
// because it comes from /proc/stat (whole seconds) a restarted sensor
// computes the very same Start values. But a sensor started before the clock
// was set (dual-boot machines with the RTC in local time, devices without an
// RTC) would then report every start time hours off for as long as it runs.
// So each call makes one cheap measurement, and only a wall-clock step of at
// least clockStepThreshold makes the boot time be read again. All Start
// values shift once by that step; callers that key on Start see those
// processes as new, which is true to what the clock did.
func clock() linuxClock {
	st := &clockState
	st.Lock()
	defer st.Unlock()
	off, ok := wallMinusBoot()
	stepped := ok && st.refOK && (off-st.ref >= clockStepThreshold || st.ref-off >= clockStepThreshold)
	if !st.loaded || stepped {
		st.val = readClock(procRoot)
		st.loaded, st.ref, st.refOK = true, off, ok
	} else if ok && !st.refOK {
		// The first measurement failed; start watching from this one.
		st.ref, st.refOK = off, true
	}
	return st.val
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
