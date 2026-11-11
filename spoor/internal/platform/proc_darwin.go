//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UNVERIFIED: this file was compiled and vetted for darwin/amd64 and
// darwin/arm64 but not executed in the build environment. The kern.procargs2
// parser it relies on is unit-tested with fixtures on every platform.

// commMax is MAXCOMLEN: the longest name the kernel keeps in p_comm.
const commMax = 16

// proc_info(2) arguments, from XNU bsd/sys/proc_info.h. The call is made
// directly (Go issues the trap itself on darwin) because libproc's wrappers
// need cgo; a failure is an errno, never a crash.
const (
	procInfoCallPIDInfo  = 2    // PROC_INFO_CALL_PIDINFO
	procPIDVnodePathInfo = 9    // PROC_PIDVNODEPATHINFO
	procPIDPathInfo      = 11   // PROC_PIDPATHINFO
	procPIDPathInfoSize  = 4096 // PROC_PIDPATHINFO_MAXSIZE (4*MAXPATHLEN)
	// struct proc_vnodepathinfo is two struct vnode_info_path (cwd, root),
	// each a 152-byte struct vnode_info followed by char[MAXPATHLEN].
	vnodeInfoSize     = 152
	vnodeInfoPathSize = vnodeInfoSize + 1024
	vnodePathInfoSize = 2 * vnodeInfoPathSize
)

// Processes lists every process from sysctl kern.proc.all. Arguments and
// environment come from kern.procargs2, which the kernel answers only for the
// caller's own processes unless the caller is root; for the rest Args is
// empty. Exe comes from proc_info, which answers for every process.
func Processes() (procs []Proc, err error) {
	defer guard(&err)
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("platform: kern.proc.all: %w", err)
	}
	if len(kps) > maxProcs {
		kps = kps[:maxProcs]
	}
	names := newUserNames()
	procs = make([]Proc, 0, len(kps))
	for i := range kps {
		procs = append(procs, procFromKinfo(&kps[i], names))
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
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || int(kp.Proc.P_pid) != pid {
		return Proc{}, fmt.Errorf("platform: pid %d: %w", pid, os.ErrNotExist)
	}
	return procFromKinfo(kp, newUserNames()), nil
}

func procFromKinfo(kp *unix.KinfoProc, names *userNames) Proc {
	pid := int(kp.Proc.P_pid)
	comm := cstring(kp.Proc.P_comm[:])
	p := Proc{PID: pid, PPID: int(kp.Eproc.Ppid), Name: comm}
	if st := kp.Proc.P_starttime; st.Sec != 0 {
		p.Start = time.Unix(int64(st.Sec), int64(st.Usec)*int64(time.Microsecond))
	}
	// The real uid: the account that started the process, even for setuid
	// binaries.
	p.UID = strconv.FormatUint(uint64(kp.Eproc.Pcred.P_ruid), 10)
	p.User = names.lookup(p.UID)
	if pid <= 0 {
		return p // kernel_task has no arguments or image path
	}
	if buf, err := procArgs(pid); err == nil {
		if exe, args, _, ok := parseProcArgs2(buf); ok {
			p.Args = args
			// The path given to exec; may be relative. Used only when the
			// kernel's own answer below is unavailable.
			p.Exe = exe
		}
	}
	if path, err := pidPath(pid); err == nil && path != "" {
		p.Exe = path
	}
	p.Name = refineName(comm, p.Args, commMax)
	return p
}

// procArgs fetches kern.procargs2 for one pid, capped so a process with a
// maximal argument area cannot make each scan allocate megabytes per pid.
func procArgs(pid int) ([]byte, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(buf) > maxCmdlineBytes+maxEnvBytes {
		buf = buf[:maxCmdlineBytes+maxEnvBytes]
	}
	return buf, nil
}

func procInfo(pid, flavor int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, unix.EINVAL
	}
	n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), uintptr(flavor), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// pidPath is proc_pidpath: the absolute path of the executable as the kernel
// knows it, independent of what the process put in argv.
func pidPath(pid int) (string, error) {
	buf := make([]byte, procPIDPathInfoSize)
	if _, err := procInfo(pid, procPIDPathInfo, buf); err != nil {
		return "", err
	}
	return cstring(buf), nil
}

// ProcEnv returns the environment the process was started with. The kernel
// answers for the caller's own processes, or for any process when the caller
// is root, and omits the environment of restricted binaries: the result is
// then an empty map and no error.
func ProcEnv(pid int) (env map[string]string, err error) {
	defer guard(&err)
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	buf, err := procArgs(pid)
	if err != nil {
		// EINVAL is how XNU says "not your process" (and "no such process").
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("platform: kern.procargs2 pid %d: %w", pid, os.ErrPermission)
		}
		return nil, fmt.Errorf("platform: kern.procargs2 pid %d: %w", pid, err)
	}
	_, _, list, ok := parseProcArgs2(buf)
	if !ok {
		return nil, fmt.Errorf("platform: kern.procargs2 pid %d: malformed buffer", pid)
	}
	return envListToMap(list), nil
}

// ProcCWD returns the working directory of the process. The kernel answers
// for the caller's own processes, or for any process when the caller is root.
func ProcCWD(pid int) (cwd string, err error) {
	defer guard(&err)
	if pid <= 0 {
		return "", fmt.Errorf("platform: invalid pid %d", pid)
	}
	buf := make([]byte, vnodePathInfoSize)
	n, err := procInfo(pid, procPIDVnodePathInfo, buf)
	if err != nil {
		return "", fmt.Errorf("platform: proc_info pid %d: %w", pid, err)
	}
	if n < vnodeInfoPathSize {
		return "", fmt.Errorf("platform: proc_info pid %d: short answer (%d bytes)", pid, n)
	}
	cwd = cstring(buf[vnodeInfoSize:vnodeInfoPathSize])
	if cwd == "" {
		return "", fmt.Errorf("platform: proc_info pid %d: no working directory", pid)
	}
	return cwd, nil
}
