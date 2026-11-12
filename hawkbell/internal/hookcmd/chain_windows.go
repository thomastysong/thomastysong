//go:build windows

package hookcmd

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// fillChain takes one Toolhelp32 snapshot and walks parent ids in it.
// platform.ProcessByPID takes a full snapshot per call, which would cost one
// snapshot per ancestor on the hook's hot path. Windows does not re-parent
// orphans, so a parent id can name an unrelated process that reused the pid
// after the real parent exited: the walk stops at the first "parent" that
// was created after its child.
func fillChain(p *event.Process) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	type entry struct {
		ppid uint32
		name string
	}
	table := make(map[uint32]entry, 256)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		table[pe.ProcessID] = entry{pe.ParentProcessID, windows.UTF16ToString(pe.ExeFile[:])}
		if len(table) >= 1<<16 {
			break
		}
	}
	self := createdAt(uint32(os.Getpid()))
	c, ok := table[uint32(p.PID)]
	if !ok {
		return
	}
	start := createdAt(uint32(p.PID))
	if !start.IsZero() && !self.IsZero() && start.After(self) {
		return // the pid we were handed was recycled
	}
	p.PPID, p.Name = int(c.ppid), c.name
	p.Exe = imagePath(uint32(p.PID))
	if !start.IsZero() {
		p.StartTime = event.At(start)
	}
	child, cur := start, c.ppid
	for i := 0; i < maxAncestors && cur != 0; i++ {
		a, ok := table[cur]
		if !ok {
			return
		}
		st := createdAt(cur)
		if !st.IsZero() && !child.IsZero() && st.After(child) {
			return
		}
		p.Ancestors = append(p.Ancestors, a.name)
		if a.ppid == cur {
			return
		}
		child, cur = st, a.ppid
	}
}

func createdAt(pid uint32) time.Time {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return time.Time{}
	}
	return time.Unix(0, c.Nanoseconds())
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
