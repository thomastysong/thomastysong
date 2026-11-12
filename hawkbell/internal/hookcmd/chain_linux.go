//go:build linux

package hookcmd

import (
	"bytes"
	"io"
	"os"
	"strconv"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// fillChain reads the caller through platform.ProcessByPID, so its start
// time is derived exactly as the daemon's process monitor derives it (the
// join key must match), and walks the ancestors through /proc/<pid>/stat
// alone: a name and a parent pid are all an ancestor contributes, and
// ProcessByPID would also read each one's command line, status and
// account name on the hook's hot path. The kernel maintains the parent pid
// of a live process (orphans are re-parented), so a recycled pid cannot
// appear as a parent.
func fillChain(p *event.Process) {
	c, err := platform.ProcessByPID(p.PID)
	if err != nil {
		return
	}
	p.PPID, p.Name, p.Exe = c.PPID, c.Name, c.Exe
	if !c.Start.IsZero() {
		p.StartTime = event.At(c.Start)
	}
	cur := c.PPID
	for i := 0; i < maxAncestors && cur > 0; i++ {
		name, ppid, ok := procStat(cur)
		if !ok {
			return
		}
		p.Ancestors = append(p.Ancestors, name)
		if ppid == cur {
			return
		}
		cur = ppid
	}
}

// procStat reads the command name and parent pid from /proc/<pid>/stat.
// The name is in parentheses and may itself contain ") ", so the fields
// after it are found from the last ')'.
func procStat(pid int) (name string, ppid int, ok bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", 0, false
	}
	open, end := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return "", 0, false
	}
	// After ") ": state, then ppid.
	rest := bytes.Fields(b[end+1:])
	if len(rest) < 2 {
		return "", 0, false
	}
	ppid, err = strconv.Atoi(string(rest[1]))
	if err != nil || ppid < 0 {
		return "", 0, false
	}
	return string(b[open+1 : end]), ppid, true
}
