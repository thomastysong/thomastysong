//go:build !windows && !linux

package hookcmd

import (
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// fillChain walks the parent chain through the process table. On Linux and
// macOS the parent pid of a live process is maintained by the kernel
// (orphans are re-parented), so a recycled pid cannot appear as a parent.
// Elsewhere platform answers ErrUnsupported and only the pid is kept.
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
		a, err := platform.ProcessByPID(cur)
		if err != nil {
			return
		}
		p.Ancestors = append(p.Ancestors, a.Name)
		if a.PPID == cur {
			return
		}
		cur = a.PPID
	}
}
