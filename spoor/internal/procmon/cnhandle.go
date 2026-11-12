package procmon

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// cnLoop reads the process connector until ctx ends, stop is set, or the
// socket fails. Exec events are handled inline, in this goroutine, because
// /proc/<pid> must be read before a short-lived process is gone: a queue in
// between would let a build's burst of execs age past their own exits.
func (m *Monitor) cnLoop(ctx context.Context, c cnConn, stop *atomic.Bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			m.st.errors.Add(1)
			err = errors.New("procmon: internal error in the process connector reader")
		}
	}()
	buf := make([]byte, 64<<10)
	var evs []cnEvent
	for ctx.Err() == nil && !stop.Load() {
		n, rerr := c.recv(buf)
		switch {
		case rerr == nil:
		case errors.Is(rerr, errCNTimeout):
			continue
		case errors.Is(rerr, errCNOverflow):
			// The kernel dropped events: the table may have missed execs
			// and exits. A full rescan puts it right.
			m.st.overflows.Add(1)
			m.requestResync()
			continue
		default:
			return rerr
		}
		evs = parseCN(buf[:n], evs[:0])
		for i := range evs {
			m.handleCN(&evs[i])
		}
	}
	return nil
}

func (m *Monitor) handleCN(e *cnEvent) {
	switch e.what {
	case procEventFork:
		// A new thread is a fork event too; only new processes matter.
		if e.childPID == e.childTGID && e.childTGID > 0 {
			m.cnFork(e.parentTGID, e.childTGID)
		}
	case procEventExec:
		if e.tgid > 0 {
			m.cnExec(e.tgid, m.monoWall(e.ts))
		}
	case procEventExit:
		if e.pid == e.tgid && e.tgid > 0 {
			m.cnExit(e.tgid, exitFromStatus(e.exitCode))
		}
	}
}

// cnFork records a child with its parent's image and attribution: until it
// runs exec it is a copy of the parent, and if it never does (a subshell)
// this is all the monitor will know about it.
func (m *Monitor) cnFork(ppid, pid int) {
	if pid > maxPID || ppid > maxPID {
		return
	}
	now := m.now()
	m.mu.Lock()
	var evs []*event.Event
	if old := m.nodes[pid]; old != nil {
		evs = m.retire(old, now, nil) // its exit was missed
	}
	if len(m.nodes) >= maxTable {
		m.st.tableFull.Add(1)
		m.mu.Unlock()
		m.enqueue(evs)
		return
	}
	m.seq++
	n := &node{pid: pid, ppid: ppid, added: m.seq}
	if p := m.nodes[ppid]; p != nil {
		n.comm, n.name, n.exe, n.uid, n.user = p.comm, p.name, p.exe, p.uid, p.user
		n.env = p.env
		// Until it runs exec it is the parent's image: spoor's own hook if
		// the parent was, a kernel thread if kthreadd forked it, and as
		// readable as the parent.
		n.self, n.kthread, n.unreadable = p.self, p.kthread, p.unreadable
		if p.root != nil {
			n.owner = p.root
		} else {
			n.owner = p.owner
			if n.owner == nil {
				n.owner = m.enclosing(p)
			}
		}
		n.resolved = p.resolved
	}
	m.nodes[pid] = n
	m.mu.Unlock()
	m.enqueue(evs)
}

// cnExec reads the new image at once and ingests it.
func (m *Monitor) cnExec(pid int, at time.Time) {
	m.st.execs.Add(1)
	seen := m.canarySeen(pid)
	m.mu.Lock()
	seq0 := m.seq
	m.mu.Unlock()
	o := m.prepare(ident{pid: pid}, nil, viaCNProc, at)
	if o == nil {
		if !seen { // the canary (true(1)) is usually gone already
			m.st.readMisses.Add(1)
		}
		return
	}
	if o.canary {
		m.canaryHit()
		return
	}
	o.exec = true
	m.commit([]*observed{o}, seq0, m.now())
}

func (m *Monitor) cnExit(pid int, exit *exitInfo) {
	now := m.now()
	m.mu.Lock()
	m.seq++
	m.exitMark[pid] = exitMark{seq: m.seq, at: now}
	var evs []*event.Event
	if n := m.nodes[pid]; n != nil {
		evs = m.retire(n, now, exit)
	}
	m.mu.Unlock()
	m.enqueue(evs)
}

// requestResync marks the table for a rescan. Only the first request wakes
// the loop; the rest of a storm finds the mark already set (see
// runner.resyncDue for when the rescan runs).
func (m *Monitor) requestResync() {
	if !m.resyncRq.Swap(true) {
		m.wake()
	}
}

func (m *Monitor) wake() {
	select {
	case m.nudge <- struct{}{}:
	default:
	}
}
