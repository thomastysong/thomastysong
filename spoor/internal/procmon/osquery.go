package procmon

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/osqexec"
)

// execSource is the second exec provider: internal/osqexec's Source, which
// pulls kernel-backed exec rows from a running osqueryd over its extension
// socket.
type execSource interface {
	Poll(ctx context.Context) ([]*event.Event, error)
	Status() string
}

// canaryAgent is the agent id osqAttribute hands to osqexec for the
// self-test process, so that its row comes back and can be recognised.
const canaryAgent = "\x00spoor-canary"

// osqAttribute is the Attribute callback given to osqexec. Rows arrive
// seconds after the exec, when the process (and often its parent shell) is
// gone, so exited processes are looked up in the tombstones. A row about an
// agent root itself is not a process.exec of that agent (its start is
// reported separately); it counts only for an enclosing agent.
func (m *Monitor) osqAttribute(pid, ppid int) (agentID, sessionID string, ok bool) {
	if pid > 0 && pid == m.canaryPID() {
		return canaryAgent, "", true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.lookup(pid); n != nil {
		if n.root != nil {
			if n.owner != nil {
				return n.owner.ap.AgentID, "", true
			}
			return "", "", false
		}
		if a, s, ok := m.agentOf(n); ok {
			return a, s, true
		}
		return "", "", false
	}
	if p := m.lookup(ppid); p != nil {
		if p.root != nil {
			return p.root.ap.AgentID, "", true
		}
		return m.agentOf(p)
	}
	return "", "", false
}

// lookup finds a live or recently exited process. Caller holds m.mu.
func (m *Monitor) lookup(pid int) *node {
	if pid <= 0 {
		return nil
	}
	if n := m.nodes[pid]; n != nil {
		return n
	}
	return m.tomb[pid]
}

// agentOf gives the agent id and session id of a non-root process. Caller
// holds m.mu.
func (m *Monitor) agentOf(n *node) (string, string, bool) {
	owner := n.owner
	if owner == nil && n.exited.IsZero() {
		owner = m.enclosing(n)
	}
	if owner != nil {
		sid := n.env.session(owner.prod.id)
		if sid == "" && len(owner.ap.SessionIDs) == 1 {
			sid = owner.ap.SessionIDs[0]
		}
		return owner.ap.AgentID, sid, true
	}
	if p := n.env.product; p != "" {
		return p, n.env.session(p), true
	}
	return "", "", false
}

// pollOsquery reads osquery and forwards the attributed exec events. It
// returns whether osquery is delivering.
func (m *Monitor) pollOsquery(ctx context.Context, now time.Time) bool {
	if m.osq == nil {
		return false
	}
	evs, err := m.osq.Poll(ctx)
	if err != nil {
		if !errors.Is(err, osqexec.ErrUnavailable) && ctx.Err() == nil {
			m.st.errors.Add(1)
		}
		return false
	}
	var out []*event.Event
	m.mu.Lock()
	for _, ev := range evs {
		if ev == nil || ev.Process == nil {
			continue
		}
		if ev.Agent != nil && ev.Agent.ID == canaryAgent {
			if m.can.pending && ev.Process.PID == m.can.pid {
				m.can.hit = true
			}
			continue
		}
		owner := m.ownerForRow(ev.Process.PID, ev.Process.PPID)
		var b *bucket
		if owner != nil {
			b = &owner.bucket
			if ev.Agent != nil && ev.Agent.ID == owner.ap.AgentID {
				ev.Agent.PID, ev.Agent.Name = owner.ap.PID, owner.prod.name
			}
			if ev.Container == nil {
				ev.Container = eventContainer(owner.ap.Container)
			}
		} else if ev.Agent != nil {
			b = m.markerB["osq:"+ev.Agent.ID]
			if b == nil {
				b = &bucket{}
				m.markerB["osq:"+ev.Agent.ID] = b
			}
		}
		m.st.attributed.Add(1)
		if b != nil && (!b.take(now, m.rate, m.burst) || !m.global.take(now, globalExecRate, globalExecRate)) {
			b.dropped++
			m.st.rateDropped.Add(1)
			continue
		}
		if ev.Labels == nil {
			ev.Labels = map[string]string{}
		}
		ev.Labels["exec_source"] = SourceOsquery
		if b != nil && b.dropped > 0 {
			ev.Labels["exec_dropped"] = strconv.FormatUint(b.dropped, 10)
			b.dropped = 0
		}
		m.st.execEvents.Add(1)
		m.st.osqEvents.Add(1)
		out = append(out, ev)
	}
	m.mu.Unlock()
	m.enqueue(out)
	return true
}

// ownerForRow finds the agent root behind an osquery row. Caller holds m.mu.
func (m *Monitor) ownerForRow(pid, ppid int) *root {
	for _, p := range []int{pid, ppid} {
		n := m.lookup(p)
		if n == nil {
			continue
		}
		if n.root != nil && p == ppid {
			return n.root
		}
		if n.owner != nil {
			return n.owner
		}
	}
	return nil
}
