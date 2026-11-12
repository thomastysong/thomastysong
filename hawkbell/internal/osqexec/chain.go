package osqexec

// chainCache remembers which recent pids were attributed to an agent, so
// that attribution follows a chain of short-lived processes. By the time
// osquery delivers a row (seconds after the exec) both the process and its
// parent shell are usually gone and the caller's Attribute function cannot
// see them any more; but the shell's own exec row came first in the stream,
// named the agent as its parent, and was attributed.
type chainCache struct {
	m map[int]chainEntry
}

type chainEntry struct {
	ppid    int
	agent   string
	session string
	at      int64 // row time of the latest use, seconds
}

const (
	// chainTTL is how long an attribution may be inherited without the
	// process showing up again. It bounds the damage of pid reuse: a
	// recycled pid would have to reappear as a parent within this window
	// without an exec row of its own under a different parent.
	chainTTL = 120
	chainMax = 1 << 16
)

func (c *chainCache) init() { c.m = map[int]chainEntry{} }

// resolve combines the caller's verdict for a row with what the stream has
// shown so far and records the outcome for the row's pid.
func (c *chainCache) resolve(r *rec, agent, session string, ok bool) (string, string, bool) {
	if !ok {
		if e, hit := c.m[r.pid]; hit && e.ppid == r.ppid && r.time-e.at <= chainTTL {
			// The same process running exec again (sh -c "exec prog").
			agent, session, ok = e.agent, e.session, true
		} else if e, hit := c.m[r.ppid]; hit && r.ppid > 1 && r.time-e.at <= chainTTL {
			agent, session, ok = e.agent, e.session, true
			e.at = r.time // the parent is evidently still alive
			c.m[r.ppid] = e
		}
	} else if session == "" {
		if e, hit := c.m[r.ppid]; hit && e.agent == agent && r.time-e.at <= chainTTL {
			session = e.session
		}
	}
	if !ok {
		// Whatever this pid was before, it now belongs to something else.
		delete(c.m, r.pid)
		return "", "", false
	}
	if len(c.m) >= chainMax {
		c.prune(r.time + chainTTL/2)
		if len(c.m) >= chainMax {
			c.m = map[int]chainEntry{}
		}
	}
	c.m[r.pid] = chainEntry{ppid: r.ppid, agent: agent, session: session, at: r.time}
	return agent, session, true
}

// prune forgets entries not used since chainTTL before now (row time).
func (c *chainCache) prune(now int64) {
	for pid, e := range c.m {
		if now-e.at > chainTTL {
			delete(c.m, pid)
		}
	}
}
