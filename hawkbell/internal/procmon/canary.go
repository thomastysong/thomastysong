package procmon

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// The exec self-test. A provider can report itself active while delivering
// nothing (a subscriber whose publisher died, a netlink socket in the wrong
// namespace, a filter someone installed), so every five minutes the monitor
// runs a harmless program with a random nonce in its arguments and checks
// that the active provider reported that exec. ExecHealthy reflects the
// last result.
//
// The program is a fixed system binary (/usr/bin/true, or cmd.exe running
// "rem" on Windows), started directly with os.StartProcess: no shell, no
// PATH lookup, an empty environment, stdio on the null device. A Unix
// candidate must be a root-owned regular file that nobody else can write.

const canaryPrefix = "hawkbell-exec-canary-"

type canaryState struct {
	pending  bool
	provider string
	pid      int
	nonce    string
	started  time.Time
	next     time.Time
	hit      bool
	recent   [64]int // pids of the latest execs, for an exec seen before StartProcess returned
	recentAt int
}

// isCanary reports whether a process is the pending self-test. Being taken
// for the canary means not being ingested at all, so the test is narrow: a
// test must be pending, the process must be a child of this monitor, carry
// the nonce in its arguments and, once StartProcess has returned, have the
// canary's pid. The nonce is readable by every local user while the canary
// runs; none of them can make their process a child of the monitor.
func (m *Monitor) isCanary(rec *platform.Proc) bool {
	m.mu.Lock()
	pending, nonce, pid := m.can.pending, m.can.nonce, m.can.pid
	m.mu.Unlock()
	if !pending || nonce == "" || rec.PPID <= 0 || rec.PPID != m.canaryParent {
		return false
	}
	if pid != 0 && rec.PID != pid {
		return false
	}
	for _, a := range rec.Args {
		if a == nonce {
			return true
		}
	}
	return false
}

// canarySeen is called for every exec the connector reports. It records the
// pid (the canary's exec can arrive before StartProcess returns its pid) and
// reports whether it is the pending canary's pid, which proves the
// provider delivered that exec. Whether the process is skipped is decided
// on its record (isCanary), never on the pid alone.
func (m *Monitor) canarySeen(pid int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &m.can
	c.recent[c.recentAt%len(c.recent)] = pid
	c.recentAt++
	if c.pending && c.pid != 0 && pid == c.pid {
		c.hit = true
		return true
	}
	return false
}

// settle ends the pending self-test and forgets its nonce and pid, so that
// neither can be used afterwards to have a process skipped. Caller holds
// m.mu.
func (c *canaryState) settle(next time.Time) {
	c.pending, c.hit, c.pid, c.nonce = false, false, 0, ""
	c.next = next
}

func (m *Monitor) canaryHit() {
	m.mu.Lock()
	if m.can.pending {
		m.can.hit = true
	}
	m.mu.Unlock()
}

// canaryTick starts a self-test when one is due and settles the pending
// one. It runs on the monitor goroutine.
func (m *Monitor) canaryTick(now time.Time, provider string) {
	m.mu.Lock()
	c := &m.can
	if c.provider != provider {
		// A new provider has proved nothing yet.
		c.pending, c.provider, c.hit, c.pid, c.nonce = false, provider, false, 0, ""
		c.next = now.Add(m.canaryFirst)
		m.healthy.Store(false)
	}
	if provider != SourceCNProc && provider != SourceOsquery {
		m.mu.Unlock()
		m.healthy.Store(false)
		return
	}
	if c.pending {
		wait := canaryWaitCN
		if provider == SourceOsquery {
			wait = canaryWaitOsq
		}
		switch {
		case c.hit:
			c.settle(now.Add(m.canaryEvery))
			m.healthy.Store(true)
			m.st.canaryHits.Add(1)
			m.st.lastCanary.Store(now.UnixNano())
		case now.Sub(c.started) > wait || now.Before(c.started):
			c.settle(now.Add(m.canaryEvery))
			m.healthy.Store(false)
		}
		if c.pending || now.Before(c.next) {
			m.mu.Unlock()
			return
		}
	}
	if now.Before(c.next) {
		m.mu.Unlock()
		return
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	c.nonce = canaryPrefix + hex.EncodeToString(b[:])
	c.pending, c.hit, c.pid, c.started = true, false, 0, now
	nonce := c.nonce
	m.mu.Unlock()

	path, args, ok := m.canaryFn()
	if !ok {
		m.mu.Lock()
		c.settle(now.Add(m.canaryEvery))
		m.mu.Unlock()
		m.healthy.Store(false)
		return
	}
	m.st.canaryRuns.Add(1)
	pid, err := startCanary(path, append(args, nonce))
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		c.settle(now.Add(m.canaryEvery))
		m.healthy.Store(false)
		return
	}
	c.pid = pid
	for _, p := range c.recent {
		if p == pid {
			c.hit = true
		}
	}
}

// canaryPID returns the pid of the pending self-test, 0 when none.
func (m *Monitor) canaryPID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.can.pending {
		return m.can.pid
	}
	return 0
}

func startCanary(path string, args []string) (int, error) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		return 0, err
	}
	defer null.Close()
	p, err := os.StartProcess(path, args, &os.ProcAttr{
		Dir:   canaryDir(),
		Env:   []string{},
		Files: []*os.File{null, null, null},
	})
	if err != nil {
		return 0, err
	}
	pid := p.Pid
	go func() { _, _ = p.Wait() }()
	return pid, nil
}
