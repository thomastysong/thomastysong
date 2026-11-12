package procmon

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/osqexec"
)

// fakeOsq stands in for osqexec.Source. Like the real one it asks the
// monitor's Attribute callback about every row and returns only the rows
// that callback accepts.
type fakeOsq struct {
	mu     sync.Mutex
	attr   func(pid, ppid int) (string, string, bool)
	rows   [][2]int    // pid, ppid
	times  []time.Time // event time of each row (default: now)
	err    error
	polls  int
	status string
	closed int
	// canary makes Poll report the monitor's pending self-test process.
	canary func() int
}

func (f *fakeOsq) Close() {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
}

func (f *fakeOsq) Poll(context.Context) ([]*event.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.err != nil {
		f.status = "unavailable"
		return nil, f.err
	}
	f.status = "event"
	rows, times := f.rows, f.times
	f.rows, f.times = nil, nil
	if f.canary != nil {
		if pid := f.canary(); pid != 0 {
			rows = append(rows, [2]int{pid, os.Getpid()})
		}
	}
	var out []*event.Event
	for i, r := range rows {
		agent, session, ok := f.attr(r[0], r[1])
		if !ok {
			continue
		}
		ev := event.New(event.KindActivity, event.TypeProcessExec, event.SourceOsquery)
		if i < len(times) {
			ev.TS = event.At(times[i])
		}
		ev.Fidelity = event.FidelityObserved
		ev.Agent = &event.Agent{ID: agent}
		ev.Process = &event.Process{PID: r[0], PPID: r[1], Name: "x"}
		if session != "" {
			ev.Session = &event.Session{ID: session}
		}
		out = append(out, ev)
	}
	return out, nil
}

func (f *fakeOsq) Status() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func osqueryTree(h *fakeHost) {
	h.add(fakeProc{pid: 1, comm: "init", ticks: 1, args: []string{"/sbin/init"}, exe: "/sbin/init", uid: "0"})
	h.add(fakeProc{pid: 10, ppid: 1, comm: "claude", ticks: 100, args: []string{"claude"}, exe: "/usr/local/bin/claude",
		cgroup: "0::/system.slice/docker-" + dockerID + ".scope\n", children: []int{11}})
	h.add(fakeProc{pid: 11, ppid: 10, comm: "bash", ticks: 110, args: []string{"bash"}, exe: "/usr/bin/bash",
		env: map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s-11"}, children: []int{12}})
	h.add(fakeProc{pid: 12, ppid: 11, comm: "codex", ticks: 120, args: []string{"codex"}, exe: "/usr/local/bin/codex",
		env: map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s-11"}})
	h.add(fakeProc{pid: 20, ppid: 1, comm: "sshd", ticks: 50, args: []string{"sshd"}, exe: "/usr/sbin/sshd", uid: "0"})
}

func TestOsqAttribute(t *testing.T) {
	h := newFakeHost(t)
	osqueryTree(h)
	m, clk := newFixtureMonitor(t, h)
	m.fullScan(m.now())
	drain(m)

	check := func(pid, ppid int, agent, session string, ok bool) {
		t.Helper()
		a, s, k := m.osqAttribute(pid, ppid)
		if a != agent || s != session || k != ok {
			t.Errorf("osqAttribute(%d,%d) = %q %q %v, want %q %q %v", pid, ppid, a, s, k, agent, session, ok)
		}
	}
	check(11, 10, "claude-code", "s-11", true)
	check(10, 1, "", "", false)            // the root itself: its start is reported, not an exec
	check(12, 11, "claude-code", "", true) // a nested root is an exec of the enclosing agent
	check(9999, 11, "claude-code", "s-11", true)
	check(9999, 10, "claude-code", "", true)
	check(9999, 20, "", "", false)
	check(20, 1, "", "", false)

	// The shell exits; osquery reports its exec seconds later.
	h.remove(11)
	clk.add(time.Second)
	m.fullScan(m.now())
	check(11, 10, "claude-code", "s-11", true)
	clk.add(tombTTL + time.Second)
	m.mu.Lock()
	m.prune(m.now())
	m.mu.Unlock()
	check(11, 10, "claude-code", "", true) // the parent still answers
	check(11, 77, "", "", false)
}

func TestOsqueryProvider(t *testing.T) {
	h := newFakeHost(t)
	osqueryTree(h)
	m, clk := newFixtureMonitor(t, h)
	fo := &fakeOsq{attr: m.osqAttribute, rows: [][2]int{{4001, 11}, {4002, 20}}}
	m.osq = fo
	r := &runner{m: m}
	r.tick(t.Context())
	if m.Source() != SourceOsquery {
		t.Fatalf("source = %s", m.Source())
	}
	count := func(evs []*event.Event) (osq, poll int) {
		for _, e := range ofType(evs, event.TypeProcessExec) {
			switch e.Labels["exec_source"] {
			case SourceOsquery:
				osq++
				if e.Agent.PID != 10 || e.Agent.Name != "Claude Code" || e.Container == nil || e.Container.ID != dockerID {
					t.Errorf("osquery event not enriched: %+v %+v", e.Agent, e.Container)
				}
			default:
				poll++
			}
		}
		return
	}
	// The first tick scanned (the agent's running children are reported
	// from the scan) and then read osquery (one attributed row).
	if osq, poll := count(drain(m)); osq != 1 || poll != 2 {
		t.Fatalf("first tick: osquery events %d, poll events %d", osq, poll)
	}
	// From now on what the scan sees is left to osquery.
	h.add(fakeProc{pid: 14, ppid: 11, comm: "make", ticks: 140, args: []string{"make"}, exe: "/usr/bin/make"})
	fo.mu.Lock()
	fo.rows = [][2]int{{14, 11}}
	fo.mu.Unlock()
	clk.add(r.osqInterval())
	r.tick(t.Context())
	if osq, poll := count(drain(m)); osq != 1 || poll != 0 {
		t.Fatalf("second tick: osquery events %d, poll events %d", osq, poll)
	}
	if st := m.Stats(); st.OsqueryEvts != 2 || st.Osquery != "event" {
		t.Errorf("stats = %+v", st)
	}

	// osquery goes away: the poller reports again and osquery is retried
	// only after osqRetryEvery.
	fo.mu.Lock()
	fo.err = fmt.Errorf("%w: test", osqexec.ErrUnavailable)
	fo.mu.Unlock()
	clk.add(r.osqInterval())
	r.tick(t.Context())
	if m.Source() != SourcePoll {
		t.Fatalf("source after outage = %s", m.Source())
	}
	polls := fo.polls
	clk.add(10 * time.Second)
	r.tick(t.Context())
	if fo.polls != polls {
		t.Error("osquery retried before osqRetryEvery")
	}
	h.add(fakeProc{pid: 13, ppid: 11, comm: "ls", ticks: 130, args: []string{"ls"}, exe: "/usr/bin/ls"})
	clk.add(m.o.Idle)
	r.tick(t.Context())
	if e := byPID(ofType(drain(m), event.TypeProcessExec), 13); e == nil || e.Labels["exec_source"] != SourcePoll {
		t.Errorf("poll event after osquery outage = %+v", e)
	}
}

// TestOsqueryRateCapOnEventTime checks that osquery rows are capped by when
// the execs happened, not by when the batch arrived: osquery delivers rows
// seconds late and in batches, and a steady 10 execs a second must not be
// cut to the 20-per-second cap just because 60 of them arrive together.
func TestOsqueryRateCapOnEventTime(t *testing.T) {
	h := newFakeHost(t)
	osqueryTree(h)
	m, clk := newFixtureMonitor(t, h)
	m.fullScan(m.now())
	drain(m)
	fo := &fakeOsq{attr: m.osqAttribute}
	m.osq = fo

	feed := func(n int, at func(i int) time.Time) {
		fo.mu.Lock()
		for i := 0; i < n; i++ {
			fo.rows = append(fo.rows, [2]int{5000 + len(fo.rows), 11})
			fo.times = append(fo.times, at(i))
		}
		fo.mu.Unlock()
	}
	osqExecs := func() []*event.Event {
		var out []*event.Event
		for _, e := range ofType(drain(m), event.TypeProcessExec) {
			if e.Labels["exec_source"] == SourceOsquery {
				out = append(out, e)
			}
		}
		return out
	}

	// 60 execs at 10 a second over the six seconds before the poll.
	base := m.now().Add(-8 * time.Second)
	feed(60, func(i int) time.Time { return base.Add(time.Duration(i) * 100 * time.Millisecond) })
	if !m.pollOsquery(t.Context(), m.now()) {
		t.Fatal("osquery not delivering")
	}
	if got := osqExecs(); len(got) != 60 {
		t.Fatalf("steady rate: %d of 60 rows emitted (dropped %d)", len(got), m.Stats().RateDropped)
	}

	// 60 execs within one second: the cap applies.
	clk.add(5 * time.Second)
	burst := m.now().Add(-2 * time.Second)
	feed(60, func(int) time.Time { return burst })
	m.pollOsquery(t.Context(), m.now())
	if got := osqExecs(); len(got) != execRate {
		t.Fatalf("burst: %d rows emitted, want the cap %d", len(got), execRate)
	}
	if st := m.Stats(); st.RateDropped != 40 {
		t.Errorf("rate dropped = %d", st.RateDropped)
	}
	// The next row that gets through reports what was dropped.
	clk.add(time.Second)
	feed(1, func(int) time.Time { return m.now().Add(-time.Second) })
	m.pollOsquery(t.Context(), m.now())
	if got := osqExecs(); len(got) != 1 || got[0].Labels["exec_dropped"] != "40" {
		t.Fatalf("after the burst: %+v", got)
	}

	// Implausible row times (future, ancient) fall back to arrival time.
	now := m.now()
	for _, ts := range []time.Time{now.Add(time.Hour), now.Add(-24 * time.Hour), {}} {
		if got := osqRowTime(&event.Event{TS: event.At(ts)}, now); !got.Equal(now) {
			t.Errorf("osqRowTime(%v) = %v", ts, got)
		}
	}
}

// TestOsqueryClosed checks that the monitor lets go of osqueryd's socket
// when it stops and when the kill switch is pulled.
func TestOsqueryClosed(t *testing.T) {
	h := newFakeHost(t)
	osqueryTree(h)
	m, _ := newFixtureMonitor(t, h)
	fo := &fakeOsq{attr: m.osqAttribute}
	m.osq = fo
	var off atomic.Bool
	m.disabled = off.Load
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	waitFor(t, 5*time.Second, "osquery to be polled", func() bool {
		fo.mu.Lock()
		defer fo.mu.Unlock()
		return fo.polls > 0
	})
	off.Store(true)
	m.wake()
	waitFor(t, 5*time.Second, "the kill switch", func() bool { return m.Stats().Disabled })
	fo.mu.Lock()
	closed := fo.closed
	fo.mu.Unlock()
	if closed != 1 {
		t.Errorf("closed %d times after the kill switch", closed)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	fo.mu.Lock()
	defer fo.mu.Unlock()
	if fo.closed != 2 {
		t.Errorf("closed %d times after Run returned", fo.closed)
	}
}

// TestOsqueryCanary runs the real self-test process and has the fake
// provider report it, as osqexec would.
func TestOsqueryCanary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix canary")
	}
	if _, _, ok := canaryCommand(); !ok {
		t.Skip("no root-owned true(1) on this host")
	}
	h := newFakeHost(t)
	osqueryTree(h)
	m, clk := newFixtureMonitor(t, h)
	m.canaryFirst = 0
	fo := &fakeOsq{attr: m.osqAttribute, canary: m.canaryPID}
	m.osq = fo
	r := &runner{m: m}
	ctx := t.Context()
	r.tick(ctx) // osquery becomes the provider; the self-test starts
	if !m.canaryPending() {
		t.Fatal("no self-test started")
	}
	clk.add(r.osqInterval())
	r.tick(ctx) // osquery reports the canary row
	clk.add(time.Millisecond)
	r.tick(ctx)
	if !m.ExecHealthy() {
		t.Fatalf("exec provider not healthy: %+v", m.Stats())
	}
	for _, e := range drain(m) {
		if e.Agent != nil && e.Agent.ID == canaryAgent {
			t.Fatal("the canary was emitted")
		}
	}
	if st := m.Stats(); st.CanaryRuns != 1 || st.CanaryHits != 1 || st.LastCanary.IsZero() {
		t.Errorf("stats = %+v", st)
	}
	// A provider that stops reporting turns unhealthy at the next test.
	fo.mu.Lock()
	fo.canary = nil
	fo.mu.Unlock()
	clk.add(m.canaryEvery)
	r.tick(ctx)
	clk.add(canaryWaitOsq + time.Second)
	r.tick(ctx)
	if m.ExecHealthy() {
		t.Error("still healthy after a missed self-test")
	}
}
