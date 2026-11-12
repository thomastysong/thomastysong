package procmon

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// runner holds the state only the Run goroutine touches.
type runner struct {
	m          *Monitor
	cn         cnConn
	cnStop     *atomic.Bool
	cnDone     chan error
	cnRetryAt  time.Time
	nextFull   time.Time
	nextActive time.Time
	nextOsq    time.Time
	noChildren bool
	disabled   bool
}

// Run monitors processes until ctx is cancelled, then returns nil. Exec
// providers are tried in order: the Linux process connector (when
// Options.ExecEvents is set and the kernel allows it), osquery's evented
// process table, then polling. Polling always runs as well: it finds agents
// that were running before the monitor started, resynchronises after the
// connector overflows, and is the only provider where the others are
// missing. Run returns an error when the Monitor could not be set up (no
// catalog, unusable HostRoot) or is already running.
func (m *Monitor) Run(ctx context.Context) (err error) {
	if m.initErr != nil {
		return m.initErr
	}
	if m.src == nil || m.cat == nil {
		return errors.New("procmon: monitor is not initialised (use New)")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !m.running.CompareAndSwap(false, true) {
		return errAlreadyRunning
	}
	defer m.running.Store(false)

	stopEmit := make(chan struct{})
	emitDone := make(chan struct{})
	go m.emitLoop(stopEmit, emitDone)
	r := &runner{m: m}
	defer func() {
		if rec := recover(); rec != nil {
			m.st.errors.Add(1)
			err = fmt.Errorf("procmon: internal error: %v", rec)
		}
		r.stopCN()
		close(stopEmit)
		select {
		case <-emitDone:
		case <-time.After(5 * time.Second):
		}
	}()
	return r.loop(ctx)
}

func (r *runner) loop(ctx context.Context) error {
	m := r.m
	r.tick(ctx)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		timer.Reset(r.wait(m.now()))
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		case <-m.nudge:
		case err := <-r.cnDone:
			r.cnFailed(err, m.now())
		}
		if ctx.Err() != nil {
			return nil
		}
		r.tick(ctx)
	}
}

func (r *runner) tick(ctx context.Context) {
	m := r.m
	now := m.now()
	if m.disabled() {
		if !r.disabled {
			r.enterDisabled()
		}
		return
	}
	if r.disabled {
		r.disabled = false
		r.nextFull = time.Time{}
	}
	m.refreshIndex(now)
	if r.cn == nil && m.o.ExecEvents && !now.Before(r.cnRetryAt) {
		r.startCN(ctx, now)
	}
	r.setProvider()
	// Scan before asking osquery: its rows are attributed through the
	// table, which must already hold the agents.
	switch {
	case m.resyncRq.Swap(false) || !now.Before(r.nextFull):
		r.full(now)
	case r.cn == nil && m.liveRoots() > 0 && !now.Before(r.nextActive):
		r.active(now)
	}
	if r.cn == nil && m.osq != nil && !now.Before(r.nextOsq) {
		live := m.pollOsquery(ctx, now)
		m.osqLive.Store(live)
		if live {
			r.nextOsq = now.Add(r.osqInterval())
		} else {
			r.nextOsq = now.Add(osqRetryEvery)
		}
		r.setProvider()
	}
	m.canaryTick(now, m.Source())
	m.mu.Lock()
	m.prune(now)
	m.mu.Unlock()
}

func (r *runner) osqInterval() time.Duration {
	if d := r.m.o.OsqueryInterval; d > 0 {
		return d
	}
	return 5 * time.Second
}

// full runs a full scan and schedules the next one. A scan never takes more
// than about 5% of a core: on a host with very many processes the interval
// stretches to twenty times the last scan's duration.
func (r *runner) full(now time.Time) {
	m := r.m
	start := time.Now()
	m.fullScan(now)
	took := time.Since(start)
	interval := m.o.Idle
	if r.cn != nil {
		interval = m.resync
	}
	if min := 20 * took; min > interval {
		interval = min
	}
	r.nextFull = now.Add(interval)
	r.nextActive = now.Add(m.o.Active)
}

func (r *runner) active(now time.Time) {
	m := r.m
	start := time.Now()
	if !r.noChildren && !m.activeScan(now) {
		r.noChildren = true
	}
	if r.noChildren {
		m.fullScan(now)
	}
	took := time.Since(start)
	interval := m.o.Active
	if min := 20 * took; min > interval {
		interval = min
	}
	r.nextActive = now.Add(interval)
}

// wait returns how long to sleep before the next tick.
func (r *runner) wait(now time.Time) time.Duration {
	m := r.m
	w := m.o.Idle
	until := func(t time.Time) time.Duration { return t.Sub(now) }
	if r.disabled {
		return w
	}
	if d := until(r.nextFull); d < w {
		w = d
	}
	if r.cn == nil && m.liveRoots() > 0 {
		if d := until(r.nextActive); d < w {
			w = d
		}
	}
	if r.cn == nil && m.osq != nil {
		if d := until(r.nextOsq); d < w {
			w = d
		}
	}
	if m.canaryPending() && w > 500*time.Millisecond {
		w = 500 * time.Millisecond
	}
	if w < 10*time.Millisecond {
		w = 10 * time.Millisecond
	}
	return w
}

func (r *runner) setProvider() {
	m := r.m
	switch {
	case r.cn != nil:
		m.provider.Store(SourceCNProc)
	case m.osqLive.Load():
		m.provider.Store(SourceOsquery)
	default:
		m.provider.Store(SourcePoll)
	}
}

func (r *runner) startCN(ctx context.Context, now time.Time) {
	m := r.m
	c, err := m.openCN()
	if err != nil {
		m.cnErr.Store(err.Error())
		r.cnRetryAt = now.Add(cnRetryEvery)
		return
	}
	stop := &atomic.Bool{}
	done := make(chan error, 1)
	r.cn, r.cnStop, r.cnDone = c, stop, done
	m.cnLive.Store(true)
	m.cnErr.Store("")
	m.osqLive.Store(false)
	go func() { done <- m.cnLoop(ctx, c, stop) }()
	// Whatever happened before the subscription is only in /proc.
	m.resyncRq.Store(true)
}

func (r *runner) cnFailed(err error, now time.Time) {
	m := r.m
	if r.cn != nil {
		r.cn.close()
	}
	r.cn, r.cnStop, r.cnDone = nil, nil, nil
	m.cnLive.Store(false)
	if err == nil {
		err = errors.New("procmon: process connector reader stopped")
	}
	m.cnErr.Store(err.Error())
	r.cnRetryAt = now.Add(cnRetryEvery)
	r.nextFull = now
}

// stopCN stops the reader and closes the socket. The reader notices within
// one read timeout; the socket is closed only after it has returned so that
// the descriptor cannot be reused under a pending read.
func (r *runner) stopCN() {
	if r.cn == nil {
		return
	}
	r.cnStop.Store(true)
	select {
	case <-r.cnDone:
	case <-time.After(3 * time.Second):
	}
	r.cn.close()
	r.cn, r.cnStop, r.cnDone = nil, nil, nil
	r.m.cnLive.Store(false)
}

// enterDisabled idles every provider while the kill switch file exists.
func (r *runner) enterDisabled() {
	m := r.m
	r.disabled = true
	r.stopCN()
	m.cnErr.Store("disabled by the kill switch")
	m.osqLive.Store(false)
	m.healthy.Store(false)
	m.provider.Store(SourceDisabled)
	m.mu.Lock()
	m.can = canaryState{}
	m.mu.Unlock()
}

func (m *Monitor) liveRoots() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.roots)
}

func (m *Monitor) canaryPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.can.pending
}
