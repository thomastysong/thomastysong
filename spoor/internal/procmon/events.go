package procmon

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// Bounds on what one event carries from a command line. A command line is
// whatever a process chose to exec; the emitted line is capped at 16 KiB
// downstream, and these keep a process event well inside that.
const (
	maxEventArgs     = 64
	maxEventArgBytes = 1024
	maxEventArgsSum  = 8192
)

// capArgs bounds an argument list before redaction. cut reports that
// something was dropped or shortened.
func capArgs(args []string) (out []string, cut bool) {
	total := 0
	for i, a := range args {
		if i >= maxEventArgs {
			return out, true
		}
		if len(a) > maxEventArgBytes {
			a, cut = capString(a, maxEventArgBytes), true
		}
		if total+len(a) > maxEventArgsSum {
			return out, true
		}
		total += len(a)
		out = append(out, a)
	}
	return out, cut
}

// bucket is a token bucket. Each agent root may report at most `rate`
// process.exec events per second; the overflow is counted and the count is
// attached to the next event that gets through, so a burst is visible as a
// number rather than as silence.
type bucket struct {
	tokens  float64
	last    time.Time
	dropped uint64
	init    bool
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if !b.init {
		b.tokens, b.last, b.init = burst, now, true
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// exitInfo is a decoded exit status from the process connector.
type exitInfo struct {
	code, signal int
}

// exitFromStatus decodes the kernel's task exit_code, which has the wait(2)
// status layout: the terminating signal in the low 7 bits, else the exit
// code in bits 8..15.
func exitFromStatus(status uint32) *exitInfo {
	if sig := status & 0x7f; sig != 0 {
		return &exitInfo{signal: int(sig)}
	}
	return &exitInfo{code: int(status >> 8 & 0xff)}
}

func (m *Monitor) newEvent(typ string, ts, now time.Time) *event.Event {
	if ts.IsZero() {
		ts = now
	}
	ev := &event.Event{
		V:         event.SchemaVersion,
		TS:        event.At(ts),
		Kind:      event.KindActivity,
		Type:      typ,
		Source:    event.SourceProcess,
		Fidelity:  event.FidelityObserved,
		Integrity: m.integrity,
	}
	if now.Sub(ts) > time.Minute {
		ev.Emitted = event.At(now)
	}
	return ev
}

func eventUser(u event.User) *event.User {
	if u.Name == "" && u.ID == "" {
		return nil
	}
	v := u
	return &v
}

func eventContainer(c event.Container) *event.Container {
	if c == (event.Container{}) {
		return nil
	}
	v := c
	return &v
}

// startEvent reports an agent root. TS is the process start, so a sensor
// restart reports the same record (same id) for an agent that kept running.
func (m *Monitor) startEvent(r *root, now time.Time) *event.Event {
	ap := &r.ap
	ev := m.newEvent(event.TypeAgentProcessStart, ap.Start, now)
	ev.ID = event.StableID(ev.TS.Time, event.TypeAgentProcessStart, strconv.Itoa(ap.PID), strconv.FormatUint(r.k.key, 10))
	ev.Agent = &event.Agent{ID: ap.AgentID, Name: r.prod.name, PID: ap.PID}
	ev.User = eventUser(ap.User)
	ev.Process = &event.Process{
		PID:        ap.PID,
		PPID:       ap.PPID,
		Name:       ap.Name,
		Exe:        ap.Exe,
		Args:       append([]string(nil), ap.Args...),
		StartTime:  event.At(ap.Start),
		User:       ap.User.Name,
		Ancestors:  append([]string(nil), ap.Ancestors...),
		EnvMarkers: append([]string(nil), ap.EnvMarkers...),
		Flags:      append([]string(nil), ap.Flags...),
	}
	if ap.Start.IsZero() {
		ev.Process.StartTime = event.Time{}
	}
	if ap.CWD != "" {
		ev.Session = &event.Session{CWD: ap.CWD}
	}
	ev.Container = eventContainer(ap.Container)
	ev.Labels = rootLabels(ap)
	if r.argsCut {
		ev.Truncated = []string{"process.args"}
	}
	return ev
}

// rootLabels carries the AgentProc attributes that have no field in the
// event contract. Rules match them as labels.<name>.
func rootLabels(ap *AgentProc) map[string]string {
	l := map[string]string{}
	set := func(k string, v bool) {
		if v {
			l[k] = "true"
		}
	}
	set("headless", ap.Headless)
	set("bare", ap.Bare)
	set("hook_free", ap.HookFree)
	set("persistence_free", ap.PersistenceFree)
	if ap.LifecycleParent != "" {
		l["lifecycle_parent"] = ap.LifecycleParent
	}
	if ap.ConfigHome != "" {
		l["config_home"] = ap.ConfigHome
	}
	if ap.ParentAgent != "" {
		l["parent_agent"] = ap.ParentAgent
	}
	if len(ap.Evidence) > 0 {
		l["evidence"] = strings.Join(ap.Evidence, ",")
	}
	if len(l) == 0 {
		return nil
	}
	return l
}

// stopEvent reports the end of an agent root.
func (m *Monitor) stopEvent(r *root, at time.Time, exit *exitInfo) *event.Event {
	ap := &r.ap
	ev := m.newEvent(event.TypeAgentProcessStop, at, at)
	ev.ID = event.StableID(ev.TS.Time, event.TypeAgentProcessStop, strconv.Itoa(ap.PID), strconv.FormatUint(r.k.key, 10))
	ev.Agent = &event.Agent{ID: ap.AgentID, Name: r.prod.name, PID: ap.PID}
	ev.User = eventUser(ap.User)
	ev.Process = &event.Process{
		PID: ap.PID, PPID: ap.PPID, Name: ap.Name, Exe: ap.Exe,
		StartTime: event.At(ap.Start), User: ap.User.Name,
		Flags: append([]string(nil), ap.Flags...),
	}
	if ap.Start.IsZero() {
		ev.Process.StartTime = event.Time{}
	}
	if n := len(ap.SessionIDs); n > 0 {
		ev.Session = &event.Session{ID: ap.SessionIDs[n-1]}
	}
	ev.Container = eventContainer(ap.Container)
	out := &event.Outcome{Status: "unknown"}
	if !ap.Start.IsZero() && at.After(ap.Start) {
		out.DurationMS = at.Sub(ap.Start).Milliseconds()
	}
	if exit != nil {
		switch {
		case exit.signal != 0:
			out.Status = "interrupted"
			out.Error = "signal " + strconv.Itoa(exit.signal)
		case exit.code == 0:
			out.Status = "ok"
			code := 0
			out.ExitCode = &code
		default:
			out.Status = "error"
			code := exit.code
			out.ExitCode = &code
		}
	}
	ev.Outcome = out
	if len(ap.SessionIDs) > 1 {
		ev.Labels = map[string]string{"sessions": strconv.Itoa(len(ap.SessionIDs))}
	}
	return ev
}

// execFor applies the per-root rate cap and builds a process.exec event.
// Caller holds m.mu.
func (m *Monitor) execFor(n *node, o *observed, owner *root, marker string, now time.Time) []*event.Event {
	if o.rec == nil {
		return nil
	}
	m.st.attributed.Add(1)
	if o.via == viaPoll && m.osqLive.Load() {
		// osquery is the exec provider; a process the poller happened to
		// see is reported by osquery with the exec itself.
		return nil
	}
	var b *bucket
	if owner != nil {
		b = &owner.bucket
	} else {
		b = m.markerB[marker]
		if b == nil {
			b = &bucket{}
			m.markerB[marker] = b
		}
	}
	if !b.take(now, m.rate, m.burst) || !m.global.take(now, globalExecRate, globalExecRate) {
		b.dropped++
		m.st.rateDropped.Add(1)
		return nil
	}
	ev := m.execEvent(n, o, owner, marker, now)
	if b.dropped > 0 {
		ev.Labels["exec_dropped"] = strconv.FormatUint(b.dropped, 10)
		b.dropped = 0
	}
	m.st.execEvents.Add(1)
	return []*event.Event{ev}
}

func (m *Monitor) execEvent(n *node, o *observed, owner *root, marker string, now time.Time) *event.Event {
	rec := o.rec
	ts := o.ts
	if ts.IsZero() {
		ts = rec.Start
	}
	args, cut := capArgs(rec.Args)
	ev := m.newEvent(event.TypeProcessExec, ts, now)
	ev.ID = event.StableID(ev.TS.Time, event.TypeProcessExec, strconv.Itoa(n.pid), strconv.FormatUint(n.key, 10), rec.Exe, argsDigest(args))
	product := marker
	attribution := "env_marker"
	if owner != nil {
		product = owner.prod.id
		attribution = "tree"
		ev.Agent = &event.Agent{ID: owner.ap.AgentID, Name: owner.prod.name, PID: owner.ap.PID}
		ev.Container = eventContainer(owner.ap.Container)
	} else {
		a := &event.Agent{ID: marker}
		if pi := m.index().prod(marker); pi != nil {
			a.Name = pi.name
		}
		ev.Agent = a
	}
	ev.User = eventUser(event.User{Name: n.user, ID: n.uid})
	p := &event.Process{
		PID:        n.pid,
		PPID:       n.ppid,
		Name:       n.name,
		Exe:        n.exe,
		Args:       classify.RedactArgs(args),
		User:       n.user,
		Ancestors:  m.execAncestors(n, owner),
		EnvMarkers: append([]string(nil), n.env.markers...),
	}
	if !n.start.IsZero() {
		p.StartTime = event.At(n.start)
	}
	if o.cand != nil {
		// The process is itself an agent (nested, relaunched, or a
		// launcher's payload): its risky flags matter as much as a root's.
		p.Flags = append([]string(nil), o.cand.ap.Flags...)
	}
	ev.Process = p
	sid := n.env.session(product)
	if sid == "" && owner != nil && len(owner.ap.SessionIDs) == 1 {
		sid = owner.ap.SessionIDs[0]
	}
	if sid != "" || o.cwd != "" {
		ev.Session = &event.Session{ID: sid, CWD: o.cwd}
	}
	if cut {
		ev.Truncated = []string{"process.args"}
	}
	ev.Labels = map[string]string{"exec_source": o.via, "attribution": attribution}
	return ev
}

// execAncestors lists process names from the parent of n up to and
// including the agent root it belongs to.
func (m *Monitor) execAncestors(n *node, owner *root) []string {
	var out []string
	p := m.parentOf(n)
	for d := 0; p != nil && d < maxExecAnc; d++ {
		out = append(out, p.name)
		if owner != nil && p == owner.n {
			break
		}
		p = m.parentOf(p)
	}
	return out
}

func argsDigest(args []string) string {
	h := sha256.New()
	for _, a := range args {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// enqueue hands events to the emitter goroutine without blocking: the
// netlink reader must keep draining its socket whatever Emit does.
func (m *Monitor) enqueue(evs []*event.Event) {
	if m.o.Emit == nil {
		return
	}
	for _, ev := range evs {
		if ev == nil {
			continue
		}
		select {
		case m.queue <- ev:
		default:
			m.st.queueDropped.Add(1)
		}
	}
}

// emitLoop calls Options.Emit in order until stop is closed, then drains
// what is queued.
func (m *Monitor) emitLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case ev := <-m.queue:
			m.emitOne(ev)
		case <-stop:
			for {
				select {
				case ev := <-m.queue:
					m.emitOne(ev)
				default:
					return
				}
			}
		}
	}
}

func (m *Monitor) emitOne(ev *event.Event) {
	defer func() {
		if recover() != nil {
			m.st.errors.Add(1)
		}
	}()
	if m.o.Emit != nil {
		m.o.Emit(ev)
	}
}
