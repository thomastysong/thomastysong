package procmon

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Bounds on what one event carries from a command line. A command line is
// whatever a process chose to exec; the emitted line is capped at 16 KiB
// downstream, and these keep a process event well inside that. The bounds
// apply to the REDACTED text: cutting first would leave half a secret
// whose closing quote or delimiter is gone, which no redaction rule
// recognises any more.
const (
	maxEventArgs     = 64
	maxEventArgBytes = 1024
	maxEventArgsSum  = 8192
	// maxNameBytes bounds a process name after redaction.
	maxNameBytes = 255
	// maxMarkerLen is the longest "[REDACTED:...]" or "[TRUNCATED:...]"
	// marker a cut looks back for, so that it never splits one.
	maxMarkerLen = 160
)

// emitArgs returns the form of an argument vector that may leave the
// monitor: redacted with classify.RedactArgs, then bounded. A cut argument
// ends in a "[TRUNCATED:<n>B]" marker; arguments past the bounds are
// replaced by one final "[TRUNCATED:<n>B]" placeholder counting their
// bytes. cut reports that anything was shortened or dropped.
//
// Redaction runs on the arguments that can be emitted plus one (RedactArgs
// carries state forward only, and the extra argument gives the last kept
// one its real successor), so its cost is bounded by the read limits on
// the command line, not by the argument count.
func emitArgs(raw []string) (out []string, cut bool) {
	if len(raw) == 0 {
		return nil, false
	}
	args, dropped := raw, 0
	if readerCut(raw) {
		// The reader stopped inside the last argument: whatever secret it
		// holds may have lost its end. It is never emitted.
		args, dropped, cut = raw[:len(raw)-1], len(raw[len(raw)-1]), true
	}
	keep := len(args)
	if keep > maxEventArgs {
		keep = maxEventArgs - 1 // room for the placeholder
		for _, a := range args[keep:] {
			dropped += len(a)
		}
		cut = true
	}
	end := keep + 1
	if end > len(args) {
		end = len(args)
	}
	red := classify.RedactArgs(args[:end])[:keep]
	// The placeholder must fit inside the total budget.
	budget := maxEventArgsSum - len(truncMarker(maxCmdlineBytes))
	total := 0
	for i, a := range red {
		if len(a) > maxEventArgBytes {
			a, cut = cutValue(a, maxEventArgBytes), true
		}
		if total+len(a) > budget {
			for _, b := range red[i:] {
				dropped += len(b)
			}
			cut = true
			break
		}
		total += len(a)
		out = append(out, a)
	}
	if dropped > 0 {
		out = append(out, truncMarker(dropped))
	}
	return out, cut
}

// readerCut reports that an argument vector filled the command-line read
// limit, so its last argument is probably incomplete.
func readerCut(args []string) bool {
	n := len(args) - 1
	for _, a := range args {
		n += len(a)
		if n >= maxCmdlineBytes-1 {
			return true
		}
	}
	return false
}

// emitName returns the form of a process name the monitor keeps and emits.
// A name is not always the program's: a Node process.title or a
// setproctitle(3) user writes its whole command line over argv[0], and the
// name refined from argv[0] (or the kernel's first 15 bytes of it) then
// carries that command line, credentials included. It gets the same
// redaction as the arguments, split on white space as the title was
// written.
func emitName(name string) string {
	if name == "" {
		return ""
	}
	var red string
	if len(name) <= 4*maxNameBytes && strings.ContainsAny(name, " \t") {
		red = strings.Join(classify.RedactArgs(strings.Fields(name)), " ")
	} else {
		red = classify.RedactArgs([]string{name})[0]
	}
	return cutValue(red, maxNameBytes)
}

// truncMarker states how many bytes were cut. Like classify's it carries no
// digest of the cut text: an unkeyed hash would confirm guesses about it.
func truncMarker(n int) string { return "[TRUNCATED:" + strconv.Itoa(n) + "B]" }

// cutValue shortens s to at most max bytes, ending in a "[TRUNCATED:<n>B]"
// marker. A cut never splits a rune or a marker already in s.
func cutValue(s string, max int) string {
	if len(s) <= max {
		return s
	}
	h := max - len(truncMarker(len(s)))
	if h < 0 {
		h = 0
	}
	for h > 0 && !utf8.RuneStart(s[h]) {
		h--
	}
	lo := h - maxMarkerLen
	if lo < 0 {
		lo = 0
	}
	for j := lo; j < h; j++ {
		if s[j] != '[' || !(strings.HasPrefix(s[j:], "[REDACTED:") || strings.HasPrefix(s[j:], "[TRUNCATED:")) {
			continue
		}
		if e := strings.IndexByte(s[j:], ']'); e < 0 || j+e >= h {
			h = j
			break
		}
	}
	return s[:h] + truncMarker(len(s)-h)
}

// isCutName reports a name that emitName had to shorten.
func isCutName(name string) bool {
	return strings.HasSuffix(name, "B]") && strings.Contains(name, "[TRUNCATED:")
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
	ev.Truncated = truncatedFields(ev.Process, r.argsCut)
	return ev
}

// truncatedFields lists the process fields of an event that were cut.
func truncatedFields(p *event.Process, argsCut bool) []string {
	var out []string
	if argsCut {
		out = append(out, "process.args")
	}
	if isCutName(p.Name) {
		out = append(out, "process.name")
	}
	return out
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
	ev.Truncated = truncatedFields(ev.Process, false)
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
	args, cut := o.args, o.argsCut
	if !o.argsDone {
		args, cut = emitArgs(rec.Args)
	}
	ev := m.newEvent(event.TypeProcessExec, ts, now)
	// The id covers the emitted (redacted) arguments only, through a keyed
	// digest (argsDigest): a digest of the raw command line would let a
	// reader test guesses about the credentials redaction removed. Its
	// time is the process's start, not the exec time the connector
	// reports, so the connector's record of an exec and a rescan's record
	// of the same process (after a restart, which reports every live
	// process again) get one id; with the daemon's persisted key
	// (Options.IDKey) that holds across restarts. A process that runs the
	// same program with the same arguments twice under one pid gets one id
	// for both.
	idAt := n.start
	if idAt.IsZero() {
		idAt = ev.TS.Time
	}
	ev.ID = event.StableID(idAt, event.TypeProcessExec, strconv.Itoa(n.pid), strconv.FormatUint(n.key, 10), n.exe, argsDigest(m.idKey, args))
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
		Args:       append([]string(nil), args...),
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
	ev.Truncated = truncatedFields(p, cut)
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

// argsKey is the key for argsDigest of a monitor without Options.IDKey:
// 32 random bytes drawn once per process and never stored. Ids are then
// stable within one run of the sensor and differ between runs.
var argsKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	// crypto/rand.Read does not fail on the supported systems (Go 1.24+
	// aborts the process instead of returning short), so k is always full.
	_, _ = rand.Read(k)
	return k
})

// minIDKey is the shortest Options.IDKey used (the engine's
// MinIdentityKeyLen); a shorter one is replaced by argsKey.
const minIDKey = 16

// argsKeyFor returns the argsDigest key for Options.IDKey: a copy of it,
// or argsKey when it is missing or too short.
func argsKeyFor(k []byte) []byte {
	if len(k) < minIDKey {
		return argsKey()
	}
	return bytes.Clone(k)
}

// argsDomain separates procmon's digests from every other digest under
// the same key (the daemon's identity key also keys the engine's prompt
// and content digests).
const argsDomain = "hawkbell/procmon/args/v1"

// argsDigest summarises emitted arguments for an event id with an HMAC
// under key. The arguments are procmon's own redaction of the command
// line; the privacy stage may redact more before a record leaves (a
// stricter profile, a pattern only it knows). An unkeyed digest of
// procmon's form would then be a guessing oracle: anyone holding the
// shipped record could hash candidate values for what privacy removed and
// compare with the id. Keyed, the id confirms nothing. The fingerprints in
// classify's markers are left out as well: they are unkeyed hashes of the
// secrets, and two runs of one command with different secrets are the same
// action as far as the id is concerned.
func argsDigest(key []byte, args []string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(argsDomain))
	h.Write([]byte{0})
	for _, a := range args {
		h.Write([]byte(stripFingerprints(a)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// stripFingerprints turns every "[REDACTED:<kind>:<fp>]" in s into
// "[REDACTED:<kind>]".
func stripFingerprints(s string) string {
	const open = "[REDACTED:"
	if !strings.Contains(s, open) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, open)
		if i < 0 {
			break
		}
		e := strings.IndexByte(s[i:], ']')
		if e < 0 || e > maxMarkerLen {
			b.WriteString(s[:i+len(open)])
			s = s[i+len(open):]
			continue
		}
		marker := s[i : i+e]
		if c := strings.LastIndexByte(marker, ':'); c >= len(open) {
			marker = marker[:c]
		}
		b.WriteString(s[:i])
		b.WriteString(marker)
		b.WriteByte(']')
		s = s[i+e+1:]
	}
	b.WriteString(s)
	return b.String()
}

// enqueue hands events to the emitter goroutine without blocking: the
// netlink reader must keep draining its socket whatever Emit does.
func (m *Monitor) enqueue(evs []*event.Event) {
	if m.o.Emit == nil || m.off.Load() {
		// Nothing leaves while the kill switch is on, including what a
		// reader that was mid-flight when it was pulled still produces.
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
