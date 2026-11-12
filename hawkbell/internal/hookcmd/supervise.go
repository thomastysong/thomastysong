package hookcmd

import (
	"bytes"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/hookio"
	"github.com/thomastysong/thomastysong/hawkbell/internal/spool"
)

// supervise is `hawkbell hook`. It does as little as possible itself: kill
// switch, config, a bounded read of stdin, then a worker process does the
// rest under a hard deadline. Every outcome other than a healthy worker
// reply is answered with the dialect's allow-shaped reply (observe mode) or
// its timeout reply (guard mode), and the exit status is always 0.
//
// An in-process recover cannot provide that: a panic in another goroutine,
// a stack overflow, concurrent map writes and a deadlock all end a Go
// program with exit status 2, which every agent reads as "block" (a
// crashing UserPromptSubmit hook in Claude Code rejects every prompt, a
// crashing Stop hook keeps the agent running, a crashing Copilot
// preToolUse hook denies every tool call). Only a separate process
// contains them.
//
// Nothing before the reply touches the spool: health records are collected
// and appended only after the reply is written, with a bounded wait,
// because the spool's lock can be held by any process of the user.
func supervise(stdin io.Reader, stdout io.Writer, o opts, env Env) int {
	start := time.Now()
	t0 := env.Now()
	cfgPath := configPath(o)
	if killSwitch(cfgPath) {
		return 0
	}
	cfg, _ := loadConfig(cfgPath) // the worker reports a bad config on its records
	m := modeOf(cfg)
	if !m.enabled {
		return 0
	}
	deadline := start.Add(hardDeadline(cfg, m))
	limit := inputCap(cfg)

	// stdin gets at most half of the budget, so a worker still has time
	// to answer when the agent is slow to close the pipe. The worker is
	// told when the wait ran out: what it got may be a prefix, and in guard
	// mode a prefix that does not parse is answered "ask", not "allow".
	in := readBounded(stdin, limit, time.Until(deadline)/2)
	s := &supervisor{o: o, env: env, cfg: cfg, m: m, t0: t0, payload: in.b}
	defer s.flush()
	if in.timedOut {
		s.note(ReasonStdin, "stdin still open after "+strconv.FormatInt(time.Since(start).Milliseconds(), 10)+"ms")
	}

	exe, err := selfExe(env)
	if err != nil {
		s.note(ReasonWorkerStart, "executable path unavailable")
		return s.fallback(stdout)
	}
	argv := workerArgs(o, cfgPath, env.PPID, t0, deadline, in)
	res := runChild(exe, argv, workerEnviron(in), in.b, MaxReply+len(replyEnd), deadline)
	if res.startErr != nil {
		s.note(ReasonWorkerStart, "worker could not be started")
		return s.fallback(stdout)
	}
	clean := res.exited && res.code == exitOK
	out, final := unframe(res.stdout)
	reply, ok := validReply(out, MaxReply)
	if ok && len(out) > 0 && !res.complete && !final {
		ok = false // the pipe was abandoned: what was read may be a prefix
	}
	after := ""
	if final {
		after = " after its reply"
	}
	switch {
	case res.timedOut:
		s.note(ReasonWorkerTimeout, "worker killed at the "+strconv.FormatInt(deadline.Sub(start).Milliseconds(), 10)+"ms deadline"+after)
	case !ok:
		s.note(ReasonBadReply, "worker reply of "+strconv.Itoa(len(out))+" bytes is not one complete JSON object under "+strconv.Itoa(MaxReply)+" bytes ("+res.state+")")
	case !clean:
		s.note(workerReason(res.code), res.state+after)
	}
	// A framed reply is the worker's final decision, empty ("proceed")
	// included, whatever became of the worker afterwards: it answers
	// before it appends its records, so a full disk, an unsafe spool or a
	// spool lock held by another process cost the records, not the answer.
	// Without the frame, a complete reply object is still forwarded (the
	// worker writes it in one piece), but silence from a worker that did
	// not finish cleanly is not an answer.
	if !ok || (!final && len(reply) == 0 && !clean) {
		return s.fallback(stdout)
	}
	if len(reply) > 0 {
		_, _ = stdout.Write(reply)
	}
	return 0
}

// unframe splits a framed worker reply. final reports that the output
// ends with replyEnd; anything else is returned unchanged and not final.
func unframe(b []byte) (reply []byte, final bool) {
	if bytes.HasSuffix(b, []byte(replyEnd)) {
		return b[:len(b)-len(replyEnd)], true
	}
	return b, false
}

// workerReason maps a worker exit code to a health reason.
func workerReason(code int) string {
	switch code {
	case exitSpool:
		return ReasonSpool
	case exitRender:
		return ReasonRender
	case exitWatchdog:
		return ReasonWorkerTimeout
	}
	return ReasonWorkerCrash
}

// supervisor carries what the failure path needs.
type supervisor struct {
	o       opts
	env     Env
	cfg     *config.Config
	m       mode
	t0      time.Time
	payload []byte
	notes   []healthNote
}

type healthNote struct{ reason, detail string }

// fallback answers for a worker that did not: nothing (proceed) in observe
// mode, and the dialect's "ask" in guard mode when the event is one the
// agent gates. On Codex and Gemini an ask is rendered as a warning and the
// action proceeds; on events an agent does not gate there is nothing to
// answer. The exit status is 0 in every case.
func (s *supervisor) fallback(stdout io.Writer) int {
	if !s.m.guard {
		return 0
	}
	defer func() { _ = recover() }()
	d := s.dialect()
	req := fallbackRequest(d, eventNameOf(s.payload, s.o.event, s.env.Getenv))
	if req == nil || !req.Blocking {
		return 0
	}
	reply, ok := render(d, req, hookio.Decision{Action: hookio.ActionAsk, Reason: "the guard check did not complete; confirm this action"})
	if !ok {
		return 0
	}
	if r, ok := validReply(reply, MaxReply); ok && len(r) > 0 {
		_, _ = stdout.Write(r)
	}
	return 0
}

// dialect resolves the dialect for the fallback reply. hookio.Detect runs
// only when --agent is missing or unknown (the installer always writes it).
func (s *supervisor) dialect() hookio.Dialect {
	if d, ok := hookio.Get(s.o.agent); ok {
		return d
	}
	env, _ := hookEnv(s.env.Getenv, s.o.event)
	if d, ok := hookio.Detect(s.payload, env); ok {
		return d
	}
	return nil
}

// healthWait bounds the health appends after the reply is written. Each
// is one spool append, which waits for the spool's lock without a timeout
// (spool.Append); any process of the user can hold that lock.
const healthWait = 250 * time.Millisecond

// healthPending lets tests wait for appends the supervisor stopped waiting
// for. Production never waits on it: the process exits.
var healthPending sync.WaitGroup

// note records a health reason to append once the reply is out.
func (s *supervisor) note(reason, detail string) {
	s.notes = append(s.notes, healthNote{reason, detail})
}

// flush appends the noted health.error records to the user's spool when it
// can, waiting at most healthWait. The reply has already been written, so
// a slow or blocked spool delays only the exit, by a bounded amount, and
// never what the agent was told.
func (s *supervisor) flush() {
	if len(s.notes) == 0 {
		return
	}
	notes := s.notes
	s.notes = nil
	done := make(chan struct{})
	healthPending.Add(1)
	go func() {
		defer healthPending.Done()
		defer close(done)
		defer func() { _ = recover() }()
		s.appendHealth(notes)
	}()
	t := time.NewTimer(healthWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

func (s *supervisor) appendHealth(notes []healthNote) {
	dir, err := spool.Dir(s.cfg.DataDir, s.env.UID, s.env.Home)
	if err != nil {
		return
	}
	w, err := spool.OpenWriter(dir)
	if err != nil {
		return
	}
	agentID := ""
	if id, ok := hookio.AgentIDFor(s.o.agent); ok {
		agentID = id
	} else if t := token(s.o.agent, 32); t != "other" {
		agentID = t
	}
	eventName := eventNameOf(s.payload, s.o.event, s.env.Getenv)
	_, markers := hookEnv(s.env.Getenv, s.o.event)
	st := newStamper(s.t0, s.env, s.env.PPID, markers, map[string]string{"hook_mode": s.m.String()})
	for _, n := range notes {
		e := healthRecord(agentID, eventName, n.reason, n.detail)
		st.stamp(e, "health:"+n.reason+":"+strconv.FormatInt(s.t0.UnixNano(), 10))
		e.Source = event.SourceSensor
		_ = appendRecord(w, e)
	}
}
