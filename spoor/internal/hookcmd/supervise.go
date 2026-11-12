package hookcmd

import (
	"io"
	"strconv"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
	"github.com/thomastysong/spoor/internal/spool"
)

// supervise is `spoor hook`. It does as little as possible itself: kill
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
	// to answer when the agent is slow to close the pipe.
	in := readBounded(stdin, limit, time.Until(deadline)/2)
	s := &supervisor{o: o, env: env, cfg: cfg, m: m, t0: t0, payload: in.b}
	if in.timedOut {
		s.health(ReasonStdin, "stdin still open after "+strconv.FormatInt(time.Since(start).Milliseconds(), 10)+"ms")
	}

	exe, err := selfExe(env)
	if err != nil {
		s.health(ReasonWorkerStart, "executable path unavailable")
		return s.fallback(stdout)
	}
	argv := workerArgs(o, cfgPath, env.PPID, t0, deadline)
	res := runChild(exe, argv, in.b, MaxReply, deadline)
	if res.startErr != nil {
		s.health(ReasonWorkerStart, "worker could not be started")
		return s.fallback(stdout)
	}
	clean := res.exited && res.code == exitOK
	reply, ok := validReply(res.stdout, MaxReply)
	if ok && len(res.stdout) > 0 && !res.complete {
		ok = false // the pipe was abandoned: what was read may be a prefix
	}
	switch {
	case res.timedOut:
		s.health(ReasonWorkerTimeout, "worker killed at the "+strconv.FormatInt(deadline.Sub(start).Milliseconds(), 10)+"ms deadline")
	case !ok:
		s.health(ReasonBadReply, "worker reply of "+strconv.Itoa(len(res.stdout))+" bytes is not one complete JSON object under "+strconv.Itoa(MaxReply)+" bytes ("+res.state+")")
	case !clean:
		s.health(workerReason(res.code), res.state)
	}
	// A complete reply is forwarded even when the worker failed after
	// writing it (it writes the reply before appending its records).
	// Silence or a partial reply from a worker that did not finish cleanly
	// is not an answer.
	if !ok || (len(reply) == 0 && !clean) {
		return s.fallback(stdout)
	}
	if len(reply) > 0 {
		_, _ = stdout.Write(reply)
	}
	return 0
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
}

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

// health appends a health.error record to the user's spool when it can.
// It never blocks the reply for long: one spool append, no retries.
func (s *supervisor) health(reason, detail string) {
	defer func() { _ = recover() }()
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
	e := healthRecord(agentID, eventNameOf(s.payload, s.o.event, s.env.Getenv), reason, detail)
	_, markers := hookEnv(s.env.Getenv, s.o.event)
	st := newStamper(s.t0, s.env, s.env.PPID, markers, map[string]string{"hook_mode": s.m.String()})
	st.stamp(e, "health:"+reason+":"+strconv.FormatInt(s.t0.UnixNano(), 10))
	e.Source = event.SourceSensor
	_ = appendRecord(w, e)
}
