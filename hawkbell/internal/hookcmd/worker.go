package hookcmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/hookio"
	"github.com/thomastysong/thomastysong/hawkbell/internal/privacy"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
	"github.com/thomastysong/thomastysong/hawkbell/internal/spool"
)

const (
	// replyMargin is kept free before the hard deadline for writing the
	// reply after evaluation.
	replyMargin = 15 * time.Millisecond
	// watchdogSlack is how long a supervised worker outlives its hard
	// deadline before it exits on its own. The supervisor kills it at the
	// deadline; the watchdog covers a supervisor that was itself killed by
	// the agent, so an orphaned worker cannot linger.
	watchdogSlack = time.Second
	// stdinGrace is how long past the hard deadline a worker still waits
	// for its stdin to close, and for its spool appends. Under a supervisor
	// neither ever waits (the supervisor writes the payload and closes the
	// pipe; it kills the worker at the deadline); the bound is for a worker
	// run by hand.
	stdinGrace = watchdogSlack / 2

	// Session state is saved under a lock with a bounded wait, retrying
	// the evaluation when another hook of the session saved in between.
	stateLockName    = ".hook-state.lock"
	stateLockWait    = 100 * time.Millisecond
	lockPoll         = time.Millisecond
	maxStateAttempts = 4
	minRetryBudget   = 2 * replyMargin
)

// replyEnd ends a framed worker reply (--framed, set by the supervisor):
// the decision is final, whether the reply before it is empty or not, and
// whatever the worker does afterwards (append, crash, hang on a lock) does
// not change it. A NUL byte never occurs in JSON text, so the marker
// cannot be part of a reply.
const replyEnd = "\x00hawkbell-reply-end\x00"

// Test seams. All are no-ops or the real thing in production; the fault
// hook can only be set from this package's tests, never from the
// environment or the command line.
var (
	exitFunc     = os.Exit
	faultHook    func(stage string)
	appendRecord = func(w *spool.Writer, e *event.Event) error { return w.Append(e) }
	renderReply  = render
)

func fault(stage string) {
	if faultHook != nil {
		faultHook(stage)
	}
}

// work is one worker invocation.
type work struct {
	o        opts
	env      Env
	cfg      *config.Config
	cfgErr   error
	m        mode
	t0       time.Time
	deadline time.Time
	in       inputResult

	dialect  hookio.Dialect
	agentID  string
	envMap   map[string]string
	markers  []string
	spool    *spool.Writer
	spoolDir string
	spoolErr error
	// prune lists what this hook deletes its own expired files from
	// (spool.Location.Prune); empty when the spool could not be opened.
	prune  []spool.Target
	policy *privacy.Policy
}

// runWorker does the actual work of one hook invocation: parse, stamp,
// optionally evaluate, answer, append. It runs in its own process under the
// supervisor (or directly, unsupervised, when invoked with --worker by hand).
func runWorker(stdin io.Reader, stdout io.Writer, o opts, env Env) int {
	start := time.Now()
	w := &work{o: o, env: env, t0: o.t0}
	if w.t0.IsZero() {
		w.t0 = env.Now()
	}
	w.cfg, w.cfgErr = loadConfig(configPath(o))
	w.m = modeOf(w.cfg)
	w.deadline = o.deadline
	if w.deadline.IsZero() {
		w.deadline = start.Add(hardDeadline(w.cfg, w.m))
	} else {
		// Stopped on return: it is for a worker that never returns.
		defer armWatchdog(w.deadline).Stop()
	}
	if !w.m.enabled {
		w.answer(stdout, nil)
		return exitOK
	}
	fault("start")
	// The wait is not cut to the guard budget: a worker that starts late
	// must still read the payload its supervisor already wrote (an empty
	// read would decide "allow"). The evaluation budget, not the read,
	// shrinks with the time left, and an evaluation without time answers
	// "ask".
	w.in = readBounded(stdin, inputCap(w.cfg), time.Until(w.deadline)+stdinGrace)
	w.adoptSupervisorRead()
	return w.run(stdout)
}

// adoptSupervisorRead folds in what the supervisor knows about stdin: that
// it stopped waiting for the agent to close it (the payload may be a
// prefix), and the size (--stdin-bytes) and digest (envStdinSHA256, not
// argv: see there) of bytes it drained past the cap.
func (w *work) adoptSupervisorRead() {
	if w.o.stdinCut {
		w.in.timedOut = true
	}
	n, sum := w.o.stdinBytes, strings.ToLower(handoffDigest(w.env.Getenv))
	if n > int64(len(w.in.b)) && n >= w.in.total && isHexSHA256(sum) {
		w.in.total, w.in.sum = n, sum
	}
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// answer writes the reply in one write. Under a supervisor (--framed) it
// ends with replyEnd, so an empty reply ("proceed") is as final as a deny.
func (w *work) answer(stdout io.Writer, reply []byte) {
	if w.o.framed {
		reply = append(append(make([]byte, 0, len(reply)+len(replyEnd)), reply...), replyEnd...)
	}
	if len(reply) > 0 {
		_, _ = stdout.Write(reply)
	}
}

func armWatchdog(deadline time.Time) *time.Timer {
	return time.AfterFunc(max0(time.Until(deadline)+watchdogSlack), func() { exitFunc(exitWatchdog) })
}

func (w *work) run(stdout io.Writer) int {
	payload := w.in.b
	limit := inputCap(w.cfg)
	w.envMap, w.markers = hookEnv(w.env.Getenv, w.o.event)
	w.dialect = resolveDialect(w.o.agent, payload, w.envMap)
	w.agentID = agentIDOf(w.dialect, w.o.agent)
	evs, req, anomaly := w.parse(payload, limit)
	fault("parsed")

	w.openSpool()
	ppid := w.o.ppid
	if ppid <= 0 {
		ppid = w.env.PPID
	}
	st := newStamper(w.t0, w.env, ppid, w.markers, w.baseLabels())
	st.payload = payload
	st.salt = loadSalt(w.spool)
	if anomaly != "" {
		size, digest := w.in.rawDigest()
		evs = append(evs, anomalyRecord(w.agentID, anomaly, payload, size, digest))
	}
	stampAll(st, evs)

	w.policy = w.privacyPolicy()
	kept := evs[:0]
	for _, e := range evs {
		if e != nil && !w.policy.Excluded(e) {
			kept = append(kept, e)
		}
	}
	evs = kept
	if len(evs) == 0 {
		// Excluded sessions leave no record and get no decision: exclusion
		// happens before any content processing. The account's expired
		// spool files are still deleted, after the reply: an account
		// excluded after it was recorded must not keep them for good.
		w.answer(stdout, nil)
		w.bounded(func() int { w.pruneSpools(); return exitOK })
		return exitOK
	}

	var ev evalResult
	if w.m.rules() {
		ev = w.evaluate(evs)
	}
	dec := w.decision(ev, req, anomaly)

	code := exitOK
	var reply []byte
	if dec.Action != hookio.ActionNone && req != nil {
		r, ok := renderReply(w.dialect, req, dec)
		if !ok {
			code = exitRender
		}
		reply = r
	}
	fault("reply")
	// One write: the supervisor forwards only a complete object, and a
	// reply under the pipe buffer size arrives in one piece. It goes out
	// before the records, so a decision survives a spool that cannot be
	// written. A decision that could not be rendered is not answered at
	// all (no end marker either): the supervisor then gives the dialect's
	// fallback ("ask" in guard mode) instead of an implicit "proceed".
	if code != exitRender {
		w.answer(stdout, reply)
	}
	carried := replyCarries(reply, dec.Action)
	annotateDecision(evs, ev.dets, dec, reply, carried)

	fault("append")
	if c := w.appendBounded(evs, ev); c != exitOK && code == exitOK {
		code = c
	}
	return code
}

// resolveDialect picks the wire format: --agent when it names a known
// dialect, else whatever the payload looks like.
func resolveDialect(agent string, payload []byte, env map[string]string) hookio.Dialect {
	if agent != "" {
		if d, ok := hookio.Get(agent); ok {
			return d
		}
	}
	if d, ok := hookio.Detect(payload, env); ok {
		return d
	}
	return nil
}

func agentIDOf(d hookio.Dialect, flag string) string {
	if d != nil {
		if id, ok := hookio.AgentIDFor(d.ID()); ok {
			return id
		}
	}
	if t := token(flag, 32); t != "" && t != "other" {
		return t
	}
	return "unknown"
}

// parse turns the payload into events. code is the anomaly to report next
// to (or instead of) the events.
func (w *work) parse(payload []byte, limit int) (evs []*event.Event, req *hookio.Request, code string) {
	if w.dialect == nil {
		return nil, nil, anomalyUnknownAgent
	}
	if len(payload) > limit && limit < hookio.MaxInput {
		// Over an operator cap below hookio's: nothing is decoded, but the
		// event name is enough for a guard answer.
		return nil, fallbackRequest(w.dialect, eventNameOf(payload, w.o.event, w.env.Getenv)), anomalyTooLarge
	}
	evs, req, err := w.dialect.Parse(payload, w.envMap)
	if err == nil {
		if len(evs) == 0 {
			code = anomalyNoEvent
		}
		return evs, req, code
	}
	switch {
	case errors.Is(err, hookio.ErrTooLarge):
		code = anomalyTooLarge
	case errors.Is(err, hookio.ErrTooDeep):
		code = anomalyTooDeep
	case errors.Is(err, hookio.ErrEmpty):
		code = anomalyEmpty
	case errors.Is(err, hookio.ErrNoEvent):
		code = anomalyNoEvent
	case errors.Is(err, hookio.ErrInternal):
		code = anomalyInternal
	default:
		code = anomalyMalformed
	}
	if w.in.timedOut && (code == anomalyMalformed || code == anomalyEmpty) {
		// The agent had not finished writing: what did not parse may be
		// a prefix of a gated call, so the event name (read from the
		// prefix, --event or the environment) still gets a guard answer.
		code = anomalyStdin
		if req == nil {
			req = fallbackRequest(w.dialect, eventNameOf(payload, w.o.event, w.env.Getenv))
		}
	}
	return evs, req, code
}

func (w *work) openSpool() {
	loc, err := spool.Locate(w.cfg.DataDir, w.env.UID, w.env.Home)
	if err == nil {
		w.spool, err = spool.OpenWriter(loc.Dir)
	}
	if err == nil {
		w.spoolDir, w.prune = loc.Dir, loc.Prune
	}
	w.spoolErr = err
}

// pruneSpools deletes this account's expired files that no daemon
// deletes, in the directories spool.Location.Prune lists: record files,
// session state and temporary files in the fallback spool in the home
// (also while the system spool is in use; not while $HAWKBELL_SPOOL is
// set) or in a $HAWKBELL_SPOOL directory, and only session state and
// temporary files in the system spool, whose record files the daemon
// deletes (also when $HAWKBELL_SPOOL names it). It uses retention.spool and runs after the
// reply, inside appendBounded's time bound: after the records are appended,
// or in place of that when every event was excluded. A directory not due
// for a scan (spool.MaybePrune) costs one lstat, two when it does not
// exist.
func (w *work) pruneSpools() {
	for _, t := range w.prune {
		_, _ = spool.MaybePrune(t, w.cfg.Retention.Spool.D())
	}
}

// baseLabels are put on every record: the operator's labels, the hook
// mode, and a config that could not be used.
func (w *work) baseLabels() map[string]string {
	l := make(map[string]string, len(w.cfg.Labels)+2)
	for k, v := range w.cfg.Labels {
		l[k] = v
	}
	l["hook_mode"] = w.m.String()
	if w.cfgErr != nil {
		l["hook_config"] = "invalid"
	}
	return l
}

func (w *work) privacyPolicy() *privacy.Policy {
	prof, err := privacy.ParseProfile(w.cfg.Privacy.Profile)
	if err != nil {
		prof = privacy.ProfileMinimal
	}
	ex := w.cfg.Privacy.Exclude
	// No key: the tenant key file is root-only, and in daemonless mode the
	// hook emits no content-derived digest at all.
	return &privacy.Policy{
		Profile:           prof,
		KeyID:             w.cfg.Privacy.KeyID,
		PseudonymizeUsers: w.cfg.Privacy.PseudonymizeUsers,
		Exclude:           privacy.Exclusions{Paths: ex.Paths, Repos: ex.Repos, Users: ex.Users},
		MaxLine:           w.cfg.Output.MaxLine,
	}
}

// stampAll stamps every record. Several records of one payload that share
// a natural key and type get an index so their ids differ.
func stampAll(st *stamper, evs []*event.Event) {
	type k struct{ nat, typ string }
	keys := make([]string, len(evs))
	seen := map[k]int{}
	for i, e := range evs {
		keys[i] = st.naturalKey(e, i, false)
		seen[k{keys[i], e.Type}]++
	}
	for i, e := range evs {
		nat := keys[i]
		if nat != "" && seen[k{nat, e.Type}] > 1 {
			nat = st.naturalKey(e, i, true)
		}
		st.stamp(e, nat)
	}
}

// evalResult is what rule evaluation produced for one invocation.
type evalResult struct {
	response string // none | ask | block, strongest over the events
	rule     string
	reason   string
	timeout  bool
	noRules  bool // the rule set could not be loaded at all
	stateErr bool // session state could not be saved
	dets     []*event.Event
	states   []savedState
}

type savedState struct {
	agent, session string
	data           []byte
}

// sessRef names one session of the events: the engine's key and the ids
// the spool hashes into the state file name.
type sessRef struct {
	key, agent, session string
}

type loadedState struct {
	b  []byte
	ok bool
}

func sessionsOf(evs []*event.Event) []sessRef {
	var out []sessRef
	seen := map[string]bool{}
	for _, e := range evs {
		key := rules.SessionKey(e)
		if seen[key] {
			continue
		}
		seen[key] = true
		s := sessRef{key: key}
		if e.Agent != nil {
			s.agent = e.Agent.ID
		}
		if e.Session != nil {
			s.session = e.Session.ID
		}
		out = append(out, s)
	}
	return out
}

// evaluate runs the guard subset (guard mode) or the full set (in-hook
// detection) over the events, carrying session state through the spool's
// state files. This is the order the rule engine's one-shot contract asks
// for: ImportSession, Eval, ExportSession.
//
// Hooks of one session run concurrently (each parallel tool call has its
// own hook process), so the state is saved optimistically: under a lock,
// and only if nobody saved since this hook loaded it. Otherwise the events
// are evaluated again on top of the newer state, as if this hook had run
// after the other one; a plain load-evaluate-save would let a hook that
// loaded early overwrite a flag a parallel hook had just set, and the
// guard rule requiring it would silently stop firing. The lock is held
// only for the compare and the write, except in the last round, which
// holds it from load to save so a hook of a busy session still makes
// progress. Every wait for the lock is bounded (lockWait).
func (w *work) evaluate(evs []*event.Event) (r evalResult) {
	set, degraded, err := loadRuleSet(w.cfg, w.m.guard && !w.m.detect)
	if err != nil || set == nil {
		labelAll(evs, "hook_rules", "unavailable")
		return evalResult{response: rules.ResponseNone, noRules: true}
	}
	sessions := sessionsOf(evs)
	for attempt := 1; ; attempt++ {
		final := attempt >= maxStateAttempts
		lock := lockTry
		var unlock func()
		if final && w.spool != nil {
			lock = lockFailed
			if un, ok := w.lockStates(); ok {
				unlock, lock = un, lockHeld
			}
		}
		var c stateCommit
		r, c = w.round(set, degraded, evs, sessions, lock)
		if unlock != nil {
			unlock()
		}
		switch c {
		case stateSaved:
		case stateUnlocked:
			labelAll(evs, "hook_state", "unlocked")
		case stateSaveFailed:
			r.stateErr = true
		case stateConflict:
			// Another hook of the session saved in between.
			if !final && time.Until(w.deadline) >= minRetryBudget {
				continue
			}
			// This result stands, but its state is not saved over the
			// newer one: a later hook builds on that.
			labelAll(evs, "hook_state", "conflict")
		}
		return r
	}
}

// round is one evaluation of the events on top of the saved state, and
// the attempt to save the state it produced.
func (w *work) round(set *rules.Set, degraded bool, evs []*event.Event, sessions []sessRef, lock lockMode) (evalResult, stateCommit) {
	unlabelAll(evs, "hook_state", "guard_timeout")
	var loaded map[string]loadedState
	if w.spool != nil {
		loaded = w.loadStates(sessions)
	}
	r, supDegraded := w.evalOnce(set, evs, sessions, loaded)
	if degraded || supDegraded {
		labelAll(evs, "hook_rules", "degraded")
	}
	if w.spool == nil || len(r.states) == 0 {
		return r, stateSaved
	}
	return r, w.commitStates(sessions, loaded, r.states, lock)
}

func (w *work) loadStates(sessions []sessRef) map[string]loadedState {
	out := make(map[string]loadedState, len(sessions))
	for _, s := range sessions {
		b, ok := w.spool.LoadState(s.agent, s.session)
		out[s.key] = loadedState{b, ok}
	}
	return out
}

// evalOnce evaluates every event with a fresh engine seeded from loaded.
func (w *work) evalOnce(set *rules.Set, evs []*event.Event, sessions []sessRef, loaded map[string]loadedState) (r evalResult, degraded bool) {
	r.response = rules.ResponseNone
	budget := w.cfg.Guard.Deadline.D()
	if left := time.Until(w.deadline) - replyMargin; left < budget {
		budget = left
	}
	if budget < time.Millisecond {
		budget = time.Millisecond
	}
	o, degraded := engineOptions(w.cfg, w.env, w.t0, budget)
	eng := rules.NewEngine(set, o)
	for _, s := range sessions {
		if st := loaded[s.key]; st.ok && eng.ImportSession(s.key, st.b) != nil {
			labelAll(evs, "hook_state", "rejected")
		}
	}
	for _, e := range evs {
		res := eng.Eval(e)
		fault("eval")
		if res.Timeout {
			r.timeout = true
			label(e, "guard_timeout", "1")
		}
		if rank(res.Response) > rank(r.response) {
			r.response, r.rule, r.reason = res.Response, res.Rule, res.Reason
		}
		r.dets = append(r.dets, res.Detections...)
	}
	for _, s := range sessions {
		if b, ok := eng.ExportSession(s.key); ok {
			r.states = append(r.states, savedState{s.agent, s.session, b})
		}
	}
	return r, degraded
}

type stateCommit int

const (
	stateSaved stateCommit = iota
	stateUnlocked
	stateSaveFailed
	stateConflict
)

// lockMode is how commitStates treats the state lock.
type lockMode int

const (
	lockTry    lockMode = iota // take it for the compare and the write
	lockHeld                   // the caller holds it
	lockFailed                 // the caller could not get it in time
)

// commitStates saves states if the state files still hold what this hook
// loaded. When the lock cannot be had in time (any process of the user can
// hold it), the compare and the save run unlocked: the window for a lost
// update is then small again, and the records say so.
func (w *work) commitStates(sessions []sessRef, loaded map[string]loadedState, states []savedState, lock lockMode) stateCommit {
	locked := lock == lockHeld
	if lock == lockTry {
		if unlock, ok := w.lockStates(); ok {
			defer unlock()
			locked = true
		}
	}
	for _, s := range sessions {
		b, ok := w.spool.LoadState(s.agent, s.session)
		if was := loaded[s.key]; ok != was.ok || !bytes.Equal(b, was.b) {
			return stateConflict
		}
	}
	for _, st := range states {
		if w.spool.SaveState(st.agent, st.session, st.data) != nil {
			return stateSaveFailed
		}
	}
	if !locked {
		return stateUnlocked
	}
	return stateSaved
}

// lockStates takes the session-state lock, waiting at most stateLockWait
// and never more than half the time left, so a lock held by a stuck or
// hostile process delays the answer but cannot turn it into a timeout.
func (w *work) lockStates() (func(), bool) {
	if w.spoolDir == "" {
		return nil, false
	}
	d := filepath.Join(w.spoolDir, "state")
	if os.MkdirAll(d, 0o700) != nil {
		return nil, false
	}
	return tryLock(filepath.Join(d, stateLockName), max0(min(stateLockWait, (time.Until(w.deadline)-replyMargin)/2)))
}

func rank(resp string) int {
	switch resp {
	case rules.ResponseBlock:
		return 2
	case rules.ResponseAsk:
		return 1
	}
	return 0
}

// decision maps the evaluation to what the agent is told. Only guard mode
// answers. guard.max_response caps a block to an ask. An evaluation that
// could not run, or a payload too large or too deep to inspect, or one the
// agent had not finished writing when the wait for stdin ran out, answers
// "ask" on an event the agent gates: a guard that cannot look never turns
// into an implicit allow (on Codex and Gemini an ask is only a warning; see
// the package doc).
func (w *work) decision(r evalResult, req *hookio.Request, anomaly string) hookio.Decision {
	if !w.m.guard || req == nil {
		return hookio.Decision{Action: hookio.ActionNone}
	}
	d := hookio.Decision{Action: hookio.ActionNone, Reason: r.reason, RuleID: r.rule}
	switch r.response {
	case rules.ResponseBlock:
		d.Action = hookio.ActionDeny
		if w.cfg.Guard.MaxResponse != rules.ResponseBlock {
			d.Action = hookio.ActionAsk
		}
	case rules.ResponseAsk:
		d.Action = hookio.ActionAsk
	}
	if d.Action == hookio.ActionNone && req.Blocking {
		switch {
		case r.noRules:
			d = hookio.Decision{Action: hookio.ActionAsk, Reason: "guard rules could not be loaded; confirm this action"}
		case anomaly == anomalyTooLarge || anomaly == anomalyTooDeep || anomaly == anomalyStdin:
			d = hookio.Decision{Action: hookio.ActionAsk, Reason: "hook payload could not be inspected (" + anomaly + "); confirm this action"}
		}
	}
	return d
}

// annotateDecision records on the activity what the agent was told, so the
// daemon (which re-detects from the spool) can mark its own finding as
// enforced, and sets Detection.Enforced on the hook's own findings only
// when the reply actually carried the rule's decision.
func annotateDecision(evs, dets []*event.Event, d hookio.Decision, reply []byte, carried bool) {
	if d.Action == hookio.ActionNone {
		return
	}
	shown := "none"
	switch {
	case carried:
		shown = d.Action
	case len(reply) > 0:
		shown = "warn" // Codex and Gemini render an ask as a warning
	}
	for _, e := range evs {
		if e.Type != event.TypeToolPre && e.Type != event.TypePromptSubmit {
			continue
		}
		label(e, "guard_reply", shown)
		if d.RuleID != "" {
			label(e, "guard_rule", token(d.RuleID, 64))
		}
		if carried {
			if e.Outcome == nil {
				e.Outcome = &event.Outcome{}
			}
			e.Outcome.Decision, e.Outcome.DecisionSource = d.Action, "hawkbell"
		}
	}
	if !carried {
		return
	}
	for _, det := range dets {
		x := det.Detection
		if x == nil || x.RuleID != d.RuleID {
			continue
		}
		if (x.Response == rules.ResponseBlock && d.Action == hookio.ActionDeny) ||
			(x.Response == rules.ResponseAsk && d.Action == hookio.ActionAsk) {
			x.Enforced = true
		}
	}
}

// appendBounded runs appendAll with a time bound. spool.Append waits for
// the spool's lock without a timeout, and any process of the user can hold
// that lock. A supervised worker has already answered and is killed at the
// deadline; a worker run by hand gives up stdinGrace after it.
func (w *work) appendBounded(evs []*event.Event, r evalResult) int {
	return w.bounded(func() int { return w.appendAll(evs, r) })
}

// bounded runs f, which touches the spool, with appendBounded's time bound
// (a spool on a hung file system blocks any call). It returns f's exit
// code, exitInternal when f panicked, exitSpool when time ran out.
func (w *work) bounded(f func() int) int {
	done := make(chan int, 1)
	go func() {
		code := exitInternal
		defer func() {
			_ = recover()
			done <- code
		}()
		code = f()
	}()
	t := time.NewTimer(max0(time.Until(w.deadline)) + stdinGrace)
	defer t.Stop()
	select {
	case c := <-done:
		return c
	case <-t.C:
		return exitSpool
	}
}

// appendAll writes the activity, then (in-hook detection only) the
// findings at or above rules.min_class and their context, the same floor
// the daemon applies. Findings from plain guard mode are not spooled: the
// daemon re-detects from the activity and would refuse detection records
// from a user spool anyway. Session state was saved by evaluate. Last, it
// prunes the spools no daemon prunes (pruneSpools).
func (w *work) appendAll(evs []*event.Event, r evalResult) int {
	if w.spool == nil {
		return exitSpool
	}
	code := exitOK
	if r.stateErr {
		code = exitSpool
	}
	put := func(e *event.Event) {
		if appendRecord(w.spool, e) != nil {
			code = exitSpool
		}
	}
	for _, e := range evs {
		put(e)
	}
	if w.m.detect {
		minRank := event.ClassRank(w.cfg.Rules.MinClass)
		for _, det := range r.dets {
			class := ""
			if det.Detection != nil {
				class = det.Detection.Class
				if event.ClassRank(class) < minRank {
					continue
				}
			}
			out, _, ok := w.policy.Emit(det)
			if !ok || out == nil {
				continue
			}
			// The spool writes a record's local content next to it; a
			// finding that may be shipped from here must not carry any.
			out.Content, out.Feat = nil, nil
			out.Integrity = det.Integrity
			put(out)
			// Context follows findings and alerts only, as in the daemon.
			if n := w.cfg.Privacy.ContextEvents; n > 0 && event.ClassRank(class) >= event.ClassRank(event.ClassFinding) {
				for _, c := range w.policy.ContextFor(out.ID, evs, min(n, privacy.MaxContext)) {
					c.Content, c.Feat = nil, nil
					put(c)
				}
			}
		}
	}
	w.pruneSpools()
	return code
}

func label(e *event.Event, k, v string) {
	if e.Labels == nil {
		e.Labels = map[string]string{}
	}
	e.Labels[k] = v
}

func labelAll(evs []*event.Event, k, v string) {
	for _, e := range evs {
		label(e, k, v)
	}
}

func unlabelAll(evs []*event.Event, keys ...string) {
	for _, e := range evs {
		for _, k := range keys {
			delete(e.Labels, k)
		}
	}
}
