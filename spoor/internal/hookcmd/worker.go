package hookcmd

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/rules"
	"github.com/thomastysong/spoor/internal/spool"
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
)

// Test seams. All are no-ops or the real thing in production; the fault
// hook can only be set from this package's tests, never from the
// environment or the command line.
var (
	exitFunc     = os.Exit
	faultHook    func(stage string)
	appendRecord = func(w *spool.Writer, e *event.Event) error { return w.Append(e) }
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
	spoolErr error
	policy   *privacy.Policy
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
		armWatchdog(w.deadline)
	}
	if !w.m.enabled {
		return exitOK
	}
	fault("start")
	w.in = readBounded(stdin, inputCap(w.cfg), time.Until(w.deadline)-replyMargin)
	return w.run(stdout)
}

func armWatchdog(deadline time.Time) {
	time.AfterFunc(max0(time.Until(deadline)+watchdogSlack), func() { exitFunc(exitWatchdog) })
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
		evs = append(evs, anomalyRecord(w.agentID, anomaly, payload))
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
		// happens before any content processing.
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
		r, ok := render(w.dialect, req, dec)
		if !ok {
			code = exitRender
		}
		reply = r
	}
	fault("reply")
	if len(reply) > 0 {
		// One write: the supervisor forwards only a complete object, and a
		// reply under the pipe buffer size arrives in one piece.
		_, _ = stdout.Write(reply)
	}
	carried := replyCarries(reply, dec.Action)
	annotateDecision(evs, ev.dets, dec, reply, carried)

	fault("append")
	if c := w.appendAll(evs, ev); c != exitOK && code == exitOK {
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
		code = anomalyStdin
	}
	return evs, req, code
}

func (w *work) openSpool() {
	dir, err := spool.Dir(w.cfg.DataDir, w.env.UID, w.env.Home)
	if err == nil {
		w.spool, err = spool.OpenWriter(dir)
	}
	w.spoolErr = err
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
	dets     []*event.Event
	states   []savedState
}

type savedState struct {
	agent, session string
	data           []byte
}

// evaluate runs the guard subset (guard mode) or the full set (in-hook
// detection) over the events, carrying session state through the spool's
// state files. This is the order the rule engine's one-shot contract asks
// for: ImportSession, Eval, ExportSession.
func (w *work) evaluate(evs []*event.Event) (r evalResult) {
	r.response = rules.ResponseNone
	set, degraded, err := loadRuleSet(w.cfg, w.m.guard && !w.m.detect)
	if err != nil || set == nil {
		r.noRules = true
		labelAll(evs, "hook_rules", "unavailable")
		return r
	}
	budget := w.cfg.Guard.Deadline.D()
	if left := time.Until(w.deadline) - replyMargin; left < budget {
		budget = left
	}
	if budget < time.Millisecond {
		budget = time.Millisecond
	}
	o, supDegraded := engineOptions(w.cfg, w.env, w.t0, budget)
	if degraded || supDegraded {
		labelAll(evs, "hook_rules", "degraded")
	}
	eng := rules.NewEngine(set, o)

	type sess struct{ agent, session string }
	keys := map[string]sess{}
	var order []string
	for _, e := range evs {
		key := rules.SessionKey(e)
		if _, done := keys[key]; !done {
			s := sess{}
			if e.Agent != nil {
				s.agent = e.Agent.ID
			}
			if e.Session != nil {
				s.session = e.Session.ID
			}
			keys[key] = s
			order = append(order, key)
			if w.spool != nil {
				if b, ok := w.spool.LoadState(s.agent, s.session); ok {
					if eng.ImportSession(key, b) != nil {
						labelAll(evs, "hook_state", "rejected")
					}
				}
			}
		}
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
	for _, key := range order {
		if b, ok := eng.ExportSession(key); ok {
			s := keys[key]
			r.states = append(r.states, savedState{s.agent, s.session, b})
		}
	}
	return r
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
// could not run, or a payload too large or too deep to inspect, answers
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
		case anomaly == anomalyTooLarge || anomaly == anomalyTooDeep:
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
			e.Outcome.Decision, e.Outcome.DecisionSource = d.Action, "spoor"
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

// appendAll writes the activity, then (in-hook detection only) the
// findings and their context, then the session state. Findings from plain
// guard mode are not spooled: the daemon re-detects from the activity and
// would refuse detection records from a user spool anyway.
func (w *work) appendAll(evs []*event.Event, r evalResult) int {
	if w.spool == nil {
		return exitSpool
	}
	code := exitOK
	put := func(e *event.Event) {
		if appendRecord(w.spool, e) != nil {
			code = exitSpool
		}
	}
	for _, e := range evs {
		put(e)
	}
	if w.m.detect {
		for _, det := range r.dets {
			out, _, ok := w.policy.Emit(det)
			if !ok || out == nil {
				continue
			}
			// The spool writes a record's local content next to it; a
			// finding that may be shipped from here must not carry any.
			out.Content, out.Feat = nil, nil
			out.Integrity = det.Integrity
			put(out)
			if n := w.cfg.Privacy.ContextEvents; n > 0 {
				for _, c := range w.policy.ContextFor(out.ID, evs, min(n, privacy.MaxContext)) {
					c.Content, c.Feat = nil, nil
					put(c)
				}
			}
		}
	}
	for _, s := range r.states {
		if w.spool.SaveState(s.agent, s.session, s.data) != nil {
			code = exitSpool
		}
	}
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
