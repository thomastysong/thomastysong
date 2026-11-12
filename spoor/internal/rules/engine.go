package rules

import (
	"container/list"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
)

// Engine defaults.
const (
	DefaultSuppressFor = time.Hour
	DefaultMaxSessions = 2000
	DefaultFlagTTL     = 30 * time.Minute
	DefaultDeadline    = 150 * time.Millisecond
	// AlertSuppressCap bounds the dedup window of alert-class rules, so a
	// repeated alert is not silenced for the operator-configured hour.
	AlertSuppressCap  = 10 * time.Minute
	maxScopedCounters = 10000
	maxReason         = 512
	maxEvidenceValue  = 256
)

// Baseline remembers what has been seen before, for rules with a novelty
// block. Seen records key and reports whether it had been recorded
// earlier. A first sighting may only add attention (a tag, a higher class);
// "seen before" never lowers anything.
type Baseline interface {
	Seen(key string) bool
}

// Options configures an Engine. Zero values select the defaults.
type Options struct {
	Now          func() time.Time
	SuppressFor  time.Duration // default 1h: repeats of one dedup key inside the window are counted, not emitted (alert class: at most 10m)
	MaxSessions  int           // LRU cap, default 2000
	FlagTTL      time.Duration // default 30m when a rule does not set ttl
	Deadline     time.Duration // per-event wall clock budget, default 150ms
	Suppressions []Suppression // operator exceptions, applied with the set's own suppressions.yaml
	Home, OS     string
	// HostTags are the operator-configured tags of this host (Fleet labels,
	// "offsec", "ci"); rules see them as host.tags and suppressions can be
	// limited to them.
	HostTags []string
	// Baseline backs novelty blocks; nil uses an in-memory store of 10,000
	// keys, which is meaningful only in a long-lived process.
	Baseline Baseline
}

// Result is the outcome of evaluating one event.
type Result struct {
	// Detections holds detection.finding records (and posture.check
	// records for inventory rules). Content and Feat are shared with the
	// triggering event so the privacy stage can build evidence.
	Detections []*event.Event
	// Response is the strongest of none < ask < block among matched rules
	// whose response applies to this event type (tool.pre, prompt.submit).
	// On deadline expiry with a guard rule still pending it is at least
	// ask: a stalled evaluation never turns into an implicit allow.
	Response string
	Rule     string // rule id that asked for Response
	Reason   string // human sentence for the agent and the user
	Timeout  bool
	Elapsed  time.Duration
}

// Engine evaluates events against a rule set with per-session state. It is
// safe for concurrent use; evaluation is serialized internally.
type Engine struct {
	o        Options
	clock    func() time.Time // wall clock for the deadline; replaced in tests
	lists    map[string]*namedList
	sups     []Suppression
	flagOnly map[string]bool
	byType   map[string][]*rule // activity rules for one event type, in set order
	anyType  []*rule            // activity rules without a type prefilter
	invRules []*rule
	guard    []*rule // activity rules with response ask|block
	hash     string
	version  string
	baseline Baseline

	mu       sync.Mutex
	sessions *sessions
	scoped   *scopedCounters
	ruleNS   map[string]uint64

	evals, matches, detections, suppressed, suppressedOp atomic.Uint64
	timeouts, panics, evicted, missingLists              atomic.Uint64
	imports, importsRejected                             atomic.Uint64
}

// NewEngine snapshots s; later changes to s do not affect the engine.
func NewEngine(s *Set, o Options) *Engine {
	if s == nil {
		s = newSet()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.SuppressFor <= 0 {
		o.SuppressFor = DefaultSuppressFor
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = DefaultMaxSessions
	}
	if o.FlagTTL <= 0 {
		o.FlagTTL = DefaultFlagTTL
	}
	if o.Deadline <= 0 {
		o.Deadline = DefaultDeadline
	}
	e := &Engine{
		o:        o,
		clock:    time.Now,
		lists:    map[string]*namedList{},
		flagOnly: map[string]bool{},
		byType:   map[string][]*rule{},
		hash:     s.Hash(),
		version:  s.Version(),
		baseline: o.Baseline,
		sessions: newSessions(o.MaxSessions),
		scoped:   newScopedCounters(maxScopedCounters),
		ruleNS:   map[string]uint64{},
	}
	if e.baseline == nil {
		e.baseline = newMemBaseline(10000)
	}
	for k, v := range s.lists {
		e.lists[k] = v
	}
	for k, v := range s.flagOnly {
		e.flagOnly[k] = v
	}
	e.sups = append(append([]Suppression(nil), s.suppressions...), o.Suppressions...)
	types := map[string]bool{}
	var activity []*rule
	for _, r := range s.rules {
		if !s.enabled(r) {
			continue
		}
		if r.Kind == KindInventory {
			e.invRules = append(e.invRules, r)
			continue
		}
		activity = append(activity, r)
		if r.response == ResponseAsk || r.response == ResponseBlock {
			e.guard = append(e.guard, r)
		}
		for _, t := range r.whenTypes {
			types[t] = true
		}
	}
	for _, r := range activity {
		if r.whenTypes == nil {
			e.anyType = append(e.anyType, r)
		}
	}
	// Each type's list keeps set order (typed and untyped rules
	// interleaved), so results never depend on which index served them.
	for t := range types {
		for _, r := range activity {
			if r.whenTypes == nil || contains(r.whenTypes, t) {
				e.byType[t] = append(e.byType[t], r)
			}
		}
	}
	return e
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func blockable(typ string) bool {
	return typ == event.TypeToolPre || typ == event.TypePromptSubmit
}

func responseRank(r string) int {
	switch r {
	case ResponseAsk:
		return 1
	case ResponseBlock:
		return 2
	}
	return 0
}

func isActivity(ev *event.Event) bool {
	return ev.Kind == event.KindActivity || ev.Kind == ""
}

func (e *Engine) candidates(ev *event.Event) []*rule {
	if ev.Kind == event.KindInventory {
		return e.invRules
	}
	if !isActivity(ev) {
		return nil
	}
	if l, ok := e.byType[ev.Type]; ok {
		return l
	}
	return e.anyType
}

// guardApplies reports whether any guard rule could answer for this event.
func (e *Engine) guardPending(rest []*rule, ev *event.Event) *rule {
	if !blockable(ev.Type) {
		return nil
	}
	for _, r := range rest {
		if (r.response == ResponseAsk || r.response == ResponseBlock) && !e.flagOnly[r.ID] &&
			(r.whenTypes == nil || contains(r.whenTypes, ev.Type)) {
			return r
		}
	}
	return nil
}

// Eval computes the event's features if needed, updates session state and
// evaluates every applicable rule. It never panics: an internal failure
// returns ask for an event a guard rule could have answered, none
// otherwise.
func (e *Engine) Eval(ev *event.Event) Result {
	return e.evaluate(ev, nil)
}

func (e *Engine) evaluate(ev *event.Event, fired map[string]bool) (res Result) {
	res.Response = ResponseNone
	if ev == nil {
		return res
	}
	start := e.clock()
	defer func() {
		if r := recover(); r != nil {
			e.panics.Add(1)
			res = Result{Response: ResponseNone, Elapsed: e.clock().Sub(start)}
			if g := e.guardPending(e.guard, ev); g != nil {
				res.Response, res.Rule = ResponseAsk, g.ID
				res.Reason = "spoor could not finish evaluating this action; confirm it before it runs."
			}
		}
	}()
	e.evals.Add(1)
	features.Compute(ev, features.Context{Home: e.o.Home, OS: e.o.OS})

	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Now()
	deadline := start.Add(e.o.Deadline)
	var st *sessionState
	skey := ""
	if isActivity(ev) {
		skey = SessionKey(ev)
		st = e.session(skey, now)
		e.updateSession(st, ev, now)
	}
	fields := features.Fields(ev)
	if len(e.o.HostTags) > 0 {
		fields["host.tags"] = append([]string(nil), e.o.HostTags...)
	}
	cands := e.candidates(ev)
	thread := ""
	if ev.Session != nil {
		thread = ev.Session.SubagentID
	}
	ctx := &evalCtx{lists: e.lists, missingList: func(string) { e.missingLists.Add(1) }}
	var vis, visAll map[string]flagEntry
	type pending struct {
		r   *rule
		evs string
	}
	var sets []pending
	var memo evidenceMemo
	prev := e.clock()
	for i, r := range cands {
		if i > 0 {
			t := e.clock()
			e.ruleNS[cands[i-1].ID] += uint64(t.Sub(prev))
			prev = t
		}
		if prev.After(deadline) {
			res.Timeout = true
			e.timeouts.Add(1)
			if g := e.guardPending(cands[i:], ev); g != nil && responseRank(res.Response) < responseRank(ResponseAsk) {
				res.Response, res.Rule = ResponseAsk, g.ID
				res.Reason = "spoor did not finish evaluating this action in time; confirm it before it runs."
			}
			break
		}
		if r.when != nil && !r.when.eval(fields, ctx) {
			continue
		}
		var used []flagEntryNamed
		if len(r.require) > 0 || len(r.requireAny) > 0 {
			if st == nil {
				continue
			}
			var view map[string]flagEntry
			if r.flagScope == ScopeSession {
				if visAll == nil {
					visAll = st.visible(thread, true)
				}
				view = visAll
			} else {
				if vis == nil {
					vis = st.visible(thread, false)
				}
				view = vis
			}
			var ok bool
			if used, ok = requireFlags(r, view); !ok {
				continue
			}
		}
		if !r.match.eval(fields, ctx) {
			continue
		}
		if r.allow != nil && r.allow.eval(fields, ctx) {
			continue
		}
		chain := []hit{{t: now, ev: ev.ID}}
		if r.threshold != nil {
			reached, hits := e.thresholdHit(r, ev, st, now)
			if !reached {
				continue
			}
			chain = hits
		}
		e.matches.Add(1)
		if fired != nil {
			fired[r.ID] = true
		}
		if len(r.setFlags) > 0 && st != nil {
			sets = append(sets, pending{r: r, evs: ev.ID})
		}
		if e.flagOnly[r.ID] {
			continue
		}
		if e.operatorSuppressed(r, fields, now) {
			e.suppressedOp.Add(1)
			continue
		}
		if r.response != ResponseNone && blockable(ev.Type) && responseRank(r.response) > responseRank(res.Response) {
			res.Response, res.Rule, res.Reason = r.response, r.ID, reasonFor(r)
		}
		if !r.emit {
			continue
		}
		if memo == nil {
			memo = evidenceMemo{}
		}
		if r.Kind == KindInventory {
			res.Detections = append(res.Detections, e.posture(r, ev, fields, now, memo))
			e.detections.Add(1)
			continue
		}
		det := e.detection(r, ev, fields, used, chain, now, skey, memo)
		if e.dedupe(st, r, det, fields, now, skey) {
			e.suppressed.Add(1)
			continue
		}
		res.Detections = append(res.Detections, det)
		e.detections.Add(1)
	}
	if n := len(cands); n > 0 && !res.Timeout {
		e.ruleNS[cands[n-1].ID] += uint64(e.clock().Sub(prev))
	}
	// Flags set by this event take effect for later events only, so the
	// outcome never depends on the order rules are listed in.
	for _, p := range sets {
		ttl := p.r.ttl
		if ttl <= 0 {
			ttl = e.o.FlagTTL
		}
		for _, f := range p.r.setFlags {
			st.setFlag(thread, p.r.flagScope, f, ttl, now, p.evs)
		}
	}
	res.Elapsed = e.clock().Sub(start)
	return res
}

type flagEntryNamed struct {
	name string
	flagEntry
}

func requireFlags(r *rule, view map[string]flagEntry) ([]flagEntryNamed, bool) {
	var used []flagEntryNamed
	for _, f := range r.require {
		fe, ok := view[f]
		if !ok {
			return nil, false
		}
		used = append(used, flagEntryNamed{f, fe})
	}
	if len(r.requireAny) > 0 {
		found := false
		for _, f := range r.requireAny {
			if fe, ok := view[f]; ok {
				used = append(used, flagEntryNamed{f, fe})
				found = true
			}
		}
		if !found {
			return nil, false
		}
	}
	return used, true
}

func reasonFor(r *rule) string {
	s := fmt.Sprintf("spoor %s: %s.", r.ID, strings.TrimSuffix(r.Title, "."))
	if r.remedy != "" {
		s += " " + r.remedy
	}
	return cutString(s, maxReason)
}

func cutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

func (e *Engine) session(key string, now time.Time) *sessionState {
	if st := e.sessions.get(key); st != nil {
		return st
	}
	st := newSession(key, now)
	if n := e.sessions.put(st); n > 0 {
		e.evicted.Add(uint64(n))
	}
	return st
}

func (e *Engine) osName(ev *event.Event) string {
	if e.o.OS != "" {
		return strings.ToLower(e.o.OS)
	}
	if ev.Host != nil && ev.Host.OS != "" {
		return strings.ToLower(ev.Host.OS)
	}
	return runtime.GOOS
}

// updateSession advances the session with ev and writes the session
// features into ev.Feat.
func (e *Engine) updateSession(st *sessionState, ev *event.Event, now time.Time) {
	f := ev.Feat
	first := st.events == 0
	st.events++
	if now.After(st.last) {
		st.last = now
	}
	useID := ""
	if ev.Tool != nil {
		useID = ev.Tool.UseID
	}
	switch ev.Type {
	case event.TypeToolPre:
		st.toolCalls++
		st.rememberUse(useID)
	case event.TypeToolPost:
		if useID == "" || !st.seenUse(useID) {
			st.toolCalls++
		}
		st.rememberUse(useID)
	case event.TypePromptSubmit:
		st.prompts++
	}
	st.expire(now)

	cwd := ""
	if ev.Session != nil {
		cwd = ev.Session.CWD
	}
	goos := e.osName(ev)
	execs := execPaths(ev)
	if len(execs) > 0 || f["shell.parse_ok"] != nil {
		f["session.runs_written_file"] = false
		for _, p := range execs {
			if d := pathDigest(p, cwd, e.o.Home, goos); d != "" && st.hasWritten(d) {
				f["session.runs_written_file"] = true
				f["session.written_exec_path"] = p
				break
			}
		}
	}
	for i, p := range writtenPaths(ev) {
		if i >= 64 {
			break
		}
		if d := pathDigest(p, cwd, e.o.Home, goos); d != "" {
			st.addWritten(d)
		}
	}

	if kinds, checked := st.secretFlow(ev); checked {
		f["session.secret_flow"] = len(kinds) > 0
		if len(kinds) > 0 {
			f["session.secret_flow_kinds"] = kinds
		}
	}
	st.captureSecrets(ev)

	thread := ""
	if ev.Session != nil {
		thread = ev.Session.SubagentID
	}
	if names := st.flagNames(thread); len(names) > 0 {
		f["session.flags"] = names
	} else {
		delete(f, "session.flags")
	}
	f["session.tool_calls"] = float64(st.toolCalls)
	f["session.prompts"] = float64(st.prompts)
	f["session.age_s"] = now.Sub(st.created).Seconds()
	f["session.first_event"] = first
}

// thresholdHit records a match for a threshold rule and reports whether the
// count was reached inside the window; on success the counter restarts and
// the hits that made up the count are returned.
func (e *Engine) thresholdHit(r *rule, ev *event.Event, st *sessionState, now time.Time) (bool, []hit) {
	th := r.threshold
	var hits []hit
	store := func(h []hit) {}
	switch {
	case th.by == BySession && st != nil:
		hits = st.counters[r.ID]
		store = func(h []hit) {
			if h == nil {
				delete(st.counters, r.ID)
				return
			}
			if _, ok := st.counters[r.ID]; !ok && len(st.counters) >= maxSessionCounters {
				for k := range st.counters { // drop an arbitrary counter: bounded memory over exactness
					delete(st.counters, k)
					break
				}
			}
			st.counters[r.ID] = h
		}
	default:
		key := r.ID + "\x00" + th.by + "\x00"
		switch th.by {
		case ByUser:
			if ev.User != nil {
				key += ev.User.ID
			}
		case ByHost:
			if ev.Host != nil {
				key += ev.Host.ID
			}
		default:
			key += SessionKey(ev)
		}
		hits = e.scoped.get(key)
		store = func(h []hit) { e.scoped.put(key, h) }
	}
	if th.window > 0 {
		cut := 0
		for cut < len(hits) && now.Sub(hits[cut].t) > th.window {
			cut++
		}
		hits = hits[cut:]
	}
	hits = append(append([]hit(nil), hits...), hit{t: now, ev: ev.ID})
	if len(hits) > th.count {
		hits = hits[len(hits)-th.count:]
	}
	if len(hits) >= th.count {
		store(nil)
		return true, hits
	}
	store(hits)
	return false, nil
}

func (e *Engine) operatorSuppressed(r *rule, fields map[string]any, now time.Time) bool {
	for i := range e.sups {
		if e.sups[i].applies(r.ID, fields, now, e.o.HostTags) {
			return true
		}
	}
	return false
}

// dedupe applies the suppression window. It returns true when the
// detection is a repeat inside the window; otherwise it stamps Count with
// the repeats it stands for and remembers the emission.
func (e *Engine) dedupe(st *sessionState, r *rule, det *event.Event, fields map[string]any, now time.Time, skey string) bool {
	if st == nil {
		return false
	}
	window := e.o.SuppressFor
	if det.Detection.Class == event.ClassAlert && window > AlertSuppressCap {
		window = AlertSuppressCap
	}
	key := det.Detection.DedupKey
	ent := st.dedup[key]
	if ent != nil && now.Sub(ent.last) < window && !now.Before(ent.last) {
		ent.suppressed++
		return true
	}
	count := 1
	if ent != nil {
		count += ent.suppressed
	}
	det.Detection.Count = count
	st.putDedup(key, &dedupEntry{last: now})
	return false
}

// Stats returns counters: evals, matches, detections, suppressed,
// suppressed_operator, timeouts, panics, sessions, sessions_evicted,
// lists_missing, imports, imports_rejected, and rule_ns.<id> (cumulative
// evaluation time) for the ten most expensive rules.
func (e *Engine) Stats() map[string]uint64 {
	out := map[string]uint64{
		"evals":               e.evals.Load(),
		"matches":             e.matches.Load(),
		"detections":          e.detections.Load(),
		"suppressed":          e.suppressed.Load(),
		"suppressed_operator": e.suppressedOp.Load(),
		"timeouts":            e.timeouts.Load(),
		"panics":              e.panics.Load(),
		"sessions_evicted":    e.evicted.Load(),
		"lists_missing":       e.missingLists.Load(),
		"imports":             e.imports.Load(),
		"imports_rejected":    e.importsRejected.Load(),
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out["sessions"] = uint64(e.sessions.len())
	type kv struct {
		id string
		ns uint64
	}
	all := make([]kv, 0, len(e.ruleNS))
	for id, ns := range e.ruleNS {
		all = append(all, kv{id, ns})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ns != all[j].ns {
			return all[i].ns > all[j].ns
		}
		return all[i].id < all[j].id
	})
	for i := 0; i < len(all) && i < 10; i++ {
		out["rule_ns."+all[i].id] = all[i].ns
	}
	return out
}

// ExportSession returns the session's state as small JSON (at most 64 KiB)
// for a one-shot hook process to persist between invocations.
func (e *Engine) ExportSession(key string) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.sessions.get(key)
	if st == nil {
		return nil, false
	}
	b, err := marshalBounded(st.export())
	if err != nil {
		return nil, false
	}
	return b, true
}

// ImportSession replaces the state of key with data from ExportSession. It
// rejects state over 64 KiB, malformed state, state exported for another
// key and values outside the engine's bounds.
func (e *Engine) ImportSession(key string, data []byte) error {
	st, err := importState(key, data, e.o.Now())
	if err != nil {
		e.importsRejected.Add(1)
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if n := e.sessions.put(st); n > 0 {
		e.evicted.Add(uint64(n))
	}
	e.imports.Add(1)
	return nil
}

// scopedCounters holds per-user and per-host threshold counters.
type scopedCounters struct {
	max   int
	lru   *list.List
	items map[string]*list.Element
}

type scopedEntry struct {
	key  string
	hits []hit
}

func newScopedCounters(max int) *scopedCounters {
	return &scopedCounters{max: max, lru: list.New(), items: map[string]*list.Element{}}
}

func (s *scopedCounters) get(key string) []hit {
	if el, ok := s.items[key]; ok {
		s.lru.MoveToFront(el)
		return el.Value.(*scopedEntry).hits
	}
	return nil
}

func (s *scopedCounters) put(key string, h []hit) {
	if el, ok := s.items[key]; ok {
		if h == nil {
			s.lru.Remove(el)
			delete(s.items, key)
			return
		}
		el.Value.(*scopedEntry).hits = h
		s.lru.MoveToFront(el)
		return
	}
	if h == nil {
		return
	}
	s.items[key] = s.lru.PushFront(&scopedEntry{key: key, hits: h})
	for s.lru.Len() > s.max {
		el := s.lru.Back()
		s.lru.Remove(el)
		delete(s.items, el.Value.(*scopedEntry).key)
	}
}

// memBaseline is the default novelty store.
type memBaseline struct {
	mu    sync.Mutex
	max   int
	lru   *list.List
	items map[string]*list.Element
}

func newMemBaseline(max int) *memBaseline {
	return &memBaseline{max: max, lru: list.New(), items: map[string]*list.Element{}}
}

func (b *memBaseline) Seen(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.items[key]; ok {
		b.lru.MoveToFront(el)
		return true
	}
	b.items[key] = b.lru.PushFront(key)
	for b.lru.Len() > b.max {
		el := b.lru.Back()
		b.lru.Remove(el)
		delete(b.items, el.Value.(string))
	}
	return false
}
