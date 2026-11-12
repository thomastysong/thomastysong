package engine

import (
	"container/list"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/privacy"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

// Pipeline is the detection pipeline of one hawkbell process.
type Pipeline struct {
	o         Options
	cfg       *config.Config
	pol       *privacy.Policy
	mode      string
	integrity event.Integrity
	forceHost bool
	writer    string
	started   time.Time
	minRank   int
	contextN  int
	rate      float64
	burst     float64
	labels    map[string]string // operator labels from config.Labels
	streamsOK map[string]bool   // nil: every stream ships
	homes     *homeCache
	bl        *Baseline
	blPath    string
	disabled  func() bool
	async     bool
	ruleOpts  rules.Options
	salt      []byte // per-process key for local-only dedup keys
	idKey     []byte // identity key: Options.IdentityKey, the daemon's key file or the per-process key (identity.go)
	keyStored bool   // idKey outlives the process (configured or read from the key file)

	// ingest side (no processing lock)
	qmu      sync.Mutex
	queue    []queued
	qcap     int
	qclosed  bool // set under qmu by Close before its final drain
	wake     chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	closeErr error
	once     sync.Once

	disAt  atomic.Int64 // unix nanos of the cached kill-switch reading
	disVal atomic.Bool

	ingested, queueDropped, disabledDropped, closedDropped atomic.Uint64

	// processing side, guarded by pmu
	pmu       sync.Mutex
	set       *rules.Set
	eng       *rules.Engine
	rulesVer  string
	rulesHash string
	bundleVer string

	sessions   map[string]*list.Element // of *session, LRU by wall time
	lru        *list.List
	excluded   map[string]struct{}
	corr       *correlator
	cov        map[covKey]*covEntry
	covPerUser map[string]int
	procs      map[string]*proc
	buckets    map[string]*bucket // activity buckets without a session, and per account
	mcpDefs    map[mcpDefKey]string

	// OTel attribution (attribution.go)
	attrIdx     map[string]map[string]struct{} // attribution key -> live session keys
	attrExcl    map[string]struct{}
	pending     []*pendingRec
	pendingKeys map[string]int
	adopt       []string

	outbox   []*event.Event
	local    []*event.Event
	stateQ   []*event.Event
	streams  map[string]*streamStat
	seq      map[string]uint64
	lseq     map[string]uint64
	surfaces map[event.Source]*surfaceStat
	ctr      counters

	lastHeartbeat time.Time
	lastBLSave    time.Time
	lastWriteErr  string
}

// New validates the options and returns a running Pipeline. In daemon mode
// a worker goroutine processes the ingest queue; in every other mode Ingest
// processes synchronously in the caller's goroutine.
func New(o Options) (*Pipeline, error) {
	if o.Outbox == nil {
		return nil, errNoOutbox
	}
	cfg := o.Config
	if cfg == nil {
		cfg = config.Default("")
	}
	if o.Mode == "" {
		o.Mode = ModeDaemon
	}
	if !validMode(o.Mode) {
		return nil, fmt.Errorf("engine: unknown mode %q", o.Mode)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Integrity == "" {
		o.Integrity = event.IntegrityUser
		if platform.IsPrivileged() {
			o.Integrity = event.IntegrityRoot
		}
	}
	if o.Integrity != event.IntegrityRoot && o.Integrity != event.IntegrityUser {
		return nil, fmt.Errorf("engine: integrity %q: want root or user", o.Integrity)
	}
	if o.SensorVersion == "" {
		o.SensorVersion = "dev"
	}
	minClass := cfg.Rules.MinClass
	if minClass == "" {
		minClass = event.ClassFinding
	}
	if !validClass(minClass) {
		return nil, fmt.Errorf("rules.min_class %q: want signal, finding or alert", minClass)
	}
	set, err := ruleSet(o.Rules, cfg.Rules.Disable)
	if err != nil {
		return nil, err
	}
	var pol *privacy.Policy
	if o.Policy == nil {
		if pol, err = PolicyFromConfig(cfg); err != nil {
			return nil, err
		}
	} else {
		c := *o.Policy // the caller's policy is not modified
		pol = &c
		if pol.MaxLine == 0 {
			pol.MaxLine = cfg.Output.MaxLine
		}
	}
	sups, err := suppressions(cfg.Rules.Suppressions)
	if err != nil {
		return nil, err
	}
	keyIn, keyStored := o.IdentityKey, len(o.IdentityKey) > 0
	var keyErr error
	if !keyStored {
		// The daemon's identities must hold across restarts: it keeps its
		// key under the checkpoint directory (identity.go).
		if path := identityKeyPath(cfg, o.Mode); path != "" {
			if keyIn, keyErr = LoadOrCreateIdentityKey(path); keyErr == nil {
				keyStored = true
			}
		}
	}
	idKey, err := identityKey(keyIn)
	if err != nil {
		return nil, err
	}
	o.IdentityKey = nil // the pipeline's copy is idKey; Options is kept for reference only

	p := &Pipeline{
		o: o, cfg: cfg, mode: o.Mode, integrity: o.Integrity, idKey: idKey, keyStored: keyStored,
		forceHost:   o.Host.ID != "" || o.Host.Name != "",
		started:     o.Now(),
		minRank:     event.ClassRank(minClass),
		contextN:    min(max(cfg.Privacy.ContextEvents, 0), privacy.MaxContext),
		rate:        float64(cfg.Limits.ActivityPerSecond),
		burst:       float64(cfg.Limits.ActivityBurst),
		async:       o.Mode == ModeDaemon,
		disabled:    o.Disabled,
		bundleVer:   o.BundleVersion,
		sessions:    map[string]*list.Element{},
		lru:         list.New(),
		excluded:    map[string]struct{}{},
		corr:        newCorrelator(),
		cov:         map[covKey]*covEntry{},
		procs:       map[string]*proc{},
		covPerUser:  map[string]int{},
		buckets:     map[string]*bucket{},
		mcpDefs:     map[mcpDefKey]string{},
		attrIdx:     map[string]map[string]struct{}{},
		attrExcl:    map[string]struct{}{},
		pendingKeys: map[string]int{},
		streams:     map[string]*streamStat{},
		seq:         map[string]uint64{},
		lseq:        map[string]uint64{},
		surfaces:    map[event.Source]*surfaceStat{},
		wake:        make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
	if p.disabled == nil {
		p.disabled = defaultDisabled
	}
	if p.rate <= 0 {
		p.rate = 20
	}
	if p.burst <= 0 {
		p.burst = 200
	}
	p.qcap = o.QueueSize
	if p.qcap <= 0 {
		p.qcap = DefaultQueueSize
	}
	p.writer = randomWriter(o.Mode)
	p.salt = make([]byte, 32)
	_, _ = rand.Read(p.salt)
	if len(cfg.Labels) > 0 {
		p.labels = make(map[string]string, len(cfg.Labels))
		for k, v := range cfg.Labels {
			p.labels[k] = v
		}
	}
	if len(cfg.Output.Streams) > 0 {
		p.streamsOK = map[string]bool{}
		for _, s := range cfg.Output.Streams {
			p.streamsOK[s] = true
		}
	}
	p.homes = newHomeCache(o.HomeOf)
	if pol.HomeOf == nil {
		pol.HomeOf = func(user string) string { return p.homes.home("", user, time.Now()) }
	}
	p.pol = pol

	if keyErr != nil {
		// A key file that cannot be trusted is never replaced: run with the
		// per-process key (identities hold for this run only) and report it.
		p.ctr.identityKeyErrors++
	}

	p.blPath = baselinePath(cfg, o.Mode)
	var blErr error
	p.bl, blErr = OpenBaseline(p.blPath, BaselineKeys, p.idKey)
	if blErr != nil {
		// A damaged baseline, or one keyed with another identity key, is a
		// cache: start empty and report it.
		p.ctr.baselineErrors++
	}

	p.ruleOpts = rules.Options{
		Now:          o.Now,
		SuppressFor:  cfg.Rules.SuppressFor.D(),
		Suppressions: sups,
		OS:           o.Host.OS,
		HostTags:     append([]string(nil), cfg.Tags...),
		Baseline:     p.bl,
	}
	if o.Mode == ModeHook {
		// One process per user: the acting user's home is the home.
		p.ruleOpts.Home = platform.CurrentUser().Home
	}
	p.installRules(set)

	if p.async {
		p.wg.Add(1)
		go p.worker()
	}
	return p, nil
}

func randomWriter(mode string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return mode + "-" + hex.EncodeToString(b[:])
}

// installRules builds a rules engine for s; called with pmu held (or before
// the pipeline is shared).
func (p *Pipeline) installRules(s *rules.Set) {
	p.set = s
	p.eng = rules.NewEngine(s, p.ruleOpts)
	p.rulesVer = s.Version()
	p.rulesHash = s.Hash()
}

// SetRules swaps the rule set (a bundle update) without a restart. The
// per-session rule state (flags, counters, written paths, secret
// fingerprints) of every live session is carried over to the new engine.
// bundleVersion "" keeps the current one. (Additive API.)
func (p *Pipeline) SetRules(s *rules.Set, bundleVersion string) error {
	if s == nil {
		return errors.New("engine: SetRules: nil set")
	}
	s, err := ruleSet(s, p.cfg.Rules.Disable)
	if err != nil {
		return err
	}
	p.pmu.Lock()
	defer p.pmu.Unlock()
	old := p.eng
	p.installRules(s)
	if bundleVersion != "" {
		p.bundleVer = bundleVersion
	}
	for k := range p.sessions {
		if b, ok := old.ExportSession(k); ok {
			if err := p.eng.ImportSession(k, b); err != nil {
				p.ctr.errors++
			}
		}
	}
	return nil
}

// Ingest hands events to the pipeline. It is safe for concurrent use. In
// daemon mode it only appends to a bounded queue and returns; when the queue
// is full the events are dropped and counted (ingest.queue_dropped), never
// silently. While the kill switch is on, input is dropped and counted
// (ingest.disabled_dropped).
func (p *Pipeline) Ingest(evs ...*event.Event) {
	n := uint64(len(evs))
	if n == 0 {
		return
	}
	p.ingested.Add(n)
	if p.closed.Load() {
		p.closedDropped.Add(n)
		return
	}
	if p.disabledNow(false) {
		p.disabledDropped.Add(n)
		return
	}
	if !p.async {
		p.pmu.Lock()
		defer p.pmu.Unlock()
		if p.closed.Load() {
			// Close ran while this call waited for the lock.
			p.closedDropped.Add(n)
			return
		}
		now := p.o.Now()
		for _, ev := range evs {
			p.processSafe(ev, now)
		}
		p.flushWrites()
		return
	}
	// The arrival time travels with the record: the hold for a hook
	// counterpart and the session clocks count from when the record
	// reached the pipeline, not from when the worker got to it.
	at := p.o.Now()
	p.qmu.Lock()
	if p.qclosed {
		// Close has drained the queue for the last time: this call passed
		// the closed check before Close started and must still be counted.
		p.qmu.Unlock()
		p.closedDropped.Add(n)
		return
	}
	room := p.qcap - len(p.queue)
	if room < len(evs) {
		if room < 0 {
			room = 0
		}
		p.queueDropped.Add(uint64(len(evs) - room))
		evs = evs[:room]
	}
	for _, ev := range evs {
		p.queue = append(p.queue, queued{ev, at})
	}
	p.qmu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// disabledNow reads the kill switch, cached for a second on the ingest path
// (fresh=false) so a hot Ingest does not stat a file per call.
func (p *Pipeline) disabledNow(fresh bool) bool {
	now := time.Now().UnixNano()
	if !fresh && now-p.disAt.Load() < int64(disabledTTL) {
		return p.disVal.Load()
	}
	v := p.disabled()
	p.disVal.Store(v)
	p.disAt.Store(now)
	return v
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case <-p.wake:
		}
		// pmu is taken before the queue is swapped, so a Tick that holds
		// pmu has seen every event queued before it started.
		p.pmu.Lock()
		if p.disabledNow(true) {
			// Pulled after these records were queued: they are dropped and
			// counted like any input that arrives while the switch is on.
			p.dropQueued()
		} else {
			p.drainLocked()
		}
		p.flushWrites()
		p.pmu.Unlock()
	}
}

// dropQueued discards the queue and counts it (kill switch).
func (p *Pipeline) dropQueued() {
	p.qmu.Lock()
	n := len(p.queue)
	p.queue = nil
	p.qmu.Unlock()
	p.disabledDropped.Add(uint64(n))
}

// drainLocked processes everything queued; pmu must be held.
func (p *Pipeline) drainLocked() {
	for {
		p.qmu.Lock()
		batch := p.queue
		p.queue = nil
		p.qmu.Unlock()
		if len(batch) == 0 {
			return
		}
		for _, q := range batch {
			p.processSafe(q.ev, q.at)
		}
	}
}

// queued is one record waiting for the daemon worker.
type queued struct {
	ev *event.Event
	at time.Time
}

// Tick runs the timers: it first processes everything queued, then
// releases transcript and OTel tool events whose hook never came, checks
// sessions for hook bypass, emits rolling and idle session summaries, writes
// the heartbeat when it is due (config heartbeat, default 5 min; the first
// Tick always writes one) and applies the batched state changes. While the
// kill switch is on it writes only a heartbeat whose status is disabled.
func (p *Pipeline) Tick(now time.Time) {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	if p.closed.Load() {
		return
	}
	p.tickLocked(now, false)
}

func (p *Pipeline) tickLocked(now time.Time, closing bool) {
	defer func() {
		if r := recover(); r != nil {
			p.ctr.panics++
			p.ctr.errors++
		}
	}()
	disabled := p.disabledNow(true)
	if disabled {
		// Collectors idle: queued input is dropped and counted like any
		// input that arrives while the switch is on.
		p.dropQueued()
		if closing {
			// Held and waiting records and session rollups end with the
			// process.
			n := len(p.pending)
			for _, h := range p.corr.held {
				if !h.done {
					n++
				}
			}
			p.disabledDropped.Add(uint64(n))
		}
		if p.heartbeatDue(now) || closing {
			p.heartbeat(now, true)
		}
		p.flushWrites()
		return
	}
	p.drainLocked()
	p.releasePending(now, closing)
	p.adoptPending(now)
	p.releaseHeld(now, closing)
	p.checkBypass(now)
	p.sweepSessions(now, closing)
	p.corr.expire(now)
	if p.heartbeatDue(now) || closing {
		p.heartbeat(now, false)
	}
	p.flushWrites()
	p.flushState(now)
	if p.bl.Dirty() && p.blPath != "" && (closing || now.Sub(p.lastBLSave) >= baselineSaveGap) {
		if err := p.bl.Save(); err != nil {
			p.ctr.baselineErrors++
		}
		p.lastBLSave = now
	}
}

func (p *Pipeline) heartbeatDue(now time.Time) bool {
	every := p.cfg.Heartbeat.D()
	if every <= 0 {
		every = 5 * time.Minute
	}
	return p.lastHeartbeat.IsZero() || now.Sub(p.lastHeartbeat) >= every
}

// Coverage returns the per-agent, per-account visibility statement.
func (p *Pipeline) Coverage() []event.Coverage {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	return p.coverage(p.o.Now())
}

// Stats returns the pipeline's counters since start (the totals that go into
// heartbeats). (Additive API, for tests and `hawkbell doctor`.)
func (p *Pipeline) Stats() map[string]uint64 {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	return p.totals()
}

// Writer returns this process's writer id (Event.Writer of shipped records).
func (p *Pipeline) Writer() string { return p.writer }

// Close stops the worker, processes what is queued, releases held events,
// emits session summaries (Final only outside daemon mode: a daemon restart
// does not end anyone's session) and a last heartbeat, flushes the sinks
// and the state batch, and saves the baseline. Sinks and the state store
// stay open: they belong to the caller. Close is idempotent.
func (p *Pipeline) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		p.qmu.Lock()
		p.qclosed = true
		p.qmu.Unlock()
		close(p.done)
		p.wg.Wait()
		p.pmu.Lock()
		defer p.pmu.Unlock()
		p.tickLocked(p.o.Now(), true)
		var errs []error
		if err := p.o.Outbox.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("outbox flush: %w", err))
		}
		if p.o.Local != nil {
			if err := p.o.Local.Flush(); err != nil {
				errs = append(errs, fmt.Errorf("local flush: %w", err))
			}
		}
		if p.blPath != "" && p.bl.Dirty() {
			if err := p.bl.Save(); err != nil {
				errs = append(errs, fmt.Errorf("baseline: %w", err))
			}
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}
