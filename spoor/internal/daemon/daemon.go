package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/otelrecv"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/procmon"
	"github.com/thomastysong/spoor/internal/sink"
	"github.com/thomastysong/spoor/internal/state"
)

// Version is the sensor version stamped on heartbeats. cmd/spoor sets it
// from its build information.
var Version = "dev"

// ServiceName is the Windows service name the installer registers
// (packaging/windows/install-service.ps1).
const ServiceName = "spoor"

// Timing of the daemon's own loops. Collector intervals come from the
// configuration.
const (
	tickEvery        = time.Second      // engine.Pipeline.Tick cadence (the engine builder asks for about 1 s)
	maintenanceEvery = 30 * time.Second // outbox/local pruning, user refresh, bundle check
	usersEvery       = time.Minute      // re-read the account list
	bundleCheckEvery = time.Minute      // notice a bundle another process installed
	stopTimeout      = 12 * time.Second // collectors must stop within this; systemd waits 20 s in all
	adapterPoll      = 2 * time.Second
)

// runEnv holds what Run takes from the operating system. Tests replace it
// to run the daemon against a fake home without root.
type runEnv struct {
	users      func() ([]platform.UserHome, error)
	disabled   func() bool
	privileged bool
	now        func() time.Time
	host       func() (event.Host, string)
	hookStatus func(c *catalog.Catalog, o hookinstall.Options) ([]hookinstall.State, error)
	stdout     io.Writer
	tick       time.Duration
	maint      time.Duration

	// Test hooks; nil in production.
	onTranscriptPrimed func()
}

func defaultEnv() runEnv {
	return runEnv{
		users:      platform.Users,
		disabled:   platform.Disabled,
		privileged: platform.IsPrivileged(),
		now:        time.Now,
		host:       func() (event.Host, string) { return platform.HostInfo(), platform.HostIDSource() },
		hookStatus: hookinstall.Status,
		stdout:     os.Stdout,
		tick:       tickEvery,
		maint:      maintenanceEvery,
	}
}

// Run is `spoor run`: it wires every collector to the pipeline and blocks
// until ctx is done, then stops the collectors, closes the pipeline (which
// processes what is queued and writes a last heartbeat), flushes and closes
// the sinks and the state database, and returns. Under the Windows service
// control manager it runs as the service and also stops on its requests.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if handled, err := runService(ctx, cfg, log); handled {
		return err
	}
	return run(ctx, cfg, log, defaultEnv())
}

func run(ctx context.Context, cfg *config.Config, log *slog.Logger, env runEnv) error {
	if cfg == nil {
		return errors.New("daemon: no configuration")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if cfg.DataDir == "" {
		return errors.New("daemon: data_dir is not set")
	}
	d, err := newDaemon(cfg, log, env)
	if err != nil {
		return err
	}
	return d.serve(ctx)
}

// daemon is one running sensor.
type daemon struct {
	cfg     *config.Config
	log     *slog.Logger
	env     runEnv
	started time.Time

	host         event.Host
	hostIDSource string
	layout       layout

	cat    *catalog.Catalog
	policy *privacy.Policy // the daemon's own copy, for project-scan exclusions
	pipe   *engine.Pipeline
	store  *state.Store

	outbox   sink.Sink // what the pipeline writes to: files, plus stdout when configured
	files    sink.Sink // the outbox segment files
	local    sink.Sink
	pruner   *outboxPruner
	shippers []*shipperRun

	users  *userSet
	procs  *procView
	hooks  *hookView
	board  *board
	mon    *procmon.Monitor
	otel   *otelrecv.Receiver
	bundle *bundleMgr
	scans  *scanner
	trans  *transcriptRunner

	gate *killGate

	earlyMu sync.Mutex
	early   []*event.Event // health records produced before the pipeline existed

	wg sync.WaitGroup
}

// emit hands a record the daemon produced itself (health errors) to the
// pipeline, or keeps it until the pipeline exists.
func (d *daemon) emit(ev *event.Event) {
	d.earlyMu.Lock()
	if d.pipe == nil {
		if len(d.early) < 64 {
			d.early = append(d.early, ev)
		}
		d.earlyMu.Unlock()
		return
	}
	d.earlyMu.Unlock()
	d.pipe.Ingest(ev)
}

func newDaemon(cfg *config.Config, log *slog.Logger, env runEnv) (_ *daemon, err error) {
	d := &daemon{
		cfg:     cfg,
		log:     log,
		env:     env,
		started: env.now(),
		users:   newUserSet(),
		procs:   newProcView(),
		hooks:   newHookView(),
		board:   newBoard(),
		gate:    newKillGate(env.disabled, env.now),
	}
	// Anything opened before a later step fails is closed again.
	defer func() {
		if err != nil {
			d.closeStores()
		}
	}()

	d.host, d.hostIDSource = env.host()
	if cfg.HostID != "" {
		d.host.ID, d.hostIDSource = cfg.HostID, "config"
	}
	if !env.privileged {
		log.Warn("spoor is not running privileged: only this account's agents are visible, and records are user-integrity")
	}

	if d.layout, err = prepareLayout(cfg, env.privileged, log); err != nil {
		return nil, err
	}
	if err := d.refreshUsers(); err != nil {
		log.Warn("account list unavailable", "error", err)
	}

	if d.cat, err = catalog.Load(); err != nil {
		return nil, fmt.Errorf("daemon: catalog: %w", err)
	}
	d.bundle = newBundleMgr(d)
	set, bundleVer := d.bundle.initial()

	if d.policy, err = engine.PolicyFromConfig(cfg); err != nil {
		return nil, fmt.Errorf("daemon: privacy: %w", err)
	}
	if err := d.openSinks(); err != nil {
		return nil, err
	}
	if st, serr := state.Open(cfg.StateDB()); serr != nil {
		// The sensor keeps collecting and shipping without its state
		// database; Fleet's freshness policy fails, which is the signal.
		log.Error("state database unavailable; Fleet tables will not be updated", "path", cfg.StateDB(), "error", serr)
		d.board.add("state.open_failed", 1)
	} else {
		d.store = st
	}

	if config.On(cfg.Sources.Processes.Enabled, true) {
		d.mon = procmon.New(procmon.Options{
			Catalog:         d.cat,
			Idle:            cfg.Sources.Processes.Idle.D(),
			Active:          cfg.Sources.Processes.Active.D(),
			Emit:            func(ev *event.Event) { d.ingest(ev) },
			HostRoot:        cfg.HostRoot,
			ExecEvents:      config.On(cfg.Sources.Processes.ExecEvents, true),
			OsquerySocket:   cfg.Sources.OsqueryExec.Socket,
			OsqueryInterval: cfg.Sources.OsqueryExec.Interval.D(),
			NoOsquery:       !config.On(cfg.Sources.OsqueryExec.Enabled, true),
		})
	}
	if cfg.Sources.OTLP.Enabled {
		d.otel = otelrecv.New(otelrecv.Options{
			Addr: cfg.Sources.OTLP.Addr,
			Emit: func(ev *event.Event) { d.ingest(ev) },
		})
	}

	pipe, err := engine.New(engine.Options{
		Config:        cfg,
		Catalog:       d.cat,
		Rules:         set,
		Outbox:        d.outbox,
		Local:         d.local,
		State:         d.store,
		Host:          d.host,
		Mode:          engine.ModeDaemon,
		Now:           env.now,
		Hooked:        d.hooks.lookup,
		RootSaw:       d.procs.rootSaw,
		SensorVersion: Version,
		BundleVersion: bundleVer,
		HostIDSource:  d.hostIDSource,
		Disabled:      env.disabled,
		Surfaces:      d.board.surfaces,
		Gauges:        d.board.counters,
		HomeOf:        d.users.homeOf,
	})
	if err != nil {
		return nil, fmt.Errorf("daemon: pipeline: %w", err)
	}
	d.earlyMu.Lock()
	d.pipe = pipe
	early := d.early
	d.early = nil
	d.earlyMu.Unlock()
	if len(early) > 0 {
		d.pipe.Ingest(early...)
	}
	d.scans = newScanner(d)
	d.trans = newTranscriptRunner(d)
	return d, nil
}

// releaseSettle is how long collectors keep their records back after the
// kill switch is released: the pipeline caches its view of the switch for
// up to a second (engine disabledTTL) and drops what it is handed meanwhile.
const releaseSettle = 2 * time.Second

// killGate is the collectors' view of the kill switch.
type killGate struct {
	disabled func() bool
	now      func() time.Time
	mu       sync.Mutex
	wasOff   bool
	until    time.Time
}

func newKillGate(disabled func() bool, now func() time.Time) *killGate {
	return &killGate{disabled: disabled, now: now}
}

// state reports whether the switch is on, and whether it was released so
// recently that records must not be handed to the pipeline yet.
func (g *killGate) state() (off, settling bool) {
	off = g.disabled()
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if off {
		g.wasOff = true
		return true, false
	}
	if g.wasOff {
		g.wasOff = false
		g.until = now.Add(releaseSettle)
	}
	return false, now.Before(g.until)
}

// idle is true while collectors must not hand records over.
func (g *killGate) idle() bool {
	off, settling := g.state()
	return off || settling
}

// ingest hands collector output to the pipeline. The pipeline owns the
// events from then on, so the daemon looks at what it needs (session
// working directories for project scans) before.
func (d *daemon) ingest(evs ...*event.Event) {
	if len(evs) == 0 {
		return
	}
	if d.scans != nil {
		d.scans.noteSessions(evs)
	}
	d.pipe.Ingest(evs...)
}

// serve runs until ctx is done, then shuts down in order.
func (d *daemon) serve(ctx context.Context) error {
	collectCtx, stopCollectors := context.WithCancel(ctx)
	shipCtx, stopShippers := context.WithCancel(context.Background())
	defer stopShippers()
	d.log.Info("spoor daemon started", "version", Version, "data_dir", d.cfg.DataDir,
		"host_id_source", d.hostIDSource, "privileged", d.env.privileged, "profile", d.cfg.Privacy.Profile)

	d.start(collectCtx, "tick", d.tickLoop)
	d.start(collectCtx, "maintenance", d.maintenanceLoop)
	d.start(collectCtx, "spool", newSpoolRunner(d).run)
	d.start(collectCtx, "transcripts", d.trans.run)
	d.start(collectCtx, "adapters", newAdapterRunner(d).run)
	d.start(collectCtx, "scan", d.scans.run)
	d.start(collectCtx, "projects", d.scans.projectWorker)
	d.start(collectCtx, "bundle", d.bundle.run)
	if d.mon != nil {
		d.start(collectCtx, "processes", d.runMonitor)
	} else {
		d.board.surface(event.SurfaceStatus{Name: "processes", Status: "disabled", Reason: "config"})
	}
	if d.otel != nil {
		d.start(collectCtx, "otel", d.runOTel)
	}
	var shipWG sync.WaitGroup
	for _, s := range d.shippers {
		s := s
		shipWG.Add(1)
		go func() {
			defer shipWG.Done()
			s.run(shipCtx, d)
		}()
	}

	<-ctx.Done()
	d.log.Info("spoor daemon stopping")
	stopCollectors()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopTimeout):
		// A collector stuck in a system call must not keep the records
		// already queued from being flushed.
		d.log.Error("collectors did not stop in time; flushing anyway")
	}

	var errs []error
	if err := d.pipe.Close(); err != nil {
		errs = append(errs, fmt.Errorf("pipeline: %w", err))
	}
	d.trans.commit()
	stopShippers()
	shipWG.Wait()
	if err := d.closeStores(); err != nil {
		errs = append(errs, err)
	}
	d.log.Info("spoor daemon stopped")
	return errors.Join(errs...)
}

// closeStores flushes and closes the sinks and the state database.
func (d *daemon) closeStores() error {
	var errs []error
	if d.outbox != nil {
		if err := d.outbox.Close(); err != nil && !errors.Is(err, sink.ErrClosed) {
			errs = append(errs, fmt.Errorf("outbox: %w", err))
		}
		d.outbox = nil
	}
	if d.local != nil {
		if err := d.local.Close(); err != nil && !errors.Is(err, sink.ErrClosed) {
			errs = append(errs, fmt.Errorf("local ring: %w", err))
		}
		d.local = nil
	}
	for _, s := range d.shippers {
		if s.dst != nil {
			_ = s.dst.Close()
		}
	}
	if d.store != nil {
		if err := d.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("state: %w", err))
		}
		d.store = nil
	}
	return errors.Join(errs...)
}

// start runs fn in its own goroutine and restarts it after a panic or an
// error, with backoff, until ctx is done: one broken collector must not
// take the sensor down.
func (d *daemon) start(ctx context.Context, name string, fn func(context.Context) error) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		backoff := time.Second
		for {
			err := d.guard(ctx, name, fn)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				d.log.Error("collector failed; restarting", "collector", name, "error", err, "in", backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
}

func (d *daemon) guard(ctx context.Context, name string, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			d.board.add("daemon.panics", 1)
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}

// tickLoop drives the pipeline's timers about once a second.
func (d *daemon) tickLoop(ctx context.Context) error {
	t := time.NewTicker(d.env.tick)
	defer t.Stop()
	d.refreshProcs()
	d.pipe.Tick(d.env.now())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			d.refreshProcs()
			d.pipe.Tick(d.env.now())
		}
	}
}

// maintenanceLoop keeps the local stores within their limits and notices
// account and bundle changes.
func (d *daemon) maintenanceLoop(ctx context.Context) error {
	t := time.NewTicker(d.env.maint)
	defer t.Stop()
	var lastUsers, lastStatePrune, lastBundle time.Time
	d.pruneOutbox(d.env.now())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		now := d.env.now()
		d.pruneOutbox(now)
		if p, ok := d.local.(sink.Pruner); ok {
			if err := p.Prune(); err != nil {
				d.board.add("local.prune_errors", 1)
			}
		}
		if now.Sub(lastUsers) >= usersEvery {
			lastUsers = now
			if err := d.refreshUsers(); err != nil {
				d.log.Warn("account list unavailable", "error", err)
			}
		}
		if d.store != nil && now.Sub(lastStatePrune) >= d.cfg.Heartbeat.D() {
			lastStatePrune = now
			if err := d.store.Prune(now, state.Retention{
				Detections: d.cfg.Retention.Detections.D(),
				Sessions:   d.cfg.Retention.Sessions.D(),
			}); err != nil {
				d.board.add("state.prune_errors", 1)
				d.log.Warn("state prune failed", "error", err)
			}
		}
		if now.Sub(lastBundle) >= bundleCheckEvery {
			lastBundle = now
			d.bundle.check()
		}
	}
}

// pruneOutbox runs one pruning pass and reports unread data it dropped.
func (d *daemon) pruneOutbox(now time.Time) {
	if d.pruner == nil {
		return
	}
	res := d.pruner.prune(now)
	d.recordPrune(res)
	if res.unread.events > 0 || res.unread.bytes > 0 {
		d.emit(droppedUnshippedEvent(now, res.unread))
		d.log.Warn("outbox byte cap dropped data no consumer had read",
			"bytes", res.unread.bytes, "records", res.unread.events, "segments", res.unread.segments)
	}
}

// refreshUsers re-reads the account list, makes sure every account has its
// private spool directory, and publishes the list.
func (d *daemon) refreshUsers() error {
	list, err := d.env.users()
	if err != nil {
		return err
	}
	if !d.env.privileged {
		list = ownAccount(list, currentUID(), os.UserHomeDir)
	}
	for _, u := range list {
		if err := ensureUserSpool(d.layout, u, d.env.privileged); err != nil {
			d.board.add("spool.dir_errors", 1)
			d.log.Warn("cannot prepare spool directory", "uid", u.UID, "error", err)
		}
	}
	d.users.set(list)
	d.board.set("users", uint64(len(list)))
	return nil
}

// ownAccount keeps the caller's own account: unprivileged, only its home is
// ours to read. uid is currentUID(): the numeric uid on POSIX and the SID
// on Windows, where os.Geteuid is always -1 and platform.Users names the
// account by SID. When the process's own identity cannot be read, the home
// directory decides.
func ownAccount(list []platform.UserHome, uid string, home func() (string, error)) []platform.UserHome {
	var kept []platform.UserHome
	if uid != "" {
		for _, u := range list {
			if u.UID == uid || u.UID == "" {
				kept = append(kept, u)
			}
		}
		return kept
	}
	h, err := home()
	if err != nil || h == "" {
		return nil
	}
	for _, u := range list {
		if u.Home != "" && filepath.Clean(u.Home) == filepath.Clean(h) {
			kept = append(kept, u)
		}
	}
	return kept
}

func (d *daemon) runMonitor(ctx context.Context) error {
	return d.mon.Run(ctx)
}

func (d *daemon) runOTel(ctx context.Context) error {
	err := d.otel.Run(ctx)
	if err != nil {
		d.board.surface(event.SurfaceStatus{Name: "otel", Status: "failed", Reason: "listen"})
		// A refused address does not get better by retrying every few
		// seconds; wait for the configuration to change (restart).
		d.log.Error("OTLP receiver cannot run", "addr", d.cfg.Sources.OTLP.Addr, "error", err)
		<-ctx.Done()
		return nil
	}
	return nil
}

// refreshProcs copies what the monitor knows into the views the pipeline
// reads under its own lock, so the pipeline never calls into the monitor.
func (d *daemon) refreshProcs() {
	if d.mon == nil {
		return
	}
	agents := d.mon.Agents()
	d.procs.set(agents, d.users)
	cwds := make([]agentCWD, 0, len(agents))
	for _, a := range agents {
		if a.CWD != "" {
			cwds = append(cwds, agentCWD{agent: a.AgentID, cwd: a.CWD, user: a.User})
		}
	}
	d.scans.noteAgents(cwds)
	st := d.mon.Stats()
	d.board.surface(monitorSurface(st))
	if config.On(d.cfg.Sources.OsqueryExec.Enabled, true) {
		d.board.surface(osquerySurface(st))
	}
	d.board.set("procmon.roots", uint64(st.Roots))
	d.board.set("procmon.exec_healthy", boolGauge(st.ExecHealthy))
	d.board.set("procmon.rate_dropped", st.RateDropped)
	d.board.set("procmon.queue_dropped", st.QueueDropped)
	d.board.set("procmon.overflows", st.Overflows)
	d.board.set("procmon.read_misses", st.ReadMisses)
	if d.otel != nil {
		d.board.surface(d.otel.Surface())
	}
	for _, s := range d.shippers {
		s.report(d.board)
	}
}

func boolGauge(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// osquerySurface renders the osquery exec provider (internal/osqexec,
// run by the monitor): event | unavailable | error:<reason>.
func osquerySurface(st procmon.Stats) event.SurfaceStatus {
	s := event.SurfaceStatus{Name: "osquery", Status: "ok", Events: st.OsqueryEvts}
	switch {
	case st.Disabled:
		s.Status, s.Reason = "disabled", "kill_switch"
	case st.Osquery == "event" || st.Source == procmon.SourceOsquery:
	case st.Osquery == "" || st.Osquery == "unavailable":
		s.Status, s.Reason = "disabled", "unavailable"
	default:
		s.Status, s.Reason = "failed", "error"
	}
	return s
}

// monitorSurface renders the process monitor's state for the heartbeat.
func monitorSurface(st procmon.Stats) event.SurfaceStatus {
	s := event.SurfaceStatus{Name: "processes", Status: "ok", Errors: st.Errors}
	switch {
	case st.Disabled:
		s.Status, s.Reason = "disabled", "kill_switch"
	case st.Source == procmon.SourcePoll:
		// Polling sees agents but is not exec ground truth.
		s.Status, s.Reason = "degraded", "exec_source_poll"
	case !st.ExecHealthy && !st.LastCanary.IsZero():
		s.Status, s.Reason = "degraded", "exec_selftest_failed"
	}
	if !st.LastCanary.IsZero() {
		s.LastEvent = event.At(st.LastCanary)
	}
	return s
}
