package daemon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/discovery"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/platform"
)

// scanner schedules discovery: a full scan at start and every
// scan.full_every, differential scans every scan.interval, and a project
// scan for every new session working directory. It also refreshes the hook
// registration view the pipeline's Hooked reads.
type scanner struct {
	d     *daemon
	projQ chan projectReq

	mu       sync.Mutex
	recent   map[string]time.Time // uid + cwd -> when queued
	perUser  map[string]*hourCount
	scanning bool
	projIDs  map[string]bool // assets project scans reported while a full scan ran
}

type projectReq struct {
	dir, uid string
}

type hourCount struct {
	start time.Time
	n     int
}

const (
	projectQueue       = 64
	projectAgain       = 6 * time.Hour // the same directory is scanned again only after this
	projectPerUserHour = 60
	projectDeadline    = 15 * time.Second
	projectPause       = 200 * time.Millisecond
	maxRecentProjects  = 4096
	hooksEvery         = 10 * time.Minute
)

func newScanner(d *daemon) *scanner {
	return &scanner{
		d:       d,
		projQ:   make(chan projectReq, projectQueue),
		recent:  map[string]time.Time{},
		perUser: map[string]*hourCount{},
		projIDs: map[string]bool{},
	}
}

func (s *scanner) enabled() bool { return config.On(s.d.cfg.Sources.Scan.Enabled, true) }

func (s *scanner) projectsEnabled() bool {
	return s.enabled() && config.On(s.d.cfg.Sources.Scan.Projects, true) && s.d.cfg.HostRoot == ""
}

// noteSessions queues a project scan for working directories of sessions
// not seen recently. It runs on the collectors' goroutines before the
// pipeline takes the events.
func (s *scanner) noteSessions(evs []*event.Event) {
	if !s.projectsEnabled() {
		return
	}
	for _, ev := range evs {
		if ev == nil || ev.Kind != event.KindActivity || ev.Session == nil || ev.Session.CWD == "" || ev.User == nil || ev.User.ID == "" {
			continue
		}
		if ev.Source == event.SourceProcess || ev.Source == event.SourceOsquery {
			// A child process's working directory is wherever a build or a
			// shell went, not the session's project; agent roots are
			// handled by noteAgents.
			continue
		}
		probe := &event.Event{
			Kind:    event.KindActivity,
			User:    &event.User{Name: ev.User.Name, ID: ev.User.ID},
			Session: &event.Session{ID: ev.Session.ID, CWD: ev.Session.CWD},
		}
		if ev.Repo != nil {
			r := *ev.Repo
			probe.Repo = &r
		}
		if ev.Agent != nil {
			probe.Agent = &event.Agent{ID: ev.Agent.ID}
		}
		s.queueProject(probe)
	}
}

// queueProject applies the privacy exclusions (an excluded session's
// project is never read), the per-directory and per-account rate limits,
// and queues the scan without blocking.
func (s *scanner) queueProject(probe *event.Event) {
	cwd, uid := probe.Session.CWD, probe.User.ID
	if !filepath.IsAbs(cwd) || filepath.Clean(cwd) != cwd || len(cwd) > 4096 {
		return
	}
	now := s.d.env.now()
	key := uid + "\x00" + cwd
	s.mu.Lock()
	if t, ok := s.recent[key]; ok && now.Sub(t) < projectAgain {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if s.d.policy.Excluded(probe) {
		s.d.board.add("scan.project_excluded", 1)
		s.mark(key, now)
		return
	}
	s.mu.Lock()
	hc := s.perUser[uid]
	if hc == nil || now.Sub(hc.start) >= time.Hour {
		hc = &hourCount{start: now}
		s.perUser[uid] = hc
	}
	if hc.n >= projectPerUserHour {
		s.mu.Unlock()
		s.d.board.add("scan.project_rate_limited", 1)
		return
	}
	hc.n++
	s.mu.Unlock()
	select {
	case s.projQ <- projectReq{dir: cwd, uid: uid}:
		s.mark(key, now)
	default:
		s.d.board.add("scan.project_dropped", 1)
	}
}

func (s *scanner) mark(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recent) >= maxRecentProjects {
		for k, t := range s.recent {
			if now.Sub(t) >= projectAgain {
				delete(s.recent, k)
			}
		}
		if len(s.recent) >= maxRecentProjects {
			clear(s.recent)
		}
	}
	s.recent[key] = now
}

// noteAgents queues project scans for the working directories of agent
// processes the monitor sees (root-observed, so they also cover agents
// without hooks or transcripts).
func (s *scanner) noteAgents(agents []agentCWD) {
	if !s.projectsEnabled() {
		return
	}
	for _, a := range agents {
		if a.cwd == "" || a.user.ID == "" {
			continue
		}
		s.queueProject(&event.Event{
			Kind:    event.KindActivity,
			User:    &event.User{Name: a.user.Name, ID: a.user.ID},
			Session: &event.Session{CWD: a.cwd},
			Agent:   &event.Agent{ID: a.agent},
		})
	}
}

type agentCWD struct {
	agent, cwd string
	user       event.User
}

// projectWorker runs the queued project scans one at a time.
func (s *scanner) projectWorker(ctx context.Context) error {
	d := s.d
	for {
		var req projectReq
		select {
		case <-ctx.Done():
			return nil
		case req = <-s.projQ:
		}
		if d.gate.idle() {
			continue
		}
		u, ok := d.users.byID(req.uid)
		if !ok {
			d.board.add("scan.project_unknown_user", 1)
			continue
		}
		if !ownProjectDir(req.dir, req.uid) {
			// The directory comes from a user-written record: the sensor
			// only looks into directories that account owns, never into
			// /etc or another account's tree on its say-so.
			d.board.add("scan.project_refused", 1)
			continue
		}
		res, err := discovery.ScanProject(ctx, req.dir, u, discovery.Options{
			Catalog:  d.cat,
			Prev:     s.prev(),
			Host:     &d.host,
			Env:      d.scanEnv,
			Deadline: projectDeadline,
			Now:      d.env.now,
		})
		d.board.add("scan.project_runs", 1)
		if err != nil {
			d.board.add("scan.project_errors", 1)
			continue
		}
		s.mu.Lock()
		if s.scanning {
			for _, ev := range res.Events {
				if ev.Asset != nil && ev.Asset.ID != "" {
					s.projIDs[ev.Asset.ID] = true
				}
			}
		}
		s.mu.Unlock()
		d.ingest(res.Events...)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(projectPause):
		}
	}
}

// prev is the state database's view of present assets, for differential
// output; nil without a database (every asset is then new).
func (s *scanner) prev() map[string]string {
	if s.d.store == nil {
		return nil
	}
	m, err := s.d.store.Snapshot()
	if err != nil {
		return nil
	}
	if m == nil {
		m = map[string]string{}
	}
	return m
}

// run schedules the machine scans and the hook view refresh.
func (s *scanner) run(ctx context.Context) error {
	d := s.d
	if !s.enabled() {
		d.board.surface(event.SurfaceStatus{Name: "scan", Status: "disabled", Reason: "config"})
	}
	interval := d.cfg.Sources.Scan.Interval.D()
	if interval < time.Minute {
		interval = time.Hour
	}
	fullEvery := d.cfg.Sources.Scan.FullEvery.D()
	if fullEvery <= 0 {
		fullEvery = 24 * time.Hour
	}
	var lastFull, lastScan, lastHooks time.Time
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	if !d.gate.idle() {
		// Before the first scan, which can take a minute: the pipeline's
		// coverage logic needs to know where hooks are installed.
		s.refreshHooks()
	}
	for {
		now := d.env.now()
		if s.enabled() && !d.gate.idle() && (lastScan.IsZero() || now.Sub(lastScan) >= interval) {
			full := lastFull.IsZero() || now.Sub(lastFull) >= fullEvery
			s.scan(ctx, full)
			lastScan = d.env.now()
			if full {
				lastFull = lastScan
			}
			lastHooks = time.Time{} // refresh the hook view right after a scan
		}
		if ctx.Err() != nil {
			return nil
		}
		if !d.gate.idle() && (lastHooks.IsZero() || now.Sub(lastHooks) >= hooksEvery) {
			s.refreshHooks()
			lastHooks = d.env.now()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// scan runs one machine scan and records its outcome in the state
// database: MarkScan with the ids the scan saw when it was complete, with a
// zero finish time (nothing removed) when it was not.
func (s *scanner) scan(ctx context.Context, full bool) {
	d := s.d
	started := d.env.now()
	prev := s.prev()
	s.mu.Lock()
	s.scanning = true
	clear(s.projIDs)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
	}()
	var users []platform.UserHome
	if d.cfg.HostRoot == "" {
		users = d.users.all()
	}
	res, err := discovery.Scan(ctx, discovery.Options{
		Catalog:   d.cat,
		Users:     users,
		HostRoot:  d.cfg.HostRoot,
		Projects:  config.On(d.cfg.Sources.Scan.Projects, true),
		Prev:      prev,
		Full:      full,
		Host:      &d.host,
		Env:       d.scanEnv,
		Processes: d.procSnapshot(),
		Now:       d.env.now,
	})
	d.board.add("scan.runs", 1)
	if err != nil {
		d.board.add("scan.errors", 1)
		d.board.surface(event.SurfaceStatus{Name: "scan", Status: "failed", Reason: "error"})
		d.log.Warn("discovery scan failed", "error", err)
		if d.store != nil {
			_ = d.store.MarkScan(started, time.Time{}, nil)
		}
		return
	}
	d.ingest(res.Events...)
	led := res.Ledger
	complete := prev != nil && !led.Truncated && !ledgerIncomplete(led) && ctx.Err() == nil
	if d.store != nil {
		var err error
		if complete {
			err = d.store.MarkScan(started, d.env.now(), s.seen(prev, res.Events))
		} else {
			err = d.store.MarkScan(started, time.Time{}, nil)
		}
		if err != nil {
			d.board.add("scan.mark_errors", 1)
		}
	}
	d.board.set("scan.assets_reported", uint64(len(res.Events)))
	d.board.add("scan.denied", uint64(led.Denied))
	d.board.add("scan.read_errors", uint64(led.Errors))
	surf := event.SurfaceStatus{Name: "scan", Status: "ok", LastEvent: event.At(d.env.now()), Errors: uint64(led.Errors)}
	if !complete {
		d.board.add("scan.incomplete", 1)
		surf.Status, surf.Reason = "degraded", "incomplete"
	}
	d.board.surface(surf)
}

// ledgerIncomplete reports discovery's own verdict that removals could not
// be concluded (a refused home, a read error, a cap).
func ledgerIncomplete(l discovery.Ledger) bool {
	for _, n := range l.Notes {
		if strings.HasPrefix(n, "removals not reported") {
			return true
		}
	}
	return false
}

// seen is every asset the scan observed: the previous view minus what it
// reported removed, plus what it reported, plus what project scans reported
// while it ran (applied to the database before MarkScan, they must not be
// taken for removed).
func (s *scanner) seen(prev map[string]string, evs []*event.Event) []string {
	set := make(map[string]bool, len(prev)+len(evs))
	for id := range prev {
		set[id] = true
	}
	for _, ev := range evs {
		if ev.Asset == nil || ev.Asset.ID == "" {
			continue
		}
		if ev.Asset.Change == event.ChangeRemoved {
			delete(set, ev.Asset.ID)
		} else {
			set[ev.Asset.ID] = true
		}
	}
	s.mu.Lock()
	for id := range s.projIDs {
		set[id] = true
	}
	s.mu.Unlock()
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out
}

// refreshHooks rebuilds the hook registration view from hookinstall.Status
// for every account.
func (s *scanner) refreshHooks() {
	d := s.d
	view := map[[2]string]string{}
	for _, u := range d.users.all() {
		states, err := d.env.hookStatus(d.cat, hookinstall.Options{
			Home: u.Home,
			Env:  d.procs.envFor(u.UID, d.cat),
			Root: d.cfg.HostRoot,
			GOOS: runtime.GOOS,
		})
		if err != nil {
			d.board.add("hooks.status_errors", 1)
			continue
		}
		for agent, st := range combineHookStates(states) {
			if u.Name != "" {
				view[[2]string{agent, u.Name}] = st
			}
			if u.UID != "" {
				view[[2]string{agent, u.UID}] = st
			}
		}
	}
	d.hooks.set(view)
	d.board.add("hooks.status_refreshes", 1)
}

// combineHookStates reduces hookinstall's per-scope states to the one value
// per agent that engine.Options.Hooked expects: managed | user | modified |
// shadowed | unsupported | missing, the best tier that is effective first.
// insecure_permissions counts as modified (registered, but a non-admin can
// rewrite it); foreign_only as missing.
func combineHookStates(states []hookinstall.State) map[string]string {
	rank := map[string]int{"managed": 0, "user": 1, "modified": 2, "shadowed": 3, "unsupported": 4, "missing": 5}
	out := map[string]string{}
	for _, st := range states {
		v := ""
		switch st.Status {
		case hookinstall.StatusManaged:
			v = "managed"
		case hookinstall.StatusUser:
			v = "user"
		case hookinstall.StatusModified, hookinstall.StatusInsecure:
			v = "modified"
		case hookinstall.StatusShadowed:
			v = "shadowed"
		case hookinstall.StatusUnsupported:
			v = "unsupported"
		default:
			v = "missing"
		}
		if cur, ok := out[st.AgentID]; !ok || rank[v] < rank[cur] {
			out[st.AgentID] = v
		}
	}
	return out
}

// ownProjectDir reports whether dir is a real directory (not a link) owned
// by the account. Where ownership cannot be read (Windows without a SID
// match) discovery's own per-file owner check still applies.
func ownProjectDir(dir, uid string) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	owner, ok := platform.PathOwner(dir)
	return !ok || owner == uid
}

// scanEnv is discovery.Options.Env: the relocation variables the process
// monitor saw for the account.
func (d *daemon) scanEnv(u platform.UserHome) map[string]string {
	return d.procs.envFor(u.UID, d.cat)
}

// procSnapshot converts the monitor's agent roots for discovery, which uses
// them to mark agents as running.
func (d *daemon) procSnapshot() []platform.Proc {
	agents := d.procs.list()
	if len(agents) == 0 {
		return nil
	}
	out := make([]platform.Proc, 0, len(agents))
	for _, a := range agents {
		out = append(out, platform.Proc{
			PID: a.PID, PPID: a.PPID, Name: a.Name, Exe: a.Exe, Args: a.Args,
			Start: a.Start, UID: a.User.ID, User: a.User.Name,
		})
	}
	return out
}
