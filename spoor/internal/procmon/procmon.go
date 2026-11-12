package procmon

import (
	"errors"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/osqexec"
	"github.com/thomastysong/spoor/internal/platform"
)

// Exec provider names reported by Monitor.Source. The kill switch is not a
// provider: while it is on Source reports poll and Stats.Disabled is set.
const (
	SourceCNProc  = "cn_proc"
	SourceOsquery = "osquery"
	SourcePoll    = "poll"
)

// Evidence class used when an agent was recognised from the marker
// variables its children carry rather than from the catalog fingerprints.
const EvidenceEnvMarker = "env_marker"

// EvidenceEnvMarkerWeak is the Evidence of an Attribute answer that rests
// only on a weak marker: a name the catalog has not verified, or one a user
// can export for every process of a shell (COPILOT_MODEL). Such processes
// are never reported as process.exec on that ground.
const EvidenceEnvMarkerWeak = "env_marker_weak"

// AgentProc is one running (or recently seen) agent root process.
type AgentProc struct {
	PID   int
	Start time.Time
	// AgentID is the catalog id of the agent.
	AgentID string
	User    event.User
	Exe     string
	// Args is the command line redacted with classify.RedactArgs.
	Args []string
	// Flags are the catalog RiskyFlags present in argv (also the
	// "--flag=value" spellings), in catalog spelling.
	Flags []string
	// Headless is a -p / exec / --print style non-interactive run, when the
	// agent's command line says so (see traits.go for the sources).
	Headless bool
	// SessionIDs come from the session variables of the agent's children
	// (at most 16, oldest first).
	SessionIDs []string
	// ConfigHome is the value of a HomeEnv override (CLAUDE_CONFIG_DIR,
	// CODEX_HOME ...) in the agent's environment; "" when the default is
	// used or the environment could not be read.
	ConfigHome string
	// Ancestors are process names from the parent up to init.
	Ancestors []string
	// LifecycleParent: npm | yarn | pnpm | bun | pip | setup.py |
	// extension_host | url_handler | "".
	LifecycleParent string
	Container       event.Container

	// The fields below are additions to the original specification.

	PPID int
	Name string
	// CWD is the working directory of the agent process when readable.
	CWD string
	// Bare records Claude Code bare mode (--bare or CLAUDE_CODE_SIMPLE).
	// Managed-tier tool hooks still run under it, so it is not HookFree.
	Bare bool
	// HookFree is set when no spoor hook can be expected to fire: a
	// documented hook-trust bypass (codex --dangerously-bypass-hook-trust),
	// or an agent whose catalog entry has no hook dialect.
	HookFree bool
	// PersistenceFree is set when the run writes no transcript
	// (--no-session-persistence, codex --ephemeral,
	// CLAUDE_CODE_SKIP_PROMPT_HISTORY).
	PersistenceFree bool
	// EnvMarkers are agent marker variable NAMES in the agent's own
	// environment (inherited from an enclosing agent or IDE).
	EnvMarkers []string
	// Evidence lists how the process was identified: catalog evidence
	// classes ("process_name", "path", "args" ...) or "env_marker".
	Evidence []string
	// ParentAgent is the agent id of the nearest enclosing agent root when
	// one agent runs another.
	ParentAgent string
}

func (a AgentProc) clone() AgentProc {
	c := a
	c.Args = append([]string(nil), a.Args...)
	c.Flags = append([]string(nil), a.Flags...)
	c.SessionIDs = append([]string(nil), a.SessionIDs...)
	c.Ancestors = append([]string(nil), a.Ancestors...)
	c.EnvMarkers = append([]string(nil), a.EnvMarkers...)
	c.Evidence = append([]string(nil), a.Evidence...)
	return c
}

// Options configures a Monitor.
type Options struct {
	// Catalog identifies agents. nil loads the embedded catalog.
	Catalog *catalog.Catalog
	// Idle and Active are the poll intervals: default 2s while no agent
	// root is alive, 200ms while at least one is (in poll mode).
	Idle, Active time.Duration
	// Emit receives agent.process.start/stop and process.exec events. It is
	// called from one goroutine, in order; a slow Emit makes the monitor
	// drop events (counted in Stats.QueueDropped), never stall collection.
	Emit func(*event.Event)
	// HostRoot is where the host filesystem is mounted when the sensor runs
	// in a container without the host pid namespace; <HostRoot>/proc is read
	// instead of /proc. Linux only.
	HostRoot string
	// ExecEvents turns on the Linux netlink process connector (cn_proc) for
	// exec/exit events. It needs root, or kernel >= 6.6, and the initial
	// network, user and pid namespaces; otherwise the monitor falls back
	// silently and Source reports what is in use.
	ExecEvents bool

	// Additions to the original specification:

	// OsquerySocket is the osquery extension socket for the second exec
	// provider ("" = well-known Orbit and osquery locations).
	OsquerySocket string
	// OsqueryInterval is how often osquery is polled (default 5s).
	OsqueryInterval time.Duration
	// NoOsquery turns the osquery exec provider off.
	NoOsquery bool
}

// Stats are counters since New, for the heartbeat.
type Stats struct {
	Source      string
	ExecHealthy bool
	Disabled    bool
	Roots       int // live agent roots
	Tracked     int // processes in the table
	Scans       uint64
	ActiveScans uint64
	// Execs counts exec events delivered by the process connector (every
	// process on the host); Attributed those that belonged to an agent.
	Execs      uint64
	Attributed uint64
	ExecEvents uint64 // process.exec events emitted
	// RateDropped counts process.exec events over the per-root cap of 20/s.
	RateDropped uint64
	// QueueDropped counts events dropped because Emit fell behind.
	QueueDropped uint64
	// Overflows counts netlink buffer overruns (ENOBUFS), each followed by
	// a full rescan.
	Overflows uint64
	// ReadMisses counts exec events whose process had exited before /proc
	// could be read.
	ReadMisses  uint64
	TableFull   uint64
	CanaryRuns  uint64
	CanaryHits  uint64
	LastCanary  time.Time
	CNProcError string // why the process connector is not in use
	Osquery     string // osqexec status
	OsqueryEvts uint64
	Errors      uint64
}

// Internal limits.
const (
	maxTable       = 1 << 17
	maxRoots       = 1024
	maxTomb        = 8192
	maxAncestors   = 32
	maxExecAnc     = 16
	maxWalk        = 64
	queueCap       = 4096
	defaultIdle    = 2 * time.Second
	defaultActive  = 200 * time.Millisecond
	resyncEvery    = 30 * time.Second
	tombTTL        = 2 * time.Minute
	exitMarkTTL    = time.Minute
	cnRetryEvery   = time.Minute
	cnNoAckRetry   = 10 * time.Minute
	osqRetryEvery  = time.Minute
	osqRateWindow  = 10 * time.Minute
	canaryEvery    = 5 * time.Minute
	canaryFirst    = 3 * time.Second
	canaryWaitCN   = 5 * time.Second
	canaryWaitOsq  = 90 * time.Second
	execRate       = 20
	globalExecRate = 500
	indexRefresh   = 5 * time.Minute
)

var errAlreadyRunning = errors.New("procmon: monitor is already running")

// Monitor tracks agent processes and the processes they start. It is safe
// for concurrent use.
type Monitor struct {
	o         Options
	cat       *catalog.Catalog
	src       source
	initErr   error
	self      int
	integrity event.Integrity
	// canaryParent is the pid of this process, the parent of every
	// self-test process it starts (m.self can differ in tests).
	canaryParent int

	// Injection points; New sets the real ones.
	now      func() time.Time
	disabled func() bool
	openCN   func() (cnConn, error)
	osq      execSource
	canaryFn func() (string, []string, bool)
	monoWall func(ns uint64) time.Time

	// Tunables (constants above, shortened by tests).
	resync      time.Duration
	canaryEvery time.Duration
	canaryFirst time.Duration
	rate, burst float64

	queue   chan *event.Event
	running atomic.Bool
	nudge   chan struct{}

	// provider state, read by Source/ExecHealthy without the table lock.
	provider atomic.Value // string
	cnErr    atomic.Value // string
	cnLive   atomic.Bool
	osqLive  atomic.Bool
	healthy  atomic.Bool
	resyncRq atomic.Bool
	// off is set while Run sees the kill switch.
	off atomic.Bool

	idx   atomic.Pointer[catIndex]
	idxAt atomic.Int64

	mu       sync.Mutex
	nodes    map[int]*node
	roots    map[procKey]*root
	tomb     map[int]*node
	exitMark map[int]exitMark
	markerB  map[string]*bucket
	global   bucket
	// osqGlobal is the host-wide cap for osquery rows, on their own event
	// time (see osqRowTime).
	osqGlobal bucket
	seq       uint64
	can       canaryState

	st counters
}

type counters struct {
	scans, activeScans, execs, attributed, execEvents, rateDropped atomic.Uint64
	queueDropped, overflows, readMisses, tableFull, errors         atomic.Uint64
	canaryRuns, canaryHits, osqEvents                              atomic.Uint64
	lastCanary                                                     atomic.Int64
}

// New returns a Monitor. It does not start anything; Run does. Agents and
// Attribute work before Run (Attribute reads the process table on demand).
func New(o Options) *Monitor {
	if o.Idle <= 0 {
		o.Idle = defaultIdle
	}
	if o.Active <= 0 {
		o.Active = defaultActive
	}
	m := &Monitor{
		o:            o,
		cat:          o.Catalog,
		self:         os.Getpid(),
		canaryParent: os.Getpid(),
		integrity:    event.IntegrityUser,
		now:          time.Now,
		disabled:     platform.Disabled,
		openCN:       openCNProc,
		canaryFn:     canaryCommand,
		monoWall:     monotonicToWall,
		resync:       resyncEvery,
		canaryEvery:  canaryEvery,
		canaryFirst:  canaryFirst,
		rate:         execRate,
		burst:        execRate,
		queue:        make(chan *event.Event, queueCap),
		nudge:        make(chan struct{}, 1),
		nodes:        map[int]*node{},
		roots:        map[procKey]*root{},
		tomb:         map[int]*node{},
		exitMark:     map[int]exitMark{},
		markerB:      map[string]*bucket{},
	}
	if platform.IsPrivileged() {
		m.integrity = event.IntegrityRoot
	}
	m.provider.Store(SourcePoll)
	m.cnErr.Store("not started")
	if m.cat == nil {
		c, err := catalog.Load()
		if err != nil {
			m.initErr = err
		}
		m.cat = c
	}
	if m.cat != nil {
		m.idx.Store(buildIndex(m.cat))
		m.idxAt.Store(time.Now().UnixNano())
	} else {
		m.idx.Store(&catIndex{prods: map[string]*prodInfo{}, marker: map[string]string{}, strong: map[string]bool{}, keep: map[string]bool{}})
	}
	src, err := newSource(o.HostRoot)
	if err != nil && m.initErr == nil {
		m.initErr = err
	}
	m.src = src
	if !o.NoOsquery {
		m.osq = osqexec.New(osqexec.Options{
			Socket:    o.OsquerySocket,
			Interval:  o.OsqueryInterval,
			Attribute: m.osqAttribute,
		})
	}
	return m
}

// index returns the current catalog index.
func (m *Monitor) index() *catIndex { return m.idx.Load() }

// refreshIndex rebuilds the catalog index when the catalog changed (an
// overlay was loaded) and at least every indexRefresh.
func (m *Monitor) refreshIndex(now time.Time) {
	if m.cat == nil {
		return
	}
	cur := m.index()
	stale := now.Sub(time.Unix(0, m.idxAt.Load())) > indexRefresh
	if cur != nil && !stale && cur.version == m.cat.Version() && cur.count == m.cat.Len() {
		return
	}
	m.idx.Store(buildIndex(m.cat))
	m.idxAt.Store(now.UnixNano())
}

// Source reports the exec provider in use: cn_proc, osquery or poll (poll
// also while the kill switch is on; Stats.Disabled says so).
func (m *Monitor) Source() string {
	if s, _ := m.provider.Load().(string); s != "" {
		return s
	}
	return SourcePoll
}

// ExecHealthy reports whether the active exec provider delivered the last
// self-test exec (a harmless canary process the monitor starts every five
// minutes). It is false in poll mode, which is not exec ground truth, and
// until the first self-test of a provider has completed.
func (m *Monitor) ExecHealthy() bool { return m.healthy.Load() }

// Agents returns the live agent roots, ordered by pid.
func (m *Monitor) Agents() []AgentProc {
	m.mu.Lock()
	out := make([]AgentProc, 0, len(m.roots))
	for _, r := range m.roots {
		if r.alive {
			out = append(out, r.ap.clone())
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// Stats returns a snapshot of the counters.
func (m *Monitor) Stats() Stats {
	s := Stats{
		Source:       m.Source(),
		ExecHealthy:  m.ExecHealthy(),
		Disabled:     m.off.Load(),
		Scans:        m.st.scans.Load(),
		ActiveScans:  m.st.activeScans.Load(),
		Execs:        m.st.execs.Load(),
		Attributed:   m.st.attributed.Load(),
		ExecEvents:   m.st.execEvents.Load(),
		RateDropped:  m.st.rateDropped.Load(),
		QueueDropped: m.st.queueDropped.Load(),
		Overflows:    m.st.overflows.Load(),
		ReadMisses:   m.st.readMisses.Load(),
		TableFull:    m.st.tableFull.Load(),
		CanaryRuns:   m.st.canaryRuns.Load(),
		CanaryHits:   m.st.canaryHits.Load(),
		OsqueryEvts:  m.st.osqEvents.Load(),
		Errors:       m.st.errors.Load(),
	}
	if ns := m.st.lastCanary.Load(); ns != 0 {
		s.LastCanary = time.Unix(0, ns)
	}
	if !m.cnLive.Load() {
		s.CNProcError, _ = m.cnErr.Load().(string)
	}
	if m.osq != nil {
		s.Osquery = m.osq.Status()
	}
	m.mu.Lock()
	for _, r := range m.roots {
		if r.alive {
			s.Roots++
		}
	}
	s.Tracked = len(m.nodes)
	m.mu.Unlock()
	return s
}
