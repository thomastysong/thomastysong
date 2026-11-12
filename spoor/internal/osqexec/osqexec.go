package osqexec

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// ErrUnavailable is returned by Poll when osquery cannot serve as an exec
// provider right now: no extension socket, the evented process table for
// this OS is missing or switched off, its publisher is not running, it has
// delivered nothing recently, or reading it would not be safe. It is a
// normal state, not a fault: most hosts run osquery without evented tables.
var ErrUnavailable = errors.New("osqexec: no evented process table is delivering")

// Status values. Errors are reported as "error:<reason>" with a reason from
// a closed list: socket_untrusted, connect, query, timeout, internal.
const (
	StatusEvent       = "event"
	StatusUnavailable = "unavailable"
)

const (
	defaultInterval = 5 * time.Second
	// socketTimeout is both the connect timeout and the read tick of the
	// Thrift socket. Reads are retried until the per-query deadline, so this
	// only bounds how long a cancelled Poll keeps blocking.
	socketTimeout = 2 * time.Second
	queryTimeout  = 15 * time.Second
	// probeEvery is how often availability (subscriber and publisher state)
	// is re-read while rows are flowing.
	probeEvery = time.Minute
	// recentWindow is the "is the publisher really delivering" horizon. Ten
	// minutes without a single exec on a machine that runs an agent does not
	// happen; on an idle host the provider reads as unavailable until the
	// next exec, which is the honest answer.
	recentWindow = 10 * time.Minute
	// startLookback is how far before the first poll rows are accepted. It
	// covers osquery's own delivery delay (measured 2 to 15 s) without
	// replaying an hour of history at every sensor start.
	startLookback = 30 * time.Second
	// maxLookback bounds the catch-up after the sensor could not poll for a
	// while. Older rows are counted as a gap instead of being replayed late.
	maxLookback = 5 * time.Minute
	// overlapSeconds re-reads the newest seconds on every poll: osquery
	// stamps rows per batch, so a row can appear with a time value that an
	// earlier poll has already passed. Seen event ids filter the repeats.
	overlapSeconds = 3
	pageRows       = 5000
	maxPages       = 4
	maxSeen        = 1 << 18
	// minSafeExpiry applies to osquery releases older than 5.0 only; see
	// the package comment.
	minSafeExpiry = 600
)

// Options configures a Source.
type Options struct {
	// Socket is the osquery extension-manager socket (a named pipe on
	// Windows). Empty means: try the well-known Orbit and osquery locations
	// and use the first that connects (see DefaultSockets).
	Socket string
	// Interval is how often the owner intends to call Poll. Default 5s.
	// Poll itself never sleeps; Interval is reported by Source.Interval.
	Interval time.Duration
	// Attribute decides whether a process belongs to an agent. It is called
	// for every exec row with the row's pid and parent pid, in event order.
	// Only rows it accepts (or whose parent was accepted earlier in the
	// stream) become events. Without it Poll reports status but no events.
	Attribute func(pid, ppid int) (agentID, sessionID string, ok bool)
}

// Stats are counters since New.
type Stats struct {
	Polls  uint64 // Poll calls
	Rows   uint64 // distinct rows read from the evented table
	Events uint64 // rows returned as events
	// Gaps counts the times rows were skipped rather than read late: a
	// catch-up longer than five minutes, or more rows in one poll than the
	// page budget allows.
	Gaps   uint64
	Table  string    // evented table in use, "" when none
	Socket string    // socket in use, "" when not connected
	Newest time.Time // time column of the newest row read
}

// Source pulls exec rows directly from a running osqueryd over its
// extension-manager socket, with a time/eid cursor, and returns only rows the
// caller attributes to an agent. Nothing is scheduled in Fleet and nothing
// leaves the host through osquery.
//
// A Source is safe for concurrent use; Poll calls are serialized.
type Source struct {
	attribute func(pid, ppid int) (string, string, bool)
	interval  time.Duration

	// Injection points; New sets the real ones.
	dial     dialFunc
	check    func(path string) error
	now      func() time.Time
	disabled func() bool
	sockets  []string
	tables   []tableSpec

	// state holds what Status and Detail report. It is separate from mu so
	// that a health check never waits behind a slow query.
	state atomic.Pointer[stateSnap]

	mu        sync.Mutex
	client    querier
	socket    string
	safe      bool // version/expiry guard passed on this connection
	table     *tableSpec
	probedAt  time.Time
	newest    time.Time
	cursor    int64
	seen      map[string]int64
	chain     chainCache
	integrity event.Integrity
	st        Stats
}

type stateSnap struct{ status, detail string }

// New returns a Source. It does not connect; the first Poll does.
func New(o Options) *Source {
	s := &Source{
		attribute: o.Attribute,
		interval:  o.Interval,
		dial:      dialOsquery,
		check:     checkSocket,
		now:       time.Now,
		disabled:  platform.Disabled,
		tables:    tablesFor(""),
		seen:      map[string]int64{},
		integrity: event.IntegrityUser,
	}
	if s.interval <= 0 {
		s.interval = defaultInterval
	}
	if o.Socket != "" {
		s.sockets = []string{o.Socket}
	} else {
		s.sockets = DefaultSockets()
	}
	// The rows come from osqueryd, but a record is only as trustworthy as
	// the process that relays it.
	if platform.IsPrivileged() {
		s.integrity = event.IntegrityRoot
	}
	s.chain.init()
	s.state.Store(&stateSnap{status: StatusUnavailable, detail: "not polled yet"})
	return s
}

// Interval returns the poll interval the Source was configured with.
func (s *Source) Interval() time.Duration { return s.interval }

// Status reports the provider state after the latest Poll:
// "event" (an evented table is delivering), "unavailable", or
// "error:<reason>".
func (s *Source) Status() string { return s.state.Load().status }

// Detail is a one-line explanation of Status for operators. It may name the
// socket and table, never row content.
func (s *Source) Detail() string { return s.state.Load().detail }

// Stats returns a snapshot of the counters.
func (s *Source) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Socket = s.socket
	st.Newest = s.newest
	if s.table != nil {
		st.Table = s.table.name
	}
	return st
}

// Close drops the connection to osqueryd. A later Poll reconnects.
func (s *Source) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
}

// Poll reads the exec rows that appeared since the previous call and returns
// the attributed ones as process.exec events (Source osquery, Fidelity
// observed), oldest first. The table is chosen by OS: process_events (Linux
// audit), es_process_events (macOS), process_etw_events (Windows). Poll
// returns ErrUnavailable (wrapped with the reason) when that table does not
// exist, is not active, its publisher is not running, or it has delivered
// nothing in the last ten minutes.
func (s *Source) Poll(ctx context.Context) (evs []*event.Event, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			// Row content is hostile; a parsing bug must cost one poll and
			// a reconnect, not the sensor.
			s.drop()
			evs, err = nil, s.fail("internal", fmt.Errorf("osqexec: internal error: %v", r))
		}
	}()
	s.st.Polls++
	if ctx == nil {
		ctx = context.Background()
	}
	if s.disabled() {
		s.drop()
		return nil, s.unavailable("disabled by the kill switch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.connect(); err != nil {
		return nil, err
	}
	now := s.now()
	if s.table == nil || now.Before(s.probedAt) || now.Sub(s.probedAt) >= probeEvery {
		if err := s.probe(ctx, now); err != nil {
			return nil, err
		}
	}
	evs, err = s.drain(ctx, now)
	if err != nil {
		return nil, err
	}
	s.setState(StatusEvent, s.table.name+" via "+s.socket)
	return evs, nil
}

// connect opens the first candidate socket that exists, passes the ownership
// check and accepts a connection.
func (s *Source) connect() error {
	if s.client != nil {
		return nil
	}
	var untrusted, refused error
	for _, path := range s.sockets {
		err := s.check(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			if untrusted == nil {
				untrusted = err
			}
			continue
		}
		c, err := s.dial(path, socketTimeout)
		if err != nil {
			if refused == nil {
				refused = fmt.Errorf("osqexec: %s: %w", path, err)
			}
			continue
		}
		s.client, s.socket = c, path
		s.safe, s.table = false, nil
		return nil
	}
	switch {
	case untrusted != nil:
		return s.fail("socket_untrusted", untrusted)
	case refused != nil:
		return s.fail("connect", refused)
	}
	return s.unavailable("no osquery extension socket")
}

// drop closes the connection. The cursor survives so that an osqueryd
// restart does not replay or lose rows.
func (s *Source) drop() {
	if s.client != nil {
		s.client.Close()
	}
	s.client, s.socket, s.table, s.safe = nil, "", nil, false
}

// query runs one statement with its own deadline. Any failure closes the
// connection: after a timeout the Thrift stream is out of step.
func (s *Source) query(ctx context.Context, sql string) ([]map[string]string, error) {
	qctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := s.client.QueryRowsContext(qctx, sql)
	if err == nil {
		return rows, nil
	}
	s.drop()
	if cerr := ctx.Err(); cerr != nil {
		// The caller gave up; that says nothing about osquery.
		return nil, cerr
	}
	if qctx.Err() != nil || isTimeout(err) {
		return nil, s.fail("timeout", fmt.Errorf("osqexec: query timed out: %w", err))
	}
	return nil, s.fail("query", fmt.Errorf("osqexec: %w", err))
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func (s *Source) setState(status, detail string) {
	if len(detail) > 300 {
		detail = detail[:300]
	}
	s.state.Store(&stateSnap{status: status, detail: detail})
}

func (s *Source) unavailable(reason string) error {
	s.setState(StatusUnavailable, reason)
	return fmt.Errorf("%w: %s", ErrUnavailable, reason)
}

func (s *Source) fail(reason string, err error) error {
	s.setState("error:"+reason, err.Error())
	return err
}
