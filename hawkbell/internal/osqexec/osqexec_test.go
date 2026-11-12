package osqexec

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// agentTree attributes direct children of pid 100 only, the way a process
// monitor does when the grandchildren are already gone.
func agentTree(pid, ppid int) (string, string, bool) {
	if ppid == 100 {
		return "claude-code", "sess-1", true
	}
	return "", "", false
}

func TestPollAttributesChainAndRedacts(t *testing.T) {
	const secret = "s3cr3tValue0123456789abcdef"
	f := newFake()
	f.add("process_events",
		auditRow(1, t0-5, 200, 100, "/usr/bin/bash", "bash -c make test"),
		auditRow(2, t0-5, 300, 200, "/usr/bin/make", "make test"),
		auditRow(3, t0-4, 301, 300, "/usr/bin/curl", "curl --token "+secret+" https://user:"+secret+"@example.com/x"),
		auditRow(4, t0-4, 400, 1, "/usr/sbin/cron", "cron -f"),
		auditRow(5, t0-4, 401, 400, "/usr/bin/run-parts", "run-parts /etc/cron.hourly"),
	)
	s, _ := newTestSource(t, "linux", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Status(); got != StatusEvent {
		t.Fatalf("status = %q", got)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (bash, make, curl): %+v", len(evs), evs)
	}
	wantPIDs := []int{200, 300, 301}
	for i, ev := range evs {
		if ev.Kind != event.KindActivity || ev.Type != event.TypeProcessExec || ev.Source != event.SourceOsquery || ev.Fidelity != event.FidelityObserved {
			t.Errorf("event %d: kind/type/source/fidelity = %s/%s/%s/%s", i, ev.Kind, ev.Type, ev.Source, ev.Fidelity)
		}
		if ev.Process == nil || ev.Process.PID != wantPIDs[i] {
			t.Fatalf("event %d: process = %+v, want pid %d", i, ev.Process, wantPIDs[i])
		}
		if ev.Agent == nil || ev.Agent.ID != "claude-code" {
			t.Errorf("event %d: agent = %+v", i, ev.Agent)
		}
		if ev.Session == nil || ev.Session.ID != "sess-1" || ev.Session.CWD != "/home/dev/project" {
			t.Errorf("event %d: session = %+v", i, ev.Session)
		}
		if ev.User == nil || ev.User.ID != "1000" {
			t.Errorf("event %d: user = %+v", i, ev.User)
		}
		if ev.Integrity == "" || ev.ID == "" || ev.V != event.SchemaVersion {
			t.Errorf("event %d: integrity=%q id=%q v=%d", i, ev.Integrity, ev.ID, ev.V)
		}
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(line), secret) {
			t.Errorf("event %d leaks the secret: %s", i, line)
		}
	}
	if p := evs[2].Process; p.Name != "curl" || p.Exe != "/usr/bin/curl" || p.PPID != 300 || len(p.Args) != 4 {
		t.Errorf("curl process = %+v", p)
	}
	if evs[0].TS.Unix() != t0-5 {
		t.Errorf("ts = %v, want row time", evs[0].TS)
	}
	st := s.Stats()
	if st.Rows != 5 || st.Events != 3 || st.Table != "process_events" || st.Socket == "" {
		t.Errorf("stats = %+v", st)
	}
}

func TestPollCursor(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh -c a"))
	s, c := newTestSource(t, "linux", f, agentTree)
	first, err := s.Poll(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first poll: %d events, err %v", len(first), err)
	}
	// Nothing new: the overlap re-reads the row, the seen set drops it.
	c.add(5 * time.Second)
	if evs, err := s.Poll(context.Background()); err != nil || len(evs) != 0 {
		t.Fatalf("second poll: %d events, err %v", len(evs), err)
	}
	// A new row, plus a late one that osquery stamped inside the overlap.
	f.add("process_events",
		auditRow(3, t0+6, 202, 100, "/bin/sh", "sh -c c"),
		auditRow(2, t0-3, 201, 100, "/bin/sh", "sh -c b"),
	)
	c.add(5 * time.Second)
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 2 {
		t.Fatalf("third poll: %d events, err %v", len(evs), err)
	}
	if evs[0].Process.PID != 201 || evs[1].Process.PID != 202 {
		t.Errorf("order = %d, %d; want oldest first", evs[0].Process.PID, evs[1].Process.PID)
	}
	// Replaying the same row yields the same id.
	s2, _ := newTestSource(t, "linux", f, agentTree)
	s2.now = func() time.Time { return time.Unix(t0, 0) }
	again, err := s2.Poll(context.Background())
	if err != nil || len(again) == 0 {
		t.Fatalf("replay: %d events, err %v", len(again), err)
	}
	byPID := map[int]string{}
	for _, ev := range append(first, evs...) {
		byPID[ev.Process.PID] = ev.ID
	}
	for _, ev := range again {
		if byPID[ev.Process.PID] != ev.ID {
			t.Errorf("pid %d: id %s on replay, %s before", ev.Process.PID, ev.ID, byPID[ev.Process.PID])
		}
	}
}

func TestPollEventIDReset(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(900, t0-2, 200, 100, "/bin/sh", "sh -c a"))
	s, c := newTestSource(t, "linux", f, agentTree)
	if evs, err := s.Poll(context.Background()); err != nil || len(evs) != 1 {
		t.Fatalf("first poll: %d events, err %v", len(evs), err)
	}
	// osqueryd lost its database: ids start again from 1.
	f.mu.Lock()
	f.tables["process_events"] = nil
	f.mu.Unlock()
	c.add(20 * time.Second)
	f.add("process_events", auditRow(1, t0+15, 210, 100, "/bin/sh", "sh -c b"))
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 1 || evs[0].Process.PID != 210 {
		t.Fatalf("after reset: %d events, err %v", len(evs), err)
	}
}

func TestUnavailable(t *testing.T) {
	recent := auditRow(1, t0-2, 200, 100, "/bin/sh", "sh")
	cases := []struct {
		name  string
		setup func(f *fakeOsquery)
		want  string
		ok    bool
	}{
		{name: "delivering", setup: func(f *fakeOsquery) { f.add("process_events", recent) }, ok: true},
		{name: "no evented table", setup: func(f *fakeOsquery) { f.events = nil }, want: "no evented process table"},
		{name: "subscriber off", setup: func(f *fakeOsquery) {
			f.events[1]["active"] = "0"
		}, want: "not enabled"},
		{name: "publisher dead", setup: func(f *fakeOsquery) {
			f.events[0]["active"] = "0"
			f.add("process_events", recent)
		}, want: "publisher is not running"},
		{name: "active but silent", setup: func(f *fakeOsquery) {
			f.add("process_events", auditRow(1, t0-3600, 200, 100, "/bin/sh", "sh"))
		}, want: "delivered no event"},
		{name: "empty table", setup: func(f *fakeOsquery) { f.tables["process_events"] = nil }, want: "delivered no event"},
		{name: "old osquery short expiry", setup: func(f *fakeOsquery) {
			f.version, f.flags["events_expiry"] = "4.9.0", "1"
			f.add("process_events", recent)
		}, want: "events_expiry=1"},
		{name: "old osquery long expiry", setup: func(f *fakeOsquery) {
			f.version, f.flags["events_expiry"] = "4.9.0", "3600"
			f.add("process_events", recent)
		}, ok: true},
		{name: "unparsable version short expiry", setup: func(f *fakeOsquery) {
			f.version, f.flags["events_expiry"] = "garbage", "60"
			f.add("process_events", recent)
		}, want: "events_expiry=60"},
		{name: "new osquery short expiry", setup: func(f *fakeOsquery) {
			f.flags["events_expiry"] = "1"
			f.add("process_events", recent)
		}, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.setup(f)
			s, _ := newTestSource(t, "linux", f, agentTree)
			evs, err := s.Poll(context.Background())
			if tc.ok {
				if err != nil || s.Status() != StatusEvent || len(evs) != 1 {
					t.Fatalf("err %v, status %q, %d events", err, s.Status(), len(evs))
				}
				return
			}
			if len(evs) != 0 {
				t.Fatalf("got %d events from an unavailable provider", len(evs))
			}
			mustUnavailable(t, s, err, tc.want)
		})
	}
}

func TestUnavailableRecovers(t *testing.T) {
	f := newFake()
	f.tables["process_events"] = nil
	s, c := newTestSource(t, "linux", f, agentTree)
	_, err := s.Poll(context.Background())
	mustUnavailable(t, s, err, "delivered no event")
	// The first exec after a quiet period brings the provider back.
	c.add(5 * time.Second)
	f.add("process_events", auditRow(1, t0+3, 200, 100, "/bin/sh", "sh"))
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 1 || s.Status() != StatusEvent {
		t.Fatalf("err %v, status %q, %d events", err, s.Status(), len(evs))
	}
	// And a publisher that stops is noticed at the next probe.
	c.add(recentWindow + probeEvery)
	_, err = s.Poll(context.Background())
	mustUnavailable(t, s, err, "delivered no event")
}

func TestConnectFailures(t *testing.T) {
	t.Run("no socket", func(t *testing.T) {
		s, _ := newTestSource(t, "linux", newFake(), nil)
		s.check = func(string) error { return errNotExist }
		_, err := s.Poll(context.Background())
		mustUnavailable(t, s, err, "no osquery extension socket")
	})
	t.Run("untrusted socket", func(t *testing.T) {
		s, _ := newTestSource(t, "linux", newFake(), nil)
		dialed := false
		s.check = func(string) error { return errors.New("socket is not owned by root") }
		s.dial = func(string, time.Duration) (querier, error) { dialed = true; return newFake(), nil }
		_, err := s.Poll(context.Background())
		if err == nil || errors.Is(err, ErrUnavailable) || s.Status() != "error:socket_untrusted" {
			t.Fatalf("err %v, status %q", err, s.Status())
		}
		if dialed {
			t.Fatal("connected to a socket that failed the ownership check")
		}
	})
	t.Run("refused", func(t *testing.T) {
		s, _ := newTestSource(t, "linux", newFake(), nil)
		s.dial = func(string, time.Duration) (querier, error) { return nil, errors.New("connection refused") }
		_, err := s.Poll(context.Background())
		if err == nil || s.Status() != "error:connect" {
			t.Fatalf("err %v, status %q", err, s.Status())
		}
	})
	t.Run("first that connects", func(t *testing.T) {
		f := newFake()
		f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
		s, _ := newTestSource(t, "linux", f, agentTree)
		s.sockets = []string{"/a.em", "/b.em", "/c.em"}
		s.check = func(p string) error {
			if p == "/a.em" {
				return errNotExist
			}
			return nil
		}
		s.dial = func(p string, _ time.Duration) (querier, error) {
			if p == "/b.em" {
				return nil, errors.New("refused")
			}
			return f, nil
		}
		if _, err := s.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := s.Stats().Socket; got != "/c.em" {
			t.Fatalf("socket = %q, want /c.em", got)
		}
	})
}

func TestQueryFailureReconnects(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
	s, _ := newTestSource(t, "linux", f, agentTree)
	dials := 0
	s.dial = func(string, time.Duration) (querier, error) { dials++; return f, nil }
	f.failNext, f.failErr = 1, errors.New("transport error in query: broken pipe")
	if _, err := s.Poll(context.Background()); err == nil || s.Status() != "error:query" {
		t.Fatalf("err %v, status %q", err, s.Status())
	}
	if f.closed != 1 {
		t.Fatalf("connection closed %d times after a failed query, want 1", f.closed)
	}
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 1 || dials != 2 {
		t.Fatalf("recovery: err %v, %d events, %d dials", err, len(evs), dials)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestQueryTimeout(t *testing.T) {
	f := newFake()
	s, _ := newTestSource(t, "linux", f, agentTree)
	f.failNext, f.failErr = 1, fmt.Errorf("transport error in query: %w", timeoutErr{})
	if _, err := s.Poll(context.Background()); err == nil || s.Status() != "error:timeout" {
		t.Fatalf("err %v, status %q", err, s.Status())
	}
}

func TestContextCancelled(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
	s, _ := newTestSource(t, "linux", f, agentTree)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Poll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if s.Status() != StatusEvent {
		t.Fatalf("a cancelled poll changed the status to %q", s.Status())
	}
	// Cancellation in the middle of a query: the caller gave up, osquery
	// did not fail.
	f.block = true
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.probedAt = time.Time{}
	if _, err := s.Poll(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if s.Status() != StatusEvent {
		t.Fatalf("a cancelled query changed the status to %q", s.Status())
	}
}

func TestKillSwitch(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
	s, _ := newTestSource(t, "linux", f, agentTree)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.disabled = func() bool { return true }
	before := len(f.sent())
	_, err := s.Poll(context.Background())
	mustUnavailable(t, s, err, "kill switch")
	if len(f.sent()) != before || f.closed != 1 {
		t.Fatalf("disabled poll sent %d queries, closed %d", len(f.sent())-before, f.closed)
	}
}

func TestNoAttributeNoEvents(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
	s, _ := newTestSource(t, "linux", f, nil)
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 0 || s.Status() != StatusEvent {
		t.Fatalf("err %v, %d events, status %q", err, len(evs), s.Status())
	}
}

// Every statement against an evented table must constrain time (that is
// what keeps this reader from moving the scheduler's cursor), and the
// environment column must never be asked for.
func TestQueriesAreTimeBoundAndEnvFree(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		f := newFake()
		spec := tablesFor(goos)[0]
		f.events = []map[string]string{{"name": spec.name, "publisher": "p", "type": "subscriber", "active": "1"}}
		f.add(spec.name, map[string]string{"pid": "200", "parent": "100", "ppid": "100", "path": "/x", "cmdline": "x", "time": strconv.FormatInt(t0-2, 10), "eid": "1"})
		s, _ := newTestSource(t, goos, f, agentTree)
		if _, err := s.Poll(context.Background()); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		touched := 0
		for _, q := range f.sent() {
			lq := strings.ToLower(q)
			if strings.Contains(lq, "env") {
				t.Errorf("%s: query mentions env: %s", goos, q)
			}
			if !strings.Contains(lq, "from "+spec.name) {
				continue
			}
			touched++
			if !reTime.MatchString(q) {
				t.Errorf("%s: query on %s without a time constraint: %s", goos, spec.name, q)
			}
		}
		if touched < 2 {
			t.Errorf("%s: expected a window probe and a fetch on %s, saw %d", goos, spec.name, touched)
		}
	}
}

func TestPagination(t *testing.T) {
	f := newFake()
	const n = pageRows + 250
	rows := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, auditRow(i+1, t0-10+int64(i%8), 1000+i, 100, "/bin/true", "true"))
	}
	f.add("process_events", rows...)
	s, _ := newTestSource(t, "linux", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != n || s.Stats().Gaps != 0 {
		t.Fatalf("%d events, %d gaps; want %d and 0", len(evs), s.Stats().Gaps, n)
	}
	seen := map[int]bool{}
	for _, ev := range evs {
		if seen[ev.Process.PID] {
			t.Fatalf("pid %d returned twice", ev.Process.PID)
		}
		seen[ev.Process.PID] = true
	}
}

func TestBurstBeyondBudgetIsAGap(t *testing.T) {
	f := newFake()
	const n = pageRows*maxPages + 10
	rows := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, auditRow(i+1, t0-5, 1000+i, 1, "/bin/true", "true"))
	}
	f.add("process_events", rows...)
	s, c := newTestSource(t, "linux", f, agentTree)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats(); got.Gaps != 1 || got.Rows != pageRows*maxPages {
		t.Fatalf("stats = %+v, want one gap and %d rows", got, pageRows*maxPages)
	}
	// The reader moved on instead of re-reading the same burst forever.
	c.add(10 * time.Second)
	f.add("process_events", auditRow(n+1, t0+8, 5, 100, "/bin/sh", "sh"))
	evs, err := s.Poll(context.Background())
	if err != nil || len(evs) != 1 {
		t.Fatalf("after the burst: %d events, err %v", len(evs), err)
	}
}

func TestLongOutageIsAGap(t *testing.T) {
	f := newFake()
	f.add("process_events", auditRow(1, t0-2, 200, 100, "/bin/sh", "sh"))
	s, c := newTestSource(t, "linux", f, agentTree)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	now := c.now().Unix()
	f.add("process_events",
		auditRow(2, now-1800, 201, 100, "/bin/sh", "sh -c old"),
		auditRow(3, now-10, 202, 100, "/bin/sh", "sh -c new"),
	)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Process.PID != 202 || s.Stats().Gaps != 1 {
		t.Fatalf("%d events, gaps %d; want only the recent row and one gap", len(evs), s.Stats().Gaps)
	}
}

func TestPIDReuseBreaksChain(t *testing.T) {
	f := newFake()
	f.add("process_events",
		auditRow(1, t0-9, 200, 100, "/bin/sh", "sh -c x"),           // agent child
		auditRow(2, t0-8, 200, 100, "/usr/bin/env", "env prog"),     // same process, exec again
		auditRow(3, t0-7, 200, 50, "/usr/sbin/sshd", "sshd: other"), // pid recycled under another parent
		auditRow(4, t0-6, 300, 200, "/bin/ls", "ls"),                // child of the recycled pid
	)
	attr := func(pid, ppid int) (string, string, bool) {
		// The monitor only knows the agent root; the second exec of pid 200
		// is answered by the chain.
		return agentTree(pid, ppid)
	}
	calls := 0
	s, _ := newTestSource(t, "linux", f, func(pid, ppid int) (string, string, bool) {
		calls++
		if calls == 2 {
			return "", "", false // monitor lost sight of pid 200
		}
		return attr(pid, ppid)
	})
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Process.Name != "sh" || evs[1].Process.Name != "env" {
		t.Fatalf("events = %v; want the two execs of the agent child only", names(evs))
	}
}

func TestDarwinRows(t *testing.T) {
	f := newFake()
	f.events = []map[string]string{
		{"name": "endpointsecurity", "publisher": "endpointsecurity", "type": "publisher", "active": "1"},
		{"name": "es_process_events", "publisher": "endpointsecurity", "type": "subscriber", "active": "1"},
	}
	row := func(eid int, typ string, pid, ppid, child int, path, cmdline string) map[string]string {
		return map[string]string{
			"pid": strconv.Itoa(pid), "parent": strconv.Itoa(ppid), "child_pid": strconv.Itoa(child),
			"path": path, "cmdline": cmdline, "cwd": "/Users/dev/project", "uid": "501", "username": "dev",
			"event_type": typ, "time": strconv.FormatInt(t0-3, 10), "eid": fmt.Sprintf("%010d", eid),
		}
	}
	f.add("es_process_events",
		row(1, "exec", 200, 100, 0, "/bin/zsh", "zsh -c ./build.sh"),
		row(2, "fork", 200, 100, 201, "/bin/zsh", "zsh -c ./build.sh"), // subshell, no exec of its own
		row(3, "exec", 300, 201, 0, "/usr/bin/git", "git status"),
		row(4, "exit", 300, 201, 0, "/usr/bin/git", "git status"),
		row(5, "exec", 400, 1, 0, "/usr/libexec/xpcproxy", "xpcproxy com.apple.foo"),
	)
	s, _ := newTestSource(t, "darwin", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(evs); len(got) != 2 || got[0] != "zsh" || got[1] != "git" {
		t.Fatalf("events = %v; want zsh and git (fork followed, exit ignored)", got)
	}
	if u := evs[1].User; u == nil || u.Name != "dev" || u.ID != "501" || evs[1].Process.User != "dev" {
		t.Errorf("user = %+v", u)
	}
	if evs[1].Labels["osquery_table"] != "es_process_events" {
		t.Errorf("labels = %v", evs[1].Labels)
	}
}

func TestWindowsRows(t *testing.T) {
	f := newFake()
	f.events = []map[string]string{{"name": "process_etw_events", "publisher": "etw", "type": "subscriber", "active": "1"}}
	row := func(eid int, typ string, pid, ppid int, path, cmdline string) map[string]string {
		return map[string]string{
			"pid": strconv.Itoa(pid), "ppid": strconv.Itoa(ppid), "path": path, "cmdline": cmdline,
			"username": `CORP\dev`, "type": typ, "time": strconv.FormatInt(t0-3, 10), "eid": strconv.Itoa(eid),
		}
	}
	f.add("process_etw_events",
		row(9, "ProcessStart", 200, 100, `\Device\HarddiskVolume3\Windows\System32\cmd.exe`, `cmd.exe /d /s /c "npm test"`),
		row(10, "ProcessStart", 300, 200, `C:\Program Files\nodejs\node.exe`, `node npm-cli.js test`),
		row(11, "ProcessStop", 300, 200, `C:\Program Files\nodejs\node.exe`, `node npm-cli.js test`),
		row(12, "ProcessStart", 400, 4, `C:\Windows\System32\svchost.exe`, `svchost.exe -k netsvcs`),
	)
	s, _ := newTestSource(t, "windows", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(evs); len(got) != 2 || got[0] != "cmd.exe" || got[1] != "node.exe" {
		t.Fatalf("events = %v; want cmd.exe and node.exe", got)
	}
	if u := evs[0].User; u == nil || u.Name != `CORP\dev` || u.ID != "" {
		t.Errorf("user = %+v", u)
	}
	if evs[0].Session == nil || evs[0].Session.ID != "sess-1" || evs[0].Session.CWD != "" {
		t.Errorf("session = %+v", evs[0].Session)
	}
}

func TestHostileRows(t *testing.T) {
	f := newFake()
	huge := strings.Repeat("A", 1<<20)
	many := strings.Repeat("x ", 5000)
	f.add("process_events",
		nil,
		map[string]string{},
		map[string]string{"pid": "-5", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "1"},
		map[string]string{"pid": "99999999999999999999", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "2"},
		map[string]string{"pid": "200", "parent": "100", "time": "not-a-number", "eid": "3"},
		map[string]string{"pid": "201", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "not-a-number", "path": "/bin/a\x00b", "cmdline": "a\xff\xfeb " + huge},
		map[string]string{"pid": "202", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "5", "path": strings.Repeat("/p", 4000), "cmdline": many, "cwd": "relative/../../etc", "uid": "0; DROP TABLE"},
		map[string]string{"pid": "203", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "6", "syscall": "ptrace", "cmdline": "x"},
		map[string]string{"pid": "204", "parent": "100", "time": strconv.FormatInt(t0-2, 10), "eid": "7", "cmdline": "", "path": ""},
	)
	s, _ := newTestSource(t, "linux", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (pids 201, 202, 204): %v", len(evs), names(evs))
	}
	for _, ev := range evs {
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		if len(line) > 16<<10 {
			t.Errorf("pid %d: line is %d bytes, over the 16 KiB cap", ev.Process.PID, len(line))
		}
		if len(ev.Process.Args) > maxArgs {
			t.Errorf("pid %d: %d args", ev.Process.PID, len(ev.Process.Args))
		}
		for _, a := range ev.Process.Args {
			if len(a) > maxArgBytes+64 { // a redaction marker may be longer than what it replaces
				t.Errorf("pid %d: argument of %d bytes", ev.Process.PID, len(a))
			}
		}
	}
	if ev := evs[0]; ev.Process.Exe != "" || len(ev.Truncated) == 0 {
		t.Errorf("pid 201: exe %q (NUL must drop it), truncated %v", ev.Process.Exe, ev.Truncated)
	}
	if ev := evs[1]; ev.User != nil || ev.Session.CWD != "" || len(ev.Process.Exe) > maxPathBytes || len(ev.Truncated) == 0 {
		t.Errorf("pid 202: user %+v, session %+v, exe %d bytes, truncated %v", ev.User, ev.Session, len(ev.Process.Exe), ev.Truncated)
	}
}

func TestSplitCmdline(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantCut bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"a b  c\td", 4, false},
		{strings.Repeat("a ", maxArgs+1), maxArgs, true},
		{strings.Repeat("é", maxArgBytes), 1, true},
		{strings.Repeat("b", sqlCmdline), 1, true},
	}
	for _, tc := range cases {
		got, cut := splitCmdline(tc.in)
		if len(got) != tc.want || cut != tc.wantCut {
			t.Errorf("splitCmdline(%.20q...) = %d args, cut %v; want %d, %v", tc.in, len(got), cut, tc.want, tc.wantCut)
		}
		for _, a := range got {
			if len(a) > maxArgBytes || !validUTF8(a) {
				t.Errorf("argument %d bytes, valid utf8 %v", len(a), validUTF8(a))
			}
		}
	}
}

func TestCleanCWD(t *testing.T) {
	for in, want := range map[string]string{
		`"/home/u/p"`:        "/home/u/p",
		"/home/u/p":          "/home/u/p",
		`C:\Users\u\p`:       `C:\Users\u\p`,
		`\\srv\share\p`:      `\\srv\share\p`,
		"":                   "",
		`""`:                 "",
		"relative/path":      "",
		"2F686F6D65":         "",
		"/with\nnewline":     "",
		"  /padded  ":        "/padded",
		`"/unterminated`:     "",
		"/ok/" + "é\xff\xfe": "/ok/é\uFFFD",
	} {
		if got := cleanCWD(in); got != want {
			t.Errorf("cleanCWD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMajorVersion(t *testing.T) {
	for in, want := range map[string]int{"5.19.0": 5, " 4.9.0": 4, "10.1": 10, "": 0, "v5.1": 0, "-3.0": 0, "5": 5} {
		if got := majorVersion(in); got != want {
			t.Errorf("majorVersion(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	s := New(Options{})
	if s.Interval() != 5*time.Second {
		t.Errorf("interval = %v", s.Interval())
	}
	if s.Status() != StatusUnavailable {
		t.Errorf("status before the first poll = %q", s.Status())
	}
	if len(s.sockets) != len(DefaultSockets()) {
		t.Errorf("sockets = %v", s.sockets)
	}
	s = New(Options{Socket: "/x.em", Interval: time.Second})
	if len(s.sockets) != 1 || s.sockets[0] != "/x.em" || s.Interval() != time.Second {
		t.Errorf("explicit options not honoured: %v %v", s.sockets, s.Interval())
	}
	s.Close() // closing an unconnected source is fine
}

func names(evs []*event.Event) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Process.Name
	}
	return out
}

func validUTF8(s string) bool { return strings.ToValidUTF8(s, "") == s }
