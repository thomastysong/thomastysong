package osqexec

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOsquery answers the handful of statements the package sends, from
// tables held in memory. It understands just enough SQL: which table, the
// "time >= N" bound, LIMIT and OFFSET.
type fakeOsquery struct {
	mu      sync.Mutex
	version string
	flags   map[string]string
	events  []map[string]string            // osquery_events
	tables  map[string][]map[string]string // evented tables
	queries []string
	closed  int
	// failNext makes the next n queries fail with this error.
	failNext int
	failErr  error
	// block makes queries wait for the context to end.
	block bool
}

func newFake() *fakeOsquery {
	return &fakeOsquery{
		version: "5.19.0",
		flags:   map[string]string{"events_expiry": "3600"},
		events: []map[string]string{
			{"name": "auditeventpublisher", "publisher": "auditeventpublisher", "type": "publisher", "active": "1"},
			{"name": "process_events", "publisher": "auditeventpublisher", "type": "subscriber", "active": "1"},
		},
		tables: map[string][]map[string]string{},
	}
}

var (
	reFrom   = regexp.MustCompile(`(?i)\bFROM\s+([a-z_]+)`)
	reTime   = regexp.MustCompile(`(?i)\btime\s*>=\s*(-?\d+)`)
	reLimit  = regexp.MustCompile(`(?i)\bLIMIT\s+(\d+)`)
	reOffset = regexp.MustCompile(`(?i)\bOFFSET\s+(\d+)`)
)

func (f *fakeOsquery) QueryRowsContext(ctx context.Context, sql string) ([]map[string]string, error) {
	f.mu.Lock()
	f.queries = append(f.queries, sql)
	if f.block {
		f.mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return nil, f.failErr
	}
	m := reFrom.FindStringSubmatch(sql)
	if m == nil {
		return nil, fmt.Errorf("query returned error: no table in %q", sql)
	}
	switch table := strings.ToLower(m[1]); table {
	case "osquery_events":
		return copyRows(f.events), nil
	case "osquery_info":
		return []map[string]string{{"version": f.version}}, nil
	case "osquery_flags":
		var out []map[string]string
		for k, v := range f.flags {
			if strings.Contains(sql, "'"+k+"'") {
				out = append(out, map[string]string{"name": k, "value": v})
			}
		}
		return out, nil
	default:
		rows, ok := f.tables[table]
		if !ok {
			return nil, fmt.Errorf("query returned error: no such table: %s", table)
		}
		from := int64(0)
		if tm := reTime.FindStringSubmatch(sql); tm != nil {
			from, _ = strconv.ParseInt(tm[1], 10, 64)
		}
		var out []map[string]string
		for _, r := range rows {
			ts, err := strconv.ParseInt(r["time"], 10, 64)
			if err != nil || ts >= from {
				out = append(out, r)
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			a, _ := strconv.ParseInt(out[i]["time"], 10, 64)
			b, _ := strconv.ParseInt(out[j]["time"], 10, 64)
			if a != b {
				return a < b
			}
			return out[i]["eid"] < out[j]["eid"]
		})
		if om := reOffset.FindStringSubmatch(sql); om != nil {
			off, _ := strconv.Atoi(om[1])
			if off > len(out) {
				off = len(out)
			}
			out = out[off:]
		}
		if lm := reLimit.FindStringSubmatch(sql); lm != nil {
			lim, _ := strconv.Atoi(lm[1])
			if lim < len(out) {
				out = out[:lim]
			}
		}
		return copyRows(out), nil
	}
}

func (f *fakeOsquery) Close() {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
}

func (f *fakeOsquery) add(table string, rows ...map[string]string) {
	f.mu.Lock()
	f.tables[table] = append(f.tables[table], rows...)
	f.mu.Unlock()
}

func (f *fakeOsquery) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func copyRows(in []map[string]string) []map[string]string {
	out := make([]map[string]string, len(in))
	for i, r := range in {
		if r == nil {
			continue
		}
		c := make(map[string]string, len(r))
		for k, v := range r {
			c[k] = v
		}
		out[i] = c
	}
	return out
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const t0 = int64(1794420000)

// newTestSource wires a Source to a fake osqueryd for the given OS.
func newTestSource(t *testing.T, goos string, f *fakeOsquery, attr func(pid, ppid int) (string, string, bool)) (*Source, *clock) {
	t.Helper()
	s := New(Options{Socket: "/fake/osquery.em", Attribute: attr})
	c := &clock{t: time.Unix(t0, 0)}
	s.now = c.now
	s.disabled = func() bool { return false }
	s.check = func(string) error { return nil }
	s.dial = func(string, time.Duration) (querier, error) { return f, nil }
	s.tables = tablesFor(goos)
	return s, c
}

// auditRow builds a Linux process_events row the way osquery 5.19 returns it.
func auditRow(eid int, ts int64, pid, ppid int, path, cmdline string) map[string]string {
	return map[string]string{
		"pid": strconv.Itoa(pid), "parent": strconv.Itoa(ppid), "path": path, "cmdline": cmdline,
		"cwd": `"/home/dev/project"`, "uid": "1000", "syscall": "execve",
		"time": strconv.FormatInt(ts, 10), "eid": fmt.Sprintf("%010d", eid),
	}
}

var errNotExist = fmt.Errorf("stat: %w", fs.ErrNotExist)

func mustUnavailable(t *testing.T, s *Source, err error, want string) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if s.Status() != StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", s.Status())
	}
	if want != "" && !strings.Contains(s.Detail(), want) {
		t.Fatalf("detail = %q, want it to mention %q", s.Detail(), want)
	}
}
