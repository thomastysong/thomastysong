package osqexec

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// probe decides which evented table to read, or that none can be.
//
// A subscriber row with active=1 is not enough: on a host where the BPF
// publisher failed to start, bpf_process_events still reported active=1 and
// never delivered a row. So the subscriber's publisher must be active too,
// and the table must hold at least one row from the recent window.
func (s *Source) probe(ctx context.Context, now time.Time) error {
	rows, err := s.query(ctx, "SELECT name, publisher, type, active FROM osquery_events")
	if err != nil {
		return err
	}
	subs := map[string]map[string]string{}
	pubActive := map[string]bool{}
	for _, r := range rows {
		switch r["type"] {
		case "subscriber":
			subs[r["name"]] = r
		case "publisher":
			pubActive[r["name"]] = r["active"] == "1"
		}
	}
	var pick *tableSpec
	why := "osquery has no evented process table for this OS"
	for i := range s.tables {
		t := &s.tables[i]
		sub, ok := subs[t.name]
		if !ok {
			continue
		}
		if sub["active"] != "1" {
			why = t.name + " is not enabled in osquery"
			continue
		}
		if active, known := pubActive[sub["publisher"]]; known && !active {
			why = t.name + " is enabled but its publisher is not running"
			continue
		}
		pick = t
		break
	}
	if pick == nil {
		s.table = nil
		return s.unavailable(why)
	}
	if err := s.checkSafe(ctx); err != nil {
		return err
	}
	if s.table == nil || s.table.name != pick.name {
		// Event ids are per table.
		s.seen = map[string]int64{}
	}
	if now.Sub(s.newest) > recentWindow {
		from := now.Add(-recentWindow).Unix()
		rows, err := s.query(ctx, fmt.Sprintf("SELECT time FROM %s WHERE time >= %d LIMIT 1", pick.name, from))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			s.table = nil
			return s.unavailable(fmt.Sprintf("%s is active but delivered no event in the last %s", pick.name, recentWindow))
		}
		if t, ok := parseInt64(rows[0]["time"]); ok && t >= from {
			s.newest = time.Unix(t, 0)
		} else {
			s.newest = now.Add(-recentWindow)
		}
	}
	s.table, s.probedAt = pick, now
	return nil
}

// checkSafe refuses to read evented tables of osquery releases older than
// 5.0 unless events are kept for at least ten minutes. Their documentation
// says buffered events are expired whenever the table is SELECTed, so an
// extra reader could make the organisation's own scheduled query lose rows
// under a short --events_expiry. On 5.19.0 a time-constrained ad hoc query
// was verified not to do that (see the package comment).
func (s *Source) checkSafe(ctx context.Context) error {
	if s.safe {
		return nil
	}
	rows, err := s.query(ctx, "SELECT version FROM osquery_info")
	if err != nil {
		return err
	}
	version := ""
	if len(rows) > 0 {
		version = rows[0]["version"]
	}
	if majorVersion(version) < 5 {
		flags, err := s.query(ctx, "SELECT name, value FROM osquery_flags WHERE name = 'events_expiry'")
		if err != nil {
			return err
		}
		expiry := int64(-1)
		if len(flags) > 0 {
			if v, ok := parseInt64(flags[0]["value"]); ok {
				expiry = v
			}
		}
		if expiry < minSafeExpiry {
			s.table = nil
			return s.unavailable(fmt.Sprintf("osquery %q with events_expiry=%d: an extra reader could expire rows before scheduled queries read them", clip(version, 32), expiry))
		}
	}
	s.safe = true
	return nil
}

func majorVersion(v string) int {
	head, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 || n > 1000 {
		return 0
	}
	return n
}

// drain reads the rows newer than the cursor and converts the attributed
// ones. Rows are fetched in pages so that a burst cannot make osqueryd build,
// or this process hold, an unbounded result.
func (s *Source) drain(ctx context.Context, now time.Time) ([]*event.Event, error) {
	t := s.table
	nowS := now.Unix()
	switch {
	case s.cursor == 0, s.cursor > nowS+5:
		// First poll, or the clock went backwards.
		s.cursor = nowS - int64(startLookback/time.Second)
		s.seen = map[string]int64{}
	case s.cursor < nowS-int64(maxLookback/time.Second):
		s.cursor = nowS - int64(maxLookback/time.Second)
		s.st.Gaps++
	}
	from := s.cursor - overlapSeconds
	var evs []*event.Event
	newest := s.cursor
	complete := false
	for page := 0; page < maxPages; page++ {
		rows, err := s.query(ctx, fmt.Sprintf(t.sql, from, pageRows, page*pageRows))
		if err != nil {
			if page == 0 {
				return nil, err
			}
			// Earlier pages are already marked seen; hand them over and let
			// the next poll report the failure if it persists.
			complete = true
			break
		}
		recs := parseRows(t, rows)
		for i := range recs {
			r := &recs[i]
			if r.time < from {
				continue
			}
			if _, dup := s.seen[r.key]; dup {
				continue
			}
			s.seen[r.key] = r.time
			s.st.Rows++
			if r.time > newest {
				newest = r.time
			}
			if ev := s.convert(t, r); ev != nil {
				evs = append(evs, ev)
				s.st.Events++
			}
		}
		if len(rows) < pageRows {
			complete = true
			break
		}
	}
	if !complete {
		// More rows than the budget: skip ahead rather than fall behind
		// forever, and say so.
		s.st.Gaps++
		newest = nowS
	}
	if newest > nowS {
		newest = nowS
	}
	if newest > s.cursor {
		s.cursor = newest
		s.newest = time.Unix(newest, 0)
	}
	floor := s.cursor - overlapSeconds
	for k, at := range s.seen {
		if at < floor {
			delete(s.seen, k)
		}
	}
	if len(s.seen) > maxSeen {
		s.seen = map[string]int64{}
		s.st.Gaps++
	}
	s.chain.prune(s.cursor)
	return evs, nil
}

func parseInt64(v string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n, err == nil
}

func clip(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
