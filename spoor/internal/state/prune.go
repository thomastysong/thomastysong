package state

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Retention bounds how long rows stay. A zero field means the default; a
// negative duration (or PostureScans) disables that rule. Row caps apply
// regardless.
type Retention struct {
	Detections    time.Duration // age by ts; default 30 days
	Sessions      time.Duration // age by last_event; default 7 days
	RemovedAssets time.Duration // how long a removed asset is remembered; default 7 days
	Processes     time.Duration // how long an exited agent process is kept; default 24 hours
	// PostureScans drops a posture failure that was not re-observed in this
	// many consecutive complete scans; default 2.
	PostureScans int
}

// DefaultRetention returns the defaults.
func DefaultRetention() Retention {
	return Retention{
		Detections:    30 * 24 * time.Hour,
		Sessions:      7 * 24 * time.Hour,
		RemovedAssets: 7 * 24 * time.Hour,
		Processes:     24 * time.Hour,
		PostureScans:  2,
	}
}

func (r Retention) withDefaults() Retention {
	d := DefaultRetention()
	if r.Detections == 0 {
		r.Detections = d.Detections
	}
	if r.Sessions == 0 {
		r.Sessions = d.Sessions
	}
	if r.RemovedAssets == 0 {
		r.RemovedAssets = d.RemovedAssets
	}
	if r.Processes == 0 {
		r.Processes = d.Processes
	}
	if r.PostureScans == 0 {
		r.PostureScans = d.PostureScans
	}
	return r
}

// Prune deletes rows past their retention as of now, re-applies every row
// cap, and then trims the write-ahead log and returns freed pages to the
// filesystem. Call it periodically (the daemon does so on its heartbeat).
func (s *Store) Prune(now time.Time, r Retention) (err error) {
	defer guard(&err)
	r = r.withDefaults()
	ctx, cancel := opContext()
	defer cancel()
	err = s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		cutoff := func(d time.Duration) string { return FormatTime(now.Add(-d)) }
		if r.Detections > 0 {
			if _, err := b.exec(`DELETE FROM detections WHERE ts < ?`, cutoff(r.Detections)); err != nil {
				return fmt.Errorf("state: prune detections: %w", err)
			}
		}
		if r.Sessions > 0 {
			if _, err := b.exec(`DELETE FROM sessions WHERE last_event < ?`, cutoff(r.Sessions)); err != nil {
				return fmt.Errorf("state: prune sessions: %w", err)
			}
		}
		if r.RemovedAssets > 0 {
			for _, table := range assetTables {
				if _, err := b.exec("DELETE FROM "+quoteIdent(table)+" WHERE removed_at != '' AND removed_at < ?",
					cutoff(r.RemovedAssets)); err != nil {
					return fmt.Errorf("state: prune %s: %w", table, err)
				}
			}
		}
		if r.Processes > 0 {
			if _, err := b.exec(`DELETE FROM agent_processes WHERE running = 0 AND last_seen < ?`,
				cutoff(r.Processes)); err != nil {
				return fmt.Errorf("state: prune agent_processes: %w", err)
			}
		}
		if r.PostureScans > 0 {
			seq, err := metaInt(ctx, tx, metaScanSeq)
			if err != nil {
				return err
			}
			// A row observed during scan N carries seen_scan = N. It goes
			// once PostureScans later scans completed without seeing it.
			if _, err := b.exec(`DELETE FROM posture WHERE seen_scan + ? <= ?`, r.PostureScans, seq); err != nil {
				return fmt.Errorf("state: prune posture: %w", err)
			}
		}
		for _, t := range Tables {
			if err := b.enforceCap(t); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.maintain()
	return nil
}

// maintain is best-effort housekeeping outside any transaction. A reader
// holding a snapshot (an osquery query in flight) makes the checkpoint
// report busy; the next call gets another chance, so errors are ignored.
func (s *Store) maintain() {
	ctx, cancel := opContext()
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range []string{
		"PRAGMA wal_checkpoint(TRUNCATE)",
		"PRAGMA incremental_vacuum",
		"PRAGMA optimize",
	} {
		rows, err := s.db.QueryContext(ctx, q)
		if err != nil {
			continue
		}
		// incremental_vacuum does its work as the statement is stepped.
		for rows.Next() {
		}
		rows.Close()
	}
}

// PurgeUser deletes every row that belongs to an OS account, matched by
// account name or by user id, across all tables, and returns how many rows
// went. It serves erasure requests: deleted content is overwritten in the
// file (secure_delete) and the write-ahead log is truncated afterwards so
// the rows do not linger there. The host-wide health row is not personal
// and is kept.
func (s *Store) PurgeUser(user string) (n int, err error) {
	defer guard(&err)
	user = strings.TrimSpace(user)
	if user == "" {
		// The empty owner marks system-scope rows; matching it would wipe
		// the machine-wide inventory.
		return 0, errors.New("state: purge needs a user name or id")
	}
	ctx, cancel := opContext()
	defer cancel()
	targets := []struct{ table, name, id string }{
		{"agents", "owner", "owner_id"},
		{"mcp_servers", "owner", "owner_id"},
		{"extensions", "owner", "owner_id"},
		{"posture", "owner", "owner_id"},
		{"detections", "user", "user_id"},
		{"sessions", "user", "user_id"},
		{"agent_processes", "user", "user_id"},
		{"coverage", "user", "user"},
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		n = 0
		for _, t := range targets {
			gone, err := b.exec(fmt.Sprintf("DELETE FROM %s WHERE %s = ?1 OR %s = ?1",
				quoteIdent(t.table), quoteIdent(t.name), quoteIdent(t.id)), user)
			if err != nil {
				return fmt.Errorf("state: purge %s: %w", t.table, err)
			}
			n += int(gone)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// Forget the cached sets so the next SetAgentProcesses / SetCoverage
	// writes again instead of assuming the purged rows are still there.
	s.mu.Lock()
	s.procSig, s.covSig, s.procAt, s.covAt = "", "", time.Time{}, time.Time{}
	s.mu.Unlock()
	s.maintain()
	return n, nil
}
