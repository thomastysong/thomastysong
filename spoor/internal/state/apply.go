package state

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Apply writes a batch of events in one transaction, by kind: inventory
// assets into agents, mcp_servers or extensions; failing posture checks into
// posture (a passing check deletes its row); detections; session summaries;
// and health records. Other kinds (activity) are ignored: activity never
// enters the state database.
//
// Events without a usable key (no asset id, no rule id, no session id) are
// skipped and counted in Stats.Rejected; they do not fail the batch. A
// database error rolls the whole batch back.
func (s *Store) Apply(events []*event.Event) (err error) {
	defer guard(&err)
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := opContext()
	defer cancel()
	now := s.now()
	return s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		seq, err := metaInt(ctx, tx, metaScanSeq)
		if err != nil {
			return fmt.Errorf("state: read scan sequence: %w", err)
		}
		touched := map[string]bool{}
		for _, e := range events {
			if e == nil {
				continue
			}
			table, ok, err := b.applyOne(e, now, seq)
			if err != nil {
				return fmt.Errorf("state: apply %s event %s: %w", e.Kind, clip(e.ID, maxID), err)
			}
			if !ok {
				s.rejected.Add(1)
				continue
			}
			if table != "" {
				touched[table] = true
			}
		}
		for _, t := range Tables {
			if touched[t.Name] {
				if err := b.enforceCap(t); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// applyOne routes one event. ok is false when the event belongs to a stored
// kind but lacks what is needed to key a row.
func (b *batch) applyOne(e *event.Event, now time.Time, scanSeq int64) (table string, ok bool, err error) {
	switch e.Kind {
	case event.KindInventory:
		if e.Asset == nil {
			return "", false, nil
		}
		return b.applyAsset(e, now)
	case event.KindPosture:
		if e.Check == nil {
			return "", false, nil
		}
		ok, err = b.applyCheck(e, now, scanSeq)
		return "posture", ok, err
	case event.KindDetection:
		if e.Detection == nil {
			return "", false, nil
		}
		ok, err = b.applyDetection(e, now)
		return "detections", ok, err
	case event.KindSummary:
		if e.Summary == nil {
			return "", false, nil
		}
		ok, err = b.applySummary(e, now)
		return "sessions", ok, err
	case event.KindHealth:
		if e.Health == nil {
			return "", false, nil
		}
		return "", true, b.applyHealth(e, now)
	default:
		return "", true, nil
	}
}

// batch carries one transaction and prepares each distinct statement once:
// a full scan applies thousands of rows with the same few statements.
type batch struct {
	ctx   context.Context
	tx    *sql.Tx
	s     *Store
	stmts map[string]*sql.Stmt
}

func newBatch(ctx context.Context, tx *sql.Tx, s *Store) *batch {
	return &batch{ctx: ctx, tx: tx, s: s, stmts: map[string]*sql.Stmt{}}
}

func (b *batch) close() {
	for _, st := range b.stmts {
		st.Close()
	}
}

func (b *batch) stmt(query string) (*sql.Stmt, error) {
	if st, ok := b.stmts[query]; ok {
		return st, nil
	}
	st, err := b.tx.PrepareContext(b.ctx, query)
	if err != nil {
		return nil, err
	}
	b.stmts[query] = st
	return st, nil
}

func (b *batch) exec(query string, args ...any) (int64, error) {
	st, err := b.stmt(query)
	if err != nil {
		return 0, err
	}
	res, err := st.ExecContext(b.ctx, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// row is a column list with values, in order.
type row struct {
	cols []string
	vals []any
}

func (r *row) set(col string, v any) {
	r.cols = append(r.cols, col)
	r.vals = append(r.vals, v)
}

// upsert inserts the row or, when its primary key exists, overwrites every
// non-key column given. The rowid is kept, unlike INSERT OR REPLACE.
func (b *batch) upsert(t TableDef, r *row) error {
	var q strings.Builder
	fmt.Fprintf(&q, "INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO ",
		quoteIdent(t.Name), quoteIdents(r.cols), placeholders(len(r.cols)), quoteIdents(t.key))
	isKey := map[string]bool{}
	for _, k := range t.key {
		isKey[k] = true
	}
	n := 0
	for _, c := range r.cols {
		if isKey[c] {
			continue
		}
		if n == 0 {
			q.WriteString("UPDATE SET ")
		} else {
			q.WriteString(", ")
		}
		fmt.Fprintf(&q, "%s = excluded.%s", quoteIdent(c), quoteIdent(c))
		n++
	}
	if n == 0 {
		q.WriteString("NOTHING")
	}
	_, err := b.exec(q.String(), r.vals...)
	return err
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

// enforceCap evicts the oldest rows beyond the table's cap, inside the
// transaction that added them, so no reader ever sees an oversized table.
func (b *batch) enforceCap(t TableDef) error {
	if t.rowCap <= 0 {
		return nil
	}
	st, err := b.stmt("SELECT count(*) FROM " + quoteIdent(t.Name))
	if err != nil {
		return err
	}
	var n int
	if err := st.QueryRowContext(b.ctx).Scan(&n); err != nil {
		return fmt.Errorf("state: count %s: %w", t.Name, err)
	}
	if n <= t.rowCap {
		return nil
	}
	name := quoteIdent(t.Name)
	gone, err := b.exec(fmt.Sprintf(
		"DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s ORDER BY %s LIMIT ?)", name, name, t.evict),
		n-t.rowCap)
	if err != nil {
		return fmt.Errorf("state: evict from %s: %w", t.Name, err)
	}
	if gone > 0 {
		v, _ := b.s.evicted.LoadOrStore(t.Name, new(atomic.Uint64))
		v.(*atomic.Uint64).Add(uint64(gone))
	}
	return nil
}

// mustTable returns a definition that is known to exist.
func mustTable(name string) TableDef {
	t, ok := Table(name)
	if !ok {
		panic("state: undefined table " + name)
	}
	return t
}
