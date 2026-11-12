package osqext

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"

	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

// plugins builds one table plugin per state table.
func plugins(src *source) []osquery.OsqueryPlugin {
	out := make([]osquery.OsqueryPlugin, 0, len(state.Tables))
	for _, def := range state.Tables {
		out = append(out, table.NewPlugin(def.OsqueryName(), columns(def), generator(src, def),
			table.WithDescription(def.Description)))
	}
	return out
}

// columns maps the shared definition to osquery column types. Key columns
// are declared indexed: osquery then prices a query that constrains them
// lower, which makes joins look rows up by key instead of re-reading the
// table for every outer row.
func columns(def state.TableDef) []table.ColumnDefinition {
	out := make([]table.ColumnDefinition, 0, len(def.Columns))
	for _, c := range def.Columns {
		opts := []table.ColumnOpt{table.ColumnDescription(c.Description)}
		if c.Key {
			opts = append(opts, table.IndexColumn())
		}
		typ := table.ColumnTypeText
		switch c.Type {
		case state.TypeInteger:
			typ = table.ColumnTypeInteger
		case state.TypeBigInt:
			typ = table.ColumnTypeBigInt
		}
		out = append(out, table.NewColumn(c.Name, typ, opts...))
	}
	return out
}

// generator returns the function osquery calls for each query on a table.
func generator(src *source, def state.TableDef) table.GenerateFunc {
	return func(ctx context.Context, qc table.QueryContext) (rows []map[string]string, err error) {
		defer func() {
			// osquery-go does not recover: a panic here would kill the
			// extension and take every other table with it.
			if r := recover(); r != nil {
				rows, err = nil, fmt.Errorf("%s: internal error: %v", def.OsqueryName(), r)
			}
		}()
		f := filters(def, qc)
		// One retry on a fresh handle: the cached one may have been closed
		// by a concurrent reopen, or belong to a file that was replaced
		// between the identity check and the query.
		for attempt := 0; ; attempt++ {
			h, err := src.acquire()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", def.OsqueryName(), err)
			}
			if h == nil {
				// No database: the sensor is not installed or has not
				// started. Zero rows, as ATC would give; policies carry the
				// heartbeat guard for exactly this case.
				return []map[string]string{}, nil
			}
			rows, err = h.st.QueryWhere(ctx, def.Name, nil, f)
			src.release(h)
			if err == nil {
				return rows, nil
			}
			src.drop(h)
			if attempt > 0 || ctx.Err() != nil {
				return nil, fmt.Errorf("%s: %w", def.OsqueryName(), err)
			}
		}
	}
}

// filters turns the constraints osquery passes into store filters.
//
// osquery filters the returned rows again itself, so what matters is never
// returning fewer rows than it would keep. Only two shapes are pushed, both
// of which SQLite evaluates here exactly as osquery does afterwards:
//
//   - equality (and IN lists) on any column; for numeric columns only when
//     the value is a plain integer, so no type coercion rule can differ;
//   - <, <=, >, >= on text columns, which is how the fixed-width timestamps
//     are range-queried.
//
// Constraints passed in one call are a conjunction, so they are ANDed.
// Everything else (LIKE, GLOB, numeric ranges) is left to osquery. As with
// every osquery table that uses constraints, equality is byte-exact:
// a COLLATE NOCASE comparison must be written with LIKE or lower().
func filters(def state.TableDef, qc table.QueryContext) []state.Filter {
	var out []state.Filter
	for _, col := range def.Columns { // definition order keeps the SQL stable
		list, ok := qc.Constraints[col.Name]
		if !ok {
			continue
		}
		var equals []string
		pushEquals := true
		for _, c := range list.Constraints {
			switch c.Operator {
			case table.OperatorEquals:
				if col.Numeric() && !plainInteger(c.Expression) {
					pushEquals = false
				}
				equals = append(equals, c.Expression)
			case table.OperatorGreaterThan, table.OperatorGreaterThanOrEquals,
				table.OperatorLessThan, table.OperatorLessThanOrEquals:
				if col.Numeric() {
					continue
				}
				out = append(out, state.Filter{Column: col.Name, Op: rangeOp(c.Operator), Values: []string{c.Expression}})
			}
		}
		if len(equals) > 0 && pushEquals && len(equals) <= state.MaxFilterValues {
			out = append(out, state.Filter{Column: col.Name, Op: state.OpEq, Values: equals})
		}
	}
	return out
}

func rangeOp(op table.Operator) string {
	switch op {
	case table.OperatorGreaterThan:
		return state.OpGt
	case table.OperatorGreaterThanOrEquals:
		return state.OpGe
	case table.OperatorLessThan:
		return state.OpLt
	default:
		return state.OpLe
	}
}

// plainInteger accepts only what every SQLite build reads as the same
// integer: optional minus, 1 to 18 digits, no spaces, signs or exponents.
func plainInteger(s string) bool {
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	if len(s) == 0 || len(s) > 18 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// source hands out a read-only handle on the state database and replaces it
// when the file at the path is no longer the file that was opened (sensor
// reinstalled, database deleted and recreated).
//
// Handles are reference-counted: osquery calls generators concurrently, and
// closing a handle while another query still runs on it would fail that
// query. A replaced handle is retired and closed only when its last query
// releases it.
type source struct {
	path string

	mu  sync.Mutex
	cur *handle
	fi  os.FileInfo
}

type handle struct {
	st      *state.Store
	refs    int
	retired bool
}

func newSource(path string) *source { return &source{path: path} }

// acquire returns the current handle with a reference held, or nil with no
// error when there is no database file. Callers must release it.
func (s *source) acquire() (*handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Lstat(s.path)
	if err != nil {
		s.retireLocked()
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if s.cur != nil && os.SameFile(s.fi, fi) {
		s.cur.refs++
		return s.cur, nil
	}
	s.retireLocked()
	st, err := state.OpenReadOnly(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // removed between the stat and the open
		}
		return nil, err
	}
	s.cur, s.fi = &handle{st: st, refs: 1}, fi
	return s.cur, nil
}

// release drops a reference taken by acquire.
func (s *source) release(h *handle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h.refs--
	if h.retired && h.refs <= 0 {
		_ = h.st.Close()
	}
}

// drop retires h if it is still the current handle (a query on it failed).
func (s *source) drop(h *handle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == h {
		s.retireLocked()
	}
}

// close retires the current handle; it is closed once no query uses it.
func (s *source) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retireLocked()
}

func (s *source) retireLocked() {
	if s.cur == nil {
		return
	}
	s.cur.retired = true
	if s.cur.refs <= 0 {
		_ = s.cur.st.Close()
	}
	s.cur, s.fi = nil, nil
}
