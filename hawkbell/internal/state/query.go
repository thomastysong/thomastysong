package state

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// MaxQueryRows bounds what one Query returns. It is above every row cap, so
// it only matters for a file some other program wrote, and keeps such a file
// from exhausting the osquery worker's memory.
const MaxQueryRows = 20000

// maxCell bounds one returned value. This package never stores more than
// maxPath bytes in a cell; the bound and the cleaning matter for a file
// something else wrote, whose content goes straight into osquery's logs.
const maxCell = 2048

// MaxFilterValues is the most values one Filter may carry.
const MaxFilterValues = 256

// Filter operators.
const (
	OpEq = "="
	OpGt = ">"
	OpGe = ">="
	OpLt = "<"
	OpLe = "<="
)

// Filter narrows a query on one visible column. With OpEq a row matches when
// the column equals any of Values; the other operators take exactly one
// value. Filters on different columns, and several filters on one column,
// are ANDed.
//
// Filters exist so the osquery extension can push simple WHERE terms down.
// Comparison follows SQLite's rules for the stored type: text columns
// compare as text, numeric columns compare numerically when the value looks
// like a number.
type Filter struct {
	Column string
	Op     string
	Values []string
}

// Query returns every row of a table as strings. table is a TableDef name,
// with or without TablePrefix; cols selects visible columns (nil or empty
// means all). Numbers are rendered in decimal.
//
// On a read-only store the file may come from another version: columns it
// lacks are returned as empty strings and a table it lacks yields no rows.
func (s *Store) Query(table string, cols []string) ([]map[string]string, error) {
	return s.QueryWhere(context.Background(), table, cols, nil)
}

// QueryWhere is Query with filters and a context.
func (s *Store) QueryWhere(ctx context.Context, table string, cols []string, filters []Filter) (out []map[string]string, err error) {
	defer guard(&err)
	if s == nil || s.closed.Load() {
		return nil, ErrClosed
	}
	t, ok := Table(table)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTable, table)
	}
	if len(cols) == 0 {
		cols = t.ColumnNames()
	}
	for _, c := range cols {
		if _, ok := t.Column(c); !ok {
			return nil, fmt.Errorf("state: table %s has no column %q", t.Name, c)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 6*BusyTimeout)
	defer cancel()

	// A file written by another version may lack columns or whole tables.
	// Only a read-only store can meet one; Open migrates its own file.
	present := map[string]bool(nil)
	if s.readOnly {
		present, err = tableColumns(ctx, s.db, t.Name)
		if err != nil {
			return nil, err
		}
		if len(present) == 0 {
			return []map[string]string{}, nil
		}
	}
	has := func(col string) bool { return present == nil || present[col] }

	var sel []string
	for _, c := range cols {
		if has(c) {
			sel = append(sel, quoteIdent(c))
		} else {
			sel = append(sel, "'' AS "+quoteIdent(c))
		}
	}
	var where []string
	var args []any
	if t.visible != "" {
		if s.readOnly && !visibleColumnsPresent(t, present) {
			// Without the bookkeeping column the filter cannot run; show
			// everything rather than fail.
		} else {
			where = append(where, "("+t.visible+")")
		}
	}
	for _, f := range filters {
		col, ok := t.Column(f.Column)
		if !ok {
			return nil, fmt.Errorf("state: table %s has no column %q", t.Name, f.Column)
		}
		if len(f.Values) == 0 || len(f.Values) > MaxFilterValues {
			return nil, fmt.Errorf("state: filter on %s needs 1..%d values", f.Column, MaxFilterValues)
		}
		lhs := quoteIdent(col.Name)
		if !has(col.Name) {
			lhs = "''" // the column reads as empty, so compare the empty string
		}
		switch f.Op {
		case OpEq:
			where = append(where, lhs+" IN ("+placeholders(len(f.Values))+")")
			for _, v := range f.Values {
				args = append(args, v)
			}
		case OpGt, OpGe, OpLt, OpLe:
			if len(f.Values) != 1 {
				return nil, fmt.Errorf("state: filter %s %s takes one value", f.Column, f.Op)
			}
			where = append(where, lhs+" "+f.Op+" ?")
			args = append(args, f.Values[0])
		default:
			return nil, fmt.Errorf("state: unsupported filter operator %q", f.Op)
		}
	}

	q := "SELECT " + strings.Join(sel, ", ") + " FROM " + quoteIdent(t.Name)
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " LIMIT " + strconv.Itoa(MaxQueryRows)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("state: query %s: %w", t.Name, err)
	}
	defer rows.Close()
	out = []map[string]string{}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("state: query %s: %w", t.Name, err)
		}
		m := make(map[string]string, len(cols))
		for i, c := range cols {
			m[c] = cell(vals[i])
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: query %s: %w", t.Name, err)
	}
	return out, nil
}

// visibleColumnsPresent reports whether the columns the row filter needs
// exist in the file.
func visibleColumnsPresent(t TableDef, present map[string]bool) bool {
	for _, c := range t.internal {
		if strings.Contains(t.visible, c.Name) && !present[c.Name] {
			return false
		}
	}
	return true
}

// cell renders one SQLite value as osquery wants it: a string.
func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return clip(x, maxCell)
	case []byte:
		return clip(string(x), maxCell)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprint(x)
	}
}

// ensure the interface is satisfied by both handles tableColumns is used with.
var (
	_ queryer = (*sql.DB)(nil)
	_ queryer = (*sql.Tx)(nil)
)
