package fleetgen

import (
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/state"
)

// tbl is the osquery name of a state table.
func tbl(name string) string { return state.TablePrefix + name }

// sqlString renders an SQL string literal. Values come from the catalog,
// options and constants; quoting is still done properly so an odd path or
// a future flag spelling cannot break out of the literal.
func sqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// sqlIn renders "col IN ('a', 'b')"; an empty list renders a false
// predicate, never "IN ()" (a syntax error in some SQLite builds).
func sqlIn(col string, vals []string) string {
	if len(vals) == 0 {
		return "0"
	}
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = sqlString(v)
	}
	return col + " IN (" + strings.Join(q, ", ") + ")"
}

// listHasAny is true when the comma-separated list column holds one of vals
// as a whole element. instr is exact and case-sensitive, unlike LIKE, in
// which "_" is a wildcard. spoor list columns never contain spaces around
// commas (state joins them that way); Fleet's ai_tools is normalised with
// replace() because its format is not ours to rely on.
func listHasAny(col string, vals []string, stripSpaces bool) string {
	if len(vals) == 0 {
		return "0"
	}
	list := col
	if stripSpaces {
		list = "replace(" + col + ", ' ', '')"
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = "instr(',' || " + list + " || ',', " + sqlString(","+v+",") + ") > 0"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "\n    OR ") + ")"
}

// unionAll joins row-returning SELECTs.
func unionAll(parts ...string) string { return strings.Join(parts, "\nUNION ALL\n") }

// since is the fixed-width timestamp d before now, as stored in the tables.
func since(d time.Duration) string { return state.SQLTimeAgo(d) }

// policy wraps a violation query into a fail-closed Fleet policy query.
func policySQL(violation string, window time.Duration) string {
	return state.PolicySQLWithin(violation, window)
}

// selectCols renders "SELECT a, b FROM t" from a state table definition,
// listing columns explicitly: ATC adds a "path" column of its own, so
// SELECT * would differ between ATC and the extension.
func selectCols(table string, extra string) string {
	t, ok := state.Table(table)
	if !ok {
		panic("fleetgen: unknown state table " + table)
	}
	cols := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		cols[i] = c.Name
	}
	q := "SELECT " + strings.Join(cols, ", ") + "\nFROM " + t.OsqueryName()
	if extra != "" {
		q += "\n" + extra
	}
	return q
}
