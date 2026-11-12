package fleetgen

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

// The emulator evaluates generated SQL the way osquery would, without
// osquery: the hawkbell_* names become TEMP views over a real state database
// (or empty tables when the database is missing, which is what both ATC and
// the extension return), and the osquery tables the content touches become
// TEMP tables the test fills. Two flavours:
//
//   - atc: every column is TEXT and an extra "path" column exists, exactly
//     like osquery's auto table construction;
//   - typed: numbers keep their type, no path column, like the extension.
//
// The live verification (deploy/fleet/verify.sh) checks the same content
// against a real osquery through Fleet; this keeps the semantics under unit
// test on every OS.

type flavour int

const (
	atcFlavour flavour = iota
	typedFlavour
)

func (f flavour) String() string {
	if f == atcFlavour {
		return "atc"
	}
	return "typed"
}

// osqueryStubs are the osquery tables the generated content reads, with
// the columns it uses (osquery 5.19 schema, fleetdm/fleet
// schema/osquery_fleet_schema.json and schema/tables/ai_tools.yml).
var osqueryStubs = map[string][]string{
	"osquery_info":       {"build_platform"},
	"file":               {"path"},
	"osquery_registry":   {"registry", "name", "owner_uuid", "internal", "active"},
	"ai_tools":           {"type", "name", "identifier", "category", "location", "source", "version", "path", "endpoint", "running", "pid", "port", "risk_flags", "sha256", "confidence", "evidence", "uid", "username", "detail"},
	"process_events":     {"pid", "parent", "path", "cmdline", "cwd", "uid", "time"},
	"es_process_events":  {"pid", "parent", "path", "cmdline", "cwd", "uid", "time", "event_type"},
	"process_etw_events": {"pid", "ppid", "path", "cmdline", "username", "time", "type"},
	"processes":          {"pid", "parent", "start_time"},
	"os_version":         {"platform", "platform_like", "name"},
}

type emu struct {
	t  *testing.T
	db *sql.DB
}

// newEmu opens dbPath read-only (dbPath "" means the database is missing)
// and builds the osquery-shaped schema. Every hawkbell table is registered in
// osquery_registry and build_platform is linux unless the test changes it.
func newEmu(t *testing.T, dbPath string, fl flavour) *emu {
	t.Helper()
	dsn := "file::memory:"
	if dbPath != "" {
		abs, err := filepath.Abs(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
		dsn = u.String() + "?mode=ro"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // TEMP objects live on one connection
	t.Cleanup(func() { db.Close() })
	e := &emu{t: t, db: db}
	for _, td := range state.Tables {
		var cols []string
		for _, c := range td.Columns {
			if fl == atcFlavour {
				cols = append(cols, "CAST("+c.Name+" AS TEXT) AS "+c.Name)
			} else {
				cols = append(cols, c.Name)
			}
		}
		if fl == atcFlavour {
			cols = append(cols, sqlString(dbPath)+" AS path")
		}
		if dbPath != "" {
			e.exec("CREATE TEMP VIEW " + td.OsqueryName() + " AS SELECT " + strings.Join(cols, ", ") +
				" FROM (" + state.ATCQuery(td) + ")")
			continue
		}
		var defs []string
		for _, c := range td.Columns {
			typ := "TEXT"
			if fl == typedFlavour && c.Numeric() {
				typ = "INTEGER"
			}
			defs = append(defs, c.Name+" "+typ)
		}
		if fl == atcFlavour {
			defs = append(defs, "path TEXT")
		}
		e.exec("CREATE TEMP TABLE " + td.OsqueryName() + " (" + strings.Join(defs, ", ") + ")")
	}
	for name, cols := range osqueryStubs {
		e.exec("CREATE TEMP TABLE " + name + " (" + strings.Join(cols, ", ") + ")")
	}
	e.exec("INSERT INTO osquery_info (build_platform) VALUES ('linux')")
	for _, td := range state.Tables {
		e.exec("INSERT INTO osquery_registry VALUES ('table', ?, 0, 1, 1)", td.OsqueryName())
	}
	return e
}

func (e *emu) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		e.t.Fatalf("emulator: %v\n%s", err, q)
	}
}

// rows runs q and returns its rows as strings.
func (e *emu) rows(q string) []map[string]string {
	e.t.Helper()
	rs, err := e.db.Query(q)
	if err != nil {
		e.t.Fatalf("query failed: %v\n%s", err, q)
	}
	defer rs.Close()
	cols, err := rs.Columns()
	if err != nil {
		e.t.Fatal(err)
	}
	var out []map[string]string
	for rs.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			e.t.Fatal(err)
		}
		m := map[string]string{}
		for i, c := range cols {
			m[c] = vals[i].String
		}
		out = append(out, m)
	}
	if err := rs.Err(); err != nil {
		e.t.Fatalf("query failed: %v\n%s", err, q)
	}
	return out
}

// passes is how Fleet reads a policy or label result: any row means yes.
func (e *emu) passes(q string) bool {
	e.t.Helper()
	return len(e.rows(q)) > 0
}
