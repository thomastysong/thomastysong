package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver (no CGO)
)

// SchemaVersion is stored in PRAGMA user_version. It changes only for
// migrations that are not plain column additions; added columns are created
// on open without a version bump.
const SchemaVersion = 1

// applicationID marks the file as spoor's ("SPOR"), so Open never adopts
// some other SQLite database that happens to sit at the configured path.
const applicationID = 0x53504F52

// BusyTimeout is how long a statement waits for a competing lock. Readers
// (osquery) never block a WAL writer; this covers a second spoor process,
// such as a one-shot scan while the daemon runs.
const BusyTimeout = 5 * time.Second

// maxWALBytes bounds the -wal sidecar after a checkpoint.
const maxWALBytes = 8 << 20

var (
	// ErrReadOnly is returned by every mutating method of a read-only store.
	ErrReadOnly = errors.New("state: database is open read-only")
	// ErrUnsafePath means the database location could be written or replaced
	// by another user, or is not a regular file.
	ErrUnsafePath = errors.New("state: unsafe database location")
	// ErrNotState means the file is a SQLite database that spoor did not create.
	ErrNotState = errors.New("state: file is not a spoor state database")
	// ErrSchemaTooNew means a newer spoor wrote the file.
	ErrSchemaTooNew = errors.New("state: database schema is newer than this binary")
	// ErrNoWAL means write-ahead logging could not be enabled.
	ErrNoWAL = errors.New("state: write-ahead logging unavailable (unsupported filesystem?)")
	// ErrUnknownTable is returned by Query for a name that is not in Tables.
	ErrUnknownTable = errors.New("state: unknown table")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("state: store is closed")
)

// Store is the open state database. It is safe for concurrent use; writers
// are serialised.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
	closed   atomic.Bool

	// mu serialises write transactions. SQLite allows one writer anyway;
	// queueing here instead of in busy_timeout keeps lock errors out of the
	// normal path.
	mu  sync.Mutex
	now func() time.Time

	// Signatures of the last agent-process and coverage sets written, so a
	// caller that pushes the same set every tick does not turn each tick
	// into a write transaction (WAL growth, flash wear).
	procSig, covSig string
	procAt, covAt   time.Time

	rejected atomic.Uint64
	evicted  sync.Map // table name -> *atomic.Uint64
}

// Open opens the state database for writing, creating it when missing: the
// directory with mode 0700 and the file with mode 0600. When running
// privileged on a POSIX system it refuses a location another user could
// write (ErrUnsafePath). The schema is created or migrated by PRAGMA
// user_version.
func Open(path string) (s *Store, err error) {
	defer guard(&err)
	abs, err := absPath(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create directory: %w", err)
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	if err := prepareFile(abs); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(abs, false))
	if err != nil {
		return nil, fmt.Errorf("state: open: %w", err)
	}
	// One connection: a single writer by construction, and reads made through
	// this handle see a consistent order with its writes.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s = &Store{db: db, path: abs, now: time.Now}
	if err := s.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing state database with SQLite mode=ro. It never
// creates the file or changes its schema; it is what the osquery extension
// uses. A database written by a different version is accepted: Query returns
// empty strings for columns the file lacks and no rows for tables it lacks.
// A privileged caller on a POSIX system is held to the same location rules
// as Open (ErrUnsafePath), because what it reads decides Fleet policies.
func OpenReadOnly(path string) (s *Store, err error) {
	defer guard(&err)
	abs, err := absPath(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, abs)
	}
	if err := checkDir(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	if err := checkExisting(abs, fi); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(abs, true))
	if err != nil {
		return nil, fmt.Errorf("state: open: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	s = &Store{db: db, path: abs, readOnly: true, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 2*BusyTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: open read-only: %w", err)
	}
	return s, nil
}

// Path returns the absolute path of the database file.
func (s *Store) Path() string { return s.path }

// ReadOnly reports whether the store was opened with OpenReadOnly.
func (s *Store) ReadOnly() bool { return s.readOnly }

// Close checkpoints the write-ahead log and closes the database.
func (s *Store) Close() (err error) {
	defer guard(&err)
	if s == nil || s.closed.Swap(true) {
		return nil
	}
	if !s.readOnly {
		s.mu.Lock()
		// Best effort: a reader holding a snapshot makes TRUNCATE report
		// busy, which is not a reason to fail the close.
		_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		s.mu.Unlock()
	}
	return s.db.Close()
}

func absPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("state: empty database path")
	}
	if strings.ContainsRune(path, 0) {
		return "", errors.New("state: database path contains NUL")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	return abs, nil
}

// dsn builds the driver name. The path travels as a file: URI so that SQLite
// applies mode=ro itself (a plain file name would silently drop it and open
// read-write), with every special character percent-encoded by net/url.
func dsn(abs string, readOnly bool) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows: C:/x -> /C:/x, the form SQLite's URI parser expects
	}
	u := url.URL{Scheme: "file", Path: p}
	q := []string{fmt.Sprintf("_busy_timeout=%d", BusyTimeout.Milliseconds())}
	if readOnly {
		// query_only is belt and braces: mode=ro already makes writes fail.
		q = append([]string{"mode=ro"}, q...)
		q = append(q, "_query_only=1", "_pragma=temp_store(MEMORY)")
	} else {
		q = append(q,
			// BEGIN IMMEDIATE: take the write lock up front instead of
			// failing on upgrade when another process holds a read lock.
			"_txlock=immediate",
			// Must precede the first write to the file to take effect.
			"_auto_vacuum=INCREMENTAL",
			"_journal_mode=WAL",
			"_synchronous=NORMAL",
			// Erasure requests (PurgeUser) must not leave the deleted rows
			// readable in free pages.
			"_pragma=secure_delete(ON)",
			fmt.Sprintf("_pragma=journal_size_limit(%d)", maxWALBytes),
			"_pragma=temp_store(MEMORY)",
		)
	}
	return u.String() + "?" + strings.Join(q, "&")
}

// initialize verifies the journal mode and brings the schema up to date.
func (s *Store) initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*BusyTimeout)
	defer cancel()
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("state: open: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("%w: journal mode is %q", ErrNoWAL, mode)
	}
	var appID, version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if appID != 0 && appID != applicationID {
		return fmt.Errorf("%w: application_id %#x", ErrNotState, appID)
	}
	if appID == 0 {
		var n int
		if err := s.db.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&n); err != nil {
			return fmt.Errorf("state: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("%w: it already holds %d foreign tables", ErrNotState, n)
		}
	}
	if version > SchemaVersion {
		return fmt.Errorf("%w: file is version %d, this binary writes version %d", ErrSchemaTooNew, version, SchemaVersion)
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		for v := version; v < SchemaVersion; v++ {
			if err := migrations[v](ctx, tx); err != nil {
				return fmt.Errorf("state: migrate from version %d: %w", v, err)
			}
		}
		if err := addMissingColumns(ctx, tx); err != nil {
			return err
		}
		// PRAGMA values cannot be bound; both are compile-time integers.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", applicationID)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion))
		return err
	})
}

// migrations[v] upgrades a database at user_version v to v+1.
var migrations = []func(context.Context, *sql.Tx) error{
	migrateV0toV1,
}

func migrateV0toV1(ctx context.Context, tx *sql.Tx) error {
	for _, t := range Tables {
		if _, err := tx.ExecContext(ctx, t.ddl()); err != nil {
			return fmt.Errorf("create %s: %w", t.Name, err)
		}
		for _, idx := range t.indexes {
			if _, err := tx.ExecContext(ctx, idx); err != nil {
				return fmt.Errorf("index on %s: %w", t.Name, err)
			}
		}
	}
	_, err := tx.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '') WITHOUT ROWID`)
	return err
}

// addMissingColumns adds columns that a newer binary defines and an older
// file lacks. Adding a defaulted column is always safe in SQLite, so plain
// schema growth needs no migration step and no version bump.
func addMissingColumns(ctx context.Context, tx *sql.Tx) error {
	for _, t := range Tables {
		have, err := tableColumns(ctx, tx, t.Name)
		if err != nil {
			return err
		}
		for _, c := range t.allColumns() {
			if have[c.Name] {
				continue
			}
			stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", quoteIdent(t.Name), columnDDL(c))
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("state: add column %s.%s: %w", t.Name, c.Name, err)
			}
		}
	}
	return nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// tableColumns returns the column names a table really has in the file
// (empty when the table does not exist).
func tableColumns(ctx context.Context, q queryer, table string) (map[string]bool, error) {
	// table_info takes no bound parameter; the name comes from Tables.
	rows, err := q.QueryContext(ctx, "SELECT name FROM pragma_table_info("+quoteLiteral(table)+")")
	if err != nil {
		return nil, fmt.Errorf("state: table info %s: %w", table, err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// write runs fn in one immediate transaction.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if s.readOnly {
		return ErrReadOnly
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: commit: %w", err)
	}
	return nil
}

// opContext bounds one store operation. Lock waits are already limited by
// busy_timeout; this stops a pathological statement from hanging the caller.
func opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 12*BusyTimeout)
}

// guard turns a panic into an error at the package boundary: the sensor must
// survive whatever a hostile event or a damaged file throws at it.
func guard(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("state: internal error: %v", r)
	}
}

// metaInt reads an integer from the meta table (0 when absent).
func metaInt(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, k string) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, "SELECT CAST(v AS INTEGER) FROM meta WHERE k = ?", k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func setMetaInt(ctx context.Context, tx *sql.Tx, k string, v int64) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, fmt.Sprint(v))
	return err
}

const metaScanSeq = "scan_seq"

// Stats is a point-in-time summary for health reporting and tests.
type Stats struct {
	Rows     map[string]int    // rows per table, internal ones included
	Evicted  map[string]uint64 // rows dropped by a row cap since Open
	Rejected uint64            // events Apply skipped for lack of a usable key since Open
}

// Stats counts rows and reports evictions and rejected events.
func (s *Store) Stats() (st Stats, err error) {
	defer guard(&err)
	if s.closed.Load() {
		return st, ErrClosed
	}
	ctx, cancel := opContext()
	defer cancel()
	st.Rows = make(map[string]int, len(Tables))
	st.Evicted = make(map[string]uint64, len(Tables))
	for _, t := range Tables {
		var n int
		err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+quoteIdent(t.Name)).Scan(&n)
		if err != nil {
			if s.readOnly && isNoSuchTable(err) {
				continue
			}
			return st, fmt.Errorf("state: count %s: %w", t.Name, err)
		}
		st.Rows[t.Name] = n
		if v, ok := s.evicted.Load(t.Name); ok {
			st.Evicted[t.Name] = v.(*atomic.Uint64).Load()
		}
	}
	st.Rejected = s.rejected.Load()
	return st, nil
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
