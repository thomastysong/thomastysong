package state

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOpenCreatesPrivateWALDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data", "nested")
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Path() != path || s.ReadOnly() {
		t.Fatalf("Path=%q ReadOnly=%v", s.Path(), s.ReadOnly())
	}
	if runtime.GOOS != "windows" {
		di, _ := os.Stat(dir)
		if di.Mode().Perm() != 0o700 {
			t.Errorf("directory mode %04o, want 0700", di.Mode().Perm())
		}
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode %04o, want 0600", fi.Mode().Perm())
		}
	}
	mustApply(t, s, assetEvent(0, agentAsset("a1"), user("alice", "1000")))
	if runtime.GOOS != "windows" {
		for _, side := range []string{"-wal", "-shm"} {
			fi, err := os.Stat(path + side)
			if err != nil {
				t.Fatalf("WAL sidecar %s missing: %v", side, err)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("sidecar %s mode %04o is readable by others", side, fi.Mode().Perm())
			}
		}
	}
	var mode string
	var version, appID int
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode=%q err=%v, want wal", mode, err)
	}
	s.db.QueryRow("PRAGMA user_version").Scan(&version)
	s.db.QueryRow("PRAGMA application_id").Scan(&appID)
	if version != SchemaVersion || appID != applicationID {
		t.Fatalf("user_version=%d application_id=%#x", version, appID)
	}

	// Reopening keeps the data and the inode: the file is never replaced.
	before, _ := os.Stat(path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("database file was replaced on reopen")
	}
	if rows := mustQuery(t, s2, "agents"); len(rows) != 1 {
		t.Fatalf("rows after reopen: %d", len(rows))
	}
}

func TestFileIsNeverReplaced(t *testing.T) {
	s, c := newStore(t)
	before, _ := os.Stat(s.Path())
	mustApply(t, s, assetEvent(0, agentAsset("a1"), user("alice", "1000")))
	if err := s.MarkScan(c.now(), c.now(), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(c.now().Add(365*24*time.Hour), Retention{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PurgeUser("alice"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(s.Path())
	if !os.SameFile(before, after) {
		t.Fatal("database file identity changed; ATC would replay a stale WAL over a renamed file")
	}
}

func TestOpenRejectsBadPaths(t *testing.T) {
	for _, p := range []string{"", "   ", "a\x00b"} {
		if _, err := Open(p); err == nil {
			t.Errorf("Open(%q) succeeded", p)
		}
		if _, err := OpenReadOnly(p); err == nil {
			t.Errorf("OpenReadOnly(%q) succeeded", p)
		}
	}
	// A directory where the file should be.
	dir := t.TempDir()
	if _, err := Open(dir); err == nil {
		t.Error("Open(directory) succeeded")
	}
	// The parent is a regular file.
	f := filepath.Join(dir, "plain")
	os.WriteFile(f, []byte("x"), 0o600)
	if _, err := Open(filepath.Join(f, "state.db")); err == nil {
		t.Error("Open under a regular file succeeded")
	}
}

func TestOpenRejectsForeignDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrNotState) {
		t.Fatalf("Open(foreign db) = %v, want ErrNotState", err)
	}

	// Another application's id.
	path2 := filepath.Join(t.TempDir(), "app.db")
	db, _ = sql.Open("sqlite", path2)
	db.Exec("PRAGMA application_id = 12345")
	db.Exec("CREATE TABLE t (x)")
	db.Close()
	if _, err := Open(path2); !errors.Is(err, ErrNotState) {
		t.Fatalf("Open(other application_id) = %v, want ErrNotState", err)
	}

	// Garbage that is not SQLite at all.
	path3 := filepath.Join(t.TempDir(), "junk.db")
	os.WriteFile(path3, []byte(strings.Repeat("not a database ", 500)), 0o600)
	if _, err := Open(path3); err == nil {
		t.Fatal("Open(garbage) succeeded")
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	s, _ := newStore(t)
	path := s.Path()
	s.Close()
	db := rawDB(t, path)
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open = %v, want ErrSchemaTooNew", err)
	}
	// The read-only side must keep working across versions.
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly on newer schema: %v", err)
	}
	defer ro.Close()
	if _, err := ro.Query("health", nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAddsColumnsMissingFromOlderFile(t *testing.T) {
	s, _ := newStore(t)
	path := s.Path()
	mustApply(t, s, assetEvent(0, agentAsset("a1"), user("alice", "1000")))
	s.Close()
	db := rawDB(t, path)
	for _, stmt := range []string{
		"ALTER TABLE agents DROP COLUMN native_otel",
		"ALTER TABLE agent_processes DROP COLUMN running",
		"DROP TABLE coverage",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	// Simulate "one version behind" so the table-creating migration reruns.
	db.Exec("PRAGMA user_version = 0")
	db.Close()

	// The read-only view tolerates the old shape.
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ro.Query("agents", nil)
	if err != nil {
		t.Fatalf("Query on older file: %v", err)
	}
	if len(rows) != 1 || rows[0]["native_otel"] != "" || rows[0]["name"] != "Claude Code" {
		t.Fatalf("older file rows: %v", rows)
	}
	if _, ok := rows[0]["native_otel"]; !ok {
		t.Fatal("missing column must still be present as an empty string")
	}
	if rows, err := ro.Query("coverage", nil); err != nil || len(rows) != 0 {
		t.Fatalf("missing table: rows=%v err=%v, want none", rows, err)
	}
	// Filtering on the missing column behaves as if it were empty.
	got, err := ro.QueryWhere(t.Context(), "agents", nil, []Filter{{Column: "native_otel", Op: OpEq, Values: []string{""}}})
	if err != nil || len(got) != 1 {
		t.Fatalf("filter on missing column: %v %v", got, err)
	}
	ro.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen older file: %v", err)
	}
	defer s2.Close()
	have, err := tableColumns(t.Context(), s2.db, "agents")
	if err != nil || !have["native_otel"] {
		t.Fatalf("native_otel not restored: %v %v", have, err)
	}
	if rows := mustQuery(t, s2, "agents"); len(rows) != 1 || rows[0]["name"] != "Claude Code" {
		t.Fatalf("data lost in migration: %v", rows)
	}
	if err := s2.SetAgentProcesses([]AgentProcess{{PID: 7, AgentID: "codex"}}); err != nil {
		t.Fatal(err)
	}
	if err := s2.SetCoverage(nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenReadOnly(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.db")
	if _, err := OpenReadOnly(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenReadOnly(missing) = %v, want os.ErrNotExist", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("OpenReadOnly created the file")
	}
	if _, err := OpenReadOnly(dir); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenReadOnly(directory) = %v, want ErrUnsafePath", err)
	}

	s, c := newStore(t)
	mustApply(t, s, assetEvent(0, agentAsset("a1"), user("alice", "1000")))
	ro, err := OpenReadOnly(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if !ro.ReadOnly() {
		t.Fatal("ReadOnly() = false")
	}
	if rows := mustQuery(t, ro, "agents"); len(rows) != 1 {
		t.Fatalf("reader sees %d rows", len(rows))
	}
	// The reader follows the writer's later commits.
	mustApply(t, s, assetEvent(time.Second, agentAsset("a2"), user("alice", "1000")))
	if rows := mustQuery(t, ro, "agents"); len(rows) != 2 {
		t.Fatalf("reader sees %d rows after second commit", len(rows))
	}

	// Every mutation is refused.
	for name, err := range map[string]error{
		"Apply":             ro.Apply([]*testEvent{assetEvent(0, agentAsset("x"), nil)}),
		"SetAgentProcesses": ro.SetAgentProcesses([]AgentProcess{{PID: 1}}),
		"SetCoverage":       ro.SetCoverage(nil),
		"MarkScan":          ro.MarkScan(c.now(), c.now(), nil),
		"Prune":             ro.Prune(c.now(), Retention{}),
		"SetHealth":         ro.SetHealth(Health{}),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s on read-only store = %v, want ErrReadOnly", name, err)
		}
	}
	if _, err := ro.PurgeUser("alice"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("PurgeUser on read-only store = %v", err)
	}
	// And even raw SQL through the handle cannot write.
	if _, err := ro.db.Exec("DELETE FROM agents"); err == nil {
		t.Fatal("read-only handle accepted a DELETE")
	}
	if snap, err := ro.Snapshot(); err != nil || len(snap) != 2 {
		t.Fatalf("Snapshot via reader: %v %v", snap, err)
	}
	if _, err := ro.Removed(); err != nil {
		t.Fatal(err)
	}
	if st, err := ro.Stats(); err != nil || st.Rows["agents"] != 2 {
		t.Fatalf("Stats via reader: %+v %v", st, err)
	}
}

func TestReadOnlyOnEmptyOrUninitialisedFile(t *testing.T) {
	// The writer has created the file but not yet the schema.
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly(empty file): %v", err)
	}
	defer ro.Close()
	for _, td := range Tables {
		rows, err := ro.Query(td.Name, nil)
		if err != nil || len(rows) != 0 {
			t.Fatalf("%s on empty file: rows=%v err=%v", td.Name, rows, err)
		}
	}
	if snap, err := ro.Snapshot(); err != nil || len(snap) != 0 {
		t.Fatalf("Snapshot on empty file: %v %v", snap, err)
	}
	if ev, err := ro.Removed(); err != nil || len(ev) != 0 {
		t.Fatalf("Removed on empty file: %v %v", ev, err)
	}
}

func TestUseAfterClose(t *testing.T) {
	s, c := newStore(t)
	s.Close()
	if err := s.Apply([]*testEvent{assetEvent(0, agentAsset("a"), nil)}); !errors.Is(err, ErrClosed) {
		t.Errorf("Apply after Close = %v", err)
	}
	if _, err := s.Query("agents", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Query after Close = %v", err)
	}
	if err := s.MarkScan(c.now(), c.now(), nil); !errors.Is(err, ErrClosed) {
		t.Errorf("MarkScan after Close = %v", err)
	}
	if _, err := s.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Errorf("Snapshot after Close = %v", err)
	}
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
	if _, err := nilStore.Query("agents", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("nil Query = %v", err)
	}
}

func TestDSNEscapesPath(t *testing.T) {
	// A directory name with every character that is special in a URI.
	dir := filepath.Join(t.TempDir(), "odd dir?x=1#frag&y %41")
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustApply(t, s, assetEvent(0, agentAsset("a1"), nil))
	s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not at the requested path: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 {
		t.Fatalf("unexpected siblings created: %v", entries)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if rows := mustQuery(t, ro, "agents"); len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if !strings.Contains(dsn(path, true), "mode=ro") || strings.Contains(dsn(path, false), "mode=ro") {
		t.Fatal("mode=ro must be present only in the read-only DSN")
	}
}
