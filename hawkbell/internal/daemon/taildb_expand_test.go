package daemon

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
)

// ExpandTailDB is what both the pruner and `hawkbell doctor` read
// output.fluent_bit.tail_db through.
func TestExpandTailDB(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"hawkbell-findings.db", "hawkbell-activity.db"} {
		makeTailDB(t, filepath.Join(dir, n), nil).Close()
	}
	glob := filepath.Join(dir, "hawkbell-*.db")
	missing := filepath.Join(dir, "missing.db")
	nomatch := filepath.Join(dir, "nope-*.db")
	bad := filepath.Join(dir, "[")
	spec := " " + glob + " , " + missing + ",," + nomatch + "," + bad + "," + filepath.Join(dir, "hawkbell-findings.db")
	dbs, skipped := ExpandTailDB(spec)
	if skipped != 0 {
		t.Errorf("skipped %d", skipped)
	}
	want := []TailDB{
		{Path: filepath.Join(dir, "hawkbell-activity.db"), Pattern: glob},
		{Path: filepath.Join(dir, "hawkbell-findings.db"), Pattern: glob},
		{Path: missing},
		{Path: nomatch, Pattern: nomatch, NoMatch: true},
		{Path: bad, Pattern: bad, NoMatch: true, BadPattern: true},
	}
	if fmt.Sprint(dbs) != fmt.Sprint(want) {
		t.Fatalf("expanded\n got %+v\nwant %+v", dbs, want)
	}
	// The consumers are the same list.
	cons := tailDBConsumers(spec, "")
	if len(cons) != len(want) {
		t.Fatalf("%d consumers for %d databases", len(cons), len(want))
	}
	for i, c := range cons {
		if c.id() != "fluent-bit:"+want[i].Path {
			t.Errorf("consumer %d is %s, want %s", i, c.id(), want[i].Path)
		}
	}
	if dbs, _ := ExpandTailDB(" , "); len(dbs) != 0 {
		t.Errorf("blank spec expanded to %+v", dbs)
	}
}

func TestExpandTailDBCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxTailDBs+4; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("db-%02d.db", i)), nil, 0o600)
	}
	dbs, skipped := ExpandTailDB(filepath.Join(dir, "*.db"))
	if len(dbs) != maxTailDBs || skipped != 4 {
		t.Fatalf("%d databases, %d skipped", len(dbs), skipped)
	}
	if got := tailDBConsumers(filepath.Join(dir, "*.db"), ""); len(got) != maxTailDBs {
		t.Fatalf("%d consumers", len(got))
	}
}

func TestCheckTailDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hawkbell-findings.db")
	makeTailDB(t, path, []tailRow{
		{name: "/outbox/detection-20261112-10-0001.ndjson", offset: 10, inode: 7},
		{name: "/outbox/detection-20261112-10-0001.ndjson", offset: 0, inode: 8}, // an older inode, same name
		{name: "/outbox/health-20261112-10-0001.ndjson", offset: 5, inode: 9},
		{name: "/var/log/other.log", offset: 1, inode: 10}, // not a segment
	}).Close()
	n, inPlace, err := CheckTailDB(path, "")
	if err != nil || n != 3 || inPlace != nil {
		t.Fatalf("CheckTailDB = %d, %v, %v", n, inPlace, err)
	}
	if _, _, err := CheckTailDB(filepath.Join(dir, "missing.db"), ""); err == nil {
		t.Error("a missing database checked")
	}
	junk := filepath.Join(dir, "junk.db")
	os.WriteFile(junk, []byte("not sqlite"), 0o600)
	if _, _, err := CheckTailDB(junk, ""); err == nil {
		t.Error("junk checked as a tail database")
	}
	// Junk stays unreadable through a copy, and the copy is removed.
	copyDir := filepath.Join(t.TempDir(), "copy")
	if _, inPlace, err := CheckTailDB(junk, copyDir); err == nil || inPlace == nil {
		t.Errorf("junk through a copy: %v, %v", inPlace, err)
	}
	if ents, _ := os.ReadDir(copyDir); len(ents) != 0 {
		t.Errorf("the copy left %d entries behind", len(ents))
	}
	// No copy directory: a failed read leaves nothing behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("CheckTailDB created %s", e.Name())
		}
	}
}

// lockTailDB holds a tail database the way Fluent Bit 5.2.0 does with
// db.locking true (journal_mode WAL, locking_mode EXCLUSIVE; see
// deploy/fluent-bit/VERIFIED.md, "Fixes added 2026-11-12"): after the
// writer's first write no other connection can read the file in place.
func lockTailDB(t *testing.T, path string, rows []tailRow) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteURI(path, "_pragma=journal_mode(WAL)&_pragma=locking_mode(EXCLUSIVE)"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(fluentBitSchema); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO in_tail_files (name, offset, inode, created) VALUES (?, ?, ?, 1794462503)`, r.name, r.offset, int64(r.inode)); err != nil {
			t.Fatal(err)
		}
	}
}

// A database the pruner reads through its copy fallback is readable for
// CheckTailDB too, given a copy directory; without one it is not (the
// check doctor did before, which warned about a database the pruner reads).
func TestCheckTailDBLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hawkbell-findings.db")
	lockTailDB(t, path, []tailRow{
		{name: "/outbox/detection-20261112-10-0001.ndjson", offset: 10, inode: 7},
		{name: "/outbox/health-20261112-10-0001.ndjson", offset: 5, inode: 9},
	})
	if _, err := os.Lstat(path + "-wal"); err != nil {
		t.Fatalf("no WAL beside the locked database: %v", err)
	}
	if _, inPlace, err := CheckTailDB(path, ""); err == nil || inPlace == nil {
		t.Fatalf("a locked database read in place: %v, %v", inPlace, err)
	}
	copyDir := filepath.Join(t.TempDir(), "taildb-copy")
	n, inPlace, err := CheckTailDB(path, copyDir)
	if err != nil || n != 2 || inPlace == nil {
		t.Fatalf("through a copy: %d, %v, %v", n, inPlace, err)
	}
	t.Logf("in place: %v; through a copy: %d segment rows", inPlace, n)
	// The pruner's consumer reads the same rows the same way.
	v, err := (&tailDBConsumer{path: path, copyDir: copyDir}).view()
	if err != nil || len(v.files) != 2 || v.files["detection-20261112-10-0001.ndjson"].off != 10 {
		t.Fatalf("pruner view: %+v, %v", v, err)
	}
	if ents, _ := os.ReadDir(copyDir); len(ents) != 0 {
		t.Errorf("the copy left %d entries behind", len(ents))
	}
}

// The status read (daemon.Status, which `hawkbell doctor` calls) has no
// checkpoint directory of its own. It used to copy a locked database into
// "taildb-copy" relative to the caller's working directory, which a root
// doctor run in a directory another account can write would follow. It
// now reads through a private temporary directory it removes, and a
// consumer built without a checkpoint directory never copies.
func TestStatusLockedTailDBNoCopyInWorkingDir(t *testing.T) {
	fb := t.TempDir()
	path := filepath.Join(fb, "hawkbell-findings.db")
	lockTailDB(t, path, []tailRow{{name: "/outbox/detection-20261112-10-0001.ndjson", offset: 10, inode: 7}})
	wd := t.TempDir()
	t.Chdir(wd)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)

	// Without a checkpoint directory there is no copy fallback.
	for _, c := range tailDBConsumers(path, "") {
		if tc := c.(*tailDBConsumer); tc.copyDir != "" {
			t.Errorf("consumer without a checkpoint directory copies into %q", tc.copyDir)
		}
	}

	cfg := config.Default(filepath.Join(t.TempDir(), "data"))
	cfg.Output.FluentBit.TailDB = path
	o := outboxStatus(cfg, time.Now())
	if len(o.Consumers) != 1 || !o.Consumers[0].Readable {
		t.Errorf("status consumers: %+v", o.Consumers)
	}
	for _, d := range []string{wd, tmp} {
		if ents, _ := os.ReadDir(d); len(ents) != 0 {
			t.Errorf("status left %d entries in %s (first %s)", len(ents), d, ents[0].Name())
		}
	}
}
