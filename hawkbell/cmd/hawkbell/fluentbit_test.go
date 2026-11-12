package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/thomastysong/thomastysong/hawkbell/internal/daemon"
)

// makeFluentBitDB creates a tail database shaped like Fluent Bit 5.2.0's
// (internal/daemon/taildb.go has the captured schema).
func makeFluentBitDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE in_tail_files (id INTEGER PRIMARY KEY, name TEXT NOT NULL, offset INTEGER, inode INTEGER, created INTEGER, rotated INTEGER DEFAULT 0, offset_marker INTEGER DEFAULT 0, offset_marker_size INTEGER DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO in_tail_files (name, offset, inode, created) VALUES ('/outbox/detection-20261112-10-0001.ndjson', 100, 7, 1)`); err != nil {
		t.Fatal(err)
	}
}

func tailDBDetails(f []fbFinding) string {
	var s []string
	for _, x := range f {
		if x.Code != "shipper.tail_db" || x.Status != "warn" {
			s = append(s, "unexpected "+x.Code+"/"+x.Status)
		}
		s = append(s, x.Detail)
	}
	return strings.Join(s, "\n")
}

// Doctor accepts what the daemon accepts: comma-separated paths and globs,
// with one finding per database that is missing or unreadable.
func TestCheckTailDBSpec(t *testing.T) {
	dir := t.TempDir()
	findings := filepath.Join(dir, "hawkbell-findings.db")
	activity := filepath.Join(dir, "hawkbell-activity.db")
	makeFluentBitDB(t, findings)
	makeFluentBitDB(t, activity)

	if f := checkTailDB(""); f != nil {
		t.Errorf("unset: %+v", f)
	}
	// A glob matching both databases: nothing to report.
	if f := checkTailDB(filepath.Join(dir, "hawkbell-*.db")); len(f) != 0 {
		t.Errorf("glob:\n%s", tailDBDetails(f))
	}
	// A comma list, with spaces and an empty member, as the daemon reads it.
	if f := checkTailDB(" " + findings + " ,," + activity + " "); len(f) != 0 {
		t.Errorf("comma list:\n%s", tailDBDetails(f))
	}
	// One member missing: one finding, about that member.
	missing := filepath.Join(dir, "hawkbell-other.db")
	f := checkTailDB(findings + "," + missing + "," + activity)
	if len(f) != 1 || !strings.Contains(f[0].Detail, missing) || strings.Contains(f[0].Detail, findings) {
		t.Errorf("missing member:\n%s", tailDBDetails(f))
	}
	// A pattern with no match, and one filepath.Glob refuses.
	f = checkTailDB(filepath.Join(dir, "nope-*.db") + "," + filepath.Join(dir, "x[") + "," + findings)
	all := tailDBDetails(f)
	if len(f) != 2 || !strings.Contains(all, "matches no file") || !strings.Contains(all, "not a valid pattern") {
		t.Errorf("patterns:\n%s", all)
	}
	// A file the glob matches that is not a tail database is unreadable.
	junk := filepath.Join(dir, "hawkbell-junk.db")
	writeTestFile(t, junk, "not sqlite", 0o600)
	f = checkTailDB(filepath.Join(dir, "hawkbell-*.db"))
	if len(f) != 1 || !strings.Contains(f[0].Detail, junk) {
		t.Errorf("junk member:\n%s", tailDBDetails(f))
	}
	if f := checkTailDB(" , "); len(f) != 1 || !strings.Contains(f[0].Detail, "names no database") {
		t.Errorf("blank:\n%s", tailDBDetails(f))
	}
}

// A database Fluent Bit holds locked (db.locking true: journal_mode WAL,
// locking_mode EXCLUSIVE) cannot be read in place, and the pruner reads a
// copy of it instead (internal/daemon/taildb.go, readTailDB). Doctor does
// the same, so it does not warn about a database the pruner reads, and it
// leaves no copy behind.
func TestCheckTailDBLocked(t *testing.T) {
	dir := t.TempDir()
	findings := filepath.Join(dir, "hawkbell-findings.db")
	activity := filepath.Join(dir, "hawkbell-activity.db")
	makeFluentBitDB(t, activity)
	db, err := sql.Open("sqlite", "file:"+findings+"?_pragma=journal_mode(WAL)&_pragma=locking_mode(EXCLUSIVE)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE in_tail_files (id INTEGER PRIMARY KEY, name TEXT NOT NULL, offset INTEGER, inode INTEGER, created INTEGER, rotated INTEGER DEFAULT 0, offset_marker INTEGER DEFAULT 0, offset_marker_size INTEGER DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO in_tail_files (name, offset, inode, created) VALUES ('/outbox/detection-20261112-10-0001.ndjson', 100, 7, 1)`); err != nil {
		t.Fatal(err)
	}
	// The database is locked: an in-place read fails.
	if _, inPlace, err := daemon.CheckTailDB(findings, ""); err == nil || inPlace == nil {
		t.Fatalf("the test database is not locked: %v, %v", inPlace, err)
	}
	tmp := t.TempDir()
	setTempDir(t, tmp)
	start := time.Now()
	if f := checkTailDB(filepath.Join(dir, "hawkbell-*.db")); len(f) != 0 {
		t.Errorf("locked database flagged:\n%s", tailDBDetails(f))
	}
	t.Logf("checkTailDB took %.1f s", time.Since(start).Seconds())
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Errorf("doctor left %d entries in the temporary directory", len(ents))
	}
	// Without a directory for the copy, the locked database is reported.
	setTempDir(t, filepath.Join(tmp, "missing"))
	f := checkTailDB(filepath.Join(dir, "hawkbell-*.db"))
	if len(f) != 1 || !strings.Contains(f[0].Detail, findings) || !strings.Contains(f[0].Detail, "could not create a directory for a copy") {
		t.Errorf("no copy directory:\n%s", tailDBDetails(f))
	}
}

// setTempDir points os.TempDir, which checkTailDB's os.MkdirTemp("", ...)
// uses, at dir: $TMPDIR on Unix; on Windows GetTempPath, which takes %TMP%
// first, then %TEMP%.
func setTempDir(t *testing.T, dir string) {
	t.Helper()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, dir)
	}
}

var flbVar = regexp.MustCompile(`\$\{[A-Z_]+:-([^}]*)\}`)

// The tail_db value docs/FLUENT-BIT.md recommends matches every database
// the shipped inputs write, and doctor accepts it.
func TestCheckTailDBShippedSpec(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "FLUENT-BIT.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*tail_db:\s*(\S+)`).FindSubmatch(doc)
	if m == nil {
		t.Fatal("docs/FLUENT-BIT.md recommends no tail_db")
	}
	spec := string(m[1])

	cfg, _ := testConfig(t, "")
	out := filepath.Join(t.TempDir(), "fb")
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "export", "fluent-bit", "--config", cfg, "--out", out)
	secs, err := readFluentBitConfig(filepath.Join(out, "hawkbell-inputs.yaml"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var dbs []string
	for _, s := range secs {
		if s.kind == "input" && s.props["db"] != "" {
			dbs = append(dbs, flbVar.ReplaceAllString(s.props["db"], "$1")) // the default of ${VAR:-default}
		}
	}
	if len(dbs) != 2 {
		t.Fatalf("shipped tail databases: %v", dbs)
	}
	for _, db := range dbs {
		if ok, _ := filepath.Match(spec, db); !ok {
			t.Errorf("recommended tail_db %s does not match the shipped database %s", spec, db)
		}
	}

	// The same layout under a temporary root.
	root := t.TempDir()
	reroot := func(p string) string { return filepath.Join(root, strings.TrimPrefix(p, "/var/lib/fluent-bit")) }
	if !strings.HasPrefix(spec, "/var/lib/fluent-bit/") {
		t.Fatalf("recommended tail_db %s is not under /var/lib/fluent-bit", spec)
	}
	local := reroot(spec)
	f := checkTailDB(local)
	if len(f) != 1 || !strings.Contains(f[0].Detail, "matches no file") {
		t.Errorf("before Fluent Bit started:\n%s", tailDBDetails(f))
	}
	for _, db := range dbs {
		makeFluentBitDB(t, reroot(db))
	}
	if f := checkTailDB(local); len(f) != 0 {
		t.Errorf("shipped spec flagged:\n%s", tailDBDetails(f))
	}

	// End to end through doctor: the fluent_bit check is clean.
	cfg2, _ := testConfig(t, "output:\n  fluent_bit:\n    tail_db: "+local+"\n")
	ta = newTestApp(t)
	ta.run("doctor", "--config", cfg2, "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "fluent_bit"); c.Status != "ok" {
		t.Errorf("doctor flags the shipped tail_db: %+v", c)
	}
}

// /api/v1/storage answers 404 for the first seconds after Fluent Bit starts
// as well as when storage.metrics is off: the warning says both, and to
// rerun. /api/v1/metrics answers 404 for a moment after start too.
func TestFluentBitStorageNotUpYet(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   []string
	}{
		{"404", func(w http.ResponseWriter) { http.NotFound(w, nil) },
			[]string{"answered 404", "started only seconds ago", "storage.metrics is off", "rerun hawkbell doctor"}},
		{"500", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
			[]string{"could not be read", "500", "rerun hawkbell doctor"}},
		{"no storage_layer", func(w http.ResponseWriter) { fmt.Fprint(w, `{"input_chunks":{}}`) },
			[]string{"no storage_layer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"fluent-bit":{"version":"5.2.0","edition":"Community","flags":[]}}`)
			})
			mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"input":{},"filter":{},"output":{}}`)
			})
			mux.HandleFunc("/api/v1/storage", func(w http.ResponseWriter, r *http.Request) { tc.answer(w) })
			srv := httptest.NewServer(mux)
			defer srv.Close()
			f, ver := checkFluentBitAPI(context.Background(), loopbackClient(3*time.Second), srv.URL)
			if ver != "5.2.0" || len(f) != 1 || f[0].Code != "shipper.storage_metrics" || f[0].Status != "warn" {
				t.Fatalf("%s %+v", ver, f)
			}
			for _, w := range tc.want {
				if !strings.Contains(f[0].Detail, w) {
					t.Errorf("no %q in %q", w, f[0].Detail)
				}
			}
			if tc.name != "404" && strings.Contains(f[0].Detail, "storage.metrics is off") {
				t.Errorf("blames storage.metrics for %s: %q", tc.name, f[0].Detail)
			}
		})
	}
}

func TestFluentBitMetricsNotUpYet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fluent-bit":{"version":"5.2.0","edition":"Community","flags":[]}}`)
	})
	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/api/v1/storage", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f, _ := checkFluentBitAPI(context.Background(), loopbackClient(3*time.Second), srv.URL)
	if len(f) != 2 || f[0].Code != "shipper.metrics" || !strings.Contains(f[0].Detail, "started less than a second ago") || !strings.Contains(f[0].Detail, "rerun hawkbell doctor") {
		t.Fatalf("%+v", f)
	}
}
