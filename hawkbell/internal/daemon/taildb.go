package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // the pure-Go driver the state package registers too

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
)

// Fluent Bit's tail input records, per followed file, the path it opened,
// the byte offset it has consumed and the inode, in table in_tail_files of
// its SQLite "db". Captured from fluent/fluent-bit 5.2.0 in this sandbox
// (2026-11-12):
//
//	CREATE TABLE in_tail_files (id INTEGER PRIMARY KEY, name TEXT NOT NULL,
//	  offset INTEGER, inode INTEGER, created INTEGER, rotated INTEGER DEFAULT 0,
//	  offset_marker INTEGER DEFAULT 0, offset_marker_size INTEGER DEFAULT 0)
//
// The name is the path inside Fluent Bit's own mount namespace (a container
// sees /w/outbox/... where the host has /var/lib/hawkbell/outbox/...), so rows
// are matched by base name and inode. The shipped configuration sets
// db.locking false so that this read-only reader is not locked out, and
// db.compare_filename true so a reused inode is not mistaken for a file
// already read.

const (
	maxTailDBBytes = 64 << 20 // a tail DB is a few pages; anything larger is not one
	maxTailRows    = 100000
	maxTailDBs     = 16
	tailDBTimeout  = 5 * time.Second
)

type tailRow struct {
	name   string
	offset int64
	inode  uint64
}

// tailDBConsumer is one Fluent Bit tail database.
type tailDBConsumer struct {
	path    string
	copyDir string
}

func (c *tailDBConsumer) id() string { return "fluent-bit:" + c.path }

func (c *tailDBConsumer) view() (consumerView, error) {
	rows, err := readTailDB(c.path, c.copyDir)
	if err != nil {
		return consumerView{}, err
	}
	return tailView(rows), nil
}

// tailView is what the rows of one tail database say was read.
func tailView(rows []tailRow) consumerView {
	v := consumerView{files: make(map[string]readPos, len(rows))}
	for _, r := range rows {
		base := r.name
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		if _, ok := sink.ParseSegmentName(base); !ok {
			continue
		}
		pos := readPos{off: r.offset, inode: r.inode}
		if _, ok := v.files[base]; !ok {
			v.files[base] = pos
			continue
		}
		// Two rows for one name (an old inode Fluent Bit has not cleaned
		// up yet, and the current file, or one name in two directories):
		// all are kept, and consumerView.readOffset picks the row for the
		// inode on disk.
		if v.more == nil {
			v.more = map[string][]readPos{}
		}
		if len(v.more[base]) < 8 {
			v.more[base] = append(v.more[base], pos)
		}
	}
	return v
}

// TailDB is one database named by output.fluent_bit.tail_db, after
// expansion.
type TailDB struct {
	// Path is the database file; for a pattern that matched nothing it is
	// the pattern itself, kept as a consumer that cannot be read.
	Path string
	// Pattern is the glob Path came from ("" for a plain path).
	Pattern string
	// NoMatch: the pattern matched no file. BadPattern: filepath.Glob
	// refused it. Either way the daemon keeps it as a consumer that cannot
	// be read, so pruning stays conservative until Fluent Bit creates it.
	NoMatch, BadPattern bool
}

// ExpandTailDB expands output.fluent_bit.tail_db: a comma-separated list of
// database paths or glob patterns (the shipped Fluent Bit configuration uses
// one database per tail input). Duplicates are dropped; at most maxTailDBs
// databases are returned and skipped counts the rest. The pruner and
// `hawkbell doctor` both read the setting through this function.
func ExpandTailDB(spec string) (dbs []TailDB, skipped int) {
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		found := []TailDB{{Path: part}}
		if strings.ContainsAny(part, "*?[") {
			m, err := filepath.Glob(part)
			switch {
			case err != nil:
				found = []TailDB{{Path: part, Pattern: part, NoMatch: true, BadPattern: true}}
			case len(m) == 0:
				found = []TailDB{{Path: part, Pattern: part, NoMatch: true}}
			default:
				found = found[:0]
				for _, p := range m {
					found = append(found, TailDB{Path: p, Pattern: part})
				}
			}
		}
		for _, db := range found {
			if seen[db.Path] {
				continue
			}
			seen[db.Path] = true
			if len(dbs) >= maxTailDBs {
				skipped++
				continue
			}
			dbs = append(dbs, db)
		}
	}
	return dbs, skipped
}

// CheckTailDB reads one tail database the way the pruner does (readTailDB),
// including the fallback to a private copy under copyDir when the database
// cannot be read in place (Fluent Bit's db.locking true, a read-only
// mount), and returns how many rows about outbox segments it holds. inPlace
// is the error of the in-place read when the copy was read instead, nil
// otherwise. The pruner copies into its checkpoint directory; a caller that
// is not the daemon passes a directory of its own. With copyDir "" there is
// no fallback, so a database the pruner reads through a copy fails here.
func CheckTailDB(path, copyDir string) (segments int, inPlace, err error) {
	rows, inPlace, err := readTailDBVia(path, copyDir)
	if err != nil {
		return 0, inPlace, err
	}
	v := tailView(rows)
	for _, more := range v.more {
		segments += len(more)
	}
	return segments + len(v.files), inPlace, nil
}

// tailDBConsumers is one consumer per database ExpandTailDB names. A
// database that cannot be read in place is copied into "taildb-copy" under
// checkDir; with checkDir "" it is not copied (never into a directory
// relative to the working directory) and reads as unreadable.
func tailDBConsumers(spec, checkDir string) []consumer {
	dbs, _ := ExpandTailDB(spec)
	copyDir := ""
	if checkDir != "" {
		copyDir = filepath.Join(checkDir, "taildb-copy")
	}
	out := make([]consumer, 0, len(dbs))
	for _, db := range dbs {
		out = append(out, &tailDBConsumer{path: db.Path, copyDir: copyDir})
	}
	return out
}

// readTailDB returns the rows of a Fluent Bit tail database without ever
// writing to it or creating anything beside it.
//
// SQLite opens a WAL database through its -wal and -shm sidecars and
// creates them when they are missing, even for a read-only connection; a
// root-owned -shm left in Fluent Bit's directory can then lock a Fluent Bit
// running as another user out of its own database (observed here: a mode=ro
// read of a stopped Fluent Bit's database created both files). So:
//
//   - no -wal file (Fluent Bit stopped cleanly, or rollback journal mode):
//     the file is not being written; it is opened as immutable, which reads
//     it without locks or sidecars;
//   - a -wal file (Fluent Bit running): opened read-only in place, sharing
//     Fluent Bit's own sidecars (the shipped configuration sets db.locking
//     false so this reader is not locked out);
//   - when that fails (a read-only mount under systemd ProtectSystem=strict,
//     a lock), the database and its WAL are copied into the daemon's own
//     checkpoint directory and read there. A copy can be slightly behind but
//     every row in it is one that existed, so it never reports more than was
//     read. A locked database costs the 2 s busy timeout before the copy.
func readTailDB(path, copyDir string) ([]tailRow, error) {
	rows, _, err := readTailDBVia(path, copyDir)
	return rows, err
}

// readTailDBVia is readTailDB that also returns the in-place read's error
// when the copy was read instead.
func readTailDBVia(path, copyDir string) (rows []tailRow, inPlace, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > maxTailDBBytes {
		return nil, nil, fmt.Errorf("%s: %d bytes is too large for a tail database", path, fi.Size())
	}
	_, werr := os.Lstat(path + "-wal")
	walExists := werr == nil
	if walExists {
		rows, err = queryTailDB(path, false)
	} else {
		rows, err = queryTailDB(path, true)
	}
	if err == nil {
		return rows, nil, nil
	}
	if copyDir == "" {
		return nil, err, err
	}
	rows, cerr := queryCopy(path, copyDir)
	if cerr != nil {
		return nil, err, fmt.Errorf("%w (copy: %v)", err, cerr)
	}
	return rows, err, nil
}

// sqliteURI renders a file path as the URI SQLite's parser expects.
func sqliteURI(path, query string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows C:/x -> /C:/x
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String() + "?" + query
}

func queryTailDB(path string, immutable bool) ([]tailRow, error) {
	q := "mode=ro&_busy_timeout=2000&_query_only=1"
	if immutable {
		q += "&immutable=1"
	}
	return queryRows(sqliteURI(path, q))
}

// queryCopy reads a private copy of the database and its WAL.
func queryCopy(path, copyDir string) ([]tailRow, error) {
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(copyDir, "db-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	dst := filepath.Join(tmp, "tail.db")
	if err := copyFile(path, dst); err != nil {
		return nil, err
	}
	if err := copyFile(path+"-wal", dst+"-wal"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Not read-only: SQLite replays the copied WAL into the copy.
	return queryRows(sqliteURI(dst, "_busy_timeout=2000"))
}

func queryRows(dsn string) ([]tailRow, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), tailDBTimeout)
	defer cancel()
	rs, err := db.QueryContext(ctx, fmt.Sprintf("SELECT name, offset, inode FROM in_tail_files LIMIT %d", maxTailRows))
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []tailRow
	for rs.Next() {
		var name sql.NullString
		var off, ino sql.NullInt64
		if err := rs.Scan(&name, &off, &ino); err != nil {
			return nil, err
		}
		if !name.Valid {
			continue
		}
		// SQLite stores the 64-bit inode (or NTFS file index) signed.
		out = append(out, tailRow{name: name.String, offset: off.Int64, inode: uint64(ino.Int64)})
	}
	return out, rs.Err()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(in, maxTailDBBytes))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// shipperConsumer is a hawkbell Shipper's checkpoint (sink.Shipper). Its
// format is {"v":1,"files":{"<segment>":{"off":N,...}}}; a Shipper reads
// every segment in the directory.
type shipperConsumer struct {
	name string
	path string
}

func (c *shipperConsumer) id() string { return "shipper:" + c.name }

func (c *shipperConsumer) view() (consumerView, error) {
	v := consumerView{files: map[string]readPos{}, all: true}
	b, err := readSmallFile(c.path, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil // nothing shipped yet
	}
	if err != nil {
		return v, err
	}
	var cp struct {
		V     int `json:"v"`
		Files map[string]struct {
			Off int64 `json:"off"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &cp); err != nil || cp.V != 1 {
		return v, fmt.Errorf("shipper checkpoint %s: unreadable", filepath.Base(c.path))
	}
	for name, cur := range cp.Files {
		if _, ok := sink.ParseSegmentName(name); ok && cur.Off >= 0 {
			v.files[name] = readPos{off: cur.Off}
		}
	}
	return v, nil
}

// readSmallFile reads a file without following a final symlink, with a cap.
func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", filepath.Base(path), limit)
	}
	return b, nil
}

// writeFileAtomic replaces path with b through a temporary file in the same
// directory and a rename.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil && !isNotSupported(err) {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func isNotSupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported)
}
