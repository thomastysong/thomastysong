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

	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/sink"
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
// sees /w/outbox/... where the host has /var/lib/spoor/outbox/...), so rows
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
	v := consumerView{files: make(map[string]readPos, len(rows))}
	for _, r := range rows {
		base := r.name
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		if _, ok := sink.ParseSegmentName(base); !ok {
			continue
		}
		// Two rows for one name (an old inode Fluent Bit has not yet
		// cleaned up, and the current file): keep the one for the inode
		// on disk, which measure() checks; otherwise the furthest read.
		if cur, ok := v.files[base]; ok && cur.off >= r.offset {
			continue
		}
		v.files[base] = readPos{off: r.offset, inode: r.inode}
	}
	return v, nil
}

// tailDBConsumers expands output.fluent_bit.tail_db: a comma-separated list
// of database paths or glob patterns (the shipped Fluent Bit configuration
// uses one database per tail input).
func tailDBConsumers(spec, checkDir string) []consumer {
	var out []consumer
	seen := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		paths := []string{part}
		if strings.ContainsAny(part, "*?[") {
			m, err := filepath.Glob(part)
			if err != nil || len(m) == 0 {
				// Keep the pattern as a consumer that cannot be read, so the
				// pruner stays conservative until Fluent Bit creates it.
				m = []string{part}
			}
			paths = m
		}
		for _, p := range paths {
			if seen[p] || len(out) >= maxTailDBs {
				continue
			}
			seen[p] = true
			out = append(out, &tailDBConsumer{path: p, copyDir: filepath.Join(checkDir, "taildb-copy")})
		}
	}
	return out
}

// readTailDB returns the rows of a Fluent Bit tail database without ever
// writing to it. It first opens the file read-only in place. SQLite needs
// the -shm file of a WAL database; when Fluent Bit has stopped and removed
// it and the directory is read-only to this process (systemd
// ProtectSystem=strict), the file is opened as immutable, which is true
// while nobody writes it. As a last resort the database and its WAL are
// copied into the daemon's own checkpoint directory and read there.
func readTailDB(path, copyDir string) ([]tailRow, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > maxTailDBBytes {
		return nil, fmt.Errorf("%s: %d bytes is too large for a tail database", path, fi.Size())
	}
	rows, err := queryTailDB(path, false)
	if err == nil {
		return rows, nil
	}
	if _, werr := os.Lstat(path + "-wal"); errors.Is(werr, os.ErrNotExist) {
		if rows, ierr := queryTailDB(path, true); ierr == nil {
			return rows, nil
		}
	}
	if copyDir == "" {
		return nil, err
	}
	rows, cerr := queryCopy(path, copyDir)
	if cerr != nil {
		return nil, fmt.Errorf("%w (copy: %v)", err, cerr)
	}
	return rows, nil
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

// shipperConsumer is a spoor Shipper's checkpoint (sink.Shipper). Its
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
