package osqext

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// rowQuerier is the part of osquery-go's client the host id lookup needs.
type rowQuerier interface {
	QueryRow(sql string) (map[string]string, error)
}

const hostUUIDQuery = "SELECT uuid FROM system_info"

const maxHostIDLen = 128

// hostIDDelays are the waits before each attempt. The first is not zero:
// an autoloaded extension starts while osquery is still initialising, and
// the lookup must not compete with table registration.
var hostIDDelays = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second, time.Minute}

// syncHostID fetches osquery's host uuid and stores it, retrying a few
// times. It gives up quietly after the last attempt: tables keep working
// and the daemon falls back to its own host id sources.
func syncHostID(stop <-chan struct{}, dial func() (rowQuerier, func(), error), file string) {
	defer func() {
		if r := recover(); r != nil {
			Logf("host id: internal error: %v", r)
		}
	}()
	var last error
	for _, wait := range hostIDDelays {
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
		if last = fetchHostID(dial, file); last == nil {
			return
		}
	}
	Logf("host id not written to %s: %v", file, last)
}

func fetchHostID(dial func() (rowQuerier, func(), error), file string) error {
	q, done, err := dial()
	if err != nil {
		return err
	}
	defer done()
	id, err := hostUUID(q)
	if err != nil {
		return err
	}
	return writeHostID(file, id)
}

// hostUUID asks osquery for the id Fleet knows this host by.
func hostUUID(q rowQuerier) (string, error) {
	row, err := q.QueryRow(hostUUIDQuery)
	if err != nil {
		return "", fmt.Errorf("query system_info: %w", err)
	}
	id := strings.TrimSpace(row["uuid"])
	if !validHostID(id) {
		return "", fmt.Errorf("osquery returned an unusable host uuid %q", clipForLog(id))
	}
	return id, nil
}

// validHostID accepts what is safe in a file, a log line and a query
// string. The id ends up on every record the sensor emits.
func validHostID(s string) bool {
	if s == "" || len(s) > maxHostIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

func clipForLog(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.ToValidUTF8(s, "?")
}

// writeHostID stores id in file with mode 0644, atomically, creating the
// directory (0755) when needed. Unprivileged hook processes read the file,
// hence world-readable. An unchanged file is left untouched so its mtime
// keeps saying when the id last changed.
func writeHostID(file, id string) error {
	if !validHostID(id) {
		return errors.New("host id must be 1-128 characters of [A-Za-z0-9._:-]")
	}
	if strings.TrimSpace(file) == "" || strings.ContainsRune(file, 0) {
		return errors.New("empty host id file path")
	}
	want := []byte(id + "\n")
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Checked before anything in the directory is opened: once it is known
	// that no other user can write there, nothing below can be swapped.
	if err := checkHostIDDir(dir); err != nil {
		return err
	}
	if cur, err := readSmallRegular(file, 2*maxHostIDLen); err == nil && bytes.Equal(cur, want) {
		return nil
	}
	// CreateTemp opens with O_EXCL and mode 0600, so nothing planted in the
	// directory beforehand is written through.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(file)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(want); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o644); err != nil && runtime.GOOS != "windows" {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	// Rename replaces whatever is at the destination, including a symbolic
	// link, without following it.
	if err := os.Rename(name, file); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// readSmallRegular reads a regular file of at most max bytes without
// following a link at the final component.
func readSmallRegular(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, errors.New("not a small regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}
