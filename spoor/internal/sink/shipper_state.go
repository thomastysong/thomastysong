package sink

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// fileCursor is the persisted position in one segment.
type fileCursor struct {
	Offset int64 `json:"off"`
	// Fingerprint is the hex SHA-256 prefix of the first FingerprintLen
	// bytes of the file, recorded once Offset has passed them.
	Fingerprint    string `json:"fp,omitempty"`
	FingerprintLen int    `json:"fpn,omitempty"`
}

type checkpointFile struct {
	V     int                    `json:"v"`
	Files map[string]*fileCursor `json:"files"`
}

// fingerprint hashes the first bytes of a segment, at most fingerprintLen
// and never past upTo (the shipped offset), so the hashed range is complete
// and, the file being append-only, will not change.
func fingerprint(f *os.File, upTo int64) (string, int) {
	n := int64(fingerprintLen)
	if upTo < n {
		n = upTo
	}
	if n <= 0 {
		return "", 0
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return "", 0
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8]), int(n)
}

// sameFile reports whether f still starts with the bytes recorded in cur.
func sameFile(f *os.File, cur *fileCursor) bool {
	if cur.Fingerprint == "" || cur.FingerprintLen <= 0 {
		return true
	}
	fp, n := fingerprint(f, int64(cur.FingerprintLen))
	return n == cur.FingerprintLen && fp == cur.Fingerprint
}

// load reads the checkpoint. A missing file means a first run. An
// unreadable one is treated the same way, which re-ships what is still on
// disk: duplicates are recoverable downstream (events carry ids), a shipper
// that refuses to start is not.
func (s *Shipper) load() {
	s.files = make(map[string]*fileCursor)
	s.removeStaleTemps()
	f, err := os.Open(s.o.Checkpoint)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.count(func(st *ShipperStats) { st.Resets++ })
		}
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCheckpoint+1))
	var cp checkpointFile
	if err != nil || len(raw) > maxCheckpoint || json.Unmarshal(raw, &cp) != nil || cp.V != 1 {
		s.count(func(st *ShipperStats) { st.Resets++ })
		return
	}
	for name, cur := range cp.Files {
		if _, ok := parseSegment(name); !ok || cur == nil || cur.Offset < 0 {
			continue
		}
		if cur.FingerprintLen < 0 || cur.FingerprintLen > fingerprintLen {
			cur.Fingerprint, cur.FingerprintLen = "", 0
		}
		s.files[name] = cur
	}
}

// removeStaleTemps deletes temporary checkpoint files left by a process
// that died between creating one and renaming it. Only this checkpoint's
// own pattern is matched, and only files old enough that no live save can
// still be using them.
func (s *Shipper) removeStaleTemps() {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(s.o.Checkpoint), globEscape(filepath.Base(s.o.Checkpoint))+".*.tmp"))
	if err != nil {
		return
	}
	for _, m := range matches {
		if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > time.Minute {
			os.Remove(m)
		}
	}
}

// globEscape quotes the characters filepath.Glob treats as syntax.
func globEscape(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', '\\':
			b = append(b, '[', s[i], ']')
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}

// save writes the checkpoint atomically: a uniquely named temporary file in
// the same directory, fsync, rename over the old one. The random name and
// exclusive create matter when the directory is writable by other users: a
// predictable temporary name could be pre-planted as a symlink.
func (s *Shipper) save() error {
	if !s.dirty {
		return nil
	}
	raw, err := json.Marshal(checkpointFile{V: 1, Files: s.files})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.o.Checkpoint)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.o.Checkpoint)+".*.tmp")
	if err != nil {
		return fmt.Errorf("sink shipper: checkpoint: %w", err)
	}
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.o.Checkpoint)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("sink shipper: checkpoint: %w", err)
	}
	s.dirty = false
	_ = syncDir(dir)
	return nil
}
