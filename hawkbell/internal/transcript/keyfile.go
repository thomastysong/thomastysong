package transcript

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Line keys. A record the log gives no id of its own (every Codex record,
// Claude Code bookkeeping records) is identified by an HMAC of its line
// (lineDigest), because the line holds prompts and tool output and an
// unkeyed digest of it would let a reader of the shipped ids confirm a
// guess. The key decides how long those ids hold:
//
//   - TailerOptions.IdentityKey when it is set;
//   - otherwise, for a Tailer with a StateFile, a key kept beside the
//     checkpoint store (StateFile + KeyFileSuffix), created on first use: a
//     line is read again only because a stored checkpoint says so (a crash
//     between Poll and Commit, a cancelled archive pass), and the key lives
//     as long as the checkpoints do, so the repeated events carry the same
//     ids in the restarted process;
//   - otherwise (ReadFile, a Tailer without a StateFile, or a key file that
//     cannot be used) a random key drawn once per process.
const (
	// KeyFileSuffix is appended to TailerOptions.StateFile to name the file
	// that holds the Tailer's line key when TailerOptions.IdentityKey is
	// empty.
	KeyFileSuffix = ".key"
	// minIdentityKeyLen is the shortest TailerOptions.IdentityKey used.
	minIdentityKeyLen = 16

	lineKeyLen = 32
	maxKeyFile = 4096
)

// processLineKey is the per-process line key: random, never stored.
var processLineKey = sync.OnceValue(func() []byte {
	k := make([]byte, lineKeyLen)
	_, _ = rand.Read(k) // never fails (crypto/rand aborts the process instead)
	return k
})

// lineKeyFrom derives the line key from a caller's identity key, in its own
// domain, so the caller's other digests under that key can never be
// presented as a line digest or the other way round.
func lineKeyFrom(identity []byte) []byte {
	m := hmac.New(sha256.New, identity)
	m.Write([]byte("hawkbell/transcript/line-key/v2\x00"))
	return m.Sum(nil)
}

// resolveKey picks the Tailer's line key (see Line keys). A problem is
// returned when a configured source could not be used and the per-process
// key stands in.
func (t *Tailer) resolveKey() (key []byte, prob *Problem) {
	if k := t.o.IdentityKey; len(k) > 0 {
		if len(k) >= minIdentityKeyLen {
			return lineKeyFrom(k), nil
		}
		prob = &Problem{Kind: ProblemUnreadable, Detail: fmt.Sprintf("identity key is %d bytes, at least %d required; ignored", len(k), minIdentityKeyLen)}
	}
	if t.o.StateFile != "" {
		path := t.o.StateFile + KeyFileSuffix
		k, err := loadOrCreateKey(path)
		if err == nil {
			return k, prob
		}
		prob = &Problem{Kind: ProblemUnreadable, Path: path, Detail: "line key: " + errText(err) +
			"; ids of records without a log id hold for this process only"}
	}
	return processLineKey(), prob
}

// loadOrCreateKey returns the key stored at path, creating it on first use:
// lineKeyLen random bytes, hex on one line, mode 0600, in a directory
// created 0700. It is created under a temporary name and linked into
// place, so a crash never leaves a partial key and two tailers starting at
// once agree on one. A file that exists but cannot be trusted (see
// readKey) is an error, never replaced: replacing it would change every id
// derived from it.
func loadOrCreateKey(path string) ([]byte, error) {
	k, err := readKey(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, lineKeyLen)
	_, _ = rand.Read(key)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // 0600
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	fail := func(err error) ([]byte, error) {
		tmp.Close()
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			return fail(err)
		}
	}
	if _, err := tmp.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// A link never replaces an existing file: whoever links first wins and
	// everyone else reads the winner's key.
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readKey(path)
		}
		// File systems without hard links: rename is still atomic, only
		// not exclusive.
		if err := os.Rename(name, path); err != nil {
			return nil, err
		}
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	return key, nil
}

// readKey reads a key written by loadOrCreateKey. The file is opened
// without following a symbolic link and without blocking on a FIFO, and
// must be a regular file of at most maxKeyFile bytes, not accessible to
// group or others on POSIX systems, holding at least minIdentityKeyLen
// bytes of hex. An absent file is an error wrapping os.ErrNotExist.
func readKey(path string) ([]byte, error) {
	f, meta, err := openBeneath(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !meta.regular {
		return nil, fmt.Errorf("%s: %w", path, errNotRegular)
	}
	if runtime.GOOS != "windows" {
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s: mode %04o lets group or others read it; chmod 600", path, fi.Mode().Perm())
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxKeyFile)
	}
	k, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: not hex", path)
	}
	if len(k) < minIdentityKeyLen {
		return nil, fmt.Errorf("%s: %d bytes, at least %d required", path, len(k), minIdentityKeyLen)
	}
	return k, nil
}
