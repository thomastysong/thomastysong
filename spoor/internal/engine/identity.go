package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// Identity keys. Every identifier the pipeline derives from what a record
// says (the prompt text that pairs a hook prompt with its transcript twin,
// the digest that names a record which came without an id) is an
// HMAC-SHA256 under an identity key. Everything else that goes into Dedupe
// and ID (host, account, agent, session, type, time) is visible in the
// shipped record, so an unkeyed digest would let any reader of the logs
// confirm a guess about the prompt, or about a secret the redactor removed
// from a command, by recomputing it (the privacy red team recovered four of
// six prompts from a 1,600-entry dictionary that way).
const (
	// IdentityKeyFile is the file name of the daemon's identity key under
	// the checkpoint directory (IdentityKeyPath).
	IdentityKeyFile = "identity.key"
	// IdentityKeyLen is the size of a generated identity key, in bytes.
	IdentityKeyLen = 32
	// MinIdentityKeyLen is the shortest Options.IdentityKey New accepts.
	MinIdentityKeyLen = 16
)

// Domain separators, so a digest computed for one purpose can never be
// presented as another.
const (
	domPrompt  = "spoor/engine/prompt/v2"
	domContent = "spoor/engine/content/v2"
)

// processIdentityKey is the key of pipelines built without
// Options.IdentityKey: random, drawn once per process. Identity is then
// deterministic for the life of the process (a hook record and its
// transcript twin still pair, a replayed record still collapses) but not
// across runs, and no reader can test a guess against it.
var processIdentityKey = sync.OnceValue(func() []byte {
	k := make([]byte, IdentityKeyLen)
	_, _ = rand.Read(k) // never fails (crypto/rand aborts the process instead)
	return k
})

// identityKey returns the key a pipeline uses: a copy of the caller's key
// (so later changes to the caller's slice cannot move identities), or the
// per-process key when none is configured.
func identityKey(k []byte) ([]byte, error) {
	if len(k) == 0 {
		return processIdentityKey(), nil
	}
	if len(k) < MinIdentityKeyLen {
		return nil, fmt.Errorf("engine: IdentityKey is %d bytes, at least %d required", len(k), MinIdentityKeyLen)
	}
	return bytes.Clone(k), nil
}

// keyed starts an HMAC for one identity domain.
func (p *Pipeline) keyed(domain string) hash.Hash {
	m := hmac.New(sha256.New, p.idKey)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	return m
}

// hasNaturalKey reports whether naturalKey returns a key, without hashing
// anything.
func hasNaturalKey(ev *event.Event) bool {
	switch ev.Type {
	case event.TypeToolPre, event.TypeToolPost:
		return ev.Tool != nil && ev.Tool.UseID != ""
	case event.TypePromptSubmit:
		return ev.Content != nil && ev.Content.PromptText != ""
	case event.TypeSessionStart, event.TypeSessionEnd:
		return ev.Session != nil && ev.Session.ID != ""
	}
	return false
}

// naturalKey is the surface-independent identity of an activity record:
// the agent's tool-call id, a keyed digest of the prompt text, or the
// session for start and end. "" when there is none. Tool-call and session
// ids are random values the agent generates, not content, so they are used
// as they are: they are also what joins spoor records to the agent's own
// telemetry.
func (p *Pipeline) naturalKey(ev *event.Event) string {
	if !hasNaturalKey(ev) {
		return ""
	}
	switch ev.Type {
	case event.TypeToolPre, event.TypeToolPost:
		return "tool:" + ev.Tool.UseID
	case event.TypePromptSubmit:
		m := p.keyed(domPrompt)
		m.Write([]byte(ev.Content.PromptText))
		return "prompt:" + hex.EncodeToString(m.Sum(nil)[:16])
	}
	return "session"
}

// contentKey is a deterministic, keyed digest of what a record describes,
// for records that came without an id. It runs before the privacy stage,
// so it sees commands, paths and URLs before redaction: only the key keeps
// the shipped ID from confirming a guess about what was redacted.
func (p *Pipeline) contentKey(ev *event.Event) string {
	m := p.keyed(domContent)
	w := func(s string) {
		// Length-prefixed, so no value can shift bytes into the next one.
		m.Write([]byte(strconv.Itoa(len(s))))
		m.Write([]byte{':'})
		m.Write([]byte(s))
	}
	host, user, agent, sess := idParts(ev)
	w(host)
	w(user)
	w(agent)
	w(sess)
	if t := ev.Tool; t != nil {
		w(t.Name)
		w(t.UseID)
		w(t.InputSHA256)
	} else {
		w("")
		w("")
		w("")
	}
	if t := ev.Target; t != nil {
		w(t.Command)
		w(t.Path)
		w(t.URL)
		w(t.Query)
	} else {
		w("")
		w("")
		w("")
		w("")
	}
	if pr := ev.Process; pr != nil {
		w(strconv.Itoa(pr.PID))
		w(pr.Exe)
		w(pr.StartTime.String())
	} else {
		w("")
		w("")
		w("")
	}
	if a := ev.Asset; a != nil {
		w(a.ID)
		w(a.SHA256)
	} else {
		w("")
		w("")
	}
	if c := ev.Check; c != nil {
		w(c.ID)
		w(c.AssetID)
		w(c.Status)
	} else {
		w("")
		w("")
		w("")
	}
	if d := ev.Detection; d != nil {
		w(d.RuleID)
		w(d.DedupKey)
	} else {
		w("")
		w("")
	}
	if c := ev.Content; c != nil {
		w(c.PromptText)
	} else {
		w("")
	}
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// IdentityKeyPath is where the daemon keeps its identity key:
// <data_dir>/checkpoints/identity.key, beside the other private state. ""
// without a data directory.
func IdentityKeyPath(cfg *config.Config) string {
	if cfg == nil || cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(cfg.CheckDir(), IdentityKeyFile)
}

// LoadOrCreateIdentityKey returns the identity key stored at path,
// creating it on first use: IdentityKeyLen random bytes, hex-encoded on one
// line, mode 0600, in a directory created 0700. The file is created under
// a temporary name and linked into place, so a crash never leaves a
// partial key and two processes starting at once agree on one key.
//
// An existing file is read without following symbolic links and must be a
// regular file of at most 4 KiB, not accessible to group or others on
// POSIX systems, holding at least MinIdentityKeyLen bytes of hex. Anything
// else is an error rather than a silent replacement: a caller that cannot
// read its key should run with an empty Options.IdentityKey (identities
// then hold for this run only) and report it.
func LoadOrCreateIdentityKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("engine: identity key: empty path")
	}
	k, err := ReadIdentityKey(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	key := make([]byte, IdentityKeyLen)
	_, _ = rand.Read(key)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // 0600
	if err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(0o600); err != nil {
			tmp.Close()
			return nil, fmt.Errorf("engine: identity key: %w", err)
		}
	}
	if _, err := tmp.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	// A link never replaces an existing file: whoever links first wins and
	// everyone else reads the winner's key.
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ReadIdentityKey(path)
		}
		// File systems without hard links: rename is still atomic, only
		// not exclusive.
		if err := os.Rename(name, path); err != nil {
			return nil, fmt.Errorf("engine: identity key: %w", err)
		}
	}
	syncDir(dir)
	return key, nil
}

const maxIdentityKeyFile = 4096

// ReadIdentityKey reads an identity key written by LoadOrCreateIdentityKey
// (hex on one line); see there for the checks. An absent file is an error
// that wraps os.ErrNotExist.
func ReadIdentityKey(path string) ([]byte, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("engine: identity key %s: not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("engine: identity key %s: mode %04o lets group or others read it; chmod 600", path, fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxIdentityKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("engine: identity key: %w", err)
	}
	if len(b) > maxIdentityKeyFile {
		return nil, fmt.Errorf("engine: identity key %s: larger than %d bytes", path, maxIdentityKeyFile)
	}
	k, err := hex.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil {
		return nil, fmt.Errorf("engine: identity key %s: not hex", path)
	}
	if len(k) < MinIdentityKeyLen {
		return nil, fmt.Errorf("engine: identity key %s: %d bytes, at least %d required", path, len(k), MinIdentityKeyLen)
	}
	return k, nil
}

// syncDir makes a rename or link in dir durable (best effort; Windows has
// no directory sync).
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
