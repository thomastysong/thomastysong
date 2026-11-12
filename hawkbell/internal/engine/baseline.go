package engine

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// Baseline is the persistent first-seen store behind rules novelty blocks
// (rules.Options.Baseline; BUILD-C C2 item 7). Rules ask it whether a key
// (a digest of the rule id and the novelty fields, for example the account
// and the egress host, or the account and an MCP server definition hash)
// has been seen before. It is an LRU of at most max keys, kept in a file
// under the checkpoint directory so a daemon restart does not make every
// host look new again.
//
// What a key names (which account contacted which host, which MCP server it
// called) is activity history, and the file outlives the activity records it
// was built from (minimal keeps those in a rotating local ring; a deleted
// transcript is forgotten). Host names and account names are guessable, so
// an unkeyed digest of them would hand that history to anyone who gets the
// file and a host list. Every key is therefore stored as an HMAC-SHA256
// (first 12 bytes, hex) under the pipeline's identity key, in its own
// domain, whatever form the caller passes it in: the file holds no host
// name, path or account, and no digest a reader can recompute from a guess
// without the key. The key is not in the file; the header carries a keyed
// fingerprint of it, so a file written under another key (the identity key
// was lost or replaced) or in the old unkeyed format is recognised,
// discarded and overwritten at the next save rather than mixed in. The
// identity key normally sits in the same directory (IdentityKeyPath), so
// this protects the file when it travels alone (a backup, a support
// bundle), not against an administrator of the host.
//
// The file is a header line ("hawkbell-baseline 2 <key fingerprint>"), then
// one key per line, least recently used first. It is replaced atomically
// (temporary file and rename), opened without following symbolic links, and
// read with a size cap; a damaged file is discarded, because the baseline
// is a cache whose loss only makes things look new (more attention, never
// less).
type Baseline struct {
	mu    sync.Mutex
	path  string
	max   int
	lru   *list.List // front = most recent
	items map[string]*list.Element
	dirty bool
	key   []byte
	keyID string // keyed fingerprint of key, in the header
}

const (
	// baselineMagic starts the header; baselineVersion is the format.
	// Version 1 stored unkeyed SHA-256 digests and is discarded on load.
	baselineMagic   = "hawkbell-baseline "
	baselineVersion = "2"
	// baselineKeyHex is the length of a stored key: 12 bytes of HMAC, hex.
	baselineKeyHex = 24
	// Domains of the baseline's HMACs under the identity key.
	domBaseline      = "hawkbell/engine/baseline/v2"
	domBaselineKeyID = "hawkbell/engine/baseline/v2/key-id"
)

// errBaselineStale reports a baseline file that was read and discarded:
// another format or another key. It is overwritten at the next save.
var errBaselineStale = errors.New("discarded")

// OpenBaseline loads the baseline at path ("" keeps it in memory only).
// key is the identity key the stored digests are keyed with (normally the
// pipeline's; nil uses the per-process key, so a file written then cannot
// be read back by another process). It always returns a usable Baseline;
// the error reports a file that could not be read, or was written in
// another format or under another key, and was ignored. A file that was
// read and discarded is replaced at the next Save.
func OpenBaseline(path string, max int, key []byte) (*Baseline, error) {
	if max <= 0 {
		max = BaselineKeys
	}
	if len(key) == 0 {
		key = processIdentityKey()
	}
	b := &Baseline{path: path, max: max, lru: list.New(), items: map[string]*list.Element{}, key: bytes.Clone(key)}
	b.keyID = hex.EncodeToString(b.mac(domBaselineKeyID, "")[:8])
	if path == "" {
		return b, nil
	}
	err := b.load()
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if errors.Is(err, errBaselineStale) {
		// Stale content (an unkeyed version 1 file, or digests under a
		// key this process does not have) must not linger on disk.
		b.dirty = true
	}
	return b, err
}

func (b *Baseline) mac(domain, s string) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write([]byte(s))
	return m.Sum(nil)
}

// digest is the stored form of a key: HMAC-SHA256 under the identity key,
// 12 bytes, hex. Every key is digested, also one that already looks like a
// digest (the rules engine passes an unkeyed SHA-256 of the novelty
// fields), so nothing in the file can be recomputed from a guess.
func (b *Baseline) digest(key string) string {
	return hex.EncodeToString(b.mac(domBaseline, key)[:baselineKeyHex/2])
}

func (b *Baseline) header() string { return baselineMagic + baselineVersion + " " + b.keyID }

// storedKey reports whether s has the shape of a stored key.
func storedKey(s string) bool {
	if len(s) != baselineKeyHex {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Seen records key and reports whether it had been recorded before.
func (b *Baseline) Seen(key string) bool {
	k := b.digest(key)
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.items[k]; ok {
		b.lru.MoveToFront(el)
		return true
	}
	b.items[k] = b.lru.PushFront(k)
	for b.lru.Len() > b.max {
		el := b.lru.Back()
		b.lru.Remove(el)
		delete(b.items, el.Value.(string))
	}
	b.dirty = true
	return false
}

// Len returns the number of keys.
func (b *Baseline) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lru.Len()
}

// Dirty reports whether keys were added since the last load or save.
func (b *Baseline) Dirty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dirty
}

func (b *Baseline) load() error {
	f, err := platform.OpenNoFollow(b.path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("baseline %s: not a regular file", b.path)
	}
	limit := int64(b.max)*(baselineKeyHex+1) + 128
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("baseline %s: larger than %d bytes", b.path, limit)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 128), 128)
	if !sc.Scan() {
		return fmt.Errorf("baseline %s: unknown format: %w", b.path, errBaselineStale)
	}
	switch h := sc.Text(); {
	case h == b.header():
	case strings.HasPrefix(h, baselineMagic+baselineVersion+" "):
		return fmt.Errorf("baseline %s: written under another identity key: %w", b.path, errBaselineStale)
	case h == baselineMagic+"1":
		return fmt.Errorf("baseline %s: format 1 (unkeyed digests): %w", b.path, errBaselineStale)
	default:
		return fmt.Errorf("baseline %s: unknown format: %w", b.path, errBaselineStale)
	}
	var keys []string
	for sc.Scan() {
		k := sc.Text()
		if !storedKey(k) {
			return fmt.Errorf("baseline %s: malformed key: %w", b.path, errBaselineStale)
		}
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("baseline %s: %w: %w", b.path, err, errBaselineStale)
	}
	if len(keys) > b.max {
		keys = keys[len(keys)-b.max:]
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range keys { // oldest first: each push makes it the newest
		if el, ok := b.items[k]; ok {
			b.lru.MoveToFront(el)
			continue
		}
		b.items[k] = b.lru.PushFront(k)
	}
	return nil
}

// Save writes the baseline to its file (no-op for an in-memory baseline).
func (b *Baseline) Save() error {
	if b.path == "" {
		return nil
	}
	b.mu.Lock()
	var buf bytes.Buffer
	buf.Grow(b.lru.Len()*(baselineKeyHex+1) + 64)
	buf.WriteString(b.header())
	buf.WriteByte('\n')
	for el := b.lru.Back(); el != nil; el = el.Prev() {
		buf.WriteString(el.Value.(string))
		buf.WriteByte('\n')
	}
	b.dirty = false
	b.mu.Unlock()

	dir := filepath.Dir(b.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.markDirty()
		return err
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, "."+filepath.Base(b.path)+".tmp-"+hex.EncodeToString(rnd[:]))
	// O_EXCL never follows a planted link at the temporary name.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		b.markDirty()
		return err
	}
	_, werr := f.Write(buf.Bytes())
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		b.markDirty()
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		os.Remove(tmp)
		b.markDirty()
		return err
	}
	return nil
}

func (b *Baseline) markDirty() {
	b.mu.Lock()
	b.dirty = true
	b.mu.Unlock()
}
