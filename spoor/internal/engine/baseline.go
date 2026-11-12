package engine

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/thomastysong/spoor/internal/platform"
)

// Baseline is the persistent first-seen store behind rules novelty blocks
// (rules.Options.Baseline; BUILD-C C2 item 7). Rules ask it whether a key
// (a digest of the rule id and the novelty fields, for example the account
// and the egress host, or the account and an MCP server definition hash)
// has been seen before. It is an LRU of at most max keys, kept in a file
// under the checkpoint directory so a daemon restart does not make every
// host look new again.
//
// The file holds digests only: a header line, then one key per line,
// least recently used first. Keys that are not short lower-case hex are
// stored as the first 24 hex digits of their SHA-256, so the file never
// carries a host name or a path. It is replaced atomically (temporary file
// and rename), opened without following symbolic links, and read with a
// size cap; a damaged file is discarded, because the baseline is a cache
// whose loss only makes things look new (more attention, never less).
type Baseline struct {
	mu    sync.Mutex
	path  string
	max   int
	lru   *list.List // front = most recent
	items map[string]*list.Element
	dirty bool
}

const baselineHeader = "spoor-baseline 1"

// OpenBaseline loads the baseline at path ("" keeps it in memory only).
// It always returns a usable Baseline; the error reports a file that could
// not be read and was ignored.
func OpenBaseline(path string, max int) (*Baseline, error) {
	if max <= 0 {
		max = BaselineKeys
	}
	b := &Baseline{path: path, max: max, lru: list.New(), items: map[string]*list.Element{}}
	if path == "" {
		return b, nil
	}
	err := b.load()
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return b, err
}

func normKey(k string) string {
	if n := len(k); n > 0 && n <= 64 {
		hexOK := true
		for i := 0; i < n; i++ {
			c := k[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				hexOK = false
				break
			}
		}
		if hexOK {
			return k
		}
	}
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:12])
}

// Seen records key and reports whether it had been recorded before.
func (b *Baseline) Seen(key string) bool {
	k := normKey(key)
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
	limit := int64(b.max)*70 + 64
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("baseline %s: larger than %d bytes", b.path, limit)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 128), 128)
	if !sc.Scan() || sc.Text() != baselineHeader {
		return fmt.Errorf("baseline %s: unknown format", b.path)
	}
	var keys []string
	for sc.Scan() {
		k := sc.Text()
		if normKey(k) != k {
			return fmt.Errorf("baseline %s: malformed key", b.path)
		}
		keys = append(keys, k)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("baseline %s: %w", b.path, err)
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
	buf.Grow(b.lru.Len()*26 + 32)
	buf.WriteString(baselineHeader)
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
