package spool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// Root is one user's spool directory as the daemon sees it.
type Root struct {
	Dir  string
	UID  string // expected owner of every file in Dir
	User event.User
}

// ReaderOptions configures the daemon-side reader.
type ReaderOptions struct {
	Roots           func() []Root
	Checkpoint      string        // JSON checkpoint file, written atomically
	MaxLine         int           // default MaxRecord
	PerUIDPerSecond int           // default 200 records per uid per second
	Retain          time.Duration // fully read files older than this are deleted (default 72h)
	Now             func() time.Time
}

// Problem is something the reader refused or noticed.
type Problem struct {
	Kind   string // forged_kind | owner_mismatch | symlink_refused | not_regular | oversize_line | rate_limited | malformed | truncated
	Path   string
	Detail string
}

// Reader ingests spool directories with at-least-once semantics: offsets
// advance only past lines that were returned.
type Reader struct {
	o       ReaderOptions
	mu      sync.Mutex
	ck      map[string]ckpt // key: path
	buckets map[string]*bucket
	loaded  bool
}

type ckpt struct {
	FileID string `json:"file_id"`
	Offset int64  `json:"offset"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewReader returns a Reader.
func NewReader(o ReaderOptions) *Reader {
	if o.MaxLine <= 0 {
		o.MaxLine = MaxRecord
	}
	if o.PerUIDPerSecond <= 0 {
		o.PerUIDPerSecond = 200
	}
	if o.Retain <= 0 {
		o.Retain = 72 * time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Reader{o: o, ck: map[string]ckpt{}, buckets: map[string]*bucket{}}
}

// Poll reads every complete new line from every root.
func (r *Reader) Poll(ctx context.Context) ([]*event.Event, []Problem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.loaded {
		r.load()
		r.loaded = true
	}
	var out []*event.Event
	var probs []Problem
	if r.o.Roots == nil {
		return nil, nil, nil
	}
	seen := map[string]bool{}
	for _, root := range r.o.Roots() {
		if ctx.Err() != nil {
			break
		}
		evs, ps := r.pollRoot(root, seen)
		out = append(out, evs...)
		probs = append(probs, ps...)
	}
	// Forget checkpoints of files that are gone.
	for p := range r.ck {
		if !seen[p] {
			delete(r.ck, p)
		}
	}
	return out, probs, r.save()
}

func (r *Reader) pollRoot(root Root, seen map[string]bool) ([]*event.Event, []Problem) {
	var out []*event.Event
	var probs []Problem
	ents, err := os.ReadDir(root.Dir)
	if err != nil {
		return nil, nil
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	b := r.bucket(root.UID)
	for _, de := range ents {
		name := de.Name()
		if !strings.HasSuffix(name, ".ndjson") || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(root.Dir, name)
		seen[path] = true
		if de.Type()&os.ModeSymlink != 0 {
			probs = append(probs, Problem{Kind: "symlink_refused", Path: path})
			continue
		}
		evs, ps, done := r.readFile(path, root, b)
		out = append(out, evs...)
		probs = append(probs, ps...)
		if done {
			r.maybeRetire(path)
		}
		if b.tokens < 1 {
			probs = append(probs, Problem{Kind: "rate_limited", Path: root.Dir, Detail: "per-uid limit reached; backlog left for the next poll"})
			break
		}
	}
	return out, probs
}

// readFile reads new complete lines. done reports that the file was read to
// its end.
func (r *Reader) readFile(path string, root Root, b *bucket) ([]*event.Event, []Problem, bool) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		switch {
		case errors.Is(err, platform.ErrSymlink):
			return nil, []Problem{{Kind: "symlink_refused", Path: path}}, false
		case errors.Is(err, platform.ErrNotRegular):
			return nil, []Problem{{Kind: "not_regular", Path: path}}, false
		}
		return nil, nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, false
	}
	if owner, ok := platform.OwnerUID(fi); ok && root.UID != "" && owner != root.UID {
		return nil, []Problem{{Kind: "owner_mismatch", Path: path, Detail: "owner " + owner + ", expected " + root.UID}}, false
	}
	id := platform.FileID(fi, "")
	c := r.ck[path]
	var probs []Problem
	if c.FileID != "" && id != "" && c.FileID != id {
		c = ckpt{} // replaced: a new file at the same name
	}
	if fi.Size() < c.Offset {
		probs = append(probs, Problem{Kind: "truncated", Path: path})
		c.Offset = 0
	}
	c.FileID = id
	if fi.Size() == c.Offset {
		r.ck[path] = c
		return nil, probs, true
	}
	if _, err := f.Seek(c.Offset, io.SeekStart); err != nil {
		return nil, probs, false
	}
	// Read in bounded chunks; never past the last LF.
	var out []*event.Event
	buf := make([]byte, 0, 64<<10)
	chunk := make([]byte, 64<<10)
	off := c.Offset
	skipping := false
	for {
		n, rerr := f.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			line := buf[:i]
			consumed := int64(i + 1)
			if skipping {
				skipping = false
			} else if len(line) > r.o.MaxLine {
				probs = append(probs, Problem{Kind: "oversize_line", Path: path})
			} else if len(line) > 0 {
				if b.tokens < 1 {
					// Leave the rest for the next poll.
					c.Offset = off
					r.ck[path] = c
					return out, probs, false
				}
				b.tokens--
				ev, p := decode(line, root, path)
				if p != nil {
					probs = append(probs, *p)
				} else if ev != nil {
					out = append(out, ev)
				}
			}
			off += consumed
			buf = buf[i+1:]
		}
		if len(buf) > r.o.MaxLine {
			// A line still without LF that is already too long: drop what we
			// have and skip to its end.
			probs = append(probs, Problem{Kind: "oversize_line", Path: path})
			off += int64(len(buf))
			buf = buf[:0]
			skipping = true
		}
		if rerr != nil || n == 0 {
			break
		}
	}
	c.Offset = off
	r.ck[path] = c
	return out, probs, off >= fi.Size()
}

// decode turns one line into an activity event with identity taken from
// the file, or a Problem.
func decode(line []byte, root Root, path string) (*event.Event, *Problem) {
	var rec record
	if err := json.Unmarshal(line, &rec); err != nil || rec.Event == nil {
		return nil, &Problem{Kind: "malformed", Path: path}
	}
	e := rec.Event
	if e.Kind != event.KindActivity {
		return nil, &Problem{Kind: "forged_kind", Path: path, Detail: "kind " + clipStr(string(e.Kind), 32) + " is not accepted from a user spool"}
	}
	u := root.User
	e.User = &u
	e.Host = nil
	e.Integrity = event.IntegrityUser
	e.Writer = "hook-" + root.UID
	e.Detection, e.Health, e.Asset, e.Check, e.Summary = nil, nil, nil, nil, nil
	if e.Source == "" {
		e.Source = event.SourceHook
	}
	if c := rec.Content; c != nil {
		e.Content = &event.Content{PromptText: c.PromptText, ToolInput: c.ToolInput, ToolOutput: c.ToolOutput, FileContent: c.FileContent}
	}
	return e, nil
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// bucket returns the token bucket for uid, refilled for elapsed time.
func (r *Reader) bucket(uid string) *bucket {
	now := r.o.Now()
	b := r.buckets[uid]
	rate := float64(r.o.PerUIDPerSecond)
	if b == nil {
		b = &bucket{tokens: rate, last: now}
		r.buckets[uid] = b
		return b
	}
	el := now.Sub(b.last).Seconds()
	if el > 0 {
		b.tokens += el * rate
		if b.tokens > rate {
			b.tokens = rate
		}
		b.last = now
	}
	return b
}

// maybeRetire deletes a fully read file once it is older than Retain. Only a
// regular file is removed; Remove on a name never follows a symlink.
func (r *Reader) maybeRetire(path string) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if r.o.Now().Sub(fi.ModTime()) < r.o.Retain {
		return
	}
	if os.Remove(path) == nil {
		delete(r.ck, path)
	}
}

func (r *Reader) load() {
	if r.o.Checkpoint == "" {
		return
	}
	f, err := platform.OpenNoFollow(r.o.Checkpoint)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return
	}
	var m map[string]ckpt
	if json.Unmarshal(b, &m) == nil && m != nil {
		r.ck = m
	}
}

func (r *Reader) save() error {
	if r.o.Checkpoint == "" {
		return nil
	}
	b, err := json.Marshal(r.ck)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.o.Checkpoint), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(r.o.Checkpoint, b, 0o600)
}
