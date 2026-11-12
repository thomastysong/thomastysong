package transcript

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Root is one place to look for session logs.
type Root struct {
	// Glob selects the files. "*" and "?" match within one path segment,
	// "**" matches zero or more directories. The leading segments without
	// wildcards are the root's base: symbolic links are never followed
	// below it.
	Glob string
	// Parser reads the matched files; nil picks the first built-in parser
	// whose Match accepts each path.
	Parser Parser
	// User is stamped on every event. When User.ID is set (uid on POSIX,
	// SID on Windows), a file owned by a different account is refused
	// (owner_mismatch), checked on the open descriptor.
	User event.User
	// Base optionally widens the no-symlink zone. When set to an ancestor
	// of the glob's fixed prefix (typically the user's home directory),
	// every directory between Base and the matched file must be a real
	// directory: a ~/.claude that is itself a link is refused and reported.
	// Leave it empty where such links are legitimate.
	Base string
}

// TailerOptions configures a Tailer.
type TailerOptions struct {
	Roots       func() []Root          // enumerated on every discovery pass: {Path glob, Parser, User}
	StateFile   string                 // JSON checkpoint store, written atomically; "" keeps checkpoints in memory only
	MaxLine     int                    // default 8 MiB; longer lines are skipped and counted
	FromStart   bool                   // first sight of a file: read from start (backfill) or from end
	MaxBackfill time.Duration          // ignore files not modified within this window on first sight (default 24h)
	AllowUID    func(path string) bool // ownership check hook (root daemon must refuse files not owned by the home's user)

	// MaxPollBytes bounds how much one Poll reads, and so how many events
	// it can return (default 64 MiB). A file with more to read continues
	// on the next Poll.
	MaxPollBytes int64
	// DeferCommit makes Poll leave the checkpoint store untouched until
	// Commit is called. Call Commit after the returned events are durably
	// handed on: a crash in between then re-reads them instead of losing
	// them, with the same event ids as long as the line key survives too
	// (IdentityKey, or the key file beside StateFile; see Line keys).
	DeferCommit bool

	// IdentityKey keys the ids of records the log gives no id of its own
	// (Codex records, Claude Code bookkeeping records): they are an HMAC
	// of the line under a key derived from it. Pass a key the caller keeps
	// across restarts (the daemon's identity key), at least 16 bytes.
	// Empty: with a StateFile, a key kept in StateFile+KeyFileSuffix,
	// created on first use; without one, a key drawn once per process.
	IdentityKey []byte

	now func() time.Time // test clock
}

// Problem kinds.
const (
	ProblemTruncated      = "truncated"
	ProblemReplaced       = "replaced"
	ProblemDeleted        = "deleted"
	ProblemUnreadable     = "unreadable"
	ProblemSchemaDrift    = "schema_drift"
	ProblemSymlinkRefused = "symlink_refused"
	ProblemOwnerMismatch  = "owner_mismatch"
)

// Problem reports something wrong with a session log.
type Problem struct {
	Kind      string // truncated | replaced | deleted | unreadable | schema_drift | symlink_refused | owner_mismatch
	Path      string
	SessionID string
	Detail    string
}

const (
	defaultMaxLine      = 8 << 20
	defaultMaxBackfill  = 24 * time.Hour
	defaultMaxPollBytes = 64 << 20
	// primeBytes is how much of a file's head is parsed, events discarded,
	// to learn the session identity when reading starts mid-file.
	primeBytes = 256 << 10
	// orphanGrace is how long a checkpoint outlives its root: roots come
	// from user enumeration, which can fail transiently, and dropping the
	// checkpoint at once would re-read the file when the root returns.
	orphanGrace = 7 * 24 * time.Hour
	// lazyWindow: see statLazy.
	lazyWindow = 48 * time.Hour
	// driftMinLines is the sample size before unknown records are called
	// schema drift.
	driftMinLines = 20
)

// tracked is one followed file.
type tracked struct {
	path     string
	format   string
	cp       Checkpoint
	tail     string // fingerprint of the bytes before cp.Offset
	skipping bool   // cp.Offset is inside a line that must be discarded
	more     bool   // complete lines were left unread (byte budget)
	drift    bool   // schema_drift already reported
	lazy     bool   // adopted from metadata alone; not yet opened or primed
	lastSeen int64  // Unix seconds, last discovery
	lastRead int64  // Unix seconds, last time bytes were consumed
	st       *FileState
}

// Tailer follows session logs across polls.
type Tailer struct {
	o TailerOptions

	mu       sync.Mutex
	loaded   bool
	key      []byte // line key (keyfile.go), resolved by the first Poll
	files    map[string]*tracked
	reported map[string]string // path -> standing problem already reported
	dirty    bool
	rr       int
}

// NewTailer returns a Tailer. Nothing is read until the first Poll, which
// also loads (or creates) the line key.
func NewTailer(o TailerOptions) *Tailer {
	if o.MaxLine <= 0 {
		o.MaxLine = defaultMaxLine
	}
	if o.MaxBackfill <= 0 {
		o.MaxBackfill = defaultMaxBackfill
	}
	if o.MaxPollBytes <= 0 {
		o.MaxPollBytes = defaultMaxPollBytes
	}
	if o.now == nil {
		o.now = time.Now
	}
	o.IdentityKey = bytes.Clone(o.IdentityKey) // the caller's slice may change
	return &Tailer{o: o, files: map[string]*tracked{}, reported: map[string]string{}}
}

// newState returns the parser state of a newly followed or restarted file.
func (t *Tailer) newState(path string, user *event.User) *FileState {
	return &FileState{Path: path, user: user, key: t.key}
}

// pass is the state of one Poll.
type pass struct {
	ctx    context.Context
	now    time.Time
	budget int64
	evs    []*event.Event
	probs  []Problem
}

func (p *pass) problem(kind, path, session, detail string) {
	p.probs = append(p.probs, Problem{Kind: kind, Path: path, SessionID: session, Detail: detail})
}

type work struct {
	candidate
	parser Parser
	user   event.User
}

// Poll runs one discovery pass and reads what is new. It reads only complete
// (LF-terminated) lines, advances checkpoints, and reports truncation (size
// below the checkpoint, or content before it rewritten), replacement (file
// id changed) and deletion of a log it was following as Problems.
//
// Events and problems gathered before an error are returned together with
// it and must still be processed: their checkpoints have advanced. The
// error is the context's when it was cancelled, or a checkpoint store
// failure.
func (t *Tailer) Poll(ctx context.Context) (evs []*event.Event, probs []Problem, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := &pass{ctx: ctx, now: t.o.now(), budget: t.o.MaxPollBytes}
	defer func() {
		if r := recover(); r != nil {
			evs, probs = p.evs, p.probs
			err = fmt.Errorf("transcript: tailer recovered from panic: %v", r)
		}
	}()
	if !t.loaded {
		t.load(p)
	}

	todo, listed, complete := t.discover(p)
	found := make(map[string]bool, len(todo))
	for i := range todo {
		found[todo[i].path] = true
	}
	t.adoptRenames(todo, found)

	// Rotate the starting point so a file that eats the byte budget cannot
	// starve the ones sorted after it poll after poll.
	if n := len(todo); n > 0 {
		start := t.rr % n
		t.rr++
		for i := 0; i < n && ctx.Err() == nil; i++ {
			t.process(p, &todo[(start+i)%n])
		}
	}
	// A partial listing proves nothing about what is missing.
	if complete && ctx.Err() == nil {
		t.reap(p, found)
		t.forget(listed)
	}

	evs, probs = p.evs, p.probs
	if t.dirty && !t.o.DeferCommit {
		if serr := t.save(); serr != nil {
			return evs, probs, fmt.Errorf("transcript: saving checkpoints: %w", serr)
		}
	}
	return evs, probs, ctx.Err()
}

// Commit writes the checkpoint store. It is only needed with DeferCommit.
func (t *Tailer) Commit() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty {
		return nil
	}
	return t.save()
}

// Checkpoints returns the current checkpoint of every followed file.
func (t *Tailer) Checkpoints() map[string]Checkpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Checkpoint, len(t.files))
	for p, tr := range t.files {
		out[p] = tr.cp
	}
	return out
}

// State returns a copy of a followed file's parser state (identity and
// counters; pending calls are not included).
func (t *Tailer) State(path string) (FileState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tr := t.files[path]
	if tr == nil || tr.st == nil {
		return FileState{}, false
	}
	s := tr.st
	out := FileState{
		Path: s.Path, SessionID: s.SessionID, ParentSessionID: s.ParentSessionID, CWD: s.CWD,
		Model: s.Model, Version: s.Version, PermissionMode: s.PermissionMode,
		Unknown: s.Unknown, Malformed: s.Malformed, Lines: s.Lines, Oversize: s.Oversize,
	}
	if len(s.Extra) > 0 {
		out.Extra = make(map[string]string, len(s.Extra))
		for k, v := range s.Extra {
			out.Extra[k] = v
		}
	}
	return out, true
}

func (t *Tailer) load(p *pass) {
	t.loaded = true
	var prob *Problem
	if t.key, prob = t.resolveKey(); prob != nil {
		p.probs = append(p.probs, *prob)
	}
	sf, err := readStore(t.o.StateFile)
	if err != nil {
		// Start empty rather than refuse to run; the gap is reported.
		p.problem(ProblemUnreadable, t.o.StateFile, "", "checkpoint store: "+err.Error())
		return
	}
	for path, e := range sf.Files {
		t.files[path] = &tracked{
			path: path, format: e.Format, cp: e.Checkpoint, tail: e.Tail,
			skipping: e.Skipping, more: e.More, drift: e.Drift, lazy: e.State == nil && e.Offset > 0,
			lastSeen: e.LastSeen, lastRead: e.LastRead, st: loadState(e.State, path),
		}
		t.files[path].st.key = t.key
	}
}

func (t *Tailer) save() error {
	sf := &storeFile{Version: storeVersion, Files: make(map[string]*savedEntry, len(t.files))}
	for path, tr := range t.files {
		e := &savedEntry{
			Checkpoint: tr.cp, Format: tr.format, Tail: tr.tail, Skipping: tr.skipping,
			More: tr.more, Drift: tr.drift, LastSeen: tr.lastSeen, LastRead: tr.lastRead,
		}
		if !tr.lazy {
			e.State = saveState(tr.st)
		}
		sf.Files[path] = e
	}
	if err := writeStore(t.o.StateFile, sf); err != nil {
		return err
	}
	t.dirty = false
	return nil
}

// discover expands every root. complete is false when a walk was cut short,
// in which case absence from the result means nothing.
func (t *Tailer) discover(p *pass) (todo []work, listed map[string]bool, complete bool) {
	complete = true
	var roots []Root
	if t.o.Roots != nil {
		roots = t.o.Roots()
	}
	seen := map[string]bool{}
	listed = seen
	for i, r := range roots {
		if r.Glob == "" {
			continue
		}
		base, segs := splitGlob(r.Glob)
		trust, ok := t.trustBase(p, r.Base, base)
		if !ok {
			continue
		}
		w := &walker{ctx: p.ctx, root: i, base: trust}
		if len(segs) == 0 {
			dir, name := filepath.Split(base)
			if r.Base == "" {
				w.base = filepath.Clean(dir)
			}
			w.consider(filepath.Clean(dir), name)
		} else {
			w.walk(base, segs, 0)
			if w.stopped {
				complete = false
			}
		}
		cands := w.out
		for _, c := range cands {
			if seen[c.path] {
				continue
			}
			parser := r.Parser
			if parser == nil {
				parser, _ = ForPath(c.path)
			}
			if parser == nil || !parser.Match(c.path) {
				continue
			}
			seen[c.path] = true
			if c.symlink {
				t.standing(p, ProblemSymlinkRefused, c.path, "", "session log path is a symbolic link")
				continue
			}
			todo = append(todo, work{candidate: c, parser: parser, user: r.User})
		}
	}
	if p.ctx.Err() != nil {
		complete = false
	}
	sort.Slice(todo, func(a, b int) bool { return todo[a].path < todo[b].path })
	return todo, listed, complete
}

// forget drops standing problems about paths that no longer exist, so the
// same condition is reported again if it comes back.
func (t *Tailer) forget(listed map[string]bool) {
	for path := range t.reported {
		if listed[path] || t.files[path] != nil || path == t.o.StateFile {
			continue
		}
		if _, err := lstatMeta(path); errors.Is(err, os.ErrNotExist) {
			delete(t.reported, path)
		}
	}
}

// trustBase returns the directory below which symlinks are refused for a
// root: the glob's fixed prefix, or Root.Base when it is an ancestor of it.
// In the second case the directories from Base down to the prefix are
// checked here; ok is false when one of them is a link (reported) or missing.
func (t *Tailer) trustBase(p *pass, rootBase, globBase string) (trust string, ok bool) {
	if rootBase == "" {
		return globBase, true
	}
	rb := filepath.Clean(rootBase)
	rel, err := filepath.Rel(rb, globBase)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return globBase, true // Base is not an ancestor: it constrains nothing
	}
	at := rb
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			at = filepath.Join(at, part)
			m, err := lstatMeta(at)
			switch {
			case err != nil:
				return "", false
			case m.symlink:
				t.standing(p, ProblemSymlinkRefused, at, "", "a directory on the way to the session logs is a symbolic link")
				return "", false
			case !m.dir:
				return "", false
			}
			delete(t.reported, at)
		}
	}
	return rb, true
}

// standing reports a condition once and stays quiet while it persists.
func (t *Tailer) standing(p *pass, kind, path, session, detail string) {
	if t.reported[path] == kind {
		return
	}
	t.reported[path] = kind
	p.problem(kind, path, session, detail)
}

// adoptRenames moves the checkpoint of a file that changed path (Codex moves
// rollouts to archived_sessions/) so the move is neither a deletion nor a
// new file to backfill.
func (t *Tailer) adoptRenames(todo []work, found map[string]bool) {
	var gone map[string]*tracked
	for path, tr := range t.files {
		if found[path] || tr.cp.FileID == "" {
			continue
		}
		if gone == nil {
			gone = map[string]*tracked{}
		}
		gone[tr.cp.FileID] = tr
	}
	if gone == nil {
		return
	}
	for i := range todo {
		w := &todo[i]
		if t.files[w.path] != nil || w.meta.id == "" {
			continue
		}
		tr := gone[w.meta.id]
		if tr == nil || tr.format != formatOf(w.parser) {
			continue
		}
		if _, err := lstatMeta(tr.path); !errors.Is(err, os.ErrNotExist) {
			continue // the old path still exists: a hard link, not a move
		}
		delete(t.files, tr.path)
		delete(gone, w.meta.id)
		tr.path = w.path
		if tr.st != nil {
			tr.st.Path = w.path
		}
		t.files[w.path] = tr
		t.dirty = true
	}
}
