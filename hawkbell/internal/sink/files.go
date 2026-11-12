package sink

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// FilesOptions configures the Files sink. Zero values select the defaults.
type FilesOptions struct {
	Dir          string        // segments are <Dir>/<stream>-<YYYYMMDD>-<HH>-<n>.ndjson
	MaxSegment   int64         // roll to n+1 past this size (default 16 MiB)
	RetainBytes  int64         // prune oldest segments beyond this total (default 512 MiB; negative: no size limit)
	RetainAge    time.Duration // prune segments older than this (default 7 days; negative: no age limit)
	MaxLineBytes int           // events larger than this are shrunk (drop tool.input/output, then target.command tail) and marked truncated; default 16 KiB, see defaultMaxLineBytes
	FileMode     os.FileMode   // default 0640
	Format       string        // native | ocsf
	Now          func() time.Time
}

const (
	defaultMaxSegment  = 16 << 20
	defaultRetainBytes = 512 << 20
	defaultRetainAge   = 7 * 24 * time.Hour
	// defaultMaxLineBytes is the zero value's line cap. It equals the
	// operator default, output.max_line_bytes (internal/config: 16 KiB,
	// 8-64 KiB accepted); the daemon and `hawkbell scan` always pass that
	// setting, so the zero value only serves callers that set nothing, such
	// as tests. The largest accepted value, 64 KiB, is far below the
	// buffer_max_size of 1M the shipped Fluent Bit tail inputs set
	// (deploy/fluent-bit/hawkbell-inputs.yaml).
	defaultMaxLineBytes = 16 << 10
	defaultFileMode     = 0o640
	// minMaxLineBytes is the smallest accepted MaxLineBytes: the last-resort
	// shrink step (identity fields only, each clipped) always fits in it, in
	// either line format.
	minMaxLineBytes = 8192
	// maxOpenTries bounds how far openSegment walks past segments that are
	// full or unusable before giving up.
	maxOpenTries = 32
)

var errNotAppendable = errors.New("not a regular single-link file")

// filesSink implements the Files sink.
//
// Contract with readers (Fluent Bit tail, the Shipper, a human with jq):
// one event is one write(2) of one complete line on a descriptor opened
// O_APPEND, so lines from concurrent processes never interleave; files are
// never renamed, truncated or rewritten; retention deletes whole segments
// only.
type filesSink struct {
	o FilesOptions

	mu     sync.Mutex
	open   map[string]*openSegment // by stream
	closed bool
	// dirDirty is set when this process created a segment: the new
	// directory entry is not durable until the directory itself is synced.
	dirDirty bool
}

type openSegment struct {
	f     *os.File
	seg   segment
	dirty bool // written since the last fsync
	// torn is set when a write failed part way (disk full): a fragment
	// without a newline is at the end of the file, and the next line must
	// start with one or it would be glued to the fragment and lost with it.
	torn bool
}

// NewFiles returns the Files sink: append-only NDJSON segments, the durable
// local log and the Fluent Bit contract. The directory is created if needed.
//
// Several processes may append to the same directory, and to the same
// segment, at once (the daemon, and one short-lived process per agent hook).
// They coordinate through the directory alone: a writer appends to the
// highest-numbered segment of the current hour and moves to the next number
// once that file has reached MaxSegment, so every writer makes the same
// choice without shared memory or locks.
//
// The returned Sink also implements Pruner.
func NewFiles(o FilesOptions) (Sink, error) {
	if o.Dir == "" {
		return nil, errors.New("sink files: Dir is required")
	}
	f, err := checkFormat(o.Format)
	if err != nil {
		return nil, err
	}
	o.Format = f
	if o.MaxSegment <= 0 {
		o.MaxSegment = defaultMaxSegment
	}
	if o.RetainBytes == 0 {
		o.RetainBytes = defaultRetainBytes
	}
	if o.RetainAge == 0 {
		o.RetainAge = defaultRetainAge
	}
	if o.MaxLineBytes == 0 {
		o.MaxLineBytes = defaultMaxLineBytes
	}
	if o.MaxLineBytes < minMaxLineBytes {
		return nil, fmt.Errorf("sink files: MaxLineBytes %d is below the minimum %d", o.MaxLineBytes, minMaxLineBytes)
	}
	if o.FileMode == 0 {
		o.FileMode = defaultFileMode
	}
	o.FileMode &= os.ModePerm
	if o.Now == nil {
		o.Now = time.Now
	}
	// Whoever may read the files must be able to traverse the directory.
	dirMode := o.FileMode | 0o700 | (o.FileMode&0o444)>>2
	if err := os.MkdirAll(o.Dir, dirMode); err != nil {
		return nil, fmt.Errorf("sink files: %w", err)
	}
	if fi, err := os.Stat(o.Dir); err != nil {
		return nil, fmt.Errorf("sink files: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("sink files: %s is not a directory", o.Dir)
	}
	return &filesSink{o: o, open: make(map[string]*openSegment)}, nil
}

func (s *filesSink) Name() string { return "files" }

// Write appends each event as one line. A failure on one event does not stop
// the rest of the batch; the returned error reports how many were not
// written.
func (s *filesSink) Write(batch []*event.Event) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink files: %v", r)
		}
	}()
	if s.closed {
		return ErrClosed
	}
	var first error
	failed := 0
	for _, e := range batch {
		if e == nil {
			continue
		}
		line, werr := fitLine(e, s.o.Format, s.o.MaxLineBytes)
		if werr == nil {
			werr = s.appendLine(e.Kind.Stream(), line)
		}
		if werr != nil {
			failed++
			if first == nil {
				first = werr
			}
		}
	}
	if first != nil {
		return fmt.Errorf("sink files: %d of %d events not written: %w", failed, len(batch), first)
	}
	return nil
}

func (s *filesSink) appendLine(stream string, line []byte) error {
	bucket := s.o.Now().UTC().Truncate(time.Hour)
	seg := s.open[stream]
	if seg != nil && !s.usable(seg, bucket) {
		s.closeSegment(stream)
		seg = nil
	}
	if seg == nil {
		var err error
		if seg, err = s.openSegment(stream, bucket); err != nil {
			return err
		}
		s.open[stream] = seg
	}
	if seg.torn {
		line = append([]byte{'\n'}, line...)
	}
	n, err := seg.f.Write(line)
	if err != nil {
		seg.torn = seg.torn || n > 0
		return err
	}
	seg.torn = false
	seg.dirty = true
	return nil
}

// usable reports whether a cached handle may take one more line. The size
// comes from fstat, so appends by other processes count; that is what makes
// every writer leave a full segment at the same moment.
func (s *filesSink) usable(seg *openSegment, bucket time.Time) bool {
	if !seg.seg.bucket.Equal(bucket) {
		return false
	}
	fi, err := seg.f.Stat()
	if err != nil {
		return false
	}
	return fi.Size() < s.o.MaxSegment && linkCount(fi) == 1
}

// openSegment picks the segment to append to by listing the directory: the
// highest-numbered segment of this stream and hour, or the next number when
// that one is full or cannot be appended to. In-memory state is never
// trusted for the choice because other processes roll segments too.
func (s *filesSink) openSegment(stream string, bucket time.Time) (*openSegment, error) {
	segs, err := listSegments(s.o.Dir, hourPrefix(stream, bucket))
	if err != nil {
		return nil, err
	}
	n := 1
	for _, g := range segs {
		if g.stream == stream && g.bucket.Equal(bucket) && g.n > n {
			n = g.n
		}
	}
	var last error
	for tries := 0; tries < maxOpenTries; tries, n = tries+1, n+1 {
		if n > maxSegmentN {
			return nil, fmt.Errorf("segment counter exhausted for %s", stream)
		}
		name := SegmentName(stream, bucket, n)
		path := filepath.Join(s.o.Dir, name)
		f, created, err := openAppend(path, s.o.FileMode)
		if err != nil {
			// If something exists under the name but cannot be appended to
			// (a symlink, a directory, a FIFO, another user's file), step
			// over it. Anything else (no space, no permission on the
			// directory) will not get better at n+1.
			if _, lerr := os.Lstat(path); lerr != nil {
				return nil, err
			}
			last = err
			continue
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() || linkCount(fi) != 1 {
			f.Close()
			if err == nil {
				err = fmt.Errorf("%s: %w", name, errNotAppendable)
			}
			last = err
			continue
		}
		if fi.Size() >= s.o.MaxSegment {
			f.Close()
			continue
		}
		seg := &openSegment{f: f, seg: segment{name: name, stream: stream, bucket: bucket, n: n}}
		if created {
			s.dirDirty = true
			// Retention runs when the log grows by a file, which is the
			// only time the total can newly exceed a limit. Best effort: a
			// failed prune must not cost the event being written.
			_ = s.prune()
		}
		return seg, nil
	}
	if last == nil {
		last = errors.New("no appendable segment found")
	}
	return nil, fmt.Errorf("open segment for %s: %w", stream, last)
}

// closeSegment closes a segment this writer is done with (full, or its
// hour is over), syncing it first if needed since no later Flush will.
func (s *filesSink) closeSegment(stream string) error {
	seg := s.open[stream]
	if seg == nil {
		return nil
	}
	delete(s.open, stream)
	var err error
	if seg.dirty {
		err = seg.f.Sync()
	}
	if cerr := seg.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Flush fsyncs every segment written since the last Flush, and the
// directory if a segment was created.
func (s *filesSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.sync()
}

func (s *filesSink) sync() error {
	var errs []error
	for _, seg := range s.open {
		if !seg.dirty {
			continue
		}
		if err := seg.f.Sync(); err != nil {
			errs = append(errs, err)
			continue
		}
		seg.dirty = false
	}
	if s.dirDirty {
		if err := syncDir(s.o.Dir); err != nil {
			errs = append(errs, err)
		} else {
			s.dirDirty = false
		}
	}
	return errors.Join(errs...)
}

// Close closes all segments. It is idempotent.
//
// Close does not fsync. Every line is already in the kernel when Write
// returns, so nothing is lost when the process exits; what fsync adds is
// survival of a power cut, at the price of a disk flush. A hook process
// writes one event and exits between an agent and its tool call, where that
// price would be paid on every call. Callers that want durability call
// Flush before Close, as the daemon does on a timer and at shutdown.
func (s *filesSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for stream, seg := range s.open {
		seg.dirty = false
		if err := s.closeSegment(stream); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Prune enforces RetainAge and RetainBytes now.
func (s *filesSink) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.prune()
}

// prune deletes whole segments, oldest first, and nothing else.
//
// Age is taken from the hour in the file name, not from mtime: appends only
// happen during that hour, and mtime can be refreshed by anything that
// touches the file. A segment named for a future hour (the clock was wrong
// when it was written) sorts first for size pruning, otherwise it would be
// kept forever while real data is deleted to make room for it.
//
// The newest segment of each stream is never deleted, whatever the limits
// say: it is the one writers hold open.
func (s *filesSink) prune() error {
	now := s.o.Now().UTC()
	segs, err := listSegments(s.o.Dir, "")
	if err != nil {
		return err
	}
	kept := segs[:0]
	for _, g := range segs {
		fi, err := os.Lstat(filepath.Join(s.o.Dir, g.name))
		if err != nil || !fi.Mode().IsRegular() {
			continue // not ours to count or delete
		}
		g.size = fi.Size()
		kept = append(kept, g)
	}
	segs = kept
	future := func(g segment) bool { return g.bucket.After(now.Add(time.Hour)) }
	sortSegments(segs)

	newest := make(map[string]string, len(event.Streams))
	for _, g := range segs { // ascending, so the last one per stream wins
		if !future(g) {
			newest[g.stream] = g.name
		}
	}
	// Deletion order: misdated segments first, then oldest to newest.
	order := make([]segment, 0, len(segs))
	for _, g := range segs {
		if future(g) {
			order = append(order, g)
		}
	}
	for _, g := range segs {
		if !future(g) {
			order = append(order, g)
		}
	}

	var total int64
	for _, g := range order {
		total += g.size
	}
	var errs []error
	remove := func(g segment) bool {
		if err := os.Remove(filepath.Join(s.o.Dir, g.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			return false
		}
		total -= g.size
		return true
	}
	rest := order[:0]
	for _, g := range order {
		expired := s.o.RetainAge > 0 && !future(g) && g.bucket.Add(time.Hour).Before(now.Add(-s.o.RetainAge))
		if expired && newest[g.stream] != g.name && remove(g) {
			continue
		}
		rest = append(rest, g)
	}
	if s.o.RetainBytes > 0 {
		for _, g := range rest {
			if total <= s.o.RetainBytes {
				break
			}
			if newest[g.stream] == g.name {
				continue
			}
			remove(g)
		}
	}
	return errors.Join(errs...)
}
