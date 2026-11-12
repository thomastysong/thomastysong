package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// ShipperOptions configures a Shipper.
type ShipperOptions struct {
	Dir        string        // the Files sink directory to tail
	Checkpoint string        // state file; default <Dir>/.shipper-<sink name>.checkpoint
	Batch      int           // most events per Write (default 500)
	Interval   time.Duration // poll interval when idle (default 1s)
}

const (
	defaultShipBatch    = 500
	defaultShipInterval = time.Second
	// maxShipLine is the longest line the shipper will parse. The Files
	// sink never writes one longer than its MaxLineBytes (16 KiB by
	// default, 64 KiB at most through output.max_line_bytes), so anything
	// near this size was not written by hawkbell.
	maxShipLine = 1 << 20
	// shipWindow is how much of a segment is read per batch. It must exceed
	// maxShipLine so a window always holds at least one whole line or
	// proves the line is oversize.
	shipWindow = 4 << 20
	// maxBatchBytes closes a batch early so one request stays far below
	// Fluent Bit's forward buffer_max_size and typical HTTP body limits.
	maxBatchBytes = 2 << 20
	// fingerprintLen is how many leading bytes identify a segment file.
	fingerprintLen = 256
	maxCheckpoint  = 16 << 20
)

// ShipperStats is a snapshot of a Shipper's counters.
type ShipperStats struct {
	Shipped  uint64 // events acknowledged by the destination
	Batches  uint64 // successful Write calls
	BadLines uint64 // lines skipped: blank excluded; not JSON, not an event, oversize or torn
	Dropped  uint64 // events the destination refused permanently (see IsPermanent)
	Errors   uint64 // failed delivery or I/O attempts
	Resets   uint64 // times the checkpoint was unreadable and shipping restarted from the oldest segment
	Backlog  int64  // bytes on disk not yet shipped, as of the last poll
	// LastError is the text of the most recent failure. It is not cleared
	// by later successes; watch Errors and Backlog to see whether a problem
	// is ongoing.
	LastError string
}

// Shipper tails the Files segments and feeds a network Sink with
// at-least-once delivery, so the file log is the only queue.
//
// State is one offset per segment file, saved atomically after the
// destination accepted a batch. A crash between the accept and the save
// resends at most that one batch. Offsets are kept per file rather than as a
// single cursor because several processes append to the directory and the
// clock can step backwards: any existing segment may grow, and each is
// checked on every poll. A file is recognized by name plus a hash of its
// first bytes, so a segment that was pruned and later recreated under the
// same name starts again from zero instead of inheriting a stale offset.
type Shipper struct {
	o   ShipperOptions
	dst Sink

	// Tunables, fixed after NewShipper; tests shorten them.
	maxBackoff time.Duration
	// tornGrace is how long an unterminated tail may sit at the end of a
	// segment before it is declared a torn write and skipped. A healthy
	// writer finishes a line in microseconds.
	tornGrace time.Duration

	files  map[string]*fileCursor
	loaded bool
	dirty  bool
	buf    []byte
	// proven and dropsInARow gate the dropping of refused events.
	proven      bool
	dropsInARow int

	mu    sync.Mutex
	stats ShipperStats
}

// NewShipper returns a Shipper that reads segments from o.Dir and writes to
// dst. Call Run to start it. The Shipper does not close dst.
func NewShipper(o ShipperOptions, dst Sink) *Shipper {
	if o.Batch <= 0 {
		o.Batch = defaultShipBatch
	}
	if o.Interval <= 0 {
		o.Interval = defaultShipInterval
	}
	if o.Checkpoint == "" && o.Dir != "" {
		name := "sink"
		if dst != nil {
			name = safeString(dst.Name(), 32)
		}
		o.Checkpoint = filepath.Join(o.Dir, ".shipper-"+name+".checkpoint")
	}
	return &Shipper{
		o:          o,
		dst:        dst,
		maxBackoff: 30 * time.Second,
		tornGrace:  30 * time.Second,
		files:      make(map[string]*fileCursor),
	}
}

// Stats returns a snapshot of the counters. Safe to call while Run runs.
func (s *Shipper) Stats() ShipperStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Shipper) count(f func(*ShipperStats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

// Run ships until ctx is cancelled, then returns nil. It returns an error
// only for unusable options. Run must not be called concurrently on one
// Shipper, and two Shippers must not share a checkpoint file. Delivery and I/O failures are retried with
// exponential backoff (honouring an HTTP Retry-After) and are visible in
// Stats, not returned: a sensor must keep trying for as long as it runs.
//
// Only complete lines are read. A line that is not a hawkbell event is counted
// in BadLines and skipped, since waiting for it to become valid would block
// everything behind it. When the destination permanently refuses a batch
// (IsPermanent), the batch is bisected to find the offending events, which
// are counted in Dropped while everything else in it is still delivered. A
// destination that has accepted nothing in this run is not believed when it
// calls data unacceptable: that looks like a wrong endpoint, so nothing is
// dropped and the shipper retries.
func (s *Shipper) Run(ctx context.Context) error {
	if s.dst == nil {
		return errors.New("sink shipper: nil destination")
	}
	if s.o.Dir == "" {
		return errors.New("sink shipper: Dir is required")
	}
	if !s.loaded {
		s.load()
		s.loaded = true
	}
	failures := 0
	for {
		progress, err := s.poll(ctx)
		if ctx.Err() != nil {
			s.save()
			return nil
		}
		var wait time.Duration
		switch {
		case err != nil:
			failures++
			s.count(func(st *ShipperStats) { st.Errors++; st.LastError = printable([]byte(err.Error()), 512) })
			wait = s.backoff(failures, err)
		case progress:
			failures = 0
		default:
			failures = 0
			wait = s.o.Interval
		}
		if wait <= 0 {
			continue
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			s.save()
			return nil
		case <-t.C:
		}
	}
}

// backoff doubles from the poll interval up to maxBackoff, with jitter so a
// fleet that lost its collector does not return in step. A server-provided
// Retry-After raises the wait.
func (s *Shipper) backoff(failures int, err error) time.Duration {
	d := s.o.Interval
	for i := 1; i < failures && d < s.maxBackoff; i++ {
		d *= 2
	}
	if d > s.maxBackoff {
		d = s.maxBackoff
	}
	d = d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
	var he *HTTPStatusError
	if errors.As(err, &he) && he.RetryAfter > d {
		d = he.RetryAfter
	}
	return d
}

// streamPriority orders streams for shipping: when there is a backlog,
// detections and sensor health go out before bulk activity.
func streamPriority(stream string) int {
	switch stream {
	case "detection":
		return 0
	case "health":
		return 1
	case "posture":
		return 2
	case "inventory":
		return 3
	case "activity":
		return 4
	}
	return 5
}

// poll makes one pass over the directory, shipping at most one batch per
// stream so no stream starves another. Within a stream the oldest segment
// with unshipped data goes first, which keeps a stream in order whenever a
// single process wrote it.
func (s *Shipper) poll(ctx context.Context) (progress bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink shipper: %v", r)
		}
	}()
	segs, err := listSegments(s.o.Dir, "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil // nothing has been written yet
		}
		return false, err
	}
	sort.Slice(segs, func(i, j int) bool {
		pi, pj := streamPriority(segs[i].stream), streamPriority(segs[j].stream)
		if pi != pj {
			return pi < pj
		}
		if segs[i].stream != segs[j].stream {
			return segs[i].stream < segs[j].stream
		}
		return segmentLess(segs[i], segs[j])
	})
	present := make(map[string]bool, len(segs))
	for _, g := range segs {
		present[g.name] = true
	}
	for name := range s.files {
		if !present[name] {
			delete(s.files, name) // pruned; nothing left to track
			s.dirty = true
		}
	}

	var backlog int64
	shipped := make(map[string]bool) // streams that sent a batch this pass
	var firstErr error
	for _, g := range segs {
		if ctx.Err() != nil {
			break
		}
		fi, lerr := os.Lstat(filepath.Join(s.o.Dir, g.name))
		if lerr != nil || !fi.Mode().IsRegular() {
			continue
		}
		cur := s.files[g.name]
		var off int64
		if cur != nil {
			off = cur.Offset
		}
		if fi.Size() == off {
			continue
		}
		if shipped[g.stream] || firstErr != nil {
			if fi.Size() > off {
				backlog += fi.Size() - off
			}
			continue
		}
		moved, rest, serr := s.shipSegment(g, fi)
		backlog += rest
		if moved {
			progress = true
			shipped[g.stream] = true
		}
		if serr != nil {
			// Stop sending, but finish the pass so Backlog stays accurate.
			firstErr = serr
		}
	}
	s.count(func(st *ShipperStats) { st.Backlog = backlog })
	if s.dirty {
		if err := s.save(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return progress, firstErr
}

// item is one parsed line.
type item struct {
	ev  *event.Event
	end int64 // file offset just past this line's newline
	bad int   // unusable lines skipped between the previous item and this one
}

// shipSegment sends one batch from a segment. It reports whether the stored
// offset advanced and how many bytes remain unshipped.
func (s *Shipper) shipSegment(g segment, fi os.FileInfo) (moved bool, rest int64, err error) {
	path := filepath.Join(s.o.Dir, g.name)
	f, err := openRead(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, 0, nil
		}
		return false, 0, err
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
		return false, 0, err
	}
	if !fi.Mode().IsRegular() {
		return false, 0, nil
	}
	size := fi.Size()
	cur := s.files[g.name]
	if cur == nil {
		cur = &fileCursor{}
		s.files[g.name] = cur
	}
	if cur.Offset > size || !sameFile(f, cur) {
		// Not the file the offset was taken from. Starting over can
		// duplicate; keeping the offset could skip data, which is worse.
		*cur = fileCursor{}
		s.dirty = true
	}
	start := cur.Offset
	if start == size {
		return false, 0, nil
	}

	want := size - start
	if want > shipWindow {
		want = shipWindow
	}
	if int64(cap(s.buf)) < want {
		s.buf = make([]byte, want)
	}
	win := s.buf[:want]
	n, rerr := f.ReadAt(win, start)
	if rerr != nil && rerr != io.EOF {
		return false, size - start, rerr
	}
	win = win[:n]
	atEOF := start+int64(n) >= size

	items, consumed, trailingBad := s.parse(win, start)
	if consumed == start && len(items) == 0 {
		// No complete line in the window.
		switch {
		case !atEOF:
			// More than a window without a newline: skip to the next one.
			next, found, serr := skipLine(f, start+int64(n))
			if serr != nil {
				return false, size - start, serr
			}
			if found {
				consumed, trailingBad = next, 1
			}
		case time.Since(fi.ModTime()) > s.tornGrace:
			// An unterminated tail nobody has completed: a torn write.
			consumed, trailingBad = size, 1
		}
		if consumed == start {
			return false, size - start, nil
		}
	}

	delivered, derr := s.deliver(items)
	newOff := start
	bad := 0
	for i := 0; i < delivered; i++ {
		newOff = items[i].end
		bad += items[i].bad
	}
	if delivered == len(items) {
		newOff = consumed
		bad += trailingBad
	}
	if newOff != start {
		cur.Offset = newOff
		if cur.Fingerprint == "" {
			cur.Fingerprint, cur.FingerprintLen = fingerprint(f, newOff)
		}
		s.dirty = true
		moved = true
		if bad > 0 {
			s.count(func(st *ShipperStats) { st.BadLines += uint64(bad) })
		}
		// Persist before reading further: this is the at-least-once point.
		if serr := s.save(); serr != nil && derr == nil {
			derr = serr
		}
	}
	return moved, size - newOff, derr
}

// parse splits the window into complete lines and decodes them, stopping at
// the batch limits. consumed is the offset after the last complete line
// examined; trailingBad counts unusable lines after the last item.
func (s *Shipper) parse(win []byte, start int64) (items []item, consumed int64, trailingBad int) {
	consumed = start
	pos, bad, bytesIn := 0, 0, 0
	for pos < len(win) && len(items) < s.o.Batch && bytesIn < maxBatchBytes {
		nl := bytes.IndexByte(win[pos:], '\n')
		if nl < 0 {
			break
		}
		line := bytes.TrimSpace(win[pos : pos+nl])
		pos += nl + 1
		consumed = start + int64(pos)
		if len(line) == 0 {
			continue
		}
		var ev *event.Event
		if len(line) <= maxShipLine {
			ev = parseLine(line)
		}
		if ev == nil {
			bad++
			continue
		}
		bytesIn += len(line)
		items = append(items, item{ev: ev, end: consumed, bad: bad})
		bad = 0
	}
	return items, consumed, bad
}

// parseLine decodes one segment line into an event, accepting both line
// formats: a native event, or an OCSF record carrying the native event
// under unmapped.hawkbell. Numbers inside free-form fields stay json.Number so
// they are forwarded exactly as written.
func parseLine(line []byte) (ev *event.Event) {
	defer func() {
		if recover() != nil {
			ev = nil
		}
	}()
	var e event.Event
	if !decodeStrict(line, &e) {
		return nil
	}
	if e.Kind == "" || e.Type == "" {
		var env struct {
			Unmapped struct {
				Hawkbell json.RawMessage `json:"hawkbell"`
			} `json:"unmapped"`
		}
		if !decodeStrict(line, &env) || len(env.Unmapped.Hawkbell) == 0 {
			return nil
		}
		e = event.Event{}
		if !decodeStrict(env.Unmapped.Hawkbell, &e) || e.Kind == "" || e.Type == "" {
			return nil
		}
	}
	return &e
}

func decodeStrict(b []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return false
	}
	// Exactly one JSON value per line; trailing garbage means two writes
	// were glued together by a torn line.
	_, err := dec.Token()
	return err == io.EOF
}

// skipLine scans forward from off for the next newline and returns the
// offset just past it.
func skipLine(f *os.File, off int64) (next int64, found bool, err error) {
	buf := make([]byte, 64<<10)
	for {
		n, rerr := f.ReadAt(buf, off)
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			return off + int64(i) + 1, true, nil
		}
		off += int64(n)
		if rerr == io.EOF || n == 0 {
			return off, false, nil
		}
		if rerr != nil {
			return off, false, rerr
		}
	}
}
