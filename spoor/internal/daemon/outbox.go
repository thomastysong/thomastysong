package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/sink"
)

// Outbox pruning (DECISIONS A14, red-team pipeline-operator F2): deleting a
// segment Fluent Bit has not finished reading loses data silently (91% of a
// segment in the red team's run), so the daemon prunes by what its consumers
// have read, not by age alone:
//
//   - A consumer is Fluent Bit's tail database (read-only) or a spoor shipper's
//     checkpoint. A segment is consumed when every consumer that reads its
//     stream has read it to the end.
//   - Age (retention.outbox) removes consumed segments only, and segments of
//     streams nobody reads. With no consumer configured at all it removes by
//     age alone, as the sink would.
//   - The hard cap (retention.outbox_bytes) removes consumed segments first,
//     oldest first; then segments of streams nobody reads; then unread data,
//     activity first and detections last. Unread data removed is reported.
//   - The newest segment of each stream is never removed: writers append to it.

// readPos is how far a consumer has read one segment.
type readPos struct {
	off   int64
	inode uint64 // 0 when the consumer does not record it
}

// consumerView is one consumer's positions by segment base name.
type consumerView struct {
	files map[string]readPos
	all   bool // reads every stream (a shipper reads the whole directory)
}

// consumer is something that reads the outbox.
type consumer interface {
	id() string
	view() (consumerView, error)
}

// pruneOptions configure an outboxPruner.
type pruneOptions struct {
	dir        string
	maxAge     time.Duration // <= 0: no age limit
	maxBytes   int64         // <= 0: no byte cap
	consumers  func() []consumer // re-evaluated every pass: a tail database may appear later
	statePath  string // remembered stream coverage per consumer ("" = in memory)
	copyDir    string // scratch space for reading a tail database that cannot be opened in place
	privileged bool
	gid        int
	readOnly   bool // measure only (spoor doctor): never delete or save
}

// outboxPruner keeps the outbox within its limits.
type outboxPruner struct {
	o  pruneOptions
	mu sync.Mutex
	// covered remembers, per consumer, the streams it has ever listed: Fluent
	// Bit forgets a file once it is deleted, but a stream it tailed once is
	// one it tails.
	covered map[string]map[string]bool
	loaded  bool
}

func newOutboxPruner(o pruneOptions) *outboxPruner {
	return &outboxPruner{o: o, covered: map[string]map[string]bool{}}
}

// outSeg is one segment file and what is known about its consumption.
type outSeg struct {
	name, stream string
	hour         time.Time
	n            int
	size         int64
	inode        uint64
	readFrom     int64 // lowest offset among the consumers that read its stream
	covered      bool  // some consumer reads its stream
	consumed     bool  // covered, and every such consumer read it to the end
	newest       bool
	future       bool
}

func (s *outSeg) unread() int64 {
	if !s.covered || s.consumed {
		return 0
	}
	return s.size - s.readFrom
}

// streamDrop is what the cap removed of one stream before it was read.
type streamDrop struct {
	events, bytes     uint64
	seqFirst, seqLast uint64
}

// dropReport accounts for unread data the cap removed.
type dropReport struct {
	events, bytes uint64
	segments      int
	streams       map[string]*streamDrop
}

// pruneResult is the outcome of one pass (or one measurement).
type pruneResult struct {
	segments int
	bytes    int64
	oldest   time.Time
	newest   time.Time
	perStream map[string]streamSize

	consumers   int
	lagKnown    bool
	lag         int64
	consumerLag map[string]int64
	consumerErr map[string]string
	unreadOld   int // unread segments past the age limit, kept

	removedAge, removedCap, removedUnconsumed int
	removedBytes                              int64
	unread                                    dropReport
	errors                                    int
}

type streamSize struct {
	Segments int   `json:"segments"`
	Bytes    int64 `json:"bytes"`
}

// stream priority when unread data must go: what the SIEM needs most goes last.
var dropPriority = map[string]int{
	"activity":  0,
	"inventory": 1,
	"posture":   2,
	"health":    3,
	"summary":   4,
	"detection": 9,
}

func priority(stream string) int {
	if p, ok := dropPriority[stream]; ok {
		return p
	}
	return 5
}

// prune runs one pass: measure, remove by age, enforce the cap.
func (p *outboxPruner) prune(now time.Time) pruneResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	segs, res := p.measure(now)
	if p.o.readOnly {
		return res
	}
	remove := func(s *outSeg) bool {
		path := filepath.Join(p.o.dir, s.name)
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.errors++
			return false
		}
		res.removedBytes += s.size
		res.bytes -= s.size
		res.segments--
		return true
	}

	// Age: consumed segments, and segments no consumer reads.
	kept := segs[:0]
	if p.o.maxAge > 0 {
		cutoff := now.Add(-p.o.maxAge)
		for _, s := range segs {
			if !s.newest && !s.future && s.hour.Add(time.Hour).Before(cutoff) {
				if !s.covered || s.consumed {
					if remove(s) {
						res.removedAge++
						continue
					}
				} else {
					res.unreadOld++
				}
			}
			kept = append(kept, s)
		}
		segs = kept
	}

	// Cap.
	if p.o.maxBytes > 0 && res.bytes > p.o.maxBytes {
		order := capOrder(segs)
		for _, s := range order {
			if res.bytes <= p.o.maxBytes {
				break
			}
			if s.newest {
				continue
			}
			var drop *streamDrop
			if u := s.unread(); u > 0 {
				// Count before the file is gone.
				drop = countUnread(filepath.Join(p.o.dir, s.name), s.readFrom)
				drop.bytes = uint64(u)
			}
			if !remove(s) {
				continue
			}
			switch {
			case drop != nil:
				res.unread.add(s.stream, drop)
				res.lag -= s.size - s.readFrom
			case !s.covered && res.consumers > 0:
				res.removedUnconsumed++
			default:
				res.removedCap++
			}
		}
	}
	if res.lag < 0 {
		res.lag = 0
	}
	return res
}

// capOrder is the order the cap removes segments in: consumed (misdated
// first, then oldest), then streams nobody reads, then unread data by
// stream priority, oldest first.
func capOrder(segs []*outSeg) []*outSeg {
	out := append([]*outSeg(nil), segs...)
	class := func(s *outSeg) int {
		switch {
		case s.covered && s.consumed:
			return 0
		case !s.covered:
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ca, cb := class(a), class(b); ca != cb {
			return ca < cb
		}
		if a.future != b.future {
			return a.future
		}
		if class(a) > 0 {
			if pa, pb := priority(a.stream), priority(b.stream); pa != pb {
				return pa < pb
			}
		}
		if !a.hour.Equal(b.hour) {
			return a.hour.Before(b.hour)
		}
		if a.n != b.n {
			return a.n < b.n
		}
		return a.stream < b.stream
	})
	return out
}

func (r *dropReport) add(stream string, d *streamDrop) {
	if r.streams == nil {
		r.streams = map[string]*streamDrop{}
	}
	r.events += d.events
	r.bytes += d.bytes
	r.segments++
	cur := r.streams[stream]
	if cur == nil {
		c := *d
		r.streams[stream] = &c
		return
	}
	cur.events += d.events
	cur.bytes += d.bytes
	if d.seqFirst != 0 && (cur.seqFirst == 0 || d.seqFirst < cur.seqFirst) {
		cur.seqFirst = d.seqFirst
	}
	if d.seqLast > cur.seqLast {
		cur.seqLast = d.seqLast
	}
}

// countUnread counts the records in a segment from off to its end and
// notes the first and last sequence numbers among them.
func countUnread(path string, off int64) *streamDrop {
	d := &streamDrop{}
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return d
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return d
		}
	}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := readLine(r, 1<<20)
		if len(line) > 0 {
			d.events++
			var rec struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(line, &rec) == nil && rec.Seq != 0 {
				if d.seqFirst == 0 {
					d.seqFirst = rec.Seq
				}
				d.seqLast = rec.Seq
			}
		}
		if err != nil {
			return d
		}
	}
}

// readLine returns one line without its newline; a line longer than max is
// returned cut (it still counts as a record).
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(out)+len(chunk) <= max {
			out = append(out, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		out = trimEOL(out)
		return out, err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// measure lists the segments and works out what every consumer has read.
func (p *outboxPruner) measure(now time.Time) ([]*outSeg, pruneResult) {
	res := pruneResult{perStream: map[string]streamSize{}, consumerLag: map[string]int64{}, consumerErr: map[string]string{}}
	segs := p.list(now, &res)
	if !p.loaded {
		p.loadCovered()
		p.loaded = true
	}
	type cv struct {
		id  string
		v   consumerView
		err error
		cov map[string]bool
		lag int64
	}
	var views []*cv
	changed := false
	var list []consumer
	if p.o.consumers != nil {
		list = p.o.consumers()
	}
	for _, c := range list {
		v, err := c.view()
		x := &cv{id: c.id(), v: v, err: err}
		cov := p.covered[x.id]
		if cov == nil {
			cov = map[string]bool{}
			p.covered[x.id] = cov
		}
		if err == nil {
			for name := range v.files {
				if st, ok := sink.ParseSegmentName(name); ok && !cov[st] {
					cov[st] = true
					changed = true
				}
			}
		} else {
			res.consumerErr[x.id] = err.Error()
		}
		x.cov = cov
		views = append(views, x)
	}
	if changed && !p.o.readOnly {
		p.saveCovered()
	}
	res.consumers = len(views)
	res.lagKnown = len(views) > 0
	for _, s := range segs {
		first := true
		for _, x := range views {
			applies := x.v.all || x.cov[s.stream]
			if !applies && len(x.cov) == 0 {
				// A consumer that has never listed a segment (unreadable,
				// or Fluent Bit has not discovered the files yet) might
				// read anything: assume it does, so nothing it may still
				// need is removed by age.
				applies = true
			}
			if !applies {
				continue
			}
			var off int64
			if x.err == nil {
				if pos, ok := x.v.files[s.name]; ok && (pos.inode == 0 || s.inode == 0 || pos.inode == s.inode) {
					off = min(max(pos.off, 0), s.size)
				}
			}
			x.lag += s.size - off
			if first || off < s.readFrom {
				s.readFrom = off
			}
			first = false
			s.covered = true
		}
		s.consumed = s.covered && s.readFrom >= s.size
		res.lag += s.unread()
	}
	for _, x := range views {
		res.consumerLag[x.id] = x.lag
	}
	return segs, res
}

// list returns the segment files with sizes and identities, oldest first.
func (p *outboxPruner) list(now time.Time, res *pruneResult) []*outSeg {
	ents, err := os.ReadDir(p.o.dir)
	if err != nil {
		res.errors++
		return nil
	}
	var segs []*outSeg
	for _, e := range ents {
		s, ok := parseSegment(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(p.o.dir, s.name)
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		s.size = fi.Size()
		s.inode = inodeOf(fi, path)
		s.future = s.hour.After(now.Add(time.Hour))
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool {
		a, b := segs[i], segs[j]
		if !a.hour.Equal(b.hour) {
			return a.hour.Before(b.hour)
		}
		if a.n != b.n {
			return a.n < b.n
		}
		return a.stream < b.stream
	})
	newest := map[string]*outSeg{}
	for _, s := range segs {
		if !s.future {
			newest[s.stream] = s
		}
		res.segments++
		res.bytes += s.size
		ss := res.perStream[s.stream]
		ss.Segments++
		ss.Bytes += s.size
		res.perStream[s.stream] = ss
		if !s.future && (res.oldest.IsZero() || s.hour.Before(res.oldest)) {
			res.oldest = s.hour
		}
		if !s.future && s.hour.After(res.newest) {
			res.newest = s.hour
		}
	}
	for _, s := range newest {
		s.newest = true
	}
	return segs
}

// parseSegment parses <stream>-<YYYYMMDD>-<HH>-<n>.ndjson, the sink's
// segment name (sink.SegmentName), after the sink itself has accepted it.
func parseSegment(name string) (*outSeg, bool) {
	stream, ok := sink.ParseSegmentName(name)
	if !ok {
		return nil, false
	}
	base := strings.TrimSuffix(name, ".ndjson")
	rest := strings.TrimPrefix(base, stream+"-") // YYYYMMDD-HH-n
	parts := strings.Split(rest, "-")
	if len(parts) != 3 {
		return nil, false
	}
	hour, err := time.Parse("20060102-15", parts[0]+"-"+parts[1])
	if err != nil {
		return nil, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, false
	}
	return &outSeg{name: name, stream: stream, hour: hour.UTC(), n: n}, true
}

// inodeOf is the file's inode (POSIX) or NTFS file index (Windows): what
// Fluent Bit records in its tail database.
func inodeOf(fi os.FileInfo, path string) uint64 {
	id := platform.FileID(fi, path)
	i := strings.LastIndexByte(id, ':')
	if i < 0 {
		return 0
	}
	n, err := strconv.ParseUint(id[i+1:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

type coveredFile struct {
	V       int                 `json:"v"`
	Streams map[string][]string `json:"streams"`
}

func (p *outboxPruner) loadCovered() {
	if p.o.statePath == "" {
		return
	}
	b, err := readSmallFile(p.o.statePath, 1<<20)
	if err != nil {
		return
	}
	var f coveredFile
	if json.Unmarshal(b, &f) != nil || f.V != 1 {
		return
	}
	for id, list := range f.Streams {
		m := map[string]bool{}
		for _, s := range list {
			if len(m) < 64 {
				m[s] = true
			}
		}
		p.covered[id] = m
	}
}

func (p *outboxPruner) saveCovered() {
	if p.o.statePath == "" {
		return
	}
	f := coveredFile{V: 1, Streams: map[string][]string{}}
	for id, m := range p.covered {
		var list []string
		for s := range m {
			list = append(list, s)
		}
		sort.Strings(list)
		f.Streams[id] = list
	}
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	_ = writeFileAtomic(p.o.statePath, b, 0o600)
}

// droppedUnshippedEvent is the health.error the cap's removal of unread
// data produces. It carries counts and sequence ranges, never content.
func droppedUnshippedEvent(now time.Time, r dropReport) *event.Event {
	ctr := map[string]uint64{
		"events":   r.events,
		"bytes":    r.bytes,
		"segments": uint64(r.segments),
	}
	names := make([]string, 0, len(r.streams))
	for s := range r.streams {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		d := r.streams[s]
		ctr[s+".events"] = d.events
		ctr[s+".bytes"] = d.bytes
		ctr[s+".seq_first"] = d.seqFirst
		ctr[s+".seq_last"] = d.seqLast
	}
	return &event.Event{
		V:         event.SchemaVersion,
		TS:        event.At(now),
		Kind:      event.KindHealth,
		Type:      event.TypeHealthError,
		Source:    event.SourceSensor,
		Fidelity:  event.FidelityObserved,
		Integrity: "",
		Health: &event.Health{
			SensorVersion: Version,
			Mode:          "daemon",
			Reason:        "outbox.dropped_unshipped",
			Detail: fmt.Sprintf("the outbox byte cap (retention.outbox_bytes) removed %d records (%d bytes) in %d segments that no consumer had read",
				r.events, r.bytes, r.segments),
			Counters: ctr,
		},
		Labels: map[string]string{"streams": strings.Join(names, ",")},
	}
}

// recordPrune publishes a pass's outcome in the heartbeat counters.
func (d *daemon) recordPrune(r pruneResult) {
	b := d.board
	b.set("outbox.segments", uint64(max(r.segments, 0)))
	b.set("outbox.bytes", uint64(max(r.bytes, 0)))
	if r.lagKnown {
		b.set("shipper_lag_bytes", uint64(r.lag))
	} else {
		b.unset("shipper_lag_bytes")
	}
	for id, lag := range r.consumerLag {
		b.set("outbox.lag."+consumerKey(id), uint64(max(lag, 0)))
	}
	b.add("outbox.pruned_age", uint64(r.removedAge))
	b.add("outbox.pruned_cap", uint64(r.removedCap))
	b.add("outbox.pruned_unconsumed", uint64(r.removedUnconsumed))
	b.add("outbox.pruned_bytes", uint64(r.removedBytes))
	b.add("outbox.prune_errors", uint64(r.errors))
	b.set("outbox.unread_past_age", uint64(r.unreadOld))
	if r.unread.events > 0 || r.unread.bytes > 0 {
		b.add("outbox.dropped_unshipped_events", r.unread.events)
		b.add("outbox.dropped_unshipped_bytes", r.unread.bytes)
		b.add("outbox.dropped_unshipped_segments", uint64(r.unread.segments))
	}
	surf := event.SurfaceStatus{Name: "outbox", Status: "ok"}
	if len(r.consumerErr) > 0 {
		b.add("outbox.consumer_errors", uint64(len(r.consumerErr)))
		surf.Status, surf.Reason = "degraded", "consumer_unreadable"
		surf.Errors = uint64(len(r.consumerErr))
	}
	if r.unread.bytes > 0 {
		surf.Status, surf.Reason = "degraded", "dropped_unshipped"
	}
	b.surface(surf)
}

// consumerKey turns a consumer id into a short counter name component.
func consumerKey(id string) string {
	kind, path, _ := strings.Cut(id, ":")
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	var b strings.Builder
	for _, r := range base {
		if b.Len() >= 32 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			b.WriteRune(r + 32)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return kind
	}
	return kind + "." + b.String()
}
