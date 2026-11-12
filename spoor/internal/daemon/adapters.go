package daemon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/thomastysong/spoor/internal/adapter"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// adapterRunner tails other sensors' NDJSON output (sources.adapters, numbat
// today). Files are read only in complete lines, opened without following a
// final link and closed after every pass (on Windows a held handle would
// block the writer's own rotation). The user of every record is the file's
// owner, never a field of the record, unless root owns the file (a
// system-wide log, which only root could have written).
//
// Start at end of file, as for transcripts: a file that exists when its
// pattern is first looked at (first start on this data directory, a pattern
// added to the configuration, the release of the kill switch) is started at
// its end. The patterns are remembered with the checkpoints, so every file
// that appears later (the sensor starting after spoor, a date-named or
// rename-then-create rotation, a file written while the daemon was down) is
// read from its first line, unless its last change predates the pattern's
// admission (content moved in from elsewhere). A file that changed name is
// recognised by its file id and the fingerprint of its first bytes and
// continues from its checkpoint, so a rotation matched by the pattern is
// neither read twice nor skipped.
//
// One pass reads at most maxAdapterPerPoll bytes of a file, counting the
// bytes of a line that is not complete yet: a writer that never ends its
// line costs that much per pass, not the whole file. A partial line longer
// than the adapter's line limit is consumed and its rest discarded up to
// the next LF (adCkpt.Skip), counted as too_large.
type adapterRunner struct {
	d      *daemon
	ckPath string
	ck     map[string]adCkpt
	pats   map[string]int64 // admitted patterns -> when first looked at (Unix seconds)
	loaded bool
	off    bool
	dirty  bool
}

type adCkpt struct {
	ID   string `json:"id"`
	Off  int64  `json:"off"`
	Skip bool   `json:"skip,omitempty"` // Off is inside an oversize line: discard up to the next LF
	FP   string `json:"fp,omitempty"`   // fingerprint of the first FPN bytes
	FPN  int64  `json:"fpn,omitempty"`
}

const (
	maxAdapterFiles   = 256      // per pattern
	maxAdapterPerPoll = 16 << 20 // bytes read from one file per pass, partial lines included
	// fpBytes of a file's head identify it across a rename. A numbat record
	// is a few KiB and carries a unique event_id and timestamp, so this
	// covers at least the first record of a file.
	fpBytes = 4 << 10
)

func newAdapterRunner(d *daemon) *adapterRunner {
	return &adapterRunner{d: d, ckPath: filepath.Join(d.layout.check, "adapters.json"), ck: map[string]adCkpt{}, pats: map[string]int64{}}
}

func (r *adapterRunner) run(ctx context.Context) error {
	d := r.d
	if len(d.cfg.Sources.Adapters) == 0 {
		<-ctx.Done()
		return nil
	}
	t := time.NewTicker(adapterPoll)
	defer t.Stop()
	for {
		r.step()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// adPass is the state of one pass over every pattern.
type adPass struct {
	prev map[string]adCkpt // checkpoints after the previous pass
	next map[string]adCkpt // checkpoints of the files seen in this pass
	byID map[string]string // file id -> path in prev, to follow renames
	used map[string]bool   // file ids already read in this pass (hard links)
}

func (r *adapterRunner) step() {
	d := r.d
	off, settling := d.gate.state()
	if off {
		r.off = true
		d.board.update("adapters", func(s *event.SurfaceStatus) { s.Status, s.Reason = "disabled", "kill_switch" })
		return
	}
	if !r.loaded {
		r.load()
		r.loaded = true
	}
	if r.off {
		// Records written while the sensor was off are not collected
		// later: with no checkpoints and no admitted pattern the next pass
		// records every file's current end and hands nothing over, so it
		// may run at once.
		r.off = false
		r.ck = map[string]adCkpt{}
		r.pats = map[string]int64{}
		r.dirty = true
	} else if settling {
		return
	}
	ps := &adPass{prev: r.ck, next: map[string]adCkpt{}, byID: map[string]string{}, used: map[string]bool{}}
	for p, c := range r.ck {
		if c.ID != "" {
			ps.byID[c.ID] = p
		}
	}
	now := d.env.now().Unix()
	inConfig := map[string]bool{}
	seen := map[string]bool{}
	drift := false
	var errs uint64
	for _, src := range d.cfg.Sources.Adapters {
		for _, pat := range src.Paths {
			if !filepath.IsAbs(pat) {
				continue
			}
			m, err := filepath.Glob(pat)
			if err != nil {
				continue
			}
			inConfig[pat] = true
			admitted, known := r.pats[pat]
			sort.Strings(m)
			if len(m) > maxAdapterFiles {
				m = m[len(m)-maxAdapterFiles:]
			}
			for _, path := range m {
				if seen[path] {
					continue
				}
				seen[path] = true
				dr, n := r.readFile(ps, path, src.Format, !known, admitted)
				drift = drift || dr
				errs += n
			}
			if !known {
				// Admitted even with no file yet: what appears from now
				// on is new and read from its first line.
				r.pats[pat] = now
				r.dirty = true
			}
		}
	}
	for pat := range r.pats {
		if !inConfig[pat] {
			delete(r.pats, pat)
			r.dirty = true
		}
	}
	if len(ps.next) != len(ps.prev) {
		r.dirty = true
	} else {
		for p, c := range ps.next {
			if ps.prev[p] != c {
				r.dirty = true
				break
			}
		}
	}
	r.ck = ps.next
	if r.dirty {
		if b, err := json.Marshal(adCkptFile{V: 1, Files: r.ck, Patterns: r.pats}); err == nil {
			if writeFileAtomic(r.ckPath, b, 0o600) == nil {
				r.dirty = false
			}
		}
	}
	d.board.update("adapters", func(s *event.SurfaceStatus) {
		s.Status, s.Reason = "ok", ""
		s.Errors += errs
		if drift {
			s.SchemaDrift = true
		}
	})
}

// readFile reads the complete new lines of one file. fresh is true when its
// pattern is looked at for the first time; admitted is when the pattern was
// first looked at otherwise. It reports schema drift and the number of
// records that could not be converted.
func (r *adapterRunner) readFile(ps *adPass, path, format string, fresh bool, admitted int64) (drift bool, errs uint64) {
	d := r.d
	keep := func() {
		// Unreadable for now (a permission change, a race with the
		// writer): keep the checkpoint for the next pass.
		if c, ok := ps.prev[path]; ok {
			ps.next[path] = c
		}
	}
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		if errors.Is(err, platform.ErrSymlink) || errors.Is(err, platform.ErrNotRegular) {
			d.board.add("adapter.refused", 1)
		}
		keep()
		return false, 0
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		keep()
		return false, 0
	}
	id, _ := platform.FileIDOf(f)
	c, ok := ps.prev[path]
	same := ok && (c.ID == "" || id == "" || c.ID == id)
	if id != "" {
		if old, tracked := ps.byID[id]; !same && tracked && old != path && holds(old, id) {
			return false, 0 // a hard link of a file followed under its other name
		}
		if ps.used[id] {
			return false, 0 // another name of a file read in this pass
		}
		ps.used[id] = true
	}
	size := fi.Size()
	switch {
	case same:
		// The file followed under this name.
	case r.renamed(ps, f, path, id, size, &c):
		// Followed under another name until the last pass.
	case ok:
		// A new file under a known name (rename-then-create rotation,
		// delete and recreate): it was created after the last pass.
		c = adCkpt{ID: id}
	case fresh || fi.ModTime().Unix() < admitted:
		// It existed when its pattern was first looked at, or its content
		// did: no retroactive collection.
		c = adCkpt{ID: id, Off: size}
		c.FP, c.FPN = headPrint(f, size)
		ps.next[path] = c
		return false, 0
	default:
		c = adCkpt{ID: id} // appeared since: read from its first line
	}
	c.ID = id
	if size < c.Off || (size > c.Off && c.FPN > 0 && !samePrint(f, c)) {
		// Truncated, or rewritten in place: start again.
		c = adCkpt{ID: id}
		d.board.add("adapter.truncated", 1)
	}
	if c.FPN < fpBytes && size > c.FPN {
		c.FP, c.FPN = headPrint(f, size)
	}
	if size == c.Off {
		ps.next[path] = c
		return false, 0
	}
	if _, err := f.Seek(c.Off, io.SeekStart); err != nil {
		ps.next[path] = c
		return false, 0
	}
	user := r.ownerUser(fi, path)
	br := bufio.NewReaderSize(io.LimitReader(f, maxAdapterPerPoll), 256<<10)
	var batch []*event.Event
	for {
		if c.Skip {
			n, found := discardLine(br)
			c.Off += n
			if !found {
				break
			}
			c.Skip = false
			continue
		}
		line, n, st := nextLine(br, adapter.MaxNumbatLine+1)
		if st == lineIncomplete {
			break // the writer has not finished it: next pass
		}
		c.Off += int64(n)
		if st == lineOversize {
			// No end in sight within the limit: it cannot be a record.
			c.Skip = true
			errs++
			d.board.add("adapter."+format+".too_large", 1)
			continue
		}
		if len(line) == 0 {
			continue
		}
		evs, cerr := adapter.Numbat(line)
		if cerr != nil {
			errs++
			d.board.add("adapter."+format+"."+adapterErrKind(cerr), 1)
			if errors.Is(cerr, adapter.ErrVersion) || errors.Is(cerr, adapter.ErrUnknownRecord) {
				drift = true
			}
		}
		for _, ev := range evs {
			if ev == nil {
				continue
			}
			if user != nil {
				u := *user
				ev.User = &u
			}
			batch = append(batch, ev)
		}
		if len(batch) >= 256 {
			d.ingest(batch...)
			batch = nil
		}
	}
	if len(batch) > 0 {
		d.ingest(batch...)
	}
	ps.next[path] = c
	return drift, errs
}

// renamed reports whether the file at path is one the previous pass
// followed under another name that no longer holds it, and if so sets *c to
// that checkpoint. The fingerprint of the first bytes tells a renamed file
// from a new one that was given a freed inode.
func (r *adapterRunner) renamed(ps *adPass, f *os.File, path, id string, size int64, c *adCkpt) bool {
	if id == "" {
		return false
	}
	old, ok := ps.byID[id]
	if !ok || old == path {
		return false
	}
	prev := ps.prev[old]
	if holds(old, id) {
		return false // the old name still holds it: a hard link, read there
	}
	if size < prev.Off || (prev.FPN > 0 && (size < prev.FPN || !samePrint(f, prev))) {
		return false // shorter than what was read of it, or another head: another file
	}
	delete(ps.byID, id)
	*c = prev
	return true
}

// holds reports whether path is (still) the file with this id.
func holds(path, id string) bool {
	fi, err := os.Lstat(path)
	return err == nil && platform.FileID(fi, path) == id
}

// headPrint fingerprints the first bytes of a file (at most fpBytes).
func headPrint(f *os.File, size int64) (string, int64) {
	n := min(size, fpBytes)
	if n <= 0 {
		return "", 0
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return "", 0
	}
	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:16]), n
}

// samePrint reports whether the file still starts with the bytes c was
// fingerprinted on.
func samePrint(f *os.File, c adCkpt) bool {
	fp, n := headPrint(f, c.FPN)
	return n == c.FPN && fp == c.FP
}

// ownerUser is the account that owns the file, or nil for root (keep what
// the record says: only root could have written a root-owned log).
func (r *adapterRunner) ownerUser(fi os.FileInfo, path string) *event.User {
	owner, ok := platform.OwnerUID(fi)
	if !ok && runtime.GOOS == "windows" {
		owner, ok = platform.PathOwner(path)
	}
	if !ok || owner == "" || owner == "0" || owner == "S-1-5-18" || owner == "S-1-5-32-544" {
		return nil
	}
	u := event.User{ID: owner}
	if h, known := r.d.users.byID(owner); known {
		u.Name = h.Name
	}
	return &u
}

type lineState int

const (
	lineComplete   lineState = iota // an LF-terminated line
	lineIncomplete                  // no LF before the end of the data: left for the next pass, unconsumed
	lineOversize                    // no LF yet, and already longer than max: consumed
)

// nextLine returns the next LF-terminated line (without the LF, cut to max
// bytes) and the bytes consumed. A line with no LF before the end of the
// data is lineIncomplete (n is 0) unless it already has more than max
// bytes, which makes it lineOversize: those bytes are consumed and the
// caller discards the rest of the line.
func nextLine(br *bufio.Reader, max int) (line []byte, n int, st lineState) {
	for {
		chunk, err := br.ReadSlice('\n')
		n += len(chunk)
		if len(line) < max {
			room := max - len(line)
			if len(chunk) > room {
				line = append(line, chunk[:room]...)
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case err == nil:
			return trimEOL(line), n, lineComplete
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case n > max:
			return nil, n, lineOversize
		default:
			return nil, 0, lineIncomplete
		}
	}
}

// discardLine consumes bytes up to and including the next LF. found is
// false when the data ended first (everything read was consumed).
func discardLine(br *bufio.Reader) (n int64, found bool) {
	for {
		chunk, err := br.ReadSlice('\n')
		n += int64(len(chunk))
		switch {
		case err == nil:
			return n, true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return n, false
		}
	}
}

func adapterErrKind(err error) string {
	switch {
	case errors.Is(err, adapter.ErrMalformed):
		return "malformed"
	case errors.Is(err, adapter.ErrNotNumbat):
		return "not_numbat"
	case errors.Is(err, adapter.ErrVersion):
		return "version"
	case errors.Is(err, adapter.ErrUnknownRecord):
		return "unknown_record"
	case errors.Is(err, adapter.ErrTooLarge):
		return "too_large"
	case errors.Is(err, adapter.ErrInternal):
		return "internal"
	}
	return "other"
}

// adCkptFile is adapters.json. Patterns was added later: a file without it
// starts every unknown file at its end once, as before.
type adCkptFile struct {
	V        int               `json:"v"`
	Files    map[string]adCkpt `json:"files"`
	Patterns map[string]int64  `json:"patterns,omitempty"`
}

func (r *adapterRunner) load() {
	b, err := readSmallFile(r.ckPath, 4<<20)
	if err != nil {
		return
	}
	var f adCkptFile
	if json.Unmarshal(b, &f) != nil || f.V != 1 {
		return
	}
	if f.Files != nil {
		r.ck = f.Files
	}
	now := r.d.env.now().Unix()
	for pat, at := range f.Patterns {
		// A time ahead of the clock would start new files at their end.
		r.pats[pat] = min(at, now)
	}
}
