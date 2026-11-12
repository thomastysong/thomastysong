package daemon

import (
	"bufio"
	"context"
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
// today). Like transcripts, a file is started at its end when first seen,
// read only in complete lines, opened without following a final link and
// closed after every pass (on Windows a held handle would block the writer's
// own rotation). The user of every record is the file's owner, never a
// field of the record, unless root owns the file (a system-wide log, which
// only root could have written).
type adapterRunner struct {
	d      *daemon
	ckPath string
	ck     map[string]adCkpt
	loaded bool
	off    bool
	dirty  bool
}

type adCkpt struct {
	ID  string `json:"id"`
	Off int64  `json:"off"`
}

const (
	maxAdapterFiles   = 256      // per pattern
	maxAdapterPerPoll = 16 << 20 // bytes read from one file per pass
)

func newAdapterRunner(d *daemon) *adapterRunner {
	return &adapterRunner{d: d, ckPath: filepath.Join(d.layout.check, "adapters.json"), ck: map[string]adCkpt{}}
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

func (r *adapterRunner) step() {
	d := r.d
	if d.env.disabled() {
		r.off = true
		d.board.update("adapters", func(s *event.SurfaceStatus) { s.Status, s.Reason = "disabled", "kill_switch" })
		return
	}
	if !r.loaded {
		r.load()
		r.loaded = true
	}
	if r.off {
		// Records written while the sensor was off are not collected later.
		r.off = false
		r.ck = map[string]adCkpt{}
		r.dirty = true
	}
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
			sort.Strings(m)
			if len(m) > maxAdapterFiles {
				m = m[len(m)-maxAdapterFiles:]
			}
			for _, path := range m {
				if seen[path] {
					continue
				}
				seen[path] = true
				dr, n := r.readFile(path, src.Format)
				drift = drift || dr
				errs += n
			}
		}
	}
	for p := range r.ck {
		if !seen[p] {
			delete(r.ck, p)
			r.dirty = true
		}
	}
	if r.dirty {
		if b, err := json.Marshal(map[string]any{"v": 1, "files": r.ck}); err == nil {
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

// readFile reads the complete new lines of one file. It reports schema drift
// and the number of records that could not be converted.
func (r *adapterRunner) readFile(path, format string) (drift bool, errs uint64) {
	d := r.d
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		if errors.Is(err, platform.ErrSymlink) || errors.Is(err, platform.ErrNotRegular) {
			d.board.add("adapter.refused", 1)
		}
		return false, 0
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, 0
	}
	id, _ := platform.FileIDOf(f)
	c, ok := r.ck[path]
	if !ok {
		// First sight: start at the end.
		r.ck[path] = adCkpt{ID: id, Off: fi.Size()}
		r.dirty = true
		return false, 0
	}
	if c.ID != "" && id != "" && c.ID != id {
		c = adCkpt{ID: id} // a new file under the same name: read it whole
	}
	if fi.Size() < c.Off {
		c.Off = 0 // truncated in place
		d.board.add("adapter.truncated", 1)
	}
	if fi.Size() == c.Off {
		r.ck[path] = c
		return false, 0
	}
	if _, err := f.Seek(c.Off, io.SeekStart); err != nil {
		return false, 0
	}
	user := r.ownerUser(fi, path)
	br := bufio.NewReaderSize(f, 256<<10)
	var batch []*event.Event
	var read int64
	for read < maxAdapterPerPoll {
		line, n, complete := readCompleteLine(br, adapter.MaxNumbatLine+1)
		if !complete {
			break
		}
		c.Off += int64(n)
		read += int64(n)
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
	c.ID = id
	r.ck[path] = c
	r.dirty = true
	return drift, errs
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

// readCompleteLine returns the next LF-terminated line (without the LF,
// cut to max bytes) and the bytes consumed. complete is false at the end
// of the data when the last line has no LF yet: it is left for the next
// pass, unconsumed.
func readCompleteLine(br *bufio.Reader, max int) (line []byte, n int, complete bool) {
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
			return trimEOL(line), n, true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, 0, false
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

func (r *adapterRunner) load() {
	b, err := readSmallFile(r.ckPath, 4<<20)
	if err != nil {
		return
	}
	var f struct {
		V     int               `json:"v"`
		Files map[string]adCkpt `json:"files"`
	}
	if json.Unmarshal(b, &f) == nil && f.V == 1 && f.Files != nil {
		r.ck = f.Files
	}
}
