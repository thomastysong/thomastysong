package transcript

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func modeOf(parser Parser, path string) fileMode {
	if m, ok := parser.(moder); ok {
		return m.mode(path)
	}
	return modeTail
}

func (t *Tailer) changed(tr *tracked, m fileMeta, now time.Time) bool {
	switch {
	case tr.more:
		return true
	case m.size != tr.cp.Size || m.mtime != tr.cp.MTime:
		return true
	case m.id != "" && tr.cp.FileID != "" && m.id != tr.cp.FileID:
		return true
	case statLazy && now.Unix()-tr.lastRead < int64(lazyWindow/time.Second):
		return true
	}
	return false
}

func (t *Tailer) process(p *pass, w *work) {
	tr := t.files[w.path]
	mode := modeOf(w.parser, w.path)
	nowUnix := p.now.Unix()
	if tr != nil {
		tr.lastSeen = nowUnix
		if tr.st != nil {
			u := w.user
			tr.st.user = &u
		}
		if !t.changed(tr, w.meta, p.now) {
			return
		}
	} else {
		stale := p.now.Sub(time.Unix(0, w.meta.mtime)) > t.o.MaxBackfill
		if stale {
			// Not modified within the backfill window: remember where it
			// ends without opening it, so a later resume is read from
			// there. Opening and priming is deferred until it changes.
			u := w.user
			t.files[w.path] = &tracked{
				path: w.path, format: formatOf(w.parser), lazy: true, lastSeen: nowUnix,
				cp: Checkpoint{Offset: w.meta.size, Size: w.meta.size, FileID: w.meta.id, MTime: w.meta.mtime},
				st: &FileState{Path: w.path, user: &u},
			}
			t.dirty = true
			return
		}
	}

	f, meta, err := openBeneath(w.base, w.rel)
	if err != nil {
		t.openProblem(p, w.path, tr, err)
		return
	}
	defer f.Close()
	if !ownerOK(meta, w.user.ID) {
		t.standing(p, ProblemOwnerMismatch, w.path, sessionOf(tr), fmt.Sprintf("file owner %q is not the root's user %q", meta.owner, w.user.ID))
		return
	}
	if t.o.AllowUID != nil && !t.o.AllowUID(w.path) {
		t.standing(p, ProblemOwnerMismatch, w.path, sessionOf(tr), "ownership check refused the file")
		return
	}
	delete(t.reported, w.path)

	if tr == nil {
		u := w.user
		tr = &tracked{
			path: w.path, format: formatOf(w.parser), lastSeen: nowUnix,
			cp: Checkpoint{FileID: meta.id},
			st: &FileState{Path: w.path, user: &u},
		}
		t.files[w.path] = tr
		t.dirty = true
		if !t.o.FromStart || t.archiveOfKnown(w.path, mode) {
			t.startAtEnd(tr, w.parser, f, meta, mode)
			return
		}
	} else if mode == modeTail {
		t.verify(p, tr, f, meta)
		if tr.lazy {
			t.activate(tr, w.parser, f, meta)
		}
	}

	if mode != modeTail && p.budget <= 0 {
		// Whole-file formats cannot stop halfway; when this poll's byte
		// budget is spent they wait for the next one.
		tr.more = true
		t.dirty = true
		return
	}
	switch mode {
	case modeTail:
		t.tail(p, tr, w.parser, f, meta)
	case modeZstd:
		t.archive(p, tr, w.parser, f, meta)
	case modeDocument:
		t.document(p, tr, w.parser, f, meta)
	}
}

func sessionOf(tr *tracked) string {
	if tr == nil || tr.st == nil {
		return ""
	}
	return tr.st.SessionID
}

func (t *Tailer) openProblem(p *pass, path string, tr *tracked, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Gone between listing and open; the next pass sorts it out.
	case errors.Is(err, errSymlink):
		t.standing(p, ProblemSymlinkRefused, path, sessionOf(tr), "a symbolic link is in the session log path")
	case errors.Is(err, errNotRegular):
		t.standing(p, ProblemUnreadable, path, sessionOf(tr), "not a regular file")
	default:
		t.standing(p, ProblemUnreadable, path, sessionOf(tr), errText(err))
	}
}

// errText renders an OS error without repeating the path, which the Problem
// already carries.
func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// archiveOfKnown reports whether path is the compressed archive of a log
// that is already being followed; its content was read from the original.
func (t *Tailer) archiveOfKnown(path string, mode fileMode) bool {
	if mode != modeZstd {
		return false
	}
	return t.files[strings.TrimSuffix(path, ".zst")] != nil
}

// startAtEnd adopts a file without emitting its existing content.
func (t *Tailer) startAtEnd(tr *tracked, parser Parser, f *os.File, meta fileMeta, mode fileMode) {
	tr.cp = Checkpoint{Offset: meta.size, Size: meta.size, FileID: meta.id, MTime: meta.mtime}
	switch mode {
	case modeTail:
		if b, ok := lastByte(f, meta.size); ok && b != '\n' {
			// The writer is mid-line; the rest of that line is not a
			// record and must be discarded when it arrives.
			tr.skipping = true
		}
		t.prime(tr, parser, f, meta.size)
		tr.tail = tailPrint(f, meta.size)
	case modeDocument:
		// Learn which messages already exist so a later rewrite only
		// yields the new ones.
		if b, err := readDocument(f, meta.size); err == nil {
			_, _ = parser.ParseLine(b, tr.st)
			quiesce(tr.st)
		}
	}
}

// activate finishes the adoption of a file that was remembered from its
// metadata alone and has now changed.
func (t *Tailer) activate(tr *tracked, parser Parser, f *os.File, meta fileMeta) {
	tr.lazy = false
	if tr.cp.FileID == "" {
		tr.cp.FileID = meta.id
	}
	if tr.cp.Offset > meta.size {
		return // verify() has already reset it
	}
	if b, ok := lastByte(f, tr.cp.Offset); ok && b != '\n' {
		tr.skipping = true
	}
	t.prime(tr, parser, f, tr.cp.Offset)
}

// prime parses the head of a file with events discarded, so that reading
// which starts mid-file still knows the session id, cwd and model that only
// the first records carry.
func (t *Tailer) prime(tr *tracked, parser Parser, f *os.File, upTo int64) {
	if upTo <= 0 {
		return
	}
	if upTo > primeBytes {
		upTo = primeBytes
	}
	budget := int64(primeBytes)
	_, _ = readLines(f, 0, upTo, t.o.MaxLine, false, &budget, func() bool { return false }, func(line []byte) {
		_, _ = parser.ParseLine(line, tr.st)
	})
	quiesce(tr.st)
}

// quiesce clears what priming must not leave behind: counters of lines that
// were not really consumed, calls that will never be paired, and a "latest
// timestamp" that belongs to old records.
func quiesce(st *FileState) {
	st.Lines, st.Unknown, st.Malformed, st.Oversize = 0, 0, 0, 0
	st.Pending, st.pendOrder, st.hints = nil, nil, nil
	st.lastTS = time.Time{}
}

// verify detects a log that is no longer the one the checkpoint describes
// and, unless the content up to the checkpoint is intact, starts over.
func (t *Tailer) verify(p *pass, tr *tracked, f *os.File, meta fileMeta) {
	restart := func(kind, detail string) {
		p.problem(kind, tr.path, sessionOf(tr), detail)
		old := tr.st
		tr.st = &FileState{Path: tr.path}
		if old != nil {
			// Ids already turned into events stay known, so a format
			// that rewrites its file (Gemini CLI) does not replay them.
			tr.st.user, tr.st.seen, tr.st.seenRing = old.user, old.seen, old.seenRing
		}
		tr.cp.Offset, tr.skipping, tr.tail, tr.drift, tr.lazy = 0, false, "", false, false
		t.dirty = true
	}
	intact := func() bool {
		return meta.size >= tr.cp.Offset && tr.tail != "" && tailPrint(f, tr.cp.Offset) == tr.tail
	}
	switch {
	case meta.id != "" && tr.cp.FileID != "" && meta.id != tr.cp.FileID:
		if intact() {
			p.problem(ProblemReplaced, tr.path, sessionOf(tr), "file was replaced; content up to the checkpoint is unchanged, continuing")
			t.dirty = true
		} else {
			restart(ProblemReplaced, "file was replaced by a different one; reading it from the start")
		}
	case meta.size < tr.cp.Offset:
		restart(ProblemTruncated, fmt.Sprintf("size %d is below the checkpoint %d; reading from the start", meta.size, tr.cp.Offset))
	case tr.cp.Offset > 0 && tr.tail != "" && !intact():
		restart(ProblemTruncated, "content before the checkpoint changed (rewritten in place); reading from the start")
	case meta.size < tr.cp.Size:
		// Shorter than when last seen, yet everything already read is
		// intact: bytes that were written and not yet consumed (at most an
		// unterminated line) were taken back. Nothing to re-read, but an
		// append-only log does not shrink on its own.
		p.problem(ProblemTruncated, tr.path, sessionOf(tr),
			fmt.Sprintf("file shrank from %d to %d bytes; unread bytes after the checkpoint were removed", tr.cp.Size, meta.size))
		t.dirty = true
	}
}

func (t *Tailer) tail(p *pass, tr *tracked, parser Parser, f *os.File, meta fileMeta) {
	stop := func() bool { return p.ctx.Err() != nil }
	res, err := readLines(f, tr.cp.Offset, meta.size, t.o.MaxLine, tr.skipping, &p.budget, stop, func(line []byte) {
		evs, _ := parser.ParseLine(line, tr.st)
		p.evs = append(p.evs, evs...)
	})
	if res.offset != tr.cp.Offset || res.oversize > 0 {
		tr.lastRead = p.now.Unix()
	}
	tr.st.Oversize += res.oversize
	tr.cp = Checkpoint{Offset: res.offset, Size: meta.size, FileID: meta.id, MTime: meta.mtime}
	tr.skipping, tr.more = res.skipping, res.more
	tr.tail = tailPrint(f, res.offset)
	t.dirty = true
	if err != nil {
		t.standing(p, ProblemUnreadable, tr.path, sessionOf(tr), "read: "+errText(err))
	}
	t.checkDrift(p, tr)
}

// archive reads a compressed rollout whole. There is nothing to tail: the
// archive is written once, after the session went idle.
func (t *Tailer) archive(p *pass, tr *tracked, parser Parser, f *os.File, meta fileMeta) {
	user := tr.st.user
	tr.st = &FileState{Path: tr.path, user: user}
	stop := func() bool { return p.ctx.Err() != nil }
	oversize, err := readZstdLines(f, t.o.MaxLine, stop, func(line []byte) {
		evs, _ := parser.ParseLine(line, tr.st)
		p.evs = append(p.evs, evs...)
	})
	p.budget -= meta.size
	tr.st.Oversize += oversize
	t.dirty = true
	if errors.Is(err, errStopped) {
		// Cancelled midway: leave the checkpoint at zero so the archive
		// is read again; the repeated events carry the same ids.
		tr.cp = Checkpoint{FileID: meta.id}
		tr.more = true
		return
	}
	tr.cp = Checkpoint{Offset: meta.size, Size: meta.size, FileID: meta.id, MTime: meta.mtime}
	tr.more, tr.lazy, tr.lastRead = false, false, p.now.Unix()
	if err != nil {
		t.standing(p, ProblemUnreadable, tr.path, sessionOf(tr), "decompress: "+errText(err))
	}
	t.checkDrift(p, tr)
}

// document reads a file that is one JSON document rewritten on every
// change. The parser's own id bookkeeping keeps already-seen messages from
// repeating, so truncation and replacement are normal here, not problems.
func (t *Tailer) document(p *pass, tr *tracked, parser Parser, f *os.File, meta fileMeta) {
	tr.cp = Checkpoint{Offset: meta.size, Size: meta.size, FileID: meta.id, MTime: meta.mtime}
	tr.lazy, tr.more = false, false
	t.dirty = true
	b, err := readDocument(f, meta.size)
	if err != nil {
		t.standing(p, ProblemUnreadable, tr.path, sessionOf(tr), errText(err))
		return
	}
	p.budget -= int64(len(b))
	evs, _ := parser.ParseLine(b, tr.st)
	p.evs = append(p.evs, evs...)
	tr.lastRead = p.now.Unix()
}

func (t *Tailer) checkDrift(p *pass, tr *tracked) {
	st := tr.st
	if tr.drift || st.Lines < driftMinLines || (st.Unknown+st.Malformed)*2 <= st.Lines {
		return
	}
	tr.drift = true
	p.problem(ProblemSchemaDrift, tr.path, st.SessionID,
		fmt.Sprintf("unknown=%d malformed=%d lines=%d: most records are not understood by the %s parser", st.Unknown, st.Malformed, st.Lines, tr.format))
}

// reap handles followed files that the listing no longer contains.
func (t *Tailer) reap(p *pass, found map[string]bool) {
	for path, tr := range t.files {
		if found[path] {
			continue
		}
		_, err := lstatMeta(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			delete(t.files, path)
			delete(t.reported, path)
			t.dirty = true
			if _, zerr := lstatMeta(path + ".zst"); zerr == nil {
				continue // compressed in place, not removed
			}
			// Old logs age out by retention and are not news. A log
			// that was active inside the backfill window is.
			idle := p.now.Sub(time.Unix(0, tr.cp.MTime))
			if last := time.Unix(tr.lastRead, 0); tr.lastRead > 0 && p.now.Sub(last) < idle {
				idle = p.now.Sub(last)
			}
			if idle <= t.o.MaxBackfill {
				p.problem(ProblemDeleted, path, sessionOf(tr),
					fmt.Sprintf("session log removed %s after its last activity", idle.Round(time.Second)))
			}
		case err != nil:
			t.standing(p, ProblemUnreadable, path, sessionOf(tr), errText(err))
		default:
			// Still on disk but outside every root (root list changed,
			// or its directory cannot be listed right now).
			if p.now.Unix()-tr.lastSeen > int64(orphanGrace/time.Second) {
				delete(t.files, path)
				delete(t.reported, path)
				t.dirty = true
			}
		}
	}
}
