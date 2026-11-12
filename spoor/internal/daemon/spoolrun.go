package daemon

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/spool"
)

// spoolRunner ingests what hooks append to the spools.
//
// Two readers: the system spools (<data>/spool/<uid>/, where the reader
// deletes fully read files after retention.spool) and the users' own
// fallback spools under their homes, which hooks use when the system one is
// unreachable. The second reader never deletes anything: the daemon does
// not write into home directories (systemd ProtectHome=read-only).
type spoolRunner struct {
	d        *daemon
	sys, usr *spool.Reader
	standing map[string]time.Time // kind+path -> when last counted
}

// standingEvery is how often a problem that persists on the same file
// (a planted link, a file owned by someone else) is counted again.
const standingEvery = time.Hour

func newSpoolRunner(d *daemon) *spoolRunner {
	r := &spoolRunner{d: d, standing: map[string]time.Time{}}
	r.sys = spool.NewReader(spool.ReaderOptions{
		Roots:      r.systemRoots,
		Checkpoint: filepath.Join(d.layout.check, "spool.json"),
		Retain:     d.cfg.Retention.Spool.D(),
		Now:        d.env.now,
	})
	r.usr = spool.NewReader(spool.ReaderOptions{
		Roots:      r.userRoots,
		Checkpoint: filepath.Join(d.layout.check, "spool-user.json"),
		// Effectively never: see the type comment.
		Retain: 100 * 365 * 24 * time.Hour,
		Now:    d.env.now,
	})
	return r
}

func (r *spoolRunner) systemRoots() []spool.Root {
	var out []spool.Root
	seen := map[string]bool{}
	for _, u := range r.d.users.all() {
		dir, ok := r.d.layout.spoolDirFor(u.UID)
		if !ok || seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, spool.Root{Dir: dir, UID: u.UID, User: event.User{Name: u.Name, ID: u.UID}})
	}
	return out
}

func (r *spoolRunner) userRoots() []spool.Root {
	var out []spool.Root
	seen := map[string]bool{}
	for _, u := range r.d.users.all() {
		if u.UID == "" {
			continue
		}
		dir := platform.UserDirs(u.Home).Spool
		if dir == "" || seen[dir] {
			continue
		}
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		seen[dir] = true
		out = append(out, spool.Root{Dir: dir, UID: u.UID, User: event.User{Name: u.Name, ID: u.UID}})
	}
	return out
}

func (r *spoolRunner) run(ctx context.Context) error {
	d := r.d
	if !config.On(d.cfg.Sources.Hooks.Enabled, true) {
		d.board.surface(event.SurfaceStatus{Name: "hooks", Status: "disabled", Reason: "config"})
		<-ctx.Done()
		return nil
	}
	if d.cfg.HostRoot != "" {
		d.board.surface(event.SurfaceStatus{Name: "hooks", Status: "disabled", Reason: "host_root"})
		<-ctx.Done()
		return nil
	}
	poll := d.cfg.Sources.Hooks.Poll.D()
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if off, settling := d.gate.state(); off {
			d.board.update("hooks", func(s *event.SurfaceStatus) { s.Status, s.Reason = "disabled", "kill_switch" })
		} else if !settling {
			r.pollOnce(ctx)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (r *spoolRunner) pollOnce(ctx context.Context) {
	d := r.d
	failed := false
	var problems uint64
	for _, rd := range []*spool.Reader{r.sys, r.usr} {
		evs, probs, err := rd.Poll(ctx)
		if len(evs) > 0 {
			d.ingest(evs...)
		}
		problems += r.count(probs)
		if err != nil {
			failed = true
			d.board.add("spool.checkpoint_errors", 1)
		}
	}
	d.board.update("hooks", func(s *event.SurfaceStatus) {
		s.Status, s.Reason = "ok", ""
		s.Errors += problems
		if failed {
			s.Status, s.Reason = "degraded", "checkpoint"
		}
	})
}

// count turns reader problems into heartbeat counters and returns how many
// were counted. Hook supervisor failures (worker crash, timeout, bad
// reply) are hook_errors.<reason>; a line claiming a kind other than
// activity is spool.forged_kind, counted on its own because it is an
// attempt to inject findings.
func (r *spoolRunner) count(probs []spool.Problem) uint64 {
	now := r.d.env.now()
	var n uint64
	for _, p := range probs {
		switch p.Kind {
		case "hook_error":
			// The reader only passes reason codes of the form hook_[a-z_]+.
			r.d.board.add("hook_errors."+p.Detail, 1)
		case "owner_mismatch", "symlink_refused", "not_regular":
			k := p.Kind + "\x00" + p.Path
			if last, ok := r.standing[k]; ok && now.Sub(last) < standingEvery {
				continue
			}
			if len(r.standing) > 4096 {
				clear(r.standing)
			}
			r.standing[k] = now
			r.d.board.add("spool."+p.Kind, 1)
		default:
			r.d.board.add("spool."+safeKind(p.Kind), 1)
		}
		n++
	}
	return n
}

// safeKind keeps counter names inside the reader's closed vocabulary.
func safeKind(k string) string {
	switch k {
	case "forged_kind", "oversize_line", "rate_limited", "malformed", "truncated":
		return k
	}
	return "other"
}
