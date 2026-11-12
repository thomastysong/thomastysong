package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/transcript"
)

// transcriptRunner follows agents' session logs.
//
// Start at end of file (design/BUILD-C.md, Addendum): files that already
// exist when hawkbell first looks at a root are not read back.
// transcript.Tailer applies TailerOptions.FromStart to every file it has
// not seen before, so one tailer cannot both skip what existed and read new
// sessions from their first line. The runner therefore primes: when roots
// are new (first start on this data directory, a new account, a
// configuration home the process monitor just reported), a tailer with
// FromStart false makes one pass over those new roots only, which records
// the current end of every file in them; its checkpoints are committed and
// the steady tailer (FromStart true) then loads them, so every file created
// afterwards, in any root, is read from its first line. Priming only the
// new roots matters: a session file created in an admitted root since the
// steady tailer's last poll did not exist when its root was first seen and
// must not be started at its end because some other root appeared. The
// steady tailer follows admitted roots only, so a root whose priming failed
// is never read from the start.
//
// The admitted roots are kept in the checkpoint directory with the time
// each was last listed, and a root that is not listed is remembered for
// admittedGrace before it is forgotten (and primed again if it comes
// back). A configuration home is listed only once the process monitor has
// reported an agent using it, which after a restart can take a while; it
// must not be primed again then, or the sessions written there while the
// daemon was down would be skipped.
//
// sources.transcripts.backfill > 0 turns priming off: files modified within
// that window are read from the start on first sight.
type transcriptRunner struct {
	d         *daemon
	stateFile string
	rootsFile string
	backfill  time.Duration

	mu       sync.Mutex // guards t and roots (commit from the shutdown path)
	t        *transcript.Tailer
	roots    []transcript.Root // what the steady tailer follows
	admitted map[string]int64  // root glob -> last listed (Unix seconds)
	savedAt  int64             // when the roots file was last written
	loaded   bool
	off      bool // the kill switch was on at the last look
}

const (
	// admittedGrace is how long an admitted root outlives its last listing:
	// the transcript tailer keeps a checkpoint as long after its root
	// disappears (orphanGrace), so the two expire together.
	admittedGrace = 7 * 24 * time.Hour
	// admittedRefresh bounds how stale the persisted listing times get.
	admittedRefresh = time.Hour
)

func newTranscriptRunner(d *daemon) *transcriptRunner {
	return &transcriptRunner{
		d:         d,
		stateFile: filepath.Join(d.layout.check, "transcripts.json"),
		rootsFile: filepath.Join(d.layout.check, "transcript-roots.json"),
		backfill:  d.cfg.Sources.Transcripts.Backfill.D(),
		admitted:  map[string]int64{},
	}
}

func (r *transcriptRunner) run(ctx context.Context) error {
	d := r.d
	if !config.On(d.cfg.Sources.Transcripts.Enabled, true) {
		d.board.surface(event.SurfaceStatus{Name: "transcripts", Status: "disabled", Reason: "config"})
		<-ctx.Done()
		return nil
	}
	if d.cfg.HostRoot != "" {
		d.board.surface(event.SurfaceStatus{Name: "transcripts", Status: "disabled", Reason: "host_root"})
		<-ctx.Done()
		return nil
	}
	poll := d.cfg.Sources.Transcripts.Poll.D()
	if poll <= 0 {
		poll = 2 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		r.step(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// step is one poll: kill switch, root changes (priming), then reading.
func (r *transcriptRunner) step(ctx context.Context) {
	d := r.d
	off, settling := d.gate.state()
	if off {
		r.off = true
		d.board.update("transcripts", func(s *event.SurfaceStatus) { s.Status, s.Reason = "disabled", "kill_switch" })
		return
	}
	if !r.loaded {
		r.loadAdmitted()
		r.loaded = true
	}
	if r.off {
		// Nothing written while the sensor was switched off is collected
		// afterwards: forget the checkpoints and prime at once, so every
		// file starts where it stands at the release (a priming pass with
		// no checkpoints hands nothing over).
		r.off = false
		r.reset()
		r.prime(ctx, d.transcriptRoots())
	}
	if settling {
		return
	}
	roots := d.transcriptRoots()
	var fresh []transcript.Root
	for _, rt := range roots {
		if _, ok := r.admitted[rt.Glob]; !ok {
			fresh = append(fresh, rt)
		}
	}
	if len(fresh) > 0 {
		if r.backfill > 0 {
			r.admit(fresh)
		} else {
			r.prime(ctx, fresh)
		}
	}
	r.touch(roots)
	steady := roots[:0:0]
	for _, rt := range roots {
		if _, ok := r.admitted[rt.Glob]; ok {
			steady = append(steady, rt)
		}
	}
	r.mu.Lock()
	r.roots = steady
	if r.t == nil {
		r.t = r.newTailer(true, r.currentRoots)
	}
	tl := r.t
	r.mu.Unlock()
	// Lines handed over by the previous poll have been processed by now
	// (the pipeline ticks every second): commit them before reading more.
	if err := tl.Commit(); err != nil {
		d.board.add("transcript.checkpoint_errors", 1)
	}
	evs, probs, err := tl.Poll(ctx)
	r.handle(evs, probs, err)
}

func (r *transcriptRunner) newTailer(fromStart bool, roots func() []transcript.Root) *transcript.Tailer {
	o := transcript.TailerOptions{
		Roots:       roots,
		StateFile:   r.stateFile,
		FromStart:   fromStart,
		DeferCommit: true,
	}
	if r.backfill > 0 {
		o.MaxBackfill = r.backfill
	}
	return transcript.NewTailer(o)
}

// currentRoots is the steady tailer's Roots: the admitted roots.
func (r *transcriptRunner) currentRoots() []transcript.Root {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]transcript.Root(nil), r.roots...)
}

// prime records the end of every file not yet known in the given new roots
// (see the type comment) and admits them.
func (r *transcriptRunner) prime(ctx context.Context, fresh []transcript.Root) {
	r.mu.Lock()
	if r.t != nil {
		// The priming tailer loads the checkpoint store: everything the
		// steady tailer knows must be in it, and the steady tailer is
		// reloaded from it afterwards.
		if err := r.t.Commit(); err != nil {
			r.d.board.add("transcript.checkpoint_errors", 1)
		}
		r.t = nil
	}
	r.mu.Unlock()
	only := append([]transcript.Root(nil), fresh...)
	p := r.newTailer(false, func() []transcript.Root { return only })
	evs, probs, err := p.Poll(ctx)
	r.handle(evs, probs, err)
	if err := p.Commit(); err != nil {
		r.d.board.add("transcript.checkpoint_errors", 1)
		return // admit again next time rather than read the files from the start
	}
	r.admit(fresh)
	r.d.board.add("transcript.primes", 1)
	if r.d.env.onTranscriptPrimed != nil {
		r.d.env.onTranscriptPrimed()
	}
}

// admit records roots as seen and saves the list.
func (r *transcriptRunner) admit(roots []transcript.Root) {
	now := r.d.env.now().Unix()
	for _, rt := range roots {
		r.admitted[rt.Glob] = now
	}
	r.saveAdmitted(now)
}

// touch notes that the listed roots are still there and forgets admitted
// roots that have not been listed for admittedGrace, so a home that comes
// back after that is primed again.
func (r *transcriptRunner) touch(listed []transcript.Root) {
	now := r.d.env.now().Unix()
	for _, rt := range listed {
		if _, ok := r.admitted[rt.Glob]; ok {
			r.admitted[rt.Glob] = now
		}
	}
	changed := false
	for g, last := range r.admitted {
		if now-last > int64(admittedGrace/time.Second) {
			delete(r.admitted, g)
			changed = true
		}
	}
	if changed || now-r.savedAt >= int64(admittedRefresh/time.Second) {
		r.saveAdmitted(now)
	}
}

// reset drops every checkpoint so that the next step primes all roots.
func (r *transcriptRunner) reset() {
	r.mu.Lock()
	r.t = nil
	r.mu.Unlock()
	if err := os.Remove(r.stateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.d.board.add("transcript.checkpoint_errors", 1)
	}
	r.admitted = map[string]int64{}
	_ = os.Remove(r.rootsFile)
}

// handle ingests what a poll returned and accounts for its problems.
func (r *transcriptRunner) handle(evs []*event.Event, probs []transcript.Problem, err error) {
	d := r.d
	if len(evs) > 0 {
		d.ingest(evs...)
	}
	drift := false
	for _, p := range probs {
		switch p.Kind {
		case transcript.ProblemTruncated, transcript.ProblemReplaced, transcript.ProblemDeleted,
			transcript.ProblemUnreadable, transcript.ProblemSchemaDrift,
			transcript.ProblemSymlinkRefused, transcript.ProblemOwnerMismatch:
			d.board.add("transcript."+p.Kind, 1)
		default:
			d.board.add("transcript.other", 1)
		}
		if p.Kind == transcript.ProblemSchemaDrift {
			drift = true
		}
	}
	failed := err != nil && !errors.Is(err, context.Canceled)
	if failed {
		d.board.add("transcript.errors", 1)
	}
	d.board.update("transcripts", func(s *event.SurfaceStatus) {
		s.Status, s.Reason = "ok", ""
		s.Errors += uint64(len(probs))
		if drift {
			s.SchemaDrift = true
		}
		if failed {
			s.Status, s.Reason = "degraded", "checkpoint"
		}
	})
}

// commit writes the checkpoints at shutdown, after the pipeline has
// processed everything.
func (r *transcriptRunner) commit() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.t != nil {
		_ = r.t.Commit()
	}
}

// admittedFile is the roots file. Version 1 listed globs only; version 2
// adds when each was last listed.
type admittedFile struct {
	V     int              `json:"v"`
	Globs []string         `json:"globs,omitempty"`
	Roots map[string]int64 `json:"roots,omitempty"`
}

// maxAdmitted bounds the roots file (accounts x agents x configuration homes).
const maxAdmitted = 1 << 14

// loadAdmitted reads the roots primed by an earlier run. The checkpoint
// store itself may not exist (no session file had been seen yet); the roots
// file alone says the roots were looked at. Deleting the store but not the
// roots file makes the next run read files modified in the last 24 h from
// their start: that is the explicit backfill.
func (r *transcriptRunner) loadAdmitted() {
	b, err := readSmallFile(r.rootsFile, 4<<20)
	if err != nil {
		return
	}
	var f admittedFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	now := r.d.env.now().Unix()
	switch f.V {
	case 1:
		for _, g := range f.Globs {
			if len(r.admitted) < maxAdmitted {
				r.admitted[g] = now
			}
		}
	case 2:
		for g, last := range f.Roots {
			if len(r.admitted) < maxAdmitted {
				r.admitted[g] = min(last, now)
			}
		}
	}
	r.savedAt = now
}

func (r *transcriptRunner) saveAdmitted(now int64) {
	f := admittedFile{V: 2, Roots: r.admitted}
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	if err := writeFileAtomic(r.rootsFile, b, 0o600); err != nil {
		r.d.board.add("transcript.checkpoint_errors", 1)
		return
	}
	r.savedAt = now
}

// transcriptRoots lists the session-log roots of every account: the default
// locations under the home, and configuration homes the process monitor saw
// in that account's agents' environments. sources.transcripts.agents limits
// the agents.
func (d *daemon) transcriptRoots() []transcript.Root {
	want := map[string]bool{}
	for _, a := range d.cfg.Sources.Transcripts.Agents {
		want[a] = true
	}
	var roots []transcript.Root
	seen := map[string]bool{}
	add := func(list []transcript.Root) {
		for _, rt := range list {
			if rt.Parser != nil && len(want) > 0 && !want[rt.Parser.AgentID()] {
				continue
			}
			if seen[rt.Glob] {
				continue
			}
			seen[rt.Glob] = true
			roots = append(roots, rt)
		}
	}
	users := d.users.all()
	byUID := map[string]event.User{}
	for _, u := range users {
		eu := event.User{Name: u.Name, ID: u.UID}
		if _, ok := byUID[u.UID]; !ok {
			byUID[u.UID] = eu
		}
		add(transcript.HomeRoots(u.Home, eu))
	}
	homes := d.procs.configHomes()
	uids := make([]string, 0, len(homes))
	for uid := range homes {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		eu, ok := byUID[uid]
		if !ok {
			continue
		}
		agents := homes[uid]
		names := make([]string, 0, len(agents))
		for a := range agents {
			names = append(names, a)
		}
		sort.Strings(names)
		for _, agent := range names {
			for _, dir := range agents[agent] {
				if agent == "gemini-cli" {
					// GEMINI_CLI_HOME names the parent of .gemini.
					dir = filepath.Join(dir, ".gemini")
				}
				add(transcript.ConfigRoots(agent, dir, eu))
			}
		}
	}
	return roots
}
