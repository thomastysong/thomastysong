package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/procmon"
)

// TestTranscriptPriming walks the start-at-end rules through restarts, a
// configuration home that appears later, and the kill switch.
func TestTranscriptPriming(t *testing.T) {
	f := newFixture(t)
	home := f.user.Home
	cwd := filepath.Join(home, "repo")
	proj := filepath.Join(home, ".claude", "projects", "-repo")
	a := filepath.Join(proj, "a.jsonl")
	mustWrite(t, a, claudeLines("sa", cwd, "toolu_a_before", "ls", time.Now()), 0o600)

	// Relocated configuration home, reported later by the process monitor.
	alt := filepath.Join(f.root, "alt-claude")
	altFile := filepath.Join(alt, "projects", "-repo", "c.jsonl")
	mustWrite(t, altFile, claudeLines("sc", cwd, "toolu_c_before", "ls", time.Now()), 0o600)
	if err := os.Chmod(alt, 0o755); err != nil {
		t.Fatal(err)
	}

	d, out := f.unitDaemon()
	r := newTranscriptRunner(d)
	ctx := context.Background()

	r.step(ctx) // first start: primes
	if d.board.get("transcript.primes") != 1 {
		t.Fatalf("primes = %d", d.board.get("transcript.primes"))
	}
	appendFile(t, a, claudeLines("sa", cwd, "toolu_a_after", "ls", time.Now()))
	mustWrite(t, filepath.Join(proj, "b.jsonl"), claudeLines("sb", cwd, "toolu_b_new", "ls", time.Now()), 0o600)
	r.step(ctx)

	// The monitor reports the relocated home: a new root, primed again.
	d.procs.set([]procmon.AgentProc{{PID: 42, AgentID: "claude-code", User: event.User{Name: "alice", ID: f.user.UID}, ConfigHome: alt}}, d.users)
	r.step(ctx)
	if d.board.get("transcript.primes") != 2 {
		t.Fatalf("a new root was not primed: primes = %d", d.board.get("transcript.primes"))
	}
	appendFile(t, altFile, claudeLines("sc", cwd, "toolu_c_after", "ls", time.Now()))
	r.step(ctx)
	r.commit()

	// Restart: a session file written while the daemon was down is read
	// from its first line; nothing is primed again.
	mustWrite(t, filepath.Join(proj, "d.jsonl"), claudeLines("sd", cwd, "toolu_d_down", "ls", time.Now()), 0o600)
	r2 := newTranscriptRunner(d)
	d.procs = newProcView() // the relocated home is not known yet after a restart
	d.procs.set([]procmon.AgentProc{{PID: 42, AgentID: "claude-code", User: event.User{Name: "alice", ID: f.user.UID}, ConfigHome: alt}}, d.users)
	r2.step(ctx)
	if d.board.get("transcript.primes") != 2 {
		t.Errorf("a restart primed again: primes = %d", d.board.get("transcript.primes"))
	}

	// Kill switch: what is written while it is on is never collected.
	// (Tick first: the pipeline drops what is still queued when the switch
	// is pulled, by design.)
	d.pipe.Tick(time.Now())
	f.off.Store(true)
	r2.step(ctx)
	appendFile(t, a, claudeLines("sa", cwd, "toolu_a_off", "ls", time.Now()))
	f.off.Store(false)
	r2.step(ctx) // reset and prime at the release
	appendFile(t, a, claudeLines("sa", cwd, "toolu_a_on", "ls", time.Now()))
	r2.step(ctx) // settling: the pipeline may still drop input
	if got := out.useIDs(); got["toolu_a_on"] {
		t.Error("records were handed over while the pipeline could still drop them")
	}
	time.Sleep(releaseSettle)
	r2.step(ctx)
	r2.commit()

	if err := d.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	got := out.useIDs()
	for id, want := range map[string]bool{
		"toolu_a_before": false, // existed at first sight
		"toolu_c_before": false, // existed when its root first appeared
		"toolu_a_after":  true,
		"toolu_b_new":    true, // new file: read from the start
		"toolu_c_after":  true,
		"toolu_d_down":   true, // written while the daemon was down
		"toolu_a_off":    false,
		"toolu_a_on":     true,
	} {
		if got[id] != want {
			t.Errorf("%s collected = %v, want %v", id, got[id], want)
		}
	}
}

func TestTranscriptBackfill(t *testing.T) {
	f := newFixture(t)
	f.cfg.Sources.Transcripts.Backfill = config.Duration(48 * time.Hour)
	home := f.user.Home
	a := filepath.Join(home, ".claude", "projects", "-repo", "a.jsonl")
	mustWrite(t, a, claudeLines("sa", filepath.Join(home, "repo"), "toolu_backfilled", "ls", time.Now()), 0o600)
	d, out := f.unitDaemon()
	r := newTranscriptRunner(d)
	r.step(context.Background())
	r.commit()
	d.pipe.Close()
	if d.board.get("transcript.primes") != 0 {
		t.Error("backfill must not prime")
	}
	if !out.useIDs()["toolu_backfilled"] {
		t.Error("backfill did not read a pre-existing file")
	}
}

func TestTranscriptRootsFilterAndHomes(t *testing.T) {
	f := newFixture(t)
	f.cfg.Sources.Transcripts.Agents = []string{"gemini-cli"}
	d, _ := f.unitDaemon()
	gemHome := filepath.Join(f.root, "gem")
	mustMkdir(t, gemHome, 0o755)
	d.procs.set([]procmon.AgentProc{
		{AgentID: "gemini-cli", User: event.User{ID: f.user.UID}, ConfigHome: gemHome},
		{AgentID: "claude-code", User: event.User{ID: f.user.UID}, ConfigHome: "relative/dir"},
		{AgentID: "claude-code", User: event.User{ID: "999999"}, ConfigHome: gemHome}, // unknown account
	}, d.users)
	roots := d.transcriptRoots()
	if len(roots) == 0 {
		t.Fatal("no roots")
	}
	sawRelocated := false
	for _, r := range roots {
		if r.Parser == nil || r.Parser.AgentID() != "gemini-cli" {
			t.Errorf("root for another agent: %s", r.Glob)
		}
		if r.User.ID != f.user.UID {
			t.Errorf("root %s has user %+v", r.Glob, r.User)
		}
		if strings.HasPrefix(r.Glob, filepath.Join(gemHome, ".gemini")+string(filepath.Separator)) {
			sawRelocated = true
		}
	}
	if !sawRelocated {
		t.Errorf("GEMINI_CLI_HOME root missing: %v", roots)
	}
}

// TestTranscriptFirstSessionOnEmptyHome: with no session log yet the
// checkpoint store stays empty; the first session created afterwards, and
// one created while the daemon was down, must still be read from their
// first line.
func TestTranscriptFirstSessionOnEmptyHome(t *testing.T) {
	f := newFixture(t)
	home := f.user.Home
	cwd := filepath.Join(home, "repo")
	proj := filepath.Join(home, ".claude", "projects", "-repo")
	d, out := f.unitDaemon()
	ctx := context.Background()
	r := newTranscriptRunner(d)
	r.step(ctx)
	r.step(ctx)
	if n := d.board.get("transcript.primes"); n != 1 {
		t.Fatalf("primes = %d, want 1", n)
	}
	mustWrite(t, filepath.Join(proj, "first.jsonl"), claudeLines("s1", cwd, "toolu_first", "ls", time.Now()), 0o600)
	r.step(ctx)
	r.commit()
	mustWrite(t, filepath.Join(proj, "down.jsonl"), claudeLines("s2", cwd, "toolu_down", "ls", time.Now()), 0o600)
	r2 := newTranscriptRunner(d)
	r2.step(ctx)
	r2.commit()
	d.pipe.Close()
	if n := d.board.get("transcript.primes"); n != 1 {
		t.Errorf("primes = %d after a restart, want 1", n)
	}
	got := out.useIDs()
	if !got["toolu_first"] || !got["toolu_down"] {
		t.Errorf("collected %v", got)
	}
}

// TestTranscriptNewRootPrimesOnlyItself: when a new root appears (here a
// relocated configuration home reported by the process monitor), only that
// root is primed. A session file created in an already admitted root since
// the steady tailer's last poll did not exist when its root was first seen
// and is read from its first line.
func TestTranscriptNewRootPrimesOnlyItself(t *testing.T) {
	f := newFixture(t)
	home := f.user.Home
	cwd := filepath.Join(home, "repo")
	proj := filepath.Join(home, ".claude", "projects", "-repo")
	mustMkdir(t, proj, 0o755)
	alt := filepath.Join(f.root, "alt-claude")
	mustMkdir(t, filepath.Join(alt, "projects", "-repo"), 0o755)
	mustWrite(t, filepath.Join(alt, "projects", "-repo", "old.jsonl"), claudeLines("s-old", cwd, "toolu_alt_old", "ls", time.Now()), 0o600)
	if err := os.Chmod(alt, 0o755); err != nil {
		t.Fatal(err)
	}

	d, out := f.unitDaemon()
	r := newTranscriptRunner(d)
	ctx := context.Background()
	r.step(ctx) // first start: the home root is primed
	r.step(ctx) // steady tailer

	// A new session starts in the home root, which is long admitted ...
	mustWrite(t, filepath.Join(proj, "new.jsonl"), claudeLines("s-new", cwd, "toolu_new_session", "ls", time.Now()), 0o600)
	// ... and before the next poll the monitor reports a relocated home.
	d.procs.set([]procmon.AgentProc{{PID: 7, AgentID: "claude-code", User: event.User{Name: "alice", ID: f.user.UID}, ConfigHome: alt}}, d.users)
	r.step(ctx)
	r.step(ctx)
	r.commit()
	if err := d.pipe.Close(); err != nil {
		t.Fatal(err)
	}
	if d.board.get("transcript.primes") != 2 {
		t.Fatalf("primes = %d, want 2", d.board.get("transcript.primes"))
	}
	got := out.useIDs()
	if !got["toolu_new_session"] {
		t.Error("a session file created after its root was admitted was started at its end because another root appeared: its first records were lost")
	}
	if got["toolu_alt_old"] {
		t.Error("a file that existed when the new root was first seen was read back")
	}
}

// TestTranscriptRestartRemembersConfigHome: admitted roots are remembered
// across a restart even while they are not listed. After a restart the
// process monitor has not reported configuration homes yet; another root
// that is new first (a new account) must not make the daemon forget the
// relocated home, or the session written there while the daemon was down
// would be started at its end when the home is reported again.
func TestTranscriptRestartRemembersConfigHome(t *testing.T) {
	f := newFixture(t)
	cwd := filepath.Join(f.user.Home, "repo")
	alt := filepath.Join(f.root, "alt-claude")
	altProj := filepath.Join(alt, "projects", "-repo")
	mustMkdir(t, altProj, 0o755)
	if err := os.Chmod(alt, 0o755); err != nil {
		t.Fatal(err)
	}
	d, out := f.unitDaemon()
	ctx := context.Background()
	agent := []procmon.AgentProc{{PID: 9, AgentID: "claude-code", User: event.User{Name: "alice", ID: f.user.UID}, ConfigHome: alt}}
	d.procs.set(agent, d.users)
	r := newTranscriptRunner(d)
	r.step(ctx) // first start: home and relocated home primed together
	r.step(ctx)
	r.commit()

	// Daemon down: a session is written in the relocated home.
	mustWrite(t, filepath.Join(altProj, "down.jsonl"), claudeLines("s-down", cwd, "toolu_alt_down", "ls", time.Now()), 0o600)

	// Restart: a second account exists now; the monitor has not reported
	// the relocated home yet.
	bobHome := filepath.Join(f.root, "home", "bob")
	mustMkdir(t, bobHome, 0o755)
	d.users.set([]platform.UserHome{f.user, {Name: "bob", UID: f.user.UID, Home: bobHome}})
	d.procs = newProcView()
	r2 := newTranscriptRunner(d)
	r2.step(ctx)
	d.procs.set(agent, d.users) // the agent is seen again
	r2.step(ctx)
	r2.step(ctx)
	r2.commit()
	d.pipe.Close()
	if n := d.board.get("transcript.primes"); n != 2 {
		t.Errorf("primes = %d, want 2 (first start, the new account)", n)
	}
	if !out.useIDs()["toolu_alt_down"] {
		t.Error("a session written in a remembered configuration home while the daemon was down was skipped after the restart")
	}
}

// TestTranscriptAdmittedRootExpires: a root that has not been listed for
// admittedGrace is forgotten, and primed again if it comes back; one that
// is listed keeps its admission.
func TestTranscriptAdmittedRootExpires(t *testing.T) {
	f := newFixture(t)
	cwd := filepath.Join(f.user.Home, "repo")
	alt := filepath.Join(f.root, "alt-claude")
	altProj := filepath.Join(alt, "projects", "-repo")
	mustMkdir(t, altProj, 0o755)
	if err := os.Chmod(alt, 0o755); err != nil {
		t.Fatal(err)
	}
	d, out := f.unitDaemon()
	clock := time.Now()
	d.env.now = func() time.Time { return clock }
	ctx := context.Background()
	agent := []procmon.AgentProc{{PID: 9, AgentID: "claude-code", User: event.User{Name: "alice", ID: f.user.UID}, ConfigHome: alt}}
	d.procs.set(agent, d.users)
	r := newTranscriptRunner(d)
	r.step(ctx)
	if d.board.get("transcript.primes") != 1 {
		t.Fatalf("primes = %d", d.board.get("transcript.primes"))
	}
	d.procs = newProcView() // the home is no longer listed
	clock = clock.Add(admittedGrace / 2)
	r.step(ctx)
	if !r.hasAdmitted(alt) {
		t.Fatal("a root was forgotten before its grace ran out")
	}
	clock = clock.Add(admittedGrace/2 + time.Hour)
	r.step(ctx)
	if r.hasAdmitted(alt) {
		t.Fatal("a root unlisted for longer than its grace is still admitted")
	}
	// The home comes back: what is in it now existed before this sighting.
	mustWrite(t, filepath.Join(altProj, "later.jsonl"), claudeLines("s-later", cwd, "toolu_alt_later", "ls", time.Now()), 0o600)
	d.procs.set(agent, d.users)
	r.step(ctx)
	r.commit()
	d.pipe.Close()
	if n := d.board.get("transcript.primes"); n != 2 {
		t.Errorf("primes = %d, want 2", n)
	}
	if out.useIDs()["toolu_alt_later"] {
		t.Error("a file in a root seen again after its grace was read back")
	}
	// The roots file carries the listing times.
	b, err := os.ReadFile(filepath.Join(d.layout.check, "transcript-roots.json"))
	if err != nil || !strings.Contains(string(b), `"v":2`) {
		t.Errorf("roots file = %s, %v", b, err)
	}
}

// hasAdmitted reports whether any admitted root lies under dir.
func (r *transcriptRunner) hasAdmitted(dir string) bool {
	pre := filepath.Clean(dir) + string(filepath.Separator)
	for g := range r.admitted {
		if strings.HasPrefix(g, pre) {
			return true
		}
	}
	return false
}
