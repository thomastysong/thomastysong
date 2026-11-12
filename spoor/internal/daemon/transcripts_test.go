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
