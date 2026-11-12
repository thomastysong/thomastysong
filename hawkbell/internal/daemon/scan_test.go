package daemon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

func sessionEvent(uid, cwd string) *event.Event {
	ev := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
	ev.User = &event.User{Name: "alice", ID: uid}
	ev.Session = &event.Session{ID: "s", CWD: cwd}
	return ev
}

func TestQueueProjectRules(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.user.Home, "secret")
	f.cfg.Privacy.Exclude.Paths = []string{secret + "/**", secret}
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	s := d.scans
	uid := f.user.UID
	repo := filepath.Join(f.user.Home, "repo")

	s.noteSessions([]*event.Event{
		sessionEvent(uid, repo),
		sessionEvent(uid, repo), // same directory: once
		sessionEvent(uid, filepath.Join(secret, "x")),
		sessionEvent(uid, "relative/dir"),
		sessionEvent(uid, repo+"/../repo"),
		sessionEvent("", repo),
		func() *event.Event {
			e := sessionEvent(uid, filepath.Join(f.user.Home, "build", "child"))
			e.Source = event.SourceProcess
			return e
		}(),
	})
	if n := len(s.projQ); n != 1 {
		t.Fatalf("queued %d project scans, want 1", n)
	}
	if req := <-s.projQ; req.dir != repo || req.uid != uid {
		t.Errorf("queued %+v", req)
	}
	if d.board.get("scan.project_excluded") != 1 {
		t.Errorf("excluded = %d", d.board.get("scan.project_excluded"))
	}
	// Per-account rate limit.
	for i := 0; i < projectPerUserHour+5; i++ {
		s.noteSessions([]*event.Event{sessionEvent(uid, filepath.Join(f.user.Home, "p", string(rune('a'+i%26)), itoa(int64(i))))})
		select {
		case <-s.projQ:
		default:
		}
	}
	if d.board.get("scan.project_rate_limited") == 0 {
		t.Error("no rate limit per account")
	}
	// Project scans are off with scan.projects false.
	off := false
	f.cfg.Sources.Scan.Projects = &off
	s.noteSessions([]*event.Event{sessionEvent(uid, filepath.Join(f.user.Home, "other"))})
	if len(s.projQ) != 0 {
		t.Error("queued with projects disabled")
	}
}

func TestOwnProjectDir(t *testing.T) {
	dir := t.TempDir()
	if !ownProjectDir(dir, currentUID()) {
		t.Error("own directory refused")
	}
	if ownProjectDir(filepath.Join(dir, "missing"), currentUID()) {
		t.Error("missing directory accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if ownProjectDir(dir, "424242") {
		t.Error("a directory of another account accepted")
	}
	link := filepath.Join(t.TempDir(), "l")
	os.Symlink(dir, link)
	if ownProjectDir(link, currentUID()) {
		t.Error("symlink accepted")
	}
}

func TestScanSeen(t *testing.T) {
	f := newFixture(t)
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	s := d.scans
	prev := map[string]string{"a": "1", "b": "2", "c": "3"}
	evs := []*event.Event{
		{Kind: event.KindInventory, Asset: &event.Asset{ID: "b", Change: event.ChangeRemoved}},
		{Kind: event.KindInventory, Asset: &event.Asset{ID: "d", Change: event.ChangeNew}},
		{Kind: event.KindInventory, Asset: &event.Asset{ID: "c", Change: event.ChangeChanged}},
	}
	s.projIDs["p"] = true
	got := map[string]bool{}
	for _, id := range s.seen(prev, evs) {
		got[id] = true
	}
	for id, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true, "p": true} {
		if got[id] != want {
			t.Errorf("seen[%s] = %v", id, got[id])
		}
	}
}

// TestScanRecordsState runs one real discovery scan over the fake home and
// checks that its outcome reaches the state database.
func TestScanRecordsState(t *testing.T) {
	f := newFixture(t)
	mustWrite(t, filepath.Join(f.user.Home, ".claude", "settings.json"), `{"permissions":{"defaultMode":"default"}}`, 0o600)
	d, out := f.unitDaemon()
	st, err := state.Open(f.cfg.StateDB())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d.store = st
	d.scans.scan(context.Background(), true)
	d.pipe.Close()
	if d.board.get("scan.runs") != 1 {
		t.Fatalf("scan.runs = %d", d.board.get("scan.runs"))
	}
	rows, err := st.Query("health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("health rows after a scan: %v", rows)
	}
	if d.board.get("scan.incomplete") == 0 {
		if rows[0]["last_scan"] == "" || rows[0]["scan_complete"] != "1" {
			t.Errorf("a complete scan was not recorded: %v", rows[0])
		}
	} else if rows[0]["scan_complete"] != "0" {
		t.Errorf("an incomplete scan was recorded as complete: %v", rows[0])
	}
	inv := 0
	for _, e := range out.all() {
		if e.Kind == event.KindInventory {
			inv++
		}
	}
	if inv == 0 {
		t.Error("the scan reported no inventory for a home with Claude Code settings")
	}
	surf := d.board.surfaces()
	if len(surf) == 0 || surf[0].Name != "scan" {
		t.Errorf("scan surface missing: %+v", surf)
	}
}
