package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/spool"
)

// TestSpoolRunnerCounts: hook supervisor errors become hook_errors.<reason>,
// forged kinds are counted on their own and never ingested, records from
// the user's fallback spool are read too, and identity comes from the file.
func TestSpoolRunnerCounts(t *testing.T) {
	f := newFixture(t)
	d, out := f.unitDaemon()
	dir := f.spoolDir()

	writeLine := func(path string, rec any) {
		b, _ := json.Marshal(rec)
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		fh.Write(append(b, '\n'))
		fh.Close()
	}
	forged := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	forged.Detection = &event.Detection{RuleID: "SPR-FAKE-001", Title: "x", Severity: "critical"}
	hookErr := event.New(event.KindHealth, event.TypeHealthError, event.SourceHook)
	hookErr.Health = &event.Health{Mode: "hook", Reason: "hook_worker_crash"}
	act := hookToolPre("s1", "toolu_spool_1", filepath.Join(f.user.Home, "repo"), "echo hi")
	act.User = &event.User{Name: "root", ID: "0"} // a claim; the file owner decides
	act.Integrity = event.IntegrityRoot
	p := filepath.Join(dir, "activity-20261112.ndjson")
	writeLine(p, map[string]any{"v": 1, "event": forged})
	writeLine(p, map[string]any{"v": 1, "event": hookErr})
	writeLine(p, map[string]any{"v": 1, "event": act})

	// The fallback spool in the home, written by a hook that could not reach
	// the system one.
	fb := platform.UserDirs(f.user.Home).Spool
	mustMkdir(t, fb, 0o700)
	w, err := spool.OpenWriter(fb)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(hookToolPre("s2", "toolu_fallback_1", filepath.Join(f.user.Home, "repo"), "ls")); err != nil {
		t.Fatal(err)
	}

	r := newSpoolRunner(d)
	r.pollOnce(context.Background())
	r.pollOnce(context.Background()) // nothing new: nothing counted twice
	d.pipe.Close()

	if got := d.board.get("hook_errors.hook_worker_crash"); got != 1 {
		t.Errorf("hook_errors.hook_worker_crash = %d", got)
	}
	if got := d.board.get("spool.forged_kind"); got != 1 {
		t.Errorf("spool.forged_kind = %d", got)
	}
	ids := out.useIDs()
	if !ids["toolu_spool_1"] || !ids["toolu_fallback_1"] {
		t.Errorf("spool activity missing: %v", ids)
	}
	for _, e := range out.all() {
		if e.Kind == event.KindDetection && e.Detection != nil && e.Detection.RuleID == "SPR-FAKE-001" {
			t.Error("a forged detection was shipped")
		}
		if e.Kind == event.KindActivity && e.Tool != nil && e.Tool.UseID == "toolu_spool_1" {
			if e.User == nil || e.User.ID != f.user.UID || e.Integrity != event.IntegrityUser {
				t.Errorf("identity from the payload survived: user %+v integrity %s", e.User, e.Integrity)
			}
		}
	}
	if _, err := os.Stat(fb); err != nil {
		t.Errorf("the fallback spool was touched: %v", err)
	}
}

func TestSpoolRunnerStandingProblems(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink planting needs privileges on Windows")
	}
	f := newFixture(t)
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	dir := f.spoolDir()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte(`{"v":1}`+"\n"), 0o600)
	if err := os.Symlink(secret, filepath.Join(dir, "activity-20261112.ndjson")); err != nil {
		t.Fatal(err)
	}
	r := newSpoolRunner(d)
	for i := 0; i < 5; i++ {
		r.pollOnce(context.Background())
	}
	if got := d.board.get("spool.symlink_refused"); got != 1 {
		t.Errorf("a standing problem was counted %d times in one hour", got)
	}
	// An hour later it is counted again.
	r.standing["symlink_refused\x00"+filepath.Join(dir, "activity-20261112.ndjson")] = time.Now().Add(-2 * time.Hour)
	r.pollOnce(context.Background())
	if got := d.board.get("spool.symlink_refused"); got != 2 {
		t.Errorf("after an hour: %d", got)
	}
}

func TestSafeKind(t *testing.T) {
	if safeKind("forged_kind") != "forged_kind" || safeKind("../../x") != "other" {
		t.Error("safeKind")
	}
}
