package hookcmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/spool"
)

func agedFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func present(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// A supervised hook prunes the spool it writes to when no daemon does
// ($HAWKBELL_SPOOL here), with retention.spool from the config it reads,
// and still writes its own record.
func TestHookPrunesItsSpool(t *testing.T) {
	s := newSandbox(t, cfgObserve+"retention:\n  spool: 2h\n")
	if err := os.MkdirAll(s.spool, 0o700); err != nil {
		t.Fatal(err)
	}
	expired := []string{
		filepath.Join(s.spool, "activity-20200101.ndjson"),
		filepath.Join(s.spool, "state", "0123456789abcdef0123456789abcdef.json"),
	}
	kept := filepath.Join(s.spool, "activity-20200102.ndjson")
	for _, p := range expired {
		agedFile(t, p, 3*time.Hour)
	}
	agedFile(t, kept, time.Hour)
	r := s.supervised(t, "claude-code", dialects[0].payload("echo hi"), "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("exit %d, reply %q", r.code, r.stdout)
	}
	for _, p := range expired {
		if present(p) {
			t.Errorf("%s: older than retention.spool, not deleted", p)
		}
	}
	if !present(kept) {
		t.Error("file within retention.spool deleted")
	}
	if len(s.ofKind(t, event.KindActivity)) != 1 {
		t.Fatal("the hook's own record is missing")
	}
	if !present(filepath.Join(s.spool, ".prune")) {
		t.Fatal("no scan marker")
	}
}

// With the system spool in use, the hook leaves its record files to the
// daemon, prunes its session state, and prunes the fallback spool in the
// home, which the daemon never deletes from.
func TestHookPrunesHomeFallbackNotSystemSpool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	data, home := t.TempDir(), t.TempDir()
	s := newSandbox(t, cfgObserve+"data_dir: "+strconv.Quote(data)+"\n")
	t.Setenv(spool.EnvSpool, "")
	env := OSEnv()
	env.UID, env.Home = strconv.Itoa(os.Geteuid()), home
	sys := filepath.Join(data, "spool", env.UID)
	if err := os.MkdirAll(sys, 0o700); err != nil {
		t.Fatal(err)
	}
	fallback := platform.UserDirs(home).Spool
	sysOld := filepath.Join(sys, "activity-20200101.ndjson")
	sysState := filepath.Join(sys, "state", "0123456789abcdef0123456789abcdef.json")
	homeOld := filepath.Join(fallback, "activity-20200101.ndjson")
	homeState := filepath.Join(fallback, "state", "0123456789abcdef0123456789abcdef.json")
	for _, p := range []string{sysOld, sysState, homeOld, homeState} {
		agedFile(t, p, 100*time.Hour)
	}
	if r := s.worker(t, env, "claude-code", dialects[0].payload("echo hi")); r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if present(homeOld) || present(homeState) {
		t.Error("expired files in the home fallback spool not deleted")
	}
	if !present(sysOld) {
		t.Error("the hook deleted a record file from the system spool, which is the daemon's")
	}
	if present(sysState) {
		t.Error("expired session state in the system spool not deleted")
	}
	today, _ := filepath.Glob(filepath.Join(sys, "activity-2*.ndjson"))
	if len(today) != 2 {
		t.Fatalf("system spool files %v: the record was not written there", today)
	}
}

// A hook whose events are all excluded writes nothing, but still deletes
// the account's expired files: an account added to privacy.exclude.users
// after it was recorded must not keep its content for good.
func TestHookPrunesWhenExcluded(t *testing.T) {
	s := newSandbox(t, cfgObserve+"  exclude:\n    users: [hb-excluded]\n")
	expired := []string{
		filepath.Join(s.spool, "activity-20200101.ndjson"),
		filepath.Join(s.spool, "state", "0123456789abcdef0123456789abcdef.json"),
	}
	for _, p := range expired {
		agedFile(t, p, 100*time.Hour)
	}
	env := OSEnv()
	env.User = "hb-excluded"
	r := s.worker(t, env, "claude-code", dialects[0].payload("echo hi"))
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("exit %d, reply %q", r.code, r.stdout)
	}
	for _, p := range expired {
		if present(p) {
			t.Errorf("%s: expired, not deleted for an excluded account", p)
		}
	}
	if recs, _ := filepath.Glob(filepath.Join(s.spool, "activity-*.ndjson")); len(recs) != 0 {
		t.Fatalf("an excluded session left records: %v", recs)
	}
	if !present(filepath.Join(s.spool, ".prune")) {
		t.Fatal("no scan marker")
	}
}

// A switched-off hook (kill switch, sources.hooks.enabled: false) runs
// nothing, pruning included: the switch is for a hook that misbehaves.
func TestHookSwitchedOffDoesNotPrune(t *testing.T) {
	for name, cfg := range map[string]string{
		"enabled false": cfgObserve + "sources:\n  hooks:\n    enabled: false\n",
		"kill switch":   cfgObserve,
	} {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, cfg)
			if name == "kill switch" {
				if err := os.WriteFile(filepath.Join(s.dir, platform.KillSwitchName), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			old := filepath.Join(s.spool, "activity-20200101.ndjson")
			agedFile(t, old, 100*time.Hour)
			r := s.supervised(t, "claude-code", dialects[0].payload("echo hi"), "")
			if r.code != 0 || len(r.stdout) != 0 {
				t.Fatalf("exit %d, reply %q", r.code, r.stdout)
			}
			if !present(old) || present(filepath.Join(s.spool, ".prune")) {
				t.Fatal("a switched-off hook touched the spool")
			}
		})
	}
}
