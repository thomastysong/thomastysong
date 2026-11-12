package spool

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// writeAged creates path (and its directory) with an mtime age ago.
func writeAged(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"v":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setAge(t, path, age)
}

func setAge(t *testing.T, path string, age time.Duration) {
	t.Helper()
	at := time.Now().Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

const old = 100 * time.Hour // past the 72 h default

// The hook deletes expired files of the kinds it writes, and nothing else.
func TestPruneDeletesExpiredOwnFiles(t *testing.T) {
	dir := privateDir(t)
	gone := []string{
		"activity-20261101.ndjson",
		"health-20261101.ndjson",
		"detection-20261101.ndjson",
		".tmp-123456",
		"state/0123456789abcdef0123456789abcdef.json",
		"state/.tmp-42",
	}
	kept := map[string]time.Duration{
		"activity-20261112.ndjson": time.Hour, // written within the retention
		".seq-activity":            old,       // sequence counter
		".lock":                    old,       // the append lock
		"notes.txt":                old,       // not a name the hook writes
		"activity.ndjson.bak":      old,
		"state/fedcba9876543210fedcba9876543210.json": 71 * time.Hour,
		"state/.hook-state.lock":                      old,
	}
	for _, n := range gone {
		writeAged(t, filepath.Join(dir, n), old)
	}
	for n, a := range kept {
		writeAged(t, filepath.Join(dir, n), a)
	}
	res, err := maybePrune(Target{Dir: dir}, 72*time.Hour, time.Now())
	if err != nil || !res.Scanned || res.Removed != len(gone) || res.Capped {
		t.Fatalf("result %+v, err %v; want %d removed", res, err, len(gone))
	}
	for _, n := range gone {
		if exists(filepath.Join(dir, n)) {
			t.Errorf("%s: expired file kept", n)
		}
	}
	for n := range kept {
		if !exists(filepath.Join(dir, n)) {
			t.Errorf("%s: deleted", n)
		}
	}
	if fi, err := os.Lstat(filepath.Join(dir, pruneMarker)); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("marker: %v", err)
	}
}

// In a system spool only state and temporary files go: the record files
// are the daemon's, which deletes them once it has read them.
func TestPruneStateOnly(t *testing.T) {
	dir := privateDir(t)
	record := filepath.Join(dir, "activity-20261101.ndjson")
	state := filepath.Join(dir, "state", "0123456789abcdef0123456789abcdef.json")
	tmp := filepath.Join(dir, ".tmp-1")
	for _, p := range []string{record, state, tmp} {
		writeAged(t, p, old)
	}
	res, err := maybePrune(Target{Dir: dir, StateOnly: true}, 0, time.Now())
	if err != nil || res.Removed != 2 || !exists(record) || exists(state) || exists(tmp) {
		t.Fatalf("result %+v %v: record kept=%v state kept=%v tmp kept=%v", res, err, exists(record), exists(state), exists(tmp))
	}
}

// retention.spool sets the age; zero means the 72 h default; below a
// minute it is a minute.
func TestPruneRetentionSetting(t *testing.T) {
	for _, c := range []struct {
		retain    time.Duration
		age       time.Duration
		wantGone  bool
		wantEvery time.Duration
	}{
		{2 * time.Hour, 3 * time.Hour, true, time.Hour},
		{2 * time.Hour, time.Hour, false, time.Hour},
		{0, 71 * time.Hour, false, time.Hour},
		{0, 73 * time.Hour, true, time.Hour},
		{-time.Hour, 73 * time.Hour, true, time.Hour},
		{10 * time.Minute, 11 * time.Minute, true, 10 * time.Minute},
		{time.Nanosecond, 30 * time.Second, false, time.Minute},
		{time.Nanosecond, 2 * time.Minute, true, time.Minute},
	} {
		dir := privateDir(t)
		f := filepath.Join(dir, "activity-20261101.ndjson")
		writeAged(t, f, c.age)
		if _, err := maybePrune(Target{Dir: dir}, c.retain, time.Now()); err != nil {
			t.Fatal(err)
		}
		if gone := !exists(f); gone != c.wantGone {
			t.Errorf("retain %v, age %v: deleted=%v, want %v", c.retain, c.age, gone, c.wantGone)
		}
		if _, every := pruneTimes(c.retain); every != c.wantEvery {
			t.Errorf("retain %v: scan every %v, want %v", c.retain, every, c.wantEvery)
		}
	}
}

// A scan happens at most once per PruneEvery, tracked by the marker's
// mtime; a marker from far in the future (clock set back) is stale.
func TestPruneOncePerInterval(t *testing.T) {
	dir := privateDir(t)
	marker := filepath.Join(dir, pruneMarker)
	f := filepath.Join(dir, "activity-20261101.ndjson")
	now := time.Now()
	if res, _ := maybePrune(Target{Dir: dir}, 0, now); !res.Scanned {
		t.Fatal("first call did not scan")
	}
	writeAged(t, f, old)
	if res, _ := maybePrune(Target{Dir: dir}, 0, now.Add(59*time.Minute)); res.Scanned || !exists(f) {
		t.Fatalf("scanned again within the interval: %+v", res)
	}
	if res, _ := maybePrune(Target{Dir: dir}, 0, now.Add(61*time.Minute)); !res.Scanned || exists(f) {
		t.Fatalf("not scanned after the interval: %+v", res)
	}
	// Clock set back by 30 minutes: still fresh. By 2 hours: stale.
	future := time.Now().Add(30 * time.Minute)
	os.Chtimes(marker, future, future)
	if res, _ := maybePrune(Target{Dir: dir}, 0, time.Now()); res.Scanned {
		t.Fatal("marker 30 min in the future treated as stale")
	}
	future = time.Now().Add(2 * time.Hour)
	os.Chtimes(marker, future, future)
	if res, _ := maybePrune(Target{Dir: dir}, 0, time.Now()); !res.Scanned {
		t.Fatal("marker 2 h in the future treated as fresh")
	}
	// The usual case is one lstat: a missing directory is not an error.
	if res, err := MaybePrune(Target{Dir: filepath.Join(dir, "missing")}, 0); err != nil || res.Scanned {
		t.Fatalf("missing dir: %+v %v", res, err)
	}
}

// While another process holds the spool's lock (an append between its open
// and its write), nothing is deleted and the call does not wait.
func TestPruneSkipsWhileLocked(t *testing.T) {
	dir := privateDir(t)
	f := filepath.Join(dir, "activity-20261101.ndjson")
	writeAged(t, f, old)
	unlock, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := maybePrune(Target{Dir: dir}, 0, time.Now())
	if err != nil || !res.Busy || res.Scanned || !exists(f) {
		t.Fatalf("pruned under a held lock: %+v %v", res, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %v for the lock", d)
	}
	if exists(filepath.Join(dir, pruneMarker)) {
		t.Fatal("marker written although nothing was scanned")
	}
	unlock()
	if res, _ := maybePrune(Target{Dir: dir}, 0, time.Now()); !res.Scanned || exists(f) {
		t.Fatalf("not pruned once the lock was free: %+v", res)
	}
	// Once scanned, the next call ends at the marker: it does not even
	// try the lock, so a busy spool costs it nothing.
	unlock, err = lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if res, err := maybePrune(Target{Dir: dir}, 0, time.Now()); err != nil || res != (PruneResult{}) {
		t.Fatalf("fresh marker: %+v %v", res, err)
	}
}

// Many hooks at once: exactly one scans, every expired file is deleted
// once, and appends running at the same time lose nothing.
func TestPruneConcurrentHooks(t *testing.T) {
	dir := privateDir(t)
	const expired = 40
	for i := 0; i < expired; i++ {
		writeAged(t, filepath.Join(dir, "activity-2026100"+strconv.Itoa(i%10)+"-"+strconv.Itoa(i)+".ndjson"), old)
	}
	const pruners, appenders, per = 16, 4, 50
	now := time.Now()
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]PruneResult, pruners)
	errs := make([]error, pruners+appenders)
	for i := 0; i < pruners; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = maybePrune(Target{Dir: dir}, 0, now)
		}(i)
	}
	for i := 0; i < appenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := OpenWriter(dir)
			if err != nil {
				errs[pruners+i] = err
				return
			}
			<-start
			for j := 0; j < per; j++ {
				if err := w.Append(activity("echo")); err != nil {
					errs[pruners+i] = err
					return
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	scans, removed := 0, 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("pruner %d: %v", i, errs[i])
		}
		if r.Scanned {
			scans++
		}
		removed += r.Removed
	}
	for _, err := range errs[pruners:] {
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// A pruner that found the lock busy did nothing; one that came after
	// the scan found the marker fresh. So at most one scan ran, and if a
	// busy lock made every pruner give up, the next call scans.
	if scans > 1 {
		t.Fatalf("%d scans", scans)
	}
	if scans == 0 {
		r, err := maybePrune(Target{Dir: dir}, 0, now)
		if err != nil || !r.Scanned {
			t.Fatalf("no scan: %+v %v", r, err)
		}
		removed += r.Removed
	}
	if removed != expired {
		t.Fatalf("removed %d, want %d", removed, expired)
	}
	n := 0
	for _, f := range mustGlob(t, filepath.Join(dir, "*.ndjson")) {
		b, _ := os.ReadFile(f)
		for _, c := range b {
			if c == '\n' {
				n++
			}
		}
	}
	if n != appenders*per {
		t.Fatalf("%d lines after concurrent appends, want %d", n, appenders*per)
	}
}

// A run that reaches maxPruneRemovals stops and leaves the next hook due.
func TestPruneCapped(t *testing.T) {
	saved := maxPruneRemovals
	maxPruneRemovals = 2
	t.Cleanup(func() { maxPruneRemovals = saved })
	dir := privateDir(t)
	for i := 0; i < 5; i++ {
		writeAged(t, filepath.Join(dir, "activity-2026110"+strconv.Itoa(i)+".ndjson"), old)
	}
	for _, want := range []int{2, 2, 1} {
		res, err := maybePrune(Target{Dir: dir}, 0, time.Now())
		if err != nil || !res.Scanned || res.Removed != want {
			t.Fatalf("result %+v %v, want %d removed", res, err, want)
		}
		if res.Capped == exists(filepath.Join(dir, pruneMarker)) {
			t.Fatalf("capped=%v but marker present=%v", res.Capped, !res.Capped)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.ndjson")); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

// A file this process creates counts as the caller's. On Windows this is
// the case that needs the token's default owner: a file an elevated
// process creates is owned by the Administrators group, not the user.
func TestPruneOwnFileIsCallers(t *testing.T) {
	owners := callerOwners()
	if len(owners) == 0 {
		t.Skip("no ownership information on " + runtime.GOOS + ": nothing is pruned")
	}
	p := filepath.Join(privateDir(t), "activity-20261101.ndjson")
	writeAged(t, p, old)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedBy(fi, p, owners) {
		o, ok := fileOwner(fi, p)
		t.Fatalf("own file not recognised: owner %q (%v), caller %v", o, ok, owners)
	}
}

// Files of an owner that is not the caller stay, without root: the scan
// is told the caller is someone else. The same files go once it is not.
func TestPruneLeavesOtherOwnersFiles(t *testing.T) {
	dir := privateDir(t)
	files := []string{
		filepath.Join(dir, "activity-20261101.ndjson"),
		filepath.Join(dir, ".tmp-1"),
		filepath.Join(dir, "state", "0123456789abcdef0123456789abcdef.json"),
	}
	for _, p := range files {
		writeAged(t, p, old)
	}
	pruneOwners = func() []string { return []string{"no-such-owner"} }
	t.Cleanup(func() { pruneOwners = callerOwners })
	res, err := maybePrune(Target{Dir: dir}, 0, time.Now())
	if err != nil || !res.Scanned || res.Removed != 0 {
		t.Fatalf("result %+v %v: files of another owner were deleted", res, err)
	}
	for _, p := range files {
		if !exists(p) {
			t.Fatalf("%s: another owner's file deleted", p)
		}
	}
	pruneOwners = callerOwners
	if len(callerOwners()) == 0 {
		return
	}
	res, err = maybePrune(Target{Dir: dir}, 0, time.Now().Add(2*PruneEvery))
	if err != nil || res.Removed != len(files) {
		t.Fatalf("result %+v %v: the caller's own files were not deleted", res, err)
	}
}

// Which spool a hook writes to, and what it prunes itself.
func TestLocateKindsAndPruneTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	uid := strconv.Itoa(os.Geteuid())
	data, home := t.TempDir(), t.TempDir()
	fallback := platform.UserDirs(home).Spool
	sys := filepath.Join(data, "spool", uid)
	t.Setenv(EnvSpool, "")
	same := func(got []Target, want ...Target) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	l, err := Locate(data, uid, home)
	if err != nil || l.Kind != KindFallback || l.Dir != fallback || !same(l.Prune, Target{Dir: fallback}) {
		t.Fatalf("no system spool: %+v %v", l, err)
	}
	if err := os.MkdirAll(sys, 0o700); err != nil {
		t.Fatal(err)
	}
	// The system spool's records are the daemon's to delete, its state is
	// the hook's; the fallback in the home is the hook's, even while it
	// is not in use.
	l, err = Locate(data, uid, home)
	if err != nil || l.Kind != KindSystem || l.Dir != sys || !same(l.Prune, Target{Dir: sys, StateOnly: true}, Target{Dir: fallback}) {
		t.Fatalf("system spool: %+v %v", l, err)
	}
	if l, _ := Locate(data, uid, ""); l.Kind != KindSystem || !same(l.Prune, Target{Dir: sys, StateOnly: true}) {
		t.Fatalf("system spool, no home: %+v", l)
	}
	// $HAWKBELL_SPOOL replaces every other location, the home included.
	env := filepath.Join(t.TempDir(), "env")
	t.Setenv(EnvSpool, env)
	l, err = Locate(data, uid, home)
	if err != nil || l.Kind != KindOverride || l.Dir != env || !same(l.Prune, Target{Dir: env}) {
		t.Fatalf("override: %+v %v", l, err)
	}
	// ... and when it names the system spool, its records stay the
	// daemon's.
	t.Setenv(EnvSpool, sys)
	if l, err := Locate(data, uid, home); err != nil || l.Kind != KindOverride || !same(l.Prune, Target{Dir: sys, StateOnly: true}) {
		t.Fatalf("override naming the system spool: %+v %v", l, err)
	}
	if d, err := Dir(data, uid, home); err != nil || d != sys {
		t.Fatalf("Dir: %s %v", d, err)
	}
}

// The per-event cost: the directory was scanned less than an hour ago.
func BenchmarkMaybePruneFresh(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	if _, err := MaybePrune(Target{Dir: dir}, 0); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if res, _ := MaybePrune(Target{Dir: dir}, 0); res.Scanned {
			b.Fatal("scanned")
		}
	}
}

// The per-event cost when the system spool is in use and the home has no
// fallback spool: two failing lstats.
func BenchmarkMaybePruneMissing(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "spool")
	for i := 0; i < b.N; i++ {
		if res, _ := MaybePrune(Target{Dir: dir}, 0); res.Scanned {
			b.Fatal("scanned")
		}
	}
}

// A due scan that deletes three expired 64 KiB record files (set-up not
// timed).
func BenchmarkMaybePruneDue3(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	body := make([]byte, 64<<10)
	at := time.Now().Add(-old)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for j := 0; j < 3; j++ {
			p := filepath.Join(dir, "activity-1999000"+strconv.Itoa(j)+".ndjson")
			os.WriteFile(p, body, 0o600)
			os.Chtimes(p, at, at)
		}
		os.Chtimes(filepath.Join(dir, pruneMarker), at, at)
		b.StartTimer()
		if res, err := MaybePrune(Target{Dir: dir}, 0); err != nil || res.Removed != 3 {
			b.Fatalf("%+v %v", res, err)
		}
	}
}

// A due scan and a SaveState of the same session at once: the scan must
// not delete the state file the save has just replaced. SaveState used to
// rename outside the spool's lock, so a scan could Lstat the old file
// (expired), the rename land, and the Remove delete the fresh one.
func TestPruneDoesNotDeleteStateBeingSaved(t *testing.T) {
	dir := privateDir(t)
	w, err := OpenWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "state", stateName("a", "s"))
	rounds := 1000
	if testing.Short() {
		rounds = 200
	}
	lost := 0
	for i := 0; i < rounds; i++ {
		if err := w.SaveState("a", "s", []byte("old")); err != nil {
			t.Fatal(err)
		}
		setAge(t, p, old)
		_ = os.Remove(filepath.Join(dir, pruneMarker))
		done := make(chan error, 1)
		go func() { done <- w.SaveState("a", "s", []byte("fresh")) }()
		if _, err := maybePrune(Target{Dir: dir}, 0, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(p); err != nil || string(b) != "fresh" {
			lost++
		}
	}
	if lost != 0 {
		t.Fatalf("fresh state lost after a completed SaveState in %d of %d rounds", lost, rounds)
	}
}
