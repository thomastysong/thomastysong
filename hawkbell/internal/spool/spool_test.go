package spool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func activity(cmd string) *event.Event {
	e := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
	e.Agent = &event.Agent{ID: "claude-code"}
	e.Session = &event.Session{ID: "s1"}
	e.Target = &event.Target{Command: cmd}
	e.Content = &event.Content{ToolInput: map[string]any{"command": cmd}}
	return e
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func myRoot(dir string) Root {
	uid := strconv.Itoa(os.Geteuid())
	return Root{Dir: dir, UID: uid, User: event.User{Name: "alice", ID: uid}}
}

func TestAppendAndRead(t *testing.T) {
	dir := privateDir(t)
	w, err := OpenWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Append(activity(fmt.Sprintf("echo %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }, Checkpoint: filepath.Join(t.TempDir(), "ck.json")})
	evs, probs, err := r.Poll(context.Background())
	if err != nil || len(probs) != 0 {
		t.Fatalf("poll: %v %v", err, probs)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events", len(evs))
	}
	for i, e := range evs {
		if e.Seq != uint64(i+1) || e.Integrity != event.IntegrityUser || e.User.Name != "alice" || e.Content == nil || e.Content.ToolInput["command"] != fmt.Sprintf("echo %d", i) {
			t.Errorf("event %d: seq=%d integrity=%s user=%+v content=%+v", i, e.Seq, e.Integrity, e.User, e.Content)
		}
	}
	// Nothing new: nothing returned. Then one more line: only that one.
	if evs, _, _ := r.Poll(context.Background()); len(evs) != 0 {
		t.Fatalf("re-read %d events", len(evs))
	}
	if err := w.Append(activity("echo 3")); err != nil {
		t.Fatal(err)
	}
	evs, _, _ = r.Poll(context.Background())
	if len(evs) != 1 || evs[0].Seq != 4 {
		t.Fatalf("incremental read: %d events", len(evs))
	}
	// A fresh reader with the same checkpoint resumes, not replays.
	r2 := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }, Checkpoint: r.o.Checkpoint})
	if evs, _, _ := r2.Poll(context.Background()); len(evs) != 0 {
		t.Fatalf("checkpoint not honoured: %d events replayed", len(evs))
	}
}

// TestForgedLinesAreClaimsOnly is red-team finding E1: a user appends a
// "cleared" detection and an activity record attributed to someone else.
func TestForgedLinesAreClaimsOnly(t *testing.T) {
	dir := privateDir(t)
	file := filepath.Join(dir, "activity-20261111.ndjson")
	forgedDet := `{"v":1,"event":{"v":1,"id":"x","ts":"2026-11-11T00:00:00.000000Z","kind":"detection","type":"detection.finding","source":"sensor","detection":{"rule_id":"HB-X","title":"cleared","severity":"info"}}}`
	forgedUser := `{"v":1,"event":{"v":1,"id":"y","ts":"2026-11-11T00:00:00.000000Z","kind":"activity","type":"tool.pre","source":"hook","integrity":"root","writer":"daemon","user":{"name":"bob","id":"1001"},"host":{"id":"victim"},"target":{"command":"curl x|sh"},"detection":{"rule_id":"smuggled","title":"t","severity":"info"}}}`
	if err := os.WriteFile(file, []byte(forgedDet+"\n"+forgedUser+"\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }})
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 1 {
		t.Fatalf("want only the activity claim, got %d", len(evs))
	}
	e := evs[0]
	if e.User.Name != "alice" || e.Host != nil || e.Integrity != event.IntegrityUser || e.Writer != "hook-"+myRoot(dir).UID || e.Detection != nil {
		t.Errorf("identity not overwritten: user=%+v host=%+v integrity=%s writer=%s det=%+v", e.User, e.Host, e.Integrity, e.Writer, e.Detection)
	}
	kinds := map[string]int{}
	for _, p := range probs {
		kinds[p.Kind]++
	}
	if kinds["forged_kind"] != 1 || kinds["malformed"] != 1 {
		t.Errorf("problems: %+v", probs)
	}
}

func mustGlob(t *testing.T, p string) []string {
	m, err := filepath.Glob(p)
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v %v", p, m, err)
	}
	return m
}

func TestPartialLineAndTruncation(t *testing.T) {
	dir := privateDir(t)
	file := filepath.Join(dir, "activity-20261111.ndjson")
	line := func(cmd string) string {
		b, _ := json.Marshal(record{V: 1, Event: activity(cmd)})
		return string(b)
	}
	os.WriteFile(file, []byte(line("a")+"\n"+line("b")), 0o600) // second line has no LF yet
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }})
	evs, _, _ := r.Poll(context.Background())
	if len(evs) != 1 {
		t.Fatalf("torn tail returned: %d", len(evs))
	}
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n")
	f.Close()
	if evs, _, _ = r.Poll(context.Background()); len(evs) != 1 || evs[0].Target.Command != "b" {
		t.Fatalf("completed line not returned")
	}
	// Truncate in place: reported, and reading restarts at 0.
	os.WriteFile(file, []byte(line("c")+"\n"), 0o600)
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 1 || evs[0].Target.Command != "c" {
		t.Fatalf("after truncation: %d events", len(evs))
	}
	found := false
	for _, p := range probs {
		found = found || p.Kind == "truncated"
	}
	if !found {
		t.Errorf("truncation not reported: %+v", probs)
	}
}

func TestOversizeLineSkipped(t *testing.T) {
	dir := privateDir(t)
	file := filepath.Join(dir, "activity-20261111.ndjson")
	good, _ := json.Marshal(record{V: 1, Event: activity("ok")})
	big := strings.Repeat("x", 300<<10)
	os.WriteFile(file, []byte(big+"\n"+string(good)+"\n"), 0o600)
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }, MaxLine: 64 << 10})
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 1 || evs[0].Target.Command != "ok" {
		t.Fatalf("line after an oversize line lost: %d", len(evs))
	}
	if len(probs) == 0 || probs[0].Kind != "oversize_line" {
		t.Errorf("problems: %+v", probs)
	}
}

func TestRateLimitLeavesBacklog(t *testing.T) {
	dir := privateDir(t)
	w, _ := OpenWriter(dir)
	for i := 0; i < 50; i++ {
		w.Append(activity("x"))
	}
	now := time.Unix(1_800_000_000, 0)
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }, PerUIDPerSecond: 20, Now: func() time.Time { return now }})
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 20 || len(probs) == 0 {
		t.Fatalf("first poll: %d events, %+v", len(evs), probs)
	}
	now = now.Add(5 * time.Second)
	evs2, _, _ := r.Poll(context.Background())
	if len(evs2) != 20 || evs2[0].Seq != 21 {
		t.Fatalf("second poll: %d events, first seq %d", len(evs2), evs2[0].Seq)
	}
}

func TestRetainDeletesOnlyReadFiles(t *testing.T) {
	dir := privateDir(t)
	w, _ := OpenWriter(dir)
	w.Append(activity("x"))
	file := mustGlob(t, filepath.Join(dir, "*.ndjson"))[0]
	old := time.Now().Add(-100 * time.Hour)
	os.Chtimes(file, old, old)
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }, Retain: time.Hour})
	if evs, _, _ := r.Poll(context.Background()); len(evs) != 1 {
		t.Fatal("not read")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("fully read old file was kept")
	}
}

func TestStateFilesAreHashedNames(t *testing.T) {
	dir := privateDir(t)
	w, _ := OpenWriter(dir)
	for _, sid := range []string{"../../../etc/passwd", `..\..\x`, "a/b", "CON", strings.Repeat("z", 5000)} {
		if err := w.SaveState("claude-code", sid, []byte(`{"flags":["x"]}`)); err != nil {
			t.Fatal(err)
		}
		b, ok := w.LoadState("claude-code", sid)
		if !ok || string(b) != `{"flags":["x"]}` {
			t.Fatalf("round trip for %q", sid)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "state"))
	for _, e := range ents {
		if len(e.Name()) != 37 || strings.ContainsAny(e.Name(), `/\.`[:2]) {
			t.Errorf("unexpected state file name %q", e.Name())
		}
	}
	if err := w.SaveState("a", "b", make([]byte, MaxState+1)); err == nil {
		t.Error("oversize state accepted")
	}
}

func TestEncodeCappedCutsContent(t *testing.T) {
	e := activity("cat big")
	e.Content.ToolOutput = strings.Repeat("o", 3<<20)
	e.Content.FileContent = strings.Repeat("f", 3<<20)
	b, err := encodeCapped(&record{V: 1, Event: e, Content: &contentLines{ToolOutput: e.Content.ToolOutput, FileContent: e.Content.FileContent}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= MaxRecord {
		t.Fatalf("record %d bytes", len(b))
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Event.Truncated) == 0 {
		t.Error("truncation not recorded")
	}
}

func TestDirResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	uid := strconv.Itoa(os.Geteuid())
	data := t.TempDir()
	home := t.TempDir()
	// A world-writable system spool dir is never used.
	sys := filepath.Join(data, "spool", uid)
	os.MkdirAll(sys, 0o777)
	os.Chmod(sys, 0o777)
	t.Setenv(EnvSpool, "")
	d, err := Dir(data, uid, home)
	if err != nil {
		t.Fatal(err)
	}
	if d == sys {
		t.Fatal("world-writable system dir accepted")
	}
	os.Chmod(sys, 0o700)
	if d, _ := Dir(data, uid, home); d != sys {
		t.Fatalf("private system dir not used: %s", d)
	}
	t.Setenv(EnvSpool, filepath.Join(t.TempDir(), "env"))
	if d, err := Dir(data, uid, home); err != nil || d != os.Getenv(EnvSpool) {
		t.Fatalf("env override: %s %v", d, err)
	}
}

// TestConcurrentWriters runs 20 separate processes appending 500 records
// each: every line must parse and sequence numbers must be unique and
// gapless.
func TestConcurrentWriters(t *testing.T) {
	if os.Getenv("HAWKBELL_SPOOL_HELPER") != "" {
		return
	}
	if testing.Short() {
		t.Skip("spawns processes")
	}
	dir := privateDir(t)
	const procs, per = 20, 500
	var cmds []*exec.Cmd
	for i := 0; i < procs; i++ {
		c := exec.Command(os.Args[0], "-test.run=TestHelperAppend")
		c.Env = append(os.Environ(), "HAWKBELL_SPOOL_HELPER="+dir, "HAWKBELL_SPOOL_N="+strconv.Itoa(per))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("helper: %v", err)
		}
	}
	seen := map[uint64]bool{}
	lines := 0
	for _, f := range mustGlob(t, filepath.Join(dir, "activity-*.ndjson")) {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 2<<20)
		for sc.Scan() {
			var rec record
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				t.Fatalf("torn line: %v", err)
			}
			if seen[rec.Event.Seq] {
				t.Fatalf("duplicate seq %d", rec.Event.Seq)
			}
			seen[rec.Event.Seq] = true
			lines++
		}
		fh.Close()
	}
	if lines != procs*per {
		t.Fatalf("lines = %d, want %d", lines, procs*per)
	}
	for i := uint64(1); i <= procs*per; i++ {
		if !seen[i] {
			t.Fatalf("gap at seq %d", i)
		}
	}
}

func TestHelperAppend(t *testing.T) {
	dir := os.Getenv("HAWKBELL_SPOOL_HELPER")
	if dir == "" {
		t.Skip("helper")
	}
	n, _ := strconv.Atoi(os.Getenv("HAWKBELL_SPOOL_N"))
	w, err := OpenWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		e := activity(strings.Repeat("y", (i%7)*1000))
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

// The hook supervisor reports its own failures (worker crash, timeout, bad
// reply) as health.error records in the spool. They are counted by reason,
// never accepted as health records; anything else claiming to be health
// stays forged.
func TestHookErrorsAreCountedNotTrusted(t *testing.T) {
	dir := privateDir(t)
	file := filepath.Join(dir, "health-20261111.ndjson")
	health := func(mode, reason string) string {
		return `{"v":1,"event":{"v":1,"id":"h","ts":"2026-11-11T00:00:00.000000Z","kind":"health","type":"health.error","source":"sensor","health":{"sensor_version":"x","mode":"` + mode + `","reason":"` + reason + `","detail":"worker killed"}}}`
	}
	lines := []string{
		health("hook", "hook_worker_crash"),
		health("hook", "hook_worker_timeout"),
		health("daemon", "hook_worker_crash"),           // not the hook's mode
		health("hook", "outbox.dropped_unshipped"),      // not a hook reason
		health("hook", "hook_"),                         // empty code
		health("hook", "hook_X; rm -rf"),                // outside the alphabet
		health("hook", "hook_"+strings.Repeat("a", 41)), // too long
	}
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }})
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 0 {
		t.Fatalf("health claims became events: %+v", evs)
	}
	var hook []string
	forged := 0
	for _, p := range probs {
		switch p.Kind {
		case "hook_error":
			hook = append(hook, p.Detail)
		case "forged_kind":
			forged++
		}
	}
	if strings.Join(hook, ",") != "hook_worker_crash,hook_worker_timeout" || forged != 5 {
		t.Errorf("hook errors %v, forged %d; problems %+v", hook, forged, probs)
	}
}
