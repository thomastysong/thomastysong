package sink

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const (
	helperEnv     = "HAWKBELL_SINK_HELPER"
	linesPerActor = 2000
)

// TestHelperProcess is not a test: it is the body of the child processes
// started by the concurrency and crash tests.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv(helperEnv) {
	case "":
		return
	case "append":
		maxSeg, _ := strconv.ParseInt(os.Getenv("HAWKBELL_SINK_MAXSEG"), 10, 64)
		if err := appendLines(os.Getenv("HAWKBELL_SINK_DIR"), os.Getenv("HAWKBELL_SINK_WRITER"), maxSeg, nil); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "ship":
		shipHelper()
	}
}

// appendLines writes linesPerActor events, one Write per event so every
// line is its own write(2) racing with the other writers.
func appendLines(dir, writer string, maxSegment int64, shared Sink) error {
	s := shared
	if s == nil {
		var err error
		s, err = NewFiles(FilesOptions{Dir: dir, MaxSegment: maxSegment, RetainBytes: -1, RetainAge: -1})
		if err != nil {
			return err
		}
		defer s.Close()
	}
	for i := 0; i < linesPerActor; i++ {
		// Sizes from a few bytes to several kilobytes, well past PIPE_BUF,
		// so atomicity is not an accident of small writes.
		n := (i*7919 + len(writer)*31) % 6000
		if err := s.Write([]*event.Event{testEvent(fmt.Sprintf("%s-%d", writer, i), n)}); err != nil {
			return err
		}
	}
	return nil
}

func TestFilesConcurrentWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	for _, tc := range []struct {
		name       string
		maxSegment int64
	}{
		{"one_segment", 1 << 30},
		{"rolling", 512 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			const goroutines, children = 8, 4
			shared, err := NewFiles(FilesOptions{Dir: dir, MaxSegment: tc.maxSegment, RetainBytes: -1, RetainAge: -1})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			errs := make(chan error, goroutines+children)
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					errs <- appendLines(dir, fmt.Sprintf("g%d", g), tc.maxSegment, shared)
				}(g)
			}
			for c := 0; c < children; c++ {
				wg.Add(1)
				go func(c int) {
					defer wg.Done()
					cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
					cmd.Env = append(os.Environ(), helperEnv+"=append", "HAWKBELL_SINK_DIR="+dir,
						"HAWKBELL_SINK_WRITER=p"+strconv.Itoa(c), "HAWKBELL_SINK_MAXSEG="+strconv.FormatInt(tc.maxSegment, 10))
					if out, err := cmd.CombinedOutput(); err != nil {
						errs <- fmt.Errorf("child %d: %v: %s", c, err, out)
						return
					}
					errs <- nil
				}(c)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := shared.Close(); err != nil {
				t.Fatal(err)
			}

			seen := make(map[string]bool)
			for _, e := range readEvents(t, dir) { // fails on any unparsable line
				if err := checkTestEvent(e); err != nil {
					t.Fatal(err)
				}
				if seen[e.ID] {
					t.Fatalf("event %s written twice", e.ID)
				}
				seen[e.ID] = true
			}
			if want := (goroutines + children) * linesPerActor; len(seen) != want {
				t.Fatalf("found %d events, want %d", len(seen), want)
			}
			files := segmentFiles(t, dir)
			if tc.maxSegment > 1<<20 {
				if len(files) != 1 {
					t.Fatalf("expected every writer to share one segment, got %v", files)
				}
				return
			}
			if len(files) < 10 {
				t.Fatalf("expected many rolled segments, got %d", len(files))
			}
			// A segment may overshoot by the lines in flight when it filled:
			// at most one per writer.
			limit := tc.maxSegment + int64(goroutines+children)*8192
			for _, name := range files {
				fi, err := os.Stat(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if fi.Size() > limit {
					t.Errorf("%s is %d bytes, limit %d", name, fi.Size(), limit)
				}
			}
		})
	}
}

func TestSegmentNames(t *testing.T) {
	at := time.Date(2026, 11, 11, 23, 59, 59, 0, time.FixedZone("x", -8*3600)) // 07:59 next day UTC
	if got := SegmentName("activity", at, 1); got != "activity-20261112-07-0001.ndjson" {
		t.Errorf("SegmentName = %q", got)
	}
	if got := SegmentName("detection", at, 12345); got != "detection-20261112-07-12345.ndjson" {
		t.Errorf("SegmentName = %q", got)
	}
	// A stream that could escape the directory is never used as given.
	for _, bad := range []string{"../../etc/passwd", "a/b", `a\b`, "", "Activity", "a-b", "a.b", strings.Repeat("a", 64), "1abc"} {
		got := SegmentName(bad, at, 1)
		if got != "unknown-20261112-07-0001.ndjson" {
			t.Errorf("SegmentName(%q) = %q", bad, got)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("separator in %q", got)
		}
	}
	if got := SegmentName("health", at, -5); got != "health-20261112-07-0000.ndjson" {
		t.Errorf("negative n: %q", got)
	}

	for _, stream := range event.Streams {
		name := SegmentName(stream, at, 7)
		got, ok := ParseSegmentName(name)
		if !ok || got != stream {
			t.Errorf("ParseSegmentName(%q) = %q, %v", name, got, ok)
		}
	}
	seg, ok := parseSegment("activity-20261112-07-0042.ndjson")
	if !ok || seg.n != 42 || !seg.bucket.Equal(time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("parseSegment: %+v %v", seg, ok)
	}
	for _, bad := range []string{
		"", "activity.ndjson", "activity-20261112-07-0001", "activity-20261112-07-0001.ndjson.gz", "activity-20261112-07-0001.ndjson.tmp",
		"activity-2026111-07-0001.ndjson", "activity-20261112-7-0001.ndjson", "activity-20261112-24-0001.ndjson",
		"activity-20261332-07-0001.ndjson", "activity-20261112-07-.ndjson", "activity-20261112-07-1234567890.ndjson",
		"activity-20261112-07--1.ndjson", "activity-20261112-07-00x1.ndjson", "-20261112-07-0001.ndjson",
		"Activity-20261112-07-0001.ndjson", "../x-20261112-07-0001.ndjson", "a/b-20261112-07-0001.ndjson",
		"a b-20261112-07-0001.ndjson", ".shipper-forward.checkpoint", "activity-20261112-07-0001.NDJSON",
		"activity-٢٠٢٦١١١٢-07-0001.ndjson", "activity-20261112-07-0001.ndjson\x00",
	} {
		if s, ok := ParseSegmentName(bad); ok {
			t.Errorf("ParseSegmentName(%q) accepted as stream %q", bad, s)
		}
	}
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func TestFilesStreamsModeAndFormat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool", "nested")
	ck := &clock{t: testTime}
	s, err := NewFiles(FilesOptions{Dir: dir, Now: ck.Now})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "files" {
		t.Errorf("Name = %q", s.Name())
	}
	var batch []*event.Event
	for i, k := range []event.Kind{event.KindActivity, event.KindDetection, event.KindInventory, event.KindPosture, event.KindHealth, "bogus"} {
		batch = append(batch, kindEvent(k, fmt.Sprintf("e%d", i)), nil)
	}
	if err := s.Write(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"activity-20261111-10-0001.ndjson", "detection-20261111-10-0001.ndjson", "health-20261111-10-0001.ndjson",
		"inventory-20261111-10-0001.ndjson", "posture-20261111-10-0001.ndjson",
	}
	got := segmentFiles(t, dir)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("segments = %v", got)
	}
	if n := len(readEvents(t, dir)); n != 6 {
		t.Fatalf("events = %d", n)
	}
	if runtime.GOOS != "windows" {
		for _, name := range got {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o640 {
				t.Errorf("%s mode %o, want 0640", name, fi.Mode().Perm())
			}
		}
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o750 {
			t.Errorf("dir mode %o, want 0750", fi.Mode().Perm())
		}
	}
	// The hour in the name follows the clock, and a new hour is a new file.
	ck.Set(testTime.Add(time.Hour))
	if err := s.Write([]*event.Event{kindEvent(event.KindActivity, "later")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "activity-20261111-11-0001.ndjson")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := s.Write(batch); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Close: %v", err)
	}
	if err := s.Flush(); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush after Close: %v", err)
	}

	// OCSF lines carry the class and the native event.
	dir2 := t.TempDir()
	o, err := NewFiles(FilesOptions{Dir: dir2, Format: FormatOCSF, Now: ck.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Write([]*event.Event{kindEvent(event.KindDetection, "d1")}); err != nil {
		t.Fatal(err)
	}
	o.Close()
	lines := readLines(t, dir2)
	var rec map[string]any
	if len(lines) != 1 || json.Unmarshal(lines[0], &rec) != nil || rec["class_uid"] != float64(2004) {
		t.Fatalf("ocsf line: %s", lines)
	}

	for _, bad := range []FilesOptions{{}, {Dir: dir2, Format: "xml"}, {Dir: dir2, MaxLineBytes: 100}} {
		if _, err := NewFiles(bad); err == nil {
			t.Errorf("NewFiles(%+v) should fail", bad)
		}
	}
	file := filepath.Join(dir2, "plain")
	os.WriteFile(file, nil, 0o600)
	if _, err := NewFiles(FilesOptions{Dir: file}); err == nil {
		t.Error("NewFiles on a regular file should fail")
	}
}

func TestFilesRollAndSharedSegment(t *testing.T) {
	dir := t.TempDir()
	ck := &clock{t: testTime}
	opts := FilesOptions{Dir: dir, MaxSegment: 4096, Now: ck.Now, RetainBytes: -1}
	a, err := NewFiles(opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFiles(opts) // stands in for a second process
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	for i := 0; i < 60; i++ {
		w := a
		if i%2 == 1 {
			w = b
		}
		if err := w.Write([]*event.Event{testEvent(fmt.Sprintf("r%d", i), 300)}); err != nil {
			t.Fatal(err)
		}
	}
	files := segmentFiles(t, dir)
	if len(files) < 5 {
		t.Fatalf("expected rolls, got %v", files)
	}
	for i, name := range files {
		if want := SegmentName("activity", testTime, i+1); name != want {
			t.Errorf("segment %d is %s, want %s (two writers must agree on the counter)", i, name, want)
		}
		fi, _ := os.Stat(filepath.Join(dir, name))
		// Rolled once the file has reached the limit: at most one line over.
		if fi.Size() > 4096+1024 {
			t.Errorf("%s is %d bytes", name, fi.Size())
		}
		if i < len(files)-1 && fi.Size() < 4096 {
			t.Errorf("%s rolled early at %d bytes", name, fi.Size())
		}
	}
	events := readEvents(t, dir)
	if len(events) != 60 {
		t.Fatalf("events = %d", len(events))
	}
	// Each segment holds lines from both writers: they really shared files.
	raw, _ := os.ReadFile(filepath.Join(dir, files[0]))
	if !strings.Contains(string(raw), `"id":"r0"`) || !strings.Contains(string(raw), `"id":"r1"`) {
		t.Error("writers did not share the first segment")
	}
}

func writeSegment(t *testing.T, dir, name string, size int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat("x", size-1)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
}

func exists(dir, name string) bool {
	_, err := os.Lstat(filepath.Join(dir, name))
	return err == nil
}

func TestFilesPrune(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)
	ck := &clock{t: now}
	name := func(stream string, age time.Duration, n int) string { return SegmentName(stream, now.Add(-age), n) }

	t.Run("age", func(t *testing.T) {
		dir := t.TempDir()
		old := name("activity", 49*time.Hour, 1)
		edge := name("activity", 48*time.Hour, 1) // hour ends 47h30 ago: inside 48h
		fresh := name("activity", time.Hour, 1)
		onlyOld := name("posture", 30*24*time.Hour, 1) // newest of its stream: kept
		for _, n := range []string{old, edge, fresh, onlyOld} {
			writeSegment(t, dir, n, 100)
		}
		os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("keep"), 0o600)
		os.WriteFile(filepath.Join(dir, "activity-20200101-00-0001.ndjson.gz"), []byte("keep"), 0o600)
		os.Mkdir(filepath.Join(dir, "activity-20200101-00-0002.ndjson"), 0o700) // a directory with a segment name
		s, err := NewFiles(FilesOptions{Dir: dir, RetainAge: 48 * time.Hour, RetainBytes: -1, Now: ck.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.(Pruner).Prune(); err != nil {
			t.Fatal(err)
		}
		if exists(dir, old) {
			t.Error("expired segment kept")
		}
		for _, n := range []string{edge, fresh, onlyOld, "notes.txt", "activity-20200101-00-0001.ndjson.gz", "activity-20200101-00-0002.ndjson"} {
			if !exists(dir, n) {
				t.Errorf("%s was deleted", n)
			}
		}
	})

	t.Run("bytes", func(t *testing.T) {
		dir := t.TempDir()
		var names []string
		for i := 6; i >= 1; i-- { // six hourly activity segments of 1000 bytes
			n := name("activity", time.Duration(i)*time.Hour, 1)
			writeSegment(t, dir, n, 1000)
			names = append(names, n)
		}
		det := name("detection", 5*time.Hour, 1) // old but the newest detection segment
		writeSegment(t, dir, det, 1000)
		future := SegmentName("activity", now.Add(72*time.Hour), 1) // written while the clock was wrong
		writeSegment(t, dir, future, 1000)
		s, err := NewFiles(FilesOptions{Dir: dir, RetainBytes: 3500, RetainAge: -1, Now: ck.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.(Pruner).Prune(); err != nil {
			t.Fatal(err)
		}
		// 8000 bytes, limit 3500: the misdated file goes first, then the
		// oldest activity segments, never the newest of a stream.
		wantGone := []string{future, names[0], names[1], names[2], names[3]}
		wantKept := []string{names[4], names[5], det}
		for _, n := range wantGone {
			if exists(dir, n) {
				t.Errorf("%s should have been pruned", n)
			}
		}
		for _, n := range wantKept {
			if !exists(dir, n) {
				t.Errorf("%s should have been kept", n)
			}
		}
	})

	t.Run("on_roll", func(t *testing.T) {
		// Retention runs by itself when a writer creates a segment.
		dir := t.TempDir()
		s, err := NewFiles(FilesOptions{Dir: dir, MaxSegment: 2000, RetainBytes: 6000, Now: ck.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		for i := 0; i < 200; i++ {
			if err := s.Write([]*event.Event{testEvent(fmt.Sprintf("p%d", i), 200)}); err != nil {
				t.Fatal(err)
			}
		}
		files := segmentFiles(t, dir)
		var total int64
		for _, n := range files {
			fi, _ := os.Stat(filepath.Join(dir, n))
			total += fi.Size()
		}
		// The limit is enforced at each roll, so the total can exceed it by
		// at most the segment being filled.
		if total > 6000+2000+1024 {
			t.Errorf("retained %d bytes in %d segments", total, len(files))
		}
		events := readEvents(t, dir)
		if len(events) == 0 || events[len(events)-1].ID != "p199" {
			t.Error("the newest event must survive pruning")
		}
		if exists(dir, SegmentName("activity", now, 1)) {
			t.Error("the first segment should be gone")
		}
	})

	t.Run("symlink_not_followed", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privilege on Windows")
		}
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "victim")
		os.WriteFile(outside, []byte("precious"), 0o600)
		link := name("activity", 100*time.Hour, 1)
		if err := os.Symlink(outside, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
		writeSegment(t, dir, name("activity", time.Hour, 1), 10)
		s, _ := NewFiles(FilesOptions{Dir: dir, RetainAge: time.Hour, RetainBytes: 1, Now: ck.Now})
		defer s.Close()
		if err := s.(Pruner).Prune(); err != nil {
			t.Fatal(err)
		}
		if raw, err := os.ReadFile(outside); err != nil || string(raw) != "precious" {
			t.Fatalf("file outside the directory was touched: %q %v", raw, err)
		}
		if !exists(dir, link) {
			t.Error("a symlink is not a segment and must be left alone")
		}
	})
}

// TestFilesHostileNames plants things an attacker with write access to the
// directory could put under the next segment name.
func TestFilesHostileNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses symlinks and FIFOs")
	}
	ck := &clock{t: testTime}
	first := SegmentName("activity", testTime, 1)
	second := SegmentName("activity", testTime, 2)

	plant := map[string]func(t *testing.T, dir, victim string){
		"symlink_to_file": func(t *testing.T, dir, victim string) {
			if err := os.Symlink(victim, filepath.Join(dir, first)); err != nil {
				t.Fatal(err)
			}
		},
		"dangling_symlink": func(t *testing.T, dir, victim string) {
			if err := os.Symlink(victim+".new", filepath.Join(dir, first)); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, dir, _ string) {
			if err := mkfifo(filepath.Join(dir, first)); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
		},
		"directory": func(t *testing.T, dir, _ string) {
			if err := os.Mkdir(filepath.Join(dir, first), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"hard_link": func(t *testing.T, dir, victim string) {
			if err := os.Link(victim, filepath.Join(dir, first)); err != nil {
				t.Skipf("link: %v", err)
			}
		},
	}
	for name, do := range plant {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(dir, "victim.conf") // same filesystem, for the hard link
			if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
				t.Fatal(err)
			}
			do(t, dir, victim)
			s, err := NewFiles(FilesOptions{Dir: dir, Now: ck.Now})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			done := make(chan error, 1)
			go func() { done <- s.Write([]*event.Event{testEvent("h1", 10)}) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Write: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Write blocked on the planted file")
			}
			if raw, _ := os.ReadFile(victim); string(raw) != "precious" {
				t.Fatalf("victim file was written through: %q", raw)
			}
			if _, err := os.Stat(victim + ".new"); err == nil {
				t.Fatal("a file was created through the dangling symlink")
			}
			raw, err := os.ReadFile(filepath.Join(dir, second))
			if err != nil || !strings.Contains(string(raw), `"id":"h1"`) {
				t.Fatalf("event should have gone to %s: %v %q", second, err, raw)
			}
		})
	}
}

func TestFilesDeletedUnderWriter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX unlink semantics")
	}
	dir := t.TempDir()
	ck := &clock{t: testTime}
	s, err := NewFiles(FilesOptions{Dir: dir, Now: ck.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write([]*event.Event{testEvent("before", 10)}); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, SegmentName("activity", testTime, 1))
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	// The writer still holds the unlinked file; it must notice and reopen
	// rather than write into the void.
	if err := s.Write([]*event.Event{testEvent("after", 10)}); err != nil {
		t.Fatal(err)
	}
	events := readEvents(t, dir)
	if len(events) != 1 || events[0].ID != "after" {
		t.Fatalf("events on disk: %v", events)
	}
}

func TestFilesTornWriteRecovery(t *testing.T) {
	dir := t.TempDir()
	ck := &clock{t: testTime}
	s, err := NewFiles(FilesOptions{Dir: dir, Now: ck.Now})
	if err != nil {
		t.Fatal(err)
	}
	fs := s.(*filesSink)
	if err := s.Write([]*event.Event{testEvent("a", 10)}); err != nil {
		t.Fatal(err)
	}
	// Simulate a write that failed half way (disk full): a fragment with no
	// newline is at the end of the file and the sink knows it.
	path := filepath.Join(dir, SegmentName("activity", testTime, 1))
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"v":1,"id":"torn","ts":"2026-11-11T10:2`)
	f.Close()
	fs.open["activity"].torn = true
	if err := s.Write([]*event.Event{testEvent("b", 10)}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines (good, fragment, good), got %d: %q", len(lines), raw)
	}
	var e event.Event
	if json.Unmarshal([]byte(lines[2]), &e) != nil || e.ID != "b" {
		t.Fatalf("the event after a torn write was lost: %q", lines[2])
	}
	if json.Unmarshal([]byte(lines[1]), &e) == nil {
		t.Fatal("fragment unexpectedly parsed")
	}
}

func TestFilesWriteErrorIsReported(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test cannot write to")
	}
	dir := t.TempDir()
	s, err := NewFiles(FilesOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	err = s.Write([]*event.Event{testEvent("x", 1), testEvent("y", 1)})
	if err == nil || !strings.Contains(err.Error(), "2 of 2 events not written") {
		t.Fatalf("err = %v", err)
	}
}
