package sink

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// startShipper runs a Shipper with fast timings and returns a stop function
// that cancels it and waits for Run to return.
func startShipper(t testing.TB, o ShipperOptions, dst Sink, tune func(*Shipper)) (*Shipper, func()) {
	t.Helper()
	if o.Interval == 0 {
		o.Interval = 5 * time.Millisecond
	}
	s := NewShipper(o, dst)
	s.maxBackoff = 40 * time.Millisecond
	if tune != nil {
		tune(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	var stopped bool
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not stop")
		}
	}
	t.Cleanup(stop)
	return s, stop
}

// fill writes n events per stream through a Files sink with small segments.
func fill(t testing.TB, dir string, perStream int, format string) (ids []string) {
	t.Helper()
	w, err := NewFiles(FilesOptions{Dir: dir, MaxSegment: 8 << 10, RetainBytes: -1, RetainAge: -1, Format: format})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	kinds := []event.Kind{event.KindActivity, event.KindDetection, event.KindInventory, event.KindPosture, event.KindHealth}
	for i := 0; i < perStream; i++ {
		for _, k := range kinds {
			e := kindEvent(k, fmt.Sprintf("%s-%04d", k, i))
			if err := w.Write([]*event.Event{e}); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, e.ID)
		}
	}
	return ids
}

func assertExactlyOnce(t testing.TB, got, want []string) {
	t.Helper()
	g, w := sortedCopy(got), sortedCopy(want)
	if len(g) != len(w) {
		t.Fatalf("delivered %d events, want %d", len(g), len(w))
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("delivered set differs at %d: got %s want %s", i, g[i], w[i])
		}
	}
}

func TestShipperDeliversEverythingOnce(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 400, FormatNative) // 2000 events, many segments per stream
	if n := len(segmentFiles(t, dir)); n < 20 {
		t.Fatalf("test needs many segments, got %d", n)
	}
	dst := &memSink{name: "mem"}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 64}, dst, nil)
	waitFor(t, 20*time.Second, "all events", func() bool { return dst.count() >= len(want) })
	waitFor(t, 5*time.Second, "empty backlog", func() bool { return s.Stats().Backlog == 0 })
	stop()
	assertExactlyOnce(t, dst.ids(), want)

	// Within a stream, events arrive in the order they were written.
	last := map[event.Kind]string{}
	for _, e := range dst.got {
		if e.ID <= last[e.Kind] {
			t.Fatalf("stream %s out of order: %s after %s", e.Kind, e.ID, last[e.Kind])
		}
		last[e.Kind] = e.ID
	}
	for _, b := range dst.batches {
		if len(b) > 64 {
			t.Fatalf("batch of %d exceeds Batch", len(b))
		}
	}
	st := s.Stats()
	if st.Shipped != uint64(len(want)) || st.BadLines != 0 || st.Dropped != 0 || st.Errors != 0 {
		t.Errorf("stats = %+v", st)
	}
	if dst.flushes == 0 {
		t.Error("destination was never flushed before checkpointing")
	}

	// The default checkpoint sits next to the segments, is valid JSON, is
	// not mistaken for a segment, and no temporary files are left behind.
	cp := filepath.Join(dir, ".shipper-mem.checkpoint")
	raw, err := os.ReadFile(cp)
	if err != nil {
		t.Fatal(err)
	}
	var state checkpointFile
	if err := json.Unmarshal(raw, &state); err != nil || state.V != 1 || len(state.Files) != len(segmentFiles(t, dir)) {
		t.Fatalf("checkpoint: %v, %d files", err, len(state.Files))
	}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", en.Name())
		}
	}

	// A restart with the same checkpoint sends nothing again, and new
	// events appended afterwards are picked up.
	dst2 := &memSink{name: "mem"}
	s2, stop2 := startShipper(t, ShipperOptions{Dir: dir, Batch: 64}, dst2, nil)
	time.Sleep(100 * time.Millisecond)
	if n := dst2.count(); n != 0 {
		t.Fatalf("restart re-sent %d events", n)
	}
	more := fill(t, dir, 3, FormatNative)
	_ = more
	waitFor(t, 10*time.Second, "new events after restart", func() bool { return dst2.count() >= 15 })
	stop2()
	if s2.Stats().Shipped != 15 {
		t.Errorf("after restart shipped %d, want 15", s2.Stats().Shipped)
	}
}

func TestShipperFollowsLiveWriter(t *testing.T) {
	dir := t.TempDir()
	dst := &memSink{}
	_, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 50}, dst, nil) // directory does not exist yet
	time.Sleep(20 * time.Millisecond)

	w, err := NewFiles(FilesOptions{Dir: dir, MaxSegment: 16 << 10, RetainBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := 0; i < 1500; i++ {
		e := testEvent(fmt.Sprintf("live-%05d", i), i%700)
		want = append(want, e.ID)
		if err := w.Write([]*event.Event{e}); err != nil {
			t.Fatal(err)
		}
		if i%100 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	w.Close()
	waitFor(t, 20*time.Second, "all live events", func() bool { return dst.count() >= len(want) })
	stop()
	assertExactlyOnce(t, dst.ids(), want)
	for _, e := range dst.got {
		if err := checkTestEvent(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShipperRetriesTransientErrors(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 40, FormatNative)
	var calls atomic.Int64
	dst := &memSink{fail: func([]*event.Event) error {
		// Down for the first calls, then flaky.
		if n := calls.Add(1); n <= 4 || n%3 == 0 {
			return errors.New("connection refused")
		}
		return nil
	}}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 16}, dst, nil)
	waitFor(t, 20*time.Second, "delivery despite errors", func() bool { return dst.count() >= len(want) })
	stop()
	assertExactlyOnce(t, dst.ids(), want) // a failed Write must not advance, a good one must not repeat
	st := s.Stats()
	if st.Errors < 4 || st.LastError == "" || st.Dropped != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestShipperIsolatesPoisonedEvents(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewFiles(FilesOptions{Dir: dir})
	var want []string
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("ok-%03d", i)
		if i == 37 || i == 38 || i == 150 {
			id = fmt.Sprintf("poison-%03d", i)
		} else {
			want = append(want, id)
		}
		w.Write([]*event.Event{testEvent(id, 20)})
	}
	w.Close()
	dst := &memSink{fail: func(batch []*event.Event) error {
		for _, e := range batch {
			if strings.HasPrefix(e.ID, "poison") {
				return fmt.Errorf("wrapped: %w", permErr{"400 bad request"})
			}
		}
		return nil
	}}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 64}, dst, nil)
	waitFor(t, 20*time.Second, "delivery around poison", func() bool { return dst.count() >= len(want) })
	waitFor(t, 5*time.Second, "empty backlog", func() bool { return s.Stats().Backlog == 0 })
	stop()
	assertExactlyOnce(t, dst.ids(), want)
	if st := s.Stats(); st.Dropped != 3 || st.Shipped != uint64(len(want)) {
		t.Errorf("stats = %+v, want 3 dropped", st)
	}
}

// A destination that refuses everything as "permanent" looks exactly like a
// wrong URL. Nothing may be dropped on its word alone.
func TestShipperDoesNotDropForUnprovenDestination(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 30, FormatNative)
	var broken atomic.Bool
	broken.Store(true)
	dst := &memSink{fail: func([]*event.Event) error {
		if broken.Load() {
			return permErr{"400 bad request"}
		}
		return nil
	}}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 32}, dst, nil)
	waitFor(t, 10*time.Second, "refusals", func() bool { return s.Stats().Errors >= 5 })
	if st := s.Stats(); st.Dropped != 0 || st.Shipped != 0 || st.Backlog == 0 || st.LastError == "" {
		t.Fatalf("stats while the destination refuses everything: %+v", st)
	}
	broken.Store(false) // the operator fixes the endpoint
	waitFor(t, 20*time.Second, "delivery after the fix", func() bool { return dst.count() >= len(want) })
	stop()
	assertExactlyOnce(t, dst.ids(), want)
	if st := s.Stats(); st.Dropped != 0 {
		t.Errorf("dropped %d events because of a misconfiguration", st.Dropped)
	}
}

// The first record after a restart is the poisoned one: the destination is
// proven by the records behind it, then the bad one is dropped.
func TestShipperPoisonAtTheFront(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewFiles(FilesOptions{Dir: dir})
	var want []string
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("ok-%03d", i)
		if i == 0 || i == 1 || i == 49 {
			id = fmt.Sprintf("poison-%03d", i)
		} else {
			want = append(want, id)
		}
		w.Write([]*event.Event{testEvent(id, 20)})
	}
	w.Close()
	dst := &memSink{fail: func(batch []*event.Event) error {
		for _, e := range batch {
			if strings.HasPrefix(e.ID, "poison") {
				return permErr{"400"}
			}
		}
		return nil
	}}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 64}, dst, nil)
	waitFor(t, 20*time.Second, "delivery", func() bool { return dst.count() >= len(want) && s.Stats().Backlog == 0 })
	stop()
	assertExactlyOnce(t, dst.ids(), want)
	if st := s.Stats(); st.Dropped != 3 {
		t.Errorf("Dropped = %d, want 3", st.Dropped)
	}
}

// A destination that worked and then refuses everything may cost a bounded
// number of events, not the whole backlog.
func TestShipperBoundsConsecutiveDrops(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 60, FormatNative) // 300 events
	var calls atomic.Int64
	dst := &memSink{fail: func([]*event.Event) error {
		if calls.Add(1) == 1 {
			return nil // one good batch, then everything is "bad"
		}
		return permErr{"400"}
	}}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 8}, dst, nil)
	waitFor(t, 10*time.Second, "drop limit", func() bool { return s.Stats().Dropped >= maxDropsInARow })
	time.Sleep(150 * time.Millisecond)
	stop()
	st := s.Stats()
	if st.Dropped != maxDropsInARow {
		t.Errorf("Dropped = %d, want exactly %d", st.Dropped, maxDropsInARow)
	}
	if int(st.Shipped)+int(st.Dropped) >= len(want) || st.Backlog == 0 {
		t.Errorf("the backlog must stay on disk: %+v", st)
	}
}

func TestShipperCountsOTLPPartialSuccess(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 4, FormatNative) // 20 events
	var calls, firstLen atomic.Int64
	dst := &memSink{}
	dst.fail = func(batch []*event.Event) error {
		if calls.Add(1) == 1 {
			// The receiver took this request, minus two records. memSink
			// records nothing on an error, so the events of this batch show
			// up below only if the shipper wrongly sends them again.
			firstLen.Store(int64(len(batch)))
			return fmt.Errorf("sink otlp: %w", &RejectedError{Rejected: 2, Message: "schema"})
		}
		return nil
	}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 5}, dst, nil)
	waitFor(t, 10*time.Second, "all batches settled", func() bool {
		return s.Stats().Shipped+s.Stats().Dropped == uint64(len(want)) && s.Stats().Backlog == 0
	})
	stop()
	st := s.Stats()
	if st.Dropped != 2 || st.Shipped != uint64(len(want)-2) {
		t.Errorf("stats = %+v, want 2 dropped and %d shipped", st, len(want)-2)
	}
	// The partially accepted batch was not sent again.
	if got, want := dst.count(), len(want)-int(firstLen.Load()); got != want || firstLen.Load() < 2 {
		t.Errorf("destination recorded %d more events, want %d: the partially accepted batch must never be resent", got, want)
	}
}

func appendRaw(t testing.TB, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func nativeLine(t testing.TB, id string) string {
	t.Helper()
	b, err := testEvent(id, 12).MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestShipperSkipsBadLinesAndWaitsForPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SegmentName("activity", time.Now(), 1))
	glued := strings.TrimSuffix(nativeLine(t, "gl1"), "\n") + nativeLine(t, "gl2")
	huge := strings.Repeat("x", 5<<20) // longer than the read window, no newline inside
	partial := nativeLine(t, "tail")
	appendRaw(t, path, nativeLine(t, "good1")+
		"this is not json\n"+
		"\n   \n\r\n"+ // blank lines are not counted
		`{"foo":1}`+"\n"+
		`[1,2,3]`+"\n"+
		glued+
		`{"v":1,"id":"badts","ts":"yesterday","kind":"activity","type":"tool.pre"}`+"\n"+
		nativeLine(t, "good2")+
		huge+"\n"+
		nativeLine(t, "good3")+
		partial[:len(partial)/2]) // a line still being written

	dst := &memSink{}
	s, stop := startShipper(t, ShipperOptions{Dir: dir}, dst, nil)
	waitFor(t, 20*time.Second, "good lines", func() bool { return dst.count() >= 3 })
	time.Sleep(50 * time.Millisecond)
	if got := strings.Join(dst.ids(), ","); got != "good1,good2,good3" {
		t.Fatalf("delivered %s", got)
	}
	if st := s.Stats(); st.BadLines != 6 {
		t.Errorf("BadLines = %d, want 6 (garbage, two non-events, glued, bad time, oversize)", st.BadLines)
	}
	if st := s.Stats(); st.Backlog != int64(len(partial)/2) {
		t.Errorf("Backlog = %d, want the %d bytes of the unfinished line", st.Backlog, len(partial)/2)
	}
	// The writer finishes the line: now it ships.
	appendRaw(t, path, partial[len(partial)/2:])
	waitFor(t, 10*time.Second, "completed line", func() bool { return dst.count() >= 4 })
	stop()
	if got := dst.ids(); got[3] != "tail" {
		t.Fatalf("delivered %v", got)
	}
}

func TestShipperSkipsTornTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SegmentName("activity", time.Now(), 1))
	appendRaw(t, path, nativeLine(t, "a")+`{"v":1,"id":"torn","ts":"2026-11`)
	dst := &memSink{}
	s, stop := startShipper(t, ShipperOptions{Dir: dir}, dst, func(s *Shipper) { s.tornGrace = 50 * time.Millisecond })
	waitFor(t, 10*time.Second, "torn tail skipped", func() bool { return s.Stats().BadLines == 1 })
	// A later writer (which cannot know about the fragment) appends a whole
	// line; it must not be glued to the abandoned fragment.
	appendRaw(t, path, nativeLine(t, "b"))
	waitFor(t, 10*time.Second, "line after torn tail", func() bool { return dst.count() >= 2 })
	stop()
	if got := strings.Join(dst.ids(), ","); got != "a,b" {
		t.Fatalf("delivered %s", got)
	}
}

func TestShipperSurvivesPruning(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	seg := func(n int) string { return filepath.Join(dir, SegmentName("activity", now, n)) }
	for n := 1; n <= 4; n++ {
		for i := 0; i < 10; i++ {
			appendRaw(t, seg(n), nativeLine(t, fmt.Sprintf("s%d-%02d", n, i)))
		}
	}
	// The first batch goes through. The second call parks inside Write, so
	// the shipper is known to be mid-segment when retention strikes, and
	// then fails as a collector outage would.
	gate, parked := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	dst := &memSink{}
	dst.fail = func([]*event.Event) error {
		switch calls.Add(1) {
		case 1:
			return nil
		case 2:
			close(parked)
			<-gate
			return errors.New("collector down")
		}
		return nil
	}
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 5}, dst, nil)
	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("shipper never reached the second batch")
	}
	// Retention removes the segment being read and the next one.
	os.Remove(seg(1))
	os.Remove(seg(2))
	close(gate)
	waitFor(t, 10*time.Second, "remaining segments", func() bool { return dst.count() >= 25 })
	waitFor(t, 5*time.Second, "empty backlog", func() bool { return s.Stats().Backlog == 0 })
	stop()
	got := dst.ids()
	if len(got) != 25 {
		t.Fatalf("delivered %d: %v", len(got), got)
	}
	for i, id := range got[5:] {
		if want := fmt.Sprintf("s%d-%02d", 3+i/10, i%10); id != want {
			t.Fatalf("after pruning got %s at %d, want %s", id, i, want)
		}
	}
	// State for deleted segments is forgotten.
	raw, _ := os.ReadFile(filepath.Join(dir, ".shipper-mem.checkpoint"))
	var state checkpointFile
	json.Unmarshal(raw, &state)
	if len(state.Files) != 2 {
		t.Errorf("checkpoint tracks %d files, want 2", len(state.Files))
	}
}

func TestShipperDetectsRecreatedSegment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SegmentName("activity", time.Now(), 1))
	cp := filepath.Join(t.TempDir(), "ship.cp")
	appendRaw(t, path, nativeLine(t, "old1")+nativeLine(t, "old2"))

	dst := &memSink{}
	_, stop := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: cp}, dst, nil)
	waitFor(t, 10*time.Second, "first file", func() bool { return dst.count() == 2 })
	stop()

	// Same name, different and longer content: an offset from the old file
	// would silently skip the start of the new one.
	os.Remove(path)
	appendRaw(t, path, nativeLine(t, "new1")+nativeLine(t, "new2")+nativeLine(t, "new3")+nativeLine(t, "new4"))
	dst2 := &memSink{}
	_, stop2 := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: cp}, dst2, nil)
	waitFor(t, 10*time.Second, "recreated file", func() bool { return dst2.count() >= 4 })
	stop2()
	if got := strings.Join(dst2.ids(), ","); got != "new1,new2,new3,new4" {
		t.Fatalf("delivered %s", got)
	}

	// Shorter than the stored offset: also start over.
	os.Remove(path)
	appendRaw(t, path, nativeLine(t, "tiny"))
	dst3 := &memSink{}
	_, stop3 := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: cp}, dst3, nil)
	waitFor(t, 10*time.Second, "shrunk file", func() bool { return dst3.count() >= 1 })
	stop3()
	if got := strings.Join(dst3.ids(), ","); got != "tiny" {
		t.Fatalf("delivered %s", got)
	}
}

func TestShipperReadsOCSFSegments(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 5, FormatOCSF)
	dst := &memSink{}
	_, stop := startShipper(t, ShipperOptions{Dir: dir}, dst, nil)
	waitFor(t, 10*time.Second, "ocsf lines", func() bool { return dst.count() >= len(want) })
	stop()
	assertExactlyOnce(t, dst.ids(), want)
	for _, e := range dst.got {
		if e.V != event.SchemaVersion || e.Host == nil || e.Host.ID != "host-1" {
			t.Fatalf("native event not recovered from OCSF line: %+v", e)
		}
	}
}

func TestShipperCheckpointProblems(t *testing.T) {
	dir := t.TempDir()
	want := fill(t, dir, 4, FormatNative)
	for name, content := range map[string]string{
		"garbage":       "\x00\x01not json",
		"wrong_version": `{"v":99,"files":{}}`,
		"hostile_names": `{"v":1,"files":{"../../etc/passwd":{"off":10},"activity-20261111-10-0001.ndjson":{"off":-5},"x":null}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cp := filepath.Join(t.TempDir(), "cp")
			os.WriteFile(cp, []byte(content), 0o600)
			dst := &memSink{}
			s, stop := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: cp}, dst, nil)
			waitFor(t, 10*time.Second, "re-ship", func() bool { return dst.count() >= len(want) })
			stop()
			assertExactlyOnce(t, dst.ids(), want)
			if name != "hostile_names" && s.Stats().Resets != 1 {
				t.Errorf("Resets = %d", s.Stats().Resets)
			}
			raw, _ := os.ReadFile(cp)
			var state checkpointFile
			if json.Unmarshal(raw, &state) != nil || state.V != 1 {
				t.Errorf("checkpoint not rewritten: %.60q", raw)
			}
			for n := range state.Files {
				if _, ok := ParseSegmentName(n); !ok {
					t.Errorf("non-segment name persisted: %q", n)
				}
			}
		})
	}

	t.Run("unwritable", func(t *testing.T) {
		// A checkpoint that cannot be saved must not stop delivery; it
		// only costs duplicates after a restart.
		dst := &memSink{}
		s, stop := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: filepath.Join(t.TempDir(), "missing", "dir", "cp")}, dst, nil)
		waitFor(t, 10*time.Second, "delivery without checkpoint", func() bool { return dst.count() >= len(want) })
		stop()
		assertExactlyOnce(t, dst.ids(), want)
		if s.Stats().Errors == 0 {
			t.Error("checkpoint failure not counted")
		}
	})
}

func TestShipperRemovesStaleCheckpointTemps(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "ship[1].cp") // a name with glob syntax in it
	stale, fresh, other := cp+".123.tmp", cp+".456.tmp", filepath.Join(dir, "unrelated.789.tmp")
	for _, p := range []string{stale, fresh, other} {
		os.WriteFile(p, []byte("x"), 0o600)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(stale, old, old)
	os.Chtimes(other, old, old)
	_, stop := startShipper(t, ShipperOptions{Dir: dir, Checkpoint: cp}, &memSink{}, nil)
	time.Sleep(50 * time.Millisecond)
	stop()
	if _, err := os.Stat(stale); err == nil {
		t.Error("stale temporary checkpoint not removed")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must not be removed", filepath.Base(p))
		}
	}
}

func TestShipperRunArguments(t *testing.T) {
	if err := NewShipper(ShipperOptions{Dir: t.TempDir()}, nil).Run(context.Background()); err == nil {
		t.Error("nil destination accepted")
	}
	if err := NewShipper(ShipperOptions{}, &memSink{}).Run(context.Background()); err == nil {
		t.Error("empty Dir accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewShipper(ShipperOptions{Dir: t.TempDir()}, &memSink{}).Run(ctx); err != nil {
		t.Errorf("cancelled Run returned %v", err)
	}
}

func TestShipperBackoff(t *testing.T) {
	s := NewShipper(ShipperOptions{Dir: "x", Interval: 100 * time.Millisecond}, &memSink{})
	s.maxBackoff = 2 * time.Second
	prevMax := time.Duration(0)
	for failures := 1; failures <= 12; failures++ {
		ceiling := 100 * time.Millisecond << (failures - 1)
		if ceiling > 2*time.Second {
			ceiling = 2 * time.Second
		}
		for i := 0; i < 50; i++ {
			d := s.backoff(failures, errors.New("x"))
			if d < ceiling/2 || d > ceiling {
				t.Fatalf("backoff(%d) = %v, want within [%v, %v]", failures, d, ceiling/2, ceiling)
			}
		}
		if ceiling < prevMax {
			t.Fatal("backoff ceiling decreased")
		}
		prevMax = ceiling
	}
	err := fmt.Errorf("sink otlp: %w", &HTTPStatusError{Code: 429, RetryAfter: 7 * time.Second})
	if d := s.backoff(1, err); d != 7*time.Second {
		t.Errorf("Retry-After not honoured: %v", d)
	}
}

func TestParseLine(t *testing.T) {
	good := strings.TrimSpace(nativeLine(t, "x"))
	if e := parseLine([]byte(good)); e == nil || e.ID != "x" {
		t.Fatal("native line rejected")
	}
	// Numbers in free-form input are kept exactly.
	e := testEvent("n", 1)
	e.Tool.Input = map[string]any{"big": json.Number("12345678901234567890"), "f": json.Number("1.10")}
	b, _ := json.Marshal(e)
	got := parseLine(b)
	if got == nil || got.Tool.Input["big"] != json.Number("12345678901234567890") || got.Tool.Input["f"] != json.Number("1.10") {
		t.Errorf("numbers altered: %v", got.Tool.Input)
	}
	for _, bad := range []string{
		"", "null", "42", `"str"`, "[]", "{}", `{"kind":"activity"}`, `{"type":"tool.pre"}`, good + good, good + " trailing",
		`{"unmapped":{"hawkbell":null}}`, `{"unmapped":{"hawkbell":{"kind":"activity"}}}`, `{"unmapped":{"hawkbell":"x"}}`,
		`{"kind":"activity","type":"t","ts":12345}`, `{"kind":"activity","type":"t","seq":-1}`, strings.Repeat("[", 100000),
		`{"kind":"activity","type":"t","tool":{"input":` + strings.Repeat(`{"a":`, 20000) + `1` + strings.Repeat(`}`, 20000) + `}}`,
	} {
		if e := parseLine([]byte(bad)); e != nil {
			t.Errorf("parseLine accepted %.60q", bad)
		}
	}
}

// --- crash and resume, with real process death ---

// crashSink records delivered ids in a file and kills the process on a
// chosen batch, after the destination has durably accepted it but before
// the shipper can save its checkpoint: the worst moment to die.
type crashSink struct {
	out        *os.File
	batches    int
	crashAfter int
	seen       map[string]bool
	expect     int
	done       chan struct{}
}

func (c *crashSink) Name() string { return "crash" }
func (c *crashSink) Flush() error { return nil }
func (c *crashSink) Close() error { return nil }

func (c *crashSink) Write(batch []*event.Event) error {
	var sb strings.Builder
	for _, e := range batch {
		sb.WriteString(e.ID)
		sb.WriteByte('\n')
		c.seen[e.ID] = true
	}
	if _, err := c.out.WriteString(sb.String()); err != nil {
		return err
	}
	if err := c.out.Sync(); err != nil {
		return err
	}
	c.batches++
	if c.crashAfter > 0 && c.batches >= c.crashAfter {
		os.Exit(3)
	}
	if len(c.seen) >= c.expect {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
	return nil
}

func readIDs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ids = append(ids, sc.Text())
	}
	return ids, sc.Err()
}

func shipHelper() {
	dir, out := os.Getenv("HAWKBELL_SINK_DIR"), os.Getenv("HAWKBELL_SHIP_OUT")
	crashAfter, _ := strconv.Atoi(os.Getenv("HAWKBELL_SHIP_CRASH_AFTER"))
	expect, _ := strconv.Atoi(os.Getenv("HAWKBELL_SHIP_EXPECT"))
	prior, err := readIDs(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dst := &crashSink{out: f, crashAfter: crashAfter, seen: map[string]bool{}, expect: expect, done: make(chan struct{})}
	for _, id := range prior {
		dst.seen[id] = true
	}
	if len(dst.seen) >= expect {
		close(dst.done) // an earlier run already delivered everything
	}
	s := NewShipper(ShipperOptions{Dir: dir, Checkpoint: os.Getenv("HAWKBELL_SHIP_CKPT"), Batch: 100, Interval: 5 * time.Millisecond}, dst)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-dst.done:
		case <-time.After(60 * time.Second):
			fmt.Fprintln(os.Stderr, "helper timed out")
			os.Exit(1)
		}
		cancel()
	}()
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestShipperCrashResume(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	dir := t.TempDir()
	want := fill(t, dir, 600, FormatNative) // 3000 events
	state := t.TempDir()
	out, cp := filepath.Join(state, "delivered"), filepath.Join(state, "checkpoint")

	crashes := 0
	for run := 0; ; run++ {
		if run > 100 {
			t.Fatal("shipper never finished")
		}
		crashAfter := 1 + run%4 // die on the 1st..4th batch of each run
		if run >= 12 {
			crashAfter = 0 // then let it finish
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(), helperEnv+"=ship", "HAWKBELL_SINK_DIR="+dir, "HAWKBELL_SHIP_OUT="+out, "HAWKBELL_SHIP_CKPT="+cp,
			"HAWKBELL_SHIP_CRASH_AFTER="+strconv.Itoa(crashAfter), "HAWKBELL_SHIP_EXPECT="+strconv.Itoa(len(want)))
		outb, err := cmd.CombinedOutput()
		if err == nil {
			break
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 3 {
			t.Fatalf("helper failed: %v: %s", err, outb)
		}
		crashes++
	}
	if crashes < 10 {
		t.Fatalf("only %d crashes happened; the test did not exercise resume", crashes)
	}
	got, err := readIDs(out)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, id := range got {
		counts[id]++
	}
	for _, id := range want {
		if counts[id] == 0 {
			t.Fatalf("event %s was lost across %d crashes", id, crashes)
		}
	}
	if len(counts) != len(want) {
		t.Fatalf("delivered %d distinct events, want %d", len(counts), len(want))
	}
	dups := len(got) - len(want)
	// Each crash can replay at most the one batch that was accepted but not
	// yet checkpointed.
	if dups > crashes*100 {
		t.Fatalf("%d duplicates after %d crashes exceeds one batch per crash", dups, crashes)
	}
	if dups == 0 {
		t.Fatal("no duplicates at all: the crash did not land between accept and checkpoint")
	}
	for id, n := range counts {
		if n > crashes+1 {
			t.Fatalf("event %s delivered %d times", id, n)
		}
	}
	t.Logf("%d events, %d crashes, %d duplicates", len(want), crashes, dups)
}
