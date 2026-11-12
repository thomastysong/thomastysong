package daemon

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/sink"
)

// fakeConsumer is a consumer with fixed positions.
type fakeConsumer struct {
	name  string
	files map[string]readPos
	all   bool
	err   error
}

func (c *fakeConsumer) id() string { return "fake:" + c.name }
func (c *fakeConsumer) view() (consumerView, error) {
	if c.err != nil {
		return consumerView{}, c.err
	}
	return consumerView{files: c.files, all: c.all}, nil
}

// outboxFixture writes segments of n records (seq first..first+n-1) each.
type outboxFixture struct {
	t   *testing.T
	dir string
	now time.Time
}

func newOutboxFixture(t *testing.T) *outboxFixture {
	return &outboxFixture{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 12, 12, 30, 0, 0, time.UTC)}
}

// seg writes a segment hoursAgo hours before now and returns its name and size.
func (o *outboxFixture) seg(stream string, hoursAgo, n, records int, firstSeq uint64) (string, int64) {
	o.t.Helper()
	name := sink.SegmentName(stream, o.now.Add(-time.Duration(hoursAgo)*time.Hour), n)
	var b strings.Builder
	for i := 0; i < records; i++ {
		fmt.Fprintf(&b, `{"v":1,"id":"%s-%d","kind":"%s","type":"x","source":"sensor","seq":%d,"ts":"2026-11-12T00:00:00.000000Z"}`+"\n", stream, i, stream, firstSeq+uint64(i))
	}
	p := filepath.Join(o.dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o640); err != nil {
		o.t.Fatal(err)
	}
	return name, int64(b.Len())
}

func (o *outboxFixture) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(o.dir, name))
	return err == nil
}

func (o *outboxFixture) pruner(maxAge time.Duration, maxBytes int64, cs ...consumer) *outboxPruner {
	return newOutboxPruner(pruneOptions{
		dir: o.dir, maxAge: maxAge, maxBytes: maxBytes,
		consumers: func() []consumer { return cs },
		statePath: filepath.Join(o.dir, "..", filepath.Base(o.dir)+"-covered.json"),
	})
}

func TestPruneNoConsumerByAgeAndCap(t *testing.T) {
	o := newOutboxFixture(t)
	oldDet, _ := o.seg("detection", 200, 0, 3, 1)
	oldAct, _ := o.seg("activity", 200, 0, 3, 1)
	newestDet, _ := o.seg("detection", 1, 0, 3, 4)
	midAct, _ := o.seg("activity", 5, 0, 50, 4)
	newestAct, _ := o.seg("activity", 0, 0, 3, 54)
	p := o.pruner(7*24*time.Hour, 1, nil...) // a cap nothing fits under
	res := p.prune(o.now)
	if res.lagKnown {
		t.Error("lag is not known without a consumer")
	}
	if res.removedAge != 2 || o.exists(oldDet) || o.exists(oldAct) {
		t.Errorf("age pruning: removed %d", res.removedAge)
	}
	if o.exists(midAct) {
		t.Error("cap did not remove an older activity segment")
	}
	if !o.exists(newestDet) || !o.exists(newestAct) {
		t.Error("the newest segment of a stream was removed")
	}
	if res.unread.bytes != 0 {
		t.Errorf("without a consumer nothing is reported as unshipped: %+v", res.unread)
	}
}

func TestPruneShipperConsumer(t *testing.T) {
	o := newOutboxFixture(t)
	readOld, readOldSize := o.seg("summary", 300, 0, 4, 1)
	unreadOld, unreadOldSize := o.seg("detection", 300, 0, 4, 1)
	act1, act1Size := o.seg("activity", 3, 0, 10, 1)
	det2, det2Size := o.seg("detection", 3, 0, 10, 5)
	newestAct, _ := o.seg("activity", 0, 0, 2, 11)
	newestDet, _ := o.seg("detection", 0, 0, 2, 15)
	newestSum, _ := o.seg("summary", 0, 0, 2, 5)
	half := det2Size / 2
	// Line boundary at or after half.
	b, _ := os.ReadFile(filepath.Join(o.dir, det2))
	cut := int64(strings.IndexByte(string(b[half:]), '\n')) + half + 1
	c := &fakeConsumer{name: "s", all: true, files: map[string]readPos{
		readOld: {off: readOldSize},
		det2:    {off: cut},
	}}
	_ = unreadOldSize
	p := o.pruner(7*24*time.Hour, 0, c)
	res := p.prune(o.now)
	if !res.lagKnown {
		t.Fatal("lag must be known with a consumer")
	}
	if o.exists(readOld) || res.removedAge != 1 {
		t.Errorf("a consumed old segment was not pruned by age (removed %d)", res.removedAge)
	}
	if !o.exists(unreadOld) || res.unreadOld != 1 {
		t.Errorf("an unread old segment must stay (unreadOld %d)", res.unreadOld)
	}
	wantLag := unreadOldSize + act1Size + (det2Size - cut)
	for _, n := range []string{newestAct, newestDet, newestSum} {
		fi, _ := os.Stat(filepath.Join(o.dir, n))
		wantLag += fi.Size()
	}
	if res.lag != wantLag {
		t.Errorf("lag = %d, want %d", res.lag, wantLag)
	}

	// Now a cap that forces unread data out: activity goes before detection.
	total := res.bytes
	p.o.maxBytes = total - act1Size
	res = p.prune(o.now)
	if o.exists(act1) {
		t.Error("the cap removed something else before the unread activity segment")
	}
	if !o.exists(det2) || !o.exists(unreadOld) {
		t.Error("the cap removed detection data before activity")
	}
	if res.unread.events != 10 || res.unread.bytes != uint64(act1Size) || res.unread.segments != 1 {
		t.Errorf("unread report = %+v", res.unread)
	}
	if d := res.unread.streams["activity"]; d == nil || d.seqFirst != 1 || d.seqLast != 10 {
		t.Errorf("activity drop = %+v", d)
	}

	// Cap down to the newest segments: the partly read detection segment
	// is reported from the consumer's offset only.
	p.o.maxBytes = 1
	res = p.prune(o.now)
	if o.exists(det2) || o.exists(unreadOld) {
		t.Error("cap left older segments")
	}
	if !o.exists(newestAct) || !o.exists(newestDet) || !o.exists(newestSum) {
		t.Error("cap removed a newest segment")
	}
	d := res.unread.streams["detection"]
	if d == nil {
		t.Fatal("no detection drop reported")
	}
	// unreadOld (4 records, seq 1..4) + the unread half of det2.
	read := 0
	for _, c := range b[:cut] {
		if c == '\n' {
			read++
		}
	}
	if d.events != uint64(4+10-read) {
		t.Errorf("detection events dropped = %d, want %d", d.events, 4+10-read)
	}
	if d.seqFirst != 1 || d.seqLast != 14 {
		t.Errorf("detection seq range = %d..%d", d.seqFirst, d.seqLast)
	}
	ev := droppedUnshippedEvent(o.now, res.unread)
	if ev.Kind != event.KindHealth || ev.Type != event.TypeHealthError || ev.Health.Reason != "outbox.dropped_unshipped" {
		t.Errorf("health record = %+v", ev)
	}
	if ev.Health.Counters["detection.events"] != d.events || ev.Health.Counters["bytes"] != res.unread.bytes {
		t.Errorf("counters = %v", ev.Health.Counters)
	}
	if _, err := ev.MarshalLine(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneStreamCoverage(t *testing.T) {
	o := newOutboxFixture(t)
	det, detSize := o.seg("detection", 3, 0, 5, 1)
	act, _ := o.seg("activity", 3, 0, 5, 1)
	oldAct, _ := o.seg("activity", 300, 0, 5, 1)
	o.seg("detection", 0, 0, 1, 6)
	o.seg("activity", 0, 0, 1, 6)
	// A Fluent Bit database that tails detections only.
	c := &fakeConsumer{name: "fb", files: map[string]readPos{det: {off: detSize}}}
	p := o.pruner(7*24*time.Hour, 0, c)
	res := p.prune(o.now)
	if o.exists(oldAct) {
		t.Error("an old segment of a stream no consumer reads was kept")
	}
	if res.removedAge != 1 {
		t.Errorf("removedAge = %d", res.removedAge)
	}
	// Cap: the consumed detection segment goes first, then the activity
	// stream nobody reads, before any unread data; neither is reported as
	// unshipped.
	p.o.maxBytes = res.bytes - detSize - 1
	res = p.prune(o.now)
	if o.exists(det) || o.exists(act) {
		t.Error("cap kept a consumed or an unconsumed-stream segment")
	}
	if res.removedUnconsumed != 1 || res.unread.bytes != 0 {
		t.Errorf("removedUnconsumed = %d, unread = %+v", res.removedUnconsumed, res.unread)
	}
	// The coverage is remembered: Fluent Bit forgets deleted files.
	p2 := o.pruner(7*24*time.Hour, 0, &fakeConsumer{name: "fb", files: map[string]readPos{}})
	_, res2 := p2.measure(o.now)
	if !res2.lagKnown {
		t.Fatal("lag unknown")
	}
	segs, _ := p2.measure(o.now)
	for _, s := range segs {
		if s.stream == "detection" && !s.covered {
			t.Error("remembered coverage lost: detection treated as unread by nobody")
		}
		if s.stream == "activity" && s.covered {
			t.Error("activity treated as covered")
		}
	}
}

func TestPruneConservativeConsumers(t *testing.T) {
	o := newOutboxFixture(t)
	old, oldSize := o.seg("detection", 300, 0, 3, 1)
	o.seg("detection", 0, 0, 1, 4)
	// A consumer that has never been readable might read anything.
	p := o.pruner(7*24*time.Hour, 0, &fakeConsumer{name: "broken", err: errors.New("locked")})
	res := p.prune(o.now)
	if !o.exists(old) {
		t.Error("an unreadable consumer must stop age pruning of what it may still read")
	}
	if len(res.consumerErr) != 1 {
		t.Errorf("consumer errors = %v", res.consumerErr)
	}
	// An inode mismatch (the row is about a previous file of that name)
	// means not read.
	inode := inodeOf(mustLstat(t, filepath.Join(o.dir, old)), filepath.Join(o.dir, old))
	if inode == 0 && runtime.GOOS != "windows" {
		t.Fatal("no inode")
	}
	c := &fakeConsumer{name: "fb", files: map[string]readPos{old: {off: oldSize, inode: inode + 1}}}
	p = o.pruner(7*24*time.Hour, 0, c)
	if _ = p.prune(o.now); !o.exists(old) {
		t.Error("a stale row (other inode) was taken as read")
	}
	c.files[old] = readPos{off: oldSize, inode: inode}
	if _ = p.prune(o.now); o.exists(old) {
		t.Error("a fully read old segment was kept")
	}
}

func TestPruneLeavesOtherFiles(t *testing.T) {
	o := newOutboxFixture(t)
	junk := []string{"notes.txt", "detection-x.ndjson", ".shipper-otlp.checkpoint", "Detection-20261101-00-0000.ndjson"}
	for _, n := range junk {
		if err := os.WriteFile(filepath.Join(o.dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := sink.SegmentName("detection", o.now.Add(-400*time.Hour), 0)
	if runtime.GOOS != "windows" {
		if err := os.Symlink(target, filepath.Join(o.dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	o.seg("detection", 0, 0, 1, 1)
	p := o.pruner(time.Hour, 1)
	p.prune(o.now)
	for _, n := range junk {
		if !o.exists(n) {
			t.Errorf("%s removed", n)
		}
	}
	if _, err := os.Stat(target); err != nil {
		t.Error("a symlink's target was removed")
	}
}

func TestPruneReadOnlyMeasures(t *testing.T) {
	o := newOutboxFixture(t)
	old, _ := o.seg("detection", 300, 0, 3, 1)
	o.seg("detection", 0, 0, 1, 4)
	p := newOutboxPruner(pruneOptions{dir: o.dir, maxAge: time.Hour, maxBytes: 1, readOnly: true})
	res := p.prune(o.now)
	if !o.exists(old) || res.removedAge != 0 {
		t.Error("a read-only pruner removed a segment")
	}
	if res.segments != 2 {
		t.Errorf("segments = %d", res.segments)
	}
}

func mustLstat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// fluentBitSchema is in_tail_files as Fluent Bit 5.2.0 creates it
// (captured from the fluent/fluent-bit:latest image, 2026-11-12).
const fluentBitSchema = `CREATE TABLE in_tail_files (  id      INTEGER PRIMARY KEY,  name    TEXT NOT NULL,  offset  INTEGER,  inode   INTEGER,  created INTEGER,  rotated INTEGER DEFAULT 0,  offset_marker INTEGER DEFAULT 0,  offset_marker_size INTEGER DEFAULT 0)`

func makeTailDB(t *testing.T, path string, rows []tailRow) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteURI(path, "_pragma=journal_mode(WAL)"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fluentBitSchema); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO in_tail_files (name, offset, inode, created) VALUES (?, ?, ?, 1794462503)`, r.name, r.offset, int64(r.inode)); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestReadTailDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spoor-findings.db")
	want := []tailRow{
		{name: "/w/outbox/detection-20261112-05-0000.ndjson", offset: 750, inode: 1237654},
		{name: `C:\ProgramData\spoor\outbox\health-20261112-05-0000.ndjson`, offset: 120, inode: 1<<63 + 5},
		{name: "/w/outbox/not-a-segment.log", offset: 9, inode: 3},
	}
	db := makeTailDB(t, path, want)

	// Fluent Bit running: its WAL and shared memory exist.
	rows, err := readTailDB(path, "")
	if err != nil {
		t.Fatalf("while the writer is open: %v", err)
	}
	if len(rows) != 3 || rows[1].inode != 1<<63+5 || rows[0].offset != 750 {
		t.Errorf("rows = %+v", rows)
	}
	v, err := (&tailDBConsumer{path: path}).view()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.files) != 2 || v.files["health-20261112-05-0000.ndjson"].off != 120 || v.all {
		t.Errorf("view = %+v", v)
	}
	db.Close()

	// Fluent Bit stopped: nothing may be created beside its database.
	for _, side := range []string{"-wal", "-shm"} {
		os.Remove(path + side)
	}
	if _, err := readTailDB(path, ""); err != nil {
		t.Fatalf("stopped writer: %v", err)
	}
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + side); err == nil {
			t.Errorf("the reader created %s beside Fluent Bit's database", side)
		}
	}

	// The private-copy fallback reads the same rows.
	copyDir := filepath.Join(t.TempDir(), "copy")
	rows, err = queryCopy(path, copyDir)
	if err != nil || len(rows) != 3 {
		t.Fatalf("copy: %v %+v", err, rows)
	}
	if ents, _ := os.ReadDir(copyDir); len(ents) != 0 {
		t.Errorf("copy left %d entries behind", len(ents))
	}

	// Not a database, too large, missing.
	junk := filepath.Join(dir, "junk.db")
	os.WriteFile(junk, []byte("not sqlite"), 0o600)
	if _, err := readTailDB(junk, ""); err == nil {
		t.Error("junk read as a tail database")
	}
	if _, err := readTailDB(filepath.Join(dir, "missing.db"), ""); err == nil {
		t.Error("missing database read")
	}
	if _, err := readTailDB(dir, ""); err == nil {
		t.Error("a directory read as a database")
	}
}

func TestTailDBConsumersSpec(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"spoor-findings.db", "spoor-activity.db"} {
		makeTailDB(t, filepath.Join(dir, n), nil).Close()
	}
	got := tailDBConsumers(" "+filepath.Join(dir, "spoor-*.db")+" , "+filepath.Join(dir, "extra.db")+",,", "")
	if len(got) != 3 {
		t.Fatalf("consumers = %d", len(got))
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[c.id()] = true
	}
	for _, n := range []string{"spoor-findings.db", "spoor-activity.db", "extra.db"} {
		if !ids["fluent-bit:"+filepath.Join(dir, n)] {
			t.Errorf("missing consumer for %s: %v", n, ids)
		}
	}
	if got := tailDBConsumers("", ""); len(got) != 0 {
		t.Errorf("empty spec gave %d consumers", len(got))
	}
	// A pattern with no match stays a (failing) consumer, so the pruner is
	// conservative until Fluent Bit creates the file.
	got = tailDBConsumers(filepath.Join(dir, "nope-*.db"), "")
	if len(got) != 1 {
		t.Fatalf("unmatched pattern: %d consumers", len(got))
	}
	if _, err := got[0].view(); err == nil {
		t.Error("an unmatched pattern read successfully")
	}
}

func TestShipperConsumer(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "shipper-otlp.checkpoint")
	c := &shipperConsumer{name: "otlp", path: cp}
	v, err := c.view()
	if err != nil || !v.all || len(v.files) != 0 {
		t.Fatalf("missing checkpoint: %+v %v", v, err)
	}
	os.WriteFile(cp, []byte(`{"v":1,"files":{"detection-20261112-05-0000.ndjson":{"off":42,"fp":"ab","fpn":10},"../etc/passwd":{"off":1}}}`), 0o600)
	v, err = c.view()
	if err != nil || len(v.files) != 1 || v.files["detection-20261112-05-0000.ndjson"].off != 42 {
		t.Fatalf("view = %+v %v", v, err)
	}
	os.WriteFile(cp, []byte(`{"v":2}`), 0o600)
	if _, err := c.view(); err == nil {
		t.Error("an unknown checkpoint version was accepted")
	}
}

func TestConsumerKey(t *testing.T) {
	for in, want := range map[string]string{
		"fluent-bit:/var/lib/fluent-bit/spoor-findings.db": "fluent-bit.spoor-findings",
		`fluent-bit:C:\fb\Spoor Activity.db`:               "fluent-bit.spoor_activity",
		"shipper:otlp":                                     "shipper.otlp",
		"fake:":                                            "fake",
	} {
		if got := consumerKey(in); got != want {
			t.Errorf("consumerKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPruneEmptyTailDBReadsNothing: the shipped Fluent Bit configuration has
// one tail input and one database per stream group (spoor-findings.db,
// spoor-activity.db; output.fluent_bit.tail_db names both with a glob).
// Under the minimal profile no activity segment is ever written, so the
// activity database never lists a file. It must not count as a consumer of
// every stream: detections Fluent Bit read to the end are pruned by age,
// shipper_lag_bytes is what is unread, and the cap does not report shipped
// data as outbox.dropped_unshipped.
func TestPruneEmptyTailDBReadsNothing(t *testing.T) {
	o := newOutboxFixture(t)
	old, oldSize := o.seg("detection", 300, 0, 3, 1)
	recent, recentSize := o.seg("detection", 3, 0, 3, 4)
	newest, newestSize := o.seg("detection", 0, 0, 1, 7)
	ino := func(n string) uint64 {
		p := filepath.Join(o.dir, n)
		return inodeOf(mustLstat(t, p), p)
	}
	fb := t.TempDir()
	makeTailDB(t, filepath.Join(fb, "spoor-findings.db"), []tailRow{
		{name: "/var/lib/spoor/outbox/" + old, offset: oldSize, inode: ino(old)},
		{name: "/var/lib/spoor/outbox/" + recent, offset: recentSize, inode: ino(recent)},
		{name: "/var/lib/spoor/outbox/" + newest, offset: newestSize, inode: ino(newest)},
	}).Close()
	makeTailDB(t, filepath.Join(fb, "spoor-activity.db"), nil).Close()
	spec := filepath.Join(fb, "spoor-*.db")
	p := newOutboxPruner(pruneOptions{
		dir: o.dir, maxAge: 7 * 24 * time.Hour,
		consumers: func() []consumer { return tailDBConsumers(spec, "") },
		statePath: filepath.Join(t.TempDir(), "covered.json"),
	})
	res := p.prune(o.now)
	if o.exists(old) {
		t.Errorf("a 300 h old detection segment Fluent Bit read to the end was not pruned by age (unread_past_age=%d)", res.unreadOld)
	}
	if res.lag != 0 || res.consumerLag["fluent-bit:"+filepath.Join(fb, "spoor-activity.db")] != 0 {
		t.Errorf("shipper_lag_bytes = %d (per consumer %v) with every byte read by the only input that tails detections, want 0", res.lag, res.consumerLag)
	}
	// The cap removes data Fluent Bit has read without reporting a loss ...
	p.o.maxBytes = newestSize + 1
	res = p.prune(o.now)
	if o.exists(recent) || res.unread.bytes != 0 || res.removedCap != 1 {
		t.Errorf("the cap reported %d bytes Fluent Bit had read as outbox.dropped_unshipped (removed by cap %d)", res.unread.bytes, res.removedCap)
	}
	// ... and reports what it has not read.
	o.seg("detection", 2, 0, 2, 8)
	res = p.prune(o.now)
	if res.unread.bytes == 0 || res.unread.events != 2 {
		t.Errorf("the cap removed an unread detection segment without reporting it: %+v", res.unread)
	}
	// Activity appears (the profile was raised): the activity database
	// lists it, and from then on it holds activity back until read.
	act, _ := o.seg("activity", 300, 0, 2, 1)
	o.seg("activity", 0, 0, 1, 3)
	makeTailDB(t, filepath.Join(fb, "spoor-activity2.db"), []tailRow{{name: "/x/" + act, offset: 1, inode: ino(act)}}).Close()
	p.o.maxBytes = 0
	p.prune(o.now)
	if !o.exists(act) {
		t.Error("an activity segment its database has not read to the end was pruned by age")
	}

	// A database that cannot be read and has never listed anything still
	// holds every stream back.
	o2 := newOutboxFixture(t)
	old2, _ := o2.seg("detection", 300, 0, 3, 1)
	o2.seg("detection", 0, 0, 1, 4)
	p2 := newOutboxPruner(pruneOptions{
		dir: o2.dir, maxAge: 7 * 24 * time.Hour,
		consumers: func() []consumer { return tailDBConsumers(filepath.Join(t.TempDir(), "spoor-*.db"), "") },
	})
	p2.prune(o2.now)
	if !o2.exists(old2) {
		t.Error("a tail database that does not exist yet must hold segments back")
	}
}

// TestTailDBDuplicateNamePicksInodeOnDisk: two rows for one segment name (an
// older file of that name Fluent Bit has not cleaned up, and the current
// one) are told apart by inode; the stale row's larger offset must not
// count, nor hide that the current file was read to the end.
func TestTailDBDuplicateNamePicksInodeOnDisk(t *testing.T) {
	o := newOutboxFixture(t)
	old, oldSize := o.seg("detection", 300, 0, 3, 1)
	mid, midSize := o.seg("detection", 200, 0, 3, 4)
	o.seg("detection", 0, 0, 1, 7)
	ino := func(n string) uint64 {
		p := filepath.Join(o.dir, n)
		return inodeOf(mustLstat(t, p), p)
	}
	fb := filepath.Join(t.TempDir(), "spoor-findings.db")
	makeTailDB(t, fb, []tailRow{
		{name: "/var/lib/spoor/outbox/" + old, offset: oldSize, inode: ino(old)},                // the file on disk, read to the end
		{name: "/var/lib/spoor/outbox/" + old, offset: oldSize + 4096, inode: ino(old) + 12345}, // a previous file of that name
		{name: "/var/lib/spoor/outbox/" + mid, offset: midSize + 4096, inode: ino(mid) + 12345}, // only a previous file of that name
		{name: "/elsewhere/" + mid, offset: midSize / 2, inode: ino(mid) + 999},                 // same name in another directory
	}).Close()
	pr := newOutboxPruner(pruneOptions{
		dir: o.dir, maxAge: 7 * 24 * time.Hour,
		consumers: func() []consumer { return tailDBConsumers(fb, "") },
	})
	res := pr.prune(o.now)
	if o.exists(old) {
		t.Error("a segment whose current inode row shows it read to the end was kept as unread")
	}
	if !o.exists(mid) || res.unreadOld != 1 {
		t.Errorf("a segment with rows only for other inodes was taken as read (unreadOld %d)", res.unreadOld)
	}
}

func TestReadOffset(t *testing.T) {
	s := &outSeg{name: "detection-20261112-05-0000.ndjson", size: 100, inode: 7}
	for _, tc := range []struct {
		name  string
		files map[string]readPos
		more  map[string][]readPos
		want  int64
	}{
		{"none", nil, nil, 0},
		{"exact", map[string]readPos{s.name: {off: 60, inode: 7}}, nil, 60},
		{"other inode only", map[string]readPos{s.name: {off: 100, inode: 8}}, nil, 0},
		{"exact wins over larger stale", map[string]readPos{s.name: {off: 100, inode: 8}}, map[string][]readPos{s.name: {{off: 40, inode: 7}}}, 40},
		{"exact wins over smaller stale", map[string]readPos{s.name: {off: 10, inode: 8}}, map[string][]readPos{s.name: {{off: 90, inode: 7}}}, 90},
		{"unknown inodes: the least", map[string]readPos{s.name: {off: 80}}, map[string][]readPos{s.name: {{off: 30}}}, 30},
		{"clamped", map[string]readPos{s.name: {off: 500, inode: 7}}, nil, 100},
		{"negative", map[string]readPos{s.name: {off: -5, inode: 7}}, nil, 0},
	} {
		v := consumerView{files: tc.files, more: tc.more}
		if got := v.readOffset(s); got != tc.want {
			t.Errorf("%s: readOffset = %d, want %d", tc.name, got, tc.want)
		}
	}
}
