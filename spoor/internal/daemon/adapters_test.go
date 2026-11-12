package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/adapter"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// numbatLine returns a fixture of the numbat adapter as one NDJSON line.
func numbatLine(t *testing.T, name string, edit func(map[string]any)) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "adapter", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	out, _ := json.Marshal(m)
	return string(out) + "\n"
}

func TestAdapterRunner(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.root, "numbat")
	mustMkdir(t, dir, 0o755)
	log := filepath.Join(dir, "events.ndjson")
	f.cfg.Sources.Adapters = []config.AdapterSource{{Format: "numbat", Paths: []string{filepath.Join(dir, "*.ndjson"), "relative/*.ndjson"}}}
	before := numbatLine(t, "numbat_event_hook_network.json", func(m map[string]any) { m["session_id"] = "before" })
	mustWrite(t, log, before, 0o600)

	d, out := f.unitDaemon()
	r := newAdapterRunner(d)
	r.step() // first sight: end of file
	after := numbatLine(t, "numbat_event_hook_network.json", func(m map[string]any) { m["session_id"] = "after" })
	appendFile(t, log, after)
	appendFile(t, log, `{"record_type":"event","schema_version":"9.0.0","run_id":"r"}`+"\n")
	appendFile(t, log, "not json\n")
	appendFile(t, log, `{"partial":`) // no newline yet: left for the next pass
	r.step()
	r.step()
	d.pipe.Close()

	sessions := map[string]bool{}
	for _, e := range out.all() {
		if e.Session != nil {
			sessions[e.Session.ID] = true
		}
		if e.Source == event.SourceAdapter && e.Kind == event.KindActivity {
			if e.User == nil || e.User.ID != f.user.UID && currentUID() != "0" {
				t.Errorf("adapter record user = %+v, want the file owner", e.User)
			}
		}
	}
	if sessions["before"] {
		t.Error("a record that existed at first sight was read")
	}
	if !sessions["after"] {
		t.Errorf("an appended record was not read: %v", sessions)
	}
	if d.board.get("adapter.numbat.version") != 1 || d.board.get("adapter.numbat.malformed") != 1 {
		t.Errorf("errors: %v", d.board.counters())
	}
	surf := d.board.surfaces()
	if len(surf) != 1 || !surf[0].SchemaDrift || surf[0].Errors != 2 {
		t.Errorf("surface = %+v", surf)
	}
	// The checkpoint survives a restart and stops before the partial line.
	b, err := os.ReadFile(filepath.Join(d.layout.check, "adapters.json"))
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(log)
	if !strings.Contains(string(b), `"off":`+itoa(fi.Size()-int64(len(`{"partial":`)))) {
		t.Errorf("checkpoint %s does not stop before the partial line (size %d)", b, fi.Size())
	}
}

func TestAdapterRunnerRefusesLinksAndResets(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.root, "numbat")
	mustMkdir(t, dir, 0o755)
	f.cfg.Sources.Adapters = []config.AdapterSource{{Format: "numbat", Paths: []string{filepath.Join(dir, "*.ndjson")}}}
	d, out := f.unitDaemon()
	if runtime.GOOS != "windows" {
		target := filepath.Join(t.TempDir(), "shadow")
		os.WriteFile(target, []byte("x\n"), 0o600)
		if err := os.Symlink(target, filepath.Join(dir, "link.ndjson")); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "a.ndjson")
	mustWrite(t, log, "", 0o600)
	r := newAdapterRunner(d)
	r.step()
	if runtime.GOOS != "windows" && d.board.get("adapter.refused") == 0 {
		t.Error("a symlinked log was not refused")
	}
	f.off.Store(true)
	r.step()
	appendFile(t, log, numbatLine(t, "numbat_event_hook_network.json", func(m map[string]any) { m["session_id"] = "during-off" }))
	f.off.Store(false)
	r.step() // reset: starts at the current end
	appendFile(t, log, numbatLine(t, "numbat_event_hook_network.json", func(m map[string]any) { m["session_id"] = "after-on" }))
	time.Sleep(releaseSettle)
	r.step()
	d.pipe.Close()
	got := map[string]bool{}
	for _, e := range out.all() {
		if e.Session != nil {
			got[e.Session.ID] = true
		}
	}
	if got["during-off"] || !got["after-on"] {
		t.Errorf("sessions = %v", got)
	}
}

func TestNextLine(t *testing.T) {
	data := "short\n" + strings.Repeat("x", 100) + "\npartial"
	br := bufio.NewReaderSize(bytes.NewReader([]byte(data)), 16)
	line, n, st := nextLine(br, 10)
	if st != lineComplete || string(line) != "short" || n != 6 {
		t.Fatalf("1: %q %d %v", line, n, st)
	}
	line, n, st = nextLine(br, 10)
	if st != lineComplete || len(line) != 10 || n != 101 {
		t.Fatalf("2: %d %d %v", len(line), n, st)
	}
	if _, n, st = nextLine(br, 10); st != lineIncomplete || n != 0 {
		t.Fatalf("a line without LF was returned: %d %v", n, st)
	}
	// No LF and already over the limit: consumed as oversize, then the
	// rest of the line is discarded up to its LF.
	br = bufio.NewReaderSize(bytes.NewReader([]byte(strings.Repeat("y", 50))), 16)
	if _, n, st = nextLine(br, 10); st != lineOversize || n != 50 {
		t.Fatalf("oversize partial: %d %v", n, st)
	}
	br = bufio.NewReaderSize(bytes.NewReader([]byte(strings.Repeat("z", 40)+"\nnext\n")), 16)
	if n, found := discardLine(br); !found || n != 41 {
		t.Fatalf("discardLine = %d %v", n, found)
	}
	if line, _, st = nextLine(br, 10); st != lineComplete || string(line) != "next" {
		t.Fatalf("after discard: %q %v", line, st)
	}
	if n, found := discardLine(bufio.NewReader(bytes.NewReader([]byte("abc")))); found || n != 3 {
		t.Fatalf("discardLine at EOF = %d %v", n, found)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// adapterFixture is a numbat directory followed by an adapter runner.
type adapterFixture struct {
	t   *testing.T
	f   *fixture
	dir string
	d   *daemon
	out *captureSink
	r   *adapterRunner
}

func newAdapterFixture(t *testing.T, pattern string) *adapterFixture {
	t.Helper()
	f := newFixture(t)
	dir := filepath.Join(f.root, "numbat")
	mustMkdir(t, dir, 0o755)
	f.cfg.Sources.Adapters = []config.AdapterSource{{Format: "numbat", Paths: []string{filepath.Join(dir, pattern)}}}
	d, out := f.unitDaemon()
	return &adapterFixture{t: t, f: f, dir: dir, d: d, out: out, r: newAdapterRunner(d)}
}

// rec is one numbat record whose session id names it.
func (a *adapterFixture) rec(name string) string {
	return numbatLine(a.t, "numbat_event_hook_network.json", func(m map[string]any) { m["session_id"] = name })
}

func (a *adapterFixture) path(name string) string { return filepath.Join(a.dir, name) }

// counts closes the pipeline and returns how many activity events each
// record produced.
func (a *adapterFixture) counts() map[string]int {
	a.t.Helper()
	if err := a.d.pipe.Close(); err != nil {
		a.t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range a.out.all() {
		if e.Session != nil && e.Kind == event.KindActivity {
			got[e.Session.ID]++
		}
	}
	return got
}

// TestAdapterNewFileReadFromStart: only files that exist when their pattern
// is first looked at start at their end. A file created after the daemon
// started (the other sensor starting later, a date-named rotation) is read
// from its first record.
func TestAdapterNewFileReadFromStart(t *testing.T) {
	a := newAdapterFixture(t, "*.ndjson")
	a.r.step() // daemon start: numbat has not written anything yet
	log := a.path("events-20261112.ndjson")
	mustWrite(t, log, a.rec("first"), 0o600)
	a.r.step()
	appendFile(t, log, a.rec("second"))
	a.r.step()
	got := a.counts()
	if got["second"] == 0 {
		t.Fatalf("fixture: appended record not read: %v", got)
	}
	if got["first"] != got["second"] {
		t.Errorf("the first record of an adapter file created after the daemon started was not read once: %v", got)
	}
}

// TestAdapterRestart: the admitted patterns are remembered with the
// checkpoints. After a restart, a file written while the daemon was down is
// read from its first record; a file whose content is older than the
// pattern's admission (moved in from elsewhere) starts at its end.
func TestAdapterRestart(t *testing.T) {
	a := newAdapterFixture(t, "*.ndjson")
	pre := a.path("pre.ndjson")
	mustWrite(t, pre, a.rec("pre-existing"), 0o600)
	a.r.step()
	appendFile(t, pre, a.rec("pre-after"))
	a.r.step()

	// Down: a new file is written, an old one is moved in.
	mustWrite(t, a.path("down.ndjson"), a.rec("while-down"), 0o600)
	moved := a.path("moved.ndjson")
	mustWrite(t, moved, a.rec("moved-old"), 0o600)
	past := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(moved, past, past); err != nil {
		t.Fatal(err)
	}
	r2 := newAdapterRunner(a.d)
	r2.step()
	appendFile(t, moved, a.rec("moved-new"))
	r2.step()
	got := a.counts()
	for id, want := range map[string]bool{
		"pre-existing": false, "pre-after": true, "while-down": true, "moved-old": false, "moved-new": true,
	} {
		if (got[id] > 0) != want {
			t.Errorf("%s read = %v, want %v (%v)", id, got[id] > 0, want, got)
		}
	}
}

// TestAdapterRotation: a rename rotation whose new name the pattern also
// matches continues from the checkpoint (the tail written before the
// rotation is read, nothing twice), and the new file under the old name is
// read from its start, also when it appears a pass later.
func TestAdapterRotation(t *testing.T) {
	a := newAdapterFixture(t, "events.ndjson*")
	log := a.path("events.ndjson")
	mustWrite(t, log, a.rec("r0"), 0o600)
	a.r.step() // first sight: end
	appendFile(t, log, a.rec("r1"))
	a.r.step()
	appendFile(t, log, a.rec("r2")) // written just before the rotation
	if err := os.Rename(log, a.path("events.ndjson.1")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, log, a.rec("r3"), 0o600)
	a.r.step()
	appendFile(t, a.path("events.ndjson.1"), a.rec("r4")) // a late write to the rotated file
	// Second rotation with a gap: the name is missing for a pass.
	if err := os.Rename(log, a.path("events.ndjson.2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(a.path("events.ndjson.2"), filepath.Join(t.TempDir(), "archived")); err != nil {
		t.Fatal(err)
	}
	a.r.step()
	mustWrite(t, log, a.rec("r5"), 0o600)
	a.r.step()
	got := a.counts()
	one := got["r1"]
	if one == 0 {
		t.Fatalf("fixture: nothing read: %v", got)
	}
	if got["r0"] != 0 {
		t.Errorf("a record that existed at first sight was read: %v", got)
	}
	for _, id := range []string{"r2", "r3", "r4", "r5"} {
		if got[id] != one {
			t.Errorf("%s produced %d events, want %d (read exactly once): %v", id, got[id], one, got)
		}
	}
}

// TestAdapterInodeReuseNotARename: a new file that was given the inode of a
// file followed under another name is told apart by the fingerprint of its
// first bytes and read from its start, not from the old file's offset.
func TestAdapterInodeReuseNotARename(t *testing.T) {
	a := newAdapterFixture(t, "*.ndjson")
	a.r.step()
	nf := a.path("new.ndjson")
	content := a.rec("reused-inode")
	mustWrite(t, nf, content, 0o600)
	fh, err := os.Open(nf)
	if err != nil {
		t.Fatal(err)
	}
	id, err := platform.FileIDOf(fh)
	fh.Close()
	if err != nil || id == "" {
		t.Skip("no file ids here")
	}
	// The previous pass followed a deleted file with that id.
	a.r.ck[a.path("gone.ndjson")] = adCkpt{ID: id, Off: int64(len(content)), FP: "00000000000000000000000000000000", FPN: 16}
	a.r.step()
	if got := a.counts(); got["reused-inode"] == 0 {
		t.Errorf("a new file with a reused inode was taken for a rename and skipped: %v", got)
	}
}

// TestAdapterAdmissionCoarseClock is the regression test for a flake of
// TestAdapterHardLinkReadOnce (1 run in 200: map[control:2 linked:2], the
// first record of a new file lost). The kernel stamps mtime from a coarse
// clock that trails time.Now by a few milliseconds, and a pattern's
// admission is kept in whole seconds: a pattern admitted in the first
// milliseconds of a second and a file created right after it got an mtime
// in the previous second and was taken for content older than the
// admission. Simulated here deterministically with that mtime.
func TestAdapterAdmissionCoarseClock(t *testing.T) {
	a := newAdapterFixture(t, "*.ndjson")
	a.r.step() // admits the pattern
	var admitted int64
	for _, at := range a.r.pats {
		admitted = at
	}
	if admitted == 0 {
		t.Fatal("pattern not admitted")
	}
	fresh := a.path("fresh.ndjson")
	mustWrite(t, fresh, a.rec("just-after"), 0o600)
	// The coarse clock was 1 ms behind the second admission was taken in.
	lag := time.Unix(admitted, 0).Add(-time.Millisecond)
	if err := os.Chtimes(fresh, lag, lag); err != nil {
		t.Fatal(err)
	}
	old := a.path("moved.ndjson")
	mustWrite(t, old, a.rec("moved-in-old"), 0o600)
	past := time.Unix(admitted-admitSlack-1, 0)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	a.r.step()
	got := a.counts()
	if got["just-after"] == 0 {
		t.Errorf("a file written right after admission, its mtime a tick behind, was skipped: %v", got)
	}
	if got["moved-in-old"] != 0 {
		t.Errorf("content older than the admission was collected: %v", got)
	}
}

// TestAdapterHardLinkReadOnce: two names of one file are read once.
func TestAdapterHardLinkReadOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links need privileges on some Windows file systems")
	}
	a := newAdapterFixture(t, "*.ndjson")
	a.r.step()
	log := a.path("b.ndjson")
	mustWrite(t, log, a.rec("early"), 0o600)
	mustWrite(t, a.path("c.ndjson"), a.rec("control"), 0o600)
	a.r.step() // b and c are new: read from their start
	// A second name for b, sorted before it.
	if err := os.Link(log, a.path("a.ndjson")); err != nil {
		t.Skip(err)
	}
	appendFile(t, log, a.rec("linked"))
	a.r.step()
	a.r.step()
	got := a.counts()
	if got["control"] == 0 || got["early"] != got["control"] || got["linked"] != got["control"] {
		t.Errorf("a file with two names was not read exactly once: %v", got)
	}
	if _, ok := a.r.ck[log]; !ok {
		t.Errorf("the file is no longer followed under its first name: %v", a.r.ck)
	}
}

// TestAdapterUnterminatedLineBounded: one pass reads at most
// maxAdapterPerPoll bytes of a file, counting a line that has no LF yet. A
// user-owned adapter file whose tail never ends its line must not be read
// in full on every pass.
func TestAdapterUnterminatedLineBounded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc/self/io")
	}
	a := newAdapterFixture(t, "*.ndjson")
	defer a.d.pipe.Close()
	log := a.path("events.ndjson")
	mustWrite(t, log, "", 0o600)
	a.r.step() // first sight: offset 0
	const size = 256 << 20
	if err := os.Truncate(log, size); err != nil { // 256 MiB of NULs, no LF
		t.Fatal(err)
	}
	before := rchar(t)
	a.r.step()
	a.r.step()
	delta := rchar(t) - before
	if limit := uint64(2*maxAdapterPerPoll + 8<<20); delta > limit {
		t.Errorf("two passes read %d MiB from one adapter file; maxAdapterPerPoll promises at most %d MiB per pass", delta>>20, maxAdapterPerPoll>>20)
	}
	if c := a.r.ck[log]; !c.Skip || c.Off != 2*maxAdapterPerPoll {
		t.Errorf("checkpoint = %+v, want skipping at %d", c, 2*maxAdapterPerPoll)
	}
}

// TestAdapterOversizePartialSkipped: a partial line already longer than the
// adapter's limit is consumed and the rest of it discarded when its LF
// comes; the next record is read.
func TestAdapterOversizePartialSkipped(t *testing.T) {
	a := newAdapterFixture(t, "*.ndjson")
	log := a.path("events.ndjson")
	mustWrite(t, log, "", 0o600)
	a.r.step()
	if err := os.Truncate(log, int64(adapter.MaxNumbatLine)+(1<<20)); err != nil {
		t.Fatal(err)
	}
	a.r.step() // oversize with no LF: consumed, skipping
	if c := a.r.ck[log]; !c.Skip {
		t.Fatalf("checkpoint = %+v, want skipping", c)
	}
	appendFile(t, log, strings.Repeat("x", 100)+"\n"+a.rec("after-oversize"))
	a.r.step()
	if a.d.board.get("adapter.numbat.too_large") != 1 {
		t.Errorf("too_large = %d", a.d.board.get("adapter.numbat.too_large"))
	}
	if got := a.counts(); got["after-oversize"] == 0 {
		t.Errorf("the record after an oversize line was not read: %v", got)
	}
}

func rchar(t *testing.T) uint64 {
	t.Helper()
	fh, err := os.Open("/proc/self/io")
	if err != nil {
		t.Skip(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "rchar: "); ok {
			n, _ := strconv.ParseUint(v, 10, 64)
			return n
		}
	}
	t.Skip("no rchar")
	return 0
}
