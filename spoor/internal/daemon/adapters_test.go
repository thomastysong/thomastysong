package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
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

func TestReadCompleteLine(t *testing.T) {
	data := "short\n" + strings.Repeat("x", 100) + "\npartial"
	br := bufio.NewReaderSize(bytes.NewReader([]byte(data)), 16)
	line, n, ok := readCompleteLine(br, 10)
	if !ok || string(line) != "short" || n != 6 {
		t.Fatalf("1: %q %d %v", line, n, ok)
	}
	line, n, ok = readCompleteLine(br, 10)
	if !ok || len(line) != 10 || n != 101 {
		t.Fatalf("2: %d %d %v", len(line), n, ok)
	}
	if _, _, ok = readCompleteLine(br, 10); ok {
		t.Fatal("a line without LF was returned")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
