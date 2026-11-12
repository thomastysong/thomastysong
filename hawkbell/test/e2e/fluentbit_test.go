//go:build e2e

// Package e2e runs hawkbell's shipped deployment content against real
// software. These tests need Docker and the fluent/fluent-bit image and are
// gated by the e2e build tag plus HAWKBELL_E2E_FLUENTBIT=1:
//
//	HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -v
//
// Each test reproduces one transport failure found in the design review
// (docs/ASSUMPTIONS.md, "Transport") and checks that the shipped
// configuration in deploy/fluent-bit does not have it.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
)

const image = "fluent/fluent-bit:latest"

func repoRoot(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func requireFluentBit(t *testing.T) {
	t.Helper()
	if os.Getenv("HAWKBELL_E2E_FLUENTBIT") == "" {
		t.Skip("set HAWKBELL_E2E_FLUENTBIT=1 (needs docker and " + image + ")")
	}
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		t.Skipf("image %s not available: %v", image, err)
	}
}

// receiver is an HTTP sink Fluent Bit's http output posts json_lines to.
type receiver struct {
	mu     sync.Mutex
	ids    map[string]int
	tags   map[string]string // id -> tag header
	dates  map[string]float64
	status int
	srv    *http.Server
	ln     net.Listener
	posts  int
	extra  map[string]map[string]any
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func newReceiver() *receiver {
	return &receiver{ids: map[string]int{}, tags: map[string]string{}, dates: map[string]float64{}, extra: map[string]map[string]any{}, status: 200}
}

func (r *receiver) start(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	r.ln = ln
	r.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.posts++
		if r.status != 200 {
			w.WriteHeader(r.status)
			return
		}
		sc := bufio.NewScanner(req.Body)
		sc.Buffer(make([]byte, 4<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			id, _ := m["id"].(string)
			if id == "" {
				if l, ok := m["log"].(string); ok {
					id = "parse_error:" + l
				}
			}
			r.ids[id]++
			r.tags[id] = req.Header.Get("X-Tag")
			if d, ok := m["date"].(float64); ok {
				r.dates[id] = d
			}
			r.extra[id] = m
		}
		w.WriteHeader(200)
	})}
	go r.srv.Serve(ln)
}

func (r *receiver) stop() {
	if r.srv != nil {
		r.srv.Close()
	}
}

func (r *receiver) unique() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ids)
}

// fluentBit runs the image with the shipped input fragment and a test
// output config.
type fluentBit struct {
	t      *testing.T
	name   string
	cfg    string
	outbox string
	state  string
}

func newFluentBit(t *testing.T, outputs string, memoryBuffering bool) *fluentBit {
	t.Helper()
	root := repoRoot(t)
	cfg := t.TempDir()
	inputs, err := os.ReadFile(filepath.Join(root, "deploy", "fluent-bit", "hawkbell-inputs.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if memoryBuffering {
		// The failing default this configuration exists to avoid.
		inputs = bytes.ReplaceAll(inputs, []byte("storage.type: filesystem"), []byte("storage.type: memory"))
	}
	os.WriteFile(filepath.Join(cfg, "hawkbell-inputs.yaml"), inputs, 0o644)
	main := `service:
  flush: 1
  grace: 2
  log_level: info
  storage.path: /state/storage
  storage.sync: normal
  storage.keep.rejected: on
  storage.rejected.path: rejected
  scheduler.base: 1
  scheduler.cap: 2
includes:
  - hawkbell-inputs.yaml
  - outputs.yaml
`
	os.WriteFile(filepath.Join(cfg, "main.yaml"), []byte(main), 0o644)
	os.WriteFile(filepath.Join(cfg, "outputs.yaml"), []byte(outputs), 0o644)
	fb := &fluentBit{t: t, name: fmt.Sprintf("hawkbell-e2e-%d", time.Now().UnixNano()), cfg: cfg, outbox: t.TempDir(), state: t.TempDir()}
	os.Chmod(fb.outbox, 0o755)
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", fb.name).Run() })
	return fb
}

func (fb *fluentBit) start() {
	fb.t.Helper()
	exec.Command("docker", "rm", "-f", fb.name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", fb.name, "--network", "host",
		"-v", fb.cfg+":/cfg:ro", "-v", fb.outbox+":/outbox:ro", "-v", fb.state+":/state",
		"-e", "HAWKBELL_OUTBOX=/outbox", "-e", "HAWKBELL_FLB_DB=/state",
		image, "/fluent-bit/bin/fluent-bit", "-c", "/cfg/main.yaml").CombinedOutput()
	if err != nil {
		fb.t.Fatalf("docker run: %v %s", err, out)
	}
}

func (fb *fluentBit) kill(graceful bool) {
	if graceful {
		exec.Command("docker", "stop", "-t", "10", fb.name).Run()
	} else {
		exec.Command("docker", "kill", "-s", "KILL", fb.name).Run()
	}
	exec.Command("docker", "rm", "-f", fb.name).Run()
}

func (fb *fluentBit) logs() string {
	out, _ := exec.Command("docker", "logs", fb.name).CombinedOutput()
	return string(out)
}

// readAll waits until the tail database says every outbox file was read.
func (fb *fluentBit) waitRead(timeout time.Duration) {
	fb.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fb.allRead() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	fb.t.Fatalf("fluent-bit did not read the outbox within %v\n%s", timeout, fb.logs())
}

func (fb *fluentBit) allRead() bool {
	files, _ := filepath.Glob(filepath.Join(fb.outbox, "*.ndjson"))
	want := map[string]int64{}
	for _, f := range files {
		fi, err := os.Stat(f)
		if err == nil {
			want["/outbox/"+filepath.Base(f)] = fi.Size()
		}
	}
	got := map[string]int64{}
	dbs, _ := filepath.Glob(filepath.Join(fb.state, "hawkbell-*.db"))
	for _, p := range dbs {
		db, err := sql.Open("sqlite", "file:"+p+"?mode=ro")
		if err != nil {
			continue
		}
		rows, err := db.Query("select name, offset from in_tail_files")
		if err == nil {
			for rows.Next() {
				var n string
				var off int64
				rows.Scan(&n, &off)
				got[n] = off
			}
			rows.Close()
		}
		db.Close()
	}
	for n, size := range want {
		if got[n] < size {
			return false
		}
	}
	return len(want) > 0
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", msg())
}

func httpOutput(alias, match string, port int) string {
	return fmt.Sprintf(`  - name: http
    alias: %s
    %s
    host: 127.0.0.1
    port: %d
    uri: /
    format: json_lines
    json_date_key: date
    json_date_format: double
    header_tag: X-Tag
    retry_limit: no_limits
    storage.total_limit_size: 256M
`, alias, match, port)
}

func writeEvents(t *testing.T, dir string, evs []*event.Event) {
	t.Helper()
	s, err := sink.NewFiles(sink.FilesOptions{Dir: dir, FileMode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(evs); i += 500 {
		end := min(i+500, len(evs))
		if err := s.Write(evs[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func mkEvent(kind event.Kind, i int, ts time.Time) *event.Event {
	e := event.New(kind, "x", event.SourceSensor)
	e.TS = event.At(ts)
	e.ID = event.StableID(ts, string(kind), fmt.Sprint(i))
	switch kind {
	case event.KindActivity:
		e.Type = event.TypeToolPre
		e.Target = &event.Target{Command: fmt.Sprintf("echo %d", i)}
	case event.KindDetection:
		e.Type = event.TypeDetectionFinding
		e.Detection = &event.Detection{RuleID: "HB-TEST-001", Title: "t", Severity: event.SevHigh}
	case event.KindHealth:
		e.Type = event.TypeHealthHeartbeat
		e.Health = &event.Health{SensorVersion: "test", Mode: "daemon"}
	case event.KindSummary:
		e.Type = event.TypeSessionSummary
		e.Summary = &event.Summary{Events: 3}
	case event.KindPosture:
		e.Type = event.TypePostureCheck
		e.Check = &event.Check{ID: "HB-POSTURE-001", Status: "fail"}
	case event.KindInventory:
		e.Type = event.TypeInventoryAsset
		e.Asset = &event.Asset{ID: "a", Kind: event.AssetAgent, Name: "claude-code"}
	}
	return e
}

// TestFluentBitStreamsTagsAndTime: every stream arrives tagged
// hawkbell.<stream> with the record's own timestamp as event time.
func TestFluentBitStreamsTagsAndTime(t *testing.T) {
	requireFluentBit(t)
	port := freePort(t)
	rcv := newReceiver()
	rcv.start(t, port)
	defer rcv.stop()
	fb := newFluentBit(t, "pipeline:\n  outputs:\n"+httpOutput("all", "match: 'hawkbell.*'", port), false)
	base := time.Date(2026, 11, 11, 10, 0, 3, 0, time.UTC) // whole second: the fraction must still be written
	var evs []*event.Event
	kinds := []event.Kind{event.KindActivity, event.KindDetection, event.KindHealth, event.KindSummary, event.KindPosture, event.KindInventory}
	for i, k := range kinds {
		evs = append(evs, mkEvent(k, i, base.Add(time.Duration(i)*time.Second)))
	}
	writeEvents(t, fb.outbox, evs)
	// A line that is not JSON must surface on its own tag, not vanish.
	f, _ := os.OpenFile(mustGlob(t, filepath.Join(fb.outbox, "detection-*.ndjson")), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json at all\n")
	f.Close()
	fb.start()
	waitFor(t, 60*time.Second, func() bool { return rcv.unique() >= len(evs)+1 }, func() string { return fmt.Sprintf("%d records\n%s", rcv.unique(), fb.logs()) })
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	for i, e := range evs {
		if tag := rcv.tags[e.ID]; tag != "hawkbell."+string(kinds[i]) {
			t.Errorf("%s: tag %q", kinds[i], tag)
		}
		want := float64(e.TS.UnixNano()) / 1e9
		if d := rcv.dates[e.ID]; d < want-0.001 || d > want+0.001 {
			t.Errorf("%s: event time %f, want %f (ingestion time used?)", kinds[i], d, want)
		}
	}
	if rcv.tags["parse_error:not json at all"] != "hawkbell.parse_error" {
		t.Errorf("unparsable line not routed to hawkbell.parse_error: %v", rcv.tags)
	}
}

func mustGlob(t *testing.T, p string) string {
	m, _ := filepath.Glob(p)
	if len(m) == 0 {
		t.Fatalf("no file matches %s", p)
	}
	return m[0]
}

// TestFluentBitRestartWithOutputDown: the destination is unreachable, Fluent
// Bit reads 5,000 records and is killed (SIGKILL, and separately a graceful
// stop), the destination comes back, Fluent Bit restarts. With the shipped
// filesystem buffering all 5,000 arrive. The control run with memory
// buffering shows the loss this configuration prevents.
func TestFluentBitRestartWithOutputDown(t *testing.T) {
	requireFluentBit(t)
	const n = 5000
	for _, tc := range []struct {
		name     string
		graceful bool
		memory   bool
	}{
		{"shipped config, SIGKILL", false, false},
		{"shipped config, graceful stop", true, false},
		{"control: memory buffering, graceful stop", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			fb := newFluentBit(t, "pipeline:\n  outputs:\n"+httpOutput("down", "match: 'hawkbell.*'", port), tc.memory)
			now := time.Now().UTC()
			var evs []*event.Event
			for i := 0; i < n; i++ {
				evs = append(evs, mkEvent(event.KindActivity, i, now.Add(time.Duration(i)*time.Microsecond)))
			}
			writeEvents(t, fb.outbox, evs)
			fb.start()
			fb.waitRead(60 * time.Second)
			time.Sleep(2 * time.Second) // let failed flushes happen
			fb.kill(tc.graceful)
			rcv := newReceiver()
			rcv.start(t, port)
			defer rcv.stop()
			fb.start()
			if tc.memory {
				time.Sleep(15 * time.Second)
				got := rcv.unique()
				t.Logf("memory buffering delivered %d of %d after restart (documented loss)", got, n)
				if got == n {
					t.Logf("note: no loss observed in this run")
				}
				return
			}
			waitFor(t, 90*time.Second, func() bool { return rcv.unique() >= n }, func() string {
				return fmt.Sprintf("delivered %d of %d\n%s", rcv.unique(), n, fb.logs())
			})
			t.Logf("delivered %d of %d unique records (posts %d)", rcv.unique(), n, rcv.posts)
		})
	}
}

// TestFluentBitHeadOfLine: the activity destination is down and its backlog
// is large; findings must still reach a healthy SIEM promptly.
func TestFluentBitHeadOfLine(t *testing.T) {
	requireFluentBit(t)
	siemPort, archivePort := freePort(t), freePort(t)
	siem := newReceiver()
	siem.start(t, siemPort)
	defer siem.stop()
	outs := "pipeline:\n  outputs:\n" +
		httpOutput("siem", "match_regex: '^hawkbell\\.(detection|summary|health|posture|inventory|parse_error)$'", siemPort) +
		httpOutput("archive", "match: 'hawkbell.activity'", archivePort) // nothing listens here
	fb := newFluentBit(t, outs, false)
	now := time.Now().UTC()
	var evs []*event.Event
	for i := 0; i < 20000; i++ {
		evs = append(evs, mkEvent(event.KindActivity, i, now))
	}
	for i := 0; i < 10; i++ {
		evs = append(evs, mkEvent(event.KindDetection, i, now))
	}
	writeEvents(t, fb.outbox, evs)
	fb.start()
	waitFor(t, 45*time.Second, func() bool { return siem.unique() >= 10 }, func() string {
		return fmt.Sprintf("SIEM got %d of 10 detections while activity was blocked\n%s", siem.unique(), fb.logs())
	})
}

// TestFluentBitKeepsRejectedChunks: a permanent error (401 after a token
// rotation) drops the chunk even with unlimited retries; the shipped
// service settings keep a copy under storage.path/rejected.
func TestFluentBitKeepsRejectedChunks(t *testing.T) {
	requireFluentBit(t)
	port := freePort(t)
	rcv := newReceiver()
	rcv.status = 401
	rcv.start(t, port)
	defer rcv.stop()
	fb := newFluentBit(t, "pipeline:\n  outputs:\n"+httpOutput("auth", "match: 'hawkbell.*'", port), false)
	writeEvents(t, fb.outbox, []*event.Event{mkEvent(event.KindDetection, 1, time.Now().UTC())})
	fb.start()
	waitFor(t, 60*time.Second, func() bool {
		var found bool
		filepath.Walk(filepath.Join(fb.state, "storage"), func(p string, info os.FileInfo, err error) error {
			if err == nil && strings.Contains(p, "rejected") && !info.IsDir() {
				found = true
			}
			return nil
		})
		return found
	}, func() string { return "no rejected chunk kept\n" + fb.logs() })
}

// TestFluentBitOversizeRecord: a 5 MB command is shrunk by the sensor's
// writer to one record under the cap and arrives intact as JSON.
func TestFluentBitOversizeRecord(t *testing.T) {
	requireFluentBit(t)
	port := freePort(t)
	rcv := newReceiver()
	rcv.start(t, port)
	defer rcv.stop()
	fb := newFluentBit(t, "pipeline:\n  outputs:\n"+httpOutput("all", "match: 'hawkbell.*'", port), false)
	e := mkEvent(event.KindActivity, 1, time.Now().UTC())
	e.Target.Command = strings.Repeat("A", 5<<20)
	after := mkEvent(event.KindActivity, 2, time.Now().UTC())
	writeEvents(t, fb.outbox, []*event.Event{e, after})
	fi, _ := os.Stat(mustGlob(t, filepath.Join(fb.outbox, "activity-*.ndjson")))
	if fi.Size() > 128<<10 {
		t.Fatalf("segment is %d bytes: the record was not shrunk", fi.Size())
	}
	fb.start()
	waitFor(t, 60*time.Second, func() bool { return rcv.unique() >= 2 }, func() string { return fmt.Sprintf("%d records\n%s", rcv.unique(), fb.logs()) })
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	if tr, _ := rcv.extra[e.ID]["truncated"].([]any); len(tr) == 0 {
		t.Errorf("shrunk record does not list truncated fields: %v", rcv.extra[e.ID]["truncated"])
	}
}

var _ = context.Background
