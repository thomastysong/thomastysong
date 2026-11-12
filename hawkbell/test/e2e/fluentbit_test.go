//go:build e2e

// Package e2e runs hawkbell's shipped deployment content against real
// software. These tests need Docker and the fluent/fluent-bit image and are
// gated by the e2e build tag plus HAWKBELL_E2E_FLUENTBIT=1:
//
//	HAWKBELL_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -v
//
// Most tests reproduce one transport failure found in the design review
// (docs/ASSUMPTIONS.md, "Transport") and check that the shipped
// configuration in deploy/fluent-bit does not have it. The control subtests
// and the measuring tests (HTTPStatus, TailDBLoss, TailDBLocking,
// StorageMetricsStartup) record what Fluent Bit does and print the numbers
// with -v; results are in deploy/fluent-bit/VERIFIED.md.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
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

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/thomastysong/thomastysong/hawkbell/internal/daemon"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
)

// image is the Fluent Bit image the tests run: the release whose behaviour
// they record, or the one HAWKBELL_E2E_FLUENTBIT_IMAGE names. The tests
// never pull it.
var image = func() string {
	if v := os.Getenv("HAWKBELL_E2E_FLUENTBIT_IMAGE"); v != "" {
		return v
	}
	return "fluent/fluent-bit:5.2.0"
}()

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

// total counts every record received, duplicates included.
func (r *receiver) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.ids {
		n += c
	}
	return n
}

func (r *receiver) setStatus(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = code
}

func (r *receiver) postCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.posts
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

// fbOptions vary the harness around the shipped inputs fragment.
type fbOptions struct {
	outputs         string
	memoryBuffering bool   // the failing default the shipped configuration avoids
	oneInput        bool   // control: one tail input reads every stream
	memBufLimit     string // mem_buf_limit on every tail input ("" = not set)
	apiPort         int    // > 0: http_server on 127.0.0.1:apiPort
	storageMetrics  string // service storage.metrics: "on", "off", or "" (not set)
	dbLocking       bool   // db.locking true on every tail input (shipped: false)
}

func newFluentBit(t *testing.T, outputs string, memoryBuffering bool) *fluentBit {
	return newFluentBitWith(t, fbOptions{outputs: outputs, memoryBuffering: memoryBuffering})
}

func newFluentBitWith(t *testing.T, o fbOptions) *fluentBit {
	t.Helper()
	root := repoRoot(t)
	cfg := t.TempDir()
	inputs, err := os.ReadFile(filepath.Join(root, "deploy", "fluent-bit", "hawkbell-inputs.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if o.memoryBuffering {
		// The failing default this configuration exists to avoid.
		inputs = bytes.ReplaceAll(inputs, []byte("storage.type: filesystem"), []byte("storage.type: memory"))
	}
	if o.dbLocking {
		if !bytes.Contains(inputs, []byte("db.locking: false")) {
			t.Fatal("the shipped inputs no longer set db.locking: false")
		}
		inputs = bytes.ReplaceAll(inputs, []byte("db.locking: false"), []byte("db.locking: true"))
	}
	if o.oneInput || o.memBufLimit != "" {
		inputs = rewriteInputs(t, inputs, o.oneInput, o.memBufLimit)
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
`
	if o.apiPort > 0 {
		main += fmt.Sprintf("  http_server: on\n  http_listen: 127.0.0.1\n  http_port: %d\n", o.apiPort)
	}
	if o.storageMetrics != "" {
		main += "  storage.metrics: " + o.storageMetrics + "\n"
	}
	main += `includes:
  - hawkbell-inputs.yaml
  - outputs.yaml
`
	os.WriteFile(filepath.Join(cfg, "main.yaml"), []byte(main), 0o644)
	os.WriteFile(filepath.Join(cfg, "outputs.yaml"), []byte(o.outputs), 0o644)
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

// rewriteInputs varies the shipped inputs fragment for a control run, every
// other setting unchanged. oneInput: one tail input (the findings input)
// whose path also lists the activity segments, the layout the two inputs
// replaced. memBufLimit: mem_buf_limit on every tail input.
func rewriteInputs(t *testing.T, inputs []byte, oneInput bool, memBufLimit string) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(inputs, &doc); err != nil {
		t.Fatal(err)
	}
	pl, _ := doc["pipeline"].(map[string]any)
	ins, _ := pl["inputs"].([]any)
	if len(ins) != 2 {
		t.Fatalf("shipped fragment has %d inputs, want 2", len(ins))
	}
	first, _ := ins[0].(map[string]any)
	second, _ := ins[1].(map[string]any)
	if first["alias"] != "hawkbell_findings" || second["alias"] != "hawkbell_activity" {
		t.Fatalf("unexpected inputs %v / %v", first["alias"], second["alias"])
	}
	if oneInput {
		first["path"] = fmt.Sprint(first["path"]) + "," + fmt.Sprint(second["path"])
		first["alias"] = "hawkbell_all"
		ins = []any{first}
		pl["inputs"] = ins
	}
	if memBufLimit != "" {
		for _, in := range ins {
			in.(map[string]any)["mem_buf_limit"] = memBufLimit
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
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

func mustGlobAll(p string) []string {
	m, _ := filepath.Glob(p)
	return m
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
// is large; detections written 5 s after Fluent Bit started on that backlog
// must still reach a healthy SIEM promptly. The shipped
// fragment has two filesystem-buffered tail inputs (findings, activity).
// The controls only measure, and report how many detections arrived within
// the same window: one tail input for every stream (the layout the two
// inputs replaced), with filesystem buffering and with memory buffering
// capped by mem_buf_limit 5M (the design review's setup), and two inputs
// with that memory buffering.
func TestFluentBitHeadOfLine(t *testing.T) {
	requireFluentBit(t)
	const window = 45 * time.Second
	const backlogFor = 5 * time.Second
	for _, tc := range []struct {
		name     string
		oneInput bool
		memory   bool
		activity int
	}{
		{"shipped: two tail inputs", false, false, 20000},
		{"control: one tail input", true, false, 20000},
		{"control: one tail input, 200,000 activity records", true, false, 200000},
		{"control: one tail input, memory buffering, mem_buf_limit 5M", true, true, 20000},
		{"control: one tail input, memory buffering, mem_buf_limit 5M, 200,000 activity records", true, true, 200000},
		{"control: two tail inputs, memory buffering, mem_buf_limit 5M, 200,000 activity records", false, true, 200000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			siemPort, archivePort := freePort(t), freePort(t)
			siem := newReceiver()
			siem.start(t, siemPort)
			defer siem.stop()
			outs := "pipeline:\n  outputs:\n" +
				httpOutput("siem", "match_regex: '^hawkbell\\.(detection|summary|health|posture|inventory|parse_error)$'", siemPort) +
				httpOutput("archive", "match: 'hawkbell.activity'", archivePort) // nothing listens here
			o := fbOptions{outputs: outs, oneInput: tc.oneInput}
			if tc.memory {
				o.memoryBuffering, o.memBufLimit = true, "5M"
			}
			fb := newFluentBitWith(t, o)
			now := time.Now().UTC()
			var act, det []*event.Event
			for i := 0; i < tc.activity; i++ {
				act = append(act, mkEvent(event.KindActivity, i, now))
			}
			for i := 0; i < 10; i++ {
				det = append(det, mkEvent(event.KindDetection, i, now))
			}
			// The activity backlog exists and is failing before the
			// detections are written.
			writeEvents(t, fb.outbox, act)
			var actBytes int64
			for _, f := range mustGlobAll(filepath.Join(fb.outbox, "activity-*.ndjson")) {
				if fi, err := os.Stat(f); err == nil {
					actBytes += fi.Size()
				}
			}
			fb.start()
			time.Sleep(backlogFor)
			writeEvents(t, fb.outbox, det)
			start := time.Now()
			var all time.Duration
			for time.Since(start) < window {
				if siem.unique() >= 10 {
					all = time.Since(start)
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			got := siem.unique()
			inputs := strings.Join(fb.logLines("[input:tail:"), "\n")
			one := strings.Contains(inputs, "hawkbell_all") && !strings.Contains(inputs, "hawkbell_activity")
			if tc.oneInput != one {
				t.Fatalf("one tail input = %v, want %v:\n%s", one, tc.oneInput, inputs)
			}
			paused := len(fb.logLines("paused (mem buf overlimit"))
			if all > 0 {
				t.Logf("%d of 10 detections reached the SIEM, all of them %.1f s after they were written (%d activity records, %d bytes, for an unreachable archive, started %v earlier; %d 'paused (mem buf overlimit)' log lines)", got, all.Seconds(), tc.activity, actBytes, backlogFor, paused)
			} else {
				t.Logf("%d of 10 detections reached the SIEM within %v of being written (%d activity records, %d bytes, for an unreachable archive, started %v earlier; %d 'paused (mem buf overlimit)' log lines)", got, window, tc.activity, actBytes, backlogFor, paused)
			}
			if !tc.oneInput && !tc.memory && got < 10 {
				t.Fatalf("SIEM got %d of 10 detections while activity was blocked\n%s", got, fb.logs())
			}
		})
	}
}

// TestFluentBitKeepsRejectedChunks: an HTTP 401 (a rotated token) drops the
// chunk after one request even with unlimited retries; the shipped service
// settings keep a copy under storage.path/rejected. TestFluentBitHTTPStatus
// measures 400, 413 and 503 next to it.
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

// apiGet fetches a Fluent Bit API path on the loopback interface, never
// through a proxy.
func apiGet(port int, path string) (int, []byte, error) {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// outputMetrics is one output's counters from /api/v1/metrics.
func outputMetrics(t *testing.T, port int, alias string) map[string]float64 {
	t.Helper()
	code, b, err := apiGet(port, "/api/v1/metrics")
	if err != nil || code != 200 {
		t.Fatalf("metrics: %d %v", code, err)
	}
	var m struct {
		Output map[string]map[string]float64 `json:"output"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("metrics: %v %s", err, b)
	}
	if o, ok := m.Output[alias]; ok {
		return o
	}
	t.Fatalf("no output %q in %s", alias, b)
	return nil
}

// rejectedChunks lists the chunk files kept under storage.path/rejected,
// relative to storage.path.
func (fb *fluentBit) rejectedChunks() []string {
	var out []string
	dir := filepath.Join(fb.state, "storage")
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.Contains(p, "rejected") && !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// idsIn counts the record ids that occur in the kept chunk files.
func (fb *fluentBit) idsIn(files []string, evs []*event.Event) int {
	var all []byte
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(fb.state, "storage", f))
		all = append(all, b...)
	}
	n := 0
	for _, e := range evs {
		if bytes.Contains(all, []byte(e.ID)) {
			n++
		}
	}
	return n
}

// logLines returns the container log lines that contain any of the words.
func (fb *fluentBit) logLines(words ...string) []string {
	var out []string
	for _, l := range strings.Split(fb.logs(), "\n") {
		for _, w := range words {
			if strings.Contains(l, w) {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// TestFluentBitHTTPStatus measures what the http output does with a chunk
// the destination refuses, for 400, 401 and 413 (the shipped comments call
// them permanent) and 503 (a control that should be retried): the
// destination refuses for 15 s, then accepts. A dropped chunk is kept under
// storage.path/rejected and never arrives; a retried one arrives once the
// destination accepts.
func TestFluentBitHTTPStatus(t *testing.T) {
	requireFluentBit(t)
	const n = 10
	const refuseFor = 15 * time.Second
	for _, code := range []int{400, 401, 413, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			port, api := freePort(t), freePort(t)
			rcv := newReceiver()
			rcv.setStatus(code)
			rcv.start(t, port)
			defer rcv.stop()
			fb := newFluentBitWith(t, fbOptions{outputs: "pipeline:\n  outputs:\n" + httpOutput("dest", "match: 'hawkbell.*'", port), apiPort: api})
			var evs []*event.Event
			now := time.Now().UTC()
			for i := 0; i < n; i++ {
				evs = append(evs, mkEvent(event.KindDetection, i, now.Add(time.Duration(i)*time.Millisecond)))
			}
			writeEvents(t, fb.outbox, evs)
			fb.start()
			time.Sleep(refuseFor)
			m := outputMetrics(t, api, "dest")
			posts, kept := rcv.postCount(), fb.rejectedChunks()
			rejected, keptIDs := len(kept), fb.idsIn(kept, evs)
			rcv.setStatus(200)
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) && rcv.unique() < n {
				time.Sleep(250 * time.Millisecond)
			}
			delivered := rcv.unique()
			outcome := "mixed"
			switch {
			case delivered == 0 && rejected > 0 && keptIDs == n:
				outcome = "dropped (kept under rejected/)"
			case delivered == n && rejected == 0:
				outcome = "retried"
			}
			t.Logf("HTTP %d for %v: %d post(s); metrics retries=%v retries_failed=%v dropped_records=%v retried_records=%v errors=%v; rejected chunk file(s) %v holding %d of %d record ids; after the destination accepted: %d of %d delivered within 20 s => %s",
				code, refuseFor, posts, m["retries"], m["retries_failed"], m["dropped_records"], m["retried_records"], m["errors"], kept, keptIDs, n, delivered, n, outcome)
			for i, l := range fb.logLines("HTTP status", "retry", "rejected", "cannot be retried") {
				if i >= 6 {
					break
				}
				t.Logf("  log: %s", l)
			}
			if outcome == "mixed" {
				t.Fatalf("neither dropped nor retried\n%s", fb.logs())
			}
		})
	}
}

// TestFluentBitTailDBLoss: Fluent Bit delivers every record, is stopped,
// and starts again with its tail databases deleted while the segments are
// still in the outbox (an emptyDir or a wiped state directory). The control
// keeps the databases. Measures how many records arrive a second time.
func TestFluentBitTailDBLoss(t *testing.T) {
	requireFluentBit(t)
	const nAct, nDet = 4500, 500
	const n = nAct + nDet
	for _, tc := range []struct {
		name     string
		deleteDB bool
	}{
		{"control: tail databases kept", false},
		{"tail databases deleted", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			rcv := newReceiver()
			rcv.start(t, port)
			defer rcv.stop()
			fb := newFluentBit(t, "pipeline:\n  outputs:\n"+httpOutput("all", "match: 'hawkbell.*'", port), false)
			now := time.Now().UTC()
			var evs []*event.Event
			for i := 0; i < nAct; i++ {
				evs = append(evs, mkEvent(event.KindActivity, i, now.Add(time.Duration(i)*time.Microsecond)))
			}
			for i := 0; i < nDet; i++ {
				evs = append(evs, mkEvent(event.KindDetection, i, now.Add(time.Duration(i)*time.Microsecond)))
			}
			writeEvents(t, fb.outbox, evs)
			fb.start()
			waitFor(t, 60*time.Second, func() bool { return rcv.unique() >= n }, func() string {
				return fmt.Sprintf("first run delivered %d of %d\n%s", rcv.unique(), n, fb.logs())
			})
			fb.waitRead(30 * time.Second)
			time.Sleep(2 * time.Second)
			fb.kill(true)
			first := rcv.total()
			var removed []string
			if tc.deleteDB {
				m, _ := filepath.Glob(filepath.Join(fb.state, "hawkbell-*.db*"))
				for _, p := range m {
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
					removed = append(removed, filepath.Base(p))
				}
			}
			fb.start()
			// Wait until nothing new has arrived for 10 s (at most 90 s).
			start, last, lastN := time.Now(), time.Now(), rcv.total()
			for time.Since(start) < 90*time.Second && time.Since(last) < 10*time.Second {
				time.Sleep(500 * time.Millisecond)
				if c := rcv.total(); c != lastN {
					last, lastN = time.Now(), c
				}
			}
			total := rcv.total()
			t.Logf("first run: %d records received (%d unique); removed %v; after restart: %d received in total (%d unique), %d delivered again, the last %.1f s after the restart",
				first, n, removed, total, rcv.unique(), total-first, last.Sub(start).Seconds())
			if tc.deleteDB && total <= first {
				t.Fatalf("nothing was delivered again after the tail databases were deleted")
			}
			if !tc.deleteDB && total != first {
				t.Fatalf("%d records delivered again with the tail databases kept", total-first)
			}
		})
	}
}

// TestFluentBitTailDBLocking: whether the daemon and hawkbell doctor can
// read a running Fluent Bit's tail database, with the shipped db.locking
// false and with db.locking true. Both read it through daemon.CheckTailDB:
// in place, and, when that fails, through a private copy (the pruner's
// fallback, internal/daemon/taildb.go). The numbers are printed with -v.
func TestFluentBitTailDBLocking(t *testing.T) {
	requireFluentBit(t)
	const n = 10
	for _, locking := range []bool{false, true} {
		t.Run(fmt.Sprintf("db.locking=%v", locking), func(t *testing.T) {
			port := freePort(t)
			rcv := newReceiver()
			rcv.start(t, port)
			defer rcv.stop()
			fb := newFluentBitWith(t, fbOptions{outputs: "pipeline:\n  outputs:\n" + httpOutput("siem", "match: 'hawkbell.*'", port), dbLocking: locking})
			now := time.Now().UTC()
			var evs []*event.Event
			for i := 0; i < n; i++ {
				evs = append(evs, mkEvent(event.KindDetection, i, now.Add(time.Duration(i)*time.Microsecond)))
			}
			writeEvents(t, fb.outbox, evs)
			fb.start()
			waitFor(t, 60*time.Second, func() bool { return rcv.unique() >= n }, func() string {
				return fmt.Sprintf("%d of %d delivered\n%s", rcv.unique(), n, fb.logs())
			})
			db := filepath.Join(fb.state, "hawkbell-findings.db")
			copyDir := filepath.Join(t.TempDir(), "taildb-copy")
			// Wait until the database holds the segment's row (through a copy
			// if need be), then read it once each way.
			var rows int
			var err error
			waitFor(t, 30*time.Second, func() bool {
				rows, _, err = daemon.CheckTailDB(db, copyDir)
				return err == nil && rows >= 1
			}, func() string { return fmt.Sprintf("no segment row: %d, %v\n%s", rows, err, fb.logs()) })
			var sides []string
			for _, p := range []string{"-wal", "-shm"} {
				if _, err := os.Lstat(db + p); err == nil {
					sides = append(sides, filepath.Base(db+p))
				}
			}
			start := time.Now()
			_, _, direct := daemon.CheckTailDB(db, "")
			tookDirect := time.Since(start)
			start = time.Now()
			rows, inPlace, err := daemon.CheckTailDB(db, copyDir)
			tookCopy := time.Since(start)
			t.Logf("db.locking %v: beside the database %v; in-place read: error %v (%.1f s); read with a copy directory: %d segment row(s), error %v, in-place error %v (%.1f s)",
				locking, sides, direct, tookDirect.Seconds(), rows, err, inPlace, tookCopy.Seconds())
			if err != nil || rows < 1 {
				t.Fatalf("the pruner's read failed: %d rows, %v", rows, err)
			}
			if ents, _ := os.ReadDir(copyDir); len(ents) != 0 {
				t.Errorf("the copy left %d entries behind", len(ents))
			}
			if !locking && direct != nil {
				t.Errorf("shipped db.locking false: in-place read failed: %v", direct)
			}
			// db.locking true is measured, not asserted: a later image may
			// lock differently.
		})
	}
}

// TestFluentBitStorageMetricsStartup measures when /api/v1/metrics and
// /api/v1/storage start answering 200 after Fluent Bit starts, with service
// storage.metrics on, off and not set (hawkbell doctor reads both).
func TestFluentBitStorageMetricsStartup(t *testing.T) {
	requireFluentBit(t)
	type endpoint struct {
		path              string
		seen              map[int]int
		last404, first200 time.Duration
	}
	for _, setting := range []string{"on", "off", ""} {
		t.Run("storage.metrics="+setting, func(t *testing.T) {
			api := freePort(t)
			fb := newFluentBitWith(t, fbOptions{outputs: "pipeline:\n  outputs:\n    - name: null\n      match: '*'\n", apiPort: api, storageMetrics: setting})
			eps := []*endpoint{{path: "/api/v1/metrics", seen: map[int]int{}}, {path: "/api/v1/storage", seen: map[int]int{}}}
			start := time.Now()
			fb.start()
			var rootUp time.Duration
			for time.Since(start) < 30*time.Second && (eps[0].first200 == 0 || eps[1].first200 == 0) {
				if rootUp == 0 {
					if code, _, err := apiGet(api, "/"); err == nil && code == 200 {
						rootUp = time.Since(start)
					}
				}
				if rootUp > 0 {
					for _, ep := range eps {
						if ep.first200 != 0 {
							continue
						}
						code, _, err := apiGet(api, ep.path)
						if err != nil {
							continue
						}
						ep.seen[code]++
						switch code {
						case 404:
							ep.last404 = time.Since(start)
						case 200:
							ep.first200 = time.Since(start)
						}
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			for _, ep := range eps {
				t.Logf("storage.metrics %q: API up %.2f s after docker run; %s answers %v; last 404 at %.2f s, first 200 at %.2f s (0 = never within 30 s)",
					setting, rootUp.Seconds(), ep.path, ep.seen, ep.last404.Seconds(), ep.first200.Seconds())
			}
			if eps[0].first200 == 0 {
				t.Fatalf("/api/v1/metrics never answered 200\n%s", fb.logs())
			}
			if setting == "on" && eps[1].first200 == 0 {
				t.Fatalf("/api/v1/storage never answered 200\n%s", fb.logs())
			}
			if setting == "off" && eps[1].first200 != 0 {
				t.Fatalf("/api/v1/storage answered 200 with storage.metrics off")
			}
		})
	}
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
