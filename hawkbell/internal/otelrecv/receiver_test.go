package otelrecv

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// collector is a concurrency-safe Emit target.
type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) emit(ev *event.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, ev)
	c.mu.Unlock()
}

func (c *collector) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.evs)
}

type reqOpt func(*http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func remote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }
func host(h string) reqOpt      { return func(r *http.Request) { r.Host = h } }

// do sends one request straight to the handler, as a local exporter would.
func do(r *Receiver, method, path string, body []byte, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:4319"+path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "application/json")
	for _, o := range opts {
		o(req)
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	return w
}

var goodBody = otlpBody(claudeRes, "", claudeRec("tool_result", kv{"tool_name": "Bash", "tool_use_id": "toolu_1", "success": "true"}))

func TestHandlerAcceptsJSONLogs(t *testing.T) {
	var c collector
	r := New(Options{Emit: c.emit})
	w := do(r, http.MethodPost, "/v1/logs", goodBody)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "{}" {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	eq(t, "content type", w.Header().Get("Content-Type"), "application/json")
	if c.len() != 1 || c.evs[0].Tool.UseID != "toolu_1" {
		t.Fatalf("emitted %d", c.len())
	}
	// A charset parameter and a trailing slash are tolerated.
	w = do(r, http.MethodPost, "/v1/logs/", goodBody, header("Content-Type", "application/json; charset=utf-8"))
	eq(t, "status with charset", w.Code, http.StatusOK)
	st := r.Stats()
	eq(t, "requests", st.Requests, uint64(2))
	eq(t, "events", st.Events, uint64(2))
	eq(t, "rejected", st.Rejected, uint64(0))
	if st.LastEvent.IsZero() {
		t.Error("LastEvent not set")
	}
	s := r.Surface()
	if s.Name != "otel" || s.Status != "ok" || s.Events != 2 || s.SchemaDrift {
		t.Errorf("surface = %+v", s)
	}
}

func TestHandlerRejectsProtobufWithGuidance(t *testing.T) {
	r := New(Options{})
	for _, ct := range []string{"application/x-protobuf", "application/protobuf", "application/grpc"} {
		for _, path := range []string{"/v1/logs", "/v1/metrics", "/v1/traces"} {
			w := do(r, http.MethodPost, path, []byte("\x0a\x05hello"), header("Content-Type", ct))
			if w.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("%s %s: status %d", ct, path, w.Code)
			}
			msg := w.Body.String()
			for _, want := range []string{"JSON", "OTEL_EXPORTER_OTLP_PROTOCOL=http/json", `protocol = "json"`, "otlpProtocol"} {
				if !strings.Contains(msg, want) {
					t.Errorf("message lacks %q: %s", want, msg)
				}
			}
		}
	}
	st := r.Stats()
	eq(t, "protobuf", st.Protobuf, uint64(9))
	eq(t, "rejected", st.Rejected, uint64(9))
	if s := r.Surface(); s.Status != "degraded" || s.Reason != "otel.protobuf_rejected" {
		t.Errorf("surface = %+v", s)
	}
}

func TestHandlerRefusals(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
		opts   []reqOpt
		want   int
	}{
		{"get", http.MethodGet, "/v1/logs", nil, nil, http.StatusMethodNotAllowed},
		{"put", http.MethodPut, "/v1/logs", goodBody, nil, http.StatusMethodNotAllowed},
		{"options preflight", http.MethodOptions, "/v1/logs", nil, nil, http.StatusMethodNotAllowed},
		{"unknown path", http.MethodPost, "/v1/log", goodBody, nil, http.StatusNotFound},
		{"root", http.MethodPost, "/", goodBody, nil, http.StatusNotFound},
		{"traversal", http.MethodPost, "/v1/logs/../../etc/passwd", goodBody, nil, http.StatusNotFound},
		{"no content type", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Content-Type", "")}, http.StatusUnsupportedMediaType},
		{"form post", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Content-Type", "text/plain")}, http.StatusUnsupportedMediaType},
		{"remote peer", http.MethodPost, "/v1/logs", goodBody, []reqOpt{remote("192.0.2.7:4000")}, http.StatusForbidden},
		{"unparsable peer", http.MethodPost, "/v1/logs", goodBody, []reqOpt{remote("@")}, http.StatusForbidden},
		{"browser origin", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Origin", "https://evil.example")}, http.StatusForbidden},
		{"fetch metadata", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Sec-Fetch-Site", "cross-site")}, http.StatusForbidden},
		{"dns rebinding host", http.MethodPost, "/v1/logs", goodBody, []reqOpt{host("rebind.evil.example:4319")}, http.StatusForbidden},
		{"bad json", http.MethodPost, "/v1/logs", []byte(`{"resourceLogs":`), nil, http.StatusBadRequest},
		{"wrong signal body", http.MethodPost, "/v1/logs", []byte(`{"resourceSpans":[]}`), nil, http.StatusBadRequest},
		{"unsupported encoding", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Content-Encoding", "br")}, http.StatusUnsupportedMediaType},
		{"gzip header without gzip", http.MethodPost, "/v1/logs", goodBody, []reqOpt{header("Content-Encoding", "gzip")}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c collector
			r := New(Options{Emit: c.emit})
			w := do(r, tc.method, tc.path, tc.body, tc.opts...)
			eq(t, "status", w.Code, tc.want)
			eq(t, "emitted", c.len(), 0)
			eq(t, "rejected", r.Stats().Rejected, uint64(1))
			if w.Code == http.StatusMethodNotAllowed {
				eq(t, "allow", w.Header().Get("Allow"), "POST")
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Error("CORS header present: a browser could read the response")
			}
		})
	}
	// IPv6 loopback and localhost are loopback too.
	r := New(Options{})
	w := do(r, http.MethodPost, "/v1/logs", goodBody, remote("[::1]:9"), host("[::1]:4319"))
	eq(t, "ipv6", w.Code, http.StatusOK)
	w = do(r, http.MethodPost, "/v1/logs", goodBody, host("localhost:4319"))
	eq(t, "localhost", w.Code, http.StatusOK)
}

func TestHandlerBodyLimits(t *testing.T) {
	r := New(Options{MaxBody: 4096})
	pad := otlpBody(claudeRes, "", claudeRec("tool_result", kv{"tool_name": "Bash", "pad": strings.Repeat("x", 8000)}))

	w := do(r, http.MethodPost, "/v1/logs", pad)
	eq(t, "declared length over cap", w.Code, http.StatusRequestEntityTooLarge)
	var status struct {
		Code    int
		Message string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Code != 8 || status.Message == "" {
		t.Errorf("error body = %q", w.Body.String())
	}

	// Unknown length (chunked): the reader enforces the cap.
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4319/v1/logs", io.NopCloser(bytes.NewReader(pad)))
	req.ContentLength = -1
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	eq(t, "chunked over cap", rec.Code, http.StatusRequestEntityTooLarge)

	// A small gzip body that expands past the cap.
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	_, _ = zw.Write(pad)
	_ = zw.Close()
	if zbuf.Len() >= 4096 {
		t.Fatalf("test setup: compressed body is %d bytes", zbuf.Len())
	}
	w = do(r, http.MethodPost, "/v1/logs", zbuf.Bytes(), header("Content-Encoding", "gzip"))
	eq(t, "gzip bomb", w.Code, http.StatusRequestEntityTooLarge)

	// Within the cap, gzip works.
	var c collector
	r = New(Options{Emit: c.emit})
	zbuf.Reset()
	zw = gzip.NewWriter(&zbuf)
	_, _ = zw.Write(goodBody)
	_ = zw.Close()
	w = do(r, http.MethodPost, "/v1/logs", zbuf.Bytes(), header("Content-Encoding", "gzip"))
	eq(t, "gzip ok", w.Code, http.StatusOK)
	eq(t, "gzip events", c.len(), 1)
	eq(t, "default cap", r.opts.MaxBody, int64(DefaultMaxBody))
}

func TestHandlerOtherSignalsAreDiscarded(t *testing.T) {
	var c collector
	r := New(Options{Emit: c.emit})
	for _, p := range []string{"/v1/metrics", "/v1/traces"} {
		w := do(r, http.MethodPost, p, []byte(`{"resourceMetrics":[]}`))
		eq(t, p, w.Code, http.StatusOK)
	}
	eq(t, "emitted", c.len(), 0)
	eq(t, "discarded", r.Stats().Discarded, uint64(2))
}

func TestHandlerPartialSuccessAndDrift(t *testing.T) {
	recs := make([]map[string]any, 0, MaxRecords+3)
	for i := 0; i < MaxRecords+3; i++ {
		recs = append(recs, claudeRec("tool_result", kv{"tool_name": "Bash", "event.sequence": i}))
	}
	body := otlpBody(claudeRes, "", recs...)
	var n atomic.Int64
	r := New(Options{MaxBody: int64(len(body)) + 1, Emit: func(*event.Event) { n.Add(1) }})
	w := do(r, http.MethodPost, "/v1/logs", body)
	eq(t, "status", w.Code, http.StatusOK)
	var resp struct {
		PartialSuccess struct {
			RejectedLogRecords string
			ErrorMessage       string
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.PartialSuccess.RejectedLogRecords != "3" {
		t.Errorf("partial success = %q", w.Body.String())
	}
	eq(t, "emitted", n.Load(), int64(MaxRecords))
	eq(t, "dropped", r.Stats().Dropped, uint64(3))

	w = do(r, http.MethodPost, "/v1/logs", otlpBody(claudeRes, "", claudeRec("shiny_new", kv{}), claudeRec("api_request", kv{})))
	eq(t, "drift status", w.Code, http.StatusOK)
	st := r.Stats()
	eq(t, "unknown", st.Unknown, uint64(1))
	eq(t, "unknown name", st.UnknownNames["claude_code.shiny_new"], uint64(1))
	eq(t, "ignored", st.Ignored, uint64(1))
	if s := r.Surface(); !s.SchemaDrift || s.Status != "degraded" || s.Reason != "otel.schema_drift" {
		t.Errorf("surface = %+v", s)
	}
}

func TestHandlerSurvivesPanickingEmit(t *testing.T) {
	r := New(Options{Emit: func(*event.Event) { panic("consumer bug") }})
	w := do(r, http.MethodPost, "/v1/logs", goodBody)
	eq(t, "status", w.Code, http.StatusOK)
	// Nil Emit is a valid configuration (accounting only).
	r = New(Options{})
	w = do(r, http.MethodPost, "/v1/logs", goodBody)
	eq(t, "nil emit", w.Code, http.StatusOK)
	eq(t, "events counted", r.Stats().Events, uint64(1))
}

func TestHandlerBusy(t *testing.T) {
	r := New(Options{})
	for i := 0; i < maxInFlight; i++ {
		r.sem <- struct{}{}
	}
	w := do(r, http.MethodPost, "/v1/logs", goodBody)
	eq(t, "status", w.Code, http.StatusTooManyRequests)
	eq(t, "retry-after", w.Header().Get("Retry-After"), "1")
	<-r.sem
	w = do(r, http.MethodPost, "/v1/logs", goodBody)
	eq(t, "after release", w.Code, http.StatusOK)
}

func TestRunRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:4319", ":4319", "[::]:4319", "192.168.1.10:4319", "example.com:4319",
		"127.0.0.1", "127.0.0.1:port", "127.0.0.1:70000", "10.0.0.1:0"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := New(Options{Addr: addr}).Run(ctx)
		cancel()
		if err == nil {
			t.Errorf("Run(%q) listened", addr)
		}
	}
	for in, want := range map[string]string{"": DefaultAddr, "localhost:0": "127.0.0.1:0", "LOCALHOST:5": "127.0.0.1:5",
		"127.0.0.2:1": "127.0.0.2:1", "[::1]:4319": "[::1]:4319"} {
		got, err := loopbackAddr(in)
		if err != nil || got != want {
			t.Errorf("loopbackAddr(%q) = %q, %v", in, got, err)
		}
	}
}

// startReceiver runs a receiver on a free loopback port.
func startReceiver(t *testing.T, o Options) (*Receiver, string, func() error) {
	t.Helper()
	o.Addr = "127.0.0.1:0"
	r := New(o)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-r.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("Run returned early: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("receiver did not start")
	}
	stop := func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after cancel")
			return nil
		}
	}
	return r, "http://" + r.Addr(), stop
}

// localClient never uses a proxy: the sandbox sets HTTPS_PROXY and the
// receiver must be reached directly.
func localClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
}

func post(t *testing.T, c *http.Client, url, ct string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ct)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(b)
}

func TestRunEndToEnd(t *testing.T) {
	var c collector
	r, base, stop := startReceiver(t, Options{Emit: c.emit})
	client := localClient()
	defer client.CloseIdleConnections()

	if host, _, err := net.SplitHostPort(r.Addr()); err != nil || host != "127.0.0.1" {
		t.Fatalf("bound to %q", r.Addr())
	}
	code, body := post(t, client, base+"/v1/logs", "application/json", goodBody)
	if code != http.StatusOK || strings.TrimSpace(body) != "{}" {
		t.Fatalf("status=%d body=%q", code, body)
	}
	code, body = post(t, client, base+"/v1/logs", "application/x-protobuf", []byte{0x0a, 0x00})
	if code != http.StatusUnsupportedMediaType || !strings.Contains(body, "http/json") {
		t.Fatalf("protobuf: status=%d body=%q", code, body)
	}
	eq(t, "emitted", c.len(), 1)

	// A second Run on the same receiver is refused while the first serves.
	if err := r.Run(context.Background()); err == nil {
		t.Error("second Run succeeded")
	}
	// The port is taken: a new receiver on it reports the listen error.
	if err := New(Options{Addr: r.Addr()}).Run(context.Background()); err == nil {
		t.Error("listen on a busy port succeeded")
	}

	client.CloseIdleConnections()
	if err := stop(); err != nil {
		t.Errorf("Run returned %v after cancel, want nil", err)
	}
	// After shutdown nothing listens there any more.
	conn, err := net.DialTimeout("tcp", r.Addr(), time.Second)
	if err == nil {
		conn.Close()
		t.Error("still listening after shutdown")
	}
}

func TestRunConcurrentSenders(t *testing.T) {
	var n atomic.Int64
	r, base, stop := startReceiver(t, Options{Emit: func(*event.Event) { n.Add(1) }})
	client := localClient()
	const senders, each = 16, 25
	var ok, busy, other atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				body := otlpBody(claudeRes, "", claudeRec("tool_result", kv{"tool_name": "Bash", "tool_use_id": "t", "event.sequence": s*1000 + i}))
				code, _ := post(t, client, base+"/v1/logs", "application/json", body)
				switch code {
				case http.StatusOK:
					ok.Add(1)
				case http.StatusTooManyRequests:
					busy.Add(1)
				default:
					other.Add(1)
				}
			}
		}(s)
	}
	wg.Wait()
	client.CloseIdleConnections()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if other.Load() != 0 || ok.Load()+busy.Load() != senders*each || ok.Load() == 0 {
		t.Fatalf("ok=%d busy=%d other=%d", ok.Load(), busy.Load(), other.Load())
	}
	// Every acknowledged request was emitted exactly once; every refused one
	// was counted, so the sender's retries and our accounting add up.
	eq(t, "emitted", n.Load(), ok.Load())
	st := r.Stats()
	eq(t, "requests", st.Requests, uint64(ok.Load()))
	eq(t, "rejected", st.Rejected, uint64(busy.Load()))
}

func TestRunSlowClientIsCutOff(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the header timeout")
	}
	r, _, stop := startReceiver(t, Options{})
	defer func() { _ = stop() }()
	conn, err := net.Dial("tcp", r.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Send half a request line and stall: the server must hang up on its own.
	_, _ = conn.Write([]byte("POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 512)
	start := time.Now()
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("stalled client held the connection for %v", d)
	}
}

func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 2)
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	clients := []net.Conn{dial(), dial(), dial()}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	first, second := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("third connection accepted above the limit")
	case <-time.After(200 * time.Millisecond):
	}
	// Closing twice must release exactly one slot.
	first.Close()
	first.Close()
	select {
	case third := <-accepted:
		third.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("slot not released on close")
	}
	second.Close()
	// Close unblocks an Accept that is waiting for a slot.
	a, b := dial(), dial()
	clients = append(clients, a, b)
	x, y := <-accepted, <-accepted
	_ = ln.Close()
	select {
	case _, open := <-accepted:
		if open {
			t.Error("accepted after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
	x.Close()
	y.Close()
}
