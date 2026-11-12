package sink

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// otlpRecorder is an OTLP/HTTP logs receiver for tests.
type otlpRecorder struct {
	mu      sync.Mutex
	reqs    []otlpRequestSeen
	respond func(n int, w http.ResponseWriter)
}

type otlpRequestSeen struct {
	method, path, contentType, encoding, auth, ua string
	body                                          map[string]any
	rawLen                                        int
}

func (r *otlpRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var rd io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(req.Body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		rd = zr
	}
	raw, _ := io.ReadAll(rd)
	seen := otlpRequestSeen{
		method: req.Method, path: req.URL.Path, contentType: req.Header.Get("Content-Type"), encoding: req.Header.Get("Content-Encoding"),
		auth: req.Header.Get("Authorization"), ua: req.Header.Get("User-Agent"), rawLen: int(req.ContentLength),
	}
	json.Unmarshal(raw, &seen.body)
	r.mu.Lock()
	n := len(r.reqs)
	r.reqs = append(r.reqs, seen)
	respond := r.respond
	r.mu.Unlock()
	if respond != nil {
		respond(n, w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{}`))
}

func (r *otlpRecorder) seen() []otlpRequestSeen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]otlpRequestSeen(nil), r.reqs...)
}

func recordIDs(body map[string]any) []string {
	var ids []string
	rl, _ := body["resourceLogs"].([]any)
	for _, r := range rl {
		sl, _ := r.(map[string]any)["scopeLogs"].([]any)
		for _, s := range sl {
			recs, _ := s.(map[string]any)["logRecords"].([]any)
			for _, rec := range recs {
				for _, a := range rec.(map[string]any)["attributes"].([]any) {
					kv := a.(map[string]any)
					if kv["key"] == "log.record.uid" {
						ids = append(ids, kv["value"].(map[string]any)["stringValue"].(string))
					}
				}
			}
		}
	}
	return ids
}

func TestOTLPExport(t *testing.T) {
	rec := &otlpRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	s, err := NewOTLP(OTLPOptions{Endpoint: srv.URL, Headers: map[string]string{"Authorization": "Bearer tok"}, ServiceVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Name() != "otlp" {
		t.Errorf("Name = %q", s.Name())
	}
	batch := []*event.Event{testEvent("o1", 10), nil, kindEvent(event.KindDetection, "o2")}
	if err := s.Write(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(nil); err != nil || len(rec.seen()) != 1 {
		t.Errorf("an empty batch must not produce a request: %v, %d requests", err, len(rec.seen()))
	}
	if err := s.Write([]*event.Event{nil}); err != nil || len(rec.seen()) != 1 {
		t.Errorf("a batch of nils must not produce a request")
	}
	got := rec.seen()[0]
	if got.method != "POST" || got.path != "/v1/logs" || got.contentType != "application/json" || got.encoding != "" ||
		got.auth != "Bearer tok" || got.ua != "spoor/1.2.3" {
		t.Errorf("request: %+v", got)
	}
	if ids := recordIDs(got.body); strings.Join(ids, ",") != "o1,o2" {
		t.Errorf("records: %v", ids)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	// gzip
	z, _ := NewOTLP(OTLPOptions{Endpoint: srv.URL + "/", Gzip: true})
	big := []*event.Event{testEvent("z1", 20000), testEvent("z2", 20000)}
	if err := z.Write(big); err != nil {
		t.Fatal(err)
	}
	got = rec.seen()[1]
	if got.encoding != "gzip" || got.path != "/v1/logs" || got.rawLen > 4000 {
		t.Errorf("gzip request: encoding=%q path=%q len=%d", got.encoding, got.path, got.rawLen)
	}
	if ids := recordIDs(got.body); strings.Join(ids, ",") != "z1,z2" {
		t.Errorf("gzip records: %v", ids)
	}
	z.Close()
	if err := z.Write(big); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Close: %v", err)
	}
}

func TestOTLPEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:4318":              "http://127.0.0.1:4318/v1/logs",
		"http://127.0.0.1:4318/":             "http://127.0.0.1:4318/v1/logs",
		"http://127.0.0.1:4318/v1/logs":      "http://127.0.0.1:4318/v1/logs",
		"http://127.0.0.1:4318/v1/logs/":     "http://127.0.0.1:4318/v1/logs/",
		"https://otel.example.com/otlp":      "https://otel.example.com/otlp/v1/logs",
		"https://otel.example.com/otlp?x=1":  "https://otel.example.com/otlp/v1/logs?x=1",
		" http://collector:4318 ":            "http://collector:4318/v1/logs",
		"https://otel.example.com/v1/traces": "https://otel.example.com/v1/traces/v1/logs",
	} {
		s, err := NewOTLP(OTLPOptions{Endpoint: in})
		if err != nil {
			t.Errorf("NewOTLP(%q): %v", in, err)
			continue
		}
		if got := s.(*otlpSink).url; got != want {
			t.Errorf("NewOTLP(%q) posts to %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "127.0.0.1:4318", "ftp://x/", "http://", "://x", "http://user:pass@host:4318", "unix:///x"} {
		if _, err := NewOTLP(OTLPOptions{Endpoint: bad}); err == nil {
			t.Errorf("NewOTLP(%q) accepted", bad)
		}
	}
	for _, h := range []map[string]string{{"X-Bad\r\nInjected": "1"}, {"X-Ok": "v\r\nInjected: 1"}, {"": "v"}, {"Has Space": "v"}} {
		if _, err := NewOTLP(OTLPOptions{Endpoint: "http://h:1", Headers: h}); err == nil {
			t.Errorf("header %v accepted", h)
		}
	}
}

func TestOTLPResponses(t *testing.T) {
	type want struct {
		ok        bool
		permanent bool
		contains  string
	}
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   want
	}{
		{"200 empty object", 200, nil, `{}`, want{ok: true}},
		{"200 no body", 200, nil, ``, want{ok: true}},
		{"201 fluent bit default", 201, nil, ``, want{ok: true}},
		{"204", 204, nil, ``, want{ok: true}},
		{"200 not json", 200, nil, `OK`, want{ok: true}},
		{"200 partial zero", 200, nil, `{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":"warn"}}`, want{ok: true}},
		{"200 partial empty", 200, nil, `{"partialSuccess":{}}`, want{ok: true}},
		{"200 partial string", 200, nil, `{"partialSuccess":{"rejectedLogRecords":"3","errorMessage":"bad\nrecords"}}`, want{permanent: true, contains: "rejected 3 log records: bad records"}},
		{"200 partial number", 200, nil, `{"partialSuccess":{"rejectedLogRecords":2}}`, want{permanent: true, contains: "rejected 2"}},
		{"202 is not listed", 202, nil, ``, want{contains: "status 202"}},
		{"400", 400, nil, "invalid request: deserialisation error\r\n", want{permanent: true, contains: "status 400: invalid request: deserialisation error"}},
		{"413", 413, nil, ``, want{permanent: true, contains: "413"}},
		{"401", 401, nil, ``, want{contains: "401"}},
		{"404 wrong endpoint", 404, nil, ``, want{contains: "404"}},
		{"405", 405, nil, ``, want{contains: "405"}},
		{"422", 422, nil, ``, want{permanent: true, contains: "422"}},
		{"429", 429, map[string]string{"Retry-After": "7"}, ``, want{contains: "429"}},
		{"503", 503, nil, strings.Repeat("x", 5000), want{contains: "503"}},
		{"307 redirect not followed", 307, map[string]string{"Location": "http://127.0.0.1:1/steal"}, ``, want{contains: "307"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &otlpRecorder{respond: func(_ int, w http.ResponseWriter) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}}
			srv := httptest.NewServer(rec)
			defer srv.Close()
			s, err := NewOTLP(OTLPOptions{Endpoint: srv.URL, Headers: map[string]string{"X-Api-Key": "sekrit"}, Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			err = s.Write([]*event.Event{testEvent("r", 5)})
			if tc.want.ok {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want.contains) {
				t.Errorf("error %q does not contain %q", err, tc.want.contains)
			}
			if IsPermanent(err) != tc.want.permanent {
				t.Errorf("IsPermanent = %v, want %v (%v)", IsPermanent(err), tc.want.permanent, err)
			}
			if strings.ContainsAny(err.Error(), "\r\n") || len(err.Error()) > 400 || strings.Contains(err.Error(), "sekrit") {
				t.Errorf("error text not sanitized: %q", err)
			}
			if len(rec.seen()) != 1 {
				t.Errorf("%d requests, want exactly one (no redirect following, no hidden retry)", len(rec.seen()))
			}
			var he *HTTPStatusError
			if tc.status == 429 && (!errors.As(err, &he) || he.RetryAfter != 7*time.Second) {
				t.Errorf("Retry-After not parsed: %+v", he)
			}
		})
	}
}

func TestOTLPTimeoutAndTLS(t *testing.T) {
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer slow.Close()
	defer close(block)
	s, _ := NewOTLP(OTLPOptions{Endpoint: slow.URL + "?token=sekrit", Timeout: 150 * time.Millisecond})
	start := time.Now()
	err := s.Write([]*event.Event{testEvent("t", 5)})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced: %v after %v", err, time.Since(start))
	}
	if IsPermanent(err) {
		t.Error("a timeout must be retried")
	}
	if strings.Contains(err.Error(), "sekrit") {
		t.Errorf("endpoint query leaked into the error: %v", err)
	}

	rec := &otlpRecorder{}
	secure := httptest.NewUnstartedServer(rec)
	secure.Config.ErrorLog = log.New(io.Discard, "", 0) // the rejected handshake below is expected
	secure.StartTLS()
	defer secure.Close()
	trusted, _ := NewOTLP(OTLPOptions{Endpoint: secure.URL, TLS: &tls.Config{RootCAs: secure.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}})
	if err := trusted.Write([]*event.Event{testEvent("tls", 5)}); err != nil {
		t.Fatal(err)
	}
	untrusted, _ := NewOTLP(OTLPOptions{Endpoint: secure.URL, Timeout: 2 * time.Second})
	if err := untrusted.Write([]*event.Event{testEvent("tls2", 5)}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if len(rec.seen()) != 1 {
		t.Errorf("requests reaching the TLS server: %d", len(rec.seen()))
	}
}

func TestRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 0, "0": 0, "5": 5 * time.Second, " 30 ": 30 * time.Second, "-5": 0, "abc": 0,
		"999999999999": 10 * time.Minute, "86400": 10 * time.Minute, "Wed, 21 Oct 2015 07:28:00 GMT": 0,
	} {
		if got := retryAfter(in); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", in, got, want)
		}
	}
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfter(future); got < 80*time.Second || got > 91*time.Second {
		t.Errorf("retryAfter(date) = %v", got)
	}
}

// The Shipper and the OTLP sink together: a receiver that rejects one
// specific record with 400 must cost exactly that record.
func TestShipperWithOTLPPoison(t *testing.T) {
	rec := &otlpRecorder{}
	rec.respond = func(n int, w http.ResponseWriter) {
		rec.mu.Lock()
		ids := recordIDs(rec.reqs[n].body)
		rec.mu.Unlock()
		for _, id := range ids {
			if id == "poison" {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
	}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	dir := t.TempDir()
	w, _ := NewFiles(FilesOptions{Dir: dir})
	want := map[string]bool{}
	for i := 0; i < 40; i++ {
		id := "ok" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		if i == 17 {
			id = "poison"
		} else {
			want[id] = true
		}
		w.Write([]*event.Event{testEvent(id, 10)})
	}
	w.Close()
	dst, err := NewOTLP(OTLPOptions{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	s, stop := startShipper(t, ShipperOptions{Dir: dir, Batch: 16}, dst, nil)
	waitFor(t, 20*time.Second, "delivery around the poisoned record", func() bool {
		st := s.Stats()
		return st.Shipped == uint64(len(want)) && st.Dropped == 1 && st.Backlog == 0
	})
	stop()
}
