package otelrecv

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const (
	// DefaultAddr is one above the conventional OTLP/HTTP port (4318) so the
	// receiver does not collide with a collector or Fluent Bit's
	// opentelemetry input already running on the machine.
	DefaultAddr = "127.0.0.1:4319"
	// DefaultMaxBody is the request body cap, applied to the bytes on the
	// wire and again to the bytes after decompression.
	DefaultMaxBody = 4 << 20

	maxInFlight = 4  // requests converted at once; more get 429
	maxConns    = 64 // simultaneous connections
)

// Options configures a Receiver.
type Options struct {
	// Addr is the listen address. It must name a loopback address
	// ("127.0.0.1:4319", "[::1]:4319", "localhost:4319"); anything else is
	// refused by Run. Port 0 picks a free port (see Addr). Default
	// 127.0.0.1:4319.
	Addr string
	// Emit receives every converted event. It is called from the request
	// goroutines, so it may run concurrently with itself, and the sender's
	// request does not complete until it returns: a slow Emit is
	// backpressure on the agent's exporter, which is the intended behaviour.
	Emit func(*event.Event)
	// MaxBody caps a request body in bytes. Default 4 MiB.
	MaxBody int64
}

// Receiver is a loopback OTLP/HTTP endpoint for agent-native telemetry.
type Receiver struct {
	opts Options
	sem  chan struct{}

	mu      sync.Mutex
	running bool
	addr    string
	ready   chan struct{}
	isReady bool
	stats   Stats
}

// Stats is the receiver's accounting since it was created.
type Stats struct {
	Requests uint64 // log export requests converted
	Records  uint64 // log records seen in them
	Events   uint64 // events handed to Emit
	Ignored  uint64 // records with a known event name that is not converted
	Unknown  uint64 // records with an event name or sender this package does not know
	Dropped  uint64 // records beyond MaxRecords in one request
	// Rejected counts refused requests: not loopback, browser-originated,
	// wrong method, path or content type, too large, malformed, or over the
	// concurrency limit.
	Rejected uint64
	// Protobuf is the part of Rejected that was a protobuf body: an agent
	// pointed here without http/json pinned. Non-zero means telemetry is
	// being lost to a configuration error.
	Protobuf uint64
	// Discarded counts metrics and traces requests, which are acknowledged
	// and dropped.
	Discarded uint64
	// UnknownNames breaks Unknown down by event name (bounded).
	UnknownNames map[string]uint64
	LastEvent    time.Time
}

// New returns a Receiver. It does not listen until Run is called.
func New(o Options) *Receiver {
	if o.Addr == "" {
		o.Addr = DefaultAddr
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	return &Receiver{
		opts:  o,
		sem:   make(chan struct{}, maxInFlight),
		ready: make(chan struct{}),
	}
}

// Run listens and serves until ctx is cancelled, then shuts down and returns
// nil. It returns an error when the address is not loopback, when it cannot
// listen, or when the receiver is already running.
func (r *Receiver) Run(ctx context.Context) error {
	addr, err := loopbackAddr(r.opts.Addr)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("otelrecv: receiver is already running")
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("otelrecv: listen on %s: %w", addr, err)
	}
	r.mu.Lock()
	r.addr = ln.Addr().String()
	if !r.isReady {
		r.isReady = true
		close(r.ready)
	}
	r.mu.Unlock()

	srv := &http.Server{
		Handler: r.Handler(),
		// Every client is a local process that may be hostile: bound how
		// long it can hold a connection and how much header it can send.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// net/http logs malformed requests; a client must not be able to
		// write into the daemon's log that way.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(newLimitListener(ln, maxConns)) }()

	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close()
		}
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("otelrecv: serve: %w", err)
	}
}

// Ready is closed once the receiver is listening for the first time.
func (r *Receiver) Ready() <-chan struct{} { return r.ready }

// Addr returns the address the receiver is bound to, or "" before Run has
// started listening. With port 0 in Options.Addr this is where the chosen
// port can be read.
func (r *Receiver) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addr
}

// Stats returns a snapshot of the receiver's accounting.
func (r *Receiver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	if r.stats.UnknownNames != nil {
		s.UnknownNames = make(map[string]uint64, len(r.stats.UnknownNames))
		for k, v := range r.stats.UnknownNames {
			s.UnknownNames[k] = v
		}
	}
	return s
}

// Surface renders the receiver's state for the sensor heartbeat. Unknown
// event names are reported as schema drift; protobuf rejections as a
// degraded surface, because they mean an agent is exporting to a receiver
// that cannot read it.
func (r *Receiver) Surface() event.SurfaceStatus {
	st := r.Stats()
	s := event.SurfaceStatus{
		Name:        "otel",
		Status:      "ok",
		Events:      st.Events,
		Errors:      st.Rejected,
		SchemaDrift: st.Unknown > 0,
	}
	if !st.LastEvent.IsZero() {
		s.LastEvent = event.At(st.LastEvent)
	}
	switch {
	case st.Protobuf > 0:
		s.Status, s.Reason = "degraded", "otel.protobuf_rejected"
	case st.Unknown > 0:
		s.Status, s.Reason = "degraded", "otel.schema_drift"
	}
	return s
}

// Handler returns the HTTP handler, for tests and for callers that run
// their own server. The handler applies every check Run's server applies
// except the connection limit and timeouts.
func (r *Receiver) Handler() http.Handler { return http.HandlerFunc(r.serve) }

const protobufHelp = "hawkbell accepts OTLP over HTTP with JSON encoding only (Content-Type: application/json), " +
	"and this request is protobuf. Pin the JSON protocol where the agent is configured: " +
	"OTEL_EXPORTER_OTLP_PROTOCOL=http/json for Claude Code; protocol = \"json\" on the otlp-http exporter " +
	"in the [otel] table for Codex; telemetry.otlpProtocol \"http\" for Gemini CLI."

func (r *Receiver) serve(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			r.fail(w, http.StatusInternalServerError, "internal error", false)
		}
	}()
	// Defence in depth behind the loopback bind: a caller that embeds the
	// handler in its own server must not expose it by accident.
	if !loopbackRemote(req.RemoteAddr) {
		r.fail(w, http.StatusForbidden, "hawkbell accepts telemetry from this machine only", false)
		return
	}
	// A web page can make the user's browser post to 127.0.0.1. Browsers
	// send Origin (and Sec-Fetch-Site) on such requests and exporters do
	// not; a rebound DNS name shows up as a non-loopback Host.
	if req.Header.Get("Origin") != "" || req.Header.Get("Sec-Fetch-Site") != "" || !loopbackHost(req.Host) {
		r.fail(w, http.StatusForbidden, "browser-originated and non-loopback requests are refused", false)
		return
	}
	logs := false
	switch strings.TrimRight(req.URL.Path, "/") {
	case "/v1/logs":
		logs = true
	case "/v1/metrics", "/v1/traces":
	default:
		r.fail(w, http.StatusNotFound, "unknown path; OTLP logs are accepted on /v1/logs", false)
		return
	}
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		r.fail(w, http.StatusMethodNotAllowed, "OTLP export requests are POST", false)
		return
	}
	mt, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
	case "application/x-protobuf", "application/protobuf", "application/grpc", "application/grpc+proto":
		r.mu.Lock()
		r.stats.Protobuf++
		r.mu.Unlock()
		r.fail(w, http.StatusUnsupportedMediaType, protobufHelp, false)
		return
	default:
		// Also what stops a cross-site form post: application/json is not a
		// "simple" content type, so a browser would need a CORS preflight,
		// which this handler never answers.
		r.fail(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json (OTLP/HTTP JSON)", false)
		return
	}
	if req.ContentLength > r.opts.MaxBody {
		r.fail(w, http.StatusRequestEntityTooLarge, "request body exceeds "+strconv.FormatInt(r.opts.MaxBody, 10)+" bytes", true)
		return
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		// 429 is retryable in OTLP/HTTP; the exporter backs off and resends.
		w.Header().Set("Retry-After", "1")
		r.fail(w, http.StatusTooManyRequests, "receiver busy", true)
		return
	}
	body, status, msg := r.readBody(w, req)
	if status != 0 {
		r.fail(w, status, msg, true)
		return
	}
	if !logs {
		// An agent given one base endpoint sends metrics and traces here
		// too. Acknowledging them stops its exporter from retrying; nothing
		// in them is used.
		r.mu.Lock()
		r.stats.Discarded++
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, []byte("{}"))
		return
	}
	res, err := ConvertDetail(body)
	if err != nil {
		r.fail(w, http.StatusBadRequest, err.Error(), true)
		return
	}
	for _, ev := range res.Events {
		r.emit(ev)
	}
	r.account(res)
	if res.Dropped > 0 {
		out, _ := json.Marshal(map[string]any{"partialSuccess": map[string]any{
			"rejectedLogRecords": strconv.Itoa(res.Dropped),
			"errorMessage":       "more than " + strconv.Itoa(MaxRecords) + " log records in one request",
		}})
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, []byte("{}"))
}

// readBody reads the request body within MaxBody, decompressing gzip. The
// cap is applied on both sides of the decompressor so a small request cannot
// expand into a large allocation.
func (r *Receiver) readBody(w http.ResponseWriter, req *http.Request) (body []byte, status int, msg string) {
	limit := r.opts.MaxBody
	tooLarge := "request body exceeds " + strconv.FormatInt(limit, 10) + " bytes"
	var src io.Reader = http.MaxBytesReader(w, req.Body, limit)
	switch strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return nil, http.StatusRequestEntityTooLarge, tooLarge
			}
			return nil, http.StatusBadRequest, "invalid gzip body"
		}
		defer zr.Close()
		src = zr
	default:
		return nil, http.StatusUnsupportedMediaType, "unsupported Content-Encoding; use gzip or none"
	}
	data, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, http.StatusRequestEntityTooLarge, tooLarge
		}
		return nil, http.StatusBadRequest, "unreadable request body"
	}
	if int64(len(data)) > limit {
		return nil, http.StatusRequestEntityTooLarge, tooLarge + " after decompression"
	}
	return data, 0, ""
}

func (r *Receiver) emit(ev *event.Event) {
	if r.opts.Emit == nil {
		return
	}
	// A panicking consumer must not take the request goroutine's server
	// connection state with it or skip the accounting.
	defer func() { _ = recover() }()
	r.opts.Emit(ev)
}

func (r *Receiver) account(res *Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := &r.stats
	st.Requests++
	st.Records += uint64(res.Records)
	st.Events += uint64(len(res.Events))
	st.Ignored += uint64(res.Ignored)
	st.Dropped += uint64(res.Dropped)
	for name, n := range res.Unknown {
		st.Unknown += uint64(n)
		if st.UnknownNames == nil {
			st.UnknownNames = map[string]uint64{}
		}
		if _, ok := st.UnknownNames[name]; !ok && len(st.UnknownNames) >= maxUnknownNames {
			name = "_other"
		}
		st.UnknownNames[name] += uint64(n)
	}
	for _, ev := range res.Events {
		if t := ev.TS.Time; t.After(st.LastEvent) {
			st.LastEvent = t
		}
	}
}

// fail writes an error response and counts it. OTLP/HTTP asks for a Status
// message in the request's encoding; for requests that were not JSON a plain
// sentence is the most useful thing an operator can find in an agent's
// exporter log.
func (r *Receiver) fail(w http.ResponseWriter, status int, msg string, asJSON bool) {
	r.mu.Lock()
	r.stats.Rejected++
	r.mu.Unlock()
	if asJSON {
		out, _ := json.Marshal(map[string]any{"code": grpcCode(status), "message": msg})
		writeJSON(w, status, out)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// grpcCode maps an HTTP status to the google.rpc.Code an OTLP Status carries.
func grpcCode(status int) int {
	switch status {
	case http.StatusBadRequest:
		return 3 // INVALID_ARGUMENT
	case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
		return 8 // RESOURCE_EXHAUSTED
	case http.StatusUnsupportedMediaType:
		return 12 // UNIMPLEMENTED
	}
	return 13 // INTERNAL
}

// loopbackAddr validates a listen address and returns it in canonical form.
// "localhost" is mapped to 127.0.0.1 instead of being resolved: a hosts file
// that points it elsewhere must not turn this into a network listener.
func loopbackAddr(addr string) (string, error) {
	if addr == "" {
		addr = DefaultAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("otelrecv: invalid listen address %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("otelrecv: listen address %q is not a loopback address; the receiver has no authentication and must not be reachable from the network", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("otelrecv: invalid port in listen address %q", addr)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// loopbackRemote reports whether a connection's peer address is loopback.
func loopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackHost reports whether a Host header names this machine's loopback
// interface: a loopback IP literal or "localhost", with or without a port.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// limitListener caps simultaneous connections, so a local process cannot
// exhaust the daemon's file descriptors by opening sockets here.
type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func newLimitListener(ln net.Listener, n int) *limitListener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
