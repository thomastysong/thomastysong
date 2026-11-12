package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/format"
)

// OTLPOptions configures the OTLP sink. Endpoint is like
// http://127.0.0.1:4318; the path /v1/logs is appended when missing.
type OTLPOptions struct {
	Endpoint       string
	Headers        map[string]string
	Gzip           bool
	Timeout        time.Duration
	TLS            *tls.Config
	ServiceVersion string
}

const (
	defaultOTLPTimeout = 10 * time.Second
	otlpLogsPath       = "/v1/logs"
	// maxOTLPReply bounds how much of a response body is read. A success
	// body is a few bytes; an error body is only quoted in the error text.
	maxOTLPReply = 64 << 10
)

// HTTPStatusError is returned by the OTLP sink for a response that is not
// a success.
type HTTPStatusError struct {
	Code int
	// RetryAfter is the server's Retry-After delay, zero when absent.
	RetryAfter time.Duration
	// Body is the start of the response body, sanitized for logging.
	Body string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("otlp: http status %d", e.Code)
	}
	return fmt.Sprintf("otlp: http status %d: %s", e.Code, e.Body)
}

// Permanent reports whether the payload itself was refused, so that sending
// the same bytes again cannot succeed: 400 (malformed), 413 (too large) and
// 422. Everything else is treated as a condition that can change while the
// data waits on disk: 429 and 5xx by the OTLP rules, 401 and 403 because a
// credential can be fixed, and 404 or 405 because they describe the
// endpoint, not the data. Calling those permanent would let a wrong URL
// talk the shipper into discarding events.
func (e *HTTPStatusError) Permanent() bool {
	switch e.Code {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// RejectedError is returned when the receiver accepted the request but
// rejected some of its log records (OTLP partial success).
type RejectedError struct {
	Rejected int64
	Message  string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("otlp: receiver rejected %d log records: %s", e.Rejected, e.Message)
}

// Permanent is true: OTLP forbids retrying a partial success, and a retry
// would duplicate every record the receiver did accept. The Shipper counts
// the rejected records as dropped and moves on.
func (e *RejectedError) Permanent() bool { return true }

type otlpSink struct {
	o      OTLPOptions
	url    string
	client *http.Client

	mu     sync.Mutex
	closed bool
}

// NewOTLP returns an OTLP/HTTP JSON logs exporter. Each Write is one POST
// of an ExportLogsServiceRequest (see format.OTLPLogs).
//
// Status 200, 201 and 204 are success (the spec says 200; Fluent Bit's
// opentelemetry input answers 201 by default). A success body that reports
// partialSuccess.rejectedLogRecords > 0 is an error. Redirects are not
// followed, so credentials in Headers are never replayed to another host.
// The sink does not retry: it reports the failure and the Shipper decides,
// using IsPermanent and the Retry-After carried by HTTPStatusError.
func NewOTLP(o OTLPOptions) (Sink, error) {
	u, err := url.Parse(strings.TrimSpace(o.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("sink otlp: invalid endpoint: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("sink otlp: endpoint %q must be an http or https URL", o.Endpoint)
	}
	if u.User != nil {
		return nil, errors.New("sink otlp: credentials belong in Headers, not in the endpoint URL")
	}
	if !strings.HasSuffix(strings.TrimRight(u.Path, "/"), otlpLogsPath) {
		u.Path = strings.TrimRight(u.Path, "/") + otlpLogsPath
	}
	u.Fragment = ""
	for k, v := range o.Headers {
		if strings.ContainsAny(k, "\r\n: ") || k == "" || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("sink otlp: invalid header %q", k)
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultOTLPTimeout
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if o.TLS != nil {
		tr.TLSClientConfig = o.TLS.Clone()
	}
	return &otlpSink{
		o:   o,
		url: u.String(),
		client: &http.Client{
			Transport: tr,
			Timeout:   o.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (s *otlpSink) Name() string { return "otlp" }

func (s *otlpSink) Write(batch []*event.Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink otlp: %v", r)
		}
	}()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	n := 0
	for _, e := range batch {
		if e != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	body, err := format.OTLPLogs(batch, s.o.ServiceVersion)
	if err != nil {
		return fmt.Errorf("sink otlp: %w", &encodeError{err})
	}
	if err := s.post(body); err != nil {
		return fmt.Errorf("sink otlp: %w", err)
	}
	return nil
}

// encodeError marks a batch that could not be encoded: resending the same
// events would fail the same way.
type encodeError struct{ err error }

func (e *encodeError) Error() string   { return e.err.Error() }
func (e *encodeError) Unwrap() error   { return e.err }
func (e *encodeError) Permanent() bool { return true }

func (s *otlpSink) post(body []byte) error {
	var rd io.Reader = bytes.NewReader(body)
	encoding := ""
	if s.o.Gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		rd, encoding = &buf, "gzip"
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, rd)
	if err != nil {
		return err
	}
	for k, v := range s.o.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	if req.Header.Get("User-Agent") == "" {
		ua := "hawkbell"
		if s.o.ServiceVersion != "" {
			ua += "/" + safeString(s.o.ServiceVersion, 32)
		}
		req.Header.Set("User-Agent", ua)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// url.Error includes the URL; an endpoint may carry a token in its
		// query string, so only the cause is reported.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxOTLPReply))

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return partialSuccess(reply)
	}
	return &HTTPStatusError{
		Code:       resp.StatusCode,
		RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		Body:       printable(reply, 256),
	}
}

// partialSuccess inspects a success body. The count is an int64, which the
// proto3 JSON mapping writes as a string, though receivers also send a
// number; both are accepted. An unparsable body on a success status is not
// an error: the status already said the data was taken.
func partialSuccess(reply []byte) error {
	if len(bytes.TrimSpace(reply)) == 0 {
		return nil
	}
	var r struct {
		PartialSuccess *struct {
			Rejected     json.RawMessage `json:"rejectedLogRecords"`
			ErrorMessage string          `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if err := json.Unmarshal(reply, &r); err != nil || r.PartialSuccess == nil {
		return nil
	}
	raw := strings.Trim(string(bytes.TrimSpace(r.PartialSuccess.Rejected)), `"`)
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &RejectedError{Rejected: n, Message: printable([]byte(r.PartialSuccess.ErrorMessage), 256)}
}

// retryAfter parses a Retry-After header given in seconds or as an HTTP
// date, capped so a hostile or broken server cannot park the shipper.
func retryAfter(v string) time.Duration {
	const maxDelay = 10 * time.Minute
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs > int64(maxDelay/time.Second) {
			return maxDelay
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		return 0
	}
	if d > maxDelay {
		return maxDelay
	}
	return d
}

// printable makes a server-supplied byte string safe to put in an error or
// a log line: one line, no control characters, bounded length.
func printable(b []byte, n int) string {
	s := clipString(strings.ToValidUTF8(string(b), "?"), n)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}

// Flush is a no-op: Write is synchronous.
func (s *otlpSink) Flush() error { return nil }

func (s *otlpSink) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.client.CloseIdleConnections()
	return nil
}
