package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/format"
)

// ForwardOptions configures the Forward sink.
type ForwardOptions struct {
	Addr      string        // unix:///run/fluent-bit/spoor.sock | tcp://127.0.0.1:24224 | tls://host:24224
	TagPrefix string        // default "spoor"; tag is <prefix>.<stream>
	SharedKey string        // enables the HELO/PING/PONG handshake
	Hostname  string        // self_hostname, must differ from the server's
	Compress  bool          // CompressedPackedForward (gzip)
	Timeout   time.Duration // dial, write and ack wait (default 5s)
	TLS       *tls.Config

	// Username and Password answer the server's user authentication
	// (Fluent Bit security.users). They are only used together with
	// SharedKey, because the handshake that carries them only happens then.
	Username string
	Password string
}

const (
	defaultForwardTimeout = 5 * time.Second
	defaultForwardPort    = "24224"
	// maxForwardPayload is the uncompressed entry stream per message. Fluent
	// Bit rejects messages above buffer_max_size (6144000 bytes by default,
	// and that cap also applies after decompression), so a batch is split
	// well below it.
	maxForwardPayload = 1 << 20
	// maxForwardRecord is the largest single record; a bigger event is
	// shrunk the same way the Files sink shrinks an oversize line.
	maxForwardRecord = 1 << 20
	// maxForwardEntries bounds entries per message independently of size.
	maxForwardEntries = 5000
)

// forwardSink is a Fluent Forward protocol v1 client.
//
// Wire behaviour (checked byte for byte against Fluent Bit 5.2.0, see
// research/fluentbit.md section 2):
//   - PackedForward: [tag, bin(concatenated [EventTime, record]), option].
//   - EventTime is fixext8 type 0 with the nanoseconds of Event.TS.
//   - option is {"size": n, "chunk": base64(16 random bytes)}, plus
//     "compressed": "gzip" when Compress is set. Fluent Bit requires chunk
//     to be a msgpack str and echoes it as {"ack": chunk} once the entries
//     are in its input buffer.
//   - With a shared key the server speaks first (HELO), the client answers
//     PING and checks the PONG digest, so both sides prove the key.
type forwardSink struct {
	o       ForwardOptions
	network string // unix | tcp
	address string
	useTLS  bool

	mu     sync.Mutex
	conn   net.Conn
	dec    *mpDecoder
	closed bool
}

// NewForward returns a Fluent Forward client. It does not connect: the
// first Write does, so the sensor can start before Fluent Bit.
//
// Write returns nil only after the server acknowledged every message of the
// batch. On a timeout, a closed connection or a wrong ack it reconnects once
// and resends that message, then gives up and returns the error; the caller
// (normally a Shipper) retries later. Delivery is therefore at-least-once:
// a batch that spans several streams is several messages, and a failure
// part way means the earlier ones are sent again on retry.
func NewForward(o ForwardOptions) (Sink, error) {
	s := &forwardSink{o: o}
	addr := strings.TrimSpace(o.Addr)
	switch {
	case strings.HasPrefix(addr, "unix://"):
		s.network, s.address = "unix", strings.TrimPrefix(addr, "unix://")
		if s.address == "" {
			return nil, errors.New("sink forward: empty unix socket path")
		}
	case strings.HasPrefix(addr, "tcp://"):
		s.network, s.address = "tcp", strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "tls://"):
		s.network, s.address, s.useTLS = "tcp", strings.TrimPrefix(addr, "tls://"), true
	case addr == "" || strings.Contains(addr, "://"):
		return nil, fmt.Errorf("sink forward: unsupported address %q (want unix://, tcp:// or tls://)", o.Addr)
	default:
		s.network, s.address = "tcp", addr
	}
	if s.network == "tcp" {
		s.address = strings.TrimSuffix(s.address, "/")
		if _, _, err := net.SplitHostPort(s.address); err != nil {
			s.address = net.JoinHostPort(strings.Trim(s.address, "[]"), defaultForwardPort)
		}
		if host, _, err := net.SplitHostPort(s.address); err != nil || host == "" {
			return nil, fmt.Errorf("sink forward: invalid address %q", o.Addr)
		}
	}
	if s.o.TagPrefix == "" {
		s.o.TagPrefix = "spoor"
	}
	if s.o.Timeout <= 0 {
		s.o.Timeout = defaultForwardTimeout
	}
	if s.o.Hostname == "" {
		// Fluent Bit refuses a client whose self_hostname equals its own,
		// which the bare host name would on a shared machine.
		h, err := os.Hostname()
		if err != nil || h == "" {
			h = "client"
		}
		s.o.Hostname = "spoor-" + h
	}
	if s.o.Username != "" && s.o.SharedKey == "" {
		return nil, errors.New("sink forward: Username requires SharedKey")
	}
	return s, nil
}

func (s *forwardSink) Name() string { return "forward" }

// forwardMessage is one PackedForward request before framing.
type forwardMessage struct {
	tag     string
	entries []byte
	count   int
}

func (s *forwardSink) Write(batch []*event.Event) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink forward: %v", r)
		}
	}()
	if s.closed {
		return ErrClosed
	}
	msgs, err := s.pack(batch)
	if err != nil {
		return fmt.Errorf("sink forward: %w", err)
	}
	for i := range msgs {
		if err := s.deliver(&msgs[i]); err != nil {
			return fmt.Errorf("sink forward: %w", err)
		}
	}
	return nil
}

// pack groups events by stream (the tag) in first-seen order and splits
// each group at the payload and entry limits.
func (s *forwardSink) pack(batch []*event.Event) ([]forwardMessage, error) {
	var msgs []forwardMessage
	current := make(map[string]int) // tag -> index of its open message
	for _, e := range batch {
		if e == nil {
			continue
		}
		entry, err := fit(e, maxForwardRecord, packEntry)
		if err != nil {
			return nil, err
		}
		tag := s.o.TagPrefix + "." + e.Kind.Stream()
		i, ok := current[tag]
		if ok && (len(msgs[i].entries)+len(entry) > maxForwardPayload || msgs[i].count >= maxForwardEntries) {
			ok = false
		}
		if !ok {
			msgs = append(msgs, forwardMessage{tag: tag})
			i = len(msgs) - 1
			current[tag] = i
		}
		msgs[i].entries = append(msgs[i].entries, entry...)
		msgs[i].count++
	}
	return msgs, nil
}

// packEntry encodes one [EventTime, record] entry.
func packEntry(e *event.Event) ([]byte, error) {
	rec, err := format.Native(e)
	if err != nil {
		return nil, err
	}
	ts := e.TS.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	b := make([]byte, 0, 512)
	b = mpAppendArrayHeader(b, 2)
	b = mpAppendEventTime(b, ts)
	return mpAppendValue(b, rec, 0)
}

// frame builds the request bytes for one message and returns its chunk id.
func (s *forwardSink) frame(m *forwardMessage) (frame []byte, chunk string, err error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, "", err
	}
	chunk = base64.StdEncoding.EncodeToString(id[:])
	payload := m.entries
	if s.o.Compress {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(payload); err != nil {
			return nil, "", err
		}
		if err := zw.Close(); err != nil {
			return nil, "", err
		}
		payload = buf.Bytes()
	}
	b := make([]byte, 0, len(payload)+len(m.tag)+96)
	b = mpAppendArrayHeader(b, 3)
	b = mpAppendStr(b, m.tag)
	b = mpAppendBin(b, payload)
	if s.o.Compress {
		b = mpAppendMapHeader(b, 3)
	} else {
		b = mpAppendMapHeader(b, 2)
	}
	b = mpAppendStr(b, "size")
	b = mpAppendInt(b, int64(m.count))
	if s.o.Compress {
		b = mpAppendStr(b, "compressed")
		b = mpAppendStr(b, "gzip")
	}
	b = mpAppendStr(b, "chunk")
	b = mpAppendStr(b, chunk)
	return b, chunk, nil
}

// deliver sends one message and waits for its ack, reconnecting and
// resending once. The same chunk id is reused for the resend so a server
// that tracks chunks could recognize the duplicate.
func (s *forwardSink) deliver(m *forwardMessage) error {
	frame, chunk, err := s.frame(m)
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			if err := s.connect(); err != nil {
				// A refused or failed connect will not improve by trying
				// again immediately; report it and let the caller back off.
				if last != nil {
					return fmt.Errorf("%w (after: %v)", err, last)
				}
				return err
			}
		}
		if last = s.roundTrip(frame, chunk); last == nil {
			return nil
		}
		s.drop()
	}
	return last
}

func (s *forwardSink) roundTrip(frame []byte, chunk string) error {
	if err := s.conn.SetDeadline(time.Now().Add(s.o.Timeout)); err != nil {
		return err
	}
	if _, err := s.conn.Write(frame); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	v, err := s.dec.decode()
	if err != nil {
		return fmt.Errorf("waiting for ack: %w", err)
	}
	switch t := v.(type) {
	case map[string]any:
		if ack, _ := t["ack"].(string); ack == chunk {
			return nil
		}
		return errors.New("ack does not match the chunk sent")
	case []any:
		if len(t) > 0 {
			if kind, _ := t[0].(string); kind == "HELO" {
				return errors.New("server requires a shared key (received HELO); set SharedKey")
			}
		}
	}
	return errors.New("unexpected reply while waiting for ack")
}

func (s *forwardSink) drop() {
	if s.conn != nil {
		s.conn.Close()
		s.conn, s.dec = nil, nil
	}
}

func (s *forwardSink) connect() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.o.Timeout)
	defer cancel()
	d := &net.Dialer{Timeout: s.o.Timeout}
	var (
		conn net.Conn
		err  error
	)
	if s.useTLS {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if s.o.TLS != nil {
			cfg = s.o.TLS.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(s.address)
		}
		conn, err = (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, s.network, s.address)
	} else {
		conn, err = d.DialContext(ctx, s.network, s.address)
	}
	if err != nil {
		return fmt.Errorf("connect %s: %w", s.address, err)
	}
	dec := newMPDecoder(conn, replyLimits)
	if s.o.SharedKey != "" {
		if err := s.handshake(conn, dec); err != nil {
			conn.Close()
			return fmt.Errorf("handshake: %w", err)
		}
	}
	s.conn, s.dec = conn, dec
	return nil
}

// handshake runs HELO/PING/PONG. Digests are SHA-512 hex over
// salt + hostname + nonce + key, each side using its own hostname, which is
// why the two hostnames must differ.
func (s *forwardSink) handshake(conn net.Conn, dec *mpDecoder) error {
	if err := conn.SetDeadline(time.Now().Add(s.o.Timeout)); err != nil {
		return err
	}
	v, err := dec.decode()
	if err != nil {
		return fmt.Errorf("no HELO from server (is shared_key set on the forward input?): %w", err)
	}
	helo, _ := v.([]any)
	if len(helo) < 2 {
		return errors.New("malformed HELO")
	}
	if kind, _ := helo[0].(string); kind != "HELO" {
		return errors.New("expected HELO")
	}
	opts, _ := helo[1].(map[string]any)
	nonce := mpBytes(opts["nonce"])
	authSalt := mpBytes(opts["auth"])
	if len(nonce) == 0 {
		return errors.New("HELO without nonce")
	}

	var saltRaw [16]byte
	if _, err := rand.Read(saltRaw[:]); err != nil {
		return err
	}
	// Every PING field must be a msgpack str for Fluent Bit, so the salt is
	// sent as hex text rather than raw bytes.
	salt := hex.EncodeToString(saltRaw[:])
	digest := sha512Hex([]byte(salt), []byte(s.o.Hostname), nonce, []byte(s.o.SharedKey))
	user, pass := "", ""
	if s.o.Username != "" {
		user = s.o.Username
		pass = sha512Hex(authSalt, []byte(user), []byte(s.o.Password))
	}
	ping := make([]byte, 0, 256)
	ping = mpAppendArrayHeader(ping, 6)
	ping = mpAppendStr(ping, "PING")
	ping = mpAppendStr(ping, s.o.Hostname)
	ping = mpAppendStr(ping, salt)
	ping = mpAppendStr(ping, digest)
	ping = mpAppendStr(ping, user)
	ping = mpAppendStr(ping, pass)
	if _, err := conn.Write(ping); err != nil {
		return err
	}

	v, err = dec.decode()
	if err != nil {
		// Fluent Bit closes the connection without a PONG on a key mismatch.
		return fmt.Errorf("no PONG from server (shared key mismatch?): %w", err)
	}
	pong, _ := v.([]any)
	if len(pong) < 5 {
		return errors.New("malformed PONG")
	}
	if kind, _ := pong[0].(string); kind != "PONG" {
		return errors.New("expected PONG")
	}
	if ok, _ := pong[1].(bool); !ok {
		reason, _ := pong[2].(string)
		return fmt.Errorf("server rejected authentication: %s", safeString(reason, 128))
	}
	serverHost := mpBytes(pong[3])
	serverDigest := mpBytes(pong[4])
	want := sha512Hex([]byte(salt), serverHost, nonce, []byte(s.o.SharedKey))
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(string(serverDigest))), []byte(want)) != 1 {
		return errors.New("server failed to prove the shared key")
	}
	return nil
}

func mpBytes(v any) []byte {
	switch t := v.(type) {
	case string:
		return []byte(t)
	case []byte:
		return t
	}
	return nil
}

func sha512Hex(parts ...[]byte) string {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Flush is a no-op: Write is synchronous and returns after the ack.
func (s *forwardSink) Flush() error { return nil }

func (s *forwardSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.drop()
	return nil
}
