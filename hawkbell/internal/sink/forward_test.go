package sink

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/format"
)

// fakeForward is an in-test Fluent Forward v1 server that follows what
// Fluent Bit 5.2.0 does on the wire: HELO first when a shared key is set,
// PING verification, PONG with its own digest, silent close on a bad key,
// and {"ack": chunk} after each message.
type fakeForward struct {
	t  testing.TB
	ln net.Listener

	sharedKey string
	hostname  string
	users     map[string]string
	binNonce  bool // type the nonce as msgpack bin (fluentd) instead of str (Fluent Bit)

	// behave decides what to do with the n-th message (0 based) received
	// over the server's lifetime: "ack", "close" (drop the connection
	// without acking), "silent" (keep it open, never ack), "wrong" (ack a
	// different chunk), "garbage" (reply with an oversized value).
	behave func(n int) string

	mu     sync.Mutex
	msgs   []fakeMessage
	conns  int
	active map[net.Conn]struct{}
	wg     sync.WaitGroup
}

type fakeMessage struct {
	tag        string
	chunk      string
	size       int64
	compressed string
	entries    []fakeEntry
	payloadLen int
	chunkIsStr bool
}

type fakeEntry struct {
	sec, nsec uint32
	record    map[string]any
}

func newFakeForward(t testing.TB, network, addr string, tlsConf *tls.Config) *fakeForward {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}
	f := &fakeForward{t: t, ln: ln, hostname: "fake.server", active: map[net.Conn]struct{}{}}
	t.Cleanup(f.close)
	return f
}

func (f *fakeForward) start() *fakeForward {
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := f.ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.active[c] = struct{}{}
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer func() {
					c.Close()
					f.mu.Lock()
					delete(f.active, c)
					f.mu.Unlock()
				}()
				f.serve(c)
			}()
		}
	}()
	return f
}

// close stops the server and drops its connections, like a process exit.
func (f *fakeForward) close() {
	f.ln.Close()
	f.mu.Lock()
	for c := range f.active {
		c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *fakeForward) addr() string { return f.ln.Addr().String() }

func (f *fakeForward) snapshot() ([]fakeMessage, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMessage(nil), f.msgs...), f.conns
}

func (f *fakeForward) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	dec := newMPDecoder(c, bigLimits)
	if f.sharedKey != "" && !f.handshake(c, dec) {
		return // like Fluent Bit: close without a PONG
	}
	for {
		v, err := dec.decode()
		if err != nil {
			return
		}
		msg, ok := f.parse(v)
		if !ok {
			return
		}
		f.mu.Lock()
		n := len(f.msgs)
		f.msgs = append(f.msgs, msg)
		behave := f.behave
		f.mu.Unlock()
		action := "ack"
		if behave != nil {
			action = behave(n)
		}
		switch action {
		case "close":
			return
		case "silent":
			io.Copy(io.Discard, c) // until the client gives up
			return
		case "wrong":
			c.Write(mpAppendStr(mpAppendStr(mpAppendMapHeader(nil, 1), "ack"), "bm90IHlvdXIgY2h1bms="))
		case "garbage":
			c.Write([]byte{0xdb, 0xff, 0xff, 0xff, 0xff}) // a str claiming 4 GiB
			return
		default:
			c.Write(mpAppendStr(mpAppendStr(mpAppendMapHeader(nil, 1), "ack"), msg.chunk))
		}
	}
}

func (f *fakeForward) handshake(c net.Conn, dec *mpDecoder) bool {
	nonce := make([]byte, 16)
	authSalt := make([]byte, 16)
	rand.Read(nonce)
	rand.Read(authSalt)
	helo := mpAppendArrayHeader(nil, 2)
	helo = mpAppendStr(helo, "HELO")
	helo = mpAppendMapHeader(helo, 2)
	helo = mpAppendStr(helo, "nonce")
	if f.binNonce {
		helo = mpAppendBin(helo, nonce)
	} else {
		helo = mpAppendStr(helo, string(nonce)) // raw bytes typed as str, as Fluent Bit sends them
	}
	helo = mpAppendStr(helo, "auth")
	helo = mpAppendStr(helo, string(authSalt))
	c.Write(helo)

	v, err := dec.decode()
	if err != nil {
		return false
	}
	ping, _ := v.([]any)
	if len(ping) != 6 {
		return false
	}
	var s [6]string
	for i, p := range ping {
		str, ok := p.(string) // Fluent Bit rejects a PING whose fields are not str
		if !ok {
			return false
		}
		s[i] = str
	}
	kind, clientHost, salt, digest, user, pass := s[0], s[1], s[2], s[3], s[4], s[5]
	if kind != "PING" || clientHost == f.hostname {
		return false
	}
	if digest != sha512Hex([]byte(salt), []byte(clientHost), nonce, []byte(f.sharedKey)) {
		return false
	}
	pong := func(ok bool, reason string) {
		b := mpAppendArrayHeader(nil, 5)
		b = mpAppendStr(b, "PONG")
		b = mpAppendBool(b, ok)
		b = mpAppendStr(b, reason)
		b = mpAppendStr(b, f.hostname)
		b = mpAppendStr(b, sha512Hex([]byte(salt), []byte(f.hostname), nonce, []byte(f.sharedKey)))
		c.Write(b)
	}
	if f.users != nil {
		want, known := f.users[user]
		if !known || pass != sha512Hex(authSalt, []byte(user), []byte(want)) {
			pong(false, "username/password mismatch")
			return false
		}
	} else if user != "" || pass != "" {
		return false
	}
	pong(true, "")
	return true
}

func (f *fakeForward) parse(v any) (fakeMessage, bool) {
	arr, _ := v.([]any)
	if len(arr) != 3 {
		f.t.Errorf("fake server: message is not a 3-element array: %T", v)
		return fakeMessage{}, false
	}
	var m fakeMessage
	m.tag, _ = arr[0].(string)
	payload, ok := arr[1].([]byte)
	if !ok {
		f.t.Errorf("fake server: PackedForward payload must be bin, got %T", arr[1])
		return m, false
	}
	m.payloadLen = len(payload)
	opt, _ := arr[2].(map[string]any)
	m.chunk, m.chunkIsStr = opt["chunk"].(string)
	m.size, _ = opt["size"].(int64)
	m.compressed, _ = opt["compressed"].(string)
	if m.compressed == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			f.t.Errorf("fake server: bad gzip: %v", err)
			return m, false
		}
		if payload, err = io.ReadAll(zr); err != nil {
			f.t.Errorf("fake server: bad gzip: %v", err)
			return m, false
		}
	}
	dec := newMPDecoder(bytes.NewReader(payload), bigLimits)
	for {
		ev, err := dec.decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.t.Errorf("fake server: bad entry: %v", err)
			return m, false
		}
		pair, _ := ev.([]any)
		if len(pair) != 2 {
			f.t.Errorf("fake server: entry is not [time, record]")
			return m, false
		}
		ext, ok := pair[0].(mpExt)
		if !ok || ext.Type != 0 || len(ext.Data) != 8 {
			f.t.Errorf("fake server: time is not EventTime ext type 0: %#v", pair[0])
			return m, false
		}
		rec, _ := pair[1].(map[string]any)
		m.entries = append(m.entries, fakeEntry{
			sec:    uint32(ext.Data[0])<<24 | uint32(ext.Data[1])<<16 | uint32(ext.Data[2])<<8 | uint32(ext.Data[3]),
			nsec:   uint32(ext.Data[4])<<24 | uint32(ext.Data[5])<<16 | uint32(ext.Data[6])<<8 | uint32(ext.Data[7]),
			record: rec,
		})
	}
	return m, true
}

func newForward(t testing.TB, o ForwardOptions) Sink {
	t.Helper()
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	s, err := NewForward(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// sameJSON compares a decoded msgpack record with the native event object.
func sameJSON(t testing.TB, got map[string]any, e *event.Event) {
	t.Helper()
	want, err := format.Native(e)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		t.Errorf("record differs from the native event\n got %s\nwant %s", g, w)
	}
}

func TestForwardPackedForwardWithAck(t *testing.T) {
	srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
	s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr()})
	if s.Name() != "forward" {
		t.Errorf("Name = %q", s.Name())
	}
	a1 := testEvent("a1", 40)
	a1.Tool.Input = map[string]any{"command": "ls", "n": json.Number("3"), "f": json.Number("1.5"), "big": json.Number("18446744073709551615"),
		"nested": map[string]any{"list": []any{true, nil, "x"}}}
	a1.Seq = 7
	d1 := kindEvent(event.KindDetection, "d1")
	a2 := testEvent("a2", 5)
	a2.TS = event.At(testTime.Add(1500 * time.Millisecond))
	if err := s.Write([]*event.Event{a1, nil, d1, a2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	msgs, conns := srv.snapshot()
	if conns != 1 || len(msgs) != 2 {
		t.Fatalf("conns=%d msgs=%d", conns, len(msgs))
	}
	act, det := msgs[0], msgs[1]
	if act.tag != "hawkbell.activity" || det.tag != "hawkbell.detection" {
		t.Fatalf("tags %q %q", act.tag, det.tag)
	}
	if act.size != 2 || len(act.entries) != 2 || det.size != 1 || len(det.entries) != 1 {
		t.Fatalf("size option does not match entries: %d/%d %d/%d", act.size, len(act.entries), det.size, len(det.entries))
	}
	for _, m := range msgs {
		raw, err := base64.StdEncoding.DecodeString(m.chunk)
		if !m.chunkIsStr || err != nil || len(raw) != 16 {
			t.Errorf("chunk must be a str holding base64 of 16 bytes: %q", m.chunk)
		}
		if m.compressed != "" {
			t.Errorf("unexpected compressed option %q", m.compressed)
		}
	}
	if act.chunk == det.chunk {
		t.Error("chunk ids must be unique per message")
	}
	// EventTime carries the event's own time to the nanosecond.
	if act.entries[0].sec != uint32(testTime.Unix()) || act.entries[0].nsec != uint32(testTime.Nanosecond()) {
		t.Errorf("EventTime %d.%09d, want %d.%09d", act.entries[0].sec, act.entries[0].nsec, testTime.Unix(), testTime.Nanosecond())
	}
	if want := testTime.Add(1500 * time.Millisecond); act.entries[1].sec != uint32(want.Unix()) || act.entries[1].nsec != uint32(want.Nanosecond()) {
		t.Errorf("second EventTime %d.%09d", act.entries[1].sec, act.entries[1].nsec)
	}
	sameJSON(t, act.entries[0].record, a1)
	sameJSON(t, act.entries[1].record, a2)
	sameJSON(t, det.entries[0].record, d1)
	// Integers stay integers on the wire.
	in := act.entries[0].record["tool"].(map[string]any)["input"].(map[string]any)
	if in["n"] != int64(3) || in["f"] != 1.5 || in["big"] != uint64(18446744073709551615) || act.entries[0].record["seq"] != int64(7) {
		t.Errorf("number types: n=%T f=%T big=%T", in["n"], in["f"], in["big"])
	}

	// The connection is reused.
	if err := s.Write([]*event.Event{testEvent("a3", 1)}); err != nil {
		t.Fatal(err)
	}
	if _, conns := srv.snapshot(); conns != 1 {
		t.Errorf("second Write opened a new connection")
	}
	if err := s.Write(nil); err != nil {
		t.Errorf("empty batch: %v", err)
	}
	s.Close()
	if err := s.Write([]*event.Event{a1}); !errors.Is(err, ErrClosed) {
		t.Errorf("Write after Close: %v", err)
	}
}

func TestForwardOptions(t *testing.T) {
	srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
	s := newForward(t, ForwardOptions{Addr: srv.addr(), TagPrefix: "edr.agents", Compress: true}) // bare host:port is tcp
	batch := []*event.Event{testEvent("c1", 3000), testEvent("c2", 3000), testEvent("c3", 3000)}
	if err := s.Write(batch); err != nil {
		t.Fatal(err)
	}
	msgs, _ := srv.snapshot()
	if len(msgs) != 1 || msgs[0].tag != "edr.agents.activity" || msgs[0].compressed != "gzip" || len(msgs[0].entries) != 3 || msgs[0].size != 3 {
		t.Fatalf("message: %+v", msgs)
	}
	if msgs[0].payloadLen > 2000 {
		t.Errorf("payload not compressed: %d bytes for 9 KiB of repeated text", msgs[0].payloadLen)
	}
	sameJSON(t, msgs[0].entries[2].record, batch[2])

	for _, addr := range []string{"", "http://x:1", "unix://", "tcp://", "tcp://:24224", "ftp://h:1", "tls://"} {
		if _, err := NewForward(ForwardOptions{Addr: addr}); err == nil {
			t.Errorf("NewForward(%q) accepted", addr)
		}
	}
	if _, err := NewForward(ForwardOptions{Addr: "tcp://h:1", Username: "u"}); err == nil {
		t.Error("Username without SharedKey accepted")
	}
	for addr, want := range map[string]string{
		"tcp://127.0.0.1:24224": "tcp 127.0.0.1:24224", "tcp://collector": "tcp collector:24224", "tls://collector.example:24230/": "tcp collector.example:24230",
		"tcp://[::1]:24224": "tcp [::1]:24224", "tcp://[::1]": "tcp [::1]:24224", "unix:///run/fluent-bit/hawkbell.sock": "unix /run/fluent-bit/hawkbell.sock",
		"10.0.0.1:5": "tcp 10.0.0.1:5",
	} {
		s, err := NewForward(ForwardOptions{Addr: addr})
		if err != nil {
			t.Errorf("NewForward(%q): %v", addr, err)
			continue
		}
		fs := s.(*forwardSink)
		if got := fs.network + " " + fs.address; got != want {
			t.Errorf("NewForward(%q) -> %q, want %q", addr, got, want)
		}
		if fs.useTLS != strings.HasPrefix(addr, "tls://") || fs.o.TagPrefix != "hawkbell" || fs.o.Timeout != 5*time.Second || !strings.HasPrefix(fs.o.Hostname, "hawkbell-") {
			t.Errorf("defaults for %q: %+v", addr, fs.o)
		}
	}
}

func TestForwardSharedKeyHandshake(t *testing.T) {
	for _, binNonce := range []bool{false, true} {
		srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
		srv.sharedKey, srv.binNonce = "s3cret", binNonce
		srv.start()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), SharedKey: "s3cret", Hostname: "sensor.local"})
		if err := s.Write([]*event.Event{testEvent("k1", 5)}); err != nil {
			t.Fatalf("binNonce=%v: %v", binNonce, err)
		}
		if msgs, _ := srv.snapshot(); len(msgs) != 1 {
			t.Fatalf("message not delivered after handshake")
		}
	}

	t.Run("wrong_key", func(t *testing.T) {
		srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
		srv.sharedKey = "s3cret"
		srv.start()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), SharedKey: "guess"})
		err := s.Write([]*event.Event{testEvent("k2", 5)})
		if err == nil || !strings.Contains(err.Error(), "handshake") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "guess") {
			t.Error("the key leaked into the error")
		}
		if msgs, _ := srv.snapshot(); len(msgs) != 0 {
			t.Fatal("data was accepted with a wrong key")
		}
	})

	t.Run("server_does_not_know_key", func(t *testing.T) {
		// A server that answers PONG true with a digest made from another
		// key is an impostor; the client must not send it data.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		got := make(chan int, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			helo := mpAppendArrayHeader(nil, 2)
			helo = mpAppendStr(helo, "HELO")
			helo = mpAppendMapHeader(helo, 2)
			helo = mpAppendStr(mpAppendStr(helo, "nonce"), "0123456789abcdef")
			helo = mpAppendStr(mpAppendStr(helo, "auth"), "")
			c.Write(helo)
			dec := newMPDecoder(c, bigLimits)
			dec.decode() // PING
			pong := mpAppendArrayHeader(nil, 5)
			pong = mpAppendStr(pong, "PONG")
			pong = mpAppendBool(pong, true)
			pong = mpAppendStr(pong, "")
			pong = mpAppendStr(pong, "impostor")
			pong = mpAppendStr(pong, strings.Repeat("ab", 64))
			c.Write(pong)
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _ := io.Copy(io.Discard, c)
			got <- int(n)
		}()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + ln.Addr().String(), SharedKey: "s3cret", Timeout: 300 * time.Millisecond})
		if err := s.Write([]*event.Event{testEvent("k3", 5)}); err == nil || !strings.Contains(err.Error(), "prove") {
			t.Fatalf("err = %v", err)
		}
		if n := <-got; n != 0 {
			t.Fatalf("client sent %d bytes of data to an unauthenticated server", n)
		}
	})

	t.Run("users", func(t *testing.T) {
		srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
		srv.sharedKey, srv.users = "s3cret", map[string]string{"sensor": "hunter2"}
		srv.start()
		ok := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), SharedKey: "s3cret", Username: "sensor", Password: "hunter2"})
		if err := ok.Write([]*event.Event{testEvent("u1", 5)}); err != nil {
			t.Fatal(err)
		}
		bad := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), SharedKey: "s3cret", Username: "sensor", Password: "nope"})
		err := bad.Write([]*event.Event{testEvent("u2", 5)})
		if err == nil || !strings.Contains(err.Error(), "rejected") || strings.Contains(err.Error(), "nope") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("key_configured_on_one_side_only", func(t *testing.T) {
		keyed := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
		keyed.sharedKey = "s3cret"
		keyed.start()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + keyed.addr(), Timeout: 300 * time.Millisecond})
		if err := s.Write([]*event.Event{testEvent("o1", 5)}); err == nil || !strings.Contains(err.Error(), "SharedKey") {
			t.Fatalf("server wants a key, client has none: %v", err)
		}
		open := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
		s = newForward(t, ForwardOptions{Addr: "tcp://" + open.addr(), SharedKey: "s3cret", Timeout: 300 * time.Millisecond})
		if err := s.Write([]*event.Event{testEvent("o2", 5)}); err == nil || !strings.Contains(err.Error(), "HELO") {
			t.Fatalf("client has a key, server sends no HELO: %v", err)
		}
	})
}

func TestForwardReconnectsOnceAndResends(t *testing.T) {
	for _, first := range []string{"close", "silent", "wrong", "garbage"} {
		t.Run(first, func(t *testing.T) {
			srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
			srv.behave = func(n int) string {
				if n == 0 {
					return first
				}
				return "ack"
			}
			srv.start()
			s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), Timeout: 300 * time.Millisecond})
			if err := s.Write([]*event.Event{testEvent("r1", 5)}); err != nil {
				t.Fatalf("Write should succeed on the resend: %v", err)
			}
			msgs, conns := srv.snapshot()
			if len(msgs) != 2 || conns != 2 {
				t.Fatalf("msgs=%d conns=%d, want a resend on a new connection", len(msgs), conns)
			}
			if msgs[0].chunk != msgs[1].chunk {
				t.Error("the resend must carry the same chunk id")
			}
			if msgs[1].entries[0].record["id"] != "r1" {
				t.Error("resend carried different data")
			}
		})
	}

	t.Run("gives_up_after_one_resend", func(t *testing.T) {
		srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil)
		srv.behave = func(int) string { return "silent" }
		srv.start()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), Timeout: 150 * time.Millisecond})
		start := time.Now()
		err := s.Write([]*event.Event{testEvent("g1", 5)})
		if err == nil || !strings.Contains(err.Error(), "ack") {
			t.Fatalf("err = %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("gave up after %v, want about two timeouts", d)
		}
		if msgs, conns := srv.snapshot(); len(msgs) != 2 || conns != 2 {
			t.Errorf("msgs=%d conns=%d, want exactly one resend", len(msgs), conns)
		}
		// The sink recovers when the server does.
		srv.mu.Lock()
		srv.behave = nil
		srv.mu.Unlock()
		if err := s.Write([]*event.Event{testEvent("g2", 5)}); err != nil {
			t.Fatalf("after recovery: %v", err)
		}
	})

	t.Run("server_restart_between_writes", func(t *testing.T) {
		srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
		addr := srv.addr()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + addr, Timeout: 500 * time.Millisecond})
		if err := s.Write([]*event.Event{testEvent("s1", 5)}); err != nil {
			t.Fatal(err)
		}
		srv.close()
		if err := s.Write([]*event.Event{testEvent("s2", 5)}); err == nil {
			t.Fatal("Write succeeded with no server")
		}
		srv2 := newFakeForward(t, "tcp", addr, nil).start()
		if err := s.Write([]*event.Event{testEvent("s3", 5)}); err != nil {
			t.Fatalf("after restart: %v", err)
		}
		if msgs, _ := srv2.snapshot(); len(msgs) != 1 || msgs[0].entries[0].record["id"] != "s3" {
			t.Fatalf("restarted server got %+v", msgs)
		}
	})

	t.Run("connection_refused", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close()
		s := newForward(t, ForwardOptions{Addr: "tcp://" + addr, Timeout: 300 * time.Millisecond})
		if err := s.Write([]*event.Event{testEvent("x", 5)}); err == nil || !strings.Contains(err.Error(), "connect") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestForwardSplitsLargeBatches(t *testing.T) {
	srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
	s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr(), Timeout: 10 * time.Second})
	var batch []*event.Event
	var want []string
	for i := 0; i < 120; i++ { // about 3.6 MiB of activity plus a few detections
		e := testEvent(fmt.Sprintf("big-%03d", i), 30<<10)
		batch = append(batch, e)
		want = append(want, e.ID)
		if i%40 == 0 {
			batch = append(batch, kindEvent(event.KindDetection, fmt.Sprintf("det-%03d", i)))
		}
	}
	if err := s.Write(batch); err != nil {
		t.Fatal(err)
	}
	msgs, _ := srv.snapshot()
	var got []string
	activity := 0
	for _, m := range msgs {
		if m.payloadLen > maxForwardPayload {
			t.Errorf("message payload %d exceeds %d", m.payloadLen, maxForwardPayload)
		}
		if int(m.size) != len(m.entries) {
			t.Errorf("size option %d != %d entries", m.size, len(m.entries))
		}
		if m.tag == "hawkbell.activity" {
			activity++
			for _, en := range m.entries {
				got = append(got, en.record["id"].(string))
			}
		}
	}
	if activity < 4 {
		t.Errorf("expected the activity stream to be split, got %d messages", activity)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Error("events lost or reordered by splitting")
	}
}

func TestForwardShrinksOversizeRecord(t *testing.T) {
	srv := newFakeForward(t, "tcp", "127.0.0.1:0", nil).start()
	s := newForward(t, ForwardOptions{Addr: "tcp://" + srv.addr()})
	e := testEvent("huge", 10)
	e.Tool.Output = strings.Repeat("o", 3<<20)
	if err := s.Write([]*event.Event{e}); err != nil {
		t.Fatal(err)
	}
	msgs, _ := srv.snapshot()
	rec := msgs[0].entries[0].record
	if msgs[0].payloadLen > maxForwardRecord || rec["id"] != "huge" {
		t.Fatalf("payload %d bytes", msgs[0].payloadLen)
	}
	if tr, _ := rec["truncated"].([]any); len(tr) != 1 || tr[0] != "tool.output" {
		t.Errorf("truncated = %v", rec["truncated"])
	}
}

func TestForwardUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Fluent Bit has no unix socket input on Windows")
	}
	// Socket paths are limited to about 100 bytes; t.TempDir can be longer.
	dir, err := os.MkdirTemp("", "spf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "f.sock")
	srv := newFakeForward(t, "unix", sock, nil).start()
	s := newForward(t, ForwardOptions{Addr: "unix://" + sock})
	if err := s.Write([]*event.Event{testEvent("ux", 5)}); err != nil {
		t.Fatal(err)
	}
	if msgs, _ := srv.snapshot(); len(msgs) != 1 || msgs[0].entries[0].record["id"] != "ux" {
		t.Fatalf("msgs = %+v", msgs)
	}
}

// selfSigned returns a server TLS config for 127.0.0.1 and a pool that
// trusts it.
func selfSigned(t testing.TB) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hawkbell test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func TestForwardTLS(t *testing.T) {
	serverConf, pool := selfSigned(t)
	srv := newFakeForward(t, "tcp", "127.0.0.1:0", serverConf)
	srv.sharedKey = "s3cret"
	srv.start()
	s := newForward(t, ForwardOptions{Addr: "tls://" + srv.addr(), SharedKey: "s3cret", TLS: &tls.Config{RootCAs: pool}})
	if err := s.Write([]*event.Event{testEvent("tls1", 5)}); err != nil {
		t.Fatal(err)
	}
	if msgs, _ := srv.snapshot(); len(msgs) != 1 {
		t.Fatal("not delivered over TLS")
	}
	// Without the CA the certificate is not trusted and nothing is sent.
	untrusted := newForward(t, ForwardOptions{Addr: "tls://" + srv.addr(), SharedKey: "s3cret", Timeout: time.Second})
	if err := untrusted.Write([]*event.Event{testEvent("tls2", 5)}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if msgs, _ := srv.snapshot(); len(msgs) != 1 {
		t.Fatal("data sent to an unverified server")
	}
}
