package sink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bigLimits let the tests decode anything the encoder can produce.
var bigLimits = mpLimits{maxBytes: 64 << 20, maxElems: 1 << 20, maxDepth: 100, budget: 256 << 20}

func mpDecodeAll(t testing.TB, b []byte) any {
	t.Helper()
	d := newMPDecoder(bytes.NewReader(b), bigLimits)
	v, err := d.decode()
	if err != nil {
		t.Fatalf("decode: %v (% x)", err, b[:min(len(b), 32)])
	}
	if d.r.Buffered() != 0 {
		t.Fatalf("%d trailing bytes", d.r.Buffered())
	}
	return v
}

// TestMsgpackKnownBytes pins the encoder to byte sequences that were sent
// to Fluent Bit 5.2.0 and accepted (research/fluentbit.md section 2).
func TestMsgpackKnownBytes(t *testing.T) {
	// Message mode: [tag, EventTime, record].
	var b []byte
	b = mpAppendArrayHeader(b, 3)
	b = mpAppendStr(b, "agentwatch.msg")
	b = mpAppendEventTime(b, time.Unix(1794391200, 123456789))
	b, err := mpAppendValue(b, map[string]any{"n": json.Number("1"), "event": "message.mode"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "93"+
		"ae 61 67 65 6e 74 77 61 74 63 68 2e 6d 73 67"+
		"d7 00 6a f4 3c a0 07 5b cd 15"+
		"82 a5 65 76 65 6e 74 ac 6d 65 73 73 61 67 65 2e 6d 6f 64 65 a1 6e 01")
	if !bytes.Equal(b, want) {
		t.Errorf("message bytes\n got % x\nwant % x", b, want)
	}
	if len(b) != 49 {
		t.Errorf("length %d, the verified message is 49 bytes", len(b))
	}

	// Ack as the server sends it: {"ack": "<24 base64 chars>"}.
	chunk := "AAECAwQFBgcICQoLDA0ODw=="
	ack := append(unhex(t, "81 a3 61 63 6b b8"), chunk...)
	if got := mpDecodeAll(t, ack); !reflect.DeepEqual(got, map[string]any{"ack": chunk}) {
		t.Errorf("ack decoded as %v", got)
	}
	if len(ack) != 30 {
		t.Errorf("ack is %d bytes, the verified one is 30", len(ack))
	}
}

func TestMsgpackEncodingBoundaries(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string // hex prefix of the encoding
	}{
		{nil, "c0"}, {true, "c3"}, {false, "c2"},
		{0, "00"}, {127, "7f"}, {128, "cc80"}, {255, "ccff"}, {256, "cd0100"}, {65535, "cdffff"}, {65536, "ce00010000"},
		{uint64(math.MaxUint32), "ceffffffff"}, {uint64(math.MaxUint32) + 1, "cf0000000100000000"}, {uint64(math.MaxUint64), "cfffffffffffffffff"},
		{-1, "ff"}, {-32, "e0"}, {-33, "d0df"}, {-128, "d080"}, {-129, "d1ff7f"}, {-32768, "d18000"}, {-32769, "d2ffff7fff"},
		{int64(math.MinInt32), "d280000000"}, {int64(math.MinInt32) - 1, "d3ffffffff7fffffff"}, {int64(math.MinInt64), "d38000000000000000"},
		{json.Number("42"), "2a"}, {json.Number("-7"), "f9"}, {json.Number("18446744073709551615"), "cfffffffffffffffff"},
		{json.Number("1.5"), "cb3ff8000000000000"}, {json.Number("1e400"), "a5" + hex.EncodeToString([]byte("1e400"))},
		{1.5, "cb3ff8000000000000"}, {float32(0.5), "cb3fe0000000000000"},
		{"", "a0"}, {"a", "a161"}, {strings.Repeat("x", 31), "bf"}, {strings.Repeat("x", 32), "d920"}, {strings.Repeat("x", 255), "d9ff"},
		{strings.Repeat("x", 256), "da0100"}, {strings.Repeat("x", 65535), "daffff"}, {strings.Repeat("x", 65536), "db00010000"},
		{[]byte{}, "c400"}, {make([]byte, 255), "c4ff"}, {make([]byte, 256), "c50100"}, {make([]byte, 65536), "c600010000"},
		{[]any{}, "90"}, {make([]any, 15), "9f"}, {make([]any, 16), "dc0010"}, {make([]any, 65536), "dd00010000"},
		{map[string]any{}, "80"},
		{mpExt{Type: 0, Data: make([]byte, 8)}, "d700"}, {mpExt{Type: 5, Data: make([]byte, 3)}, "c70305"}, {mpExt{Type: -1, Data: make([]byte, 4)}, "d6ff"},
		{mpExt{Type: 1, Data: make([]byte, 300)}, "c8012c01"},
	} {
		b, err := mpAppendValue(nil, tc.in, 0)
		if err != nil {
			t.Errorf("%T %v: %v", tc.in, tc.in, err)
			continue
		}
		want := unhex(t, tc.want)
		if !bytes.HasPrefix(b, want) {
			t.Errorf("%T: got % x, want prefix % x", tc.in, b[:min(len(b), 12)], want)
		}
		// Everything the encoder writes, the decoder reads back whole.
		mpDecodeAll(t, b)
	}

	// Map headers at the size boundaries.
	for _, n := range []int{15, 16, 65535, 65536} {
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			m[strings.Repeat("k", 1)+string(rune('0'+i%10))+string(binary.BigEndian.AppendUint32(nil, uint32(i)))] = nil
		}
		b, err := mpAppendValue(nil, m, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := mpDecodeAll(t, b).(map[string]any); len(got) != n {
			t.Errorf("map of %d decoded with %d keys", n, len(got))
		}
	}

	if _, err := mpAppendValue(nil, struct{}{}, 0); err == nil {
		t.Error("unsupported type accepted")
	}
	deep := any("leaf")
	for i := 0; i < maxPackDepth+5; i++ {
		deep = []any{deep}
	}
	if _, err := mpAppendValue(nil, deep, 0); !errors.Is(err, errPackDepth) {
		t.Errorf("deep value: %v", err)
	}
}

func TestMsgpackEventTime(t *testing.T) {
	for _, tc := range []struct {
		t    time.Time
		want string
	}{
		{time.Unix(1794391200, 123456789), "d700 6af43ca0 075bcd15"},
		{time.Unix(0, 0), "d700 00000000 00000000"},
		{time.Unix(-5, 10), "d700 00000000 00000000"},               // before the epoch: clamped
		{time.Unix(math.MaxUint32+10, 5), "d700 ffffffff 3b9ac9ff"}, // past 2106: clamped
		{time.Unix(1, 999999999), "d700 00000001 3b9ac9ff"},
	} {
		if got := mpAppendEventTime(nil, tc.t); !bytes.Equal(got, unhex(t, tc.want)) {
			t.Errorf("%v: % x, want %s", tc.t, got, tc.want)
		}
	}
}

func TestMsgpackRoundTrip(t *testing.T) {
	in := map[string]any{
		"s": "héllo \x00 \xff", "b": true, "n": nil, "i": int64(-123456789012), "u": uint64(math.MaxUint64), "f": 3.25,
		"bin": []byte{0, 1, 2}, "arr": []any{int64(1), "two", []any{}, map[string]any{"k": int64(3)}},
		"ext": mpExt{Type: 0, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	b, err := mpAppendValue(nil, in, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := mpDecodeAll(t, b); !reflect.DeepEqual(got, any(in)) {
		t.Errorf("round trip:\n got %#v\nwant %#v", got, in)
	}
	// Deterministic: key order does not depend on map iteration.
	for i := 0; i < 20; i++ {
		b2, _ := mpAppendValue(nil, in, 0)
		if !bytes.Equal(b, b2) {
			t.Fatal("encoding is not deterministic")
		}
	}
	// Formats only a peer would send.
	if got := mpDecodeAll(t, unhex(t, "ca3fc00000")); got != 1.5 {
		t.Errorf("float32: %v", got)
	}
	if got := mpDecodeAll(t, unhex(t, "c403616263")); !bytes.Equal(got.([]byte), []byte("abc")) {
		t.Errorf("bin: %v", got)
	}
	if got := mpDecodeAll(t, unhex(t, "81c4016b01")); !reflect.DeepEqual(got, map[string]any{"k": int64(1)}) {
		t.Errorf("bin map key: %v", got)
	}
}

// TestMsgpackDecoderLimits feeds the reply decoder what a hostile or broken
// server could send. Nothing may panic, hang or allocate what a length
// prefix claims.
func TestMsgpackDecoderLimits(t *testing.T) {
	dec := func(b []byte) (any, error) { return newMPDecoder(bytes.NewReader(b), replyLimits).decode() }
	for name, b := range map[string][]byte{
		"str32 4GiB":         unhex(t, "db ffffffff 41"),
		"bin32 4GiB":         unhex(t, "c6 ffffffff 41"),
		"ext32 4GiB":         unhex(t, "c9 ffffffff 00 41"),
		"array32 4G":         unhex(t, "dd ffffffff 01"),
		"map32 4G":           unhex(t, "df ffffffff a1 61 01"),
		"str over limit":     append(unhex(t, "da 1001"), make([]byte, 4097)...),
		"array over limit":   append(unhex(t, "dc 0011"), make([]byte, 17)...),
		"nested too deep":    bytes.Repeat([]byte{0x91}, 64),
		"never used byte":    {0xc1},
		"non-string map key": unhex(t, "81 01 02"),
	} {
		v, err := dec(b)
		if err == nil {
			t.Errorf("%s: accepted as %v", name, v)
		}
	}
	// The budget also caps many values that are each within limits.
	var wide []byte
	wide = mpAppendArrayHeader(wide, 16)
	for i := 0; i < 16; i++ {
		wide = mpAppendStr(wide, strings.Repeat("x", 4000))
	}
	if _, err := dec(wide); !errors.Is(err, errMsgpackLimit) {
		t.Errorf("budget not enforced: %v", err)
	}
	// Truncated input is an I/O error, not a hang.
	full, _ := mpAppendValue(nil, map[string]any{"ack": "abcdefghijklmnopqrstuvwx"}, 0)
	for i := 0; i < len(full); i++ {
		if _, err := dec(full[:i]); err == nil {
			t.Fatalf("truncated at %d accepted", i)
		} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated at %d: %v", i, err)
		}
	}
	// Random bytes: no panic, bounded work.
	r := rand.New(rand.NewPCG(1, 2))
	buf := make([]byte, 64)
	for i := 0; i < 20000; i++ {
		for j := range buf {
			buf[j] = byte(r.Uint32())
		}
		dec(buf)
	}
}
