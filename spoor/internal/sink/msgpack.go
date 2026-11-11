package sink

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"time"
)

// A minimal MessagePack codec: exactly the subset the Forward protocol
// needs, so the sensor carries no third-party parser for bytes that arrive
// from the network. The encoder covers what a JSON round trip of an event
// can contain (maps with string keys, arrays, str, bin, int, uint, float64,
// bool, nil) plus ext for EventTime. The decoder reads server replies (HELO,
// PONG, ack) under explicit size, count and depth limits.

// maxPackDepth bounds encoder recursion. Records come from format.Native,
// which already caps Tool.Input nesting; this is the backstop for any other
// caller.
const maxPackDepth = 64

var errPackDepth = errors.New("msgpack: value nested too deeply")

// mpExt is a MessagePack extension value.
type mpExt struct {
	Type int8
	Data []byte
}

func mpAppendNil(b []byte) []byte { return append(b, 0xc0) }

func mpAppendBool(b []byte, v bool) []byte {
	if v {
		return append(b, 0xc3)
	}
	return append(b, 0xc2)
}

// mpAppendUint writes the smallest unsigned encoding.
func mpAppendUint(b []byte, u uint64) []byte {
	switch {
	case u <= 0x7f:
		return append(b, byte(u))
	case u <= math.MaxUint8:
		return append(b, 0xcc, byte(u))
	case u <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, 0xcd), uint16(u))
	case u <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, 0xce), uint32(u))
	}
	return binary.BigEndian.AppendUint64(append(b, 0xcf), u)
}

// mpAppendInt writes the smallest encoding; non-negative values use the
// unsigned family, as the reference implementations do.
func mpAppendInt(b []byte, i int64) []byte {
	switch {
	case i >= 0:
		return mpAppendUint(b, uint64(i))
	case i >= -32:
		return append(b, byte(i))
	case i >= math.MinInt8:
		return append(b, 0xd0, byte(i))
	case i >= math.MinInt16:
		return binary.BigEndian.AppendUint16(append(b, 0xd1), uint16(i))
	case i >= math.MinInt32:
		return binary.BigEndian.AppendUint32(append(b, 0xd2), uint32(i))
	}
	return binary.BigEndian.AppendUint64(append(b, 0xd3), uint64(i))
}

func mpAppendFloat64(b []byte, f float64) []byte {
	return binary.BigEndian.AppendUint64(append(b, 0xcb), math.Float64bits(f))
}

func mpAppendStr(b []byte, s string) []byte {
	n := len(s)
	switch {
	case n <= 31:
		b = append(b, 0xa0|byte(n))
	case n <= math.MaxUint8:
		b = append(b, 0xd9, byte(n))
	case n <= math.MaxUint16:
		b = binary.BigEndian.AppendUint16(append(b, 0xda), uint16(n))
	default:
		b = binary.BigEndian.AppendUint32(append(b, 0xdb), uint32(n))
	}
	return append(b, s...)
}

func mpAppendBin(b, p []byte) []byte {
	n := len(p)
	switch {
	case n <= math.MaxUint8:
		b = append(b, 0xc4, byte(n))
	case n <= math.MaxUint16:
		b = binary.BigEndian.AppendUint16(append(b, 0xc5), uint16(n))
	default:
		b = binary.BigEndian.AppendUint32(append(b, 0xc6), uint32(n))
	}
	return append(b, p...)
}

func mpAppendArrayHeader(b []byte, n int) []byte {
	switch {
	case n <= 15:
		return append(b, 0x90|byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, 0xdc), uint16(n))
	}
	return binary.BigEndian.AppendUint32(append(b, 0xdd), uint32(n))
}

func mpAppendMapHeader(b []byte, n int) []byte {
	switch {
	case n <= 15:
		return append(b, 0x80|byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, 0xde), uint16(n))
	}
	return binary.BigEndian.AppendUint32(append(b, 0xdf), uint32(n))
}

func mpAppendExt(b []byte, typ int8, data []byte) []byte {
	n := len(data)
	switch n {
	case 1:
		b = append(b, 0xd4, byte(typ))
	case 2:
		b = append(b, 0xd5, byte(typ))
	case 4:
		b = append(b, 0xd6, byte(typ))
	case 8:
		b = append(b, 0xd7, byte(typ))
	case 16:
		b = append(b, 0xd8, byte(typ))
	default:
		switch {
		case n <= math.MaxUint8:
			b = append(b, 0xc7, byte(n), byte(typ))
		case n <= math.MaxUint16:
			b = append(binary.BigEndian.AppendUint16(append(b, 0xc8), uint16(n)), byte(typ))
		default:
			b = append(binary.BigEndian.AppendUint32(append(b, 0xc9), uint32(n)), byte(typ))
		}
	}
	return append(b, data...)
}

// mpAppendEventTime writes the Forward protocol EventTime: fixext8 of type
// 0 holding big-endian uint32 seconds and uint32 nanoseconds. Times before
// the epoch or past 2106 do not fit and are clamped.
func mpAppendEventTime(b []byte, t time.Time) []byte {
	sec := t.Unix()
	nsec := uint32(t.Nanosecond())
	switch {
	case sec < 0:
		sec, nsec = 0, 0
	case sec > math.MaxUint32:
		sec, nsec = math.MaxUint32, 999_999_999
	}
	b = append(b, 0xd7, 0x00)
	b = binary.BigEndian.AppendUint32(b, uint32(sec))
	return binary.BigEndian.AppendUint32(b, nsec)
}

// mpAppendValue encodes a generic value. Map keys are written in sorted
// order so the same record always produces the same bytes.
func mpAppendValue(b []byte, v any, depth int) ([]byte, error) {
	if depth > maxPackDepth {
		return b, errPackDepth
	}
	switch t := v.(type) {
	case nil:
		return mpAppendNil(b), nil
	case bool:
		return mpAppendBool(b, t), nil
	case string:
		if uint64(len(t)) > math.MaxUint32 {
			return b, errors.New("msgpack: string too long")
		}
		return mpAppendStr(b, t), nil
	case []byte:
		if uint64(len(t)) > math.MaxUint32 {
			return b, errors.New("msgpack: bin too long")
		}
		return mpAppendBin(b, t), nil
	case json.Number:
		return mpAppendNumber(b, t), nil
	case float64:
		return mpAppendFloat64(b, t), nil
	case float32:
		return mpAppendFloat64(b, float64(t)), nil
	case int:
		return mpAppendInt(b, int64(t)), nil
	case int8:
		return mpAppendInt(b, int64(t)), nil
	case int16:
		return mpAppendInt(b, int64(t)), nil
	case int32:
		return mpAppendInt(b, int64(t)), nil
	case int64:
		return mpAppendInt(b, t), nil
	case uint:
		return mpAppendUint(b, uint64(t)), nil
	case uint8:
		return mpAppendUint(b, uint64(t)), nil
	case uint16:
		return mpAppendUint(b, uint64(t)), nil
	case uint32:
		return mpAppendUint(b, uint64(t)), nil
	case uint64:
		return mpAppendUint(b, t), nil
	case mpExt:
		if uint64(len(t.Data)) > math.MaxUint32 {
			return b, errors.New("msgpack: ext too long")
		}
		return mpAppendExt(b, t.Type, t.Data), nil
	case map[string]any:
		if uint64(len(t)) > math.MaxUint32 {
			return b, errors.New("msgpack: map too long")
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b = mpAppendMapHeader(b, len(keys))
		var err error
		for _, k := range keys {
			b = mpAppendStr(b, k)
			if b, err = mpAppendValue(b, t[k], depth+1); err != nil {
				return b, err
			}
		}
		return b, nil
	case []any:
		if uint64(len(t)) > math.MaxUint32 {
			return b, errors.New("msgpack: array too long")
		}
		b = mpAppendArrayHeader(b, len(t))
		var err error
		for _, c := range t {
			if b, err = mpAppendValue(b, c, depth+1); err != nil {
				return b, err
			}
		}
		return b, nil
	}
	return b, fmt.Errorf("msgpack: unsupported type %T", v)
}

// mpAppendNumber keeps JSON integers as integers (signed, then unsigned for
// values above MaxInt64 such as large counters) and everything else as
// float64. A literal no float can represent is carried as its text.
func mpAppendNumber(b []byte, n json.Number) []byte {
	s := n.String()
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return mpAppendInt(b, i)
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		return mpAppendUint(b, u)
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsInf(f, 0) {
		return mpAppendFloat64(b, f)
	}
	return mpAppendStr(b, s)
}

// mpLimits bounds what the decoder accepts from a peer.
type mpLimits struct {
	maxBytes int // longest str, bin or ext payload
	maxElems int // most elements in one array or map
	maxDepth int
	budget   int // total payload bytes plus elements per decoded value
}

// replyLimits fit every reply a Forward server sends (HELO, PONG, ack) with
// a wide margin, and nothing larger.
var replyLimits = mpLimits{maxBytes: 4096, maxElems: 16, maxDepth: 4, budget: 16 << 10}

var errMsgpackLimit = errors.New("msgpack: value exceeds decoder limits")

type mpDecoder struct {
	r      *bufio.Reader
	lim    mpLimits
	budget int
}

func newMPDecoder(r io.Reader, lim mpLimits) *mpDecoder {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &mpDecoder{r: br, lim: lim}
}

// decode reads one value. Results use string, []byte (bin), int64, uint64
// (only above MaxInt64), float64, bool, nil, []any, map[string]any and
// mpExt. A str is returned as a Go string without UTF-8 validation: Fluent
// Bit types its random handshake nonces as str.
func (d *mpDecoder) decode() (any, error) {
	d.budget = d.lim.budget
	return d.value(0)
}

func (d *mpDecoder) spend(n int) error {
	if n < 0 || n > d.budget {
		return errMsgpackLimit
	}
	d.budget -= n
	return nil
}

func (d *mpDecoder) uintN(n int) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(d.r, buf[8-n:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func (d *mpDecoder) payload(n uint64) ([]byte, error) {
	if n > uint64(d.lim.maxBytes) {
		return nil, errMsgpackLimit
	}
	if err := d.spend(int(n)); err != nil {
		return nil, err
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(d.r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (d *mpDecoder) value(depth int) (any, error) {
	if depth > d.lim.maxDepth {
		return nil, errMsgpackLimit
	}
	c, err := d.r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch {
	case c <= 0x7f:
		return int64(c), nil
	case c >= 0xe0:
		return int64(int8(c)), nil
	case c >= 0xa0 && c <= 0xbf:
		p, err := d.payload(uint64(c & 0x1f))
		return string(p), err
	case c >= 0x90 && c <= 0x9f:
		return d.array(uint64(c&0x0f), depth)
	case c >= 0x80 && c <= 0x8f:
		return d.mapN(uint64(c&0x0f), depth)
	}
	switch c {
	case 0xc0:
		return nil, nil
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	case 0xc4, 0xc5, 0xc6: // bin 8/16/32
		n, err := d.uintN(1 << (c - 0xc4))
		if err != nil {
			return nil, err
		}
		return d.payload(n)
	case 0xd9, 0xda, 0xdb: // str 8/16/32
		n, err := d.uintN(1 << (c - 0xd9))
		if err != nil {
			return nil, err
		}
		p, err := d.payload(n)
		return string(p), err
	case 0xcc, 0xcd, 0xce, 0xcf: // uint 8/16/32/64
		u, err := d.uintN(1 << (c - 0xcc))
		if err != nil {
			return nil, err
		}
		if u > math.MaxInt64 {
			return u, nil
		}
		return int64(u), nil
	case 0xd0:
		u, err := d.uintN(1)
		return int64(int8(u)), err
	case 0xd1:
		u, err := d.uintN(2)
		return int64(int16(u)), err
	case 0xd2:
		u, err := d.uintN(4)
		return int64(int32(u)), err
	case 0xd3:
		u, err := d.uintN(8)
		return int64(u), err
	case 0xca:
		u, err := d.uintN(4)
		return float64(math.Float32frombits(uint32(u))), err
	case 0xcb:
		u, err := d.uintN(8)
		return math.Float64frombits(u), err
	case 0xdc, 0xdd: // array 16/32
		n, err := d.uintN(2 << (c - 0xdc))
		if err != nil {
			return nil, err
		}
		return d.array(n, depth)
	case 0xde, 0xdf: // map 16/32
		n, err := d.uintN(2 << (c - 0xde))
		if err != nil {
			return nil, err
		}
		return d.mapN(n, depth)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1/2/4/8/16
		return d.ext(uint64(1) << (c - 0xd4))
	case 0xc7, 0xc8, 0xc9: // ext 8/16/32
		n, err := d.uintN(1 << (c - 0xc7))
		if err != nil {
			return nil, err
		}
		return d.ext(n)
	}
	return nil, fmt.Errorf("msgpack: invalid type byte 0x%02x", c)
}

func (d *mpDecoder) ext(n uint64) (any, error) {
	t, err := d.r.ReadByte()
	if err != nil {
		return nil, err
	}
	p, err := d.payload(n)
	if err != nil {
		return nil, err
	}
	return mpExt{Type: int8(t), Data: p}, nil
}

func (d *mpDecoder) array(n uint64, depth int) (any, error) {
	if n > uint64(d.lim.maxElems) {
		return nil, errMsgpackLimit
	}
	if err := d.spend(int(n)); err != nil {
		return nil, err
	}
	out := make([]any, 0, n)
	for i := uint64(0); i < n; i++ {
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (d *mpDecoder) mapN(n uint64, depth int) (any, error) {
	if n > uint64(d.lim.maxElems) {
		return nil, errMsgpackLimit
	}
	if err := d.spend(int(n)); err != nil {
		return nil, err
	}
	out := make(map[string]any, n)
	for i := uint64(0); i < n; i++ {
		k, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		var key string
		switch t := k.(type) {
		case string:
			key = t
		case []byte:
			key = string(t)
		default:
			return nil, errors.New("msgpack: map key is not a string")
		}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, nil
}
