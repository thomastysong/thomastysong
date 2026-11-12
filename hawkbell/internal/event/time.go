package event

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

// TimeLayout is the only timestamp format hawkbell emits: RFC 3339 in UTC with a
// fixed six-digit fraction. The fraction is always present because Fluent
// Bit's strict time parser (format "%Y-%m-%dT%H:%M:%S.%L%z") rejects values
// without one and silently falls back to ingestion time.
const TimeLayout = "2006-01-02T15:04:05.000000Z07:00"

// Time is a time.Time that marshals with TimeLayout in UTC and omits itself
// when zero (use with `omitempty`).
type Time struct{ time.Time }

// Now returns the current time as an event Time.
func Now() Time { return Time{time.Now().UTC()} }

// At converts a time.Time.
func At(t time.Time) Time { return Time{t.UTC()} }

// IsZero reports whether the time is unset; encoding/json honours this for omitempty/omitzero.
func (t Time) IsZero() bool { return t.Time.IsZero() }

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte(`""`), nil
	}
	return []byte(`"` + t.Time.UTC().Format(TimeLayout) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler. It accepts any RFC 3339 form.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	p, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	t.Time = p.UTC()
	return nil
}

// String returns the wire form.
func (t Time) String() string {
	if t.Time.IsZero() {
		return ""
	}
	return t.Time.UTC().Format(TimeLayout)
}

// NewID returns a UUIDv7 string: 48 bits of Unix milliseconds followed by
// random bits. Ids sort by creation time, which keeps downstream indexes
// append-friendly and lets consumers dedupe at-least-once deliveries.
func NewID() string {
	return NewIDAt(time.Now())
}

// NewIDAt returns a UUIDv7 for the given instant.
func NewIDAt(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	binary.BigEndian.PutUint64(b[0:8], ms<<16)
	_, _ = rand.Read(b[6:])
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return formatUUID(b)
}

func formatUUID(b [16]byte) string {
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// StableID returns a deterministic UUIDv8 for an action that has a natural
// key (for example host, agent, session, tool-call id, event type). Delivery
// is at-least-once and the same action can be seen on two surfaces, so ids
// must be reproducible: a replayed chunk or the transcript view of a tool
// call the hook already reported then collapses downstream on the id. The
// first 48 bits are the event time in milliseconds, so ids still sort by time.
func StableID(t time.Time, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(t.UnixMilli())<<16)
	copy(b[6:], sum[:10])
	b[6] = (b[6] & 0x0f) | 0x80 // version 8 (custom)
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return formatUUID(b)
}

// DedupeKey hashes the natural key of an action without the collection
// source, so the hook and transcript records of one tool call share it.
func DedupeKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// New returns an Event with version, id and timestamp set.
func New(kind Kind, typ string, src Source) *Event {
	now := time.Now().UTC()
	return &Event{
		V:      SchemaVersion,
		ID:     NewIDAt(now),
		TS:     Time{now},
		Kind:   kind,
		Type:   typ,
		Source: src,
	}
}
