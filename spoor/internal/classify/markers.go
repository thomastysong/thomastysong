package classify

import "strings"

// Redaction markers already in a string are opaque. A marker is
// "[REDACTED:<kind>:<fp>]" (this package), "[REDACTED:<kind>:hmac=<fp>]" (the
// privacy tier's keyed rewrite) or "[REDACTED:<kind>]" (fingerprint
// removed), with <kind> 1-64 of [a-z0-9_] and <fp> 8 lower-case hex digits.
//
// Pattern detection never looks inside or across one: Redact scans the text
// between markers piece by piece. Otherwise a marker's own words are taken
// for context: in "mysql://[REDACTED:database_url_with_password:1a2b3c4d]@db/x"
// the kind reads as a password-named key and ":1a2b3c4d]@db/x" as its value,
// and a second pass writes a marker inside the first one.
//
// The format is strict on purpose. Text an attacker controls can contain
// "[REDACTED:" too, and whatever a marker encloses is never scanned, so it
// must not be able to enclose anything but a kind name and a digest.

const markerOpen = "[REDACTED:"

// markerKindMax bounds the kind name of a marker.
const markerKindMax = 64

// markerLen returns the length of the redaction marker at the start of s,
// or 0 when s does not start with one.
func markerLen(s string) int {
	if !strings.HasPrefix(s, markerOpen) {
		return 0
	}
	start := len(markerOpen)
	k := start
	for k < len(s) && k-start < markerKindMax && isMarkerKindByte(s[k]) {
		k++
	}
	if k == start || k >= len(s) {
		return 0
	}
	switch s[k] {
	case ']':
		return k + 1
	case ':':
	default:
		return 0
	}
	p := k + 1
	if strings.HasPrefix(s[p:], "hmac=") {
		p += len("hmac=")
	}
	if p+9 > len(s) || s[p+8] != ']' || !isLowerHex(s[p:p+8]) {
		return 0
	}
	return p + 9
}

// isMarker reports whether v is exactly one redaction marker.
func isMarker(v string) bool {
	n := markerLen(v)
	return n > 0 && n == len(v)
}

// nextMarker returns the span of the first marker in s at or after from, or
// (-1, -1).
func nextMarker(s string, from int) (start, end int) {
	for from < len(s) {
		i := strings.Index(s[from:], markerOpen)
		if i < 0 {
			break
		}
		i += from
		if n := markerLen(s[i:]); n > 0 {
			return i, i + n
		}
		from = i + 1
	}
	return -1, -1
}

// eachUnmarked calls fn for every maximal run of s outside markers, with the
// run's offset in s.
func eachUnmarked(s string, fn func(off int, run string)) {
	pos := 0
	for {
		a, b := nextMarker(s, pos)
		if a < 0 {
			fn(pos, s[pos:])
			return
		}
		fn(pos, s[pos:a])
		pos = b
	}
}

// markAroundMarkers replaces every non-empty run of v outside existing
// markers with a marker of kind, and keeps the existing markers as written.
// It is how a structural rule redacts a whole value that already holds a
// marker without writing a marker around a marker.
func markAroundMarkers(kind, v string) string {
	if !strings.Contains(v, markerOpen) {
		return markerFor(kind, v)
	}
	var b strings.Builder
	b.Grow(len(v) + 32)
	pos := 0
	for {
		a, e := nextMarker(v, pos)
		if a < 0 {
			break
		}
		if a > pos {
			b.WriteString(markerFor(kind, v[pos:a]))
		}
		b.WriteString(v[a:e])
		pos = e
	}
	if pos < len(v) {
		b.WriteString(markerFor(kind, v[pos:]))
	}
	return b.String()
}

func isMarkerKindByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
