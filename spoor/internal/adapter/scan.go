package adapter

import (
	"bytes"
	"encoding/json"
)

// topValue is what scanTop reports about one top-level member.
type topValue struct {
	// kind is 's' string, 'n' number, 'o' object, 'a' array, 'b' boolean,
	// 'z' null; 0 when the key is absent.
	kind byte
	// text is the string value or the number literal when it is at most
	// maxTopText bytes long; longer values report their kind only.
	text string
}

const maxTopText = 256

// scanTop walks the top level of one JSON object and reports the members
// named in want. It does not build the document: nested values are skipped
// by bracket matching, so the cost is one pass over the bytes and the
// memory is the handful of short values asked for. That is what makes it
// usable on lines too large to decode and for sniffing a format.
//
// The scan is lexical. It returns false when the text is not shaped like an
// object, but it is not a validator; callers that need validity check with
// json.Valid first. When a key repeats the last occurrence wins, as it does
// in encoding/json.
func scanTop(b []byte, want map[string]bool) (map[string]topValue, bool) {
	out := map[string]topValue{}
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return nil, false
	}
	i = skipSpace(b, i+1)
	if i < len(b) && b[i] == '}' {
		return out, true
	}
	for {
		if i >= len(b) || b[i] != '"' {
			return nil, false
		}
		keyRaw, next, ok := scanString(b, i)
		if !ok {
			return nil, false
		}
		key, keep := "", false
		if len(keyRaw) <= maxTopText+2 {
			key = unquote(keyRaw)
			keep = want[key]
		}
		i = skipSpace(b, next)
		if i >= len(b) || b[i] != ':' {
			return nil, false
		}
		i = skipSpace(b, i+1)
		if i >= len(b) {
			return nil, false
		}
		var v topValue
		switch c := b[i]; {
		case c == '"':
			raw, next, ok := scanString(b, i)
			if !ok {
				return nil, false
			}
			v.kind = 's'
			if keep && len(raw) <= maxTopText+2 {
				v.text = unquote(raw)
			}
			i = next
		case c == '{' || c == '[':
			next, ok := skipNested(b, i)
			if !ok {
				return nil, false
			}
			v.kind = 'o'
			if c == '[' {
				v.kind = 'a'
			}
			i = next
		default:
			start := i
			for i < len(b) && b[i] != ',' && b[i] != '}' && !isSpace(b[i]) {
				i++
			}
			lit := b[start:i]
			switch {
			case len(lit) == 0:
				return nil, false
			case bytes.Equal(lit, []byte("true")), bytes.Equal(lit, []byte("false")):
				v.kind = 'b'
			case bytes.Equal(lit, []byte("null")):
				v.kind = 'z'
			case lit[0] == '-' || (lit[0] >= '0' && lit[0] <= '9'):
				v.kind = 'n'
				if keep && len(lit) <= maxTopText {
					v.text = string(lit)
				}
			default:
				return nil, false
			}
		}
		if keep {
			out[key] = v
		}
		i = skipSpace(b, i)
		if i >= len(b) {
			return nil, false
		}
		switch b[i] {
		case ',':
			i = skipSpace(b, i+1)
		case '}':
			return out, true
		default:
			return nil, false
		}
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpace(b []byte, i int) int {
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return i
}

// scanString returns the raw string literal starting at b[i] (quotes
// included) and the index after it.
func scanString(b []byte, i int) (raw []byte, next int, ok bool) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return b[i : j+1], j + 1, true
		}
	}
	return nil, 0, false
}

// skipNested returns the index after the object or array starting at b[i].
// It is iterative, so nesting depth cannot exhaust the stack.
func skipNested(b []byte, i int) (next int, ok bool) {
	depth := 0
	for j := i; j < len(b); j++ {
		switch b[j] {
		case '"':
			_, n, ok := scanString(b, j)
			if !ok {
				return 0, false
			}
			j = n - 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1, true
			}
		}
	}
	return 0, false
}

// unquote decodes a short JSON string literal. A literal without escapes is
// sliced; one with escapes goes through the real decoder so "_" and
// "_" compare equal, as they do for any JSON consumer.
func unquote(raw []byte) string {
	if len(raw) < 2 {
		return ""
	}
	if bytes.IndexByte(raw, '\\') < 0 {
		return string(raw[1 : len(raw)-1])
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}
