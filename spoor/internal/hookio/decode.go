package hookio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadInput reads one hook payload from r, never buffering more than
// MaxInput+1 bytes. On overflow it returns ErrTooLarge together with the
// bytes read (one byte longer than MaxInput), so the caller can still hand
// them to Parse, which recognizes the overflow by length and salvages the
// top-level fields.
func ReadInput(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return b, err
	}
	if len(b) > MaxInput {
		return b, ErrTooLarge
	}
	return b, nil
}

// decodeObject bounds stdin and decodes it as exactly one JSON object. It
// returns the decoded map and the trimmed bytes it was decoded from.
//
// Invalid UTF-8 inside strings is tolerated (encoding/json substitutes
// U+FFFD): rejecting it would let a single bad byte in a command line hide
// the whole event.
func decodeObject(stdin []byte) (map[string]any, []byte, error) {
	if len(stdin) > MaxInput {
		return nil, nil, ErrTooLarge
	}
	b := bytes.TrimSpace(bytes.TrimPrefix(stdin, utf8BOM))
	if len(b) == 0 {
		return nil, nil, ErrEmpty
	}
	if b[0] != '{' {
		return nil, nil, ErrMalformed
	}
	if tooDeep(b, MaxDepth) {
		return nil, nil, ErrTooDeep
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		// The decoder's message names at most one offending character;
		// report only where, never what.
		return nil, nil, fmt.Errorf("%w (offset %d)", ErrMalformed, dec.InputOffset())
	}
	if m == nil {
		return nil, nil, ErrMalformed
	}
	// A second value after the object means the bytes are not one payload;
	// two parsers could disagree on which one counts, so refuse.
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("%w (trailing data at offset %d)", ErrMalformed, dec.InputOffset())
	}
	return m, b, nil
}

// decodeEmbedded parses JSON that an agent passed as a string value (Copilot
// toolArgs, Cursor MCP tool_input). The same depth cap applies, since the
// embedded text is as hostile as the envelope.
func decodeEmbedded(s string) (map[string]any, bool) {
	b := bytes.TrimSpace([]byte(s))
	if len(b) < 2 || b[0] != '{' || tooDeep(b, MaxDepth) {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// tooDeep reports whether b opens more than limit nested objects/arrays. It
// is a linear scan with no recursion so it is safe on any input; brackets
// inside strings are ignored.
func tooDeep(b []byte, limit int) bool {
	depth := 0
	inStr, esc := false, false
	for _, c := range b {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > limit {
				return true
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}

const (
	// salvageFields and salvageValue bound what a salvage keeps: enough for
	// ids, names and paths, never a payload-sized string.
	salvageFields = 64
	salvageValue  = 4096
)

// salvage extracts the top-level string fields of a JSON object without
// decoding nested values and without recursion. It is used only when the
// payload was refused (too large or too deep) and tolerates truncated input:
// it returns whatever it read before the bytes stopped making sense.
func salvage(stdin []byte) map[string]any {
	out := map[string]any{}
	b := bytes.TrimPrefix(stdin, utf8BOM)
	if len(b) > MaxInput+1 {
		b = b[:MaxInput+1]
	}
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return out
	}
	i++
	for {
		i = skipSpace(b, i)
		if i >= len(b) {
			return out
		}
		if b[i] == ',' {
			i++
			continue
		}
		if b[i] != '"' {
			return out // '}' or garbage: either way we are done
		}
		key, next, ok := scanString(b, i)
		if !ok {
			return out
		}
		i = skipSpace(b, next)
		if i >= len(b) || b[i] != ':' {
			return out
		}
		i = skipSpace(b, i+1)
		if i >= len(b) {
			return out
		}
		switch b[i] {
		case '"':
			val, next, ok := scanString(b, i)
			if !ok {
				return out
			}
			// First occurrence wins and empty values are not kept, so a
			// later duplicate or an oversized (skipped) string cannot erase
			// or replace a field already read.
			if _, dup := out[key]; !dup && key != "" && val != "" && len(out) < salvageFields && len(key) <= 64 && len(val) <= salvageValue {
				out[key] = val
			}
			i = next
		case '{', '[':
			next, ok := skipComposite(b, i)
			if !ok {
				return out
			}
			i = next
		default: // number, true, false, null
			for i < len(b) && b[i] != ',' && b[i] != '}' && !isSpace(b[i]) {
				i++
			}
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

// scanString reads the JSON string starting at b[i] (which must be '"') and
// returns its decoded value and the index after the closing quote. A string
// too long to be worth keeping is skipped and returned as "".
func scanString(b []byte, i int) (string, int, bool) {
	j := i + 1
	esc := false
	for ; j < len(b); j++ {
		c := b[j]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			break
		}
	}
	if j >= len(b) {
		return "", 0, false
	}
	// Do not decode strings we would discard anyway; a multi-megabyte value
	// is exactly what salvage exists to skip. (A JSON escape is at most six
	// bytes per decoded byte, hence the factor.)
	if j-i > 6*salvageValue {
		return "", j + 1, true
	}
	var s string
	if err := json.Unmarshal(b[i:j+1], &s); err != nil {
		return "", 0, false
	}
	return s, j + 1, true
}

// skipComposite returns the index after the object or array opening at b[i].
func skipComposite(b []byte, i int) (int, bool) {
	depth := 0
	inStr, esc := false, false
	for ; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}
