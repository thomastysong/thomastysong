package hookcmd

import (
	"bytes"
	"encoding/json"
)

// maxScanValue bounds a string value topLevelStrings decodes.
const maxScanValue = 4096

// topLevelStrings returns the string values of the wanted keys at the top
// level of a JSON object. It never decodes nested values and never
// recurses, so it is safe on any input, including the payload that just
// crashed the worker: the supervisor uses it on its failure path, where it
// must not run the same parser again. Truncated or invalid input yields
// whatever was read before the bytes stopped making sense. A repeated key
// takes its last value, as encoding/json does.
func topLevelStrings(b []byte, want ...string) map[string]string {
	out := map[string]string{}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	i := skipWS(b, 0)
	if i >= len(b) || b[i] != '{' {
		return out
	}
	i++
	for {
		i = skipWS(b, i)
		if i >= len(b) {
			return out
		}
		switch b[i] {
		case ',':
			i++
			continue
		case '"':
		default:
			return out // '}' or garbage
		}
		ks, ke, ok := stringEnd(b, i)
		if !ok {
			return out
		}
		key, kok := decodeString(b[ks:ke])
		i = skipWS(b, ke)
		if i >= len(b) || b[i] != ':' {
			return out
		}
		i = skipWS(b, i+1)
		if i >= len(b) {
			return out
		}
		switch b[i] {
		case '"':
			vs, ve, ok := stringEnd(b, i)
			if !ok {
				return out
			}
			if kok && wanted(key, want) && ve-vs <= maxScanValue+2 {
				if v, ok := decodeString(b[vs:ve]); ok {
					out[key] = v
				}
			}
			i = ve
		case '{', '[':
			next, ok := skipComposite(b, i)
			if !ok {
				return out
			}
			i = next
		default: // number, true, false, null
			for i < len(b) && b[i] != ',' && b[i] != '}' && !isWS(b[i]) {
				i++
			}
		}
	}
}

func wanted(k string, want []string) bool {
	for _, w := range want {
		if k == w {
			return true
		}
	}
	return false
}

func isWS(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipWS(b []byte, i int) int {
	for i < len(b) && isWS(b[i]) {
		i++
	}
	return i
}

// stringEnd returns the bounds of the JSON string starting at b[i] (the
// opening quote), quotes included.
func stringEnd(b []byte, i int) (start, end int, ok bool) {
	esc := false
	for j := i + 1; j < len(b); j++ {
		switch {
		case esc:
			esc = false
		case b[j] == '\\':
			esc = true
		case b[j] == '"':
			return i, j + 1, true
		}
	}
	return 0, 0, false
}

// decodeString decodes one quoted JSON string token (bounded by the caller).
func decodeString(tok []byte) (string, bool) {
	if bytes.IndexByte(tok, '\\') < 0 {
		return string(tok[1 : len(tok)-1]), true
	}
	var s string
	if json.Unmarshal(tok, &s) != nil {
		return "", false
	}
	return s, true
}

// skipComposite skips an object or array with a depth counter.
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
	return i, false
}

// token keeps a payload-supplied name or id usable in a label: letters,
// digits, '_', '-', '.', ':' and '/', at most n bytes, else "other". Labels
// ship at every privacy tier, so they never carry free text.
func token(s string, n int) string {
	if s == "" {
		return ""
	}
	if len(s) > n {
		return "other"
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.', c == ':', c == '/':
		default:
			return "other"
		}
	}
	return s
}
