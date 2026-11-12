package privacy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A secret found inside a decoded payload ("echo <base64> | base64 -d |
// sh") is present in the command only in encoded form, so a plain search
// cannot remove it. redactEncoded finds base64, hex and escape-sequence
// runs, decodes each (also as UTF-16LE, PowerShell's -EncodedCommand
// form, and one level of nesting), and replaces any run whose decoding
// contains one of the needles.

const (
	minEncodedRun = 16
	maxEncodedRun = 128 << 10
	maxRuns       = 4096
)

// redactEncoded returns s with offending runs replaced and the needles
// that were found.
func redactEncoded(s string, needles []string) (string, []string) {
	var hitSet map[string]bool
	type span struct{ start, end int }
	var spans []span
	check := func(decoded []byte) bool {
		found := false
		for _, n := range needles {
			if bytes.Contains(decoded, []byte(n)) {
				if hitSet == nil {
					hitSet = map[string]bool{}
				}
				hitSet[n] = true
				found = true
			}
		}
		return found
	}
	runs := 0
	for _, rn := range encodedRuns(s) {
		if runs++; runs > maxRuns {
			break
		}
		run := s[rn[0]:rn[1]]
		matched := false
		for _, d := range decodings(run, 0) {
			if check(d) {
				matched = true
			}
		}
		if matched {
			spans = append(spans, span{rn[0], rn[1]})
		}
	}
	if len(spans) == 0 {
		return s, nil
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		if sp.start < last {
			continue
		}
		b.WriteString(s[last:sp.start])
		b.WriteString(newMarker(kindEncoded, s[sp.start:sp.end]))
		last = sp.end
	}
	b.WriteString(s[last:])
	hits := make([]string, 0, len(hitSet))
	for h := range hitSet {
		hits = append(hits, h)
	}
	return b.String(), hits
}

func isB64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

// encodedRuns returns candidate runs: maximal base64-alphabet runs of at
// least minEncodedRun bytes, and maximal non-space runs that contain at
// least four escape sequences (\xHH, \NNN, \uHHHH, %HH).
func encodedRuns(s string) [][2]int {
	var out [][2]int
	for i := 0; i < len(s); {
		if !isB64Byte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isB64Byte(s[j]) {
			j++
		}
		if j-i >= minEncodedRun && j-i <= maxEncodedRun {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	for i := 0; i < len(s); {
		if isSpaceOrQuote(s[i]) {
			i++
			continue
		}
		j := i
		esc := 0
		for j < len(s) && !isSpaceOrQuote(s[j]) {
			if (s[j] == '\\' || s[j] == '%') && j+1 < len(s) {
				esc++
			}
			j++
		}
		if esc >= 4 && j-i <= maxEncodedRun {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

func isSpaceOrQuote(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\'', '"', '`':
		return true
	}
	return false
}

// decodings returns every plausible decoding of run (bounded, one nested
// level).
func decodings(run string, depth int) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if len(b) == 0 {
			return
		}
		out = append(out, b)
		if u := utf16le(b); u != nil {
			out = append(out, u)
		}
		if depth == 0 {
			for _, rn := range encodedRuns(string(b)) {
				out = append(out, decodings(string(b[rn[0]:rn[1]]), 1)...)
				if len(out) > 32 {
					break
				}
			}
		}
	}
	trimmed := strings.TrimRight(run, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil {
			add(b)
		}
	}
	// A run can carry a non-base64 prefix glued to the payload ("-pAAAA");
	// try the longest suffix that decodes as well.
	if len(trimmed) > minEncodedRun {
		for cut := 1; cut <= 3 && cut < len(trimmed); cut++ {
			if b, err := base64.RawStdEncoding.DecodeString(trimmed[cut:]); err == nil {
				add(b)
				break
			}
		}
	}
	if len(run)%2 == 0 && allHexAny(run) {
		if b, err := hex.DecodeString(run); err == nil {
			add(b)
		}
	}
	if strings.ContainsAny(run, `\%`) {
		if b := unescapeRun(run); b != nil {
			add(b)
		}
	}
	return out
}

func allHexAny(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// utf16le converts b when it looks like UTF-16LE text (PowerShell
// -EncodedCommand): even length and a zero in most odd positions.
func utf16le(b []byte) []byte {
	if len(b) < 4 || len(b)%2 != 0 {
		return nil
	}
	zeros := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	if zeros*4 < len(b)/2*3 {
		return nil
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return []byte(string(utf16.Decode(u)))
}

// unescapeRun decodes \xHH, \NNN (octal), \uHHHH and %HH sequences and
// keeps everything else.
func unescapeRun(s string) []byte {
	var b []byte
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\' && i+3 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') && isHex(s[i+2]) && isHex(s[i+3]):
			v, _ := strconv.ParseUint(s[i+2:i+4], 16, 8)
			b = append(b, byte(v))
			i += 4
			n++
		case c == '\\' && i+5 < len(s) && s[i+1] == 'u' && allHexAny(s[i+2:i+6]):
			v, _ := strconv.ParseUint(s[i+2:i+6], 16, 32)
			b = append(b, string(rune(v))...)
			i += 6
			n++
		case c == '\\' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7':
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint(s[i+1:j], 8, 16)
			b = append(b, byte(v))
			i = j
			n++
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b = append(b, byte(v))
			i += 3
			n++
		default:
			b = append(b, c)
			i++
		}
	}
	if n == 0 {
		return nil
	}
	return b
}
