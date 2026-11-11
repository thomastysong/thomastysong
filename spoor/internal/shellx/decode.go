package shellx

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// unescapeC decodes backslash escapes as bash does for $'..', printf formats
// and echo -e. It reports whether a hex, octal or unicode escape produced a
// character, which is how commands get spelled without their letters.
func unescapeC(s string) (out string, coded bool) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case 'e', 'E':
			b.WriteByte(27)
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		case 'x':
			j := i + 1
			for j < len(s) && j < i+3 && isHexDigit(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteString("\\x")
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:j], 16, 8)
			b.WriteByte(byte(v))
			coded = true
			i = j - 1
		case 'u', 'U':
			max := 4
			if e == 'U' {
				max = 8
			}
			j := i + 1
			for j < len(s) && j < i+1+max && isHexDigit(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('\\')
				b.WriteByte(e)
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			b.WriteRune(rune(v))
			coded = true
			i = j - 1
		case 'c':
			// \cX is a control character; it never spells a command.
			if i+1 < len(s) {
				b.WriteByte(s[i+1] & 0x1f)
				i++
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			// echo and printf also accept \0NNN.
			if e == '0' && j == i+1 {
				for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
			}
			v, _ := strconv.ParseUint(s[i:j], 8, 16)
			b.WriteByte(byte(v))
			coded = true
			i = j - 1
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String(), coded
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// formatPrintf evaluates a printf format with static arguments. Only the
// directives that matter for building strings are supported (%s %b %c %d %i
// %u %x %X %o %q %%); anything else makes the result unknown.
func formatPrintf(format string, args []string) (out string, coded bool, ok bool) {
	var b strings.Builder
	used := 0
	for round := 0; round < 256; round++ {
		start := used
		for i := 0; i < len(format); i++ {
			c := format[i]
			if c == '\\' {
				// Escapes are processed on the format itself.
				j := i + 1
				for j < len(format) && j < i+10 && format[j] != '\\' && format[j] != '%' {
					j++
				}
				seg, cd := unescapeC(format[i:j])
				coded = coded || cd
				b.WriteString(seg)
				i = j - 1
				continue
			}
			if c != '%' {
				b.WriteByte(c)
				continue
			}
			i++
			if i >= len(format) {
				b.WriteByte('%')
				break
			}
			// Flags, width and precision change padding only; skip them.
			for i < len(format) && strings.IndexByte("-+ #0123456789.", format[i]) >= 0 {
				i++
			}
			if i >= len(format) {
				return "", false, false
			}
			next := func() string {
				if used < len(args) {
					used++
					return args[used-1]
				}
				return ""
			}
			switch format[i] {
			case '%':
				b.WriteByte('%')
			case 's', 'q':
				b.WriteString(next())
			case 'b':
				seg, cd := unescapeC(next())
				coded = coded || cd
				b.WriteString(seg)
			case 'c':
				if v := next(); v != "" {
					b.WriteByte(v[0])
				}
			case 'd', 'i', 'u':
				v := next()
				if v == "" {
					v = "0"
				}
				if _, err := strconv.ParseInt(v, 0, 64); err != nil {
					return "", false, false
				}
				b.WriteString(v)
			case 'x', 'X', 'o':
				v := next()
				n, err := strconv.ParseInt(v, 0, 64)
				if err != nil && v != "" {
					return "", false, false
				}
				base := 16
				if format[i] == 'o' {
					base = 8
				}
				s := strconv.FormatInt(n, base)
				if format[i] == 'X' {
					s = strings.ToUpper(s)
				}
				b.WriteString(s)
			default:
				return "", false, false
			}
			if b.Len() > maxStatic {
				return "", false, false
			}
		}
		// The format is reused while arguments remain, as printf does.
		if used >= len(args) || used == start {
			break
		}
	}
	return b.String(), coded, true
}

// decodeBase64 is lenient the way command-line decoders are: whitespace is
// ignored, both alphabets and missing padding are accepted.
func decodeBase64(s string) ([]byte, bool) {
	if len(s) > maxDecodeInput {
		return nil, false
	}
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
		case c == '-':
			clean = append(clean, '+')
		case c == '_':
			clean = append(clean, '/')
		case c == '=':
		case isAlnum(c) || c == '+' || c == '/':
			clean = append(clean, c)
		default:
			return nil, false
		}
	}
	if len(clean) < 4 || len(clean)%4 == 1 {
		return nil, false
	}
	out, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, false
	}
	return out, true
}

// decodeHex decodes plain hex dumps (xxd -r -p input): whitespace ignored,
// optional \x or 0x prefixes tolerated.
func decodeHex(s string) ([]byte, bool) {
	if len(s) > maxDecodeInput {
		return nil, false
	}
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isSpace(c) || c == ',':
		case (c == '\\' || c == '0') && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
			i++
		case isHexDigit(c):
			clean = append(clean, c)
		default:
			return nil, false
		}
	}
	if len(clean) < 2 || len(clean)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(clean)/2)
	if _, err := hex.Decode(out, clean); err != nil {
		return nil, false
	}
	return out, true
}

// decodeUTF16LE converts PowerShell -EncodedCommand bytes to a string.
func decodeUTF16LE(b []byte) (string, bool) {
	if len(b) < 2 || len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if u[0] == 0xfeff {
		u = u[1:]
	}
	s := string(utf16.Decode(u))
	if !textual(s) {
		return "", false
	}
	return s, true
}

// looksUTF16LE reports whether b is plausibly UTF-16LE text in the Latin
// range: every second byte is zero.
func looksUTF16LE(b []byte) bool {
	if len(b) < 4 || len(b)%2 != 0 {
		return false
	}
	zero := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zero++
		}
	}
	return zero*10 >= (len(b)/2)*8
}

// textual reports whether s is something a human or an interpreter would
// read: valid UTF-8, no NUL, almost entirely printable.
func textual(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	bad := 0
	n := 0
	for _, r := range s {
		n++
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if r == 0 || r == utf8.RuneError || !unicode.IsPrint(r) {
			bad++
		}
	}
	return bad*20 <= n
}

// gunzip inflates at most maxStatic bytes. Compressed payloads are a common
// second layer under base64; anything larger is not worth holding.
func gunzip(b []byte) ([]byte, bool) {
	if len(b) < 3 || b[0] != 0x1f || b[1] != 0x8b {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxStatic+1))
	if (err != nil && len(out) == 0) || len(out) > maxStatic {
		return nil, false
	}
	return out, true
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// reverseLines applies rev(1): each line is reversed, line order is kept.
func reverseLines(s string) string {
	if strings.IndexByte(s, '\n') < 0 {
		return reverseString(s)
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = reverseString(lines[i])
	}
	return strings.Join(lines, "\n")
}
