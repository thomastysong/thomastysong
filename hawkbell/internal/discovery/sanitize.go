package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
)

// safeText makes an attacker-influenced string fit to emit: names of MCP
// servers, skill folders, versions and paths all come from files a user
// (or a cloned repository) controls, so any of them can carry a credential
// or terminal control sequences. Invalid UTF-8 and control characters are
// dropped, credentials are replaced by classify's redaction marker and the
// result is capped at max bytes on a rune boundary.
func safeText(s string, max int) string {
	if s == "" {
		return ""
	}
	if len(s) > 4*max+64 {
		s = s[:4*max+64]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if r == utf8.RuneError && n <= 1 {
			continue
		}
		if unicode.IsControl(r) || isInvisibleFormat(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if red, hits := classify.Redact(out); len(hits) > 0 {
		out = red
	}
	if len(out) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
	}
	return out
}

// isInvisibleFormat covers bidi controls and tag characters, which would let
// a crafted name render differently in a console than it is stored.
func isInvisibleFormat(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	case r == 0x200B, r == 0x200C, r == 0x200D, r == 0x2060, r == 0xFEFF:
		return true
	}
	return false
}

// safeVersion accepts only version-shaped strings. A version read from a
// package manifest is attacker-controlled; anything that does not look
// like a version is dropped rather than emitted.
func safeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" || len(v) > 64 {
		return ""
	}
	digit := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-', c == '+', c == '_', c == '~':
		default:
			return ""
		}
	}
	if !digit {
		return ""
	}
	if len(classify.FindSecrets(v)) > 0 {
		return ""
	}
	return v
}

// sha256Hex is the full lower-case hex digest of b.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// digestParts hashes a list of strings unambiguously.
func digestParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
