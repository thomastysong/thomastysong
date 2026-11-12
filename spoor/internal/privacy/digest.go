package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Keyed digests.
//
// An unkeyed hash of a short value is a lookup key, not a pseudonym: the
// privacy red team recovered 4 of 6 sample prompts from their SHA-256 with
// a 1,600-entry dictionary built in 1 ms, and identical hashes linked users
// across hosts and tenants. Every content-derived digest is therefore
// HMAC-SHA-256 with the tenant key, or is not emitted.
//
// What the key does and does not protect (documented, not oversold): the
// key is present on every endpoint of the tenant, so keyed digests and
// pseudonyms protect against readers of the log store and against linkage
// across tenants, not against someone with root on an endpoint. In
// daemonless mode the hook process has no key and emits no digests.

// Digest domains keep a value hashed for one purpose from equalling the
// same value hashed for another.
const (
	domPrompt   = "spoor/v1/prompt"
	domInput    = "spoor/v1/tool.input"
	domOutput   = "spoor/v1/tool.output"
	domAccount  = "spoor/v1/account"
	domAsset    = "spoor/v1/asset"
	domDedup    = "spoor/v1/dedup"
	domSecretFP = "spoor/v1/secret-fp"
	domSummary  = "spoor/v1/summary-fp"
)

// digestHex is the length of an emitted keyed digest: 96 bits.
const digestHex = 24

func keyed(key []byte, domain string, data []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// Pseudonym returns the keyed pseudonym that replaces a user name when
// PseudonymizeUsers is set: "u_" + the first 16 hex digits of
// HMAC-SHA-256(Key, name). It returns "" without a usable key. The name is
// hashed exactly as given (case-sensitive), so tools that look a user up
// by pseudonym (purge, re-identification by the key holder) must pass the
// same spelling the sensor recorded.
func (p *Policy) Pseudonym(name string) string {
	s := p.settings()
	if s.key == nil || name == "" {
		return ""
	}
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(name))
	return "u_" + hex.EncodeToString(m.Sum(nil))[:16]
}

// contentDigest turns the unkeyed SHA-256 (hex) of a value into the keyed
// digest that may leave the endpoint. Deriving from the unkeyed hash, not
// the value, means every surface that saw the same value (hook, transcript)
// emits the same keyed digest even when only one of them carried content.
func contentDigest(key []byte, domain, sha256hex string) string {
	if key == nil || sha256hex == "" {
		return ""
	}
	return keyed(key, domain, []byte(strings.ToLower(sha256hex)))[:digestHex]
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// isSHA256Hex accepts a 64-digit hex string.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// rewriteMarkers replaces every unkeyed content fingerprint in s: those in
// classify's secret markers and the "fp:<8 hex>" summaries producers write
// in place of free text (see rewriteSummaries). With a key the fingerprint
// becomes "hmac=" + 8 hex digits of a keyed hash of the unkeyed one (so the
// same value still correlates within the tenant); without one it is
// removed.
func rewriteMarkers(s string, key []byte) string {
	return rewriteSummaries(rewriteSecretMarkers(s, key), key)
}

// rewriteSecretMarkers rewrites the fingerprints in classify's markers.
func rewriteSecretMarkers(s string, key []byte) string {
	if !strings.Contains(s, markerOpen) {
		return s
	}
	ms := classifyMarkers(s)
	if len(ms) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, m := range ms {
		b.WriteString(s[last:m.start])
		b.WriteString(markerOpen)
		b.WriteString(m.kind)
		if key != nil {
			b.WriteString(":hmac=")
			b.WriteString(keyed(key, domSecretFP, []byte(m.fp))[:8])
		}
		b.WriteByte(']')
		last = m.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// rewriteSummaries rewrites "fp:<8 hex>" summaries. Producers that will
// not emit free text reduce it to one (hookio: "tool error fp:1a2b3c4d"
// for a failed tool's error text, "denied fp:..." for a denial reason;
// otelrecv: "tool error fp:..."), and that is the first 8 hex digits of an
// UNKEYED SHA-256 of tool output: a short error text is recovered from it
// with a dictionary, and the same text links records across tenants. It
// is matched as a whole word anywhere in an emitted string, so a new
// producer of the same format is covered too.
func rewriteSummaries(s string, key []byte) string {
	if !strings.Contains(s, "fp:") {
		return s
	}
	var b strings.Builder
	last := 0
	for off := 0; off < len(s); {
		i := strings.Index(s[off:], "fp:")
		if i < 0 {
			break
		}
		i += off
		end := i + 3 + 8
		if end > len(s) || !anyCaseHex(s[i+3:end]) || (i > 0 && isWordByte(s[i-1])) || (end < len(s) && isWordByte(s[end])) {
			off = i + 1
			continue
		}
		start := i
		if key == nil && start > last && s[start-1] == ' ' {
			start-- // "tool error fp:x" -> "tool error"
		}
		b.WriteString(s[last:start])
		if key != nil {
			b.WriteString("hmac=")
			b.WriteString(keyed(key, domSummary, []byte(strings.ToLower(s[i+3:end])))[:8])
		}
		last = end
		off = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func anyCaseHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// bucket rounds a length up to the next power of four (1, 4, 16, 64, ...):
// an exact length narrows a dictionary attack on the value and is itself a
// fingerprint of short prompts.
func bucket(n int) int {
	if n <= 0 {
		return 0
	}
	b := 1
	for b < n && b < 1<<30 {
		b <<= 2
	}
	return b
}
