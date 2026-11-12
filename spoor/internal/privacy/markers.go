package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
)

// Marker handling. classify replaces a secret with
// "[REDACTED:<kind>:<fp>]" where fp is the first 8 hex digits of an
// UNKEYED SHA-256 of the secret. That fingerprint is fine for detection on
// the endpoint but an offline guessing oracle once it leaves (a short
// password is found by hashing a dictionary). Everything this package emits
// therefore has those fingerprints rewritten: keyed with the tenant key, or
// removed when there is no key.

const (
	markerOpen   = "[REDACTED:"
	truncOpen    = "[TRUNCATED:"
	maxMarkerLen = 160 // longest "[REDACTED:...]" treated as one marker
)

// unkeyedFP mirrors classify's fingerprint: the first 4 bytes of SHA-256 in
// hex. It is only used to build markers that are rewritten before output
// and to verify which substring a classify marker stood for.
func unkeyedFP(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// newMarker builds a classify-format marker for a secret this package
// found itself, so it flows through the same rewrite as classify's.
func newMarker(kind, secret string) string {
	return classify.Marker(kind, unkeyedFP(secret))
}

// truncMarker states how many bytes were cut. Like classify's, it carries
// no digest of the cut text.
func truncMarker(n int) string { return truncOpen + strconv.Itoa(n) + "B]" }

// rawMarker is one classify-format marker found in a string.
type rawMarker struct {
	start, end int
	kind, fp   string
}

// classifyMarkers finds markers with an 8-hex unkeyed fingerprint.
func classifyMarkers(s string) []rawMarker {
	var out []rawMarker
	for off := 0; off < len(s); {
		i := strings.Index(s[off:], markerOpen)
		if i < 0 {
			break
		}
		i += off
		j := i + len(markerOpen)
		k := j
		for k < len(s) && k-j <= 64 && isKindByte(s[k]) {
			k++
		}
		if k == j || k+10 > len(s) || s[k] != ':' || s[k+9] != ']' || !allHex(s[k+1:k+9]) {
			off = i + 1
			continue
		}
		out = append(out, rawMarker{start: i, end: k + 10, kind: s[j:k], fp: s[k+1 : k+9]})
		off = k + 10
	}
	return out
}

func isKindByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// protectedSpans returns the byte ranges of every redaction or truncation
// marker in s (any form, including rewritten ones). Searches for secret
// text skip these so a secret that happens to equal a kind name ("password")
// cannot mangle a marker.
func protectedSpans(s string) [][2]int {
	var out [][2]int
	for _, open := range []string{markerOpen, truncOpen} {
		for off := 0; off < len(s); {
			i := strings.Index(s[off:], open)
			if i < 0 {
				break
			}
			i += off
			end := strings.IndexByte(s[i+len(open):], ']')
			if end < 0 || end > maxMarkerLen {
				off = i + 1
				continue
			}
			end += i + len(open) + 1
			out = append(out, [2]int{i, end})
			off = end
		}
	}
	return out
}

func inSpans(spans [][2]int, start, end int) bool {
	for _, sp := range spans {
		if start < sp[1] && end > sp[0] {
			return true
		}
	}
	return false
}

// replaceOutside replaces every occurrence of old in s that does not
// overlap a marker. bounded additionally requires word boundaries around
// the match. It returns the result and the number of replacements.
func replaceOutside(s, old, repl string, bounded bool) (string, int) {
	if old == "" || len(old) > len(s) || !strings.Contains(s, old) {
		return s, 0
	}
	spans := protectedSpans(s)
	var b strings.Builder
	n, last := 0, 0
	for off := 0; off <= len(s)-len(old); {
		i := strings.Index(s[off:], old)
		if i < 0 {
			break
		}
		i += off
		end := i + len(old)
		ok := !inSpans(spans, i, end)
		if ok && bounded {
			ok = (i == 0 || isBoundary(s[i-1])) && (end == len(s) || isBoundary(s[end]))
		}
		if !ok {
			off = i + 1
			continue
		}
		if n == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:i])
		b.WriteString(repl)
		last = end
		off = end
		n++
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}

// isBoundary is what may surround a whole argument inside a larger shell
// string: whitespace, quotes, separators and grouping.
func isBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\'', '"', '`', ';', '|', '&', '(', ')', '<', '>', '{', '}':
		return true
	}
	return false
}

// secret is one credential value and the marker that replaces it.
type secret struct {
	value, marker string
}

// alignSecrets recovers the secret substrings of old that classify replaced
// to produce red: the text between the literal parts surrounding each
// marker. Where a candidate's unkeyed fingerprint matches the marker the
// recovery is exact; otherwise the candidate is still returned (searching
// for a few extra bytes is harmless, missing a secret is not).
func alignSecrets(old, red string) []secret {
	ms := classifyMarkers(red)
	if len(ms) == 0 {
		if old != red && old != "" {
			return []secret{{value: old, marker: newMarker("generic_secret", old)}}
		}
		return nil
	}
	var out []secret
	lits := make([]string, len(ms)+1)
	prev := 0
	for i, m := range ms {
		lits[i] = red[prev:m.start]
		prev = m.end
	}
	lits[len(ms)] = red[prev:]
	if !strings.HasPrefix(old, lits[0]) {
		// Structure changed in a way we cannot follow (for example a URL
		// rewritten while being redacted); fall back to the whole value.
		return []secret{{value: old, marker: newMarker("generic_secret", old)}}
	}
	pos := len(lits[0])
	for i, m := range ms {
		marker := red[m.start:m.end]
		next := lits[i+1]
		var cand string
		switch {
		case i == len(ms)-1:
			if !strings.HasSuffix(old[pos:], next) {
				return append(out, secret{value: old[pos:], marker: marker})
			}
			cand = old[pos : len(old)-len(next)]
			pos = len(old)
		case next == "":
			// Two adjacent markers: the split point is unknowable; take the
			// remainder for both.
			return append(out, secret{value: old[pos:], marker: marker})
		default:
			cand = ""
			found := false
			for off, tries := pos, 0; off <= len(old) && tries < 16; tries++ {
				j := strings.Index(old[off:], next)
				if j < 0 {
					break
				}
				j += off
				c := old[pos:j]
				if cand == "" {
					cand = c
				}
				if unkeyedFP(c) == m.fp {
					cand = c
					found = true
					pos = j + len(next)
					break
				}
				off = j + 1
			}
			if !found {
				if cand == "" {
					return append(out, secret{value: old[pos:], marker: marker})
				}
				pos += len(cand) + len(next)
			}
		}
		if cand != "" {
			out = append(out, secret{value: cand, marker: marker})
		}
	}
	return out
}

// Marker shielding. classify.Redact is not idempotent on its own markers
// for secret-named kinds: in "[REDACTED:password:b6155b48]" its assignment
// scanner reads "password:b6155b48" as a credential and nests a second
// marker. Every classify call on text that may already carry markers
// therefore goes through a shield that swaps markers for variable
// references (which classify keeps as written) and restores them after.

const shieldOpen = "${SPOOR_M"

type shield struct{ marks []string }

// hide replaces every marker in s with a numbered reference.
func (sh *shield) hide(s string) string {
	if !strings.Contains(s, markerOpen) && !strings.Contains(s, truncOpen) {
		return s
	}
	spans := protectedSpans(s)
	if len(spans) == 0 {
		return s
	}
	sortSpans(spans)
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		if sp[0] < last {
			continue
		}
		b.WriteString(s[last:sp[0]])
		b.WriteString(shieldOpen)
		b.WriteString(strconv.Itoa(len(sh.marks)))
		b.WriteByte('}')
		sh.marks = append(sh.marks, s[sp[0]:sp[1]])
		last = sp[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// show restores the markers hide removed.
func (sh *shield) show(s string) string {
	if len(sh.marks) == 0 || !strings.Contains(s, shieldOpen) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, shieldOpen)
		if i < 0 {
			break
		}
		j := i + len(shieldOpen)
		k := j
		for k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
		if k == j || k >= len(s) || s[k] != '}' {
			b.WriteString(s[:j])
			s = s[j:]
			continue
		}
		n, err := strconv.Atoi(s[j:k])
		if err != nil || n >= len(sh.marks) {
			b.WriteString(s[:k+1])
			s = s[k+1:]
			continue
		}
		b.WriteString(s[:i])
		b.WriteString(sh.marks[n])
		s = s[k+1:]
	}
	b.WriteString(s)
	return b.String()
}

func sortSpans(sp [][2]int) {
	for i := 1; i < len(sp); i++ {
		for j := i; j > 0 && sp[j][0] < sp[j-1][0]; j-- {
			sp[j], sp[j-1] = sp[j-1], sp[j]
		}
	}
}

// redactText is classify.Redact with markers shielded.
func redactText(s string) string {
	var sh shield
	h := sh.hide(s)
	out, _ := classify.Redact(h)
	return flattenNested(sh.show(unwrapShield(h, out)))
}

// redactArgs is classify.RedactArgs with markers shielded, plus this
// package's own flag rules (argrules.go).
func redactArgs(args []string) []string {
	var sh shield
	in := make([]string, len(args))
	for i, a := range args {
		in[i] = sh.hide(a)
	}
	out := classify.RedactArgs(in)
	for i := range out {
		if i < len(in) {
			out[i] = unwrapShield(in[i], out[i])
		}
		out[i] = sh.show(out[i])
	}
	moreArgSecrets(args, out)
	for i := range out {
		out[i] = flattenNested(out[i])
	}
	return out
}

// flattenNested collapses a marker wrapped around another marker into one.
// classify.RedactArgs does this to a database URL: it first redacts the
// userinfo password, then its URL pattern matches across that marker and
// yields "postgres://[REDACTED:database_url_with_password:[REDACTED:password:fp]",
// which reads as garbage and defeats marker parsing downstream. The
// combined span becomes a single marker of the outer kind.
func flattenNested(s string) string {
	if strings.Count(s, markerOpen) < 2 {
		return s
	}
	for n := 0; n < 64; n++ {
		start, end, kind := findNested(s)
		if start < 0 {
			break
		}
		s = s[:start] + newMarker(kind, s[start:end]) + s[end:]
	}
	return s
}

// findNested returns the span and outer kind of the first marker whose
// body opens another marker ("[REDACTED:kind:[REDACTED:...]",
// "[REDACTED:kind:hmac=[REDACTED...]"). The span ends after the inner
// marker's closing bracket and, when present, the outer one's.
func findNested(s string) (start, end int, kind string) {
	for off := 0; off < len(s); {
		i := strings.Index(s[off:], markerOpen)
		if i < 0 {
			break
		}
		i += off
		j := i + len(markerOpen)
		k := j
		for k < len(s) && k-j <= 64 && isKindByte(s[k]) {
			k++
		}
		p := k
		if p < len(s) && s[p] == ':' {
			p++
		}
		p += len(prefixOf(s[p:], "hmac="))
		if !strings.HasPrefix(s[p:], markerOpen) {
			off = i + 1
			continue
		}
		kind = s[j:k]
		if kind == "" {
			kind = classify.KindGenericSecret
		}
		depth := 1
		e := p
		for e < len(s) {
			if strings.HasPrefix(s[e:], markerOpen) {
				depth++
				e += len(markerOpen)
				continue
			}
			if s[e] == ']' {
				e++
				depth--
				// The outer marker's own bracket, when classify kept it.
				for depth > 0 && e < len(s) && s[e] == ']' {
					e++
					depth--
				}
				break
			}
			e++
		}
		return i, e, kind
	}
	return -1, 0, ""
}

func prefixOf(s, p string) string {
	if strings.HasPrefix(s, p) {
		return p
	}
	return ""
}

// unwrapShield undoes a marker classify put over a shield reference (it
// redacts "pass:<anything>" unconditionally): the reference stands for a
// marker that is already there, so the new marker is dropped again.
func unwrapShield(hidden, red string) string {
	if !strings.Contains(hidden, shieldOpen) || hidden == red {
		return red
	}
	for _, s := range alignSecrets(hidden, red) {
		v := s.value
		if strings.HasPrefix(v, shieldOpen) && strings.HasSuffix(v, "}") && strings.Count(v, "}") == 1 {
			red = strings.Replace(red, s.marker, v, 1)
		}
	}
	return red
}

// redactURL is classify.RedactURL with markers shielded.
func redactURL(s string, keepQuery bool) string {
	var sh shield
	return sh.show(classify.RedactURL(sh.hide(s), keepQuery))
}

// controlsToSpace replaces C0 control characters other than tab, newline
// and carriage return (and DEL) with spaces. A NUL cannot occur in a real
// argument vector; inside a command string it only serves to hide a
// program name from tool-specific redaction ("mysql\x00 -pX").
func controlsToSpace(s string) (string, bool) {
	changed := false
	b := []byte(s)
	for i, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			b[i] = ' '
			changed = true
		}
	}
	if !changed {
		return s, false
	}
	return string(b), true
}

// redactMap is classify.RedactMap with markers shielded in keys and
// string values.
func redactMap(m map[string]any, maxString int) (map[string]any, []string) {
	var sh shield
	hidden := rekeyAny(m, 0, sh.hide)
	walkAny(hidden, "", 0, func(s slot) { s.set(sh.hide(s.get())) })
	out, truncated := classify.RedactMap(hidden, maxString)
	if len(sh.marks) == 0 {
		return out, truncated
	}
	out = rekeyAny(out, 0, sh.show)
	walkAny(out, "", 0, func(s slot) { s.set(sh.show(s.get())) })
	return out, truncated
}
