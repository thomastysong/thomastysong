package classify

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// failClosed is what a redaction function returns for a value it could not
// process: an unredacted original must never leave because of a bug.
const failClosed = "[REDACTED:" + kindRedactionFailureLabel + ":00000000]"

// Marker returns the text Redact puts in place of a secret:
// "[REDACTED:<kind>:<fingerprint>]".
func Marker(kind, fingerprint string) string {
	return "[REDACTED:" + kind + ":" + fingerprint + "]"
}

func markerFor(kind, secret string) string { return Marker(kind, fingerprint(secret)) }

// truncationMarker records that n bytes were cut. It deliberately carries no
// digest of the cut content: unkeyed hashes of content are an oracle.
func truncationMarker(n int) string {
	return "[TRUNCATED:" + strconv.Itoa(n) + "B]"
}

// Redact replaces every secret FindSecrets reports in s with
// "[REDACTED:<kind>:<fingerprint>]" and returns the hits, whose offsets refer
// to s. Redacting already-redacted text changes nothing.
//
// Redact fails closed: input beyond the 16 MiB scan limit is not emitted
// unscanned but replaced by a "[TRUNCATED:<n>B]" marker, and if redaction
// itself fails the whole value is replaced by a marker.
func Redact(s string) (out string, hits []SecretHit) {
	defer func() {
		if recover() != nil {
			out, hits = failClosed, nil
		}
	}()
	scan, dropped := s, 0
	if len(s) > maxSecretScan {
		cut := safeCut(s, maxSecretScan)
		scan, dropped = s[:cut], len(s)-cut
	}
	hits = findSecrets(scan)
	if len(hits) == 0 && dropped == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(scan) + 64)
	last := 0
	for _, h := range hits {
		b.WriteString(scan[last:h.Start])
		b.WriteString(Marker(h.Kind, h.Fingerprint))
		last = h.End
	}
	b.WriteString(scan[last:])
	if dropped > 0 {
		b.WriteString(truncationMarker(dropped))
	}
	return b.String(), hits
}

// safeCut picks a cut point at or before limit that does not split a token:
// the last whitespace within 4 KiB, else a rune boundary. A token cut in half
// would match no pattern and its head would be emitted.
func safeCut(s string, limit int) int {
	if limit >= len(s) {
		return len(s)
	}
	floor := limit - 4096
	if floor < 0 {
		floor = 0
	}
	for i := limit; i > floor; i-- {
		switch s[i-1] {
		case ' ', '\n', '\t', '\r':
			return i
		}
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return limit
}

// RedactURL removes what a URL should not carry into telemetry. Userinfo is
// always stripped. Without keepQuery the query and fragment are dropped; with
// it they are kept but the values of secret-named parameters (token, key,
// sig, code, password, X-Amz-Signature ...) are replaced by markers. The
// result then passes through Redact, so credentials in the path (webhook
// URLs, bot tokens) are covered too. data: URLs keep only their media type.
// Redaction markers already in the URL are kept as written and never
// matched inside or across.
func RedactURL(raw string, keepQuery bool) (out string) {
	defer func() {
		if recover() != nil {
			out = failClosed
		}
	}()
	if raw == "" {
		return ""
	}
	dropped := 0
	if len(raw) > maxSecretScan {
		cut := safeCut(raw, maxSecretScan)
		raw, dropped = raw[:cut], len(raw)-cut
	}
	p := splitURL(raw)
	var b strings.Builder
	if p.opaque {
		if p.scheme == "data" {
			media := p.rest
			if i := strings.IndexByte(media, ','); i >= 0 {
				dropped += len(media) - i - 1
				media = media[:i+1]
			}
			return "data:" + media + truncationMarker(dropped)
		}
		rest := p.rest
		if !keepQuery {
			if i := strings.IndexAny(rest, "?#"); i >= 0 {
				rest = rest[:i]
			}
		}
		b.WriteString(p.scheme)
		b.WriteByte(':')
		b.WriteString(rest)
	} else {
		b.WriteString(p.prefix)
		b.WriteString(p.hostport)
		b.WriteString(p.path)
		if keepQuery {
			if p.hasQuery {
				b.WriteByte('?')
				b.WriteString(redactQuery(p.query))
			}
			if p.hasFrag {
				b.WriteByte('#')
				// OAuth implicit flow puts access_token in the fragment.
				if strings.Contains(p.fragment, "=") {
					b.WriteString(redactQuery(p.fragment))
				} else {
					b.WriteString(p.fragment)
				}
			}
		}
	}
	out, _ = Redact(b.String())
	if dropped > 0 && !p.opaque {
		out += truncationMarker(dropped)
	}
	return out
}

// redactQuery replaces the values of secret-named parameters in a query
// string, leaving names, order and separators as written.
func redactQuery(q string) string {
	if q == "" {
		return q
	}
	var b strings.Builder
	b.Grow(len(q))
	for {
		i := strings.IndexByte(q, '&')
		if i < 0 {
			b.WriteString(redactPair(q))
			break
		}
		b.WriteString(redactPair(q[:i]))
		b.WriteByte('&')
		q = q[i+1:]
	}
	return b.String()
}

func redactPair(pair string) string {
	i := strings.IndexByte(pair, '=')
	if i <= 0 || i == len(pair)-1 {
		return pair
	}
	name, value := percentDecode(pair[:i]), pair[i+1:]
	if !secretParamName(name) || keepAsWritten(percentDecode(value)) {
		return pair
	}
	// A value that already holds a marker keeps it: the new markers cover
	// only what is around it.
	return pair[:i+1] + markAroundMarkers(KindURLParam, value)
}

// keepAsWritten reports values that structural redaction leaves alone even
// under a secret name: references to a secret held elsewhere and template
// placeholders. Everything else under a secret name is redacted, however
// short or weak, because in a real invocation it IS the credential.
func keepAsWritten(v string) bool {
	return v == "" || isReference(v) || wrapped(v)
}
