package classify

import (
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxURLParse bounds how much of an input the URL splitter looks at for the
// scheme and authority. Hosts cannot be longer than 253 bytes; the margin is
// for userinfo.
const maxURLParse = 8 << 10

// urlParts is a tolerant decomposition of a URL-like string. It keeps the
// original text of each part (no decoding) so callers can reassemble a
// redacted URL byte for byte.
type urlParts struct {
	prefix   string // "scheme://", "//" or "" exactly as written
	scheme   string // lower-cased, "" when absent
	opaque   bool   // scheme:rest with no authority (mailto:, data:, ...)
	rest     string // for opaque URLs: everything after "scheme:"
	userinfo string
	hasUser  bool
	hostport string
	path     string
	query    string
	hasQuery bool
	fragment string
	hasFrag  bool
}

// opaqueSchemes have no authority component.
var opaqueSchemes = map[string]bool{
	"mailto": true, "data": true, "javascript": true, "tel": true, "sms": true,
	"urn": true, "about": true, "blob": true, "magnet": true, "bitcoin": true,
	"cid": true, "mid": true, "news": true, "xmpp": true, "vbscript": true,
}

// slashOptionalSchemes are parsed by browsers and curl even when the "//" is
// missing or malformed ("http:/host", "https:host").
var slashOptionalSchemes = map[string]bool{
	"http": true, "https": true, "ftp": true, "ws": true, "wss": true,
}

func isSchemeChar(c byte, first bool) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	return !first && (isDigit(c) || c == '+' || c == '-' || c == '.')
}

// splitURL never fails: input that is not a URL comes back as a schemeless
// authority and path. Backslashes end the authority the way they do in
// browsers, because "http://good\@evil/" is a known parser-confusion trick
// and treating "\" as "/" picks the host a browser-based fetcher would use.
func splitURL(s string) urlParts {
	var p urlParts
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'<>`")
	if strings.ContainsAny(s, "\t\r\n") {
		// Browsers strip these anywhere in a URL.
		s = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(s)
	}
	rest := s
	if i := strings.IndexByte(s, ':'); i > 0 && i <= 32 {
		ok := true
		for j := 0; j < i; j++ {
			if !isSchemeChar(s[j], j == 0) {
				ok = false
				break
			}
		}
		if ok {
			scheme := asciiLower(s[:i])
			after := s[i+1:]
			switch {
			case len(after) >= 2 && isSlash(after[0]) && isSlash(after[1]):
				p.scheme, p.prefix, rest = scheme, s[:i+3], after[2:]
			case opaqueSchemes[scheme]:
				p.scheme, p.opaque, p.rest = scheme, true, after
				return p
			case slashOptionalSchemes[scheme]:
				p.scheme = scheme
				trimmed := strings.TrimLeft(after, `/\`)
				p.prefix, rest = s[:len(s)-len(trimmed)], trimmed
			}
			// Otherwise "host:port" or "host:path" (scp style): no scheme.
		}
	}
	if p.scheme == "" && len(rest) >= 2 && isSlash(rest[0]) && isSlash(rest[1]) {
		p.prefix, rest = rest[:2], rest[2:]
	}
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c == '/' || c == '\\' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority, tail := rest[:end], rest[end:]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		p.userinfo, p.hasUser, p.hostport = authority[:at], true, authority[at+1:]
	} else {
		p.hostport = authority
	}
	if i := strings.IndexByte(tail, '#'); i >= 0 {
		p.fragment, p.hasFrag, tail = tail[i+1:], true, tail[:i]
	}
	if i := strings.IndexByte(tail, '?'); i >= 0 {
		p.query, p.hasQuery, tail = tail[i+1:], true, tail[:i]
	}
	p.path = tail
	return p
}

func isSlash(c byte) bool { return c == '/' || c == '\\' }

// URLHost extracts the host from a URL-like string. The scheme is optional,
// userinfo and port are removed, IPv6 brackets and zone ids are stripped, the
// result is lower-cased and has no trailing dot. scp-style remotes
// ("git@github.com:org/repo") yield the host. It returns "" when no plausible
// host is present. URLHost never panics.
func URLHost(raw string) (host string) {
	defer func() {
		if recover() != nil {
			host = ""
		}
	}()
	if len(raw) > maxURLParse {
		raw = raw[:maxURLParse]
	}
	p := splitURL(raw)
	if p.opaque {
		if p.scheme != "mailto" {
			return ""
		}
		addr := p.rest
		if i := strings.IndexAny(addr, "?#"); i >= 0 {
			addr = addr[:i]
		}
		at := strings.LastIndexByte(addr, '@')
		if at < 0 {
			return ""
		}
		return normalizeHost(addr[at+1:])
	}
	if p.scheme == "file" {
		return ""
	}
	return normalizeHost(p.hostport)
}

// normalizeHost turns a host[:port] into the canonical host used for
// classification, or "" if it cannot be a host.
func normalizeHost(hp string) string {
	hp = strings.TrimSpace(hp)
	if hp == "" || len(hp) > 1024 {
		return ""
	}
	if strings.IndexByte(hp, '%') >= 0 {
		hp = percentDecode(hp)
	}
	var h string
	switch {
	case hp[0] == '[':
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return ""
		}
		h = hp[1:end]
	case strings.Count(hp, ":") >= 2:
		// Unbracketed IPv6 literal (no port can follow it).
		h = hp
	default:
		h = hp
		if i := strings.IndexByte(hp, ':'); i >= 0 {
			// ":port", or the ":path" of an scp-style remote.
			h = hp[:i]
		}
	}
	if i := strings.IndexByte(h, '%'); i >= 0 && strings.Contains(h, ":") {
		h = h[:i] // IPv6 zone id
	}
	if !isASCII(h) {
		// IDNA maps full-width letters, digits and the ideographic full stops
		// to ASCII before resolution, so "169。254。169。254" and "ｅｖｉｌ.com"
		// reach the same hosts as their ASCII forms.
		h = norm.NFKC.String(h)
		h = strings.Map(func(r rune) rune {
			switch r {
			case '。', '．', '｡':
				return '.'
			case utf8.RuneError:
				return -1
			}
			return r
		}, h)
		h = strings.ToLower(h)
	} else {
		h = asciiLower(h)
	}
	h = strings.TrimRight(h, ".")
	if h == "" || len(h) > 253 {
		return ""
	}
	if strings.Contains(h, ":") {
		addr, err := netip.ParseAddr(h)
		if err != nil {
			return ""
		}
		return addr.WithZone("").String()
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 0x80 || isAlnum(c) || c == '.' || c == '-' || c == '_' {
			continue
		}
		return ""
	}
	return h
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// percentDecode decodes %XX sequences and leaves malformed ones as written.
func percentDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
