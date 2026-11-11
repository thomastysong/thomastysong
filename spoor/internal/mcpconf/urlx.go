package mcpconf

import (
	"net/netip"
	"regexp"
	"strings"
)

// urlParts is a lexical split of a URL. net/url is not used: declared URLs
// contain templates (${HOST}), stray spaces and other things it rejects, and
// a rejected URL would mean an endpoint with no host in the inventory.
type urlParts struct {
	scheme   string // lower-cased, without "://"
	userinfo string
	host     string // lower-cased, no port, no brackets
	port     string
	path     string
	query    string // without "?"
	fragment string // without "#"
}

var reScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://`)

func splitURL(raw string) urlParts {
	var u urlParts
	s := strings.TrimSpace(raw)
	if m := reScheme.FindString(s); m != "" {
		u.scheme = strings.ToLower(m[:len(m)-3])
		s = s[len(m):]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		u.fragment, s = s[i+1:], s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		u.query, s = s[i+1:], s[:i]
	}
	// Browsers and Node treat "\" as "/" for http-like schemes; ending the
	// authority there keeps this reading aligned with what the client will
	// actually contact for inputs like http://good.example\@evil.example/.
	authority := s
	if i := strings.IndexAny(s, `/\`); i >= 0 {
		authority, u.path = s[:i], s[i:]
	}
	if i := strings.LastIndexByte(authority, '@'); i >= 0 {
		u.userinfo, authority = authority[:i], authority[i+1:]
	}
	host := authority
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			u.port = strings.TrimPrefix(host[i+1:], ":")
			host = host[1:i]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "}") {
		// The "}" check keeps ${HOST:-localhost} in one piece.
		host, u.port = host[:i], host[i+1:]
	}
	u.host = strings.ToLower(host)
	return u
}

// isURLLike reports whether s starts with a network scheme this package
// reasons about.
func isURLLike(s string) bool {
	switch splitURL(s).scheme {
	case "http", "https", "ws", "wss":
		return reScheme.MatchString(strings.TrimSpace(s))
	}
	return false
}

// sanitizedURL is the URL without userinfo, query or fragment. It feeds the
// definition hash: rotating a token in the query must not look like a changed
// endpoint.
func sanitizedURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	u := splitURL(raw)
	var b strings.Builder
	if u.scheme != "" {
		b.WriteString(u.scheme)
		b.WriteString("://")
	}
	if strings.Contains(u.host, ":") {
		b.WriteString("[" + u.host + "]")
	} else {
		b.WriteString(u.host)
	}
	if u.port != "" {
		b.WriteString(":" + u.port)
	}
	b.WriteString(u.path)
	return b.String()
}

// isLocalHost reports whether traffic to host stays on the machine. A host
// that is a template is reported as local: it cannot be shown to leave the
// machine, and a risk flag needs evidence.
func isLocalHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" || strings.ContainsAny(h, "${}%") {
		return true
	}
	switch h {
	case "localhost", "ip6-localhost", "ip6-loopback", "host.docker.internal":
		return true
	}
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		ip = ip.Unmap()
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// reSecretParam matches query parameter (and flag, env, header) names that
// conventionally carry a credential.
var reSecretParam = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|pwd|api[-_]?key|apikey|access[-_]?key|credential|signature|sig|auth|bearer|session|jwt|private[-_]?key|pat)`)

func isSecretName(name string) bool {
	if strings.EqualFold(name, "key") {
		return true
	}
	return reSecretParam.MatchString(name)
}

// urlCredential reports whether a URL carries a credential as written:
// a password in the userinfo, or a secret-named query parameter with a
// literal value. Path tokens are judged by pathToken.
func urlCredential(raw string) bool {
	u := splitURL(raw)
	if u.userinfo != "" {
		user, pass, hasPass := strings.Cut(u.userinfo, ":")
		// A lone userinfo is a token for many APIs (https://TOKEN@host/).
		cred := user
		if hasPass {
			cred = pass
		}
		if cred != "" && !isReference(cred) {
			return true
		}
	}
	for _, kv := range strings.Split(u.query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if v != "" && isSecretName(k) && !isReference(v) {
			return true
		}
	}
	return false
}

var (
	reUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex  = regexp.MustCompile(`(?i)^[0-9a-f]+$`)
	reTok  = regexp.MustCompile(`^[A-Za-z0-9_\-.~+=]+$`)
)

// pathToken classifies one path segment.
//
//	opaque: long and random-looking; redacted from output because capability
//	        URLs (the path is the credential) are common for hosted MCP.
//	secret: opaque and not shaped like an identifier (UUID, hex id); enough
//	        evidence for the token_in_url flag.
func pathToken(seg string) (opaque, secret bool) {
	if len(seg) < 24 || !reTok.MatchString(seg) || isReference(seg) {
		return false, false
	}
	var digits, letters int
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letters++
		}
	}
	if digits < 3 || letters < 3 || shannon(seg) < 3.5 {
		return false, false
	}
	if reUUID.MatchString(seg) || (reHex.MatchString(seg) && len(seg) <= 40) {
		return true, false
	}
	return true, len(seg) >= 32
}
