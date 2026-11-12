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

func buildScheme(t *tables) {
	t.reScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://`)
}

func splitURL(raw string) urlParts {
	var u urlParts
	s := strings.TrimSpace(raw)
	if m := tab().reScheme.FindString(s); m != "" {
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
		return true
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

// urlCredential reports whether a URL carries a credential as written:
// a password in the userinfo, or a secret-named query parameter with a
// literal value. Path tokens are judged by pathToken.
func urlCredential(raw string) bool {
	u := splitURL(raw)
	if u.userinfo != "" {
		user, pass, hasPass := strings.Cut(u.userinfo, ":")
		cred := pass
		if !hasPass && len(user) >= 16 {
			// A lone userinfo is the token for many APIs
			// (https://TOKEN@host/); a short one is a user name.
			cred = user
		}
		if cred != "" && !isReference(cred) && !isDocPlaceholder(cred) {
			return true
		}
	}
	for _, kv := range strings.Split(u.query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if v != "" && isSecretParam(k) && !isReference(v) && !isDocPlaceholder(v) {
			return true
		}
	}
	return false
}

func buildTokenPatterns(t *tables) {
	t.reUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	t.reHex = regexp.MustCompile(`(?i)^[0-9a-f]+$`)
	t.reTok = regexp.MustCompile(`^[A-Za-z0-9_\-.~+=]+$`)
}

// opaqueToken reports whether s reads as machine-generated: long, one run of
// token characters, a mix of letters and digits, high entropy and few
// separators. Hyphenated names ("prod-us-east-1-cluster-2024") are not opaque.
func opaqueToken(s string) bool {
	if len(s) < 24 || !tab().reTok.MatchString(s) || isReference(s) {
		return false
	}
	var digits, letters, seps int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case isLetter(c):
			letters++
		case c == '-' || c == '_' || c == '.':
			seps++
		}
	}
	return digits >= 3 && letters >= 3 && seps <= len(s)/12 && shannon(s) >= 3.5
}

// identifierShaped reports a UUID or a short hex id: opaque, but more often
// a tenant or workspace id than a credential.
func identifierShaped(s string) bool {
	return tab().reUUID.MatchString(s) || (tab().reHex.MatchString(s) && len(s) <= 40)
}

// pathToken classifies one URL path segment.
//
//	opaque: machine-generated; redacted from output because capability URLs
//	        (the path is the credential) are common for hosted MCP servers.
//	secret: opaque, at least 32 bytes and not shaped like an identifier;
//	        enough evidence for the token_in_url flag.
func pathToken(seg string) (opaque, secret bool) {
	if !opaqueToken(seg) {
		return false, false
	}
	return true, len(seg) >= 32 && !identifierShaped(seg)
}
