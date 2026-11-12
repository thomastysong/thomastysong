package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// SecretHit locates one credential in a string. Start and End are byte
// offsets (End exclusive) into the string that was scanned. Fingerprint is
// the first 8 hex digits of SHA-256 over the secret bytes: enough to tell
// "the same key again" from "a different key" across a fleet without making
// the value recoverable.
type SecretHit struct {
	Kind        string
	Start, End  int
	Fingerprint string
}

const (
	// maxSecretScan bounds the work one call can be made to do by hostile
	// input. Redact fails closed past it (the unscanned tail is dropped).
	maxSecretScan = 16 << 20
	// minSecretScan is shorter than any reportable hit plus its context.
	minSecretScan = 8
	// maxKeyBlock bounds the search for the END line of a private key.
	maxKeyBlock = 32 << 10
)

// rawHit is a candidate before overlap resolution.
type rawHit struct {
	start, end int
	kind       string
	prio       int
}

// FindSecrets detects credentials in s. Provider-specific token formats are
// tried first; URL userinfo, Authorization and Cookie headers, private key
// blocks and assignments to secret-like names follow. Every candidate passes
// a placeholder filter (example keys, "changeme", "<token>", "${VAR}" ...) and,
// where the value is machine generated, a Shannon-entropy gate.
//
// Hits are sorted by Start and never overlap. Only the first 16 MiB of s are
// scanned. FindSecrets never panics.
func FindSecrets(s string) (hits []SecretHit) {
	defer func() {
		if recover() != nil {
			hits = nil
		}
	}()
	if len(s) > maxSecretScan {
		s = s[:maxSecretScan]
	}
	return findSecrets(s)
}

func findSecrets(s string) []SecretHit {
	if len(s) < minSecretScan {
		return nil
	}
	low := asciiLower(s)
	var raw []rawHit
	for i, d := range detectors {
		if d.wanted(s, low) {
			raw = d.scan(s, raw, i)
		}
	}
	raw = scanPrivateKeys(s, raw)
	raw = scanURLCreds(s, raw)
	raw = scanAuthHeaders(s, low, raw)
	raw = scanCookies(s, low, raw)
	raw = scanAssignments(s, low, raw)
	return finalizeHits(s, raw)
}

func (d *detector) scan(s string, raw []rawHit, prio int) []rawHit {
	body := d.body
	if body == 0 {
		body = d.group
	}
	for _, loc := range d.regex().FindAllStringSubmatchIndex(s, -1) {
		a, b := loc[2*d.group], loc[2*d.group+1]
		ba, bb := loc[2*body], loc[2*body+1]
		if a < 0 || ba < 0 {
			continue
		}
		// Token alphabets that include "." would otherwise swallow the full
		// stop of the sentence the token appears in.
		for b > a && s[b-1] == '.' {
			b--
		}
		if bb > b {
			bb = b
		}
		if bb <= ba {
			continue
		}
		v := s[ba:bb]
		if isPlaceholderToken(v) {
			continue
		}
		if d.minEnt > 0 && Entropy(v) < d.minEnt {
			continue
		}
		raw = append(raw, rawHit{a, b, d.kindFor(s[a:b]), prio})
	}
	return raw
}

// scanPrivateKeys reports PEM / OpenSSH / PGP private key blocks whole, so a
// redacted string never keeps part of the key body. A BEGIN line without key
// material after it (documentation, a regex in source code) is not a hit.
func scanPrivateKeys(s string, raw []rawHit) []rawHit {
	if !strings.Contains(s, "PRIVATE KEY") {
		return raw
	}
	begin, end, gcp := privateKeyRegexes()
	kind := KindPrivateKeyBlock
	if gcp.MatchString(s) {
		// A service-account JSON file: the key is only useful with the
		// client_email beside it, and responders handle it differently.
		kind = KindGCPServiceAccount
	}
	pos := 0
	for pos < len(s) {
		loc := begin.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		start, bodyStart := pos+loc[0], pos+loc[1]
		limit := bodyStart + maxKeyBlock
		if limit > len(s) {
			limit = len(s)
		}
		stop := bodyStart
		if e := end.FindStringIndex(s[bodyStart:limit]); e != nil {
			stop = bodyStart + e[1]
			if keyMaterial(s[bodyStart:bodyStart+e[0]]) >= 40 {
				raw = append(raw, rawHit{start, stop, kind, prioPrivateKey})
			}
		} else {
			// Truncated block: take the run of key-body bytes that follows.
			i := bodyStart
			for i < limit {
				c := s[i]
				if isAlnum(c) || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t' {
					i++
					continue
				}
				if c == '\\' && i+1 < limit && (s[i+1] == 'n' || s[i+1] == 'r') {
					i += 2 // JSON-escaped newline inside a quoted key
					continue
				}
				break
			}
			stop = i
			if keyMaterial(s[bodyStart:stop]) >= 64 {
				raw = append(raw, rawHit{start, stop, kind, prioPrivateKey})
			}
		}
		if stop <= pos {
			stop = bodyStart
		}
		pos = stop
	}
	return raw
}

// keyMaterial counts base64 alphabet bytes, ignoring escaped newlines.
func keyMaterial(body string) int {
	n := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '\\' && i+1 < len(body) && (body[i+1] == 'n' || body[i+1] == 'r') {
			i++
			continue
		}
		if isAlnum(c) || c == '+' || c == '/' {
			n++
		}
	}
	return n
}

// defaultCreds are passwords so common in local development URLs
// (postgres://postgres:postgres@localhost) that reporting them is noise.
var defaultCreds = map[string]bool{
	"postgres": true, "root": true, "admin": true, "guest": true, "user": true,
	"mysql": true, "redis": true, "mongo": true, "test": true, "dev": true,
	"local": true, "docker": true, "anonymous": true,
}

func scanURLCreds(s string, raw []rawHit) []rawHit {
	if !strings.Contains(s, "://") || !strings.Contains(s, "@") {
		return raw
	}
	for _, loc := range urlCredsRegex().FindAllStringSubmatchIndex(s, -1) {
		scheme := asciiLower(s[loc[2]:loc[3]])
		kind := KindBasicAuthURL
		if dbSchemes[scheme] {
			kind = KindDatabaseURL
		}
		user := s[loc[4]:loc[5]]
		if loc[6] >= 0 && loc[7] > loc[6] {
			pass := s[loc[6]:loc[7]]
			lp := asciiLower(pass)
			if isPlaceholder(pass) || isReference(pass) || lp == asciiLower(user) || defaultCreds[lp] {
				continue
			}
			raw = append(raw, rawHit{loc[6], loc[7], kind, prioURLCreds})
			continue
		}
		// Token in the user position (https://<token>@github.com/...).
		if len(user) >= 20 && !isPlaceholder(user) && !isReference(user) && Entropy(user) >= 3.5 {
			raw = append(raw, rawHit{loc[4], loc[5], kind, prioURLCreds})
		}
	}
	return raw
}

// authSchemes are words that are an Authorization scheme, never a credential.
var authSchemes = map[string]bool{
	"bearer": true, "basic": true, "token": true, "digest": true, "apikey": true,
	"api-key": true, "oauth": true, "negotiate": true, "ntlm": true,
	"sso-key": true, "bot": true, "key": true,
}

func scanAuthHeaders(s, low string, raw []rawHit) []rawHit {
	hasAuth := strings.Contains(low, "authorization")
	hasBearer := strings.Contains(low, "bearer")
	if !hasAuth && !hasBearer {
		return raw
	}
	authRe, bearerRe := authHeaderRegexes()
	if hasAuth {
		for _, loc := range authRe.FindAllStringSubmatchIndex(s, -1) {
			scheme := ""
			if loc[2] >= 0 {
				scheme = asciiLower(s[loc[2]:loc[3]])
			}
			a, b := loc[4], loc[5]
			v := s[a:b]
			lv := asciiLower(v)
			if scheme == "digest" || authSchemes[lv] || strings.HasPrefix(lv, "aws4-") {
				continue
			}
			if !credentialShaped(v) {
				continue
			}
			kind := KindBearerHeader
			if scheme == "basic" {
				kind = KindBasicAuthHeader
			}
			raw = append(raw, rawHit{a, b, kind, prioAuthHeader})
		}
	}
	if hasBearer {
		for _, loc := range bearerRe.FindAllStringSubmatchIndex(s, -1) {
			v := s[loc[2]:loc[3]]
			if !credentialShaped(v) || Entropy(v) < 3.0 {
				continue
			}
			raw = append(raw, rawHit{loc[2], loc[3], KindBearerHeader, prioAuthHeader})
		}
	}
	return raw
}

// credentialShaped is the gate for values in an Authorization position: the
// position already says "credential", so the bar is only high enough to drop
// prose ("authorization: required") and references ("Bearer $TOKEN").
func credentialShaped(v string) bool {
	if len(v) < 8 || isPlaceholder(v) || isReference(v) {
		return false
	}
	if hasDigit(v) {
		return true
	}
	return len(v) >= 16 && Entropy(v) >= 3.0
}

func scanCookies(s, low string, raw []rawHit) []rawHit {
	if !strings.Contains(low, "cookie") {
		return raw
	}
	for _, loc := range cookieRegex().FindAllStringSubmatchIndex(s, -1) {
		v := s[loc[2]:loc[3]]
		if !hasDigit(v) || Entropy(v) < 3.0 || isPlaceholder(v) {
			continue
		}
		raw = append(raw, rawHit{loc[2], loc[3], KindCookieHeader, prioCookie})
	}
	return raw
}

// scanAssignments finds "name = value" (also JSON, YAML, env, query-string
// and "--flag value" forms) where the name is secret-like.
func scanAssignments(s, low string, raw []rawHit) []rawHit {
	found := false
	for _, stem := range assignStems {
		if strings.Contains(low, stem) {
			found = true
			break
		}
	}
	if !found {
		return raw
	}
	assignRe, flagRe := assignRegexes()
	raw = collectAssignments(s, assignRe, false, raw)
	if strings.Contains(s, "-") {
		raw = collectAssignments(s, flagRe, true, raw)
	}
	return raw
}

func collectAssignments(s string, re *regexp.Regexp, flag bool, raw []rawHit) []rawHit {
	for _, loc := range re.FindAllStringSubmatchIndex(s, -1) {
		name := s[loc[2]:loc[3]]
		tier := secretName(name)
		if tier == nameNone {
			continue
		}
		var a, b int
		quoted := true
		switch {
		case loc[4] >= 0:
			a, b = loc[4], loc[5]
		case loc[6] >= 0:
			a, b = loc[6], loc[7]
		default:
			a, b = loc[8], loc[9]
			quoted = false
			// Sentence punctuation after a bare value is not part of it.
			for b > a && strings.IndexByte(".,)]}:", s[b-1]) >= 0 {
				b--
			}
		}
		if b <= a {
			continue
		}
		v := s[a:b]
		if flag && !quoted && v[0] == '-' {
			continue // the next flag, not a value
		}
		if !valueIsSecret(tier, v, quoted) {
			continue
		}
		kind := KindGenericSecret
		if tier == namePassword {
			kind = KindPassword
		}
		raw = append(raw, rawHit{a, b, kind, prioAssignment})
	}
	return raw
}

// valueIsSecret is the gate for a value assigned to a secret-like name in
// free text. Passwords are human chosen, so a quoted literal is accepted as
// is and a bare word needs only a digit or symbol; tokens and keys are
// machine generated, so they must look random.
func valueIsSecret(tier nameTier, v string, quoted bool) bool {
	if isPlaceholder(v) || isReference(v) {
		return false
	}
	switch tier {
	case namePassword:
		if quoted {
			return len(v) >= 3
		}
		if len(v) < 6 {
			return false
		}
		if hasDigit(v) || hasSymbol(v) {
			return true
		}
		return len(v) >= 10 && Entropy(v) >= 3.0
	case nameSecret:
		if len(v) < 8 || allDigits(v) {
			return false
		}
		e := Entropy(v)
		if len(v) < 16 {
			return hasDigit(v) && hasLetter(v) && e >= 2.5
		}
		if hasDigit(v) {
			return e >= 3.0
		}
		// No digit at all is unusual for a generated token; accept only
		// mixed-case strings that are long and dense.
		return len(v) >= 20 && hasUpper(v) && hasLower(v) && e >= 3.5 && !strings.ContainsAny(v, " _")
	}
	return false
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

func hasLetter(s string) bool { return hasUpper(s) || hasLower(s) }

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func hasLower(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
}

func hasSymbol(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '_' && c < 0x80 {
			return true
		}
	}
	return false
}

// finalizeHits sorts candidates, merges overlapping ones (the higher-priority
// kind names the merged span, and the span is the union so nothing leaks) and
// attaches fingerprints.
func finalizeHits(s string, raw []rawHit) []SecretHit {
	if len(raw) == 0 {
		return nil
	}
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].start != raw[j].start {
			return raw[i].start < raw[j].start
		}
		if raw[i].prio != raw[j].prio {
			return raw[i].prio < raw[j].prio
		}
		return raw[i].end > raw[j].end
	})
	merged := raw[:1]
	for _, h := range raw[1:] {
		cur := &merged[len(merged)-1]
		if h.start < cur.end {
			if h.end > cur.end {
				cur.end = h.end
			}
			if h.prio < cur.prio {
				cur.prio, cur.kind = h.prio, h.kind
			}
			continue
		}
		merged = append(merged, h)
	}
	hits := make([]SecretHit, len(merged))
	for i, h := range merged {
		hits[i] = SecretHit{Kind: h.kind, Start: h.start, End: h.end, Fingerprint: fingerprint(s[h.start:h.end])}
	}
	return hits
}

// fingerprint is the first 8 hex digits of SHA-256(secret).
func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:4])
}
