package mcpconf

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
)

// scanWindow is how much of one value is handed to the secret scanner. The
// total scanned for a file stays proportional to the file size because every
// byte belongs to at most one value.
const scanWindow = 64 << 10

// fp8 is the house fingerprint: first 8 hex digits of an UNKEYED SHA-256.
// It lets an analyst on the endpoint see that two redacted values are the
// same credential without seeing either. It may appear only inside a
// classify-shaped marker ("[REDACTED:<kind>:<fp8>]", outputMark): that exact
// shape is what package privacy rewrites on the way out (keyed with the
// tenant key, or removed), because an unkeyed fingerprint of a short secret
// is an offline guessing oracle. Anywhere else, use runFP8.
func fp8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func window(s string) string {
	if len(s) > scanWindow {
		return s[:scanWindow]
	}
	return s
}

func buildReferencePatterns(t *tables) {
	// reRef matches a value that is nothing but a reference to a secret kept
	// elsewhere: ${VAR}, ${env:VAR}, ${input:id} (VS Code prompts), $VAR,
	// %VAR%, {env:VAR} / {file:path} (opencode), ${{ secrets.X }} (Continue).
	// ${VAR:-default} is deliberately not matched: the default is a literal
	// and has to be scanned.
	t.reRef = regexp.MustCompile(`^(?:\$\{\{[^{}]*\}\}|\$\{[A-Za-z_][\w.]*(?::[A-Za-z_][\w./\-]*)?\}|\$[A-Za-z_]\w*|\$env:[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{(?:env|file|input|secret|secrets):[^{}]*\})$`)
	// reAuthScheme strips "Bearer " and friends so "Bearer ${TOKEN}" counts
	// as a reference.
	t.reAuthScheme = regexp.MustCompile(`^(?i)(?:bearer|basic|token|bot|apikey|api-key|key|digest)\s+`)
}

// isReference reports whether v only points at a secret (a variable, an
// input prompt, a secret-store lookup) instead of containing one.
func isReference(v string) bool {
	v = strings.TrimSpace(v)
	v = tab().reAuthScheme.ReplaceAllString(v, "")
	return tab().reRef.MatchString(strings.TrimSpace(v))
}

// isDocPlaceholder recognises the stand-ins documentation uses where a
// credential belongs. Only used for structural URL checks; everything that
// goes through classify.FindSecrets relies on its own placeholder filter.
func isDocPlaceholder(v string) bool {
	lv := strings.ToLower(strings.TrimSpace(v))
	if lv == "" {
		return true
	}
	switch lv {
	case "password", "passwd", "pass", "secret", "token", "user", "username", "changeme",
		"example", "redacted", "null", "none", "placeholder", "apikey", "api_key", "key":
		return true
	}
	if strings.HasPrefix(lv, "<") && strings.HasSuffix(lv, ">") {
		return true
	}
	if strings.HasPrefix(lv, "your") || strings.HasPrefix(lv, "my-") || strings.HasPrefix(lv, "my_") {
		return true
	}
	return strings.Trim(lv, "x*.-_") == ""
}

// nameWords splits an identifier into lower-case words at separators and
// camelCase boundaries: "X-API-Key" -> x api key, "clientSecret" -> client
// secret.
func nameWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return words
}

func buildSecretWords(t *tables) {
	t.secretWords = map[string]bool{
		"token": true, "secret": true, "secrets": true, "password": true, "passwd": true,
		"pwd": true, "passphrase": true, "credential": true, "credentials": true,
		"apikey": true, "bearer": true, "jwt": true, "pat": true, "cookie": true,
		"authorization": true,
	}
	// keyQualifiers turn the neutral word "key" into a credential name.
	t.keyQualifiers = map[string]bool{
		"api": true, "access": true, "private": true, "secret": true, "auth": true,
		"encryption": true, "signing": true, "master": true, "license": true, "ssh": true,
		"account": true, "subscription": true, "service": true,
	}
	// paramWords are additionally treated as credentials in a URL query,
	// where short names are the norm (SAS "sig", "?key=").
	t.paramWords = map[string]bool{"auth": true, "sig": true, "signature": true, "key": true, "code": true}
}

var (
	secretStems = []string{"password", "passwd", "secret", "apikey", "accesskey", "privatekey",
		"credential", "accesstoken", "authtoken", "bearer"}
)

// isSecretName reports whether a variable, flag or header name conventionally
// holds a credential. It works on whole words so that max_tokens, tokenizer
// and --path are not mistaken for one.
func isSecretName(name string) bool {
	if len(name) > 256 {
		name = name[:256]
	}
	words := nameWords(name)
	hasKey, hasQual := false, false
	for _, w := range words {
		if tab().secretWords[w] {
			return true
		}
		if w == "key" || w == "keys" {
			hasKey = true
		}
		if tab().keyQualifiers[w] {
			hasQual = true
		}
	}
	if hasKey && hasQual {
		return true
	}
	squashed := strings.Join(words, "")
	for _, stem := range secretStems {
		if strings.Contains(squashed, stem) {
			return true
		}
	}
	return strings.HasSuffix(squashed, "token")
}

func isSecretParam(name string) bool {
	if isSecretName(name) {
		return true
	}
	for _, w := range nameWords(name) {
		if tab().paramWords[w] {
			return true
		}
	}
	return false
}

// isSecretFlag reports whether a command-line flag takes a credential.
func isSecretFlag(flag string) bool {
	if !strings.HasPrefix(flag, "-") {
		return false
	}
	name, _, _ := strings.Cut(strings.TrimLeft(flag, "-"), "=")
	return isSecretName(name)
}

// secretHits wraps classify.FindSecrets with bounds checks, so a surprising
// offset from another package can never turn into a slice panic here.
func secretHits(s string) []classify.SecretHit {
	hits := classify.FindSecrets(s)
	out := hits[:0:0]
	for _, h := range hits {
		if h.Start >= 0 && h.End > h.Start && h.End <= len(s) {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// hasSecret reports whether value is a credential-shaped literal. name gives
// the scanner the assignment context it needs for secrets that have no
// provider prefix; seps are the ways the pair is spelled ("=", ": ").
func hasSecret(name, value string, seps ...string) bool {
	if strings.TrimSpace(value) == "" || isReference(value) {
		return false
	}
	v := window(value)
	if name == "" {
		return len(secretHits(v)) > 0
	}
	if len(name) > 256 {
		name = name[:256]
	}
	for _, sep := range seps {
		prefix := name + sep
		for _, h := range secretHits(prefix + v) {
			if h.End > len(prefix) {
				return true
			}
		}
	}
	return false
}

// marker renders a redaction. In output mode it carries a fingerprint; the
// definition hash uses a constant so that rotating a secret is not drift.
type marker func(kind, secret string) string

func outputMark(kind, secret string) string { return "[REDACTED:" + kind + ":" + fp8(secret) + "]" }
func hashMark(string, string) string        { return "[REDACTED]" }

func buildTextPatterns(t *tables) {
	t.reURLInText = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{1,24}://[^\s"'<>` + "`" + `]+`)
	// reAssign finds NAME=value where NAME is checked by isSecretName.
	t.reAssign = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.\-]*)=("[^"]*"|'[^']*'|[^\s"';&|]+)`)
	// reAuthHeader finds an Authorization header written inline (curl -H ...).
	t.reAuthHeader = regexp.MustCompile(`(?i)((?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:(?:bearer|basic|token|digest)\s+)?)([^\s"'\\]+)`)
	t.reHeaderLine = regexp.MustCompile(`^\s*([A-Za-z0-9_\-]+)\s*[:=]\s*(.*)$`)
	t.reEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)
}

// redactURL removes what a URL carries as credential: userinfo, values of
// secret-named query parameters and, when paths is set, opaque path tokens.
func redactURL(raw string, mark marker, paths bool) string {
	u := splitURL(raw)
	if u.scheme == "" {
		return raw
	}
	var b strings.Builder
	b.WriteString(u.scheme + "://")
	if u.userinfo != "" {
		if marked(u.userinfo) || allRefs(strings.Split(u.userinfo, ":")) {
			b.WriteString(u.userinfo + "@")
		} else {
			b.WriteString(mark("userinfo", u.userinfo) + "@")
		}
	}
	if strings.Contains(u.host, ":") {
		b.WriteString("[" + u.host + "]")
	} else {
		b.WriteString(u.host)
	}
	if u.port != "" {
		b.WriteString(":" + u.port)
	}
	if paths {
		b.WriteString(redactPath(u.path, mark))
	} else {
		b.WriteString(u.path)
	}
	if u.query != "" {
		params := strings.Split(u.query, "&")
		for i, kv := range params {
			k, v, ok := strings.Cut(kv, "=")
			if ok && v != "" && isSecretParam(k) && !isReference(v) && !marked(v) {
				params[i] = k + "=" + mark("query", v)
			}
		}
		b.WriteString("?" + strings.Join(params, "&"))
	}
	if u.fragment != "" {
		b.WriteString("#" + u.fragment)
	}
	return b.String()
}

func allRefs(parts []string) bool {
	for _, p := range parts {
		if p != "" && !isReference(p) {
			return false
		}
	}
	return true
}

func redactPath(path string, mark marker) string {
	if path == "" {
		return ""
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if opaque, _ := pathToken(seg); opaque && !marked(seg) {
			segs[i] = mark("path", seg)
		}
	}
	return strings.Join(segs, "/")
}

// redactor rewrites declared text so that it can leave the machine (output
// mode) or be hashed without tying the hash to a secret's value (hash mode).
type redactor struct {
	mark marker
	// scan enables classify.FindSecrets. The hash does not use it: a pattern
	// update would otherwise change hashes fleet-wide and read as drift.
	scan bool
}

// text applies the structure-independent rules to free text: scanner hits,
// URLs, NAME=value assignments with credential names, inline Authorization
// headers and PEM blocks.
//
// The scanner runs first, on the text as written, so its offsets are right
// and it never sees this package's own markers; the structural rules then
// leave anything already marked alone.
func (r redactor) text(s string) string {
	if s == "" {
		return s
	}
	if r.scan {
		s = redactHits(s, r.mark)
	}
	// Each rule is gated on a literal it cannot match without. The hash
	// runs these rules over whole arguments, which can be megabytes.
	if strings.Contains(s, "://") {
		s = tab().reURLInText.ReplaceAllStringFunc(s, func(m string) string {
			return redactURL(m, r.mark, r.scan)
		})
	}
	if strings.Contains(s, "=") {
		s = tab().reAssign.ReplaceAllStringFunc(s, func(m string) string {
			k, v, _ := strings.Cut(m, "=")
			bare := strings.Trim(v, `"'`)
			if !isSecretName(k) || bare == "" || isReference(bare) || marked(bare) {
				return m
			}
			return k + "=" + r.mark("assignment", bare)
		})
	}
	if containsFold(s, "authorization") {
		s = tab().reAuthHeader.ReplaceAllStringFunc(s, func(m string) string {
			sub := tab().reAuthHeader.FindStringSubmatch(m)
			if sub == nil || isReference(sub[2]) || marked(sub[2]) {
				return m
			}
			return sub[1] + r.mark("header", sub[2])
		})
	}
	// A private key cut by a size limit no longer matches a BEGIN..END
	// pattern; everything after a BEGIN marker goes, matched or not.
	if i := strings.Index(s, "-----BEGIN"); i >= 0 {
		s = s[:i] + r.mark("private_key_block", s[i:])
	}
	return s
}

// containsFold reports whether s contains the lower-case ASCII word sub in
// any letter case, without allocating a lowered copy of s.
func containsFold(s, sub string) bool {
	n := len(sub)
	if n == 0 {
		return true
	}
	first := sub[0]
	for i := 0; i+n <= len(s); i++ {
		if s[i]|0x20 != first {
			continue
		}
		if strings.EqualFold(s[i:i+n], sub) {
			return true
		}
	}
	return false
}

// marked reports whether v already contains a redaction marker.
func marked(v string) bool { return strings.Contains(v, "[REDACTED") }

func redactHits(s string, mark marker) string {
	hits := secretHits(s)
	if len(hits) == 0 {
		return s
	}
	var b strings.Builder
	pos := 0
	for _, h := range hits {
		if h.Start < pos {
			continue // overlaps a span already replaced
		}
		b.WriteString(s[pos:h.Start])
		kind := h.Kind
		if kind == "" {
			kind = "secret"
		}
		b.WriteString(mark(kind, s[h.Start:h.End]))
		pos = h.End
	}
	b.WriteString(s[pos:])
	return b.String()
}

// value redacts a string that is known to be the value of a credential slot.
func (r redactor) value(kind, v string) string {
	if v == "" || isReference(v) {
		return v
	}
	return r.mark(kind, v)
}

// headerLine redacts "Name: value" as passed to --header.
func (r redactor) headerLine(line string) string {
	m := tab().reHeaderLine.FindStringSubmatch(line)
	if m == nil {
		return r.text(line)
	}
	name, val := m[1], m[2]
	if isSecretName(name) || isSecretParam(name) {
		scheme := tab().reAuthScheme.FindString(val)
		return name + ": " + scheme + r.value("header", strings.TrimSpace(val[len(scheme):]))
	}
	return name + ": " + r.text(val)
}

// envPair redacts the value of K=V unconditionally: an env value is never
// emitted, wherever it is written.
func (r redactor) envPair(kv string) string {
	k, v, ok := strings.Cut(kv, "=")
	if !ok || !tab().reEnvName.MatchString(k) {
		return r.text(kv)
	}
	return k + "=" + r.value("env", v)
}

// args redacts an argv. container says the launcher is docker or podman,
// where -e/--env introduce environment values.
func (r redactor) args(args []string, container bool) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	prev := ""
	for i, a := range args {
		if r.scan {
			a = window(a)
		}
		lp := strings.ToLower(prev)
		switch {
		case prev != "" && !strings.Contains(prev, "=") && isSecretFlag(prev):
			out[i] = r.value("arg", a)
		case lp == "-h" || lp == "--header" || lp == "--headers":
			out[i] = r.headerLine(a)
		case container && (prev == "-e" || prev == "--env"):
			out[i] = r.envPair(a)
		case container && strings.HasPrefix(a, "-e") && len(a) > 2 && !strings.HasPrefix(a, "-e=") && tab().reEnvAssign.MatchString(a[2:]):
			out[i] = "-e" + r.envPair(a[2:]) // attached form: -eNAME=value
		case strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			flag, v, _ := strings.Cut(a, "=")
			lf := strings.ToLower(flag)
			switch {
			case isSecretFlag(flag):
				out[i] = flag + "=" + r.value("arg", v)
			case lf == "--header" || lf == "--headers" || lf == "-h":
				out[i] = flag + "=" + r.headerLine(v)
			case container && (flag == "--env" || flag == "-e"):
				out[i] = flag + "=" + r.envPair(v)
			default:
				out[i] = flag + "=" + r.text(v)
			}
		case r.scan && len(a) >= 32 && !isFlag(a) && opaqueToken(a) && !tab().reHex.MatchString(a) && !tab().reUUID.MatchString(a):
			// A long random word passed as an argument is a credential more
			// often than not. With no pattern to confirm it, it is withheld
			// from output (when in doubt, redact) but raises no flag.
			out[i] = r.mark("opaque", a)
		default:
			out[i] = r.text(a)
		}
		prev = args[i]
	}
	return out
}
