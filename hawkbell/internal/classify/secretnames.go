package classify

import "strings"

// nameTier says how a key, flag, header or parameter NAME relates to secrets.
// The two positive tiers exist because the right gate differs: passwords are
// chosen by people and are often low entropy, while tokens and keys are
// machine generated, so an entropy gate removes most false positives for them
// without losing real ones.
type nameTier uint8

const (
	nameNone     nameTier = iota
	namePassword          // value is redacted without an entropy gate
	nameSecret            // value is entropy-gated in free text
)

// maxNameLen bounds name analysis; longer "names" are not identifiers.
const maxNameLen = 128

var passwordWords = lazySet{list: []string{
	"password", "passwd", "passphrase", "pwd",
	"pass", "passcode", "passwords",
}}

var secretWords = lazySet{list: []string{
	"secret", "token", "apikey", "credential",
	"credentials", "auth", "bearer", "authorization",
	"jwt", "cookie", "cookies", "secretkey",
	"privatekey", "accesskey", "secrets",
}}

// keyQualifiers are the words that turn a following "key" into a secret name
// ("api_key", "signing-key"). A bare "key" is far too common to match alone.
var keyQualifiers = lazySet{list: []string{
	"api", "access", "auth", "private", "signing",
	"encryption", "decryption", "master", "subscription",
	"functions", "license", "secret", "account",
	"storage", "shared", "session", "deploy",
	"service", "admin", "root", "hmac", "aes",
	"sas", "app", "application", "client", "crypt",
	"webhook", "fernet", "jwt", "token",
}}

// compoundSuffixes catch names written without separators ("dbpassword",
// "authtoken"). "pass", "pwd" and "auth" are deliberately absent: they are
// suffixes of ordinary words (compass, bypass).
var compoundSuffixes = []struct {
	suffix string
	tier   nameTier
}{
	{"password", namePassword}, {"passwd", namePassword}, {"passphrase", namePassword},
	{"secret", nameSecret}, {"token", nameSecret}, {"apikey", nameSecret},
	{"secretkey", nameSecret}, {"privatekey", nameSecret}, {"accesskey", nameSecret},
}

// allowedTail lists words that may follow the keyword without changing what
// the value is ("api_key_prod", "password_confirmation", "SecretString").
// Any other trailing word means the name describes metadata about a secret
// ("token_url", "secret_name", "password_min_length"), not the secret.
var allowedTail = lazySet{list: []string{
	"key", "value", "val", "secret", "token",
	"str", "string", "b64", "base64", "hex",
	"raw", "plain", "plaintext", "binary", "pem",
	"new", "old", "current", "previous", "prev",
	"prod", "production", "dev", "development",
	"staging", "stage", "test", "live", "sandbox",
	"default", "primary", "secondary", "main",
	"backup", "confirm", "confirmation", "repeat",
	"again", "hash", "hashed", "digest", "salt",
	"enc", "encrypted", "cipher", "ciphertext",
	"admin", "root", "user", "rw", "ro",
	"read", "write", "readonly", "bearer",
	"access", "refresh", "a", "b", "x", "y",
	"v1", "v2", "v3",
}}

// booleanPrefixes start names whose value is a switch or a count
// ("has_password", "use_token", "max_tokens"), not a secret.
var booleanPrefixes = lazySet{list: []string{
	"no", "has", "have", "is", "use", "uses",
	"require", "requires", "required", "show",
	"hide", "enable", "enabled", "disable",
	"disabled", "allow", "skip", "ask", "remember",
	"mask", "redact", "with", "without", "forgot",
	"max", "min", "num", "count", "total",
}}

// paginationWords precede "token" in cursors ("nextPageToken"): high entropy,
// not credentials, and useful to keep readable.
var paginationWords = lazySet{list: []string{
	"page", "next", "continuation", "pagination",
	"cursor", "sync", "resume", "upload", "delta",
}}

// publicWords mark the non-secret half of a key pair.
var publicWords = lazySet{list: []string{
	"public", "pub", "pubkey", "publickey",
	"publishable",
}}

// splitNameWords breaks an identifier into lower-case words on separators and
// camelCase boundaries. It returns nil for names that are too long or have too
// many parts to be identifiers.
func splitNameWords(name string) []string {
	if len(name) == 0 || len(name) > maxNameLen {
		return nil
	}
	words := make([]string, 0, 6)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, asciiLower(name[start:end]))
		}
		start = -1
	}
	isUpper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	isLower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isAlnum(c) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := name[i-1]
		switch {
		case isUpper(c) && (isLower(prev) || isDigit(prev)):
			// fooBar -> foo, Bar
			flush(i)
			start = i
		case isUpper(prev) && isLower(c) && i-1 > start:
			// APIKey -> API, Key (split before the last capital)
			flush(i - 1)
			start = i - 1
		}
	}
	flush(len(name))
	if len(words) > 16 {
		return nil
	}
	return words
}

// secretName classifies a key, flag, header or variable name.
func secretName(name string) nameTier {
	words := splitNameWords(name)
	if len(words) == 0 {
		return nameNone
	}
	if booleanPrefixes.has(words[0]) && len(words) > 1 {
		return nameNone
	}
	last := -1 // index of the last word that is part of a keyword
	tier := nameNone
	for i, w := range words {
		if publicWords.has(w) {
			return nameNone
		}
		switch {
		case passwordWords.has(w):
			last, tier = i, namePassword
		case secretWords.has(w):
			if w == "token" && i > 0 && paginationWords.has(words[i-1]) {
				return nameNone
			}
			last, tier = i, nameSecret
		case w == "key" && i > 0 && keyQualifiers.has(words[i-1]):
			last, tier = i, nameSecret
		default:
			for _, cs := range compoundSuffixes {
				if len(w) > len(cs.suffix) && strings.HasSuffix(w, cs.suffix) {
					stem := w[:len(w)-len(cs.suffix)]
					if cs.suffix == "token" && (paginationWords.has(stem) || strings.HasSuffix(stem, "page")) {
						return nameNone
					}
					last, tier = i, cs.tier
					break
				}
			}
		}
	}
	if tier == nameNone {
		return nameNone
	}
	for _, w := range words[last+1:] {
		if allowedTail.has(w) || allDigits(w) {
			continue
		}
		return nameNone
	}
	return tier
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// urlParamNames are query parameter names that carry credentials in URLs but
// are too generic to treat as secret names anywhere else ("key", "code").
var urlParamNames = lazySet{list: []string{
	"key", "sig", "signature", "code", "sas",
	"hmac", "otp", "assertion", "client_assertion",
	"x-amz-signature", "x-amz-credential", "x-amz-security-token",
	"x-goog-signature", "x-goog-credential", "awsaccesskeyid",
	"sharedaccesssignature", "samlresponse",
}}

// secretParamName reports whether a URL query or fragment parameter name
// should have its value redacted.
func secretParamName(name string) bool {
	if secretName(name) != nameNone {
		return true
	}
	return urlParamNames.has(asciiLower(name))
}
