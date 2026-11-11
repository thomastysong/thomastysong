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

var passwordWords = map[string]bool{
	"password": true, "passwd": true, "passphrase": true, "pwd": true,
	"pass": true, "passcode": true, "passwords": true,
}

var secretWords = map[string]bool{
	"secret": true, "token": true, "apikey": true, "credential": true,
	"credentials": true, "auth": true, "bearer": true, "authorization": true,
	"jwt": true, "cookie": true, "cookies": true, "secretkey": true,
	"privatekey": true, "accesskey": true, "secrets": true,
}

// keyQualifiers are the words that turn a following "key" into a secret name
// ("api_key", "signing-key"). A bare "key" is far too common to match alone.
var keyQualifiers = map[string]bool{
	"api": true, "access": true, "auth": true, "private": true, "signing": true,
	"encryption": true, "decryption": true, "master": true, "subscription": true,
	"functions": true, "license": true, "secret": true, "account": true,
	"storage": true, "shared": true, "session": true, "deploy": true,
	"service": true, "admin": true, "root": true, "hmac": true, "aes": true,
	"sas": true, "app": true, "application": true, "client": true, "crypt": true,
	"webhook": true, "fernet": true, "jwt": true, "token": true,
}

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
var allowedTail = map[string]bool{
	"key": true, "value": true, "val": true, "secret": true, "token": true,
	"str": true, "string": true, "b64": true, "base64": true, "hex": true,
	"raw": true, "plain": true, "plaintext": true, "binary": true, "pem": true,
	"new": true, "old": true, "current": true, "previous": true, "prev": true,
	"prod": true, "production": true, "dev": true, "development": true,
	"staging": true, "stage": true, "test": true, "live": true, "sandbox": true,
	"default": true, "primary": true, "secondary": true, "main": true,
	"backup": true, "confirm": true, "confirmation": true, "repeat": true,
	"again": true, "hash": true, "hashed": true, "digest": true, "salt": true,
	"enc": true, "encrypted": true, "cipher": true, "ciphertext": true,
	"admin": true, "root": true, "user": true, "rw": true, "ro": true,
	"read": true, "write": true, "readonly": true, "bearer": true,
	"access": true, "refresh": true, "a": true, "b": true, "x": true, "y": true,
	"v1": true, "v2": true, "v3": true,
}

// booleanPrefixes start names whose value is a switch or a count
// ("has_password", "use_token", "max_tokens"), not a secret.
var booleanPrefixes = map[string]bool{
	"no": true, "has": true, "have": true, "is": true, "use": true, "uses": true,
	"require": true, "requires": true, "required": true, "show": true,
	"hide": true, "enable": true, "enabled": true, "disable": true,
	"disabled": true, "allow": true, "skip": true, "ask": true, "remember": true,
	"mask": true, "redact": true, "with": true, "without": true, "forgot": true,
	"max": true, "min": true, "num": true, "count": true, "total": true,
}

// paginationWords precede "token" in cursors ("nextPageToken"): high entropy,
// not credentials, and useful to keep readable.
var paginationWords = map[string]bool{
	"page": true, "next": true, "continuation": true, "pagination": true,
	"cursor": true, "sync": true, "resume": true, "upload": true, "delta": true,
}

// publicWords mark the non-secret half of a key pair.
var publicWords = map[string]bool{
	"public": true, "pub": true, "pubkey": true, "publickey": true,
	"publishable": true,
}

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
	if booleanPrefixes[words[0]] && len(words) > 1 {
		return nameNone
	}
	last := -1 // index of the last word that is part of a keyword
	tier := nameNone
	for i, w := range words {
		if publicWords[w] {
			return nameNone
		}
		switch {
		case passwordWords[w]:
			last, tier = i, namePassword
		case secretWords[w]:
			if w == "token" && i > 0 && paginationWords[words[i-1]] {
				return nameNone
			}
			last, tier = i, nameSecret
		case w == "key" && i > 0 && keyQualifiers[words[i-1]]:
			last, tier = i, nameSecret
		default:
			for _, cs := range compoundSuffixes {
				if len(w) > len(cs.suffix) && strings.HasSuffix(w, cs.suffix) {
					stem := w[:len(w)-len(cs.suffix)]
					if cs.suffix == "token" && (paginationWords[stem] || strings.HasSuffix(stem, "page")) {
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
		if allowedTail[w] || allDigits(w) {
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
var urlParamNames = map[string]bool{
	"key": true, "sig": true, "signature": true, "code": true, "sas": true,
	"hmac": true, "otp": true, "assertion": true, "client_assertion": true,
	"x-amz-signature": true, "x-amz-credential": true, "x-amz-security-token": true,
	"x-goog-signature": true, "x-goog-credential": true, "awsaccesskeyid": true,
	"sharedaccesssignature": true, "samlresponse": true,
}

// secretParamName reports whether a URL query or fragment parameter name
// should have its value redacted.
func secretParamName(name string) bool {
	if secretName(name) != nameNone {
		return true
	}
	return urlParamNames[asciiLower(name)]
}
