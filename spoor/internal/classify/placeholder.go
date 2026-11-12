package classify

import "strings"

// placeholderExact are whole values that stand in for a secret in docs,
// templates and code, compared case-insensitively.
var placeholderExact = map[string]bool{
	"password": true, "passwd": true, "pass": true, "secret": true, "token": true,
	"key": true, "apikey": true, "api_key": true, "api-key": true,
	"changeme": true, "change_me": true, "change-me": true, "changeit": true,
	"example": true, "sample": true, "test": true, "testing": true, "demo": true,
	"dummy": true, "fake": true, "foo": true, "bar": true, "baz": true,
	"foobar": true, "none": true, "null": true, "nil": true, "undefined": true,
	"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true,
	"string": true, "str": true, "text": true, "value": true, "redacted": true,
	"hidden": true, "masked": true, "removed": true, "omitted": true,
	"placeholder": true, "todo": true, "tbd": true, "fixme": true,
	"required": true, "optional": true, "unset": true, "empty": true,
	"default": true, "n/a": true, "na": true, "bearer": true, "basic": true,
	"object": true, "bool": true, "boolean": true, "int": true, "number": true,
	"any": true, "bytes": true, "secretstr": true, "inherit": true, "include": true,
	"omit": true, "same-origin": true, "password123": true, "mypassword": true,
	"mysecret": true, "mytoken": true, "secret123": true,
}

// placeholderContains are substrings that mark a value as a stand-in. "test"
// is deliberately not here: it is part of real key prefixes (sk_test_).
var placeholderContains = []string{
	"example", "placeholder", "changeme", "change_me", "redacted", "your_",
	"your-", "your.", "yourkey", "yourtoken", "yoursecret", "yourpassword",
	"yourapikey", "<your", "insert", "replace_me", "replaceme", "replace-me",
	"dummy", "xxxx", "****", "....", "1234567", "abcdefg", "notreal",
	"not_real", "not-real", "fake", "sample", "put_your", "goes_here",
	"goes-here", "_here", "-here",
}

// isPlaceholder reports whether v is a stand-in rather than a credential.
func isPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	lv := asciiLower(v)
	if placeholderExact[lv] {
		return true
	}
	// Text this package already redacted must not be redacted again, or a
	// second pass nests markers ("[REDACTED:[REDACTED:...").
	if strings.Contains(v, "[REDACTED") || strings.Contains(v, "REDACTED:") {
		return true
	}
	if wrapped(v) {
		return true
	}
	for _, sub := range placeholderContains {
		if strings.Contains(lv, sub) {
			return true
		}
	}
	// "aaaaaaaa", "abababab", "--------": no information.
	if len(v) >= 6 && distinctBytes(v, 3) < 3 {
		return true
	}
	return false
}

// isPlaceholderToken is the placeholder test for the body of a prefixed
// provider token, where exact-word values cannot occur.
func isPlaceholderToken(body string) bool {
	lb := asciiLower(body)
	for _, sub := range placeholderContains {
		if strings.Contains(lb, sub) {
			return true
		}
	}
	return len(body) >= 8 && distinctBytes(body, 4) < 4
}

// wrapped reports template syntax around the whole value: <token>, [token],
// {token}, {{ token }}, ${VAR}, $(cmd), %VAR%, __TOKEN__, @@TOKEN@@, and
// spoor's own redaction and truncation markers.
func wrapped(v string) bool {
	if len(v) < 2 {
		return false
	}
	first, last := v[0], v[len(v)-1]
	switch {
	case first == '<' && last == '>':
		return true
	case first == '[' && last == ']':
		return true
	case first == '{' && last == '}':
		return true
	case first == '%' && last == '%' && len(v) > 2:
		return true
	case strings.HasPrefix(v, "__") && strings.HasSuffix(v, "__") && len(v) > 4:
		return true
	case strings.HasPrefix(v, "@@") && strings.HasSuffix(v, "@@") && len(v) > 4:
		return true
	case strings.HasPrefix(v, "[REDACTED:") || strings.HasPrefix(v, "[TRUNCATED:"):
		return true
	}
	return false
}

// referencePrefixes start values that point at a secret held elsewhere.
var referencePrefixes = []string{
	"op://", "vault:", "arn:", "ssm:", "sm://", "ref+", "secretref:", "file:",
	"env:", "enc[", "!vault", "!secret", "sops:", "gcp:secretmanager",
	"azurekeyvault", "keyvault:", "projects/", "aws:secretsmanager", "{{",
	"#{", "process.env", "os.environ", "os.getenv", "system.getenv", "getenv",
	"env.", "env[", "env(", "secrets.", "vars.", "config.", "settings.",
	"self.", "this.", "args.", "opts.", "options.", "params.", "props.",
	"req.", "request.", "ctx.", "input(", "getpass", "prompt(", "cfg.",
}

// isReference reports whether v refers to a secret (a variable, a secret
// manager path, a file, an expression) instead of being one. References are
// kept: the variable NAME in "Bearer $GITHUB_TOKEN" is exactly the signal a
// responder wants and it is not sensitive.
func isReference(v string) bool {
	if v == "" {
		return true
	}
	switch v[0] {
	case '$':
		if varReference(v) {
			return true
		}
	case '@':
		// curl-style @file.
		if len(v) > 1 && (v[1] == '/' || v[1] == '.' || v[1] == '~') {
			return true
		}
	case '%':
		// %VAR% (cmd) and printf verbs such as %s.
		if len(v) <= 3 || v[len(v)-1] == '%' {
			return true
		}
	case '~':
		if len(v) == 1 || v[1] == '/' || v[1] == '\\' {
			return true
		}
	case '.':
		if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") || strings.HasPrefix(v, `.\`) {
			return true
		}
	case '/':
		// An absolute path: at least two components.
		if strings.IndexByte(v[1:], '/') >= 0 {
			return true
		}
	}
	if len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') && isAlnum(v[0]) {
		return true // C:\path
	}
	lv := asciiLower(v)
	for _, p := range referencePrefixes {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}
	if i := strings.Index(v, "://"); i > 0 && i < 32 && !strings.Contains(v, "@") {
		return true // a plain URL; URLs with userinfo have their own detector
	}
	if callExpression(v) || memberAccess(v) {
		return true
	}
	return dottedIdentifier(v)
}

// varReference reports shell, PowerShell and template variable syntax:
// $NAME, ${NAME}, $(cmd), $env:NAME. Crypt-style password hashes also start
// with "$" ($2b$12$..., $argon2id$...) and must NOT be taken for variables:
// they are the secret.
func varReference(v string) bool {
	if len(v) < 2 || v[0] != '$' {
		return false
	}
	if v[1] == '{' || v[1] == '(' {
		return true
	}
	i := 1
	for i < len(v) && (isAlnum(v[i]) || v[i] == '_') {
		i++
	}
	if i == 1 || isDigit(v[1]) {
		return false
	}
	return i == len(v) || v[i] != '$'
}

// callExpression reports f(...) and a.b(...) forms.
func callExpression(v string) bool {
	if len(v) < 3 || v[len(v)-1] != ')' {
		return false
	}
	open := strings.IndexByte(v, '(')
	if open <= 0 {
		return false
	}
	for i := 0; i < open; i++ {
		if c := v[i]; !isAlnum(c) && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// memberAccess reports Foo::bar and $this->bar forms.
func memberAccess(v string) bool {
	if !strings.Contains(v, "::") && !strings.Contains(v, "->") {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !isAlnum(c) && strings.IndexByte("_:>-$.", c) < 0 {
			return false
		}
	}
	return true
}

// dottedIdentifier reports a.b.c style member access with no digits, which is
// code, not a token (tokens of that length almost always contain digits).
func dottedIdentifier(v string) bool {
	if len(v) > 64 || !strings.Contains(v, ".") {
		return false
	}
	prevDot := true
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if prevDot {
				return false
			}
			prevDot = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			prevDot = false
		default:
			return false
		}
	}
	return !prevDot
}
