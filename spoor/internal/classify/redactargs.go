package classify

import (
	"regexp"
	"strings"
	"sync"
)

// flagMode says how the value belonging to a flag is redacted.
type flagMode uint8

const (
	modeNone     flagMode = iota
	modeSecret            // the whole next argument is the secret
	modeAttached          // the secret is glued to the flag: -pSECRET
	modeUserPass          // user:password, keep the user
	modePassArg           // openssl "pass:SECRET" (env:, file: and fd: are references)
	modeHeader            // "Name: value" HTTP header
	modeData              // request body: form pairs or JSON
)

// toolFlags are short flags whose meaning depends on the program. They are
// applied only when that program appears earlier in the argument list, since
// "-p" is a port for docker, a prompt for claude and a password for mysql.
var toolFlags = map[string]map[string]flagMode{
	"curl":         {"-u": modeUserPass, "--user": modeUserPass, "-U": modeUserPass, "--proxy-user": modeUserPass},
	"http":         {"-a": modeUserPass},
	"https":        {"-a": modeUserPass},
	"mysql":        {"-p": modeAttached},
	"mysqldump":    {"-p": modeAttached},
	"mysqladmin":   {"-p": modeAttached},
	"mysqlsh":      {"-p": modeAttached},
	"mariadb":      {"-p": modeAttached},
	"mariadb-dump": {"-p": modeAttached},
	"mycli":        {"-p": modeAttached},
	"7z":           {"-p": modeAttached},
	"7za":          {"-p": modeAttached},
	"7zz":          {"-p": modeAttached},
	"sshpass":      {"-p": modeSecret},
	"redis-cli":    {"-a": modeSecret},
	"valkey-cli":   {"-a": modeSecret},
	"mongosh":      {"-p": modeSecret},
	"mongo":        {"-p": modeSecret},
	"mongodump":    {"-p": modeSecret},
	"mongorestore": {"-p": modeSecret},
	"ldapsearch":   {"-w": modeSecret},
	"ldapmodify":   {"-w": modeSecret},
	"ldapadd":      {"-w": modeSecret},
	"ldapwhoami":   {"-w": modeSecret},
	"zip":          {"-P": modeSecret},
	"unzip":        {"-P": modeSecret},
	"openssl":      {"-k": modeSecret, "-K": modeSecret, "-pass": modePassArg, "-passin": modePassArg, "-passout": modePassArg},
	// Registry and cluster logins take the password after -p.
	"login": {"-p": modeSecret},
}

// headerFlags and dataFlags are safe to honour for any program: the value is
// only redacted where a secret-named header or field is found in it.
var headerFlags = map[string]bool{"-H": true, "--header": true, "--proxy-header": true}

var dataFlags = map[string]bool{
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true,
	"--data-urlencode": true, "--data-ascii": true, "--json": true, "-F": true,
	"--form": true, "--form-string": true, "--post-data": true, "--body-data": true,
}

// extraSecretFlags are flag names that are secrets by convention but carry no
// secret word.
var extraSecretFlags = map[string]bool{"pat": true, "otp": true, "passin": true, "passout": true}

var (
	jsonPairOnce sync.Once
	jsonPairRe   *regexp.Regexp
	envNameRe    *regexp.Regexp
)

func argRegexes() (*regexp.Regexp, *regexp.Regexp) {
	jsonPairOnce.Do(func() {
		jsonPairRe = regexp.MustCompile(`"((?:[^"\\]|\\.){1,128})"\s*:\s*"((?:[^"\\]|\\.)*)"`)
		envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$`)
	})
	return jsonPairRe, envNameRe
}

// RedactArgs returns a copy of an argument vector with credentials replaced
// by "[REDACTED:<kind>:<fingerprint>]". It is structural where it can be:
//
//   - the value after a secret-named flag (--token, --password, --api-key,
//     --secret, --auth, --bearer, --client-secret, -Password ...), in both
//     "--flag value" and "--flag=value" forms, and Windows "/flag:value";
//   - HTTP headers given with -H/--header (Authorization keeps its scheme,
//     Cookie and secret-named headers lose their value);
//   - request bodies given with -d/--data/-F: secret-named form fields and
//     JSON members;
//   - NAME=value arguments with a secret-like NAME;
//   - URL userinfo and secret-named query parameters;
//   - tool-specific short flags (curl -u, mysql -pSECRET, sshpass -p ...).
//
// In those positions the value is redacted whatever it looks like: a
// one-character password is still the password. Variable references ($TOKEN,
// %TOKEN%, @file) are kept. Every argument finally passes through Redact,
// which catches credentials embedded anywhere else.
//
// The result has the same length as args; args is not modified.
func RedactArgs(args []string) (out []string) {
	defer func() {
		if recover() != nil {
			out = make([]string, len(args))
			for i := range out {
				out[i] = failClosed
			}
		}
	}()
	if args == nil {
		return nil
	}
	out = make([]string, len(args))
	seen := map[string]bool{} // program and subcommand words seen so far
	pending := modeNone
	endOfFlags := false
	prevPositional, prevPrevPositional := "", ""
	for i, a := range args {
		if pending != modeNone {
			// "--password --verbose": the flag had no value after all. A
			// credential that itself starts with "--" is not a realistic case.
			if !(pending == modeSecret && len(a) > 2 && a[0] == '-' && a[1] == '-') {
				out[i] = redactByMode(pending, a)
				pending = modeNone
				continue
			}
			pending = modeNone
		}
		if !endOfFlags && a == "--" {
			out[i] = a
			if nestedCommand(seen) {
				// kubectl exec pod -- mysql -pSECRET: what follows is a new
				// command line with its own flags. Restart the scan.
				seen = map[string]bool{}
				prevPositional, prevPrevPositional = "", ""
				continue
			}
			endOfFlags = true
			continue
		}
		if !endOfFlags && len(a) > 1 && a[0] == '-' {
			out[i], pending = redactFlag(a, seen, i+1 < len(args))
			continue
		}
		if r, ok := redactWindowsFlag(a); ok {
			out[i] = r
			continue
		}
		// "config set <name> <value>" style: the value follows a secret name.
		if prevPositional != "" && pairContext(prevPrevPositional, seen) &&
			secretName(pairName(prevPositional)) != nameNone && !keepAsWritten(a) {
			out[i] = markerFor(kindForName(pairName(prevPositional)), a)
		} else {
			out[i] = redactLoose(a)
		}
		word := programWord(a)
		if word != "" {
			seen[word] = true
		}
		prevPrevPositional, prevPositional = prevPositional, a
	}
	return out
}

// programWord returns the lower-cased base name of an argument that could be
// a program or subcommand, or "".
func programWord(a string) string {
	if len(a) > 256 || strings.Contains(a, "://") {
		return ""
	}
	base := a
	if i := strings.LastIndexAny(a, `/\`); i >= 0 {
		base = a[i+1:]
	}
	if base == "" || len(base) > 64 {
		return ""
	}
	for i := 0; i < len(base); i++ {
		if c := base[i]; !isAlnum(c) && c != '_' && c != '-' && c != '.' && c != '+' {
			return ""
		}
	}
	word := strings.TrimSuffix(asciiLower(base), ".exe")
	if word == "login" && base != a {
		return "" // a subcommand is a bare word, never a path component
	}
	return word
}

// pairContext reports whether the argument before a secret NAME makes the
// next argument its VALUE: "aws configure set NAME VALUE",
// "npm config set NAME VALUE", "git config NAME VALUE".
func pairContext(before string, seen map[string]bool) bool {
	switch asciiLower(before) {
	case "set", "add", "put":
		return true
	case "config":
		return seen["git"]
	}
	return false
}

// pairName strips the scope prefix of a configuration key
// ("//registry.npmjs.org/:_authToken" -> "_authToken").
func pairName(a string) string {
	if i := strings.LastIndexAny(a, ":/"); i >= 0 {
		a = a[i+1:]
	}
	return a
}

func kindForName(name string) string {
	if secretName(name) == namePassword {
		return KindPassword
	}
	return KindGenericSecret
}

// redactFlag handles one argument that starts with "-". It returns the
// redacted argument and the mode to apply to the NEXT argument.
func redactFlag(a string, seen map[string]bool, hasNext bool) (string, flagMode) {
	flag, value, hasValue := a, "", false
	if eq := strings.IndexByte(a, '='); eq > 0 {
		flag, value, hasValue = a[:eq], a[eq+1:], true
	}
	mode := flagModeFor(flag, seen)
	if mode == modeAttached {
		return a, modeNone // only reachable for a bare "-p": nothing attached
	}
	if hasValue {
		if mode == modeNone && defineFlag(flag) {
			mode = modeSecret
		}
		if mode == modeNone {
			return flag + "=" + redactLoose(value), modeNone
		}
		return flag + "=" + redactByMode(mode, value), modeNone
	}
	if mode != modeNone {
		if !hasNext {
			return a, modeNone
		}
		return a, mode
	}
	// Glued short forms: -pSECRET, -HName: value, -uuser:pass.
	if len(a) > 2 && a[1] != '-' {
		short := a[:2]
		switch m := flagModeFor(short, seen); {
		case m == modeAttached:
			return short + redactByMode(modeAttached, a[2:]), modeNone
		case m == modeUserPass || m == modeHeader || m == modeData:
			return short + redactByMode(m, a[2:]), modeNone
		}
	}
	return redactLoose(a), modeNone
}

// nestedCommand reports programs whose "--" introduces another program's
// command line rather than plain operands.
func nestedCommand(seen map[string]bool) bool {
	for _, p := range []string{"kubectl", "oc", "docker", "podman", "nerdctl", "ssh", "gcloud", "az", "aws",
		"npx", "pnpm", "yarn", "npm", "bunx", "uvx", "uv", "poetry", "pipx", "cargo", "go", "timeout", "env",
		"sudo", "doas", "nohup", "nice", "xargs", "watch", "kind", "minikube", "vagrant", "flyctl", "fly", "heroku"} {
		if seen[p] {
			return true
		}
	}
	return false
}

// httpClients are the programs whose short -d/-F flags carry a request body.
var httpClients = []string{"curl", "wget", "wget2", "http", "https", "xh", "curlie", "httpie"}

func flagModeFor(flag string, seen map[string]bool) flagMode {
	if headerFlags[flag] {
		return modeHeader
	}
	if dataFlags[flag] {
		// Short -d and -F mean "decrypt", "daemon", "field separator" for
		// most programs (openssl enc -d -k SECRET); only treat them as a
		// request body after an HTTP client.
		if len(flag) == 2 {
			for _, c := range httpClients {
				if seen[c] {
					return modeData
				}
			}
		} else {
			return modeData
		}
	}
	for tool, flags := range toolFlags {
		if m, ok := flags[flag]; ok && seen[tool] {
			return m
		}
	}
	name := strings.TrimLeft(flag, "-")
	if name == "" || len(flag)-len(name) > 2 {
		return modeNone
	}
	// Single-letter flags are never classified by name.
	if len(name) == 1 {
		return modeNone
	}
	if extraSecretFlags[asciiLower(name)] || secretName(name) != nameNone {
		return modeSecret
	}
	return modeNone
}

// defineFlag reports "-DNAME" / "-eNAME" style flags (one option letter glued
// to a variable name) whose NAME is secret-like. Only consulted for the
// "-XNAME=value" form.
func defineFlag(flag string) bool {
	if len(flag) < 4 || flag[0] != '-' || flag[1] == '-' {
		return false
	}
	return secretName(flag[2:]) != nameNone
}

func redactByMode(mode flagMode, v string) string {
	switch mode {
	case modeSecret:
		if keepAsWritten(v) {
			return v
		}
		return markerFor(KindGenericSecret, v)
	case modeAttached:
		if keepAsWritten(v) {
			return v
		}
		return markerFor(KindPassword, v)
	case modeUserPass:
		return redactUserPass(v)
	case modePassArg:
		if strings.HasPrefix(v, "pass:") {
			return "pass:" + markerFor(KindPassword, v[5:])
		}
		return v // env:NAME, file:path, fd:N, stdin
	case modeHeader:
		return redactHeader(v)
	case modeData:
		return redactData(v)
	}
	return redactLoose(v)
}

// redactUserPass handles "user:password" (curl -u). A lone value is redacted
// only when it looks like a token ("curl -u <token>:").
func redactUserPass(v string) string {
	if keepAsWritten(v) {
		return v
	}
	i := strings.IndexByte(v, ':')
	if i < 0 || i == len(v)-1 {
		user := strings.TrimSuffix(v, ":")
		if len(user) >= 20 && Entropy(user) >= 3.5 {
			return markerFor(KindGenericSecret, user) + v[len(user):]
		}
		r, _ := Redact(v)
		return r
	}
	if keepAsWritten(v[i+1:]) {
		return v
	}
	return v[:i+1] + markerFor(KindPassword, v[i+1:])
}

// redactHeader handles one "Name: value" header.
func redactHeader(h string) string {
	i := strings.IndexByte(h, ':')
	if i <= 0 || strings.HasPrefix(h, "@") {
		return redactLoose(h)
	}
	name := strings.TrimSpace(h[:i])
	rest := h[i+1:]
	value := strings.TrimLeft(rest, " \t")
	lead := h[:i+1] + rest[:len(rest)-len(value)]
	value = strings.TrimRight(value, " \t")
	if value == "" {
		return h
	}
	switch lname := asciiLower(name); {
	case lname == "authorization" || lname == "proxy-authorization":
		scheme, cred := "", value
		if sp := strings.IndexAny(value, " \t"); sp > 0 && sp <= 24 {
			scheme, cred = value[:sp+1], strings.TrimLeft(value[sp+1:], " \t")
		}
		if keepAsWritten(cred) {
			return h
		}
		kind := KindBearerHeader
		if strings.EqualFold(strings.TrimSpace(scheme), "basic") {
			kind = KindBasicAuthHeader
		}
		return lead + scheme + markerFor(kind, cred)
	case lname == "cookie" || lname == "set-cookie":
		if keepAsWritten(value) {
			return h
		}
		return lead + markerFor(KindCookieHeader, value)
	case secretName(name) != nameNone:
		if keepAsWritten(value) {
			return h
		}
		return lead + markerFor(KindGenericSecret, value)
	}
	return redactLoose(h)
}

// formSecretNames are body field names that carry credentials in addition to
// the names secretName accepts.
var formSecretNames = map[string]bool{
	"code": true, "otp": true, "assertion": true, "client_assertion": true,
	"sig": true, "signature": true, "pin": true,
}

// redactData handles a request body argument: JSON members and form fields
// with secret names lose their values.
func redactData(d string) string {
	if strings.HasPrefix(d, "@") || d == "" {
		return d // @file reads the body from a file
	}
	trimmed := strings.TrimLeft(d, " \t\r\n")
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return redactLoose(redactJSONText(d))
	}
	var b strings.Builder
	rest := d
	for {
		pair := rest
		i := strings.IndexByte(rest, '&')
		if i >= 0 {
			pair = rest[:i]
		}
		if eq := strings.IndexByte(pair, '='); eq > 0 && eq < len(pair)-1 {
			name := percentDecode(pair[:eq])
			if (secretName(name) != nameNone || formSecretNames[asciiLower(name)]) && !keepAsWritten(pair[eq+1:]) {
				pair = pair[:eq+1] + markerFor(kindForName(name), pair[eq+1:])
			}
		}
		b.WriteString(pair)
		if i < 0 {
			break
		}
		b.WriteByte('&')
		rest = rest[i+1:]
	}
	return redactLoose(b.String())
}

// redactJSONText redacts string members with secret names in JSON text
// without re-serializing it, so formatting and member order survive.
func redactJSONText(s string) string {
	re, _ := argRegexes()
	locs := re.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		name, value := s[loc[2]:loc[3]], s[loc[4]:loc[5]]
		if secretName(name) == nameNone || keepAsWritten(value) {
			continue
		}
		b.WriteString(s[last:loc[4]])
		b.WriteString(markerFor(kindForName(name), value))
		last = loc[5]
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactWindowsFlag handles cmd.exe style "/name:value" switches.
func redactWindowsFlag(a string) (string, bool) {
	if len(a) < 4 || a[0] != '/' {
		return "", false
	}
	i := strings.IndexByte(a, ':')
	if i < 2 || i == len(a)-1 || strings.ContainsAny(a[1:i], `/\. `) {
		return "", false
	}
	name := a[1:i]
	if secretName(name) == nameNone || keepAsWritten(a[i+1:]) {
		return "", false
	}
	return a[:i+1] + markerFor(kindForName(name), a[i+1:]), true
}

// redactLoose is the catch-all for an argument with no structural role:
// NAME=value with a secret name, a URL with userinfo, then pattern redaction.
func redactLoose(a string) string { return redactLooseDepth(a, 0) }

func redactLooseDepth(a string, depth int) string {
	if a == "" {
		return a
	}
	if depth > 3 {
		// "a=b=c=d=...": stop unpacking, the pattern pass still runs.
		r, _ := Redact(a)
		return r
	}
	_, envName := argRegexes()
	if eq := strings.IndexByte(a, '='); eq > 0 && eq <= 128 && envName.MatchString(a[:eq]) {
		name, value := a[:eq], a[eq+1:]
		if secretName(name) != nameNone {
			if keepAsWritten(value) {
				return a
			}
			return a[:eq+1] + markerFor(kindForName(name), value)
		}
		// KEY=VALUE where VALUE is itself structured (--from-literal style,
		// DATABASE_URL=postgres://...).
		return a[:eq+1] + redactLooseDepth(value, depth+1)
	}
	if p := splitURL(a); p.scheme != "" && !p.opaque && p.prefix != "" && strings.HasPrefix(a, p.prefix) {
		var b strings.Builder
		b.WriteString(p.prefix)
		if p.hasUser && p.userinfo != "" && !keepAsWritten(p.userinfo) {
			kind := KindBasicAuthURL
			if dbSchemes[p.scheme] {
				kind = KindDatabaseURL
			}
			b.WriteString(markerFor(kind, p.userinfo))
			b.WriteByte('@')
		} else if p.hasUser {
			b.WriteString(p.userinfo)
			b.WriteByte('@')
		}
		b.WriteString(p.hostport)
		b.WriteString(p.path)
		if p.hasQuery {
			b.WriteByte('?')
			b.WriteString(redactQuery(p.query))
		}
		if p.hasFrag {
			b.WriteByte('#')
			if strings.Contains(p.fragment, "=") {
				b.WriteString(redactQuery(p.fragment))
			} else {
				b.WriteString(p.fragment)
			}
		}
		a = b.String()
	}
	r, _ := Redact(a)
	return r
}
