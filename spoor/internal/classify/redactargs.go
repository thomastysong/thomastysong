package classify

import (
	"regexp"
	"strings"
	"sync"
)

// headerFlags and dataFlags are safe to honour for any program: the value is
// only redacted where a secret-named header or field is found in it.
var headerFlags = lazySet{list: []string{"-H", "--header", "--proxy-header"}}

var dataFlags = lazySet{list: []string{
	"-d", "--data", "--data-raw", "--data-binary",
	"--data-urlencode", "--data-ascii", "--json", "-F",
	"--form", "--form-string", "--post-data", "--body-data",
}}

// extraSecretFlags are flag names that are secrets by convention but carry no
// secret word.
var extraSecretFlags = lazySet{list: []string{"pat", "otp", "passin", "passout"}}

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
//   - flags whose name ends in a password word (--db-pass, -storepass,
//     -keypass, --admin-password, -passphrase, /password), also written
//     "-storepass:value";
//   - HTTP headers given with -H/--header (Authorization keeps its scheme,
//     Cookie and secret-named headers lose their value);
//   - request bodies given with -d/--data/-F: secret-named form fields and
//     JSON members;
//   - NAME=value arguments with a secret-like NAME;
//   - URL userinfo and secret-named query parameters;
//   - program-specific flags, once the program has appeared in the vector:
//     curl -u user:pw, mysql -pPW, sshpass -p PW and -pPW, sqlcmd/bcp/osql
//     -P, ssh-keygen -N/-P, psexec/paexec -p, schtasks /rp and /p, keytool
//     -new, rar -pPW and -hpPW, redis-cli -a, ldapsearch -w, zip -P,
//     openssl -k and -pass pass:PW, docker login -p, smbclient (and the
//     other Samba tools) -U user%pw, lftp -u user,pw;
//   - positional credentials: sqlplus user/password@db as the command,
//     vault login TOKEN.
//
// In those positions the value is redacted whatever it looks like: a
// one-character password is still the password. Variable references ($TOKEN,
// %TOKEN%, @file), password sources (stdin, env:VAR, file:path) and prompt
// requests ("*", "-") are kept. Every argument finally passes through
// Redact, which catches credentials embedded anywhere else and leaves
// existing redaction markers as they are.
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
	st := argScan{args: args, out: make([]string, len(args)), progs: map[string]int{}}
	st.run()
	return st.out
}

// argScan is the state of one RedactArgs pass.
type argScan struct {
	args, out []string
	// progs maps the program and subcommand words seen so far to 1 + the
	// index of their latest occurrence.
	progs map[string]int
	// tools are the programs with a grammar entry seen so far, latest last,
	// one entry per program (so the list stays as short as the table).
	tools []seenTool
	// start is the index of the current command line's program: 0, or the
	// argument after a "--" that begins a nested command.
	start int
	// lastOperand is 1 + the index of the latest operand: an argument that
	// is neither a flag nor a flag's value.
	lastOperand int
	// pending is the mode the next argument is read in; pendingSlash says
	// the flag that set it was a Windows "/switch".
	pending      flagMode
	pendingSlash bool
	endOfFlags   bool
	// prev and prevPrev are the two latest operands.
	prev, prevPrev string
	// vaultLogin: "vault login" was seen and its token operand not yet.
	vaultLogin bool
}

type seenTool struct {
	name string
	spec *toolSpec
	at   int // 1 + index
}

func (st *argScan) run() {
	for i, a := range st.args {
		hasNext := i+1 < len(st.args)
		if st.pending != modeNone {
			mode, slash := st.pending, st.pendingSlash
			st.pending, st.pendingSlash = modeNone, false
			if takesValue(mode, slash, a) {
				st.out[i] = redactByMode(mode, a)
				continue
			}
		}
		if !st.endOfFlags && a == "--" {
			st.out[i] = a
			if st.nestedCommand() {
				// kubectl exec pod -- mysql -pSECRET: what follows is a new
				// command line with its own flags. Restart the scan.
				st.restart(i + 1)
				continue
			}
			st.endOfFlags = true
			continue
		}
		if !st.endOfFlags && len(a) > 1 && a[0] == '-' {
			st.out[i], st.pending = st.redactFlag(a, hasNext)
			continue
		}
		if !st.endOfFlags && len(a) > 1 && a[0] == '/' {
			if mode, ok := st.windowsSwitch(a); ok {
				st.out[i] = a
				if hasNext {
					st.pending, st.pendingSlash = mode, true
				}
				continue
			}
		}
		if r, ok := redactWindowsFlag(a); ok {
			st.out[i] = r
			continue
		}
		st.out[i] = st.operand(i, a)
		st.noteOperand(i, a)
	}
}

// takesValue reports whether a pending flag's value is a, or a is really the
// next flag ("--password --verbose": the flag had no value after all).
func takesValue(mode flagMode, slash bool, a string) bool {
	if slash && strings.HasPrefix(a, "/") {
		// "/rp" with no value prompts (schtasks), so "/rp /sc daily" moves
		// on to the next switch; a Windows password starting with "/" is
		// not a realistic case.
		return false
	}
	switch mode {
	case modeSecret:
		// A credential that itself starts with "--" is not a realistic case.
		return !(len(a) > 2 && a[0] == '-' && a[1] == '-')
	case modePassword:
		// Password-named flags often prompt when given no value, and some
		// are commands ("keytool -storepasswd -new PW"), so a following
		// flag is the next flag. Only flag-shaped words count: "-Xy7!" is
		// a password.
		return !flagShaped(a)
	}
	return true
}

// flagShaped reports "-name" / "--name" words made of letters, digits and
// dashes: an option, not a value.
func flagShaped(a string) bool {
	name := strings.TrimLeft(a, "-")
	if dashes := len(a) - len(name); dashes == 0 || dashes > 2 || name == "" || len(name) > 48 || !(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z') {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isAlnum(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// noteOperand records an operand: the program and subcommand words that
// select a grammar, and the "vault login" sequence.
func (st *argScan) noteOperand(i int, a string) {
	word := programWord(a)
	if word != "" {
		if word == "login" && programWord(st.prev) == "vault" {
			st.vaultLogin = true
		}
		st.progs[word] = i + 1
		if spec := toolSpecs()[word]; spec != nil {
			for k := range st.tools {
				if st.tools[k].name == word {
					st.tools = append(st.tools[:k], st.tools[k+1:]...)
					break
				}
			}
			st.tools = append(st.tools, seenTool{name: word, spec: spec, at: i + 1})
		}
	}
	st.lastOperand = i + 1
	st.prevPrev, st.prev = st.prev, a
}

func (st *argScan) restart(start int) {
	clear(st.progs)
	st.tools = st.tools[:0]
	st.start, st.lastOperand = start, 0
	st.prev, st.prevPrev = "", ""
	st.vaultLogin = false
}

// toolMode returns the mode the grammar of a program seen earlier gives
// flag. When two programs give the same flag a meaning, the nearer one
// wins: in "sshpass -p PW mysql -pX" the second -p is mysql's.
func (st *argScan) toolMode(flag string) flagMode {
	for k := len(st.tools) - 1; k >= 0; k-- {
		t := st.tools[k]
		if t.spec.optsFirst && st.lastOperand > t.at {
			continue // its options ended at its first operand
		}
		if m := t.spec.mode(flag); m != modeNone {
			return m
		}
	}
	return modeNone
}

// operand redacts an argument that is neither a flag nor a flag's value.
func (st *argScan) operand(i int, a string) string {
	// sqlplus user/password@db: only as the command itself, since
	// "grep -r sqlplus src/main" has the same shape.
	if i > st.start && programWord(st.args[st.start]) == "sqlplus" {
		if r, ok := redactSQLPlusLogon(a); ok {
			return r
		}
	}
	if st.vaultLogin {
		if r, ok := st.vaultToken(i, a); ok {
			return r
		}
	}
	// "config set <name> <value>" style: the value follows a secret name.
	if st.prev != "" && pairContext(st.prevPrev, st.progs) &&
		secretName(pairName(st.prev)) != nameNone && !keepAsWritten(a) {
		return markerFor(kindForName(pairName(st.prev)), a)
	}
	return redactLoose(a)
}

// vaultToken handles the operands after "vault login": the first one that
// is not an auth parameter (K=V), an address, or the value of a flag
// written without "=" is the token ("vault login -no-print TOKEN"); "-"
// reads it from stdin.
func (st *argScan) vaultToken(i int, a string) (string, bool) {
	if i > 0 {
		if p := st.args[i-1]; len(p) > 1 && p[0] == '-' && !strings.Contains(p, "=") && !vaultBoolFlags.has(p) {
			return "", false // "-method userpass": the flag's value
		}
	}
	if strings.Contains(a, "=") || strings.Contains(a, "://") {
		return "", false
	}
	st.vaultLogin = false
	if keepPasswordValue(a) {
		return a, true
	}
	return markerFor(KindVaultToken, a), true
}

// windowsSwitch recognises a "/switch" whose next argument is a password:
// a program's own (schtasks /rp) or one named like a password (/password).
func (st *argScan) windowsSwitch(a string) (flagMode, bool) {
	if m := st.toolMode(a); m != modeNone {
		return m, true
	}
	if passwordFlag(a[1:]) {
		return modePassword, true
	}
	return modeNone, false
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
func pairContext(before string, progs map[string]int) bool {
	switch asciiLower(before) {
	case "set", "add", "put":
		return true
	case "config":
		return progs["git"] > 0
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
func (st *argScan) redactFlag(a string, hasNext bool) (string, flagMode) {
	flag, value, hasValue := a, "", false
	if eq := strings.IndexByte(a, '='); eq > 0 {
		flag, value, hasValue = a[:eq], a[eq+1:], true
	}
	// The program's grammar comes first: for mysql "-pmypass" is -p with
	// "mypass" glued on, not a flag named like a password.
	if mode := st.toolMode(flag); mode != modeNone {
		return toolFlag(a, flag, value, hasValue, mode, hasNext)
	}
	if r, ok := st.gluedToolFlag(a); ok {
		return r, modeNone
	}
	if !hasValue {
		if r, ok := colonPasswordFlag(a); ok {
			return r, modeNone
		}
	}
	mode := st.genericMode(flag)
	if hasValue {
		if mode == modeNone && defineFlag(flag) {
			mode = modeSecret
		}
		if mode == modeNone {
			return flag + "=" + redactLoose(value), modeNone
		}
		if mode == modePassword && passSource(value+":") {
			return a, modeNone // "--password=env" names where the password is
		}
		return flag + "=" + redactByMode(mode, value), modeNone
	}
	if mode != modeNone {
		if !hasNext {
			return a, modeNone
		}
		return a, mode
	}
	// Glued forms whatever the program: -HName: value, -dfield=value.
	if len(a) > 2 && a[1] != '-' {
		short := a[:2]
		if m := st.genericMode(short); m == modeHeader || m == modeData {
			return short + redactByMode(m, a[2:]), modeNone
		}
	}
	return redactLoose(a), modeNone
}

// toolFlag applies a program's flag rule to a flag written alone or as
// "flag=value".
func toolFlag(a, flag, value string, hasValue bool, mode flagMode, hasNext bool) (string, flagMode) {
	if hasValue {
		return flag + "=" + redactByMode(mode, value), modeNone
	}
	switch mode {
	case modeAttached:
		return a, modeNone // the flag alone prompts: nothing attached
	case modeAttachedOrNext:
		mode = modeNextPass
	}
	if !hasNext {
		return a, modeNone
	}
	return a, mode
}

// gluedToolFlag handles a program's short flag with its value glued on:
// -pPASSWORD (mysql, sshpass, psexec), -hpPASSWORD (rar), -PPASSWORD
// (sqlcmd), -Ubob%pw (Samba), -ubob:pw (curl). The longest flag is tried
// first, so rar's -hp is not read as -h.
func (st *argScan) gluedToolFlag(a string) (string, bool) {
	if len(a) < 3 || a[0] != '-' || a[1] == '-' {
		return "", false
	}
	for n := 3; n >= 2; n-- {
		if len(a) <= n {
			continue
		}
		flag := a[:n]
		if !gluable(flag) {
			continue
		}
		switch m := st.toolMode(flag); m {
		case modeNone, modeHeader, modeData, modePassArg:
		default:
			return flag + redactByMode(m, a[n:]), true
		}
	}
	return "", false
}

// colonPasswordFlag handles "-storepass:VALUE" (keytool and other Java
// tools): a password-named flag with its value after a colon. A value that
// names where the password is ("-storepass:env VAR") leaves the argument,
// and the next one, alone.
func colonPasswordFlag(a string) (string, bool) {
	c := strings.IndexByte(a, ':')
	if c <= 0 {
		return "", false
	}
	name := strings.TrimLeft(a[:c], "-")
	if c-len(name) > 2 || !passwordFlag(name) {
		return "", false
	}
	v := a[c+1:]
	if passSource(v) || passSource(v+":") {
		return a, true
	}
	return a[:c+1] + redactByMode(modePassword, v), true
}

// nestedCommand reports programs whose "--" introduces another program's
// command line rather than plain operands.
func (st *argScan) nestedCommand() bool {
	for _, p := range []string{"kubectl", "oc", "docker", "podman", "nerdctl", "ssh", "gcloud", "az", "aws",
		"npx", "pnpm", "yarn", "npm", "bunx", "uvx", "uv", "poetry", "pipx", "cargo", "go", "timeout", "env",
		"sudo", "doas", "nohup", "nice", "xargs", "watch", "kind", "minikube", "vagrant", "flyctl", "fly", "heroku"} {
		if st.progs[p] > 0 {
			return true
		}
	}
	return false
}

// httpClients are the programs whose short -d/-F flags carry a request body.
var httpClients = []string{"curl", "wget", "wget2", "http", "https", "xh", "curlie", "httpie"}

// genericMode is the meaning of a flag that does not depend on a program's
// grammar: HTTP headers and bodies, and flags named like a credential.
func (st *argScan) genericMode(flag string) flagMode {
	if headerFlags.has(flag) {
		return modeHeader
	}
	if dataFlags.has(flag) {
		// Short -d and -F mean "decrypt", "daemon", "field separator" for
		// most programs (openssl enc -d -k SECRET); only treat them as a
		// request body after an HTTP client.
		if len(flag) == 2 {
			for _, c := range httpClients {
				if st.progs[c] > 0 {
					return modeData
				}
			}
		} else {
			return modeData
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
	if passwordFlag(name) {
		return modePassword
	}
	if extraSecretFlags.has(asciiLower(name)) || secretName(name) != nameNone {
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
		if keepAsWritten(v) || passSource(v) {
			return v
		}
		return markerFor(KindGenericSecret, v)
	case modePassword, modeNextPass, modeAttached, modeAttachedOrNext:
		if keepPasswordValue(v) {
			return v
		}
		return markerFor(KindPassword, v)
	case modeUserPass:
		return redactUserPass(v)
	case modeUserPct:
		return redactUserSep(v, '%')
	case modeUserComma:
		return redactUserSep(v, ',')
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

// redactUserSep handles "user<sep>password" (Samba user%password, lftp
// user,password): the user is kept; a value without the separator is a user
// name alone.
func redactUserSep(v string, sep byte) string {
	if keepPasswordValue(v) {
		return v // %SMBCREDS%, $LFTP_LOGIN
	}
	i := strings.IndexByte(v, sep)
	if i < 0 {
		return redactLoose(v)
	}
	if keepPasswordValue(v[i+1:]) {
		return v
	}
	return v[:i+1] + markerFor(KindPassword, v[i+1:])
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
	if keepPasswordValue(v[i+1:]) {
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
var formSecretNames = lazySet{list: []string{
	"code", "otp", "assertion", "client_assertion",
	"sig", "signature", "pin",
}}

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
			if (secretName(name) != nameNone || formSecretNames.has(asciiLower(name))) && !keepAsWritten(pair[eq+1:]) {
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
	name, v := a[1:i], a[i+1:]
	switch {
	case passwordFlag(name):
		// /password:x, /storepass:x: a password, whatever it looks like.
		if keepPasswordValue(v) {
			return "", false
		}
		return a[:i+1] + markerFor(KindPassword, v), true
	case secretName(name) != nameNone:
		if keepAsWritten(v) {
			return "", false
		}
		return a[:i+1] + markerFor(kindForName(name), v), true
	}
	return "", false
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
			if dbSchemes.has(p.scheme) {
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
