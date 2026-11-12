package shellx

import "strings"

// shellCalls lists, per language, the functions whose first string argument
// is handed to a shell. The scanner is deliberately lexical: it finds
// os.system('...') without parsing Python, which is enough to see through the
// common "wrap the shell command in an interpreter one-liner" evasion.
var shellCalls = map[string][]string{
	"python": {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
		"subprocess.check_call", "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
		"pty.spawn", "commands.getoutput", "system", "popen"},
	"javascript": {"execSync", "exec", "spawnSync", "spawn", "execFileSync", "execFile", "doShellScript", "Deno.Command"},
	"perl":       {"system", "exec", "qx", "open"},
	"ruby":       {"system", "exec", "%x", "IO.popen", "Open3.capture2", "Open3.capture3", "Open3.popen3", "spawn"},
	"php":        {"system", "exec", "shell_exec", "passthru", "popen", "proc_open"},
	"lua":        {"os.execute", "io.popen"},
	"awk":        {"system"},
	"applescript": {"do shell script"},
	"vbscript":   {".run", ".exec", "shell"},
}

// backtickLangs treat `...` as command execution.
var backtickLangs = map[string]bool{"perl": true, "ruby": true, "php": true}

// foreign scans non-shell inline code for the facts that survive a lexical
// look: URLs, shell commands passed to exec-style calls, encoded payloads
// that are decoded and executed, and whole-environment dumps.
func (a *analyzer) foreign(lang, code, origin string, depth int) {
	if depth > MaxDepth {
		a.f.Truncated = true
		return
	}
	if len(code) > maxAnalyzeText {
		code = clip(code, maxAnalyzeText)
	}
	a.scanURLs(code)
	a.scanDevTCP(code)
	lower := strings.ToLower(code)

	if lang == "sql" {
		a.sqlFacts(lower)
		return
	}
	found := 0
	var seen []string
	for _, fn := range shellCalls[lang] {
		rest := code
		lfn := fn
		ci := lang == "vbscript" || lang == "applescript"
		for found < maxEmbedded && a.tick() {
			var i int
			if ci {
				i = indexFold(rest, strings.ToLower(lfn))
			} else {
				i = strings.Index(rest, lfn)
			}
			if i < 0 {
				break
			}
			after := rest[i+len(lfn):]
			// The match must be a whole identifier, not the tail of one.
			if i > 0 && isIdentByte(rest[i-1]) && isIdentByte(lfn[0]) {
				rest = after
				continue
			}
			if s, ok := firstStringArg(after); ok && strings.TrimSpace(s) != "" {
				// "os.system" and "system" both match the same call.
				dup := false
				for _, p := range seen {
					if p == s {
						dup = true
						break
					}
				}
				if !dup {
					seen = append(seen, s)
					found++
					a.sub(s, detectDialect(s), origin, depth+1, noFlow())
				}
			}
			rest = after
		}
	}
	if backtickLangs[lang] {
		rest := code
		for found < maxEmbedded {
			i := strings.IndexByte(rest, '`')
			if i < 0 {
				break
			}
			j := strings.IndexByte(rest[i+1:], '`')
			if j < 0 {
				break
			}
			if s := rest[i+1 : i+1+j]; strings.TrimSpace(s) != "" {
				found++
				a.sub(s, Posix, origin, depth+1, noFlow())
			}
			rest = rest[i+j+2:]
		}
	}

	// Decode-and-execute of an embedded literal.
	if lit, ok := encodedExec(lang, code, lower); ok {
		if raw, ok := decodeBase64(lit); ok {
			text := string(raw)
			if z, ok := gunzip(raw); ok {
				text = string(z)
			}
			a.obf("base64_decode_exec")
			if a.addDecoded(text) {
				a.foreign(lang, text, OriginDecoded, depth+1)
			}
		}
	}

	// Download helpers.
	for _, m := range downloadMarkers[lang] {
		if strings.Contains(lower, m) {
			a.f.Downloads = true
			if hasExecMarker(lang, lower) {
				a.f.DownloadAndExecute = true
			}
			break
		}
	}

	// Whole-environment dumps.
	switch lang {
	case "python":
		if strings.Contains(code, "os.environ") && !strings.Contains(code, "os.environ[") &&
			!strings.Contains(code, "os.environ.get(") && !strings.Contains(code, "os.environ.setdefault(") {
			a.cred("env_dump")
		}
	case "javascript":
		if strings.Contains(code, "(process.env)") || strings.Contains(code, "process.env,") || strings.Contains(code, "Deno.env.toObject") {
			a.cred("env_dump")
		}
	case "ruby":
		if strings.Contains(code, "ENV.to_h") || strings.Contains(code, "ENV.inspect") || strings.Contains(code, "puts ENV") || strings.Contains(code, "p ENV") {
			a.cred("env_dump")
		}
	case "php":
		if strings.Contains(code, "$_ENV)") || strings.Contains(code, "getenv()") || strings.Contains(lower, "phpinfo(") {
			a.cred("env_dump")
		}
	case "perl":
		if strings.Contains(code, "%ENV") {
			a.cred("env_dump")
		}
	case "applescript":
		if strings.Contains(lower, "with administrator privileges") {
			a.sudo()
		}
		if strings.Contains(lower, "login item") {
			a.persist("login_item")
		}
		if strings.Contains(lower, "application \"mail\"") && strings.Contains(lower, "send") {
			a.exfil("email_send")
		}
		if strings.Contains(lower, "keychain") {
			a.cred("keychain_dump")
		}
	}
	a.readsInCode(lang, code)
}

var downloadMarkers = map[string][]string{
	"python":     {"urlopen(", "urlretrieve(", "requests.get(", "requests.post(", "httpx.get(", "urllib3", "http.client", "aiohttp"},
	"javascript": {"fetch(", "http.get(", "https.get(", "axios", "xmlhttprequest", "require('http", "require(\"http", "got("},
	"perl":       {"lwp::simple", "lwp::useragent", "http::tiny", "io::socket::inet"},
	"ruby":       {"net::http", "open-uri", "uri.open", "httparty", "faraday", "tcpsocket"},
	"php":        {"file_get_contents('http", "file_get_contents(\"http", "curl_init", "fopen('http", "fopen(\"http", "fsockopen"},
	"lua":        {"socket.http", "http.request"},
	"vbscript":   {"msxml2.xmlhttp", "winhttp.winhttprequest", "msxml2.serverxmlhttp", "adodb.stream"},
	"applescript": {"curl "},
}

func hasExecMarker(lang, lower string) bool {
	var ms []string
	switch lang {
	case "python":
		ms = []string{"exec(", "eval(", "os.system", "subprocess", "compile("}
	case "javascript":
		ms = []string{"eval(", "new function(", "child_process", "vm.run", "execsync", ".exec("}
	case "perl":
		ms = []string{"eval ", "eval(", "system(", "exec("}
	case "ruby":
		ms = []string{"eval(", "eval ", "instance_eval", "system(", "exec("}
	case "php":
		ms = []string{"eval(", "assert(", "system(", "shell_exec(", "include(", "include '", "require("}
	case "vbscript":
		ms = []string{"execute", ".run", "eval("}
	default:
		ms = []string{"eval("}
	}
	for _, m := range ms {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// encodedExec finds exec(base64.b64decode('...')), eval(atob('...')),
// eval(base64_decode('...')) and friends and returns the literal.
func encodedExec(lang, code, lower string) (string, bool) {
	var decoders []string
	switch lang {
	case "python":
		decoders = []string{"b64decode(", "decodebytes(", "a2b_base64("}
	case "javascript":
		decoders = []string{"atob(", "buffer.from("}
	case "php":
		decoders = []string{"base64_decode("}
	case "perl":
		decoders = []string{"decode_base64("}
	case "ruby":
		decoders = []string{"base64.decode64(", "base64.strict_decode64(", ".unpack("}
	default:
		return "", false
	}
	if !hasExecMarker(lang, lower) {
		return "", false
	}
	for _, d := range decoders {
		i := strings.Index(lower, d)
		if i < 0 {
			continue
		}
		if s, ok := firstStringArg("(" + code[i+len(d):]); ok && len(s) >= 8 {
			return s, true
		}
	}
	return "", false
}

// readsInCode records sensitive files opened by one-liners such as
// python -c "print(open('/home/u/.aws/credentials').read())".
func (a *analyzer) readsInCode(lang, code string) {
	var fns []string
	switch lang {
	case "python":
		fns = []string{"open(", "Path(", "read_text("}
	case "javascript":
		fns = []string{"readFileSync(", "readFile(", "createReadStream("}
	case "ruby":
		fns = []string{"File.read(", "File.open(", "IO.read("}
	case "php":
		fns = []string{"file_get_contents(", "readfile(", "fopen("}
	case "perl":
		fns = []string{"open("}
	default:
		return
	}
	n := 0
	for _, fn := range fns {
		rest := code
		for n < maxEmbedded {
			i := strings.Index(rest, fn)
			if i < 0 {
				break
			}
			rest = rest[i+len(fn)-1:]
			if s, ok := firstStringArg(rest); ok && s != "" && !strings.Contains(s, "://") && len(s) < 512 {
				// Only paths that classify as sensitive are worth a Reads
				// entry; arbitrary literals in code are too noisy.
				if readClass(s) != "" {
					a.read(s)
					n++
				}
			}
			rest = rest[1:]
		}
	}
}

// firstStringArg extracts the first string literal after an optional "(":
// 'x', "x", `x`, """x""", prefixed literals (f'x', r"x", b'x'), or a list of
// literals ['a', 'b'] which is joined with spaces (argv form).
func firstStringArg(s string) (string, bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	if i < len(s) && s[i] == '(' {
		i++
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	if i >= len(s) {
		return "", false
	}
	if s[i] == '[' {
		// argv list
		var parts []string
		i++
		for i < len(s) && len(parts) < 64 {
			for i < len(s) && (isSpace(s[i]) || s[i] == ',') {
				i++
			}
			if i >= len(s) || s[i] == ']' {
				break
			}
			lit, n, ok := readStringLit(s[i:])
			if !ok {
				break
			}
			parts = append(parts, lit)
			i += n
		}
		if len(parts) == 0 {
			return "", false
		}
		// "sh -c <script>" in argv form: the script is the command.
		if len(parts) >= 3 && (parts[1] == "-c" || parts[1] == "/c") {
			return parts[2], true
		}
		return strings.Join(parts, " "), true
	}
	lit, _, ok := readStringLit(s[i:])
	return lit, ok
}

// readStringLit reads one string literal at the start of s and returns its
// value and the number of bytes consumed.
func readStringLit(s string) (string, int, bool) {
	i := 0
	// Python literal prefixes.
	for i < len(s) && i < 2 && strings.IndexByte("fFrRbBuU", s[i]) >= 0 {
		i++
	}
	if i >= len(s) {
		return "", 0, false
	}
	q := s[i]
	if q != '\'' && q != '"' && q != '`' {
		return "", 0, false
	}
	if strings.HasPrefix(s[i:], `"""`) || strings.HasPrefix(s[i:], `'''`) {
		delim := s[i : i+3]
		end := strings.Index(s[i+3:], delim)
		if end < 0 {
			return "", 0, false
		}
		return s[i+3 : i+3+end], i + 6 + end, true
	}
	var sb strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		if c == '\\' && j+1 < len(s) {
			n := s[j+1]
			switch n {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case '\\', '\'', '"', '`':
				sb.WriteByte(n)
			default:
				sb.WriteByte('\\')
				sb.WriteByte(n)
			}
			j++
			continue
		}
		if c == q {
			return sb.String(), j + 1, true
		}
		if sb.Len() > maxStatic {
			return "", 0, false
		}
		sb.WriteByte(c)
	}
	return "", 0, false
}

// sqlFacts classifies SQL (and redis/mongo shell) text. lower must be
// lower-case.
func (a *analyzer) sqlFacts(lower string) {
	if strings.Contains(lower, "drop database") || strings.Contains(lower, "drop table") || strings.Contains(lower, "drop schema") ||
		strings.Contains(lower, "dropdatabase(") || strings.Contains(lower, ".drop(") || strings.Contains(lower, "drop owned") ||
		strings.Contains(lower, "drop keyspace") || strings.Contains(lower, "drop collection") {
		a.destructive("db_drop")
	}
	if strings.Contains(lower, "truncate ") || strings.Contains(lower, "flushall") || strings.Contains(lower, "flushdb") ||
		strings.Contains(lower, "deletemany({})") || strings.Contains(lower, ".remove({})") {
		a.destructive("db_truncate")
	}
	// DELETE FROM t without a WHERE clause empties the table.
	rest := lower
	for n := 0; n < 8; n++ {
		i := strings.Index(rest, "delete from")
		if i < 0 {
			break
		}
		stmt := rest[i:]
		if j := strings.IndexByte(stmt, ';'); j >= 0 {
			stmt = stmt[:j]
		}
		if !strings.Contains(stmt, "where") {
			a.destructive("db_truncate")
		}
		rest = rest[i+len("delete from"):]
	}
}
