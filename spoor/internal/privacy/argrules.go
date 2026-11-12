package privacy

import (
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
)

// Argument-vector rules this package adds to classify.RedactArgs.
//
// classify's flag tables cover the common database, HTTP and cloud tools;
// the review corpus still found low-entropy passwords shipped through
// flags it does not know (sshpass -pPW, keytool -storepass, sqlcmd -P,
// ssh-keygen -N, lftp -u user,pw, smbclient -U user%pw, schtasks /rp).
// A human password carries no pattern the text pass could find, so these
// are matched by position here. They run after classify and only touch
// arguments it left unchanged, so the two never redact the same value
// twice. Every privacy path that redacts an argument vector (top-level
// segments, nested commands, the syntax-blind view, process args, MCP
// launch lines) goes through redactArgs and so through these rules.

// attachedOrNext lists, per program, the case-sensitive short flags whose
// password is either attached ("-pPW") or the next argument ("-p PW").
var attachedOrNext = map[string][]string{
	"sshpass":    {"-p"},
	"sqlcmd":     {"-P"},
	"bcp":        {"-P"},
	"osql":       {"-P"},
	"ssh-keygen": {"-N", "-P"},
	"psexec":     {"-p"},
	"psexec64":   {"-p"},
	"paexec":     {"-p"},
}

// nextOnly lists, per program, case-insensitive flags whose next argument
// is a password.
var nextOnly = map[string][]string{
	"schtasks": {"/rp", "/p"},
	"keytool":  {"-new"},
}

// attachedOnly lists programs whose "-p<password>" form is the password
// ("-p" alone prompts, "-p-" means none).
var attachedOnly = map[string]string{"rar": "-p", "unrar": "-p", "winrar": "-p"}

// sambaTools take "-U user%password" / "--user=user%password".
var sambaTools = map[string]bool{
	"smbclient": true, "rpcclient": true, "smbcacls": true, "smbget": true, "smbtree": true,
	"smbmap": true, "smbpasswd": true, "net": true, "winexe": true, "samba-tool": true,
}

// moreArgSecrets applies this package's rules to in, writing redactions
// into out (classify's result for the same vector, same length).
func moreArgSecrets(in, out []string) {
	if len(in) == 0 || len(out) != len(in) {
		return
	}
	prog := progName(in[0])
	untouched := func(i int) bool { return i < len(in) && out[i] == in[i] && !keepRef(in[i]) }
	whole := func(i int) {
		if untouched(i) && in[i] != "" && in[i] != "*" && in[i] != "-" {
			out[i] = newMarker(classify.KindPassword, in[i])
		}
	}
	after := func(i, n int) {
		if untouched(i) && n < len(in[i]) && !keepRef(in[i][n:]) {
			out[i] = in[i][:n] + newMarker(classify.KindPassword, in[i][n:])
		}
	}
	for i := 1; i < len(in); i++ {
		a := in[i]
		if !untouched(i) {
			continue
		}
		for _, f := range attachedOrNext[prog] {
			switch {
			case a == f && i+1 < len(in):
				whole(i + 1)
			case strings.HasPrefix(a, f) && len(a) > len(f):
				after(i, len(f))
			}
		}
		for _, f := range nextOnly[prog] {
			if strings.EqualFold(a, f) && i+1 < len(in) {
				whole(i + 1)
			}
		}
		if f, ok := attachedOnly[prog]; ok && strings.HasPrefix(a, f) && len(a) > len(f) && a != f+"-" {
			after(i, len(f))
		}
		switch {
		case prog == "lftp" && a == "-u" && i+1 < len(in):
			// lftp -u user,password
			if j := strings.IndexByte(in[i+1], ','); j >= 0 {
				after(i+1, j+1)
			}
		case sambaTools[prog]:
			// -U user%password, -Uuser%password, --user=user%password
			v, at := "", -1
			switch {
			case (a == "-U" || a == "--user") && i+1 < len(in):
				v, at = in[i+1], i+1
			case strings.HasPrefix(a, "--user="):
				v, at = a, i
			case strings.HasPrefix(a, "-U") && len(a) > 2:
				v, at = a, i
			}
			if j := strings.IndexByte(v, '%'); at >= 0 && j >= 0 {
				after(at, j+1)
			}
		case (prog == "sqlplus" || prog == "sql") && !strings.HasPrefix(a, "-") && userPass(a) > 0:
			// sqlplus user/password@db
			j := userPass(a)
			end := strings.IndexByte(a[j:], '@')
			if end < 0 {
				after(i, j)
			} else if end > 0 && untouched(i) {
				out[i] = a[:j] + newMarker(classify.KindPassword, a[j:j+end]) + a[j+end:]
			}
		case prog == "vault" && i == 2 && strings.EqualFold(in[1], "login") && !strings.HasPrefix(a, "-") && !strings.Contains(a, "="):
			// vault login TOKEN (a positional token; "-" reads stdin).
			whole(i)
		}
		if sep, val, ok := passFlag(a); ok {
			switch {
			case sep && val != "":
				after(i, len(a)-len(val))
			case !sep && i+1 < len(in) && !(strings.HasPrefix(in[i+1], "-") && len(in[i+1]) > 1) && !passSource(in[i+1]):
				whole(i + 1)
			}
		}
	}
}

// passSource reports a value that says where a password is read from
// rather than being one (openssl -pass stdin, env:VAR, file:path, fd:N).
func passSource(v string) bool {
	low := strings.ToLower(v)
	switch low {
	case "stdin", "prompt", "-":
		return true
	}
	for _, p := range []string{"env:", "file:", "fd:"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// userPass returns the offset of the password in "user/password[@db]", or
// 0 when a is not of that form (a path, "/" for OS authentication).
func userPass(a string) int {
	j := strings.IndexByte(a, '/')
	if j <= 0 || j == len(a)-1 || strings.ContainsAny(a[:j], `.~\:@`) {
		return 0
	}
	return j + 1
}

// passFlag recognises a flag whose name ends in a password word
// (--db-pass, -storepass, -keypass, --admin-password, -passphrase). It
// returns the value attached with "=" or ":" (sep) when there is one.
// Flags that only name where a password is (":env", ":file", -file, -fd),
// switch prompting on (--ask-pass, --askpass) or off (--no-pass), or merely
// contain the letters (--bypass, --compass) are not password flags.
func passFlag(a string) (sep bool, val string, ok bool) {
	if len(a) < 3 || (a[0] != '-' && a[0] != '/') {
		return false, "", false
	}
	body := strings.TrimLeft(a, "-/")
	name := body
	if i := strings.IndexAny(body, "=:"); i >= 0 {
		name, val, sep = body[:i], body[i+1:], true
	}
	for i := 0; i < len(name); i++ {
		// A flag name, not a path ("/etc/nginx/.htpasswd" is an argument).
		if c := name[i]; !(isIdentStart(c) || c >= '0' && c <= '9' || c == '-') {
			return false, "", false
		}
	}
	low := strings.ToLower(name)
	if sep && (passSource(val) || passSource(val+":")) {
		// keytool -storepass:env VAR, --password=stdin: the value names
		// where the password is, not the password.
		return false, "", false
	}
	matched := false
	for _, w := range []string{"pass", "passwd", "password", "passphrase", "passcode"} {
		if strings.HasSuffix(low, w) {
			matched = true
		}
	}
	if !matched {
		return false, "", false
	}
	for _, w := range []string{"bypass", "compass", "surpass", "trespass", "askpass", "ask-pass", "ask_pass"} {
		if strings.HasSuffix(low, w) {
			return false, "", false
		}
	}
	if strings.HasPrefix(low, "no-") || strings.HasPrefix(low, "no_") || strings.HasPrefix(low, "skip") || strings.HasPrefix(low, "ask") {
		return false, "", false
	}
	return sep, val, true
}
