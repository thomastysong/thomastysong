package classify

import (
	"strings"
	"sync"
)

// flagMode says how the value belonging to a flag is redacted.
type flagMode uint8

const (
	modeNone flagMode = iota
	// The value is the next argument, or follows "=" in "--flag=value".
	modeSecret   // a token or key (secret-named flag); references and templates are kept
	modePassword // a password (password-named flag); a following "-x" is the next flag, not a value
	modeNextPass // the program's grammar puts a password here, whatever it looks like
	// The value is glued to a short flag.
	modeAttached       // -pPASSWORD; the flag alone prompts
	modeAttachedOrNext // -pPASSWORD, or the next argument when the flag stands alone
	// The value has structure; only the password part is redacted.
	modeUserPass  // user:password (curl -u)
	modeUserPct   // user%password (Samba -U)
	modeUserComma // user,password (lftp -u)
	modePassArg   // openssl pass:PASSWORD (env:, file:, fd:, stdin are references; anything else is the password)
	modeHeader    // "Name: value" HTTP header
	modeData      // request body: form pairs or JSON
	// The flag takes an ordinary argument (sshpass -P prompt, sudo -u
	// user): the value is no secret by position and, above all, no
	// operand, so it neither ends an optsFirst program's options nor
	// takes the program position.
	modeArg
)

// passwordMode reports modes whose value is a password chosen by a person:
// it is redacted whatever it looks like (see keepPasswordValue).
func passwordMode(m flagMode) bool {
	switch m {
	case modePassword, modeNextPass, modeAttached, modeAttachedOrNext:
		return true
	}
	return false
}

// toolSpec is what one program's grammar says about credentials in its
// arguments. Its flags apply only once the program has been seen in the
// argument vector, since "-p" is a port for docker, a prompt for claude and
// a password for mysql.
type toolSpec struct {
	flags map[string]flagMode
	// fold: flags compare case-insensitively (Windows programs, where
	// "/RP" and "/rp" are the same switch).
	fold bool
	// optsFirst: the program's own options end at its first operand, which
	// starts the command it runs ("sshpass -p PW ssh -p 22 host": the
	// second -p is ssh's port, not a password).
	optsFirst bool
	// wraps: the program runs the command named by its operands ("sudo -u
	// oracle sqlplus ..."), so that command is still in program position;
	// lead is the number of operands it takes first (timeout's duration,
	// chroot's directory).
	wraps bool
	lead  int
}

func (t *toolSpec) mode(flag string) flagMode {
	if m, ok := t.flags[flag]; ok {
		return m
	}
	if t.fold {
		return t.flags[asciiLower(flag)]
	}
	return modeNone
}

var (
	toolOnce  sync.Once
	toolIndex map[string]*toolSpec
)

// toolSpecs returns the program grammar table, built on first use.
func toolSpecs() map[string]*toolSpec {
	toolOnce.Do(func() { toolIndex = buildToolSpecs() })
	return toolIndex
}

// buildToolSpecs lists, per program, the flags that carry a credential.
//
// The password tools (sshpass, sqlcmd, bcp, osql, ssh-keygen, psexec,
// paexec, schtasks, keytool, rar, the Samba tools, lftp) came from the
// privacy tier's review corpus, which found low-entropy passwords shipped
// through flags this table did not know. A human password carries no
// pattern the text pass could find, so they are matched by position here,
// for every caller of RedactArgs.
func buildToolSpecs() map[string]*toolSpec {
	t := make(map[string]*toolSpec, 96)
	def := func(spec *toolSpec, programs ...string) {
		for _, p := range programs {
			t[p] = spec
		}
	}
	def(&toolSpec{flags: map[string]flagMode{"-u": modeUserPass, "--user": modeUserPass, "-U": modeUserPass, "--proxy-user": modeUserPass}}, "curl")
	def(&toolSpec{flags: map[string]flagMode{"-a": modeUserPass}}, "http", "https")
	def(&toolSpec{flags: map[string]flagMode{"-p": modeAttached}},
		"mysql", "mysqldump", "mysqladmin", "mysqlsh", "mariadb", "mariadb-dump", "mycli", "7z", "7za", "7zz")
	// RAR: -p<pwd> encrypts data, -hp<pwd> data and headers. "-p" alone
	// prompts and "-p-" means no password (keepPasswordValue keeps "-").
	def(&toolSpec{flags: map[string]flagMode{"-p": modeAttached, "-hp": modeAttached}}, "rar", "unrar", "winrar")
	// sshpass -P prompt, -d fd and -f file take a value; it must not be read
	// as the command sshpass runs, or -p after it is taken for ssh's port.
	def(&toolSpec{flags: map[string]flagMode{"-p": modeAttachedOrNext, "-P": modeArg, "-d": modeArg, "-f": modeArg}, optsFirst: true}, "sshpass")
	def(&toolSpec{flags: map[string]flagMode{"-P": modeAttachedOrNext}}, "sqlcmd", "bcp", "osql")
	// ssh-keygen: -N new passphrase, -P old passphrase (-p is "change").
	def(&toolSpec{flags: map[string]flagMode{"-N": modeAttachedOrNext, "-P": modeAttachedOrNext}}, "ssh-keygen")
	def(&toolSpec{flags: map[string]flagMode{"-p": modeAttachedOrNext}}, "psexec", "psexec64", "paexec")
	// schtasks: /rp run-as password ("*" prompts), /p remote password.
	def(&toolSpec{flags: map[string]flagMode{"/rp": modeNextPass, "/p": modeNextPass}, fold: true}, "schtasks")
	// keytool -storepasswd/-keypasswd -new NEWPASSWORD. Its -storepass,
	// -keypass, -srcstorepass ... are found by name (passwordFlag).
	def(&toolSpec{flags: map[string]flagMode{"-new": modeNextPass}, fold: true}, "keytool")
	def(&toolSpec{flags: map[string]flagMode{"-a": modeNextPass}}, "redis-cli", "valkey-cli")
	// mongosh -p alone prompts, so a following flag is not its value.
	def(&toolSpec{flags: map[string]flagMode{"-p": modePassword}}, "mongosh", "mongo", "mongodump", "mongorestore")
	def(&toolSpec{flags: map[string]flagMode{"-w": modeNextPass}}, "ldapsearch", "ldapmodify", "ldapadd", "ldapwhoami", "ldapdelete", "ldappasswd")
	def(&toolSpec{flags: map[string]flagMode{"-P": modeNextPass}}, "zip", "unzip")
	def(&toolSpec{flags: map[string]flagMode{"-k": modeNextPass, "-K": modeSecret, "-pass": modePassArg, "-passin": modePassArg, "-passout": modePassArg}}, "openssl")
	// Registry and cluster logins take the password after -p.
	def(&toolSpec{flags: map[string]flagMode{"-p": modeNextPass}}, "login")
	// Samba: -U user%password, -Uuser%password, --user=user%password.
	def(&toolSpec{flags: map[string]flagMode{"-U": modeUserPct, "--user": modeUserPct}},
		"smbclient", "rpcclient", "smbcacls", "smbget", "smbtree", "smbpasswd", "net", "winexe", "samba-tool")
	// UNVERIFIED: smbmap takes -u USER -p PASSWORD (from its usage text, not
	// re-read for this build); the Samba form is kept for compatibility.
	def(&toolSpec{flags: map[string]flagMode{"-U": modeUserPct, "--user": modeUserPct, "-p": modeNextPass}}, "smbmap")
	def(&toolSpec{flags: map[string]flagMode{"-u": modeUserComma}}, "lftp")
	// sqlplus [options] [logon] [@script]: the options that take a value,
	// so the logon is the first operand. Options are case-insensitive.
	def(&toolSpec{flags: argFlags("-m", "-markup", "-r", "-restrict", "-c", "-compatibility"), fold: true}, "sqlplus")
	defWrappers(t)
	return t
}

// argFlags maps each flag to modeArg.
func argFlags(flags ...string) map[string]flagMode {
	m := make(map[string]flagMode, len(flags))
	for _, f := range flags {
		m[f] = modeArg
	}
	return m
}

// defWrappers adds the programs that run another command ("sudo -u oracle
// sqlplus scott/PW@db", "rlwrap sqlplus ...", "env ORACLE_SID=x sqlplus
// ..."). Rules that hold only for a program in command position (the
// sqlplus logon) need to see through them, and their value-taking options
// must not be taken for the command.
func defWrappers(t map[string]*toolSpec) {
	wrap := func(lead int, flags map[string]flagMode, programs ...string) {
		spec := &toolSpec{flags: flags, optsFirst: true, wraps: true, lead: lead}
		for _, p := range programs {
			t[p] = spec
		}
	}
	// sudo's -h is both --help and --host, so it is left out.
	wrap(0, argFlags("-u", "-g", "-C", "-D", "-p", "-R", "-r", "-t", "-T", "-U", "--user", "--group",
		"--close-from", "--chdir", "--prompt", "--chroot", "--role", "--type", "--command-timeout",
		"--other-user", "--host"), "sudo")
	wrap(0, argFlags("-u", "-C"), "doas")
	wrap(0, argFlags("-u", "-g", "-G", "--user", "--group", "--supp-group"), "runuser")
	wrap(0, argFlags("-u", "--unset", "-C", "--chdir"), "env")
	wrap(0, argFlags("-n", "--adjustment"), "nice")
	wrap(0, argFlags("-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"), "ionice")
	wrap(0, argFlags("-i", "-o", "-e", "--input", "--output", "--error"), "stdbuf")
	wrap(0, argFlags("-o", "-f", "--output", "--format"), "time")
	wrap(0, argFlags("-o", "-e", "-p", "-s", "-u", "-E"), "strace")
	wrap(0, argFlags("-I", "-n", "-P", "-d", "-a", "-E", "-L", "-s", "--max-args", "--max-procs",
		"--delimiter", "--arg-file", "--eof", "--max-lines", "--max-chars"), "xargs")
	wrap(0, argFlags("-n", "--interval"), "watch")
	// rlwrap's -a, -i, -p and -r take no value or a glued one; these take
	// the next argument.
	wrap(0, argFlags("-b", "-C", "-D", "-e", "-f", "-g", "-H", "-l", "-O", "-q", "-s", "-S", "-t", "-w", "-z"), "rlwrap")
	wrap(1, argFlags("-s", "--signal", "-k", "--kill-after"), "timeout")
	wrap(1, argFlags("--userspec", "--groups"), "chroot")
	wrap(0, argFlags("-a"), "exec")
	wrap(0, nil, "nohup", "setsid", "unbuffer", "command", "builtin", "cmd")
}

// gluable reports a tool flag whose value may be glued to it: a short
// single-dash flag ("-p", "-U", "-hp").
func gluable(flag string) bool {
	return len(flag) >= 2 && len(flag) <= 3 && flag[0] == '-' && flag[1] != '-'
}

// passwordWordSuffixes end flag names whose value is a password.
var passwordWordSuffixes = []string{"pass", "passwd", "password", "passphrase", "passcode"}

// notPasswordSuffixes end in the letters of a password word without being
// one, or switch prompting on.
var notPasswordSuffixes = []string{"bypass", "compass", "surpass", "trespass", "askpass", "ask-pass", "ask_pass"}

// passwordFlag reports a flag NAME (without its dashes) that ends in a
// password word: --db-pass, -storepass, -keypass, -srcstorepass,
// --admin-password, -passphrase, /password. Names that switch prompting on
// or off (--ask-pass, --no-pass, --skip-password) or merely end in the
// letters (--bypass, --compass) are not password flags, and neither is
// anything that is not an identifier ("/etc/nginx/.htpasswd" is a path).
func passwordFlag(name string) bool {
	if len(name) < 2 || len(name) > maxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isAlnum(c) && c != '_' && c != '-' {
			return false
		}
	}
	low := asciiLower(name)
	matched := false
	for _, w := range passwordWordSuffixes {
		if strings.HasSuffix(low, w) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, w := range notPasswordSuffixes {
		if strings.HasSuffix(low, w) {
			return false
		}
	}
	for _, p := range []string{"no-", "no_", "skip", "ask"} {
		if strings.HasPrefix(low, p) {
			return false
		}
	}
	return true
}

// passSource reports a value that says where a password is read from
// rather than being one: "stdin", "prompt", "-", env:VAR, file:path, fd:N
// (openssl -pass, keytool -storepass:env, --password=stdin).
func passSource(v string) bool {
	low := asciiLower(v)
	switch low {
	case "stdin", "prompt", "-":
		return true
	}
	return strings.HasPrefix(low, "env:") || strings.HasPrefix(low, "file:") || strings.HasPrefix(low, "fd:")
}

// keepPasswordValue reports a value in a password position that is not a
// literal password: nothing, a prompt request ("*", "-"), a password
// source, a variable or @file reference, or redaction markers alone. Unlike
// keepAsWritten it keeps no dotted words, paths or URLs: where the grammar
// says the argument IS the password, "my.pass.word" is the password.
func keepPasswordValue(v string) bool {
	if v == "" || v == "*" || passSource(v) || onlyMarkers(v) {
		return true
	}
	switch v[0] {
	case '$':
		return varReference(v) && !strings.ContainsAny(v, " \t")
	case '%':
		return len(v) > 2 && v[len(v)-1] == '%' && !strings.ContainsAny(v, " \t")
	case '@':
		return len(v) > 1 && (v[1] == '/' || v[1] == '.' || v[1] == '~')
	}
	return false
}

// keepNamedPasswordValue is keepPasswordValue for a flag that is a password
// only by its NAME (--db-pass, --auth-user-pass, /password). There a value
// shaped like a file path is the file that holds the credentials (openvpn
// --auth-user-pass /etc/openvpn/creds.txt, --password /run/secrets/db):
// the path is what a responder needs, and a password of two or more path
// components is not a realistic case. Where a program's grammar puts the
// password (mysql -p, sshpass -p) a path is still redacted.
func keepNamedPasswordValue(v string) bool {
	return keepPasswordValue(v) || filePathValue(v)
}

// filePathValue reports a value shaped like a file name: an absolute path of
// two or more components, a ./ ../ ~/ relative path, or a drive path, with
// no white space.
func filePathValue(v string) bool {
	if len(v) < 3 || len(v) > 4096 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	for _, p := range []string{"./", "../", "~/", `.\`, `..\`, `~\`} {
		if strings.HasPrefix(v, p) && len(v) > len(p) {
			return true
		}
	}
	switch {
	case v[0] == '/':
		i := strings.IndexByte(v[1:], '/')
		return i > 0 && i+2 < len(v)
	case v[1] == ':' && (v[2] == '\\' || v[2] == '/') && (v[0]|0x20 >= 'a' && v[0]|0x20 <= 'z'):
		return len(v) > 3
	}
	return false
}

// userPass returns the offset of the password in sqlplus "user/password[@db]",
// or 0 when a is not of that form (a path, "/" for OS authentication,
// "@script.sql").
func userPass(a string) int {
	j := strings.IndexByte(a, '/')
	if j <= 0 || j == len(a)-1 || strings.ContainsAny(a[:j], `.~\:@`) {
		return 0
	}
	return j + 1
}

// redactSQLPlusLogon redacts the password of "user/password[@connect]".
// Oracle encloses a password holding special characters in double quotes
// (scott/"Pa@ss"@orcl): it then runs to the closing quote, not to the first
// "@". The connect string is kept here; RedactArgs passes it through Redact
// with the rest of the argument.
func redactSQLPlusLogon(a string) (string, bool) {
	j := userPass(a)
	if j == 0 {
		return a, false
	}
	pw, tail := a[j:], ""
	if pw[0] == '"' {
		if q := strings.IndexByte(pw[1:], '"'); q >= 0 {
			pw, tail = pw[:q+2], pw[q+2:]
		}
	} else if at := strings.IndexByte(pw, '@'); at >= 0 {
		pw, tail = pw[:at], pw[at:]
	}
	if keepPasswordValue(pw) {
		return a, false
	}
	return a[:j] + markAroundMarkers(KindPassword, pw) + tail, true
}

// vaultBoolFlags are vault CLI flags that take no value, so an operand after
// them can be the token of "vault login [flags] TOKEN". Any other flag
// written without "=" is taken to own the next argument.
var vaultBoolFlags = lazySet{list: []string{
	"-no-print", "-no-store", "-token-only", "-tls-skip-verify", "-non-interactive",
	"-h", "-help", "--no-print", "--no-store", "--token-only", "--tls-skip-verify",
	"--non-interactive", "--help",
}}
