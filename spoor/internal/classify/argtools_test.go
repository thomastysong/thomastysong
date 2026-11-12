package classify

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

// argsLeak reports a RedactArgs result that still holds secret, or that
// lost one of keep.
func argsLeak(t *testing.T, in []string, secret string, keep ...string) {
	t.Helper()
	out := RedactArgs(in)
	joined := strings.Join(out, " ")
	if len(out) != len(in) || strings.Contains(strings.Join(out, "\x00"), secret) {
		t.Errorf("RedactArgs(%q)\n  = %q\n  leaks %q", in, out, secret)
	}
	for _, k := range keep {
		if !strings.Contains(joined, k) {
			t.Errorf("RedactArgs(%q) = %s: lost %q", in, joined, k)
		}
	}
	if !wellFormedMarkers(joined) {
		t.Errorf("RedactArgs(%q) = %s: marker inside a marker", in, joined)
	}
}

// argsKept checks that RedactArgs leaves a benign vector as written.
func argsKept(t *testing.T, in ...string) {
	t.Helper()
	if out := RedactArgs(in); strings.Join(out, "\x00") != strings.Join(in, "\x00") {
		t.Errorf("RedactArgs(%q) = %q, want it unchanged", in, out)
	}
}

// patToken is a GitHub-classic-PAT-shaped value that Redact alone detects,
// assembled at run time.
func patToken(r *rand.Rand) string { return "gh" + "p_" + randAlnum(r, 36) }

func TestPasswordFlag(t *testing.T) {
	for name, want := range map[string]bool{
		"db-pass": true, "storepass": true, "keypass": true, "srcstorepass": true, "deststorepass": true,
		"admin-password": true, "passphrase": true, "passcode": true, "passwd": true, "Password": true,
		"new_password": true, "pass": true, "storepasswd": true,
		"bypass": false, "bypass-cache": false, "compass": false, "surpass": false, "trespass": false,
		"no-pass": false, "no_password": false, "ask-pass": false, "askpass": false, "ask-vault-pass": false,
		"skip-password": false, "password-file": false, "passes": false, "pass-through": false,
		"etc/nginx/.htpasswd": false, "p": false, "": false, "pass:x": false, "pass word": false,
		strings.Repeat("a", maxNameLen) + "pass": false,
	} {
		if got := passwordFlag(name); got != want {
			t.Errorf("passwordFlag(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPassSourceAndKeep(t *testing.T) {
	for v, want := range map[string]bool{
		"stdin": true, "STDIN": true, "prompt": true, "-": true, "env:DB_PASS": true,
		"file:/run/pw": true, "fd:3": true, "pass:x": false, "environment": false, "": false,
	} {
		if got := passSource(v); got != want {
			t.Errorf("passSource(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"": true, "*": true, "-": true, "stdin": true, "env:X": true, "$DB_PASS": true, "${DB_PASS}": true,
		"$(pw_cmd)": true, "%DBPASS%": true, "@./pw.txt": true, "@/run/pw": true,
		Marker(KindPassword, "1a2b3c4d"): true, Marker(KindPassword, "1a2b3c4d") + Marker(KindPassword, "5e6f7a8b"): true,
		Marker(KindPassword, "1a2b3c4d") + "x": false, "[REDACTED:qz9wertxy]": false,
		// In a password position these are passwords, whatever they look like.
		"my.dotted.word": false, "/a/b": false, "https://x.example": false, "<password>": false,
		"$2b$12$saltsaltsalt": false, "$ x": false, "$(echo hunter2)": false, "%not a var%": false, "hunter2": false, "a": false,
		"[REDACTED:Password:1a2b3c4d]": false,
	} {
		if got := keepPasswordValue(v); got != want {
			t.Errorf("keepPasswordValue(%q) = %v, want %v", v, got, want)
		}
	}
	for a, want := range map[string]bool{
		"-new": true, "--host": true, "-v": true, "-keystore": true, "--db_host": true,
		"-": false, "--": false, "-Xy7!": false, "---x": false, "-1abc": false, "x": false, "": false,
	} {
		if got := flagShaped(a); got != want {
			t.Errorf("flagShaped(%q) = %v, want %v", a, got, want)
		}
	}
}

// TestToolTable: every program named in the privacy tier's argument table
// has a grammar entry, and each entry's flags are well formed.
func TestToolTable(t *testing.T) {
	specs := toolSpecs()
	for _, prog := range []string{
		"sshpass", "sqlcmd", "bcp", "osql", "ssh-keygen", "psexec", "psexec64", "paexec",
		"schtasks", "keytool", "rar", "unrar", "winrar", "smbclient", "rpcclient", "smbcacls",
		"smbget", "smbtree", "smbmap", "smbpasswd", "net", "winexe", "samba-tool", "lftp",
		"curl", "mysql", "7z", "openssl", "redis-cli", "ldapsearch", "zip", "login", "mongosh",
	} {
		if specs[prog] == nil {
			t.Errorf("no grammar for %s", prog)
		}
	}
	for prog, spec := range specs {
		if prog != asciiLower(prog) || strings.HasSuffix(prog, ".exe") {
			t.Errorf("%q: program words are lower case without .exe", prog)
		}
		for f, m := range spec.flags {
			if m == modeNone || len(f) < 2 || (f[0] != '-' && f[0] != '/') {
				t.Errorf("%s: bad flag %q", prog, f)
			}
			if spec.fold && f != asciiLower(f) {
				t.Errorf("%s: folded flag %q must be lower case", prog, f)
			}
		}
	}
}

// TestRedactArgsNearestToolWins: when two programs in one vector give the
// same flag a meaning, the nearer one decides, every time (the old table
// was a map iterated in random order).
func TestRedactArgsNearestToolWins(t *testing.T) {
	g := newCanaryGen()
	for i := 0; i < 50; i++ {
		argv, used := g.fill([]string{"sshpass", "-p", "{pw}", "mysql", "-p{pw}", "db"})
		out := RedactArgs(argv)
		if strings.Contains(strings.Join(out, " "), "Canary") || out[5] != "db" {
			t.Fatalf("%q -> %q (%v)", argv, out, used)
		}
		// curl's -U is a proxy user:password; smbclient's is user%password.
		argv, _ = g.fill([]string{"curl", "-o", "x", "u", "&&", "smbclient", "-U", "bob%{pw}", "//h/s"})
		if out := RedactArgs(argv); !strings.HasPrefix(out[7], "bob%[REDACTED:password:") {
			t.Fatalf("%q -> %q", argv, out)
		}
	}
	// sshpass's options end at the command it runs.
	out := RedactArgs([]string{"sshpass", "-e", "ssh", "-p", "2222", "h"})
	if out[4] != "2222" {
		t.Errorf("ssh port taken for a password: %q", out)
	}
}

// TestRedactArgsHostile: huge vectors, many distinct words, flag storms and
// invalid UTF-8 stay linear, keep the vector's length and never panic.
func TestRedactArgsHostile(t *testing.T) {
	var big []string
	for i := 0; i < 50000; i++ {
		// kubectl makes each "--" start a nested command line, where
		// mysql's -p applies again.
		big = append(big, "prog"+strconv.Itoa(i), "-p", "mysql", "-pX"+strconv.Itoa(i), "kubectl", "--", "sshpass", "-p", "--password")
	}
	big = append(big, "\xff\xfe-p", "-\xff", "/\xff", "sqlplus", "a/\xff@b")
	start := time.Now()
	out := RedactArgs(big)
	if len(out) != len(big) {
		t.Fatalf("length %d, want %d", len(out), len(big))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("RedactArgs took %v on %d arguments", d, len(big))
	}
	for i := 3; i < 900; i += 9 {
		if !strings.HasPrefix(out[i], "-p[REDACTED:password:") {
			t.Fatalf("argument %d: %q", i, out[i])
		}
	}
	if RedactArgs(nil) != nil || len(RedactArgs([]string{})) != 0 {
		t.Error("nil and empty vectors")
	}
	for _, v := range [][]string{{"-"}, {"/"}, {"--"}, {"-p"}, {"sshpass", "-p"}, {"vault", "login"}, {"sqlplus"}, {"schtasks", "/rp"}} {
		if got := RedactArgs(v); len(got) != len(v) {
			t.Errorf("%q -> %q", v, got)
		}
	}
}

// TestRedactArgsSshpassValueOptions: sshpass's own value-taking options (-P
// prompt, -d fd, -f file) take their value; it is not the command sshpass
// runs. Counted as an operand, the value ended sshpass's options before
// -p, and "sshpass -P passphrase -p PW" (the idiom for key passphrases)
// shipped the password for every direct RedactArgs caller.
func TestRedactArgsSshpassValueOptions(t *testing.T) {
	g := newCanaryGen()
	for _, c := range []struct {
		tmpl []string
		keep []string
	}{
		{[]string{"sshpass", "-P", "passphrase", "-p", "{pw}", "ssh", "-i", "k", "h"}, []string{"-P passphrase -p", "ssh -i k h"}},
		{[]string{"sshpass", "-P", "assword:", "-p{pw}", "ssh", "h"}, []string{"-P assword: -p", "ssh h"}},
		{[]string{"/usr/bin/sshpass", "-d", "3", "-p", "{pw}", "scp", "f", "h:"}, []string{"-d 3 -p", "scp f h:"}},
		{[]string{"sshpass", "-v", "-P", "Enter passphrase", "-p", "{pw}", "ssh", "h"}, []string{"Enter passphrase"}},
		{[]string{"sudo", "-u", "ops", "sshpass", "-P", "passphrase", "-p", "{pw}", "ssh", "h"}, []string{"-u ops"}},
	} {
		argv, used := g.fill(c.tmpl)
		argsLeak(t, argv, used[0], c.keep...)
	}
	// The values still end nothing: after them, sshpass's options go on
	// until the command, whose -p is a port.
	argsKept(t, "sshpass", "-P", "passphrase", "-f", "/run/pw", "ssh", "-p", "2222", "h")
	argsKept(t, "sshpass", "-d", "3", "ssh", "-p", "2222", "h")
}

// TestRedactArgsKeptPartsPassRedact: what a structural rule keeps (the user
// of user:pw, user%pw and user,pw, the sqlplus connect string, a reference)
// still passes through Redact, as RedactArgs's doc comment says. They used
// to be emitted with no Redact pass, so a token Redact finds on its own
// survived RedactArgs.
func TestRedactArgsKeptPartsPassRedact(t *testing.T) {
	r := rand.New(rand.NewPCG(37, 41))
	tok := patToken(r)
	if got, _ := Redact("x " + tok); strings.Contains(got, tok) {
		t.Fatalf("precondition: Redact does not find the token: %q", got)
	}
	argsLeak(t, []string{"curl", "-u", tok + ":x-oauth-basic", "https://api.github.com/user"}, tok, ":x-oauth-basic")
	argsLeak(t, []string{"curl", "-u", tok + ":pw1", "https://h.internal"}, tok)
	argsLeak(t, []string{"smbclient", "-U", tok + "%pw1", "//h/s"}, tok, "//h/s")
	argsLeak(t, []string{"lftp", "-u", tok + ",pw1", "sftp://h"}, tok, "sftp://h")
	argsLeak(t, []string{"sqlplus", "scott/pw1@" + tok}, tok, "scott/")
	argsLeak(t, []string{"openssl", "pkcs12", "-passin", tok}, tok)
	argsLeak(t, []string{"tool", "--token", "[" + tok + "]"}, tok)
	argsLeak(t, []string{"tool", "--token", "$X:" + tok}, tok)
	argsLeak(t, []string{"vault", "login", "-method=userpass", "username=" + tok}, tok)

	// x-oauth-basic makes the user part the token, whatever its format (a
	// classic token is 40 hex digits, which no pattern claims).
	hex := strings.Map(func(c rune) rune { return rune("0123456789abcdef"[int(c)%16]) }, randAlnum(r, 40))
	argsLeak(t, []string{"curl", "-u", hex + ":x-oauth-basic", "https://api.github.com/user"}, hex, ":x-oauth-basic")
	argsKept(t, "curl", "-u", "$GITHUB_TOKEN:x-oauth-basic", "https://api.github.com/user")

	// openssl -pass*: a value with no source prefix is the password typed
	// without "pass:"; sources are kept; a following flag is the next flag.
	g := newCanaryGen()
	for _, tmpl := range [][]string{
		{"openssl", "pkcs12", "-passin", "{pw}", "-in", "x.p12"},
		{"openssl", "pkcs12", "-export", "-passout", "{pw}"},
		{"openssl", "enc", "-pass", "pass:{pw}", "-in", "f"},
	} {
		argv, used := g.fill(tmpl)
		argsLeak(t, argv, used[0])
	}
	argsKept(t, "openssl", "pkcs12", "-passin", "env:P12_PASS", "-passout", "file:/run/pw", "-in", "x.p12")
	argsKept(t, "openssl", "pkcs12", "-passin", "-in", "x.p12")
	argsKept(t, "openssl", "enc", "-pass", "pass:$ENC_PASS", "-in", "f")
	argsKept(t, "openssl", "enc", "-pass", "stdin", "-in", "f")
}

// TestRedactArgsSqlplusCommandPosition: the sqlplus logon is redacted when
// sqlplus is the command, also behind a wrapper, and Oracle's quoted
// passwords run to the closing quote. It used to fire only when sqlplus was
// the first word of the vector, and cut a quoted password at its first "@".
func TestRedactArgsSqlplusCommandPosition(t *testing.T) {
	g := newCanaryGen()
	for _, c := range []struct {
		tmpl []string
		keep []string
	}{
		{[]string{"rlwrap", "sqlplus", "scott/{pw}@orcl"}, []string{"scott/", "@orcl"}},
		{[]string{"sudo", "-u", "oracle", "sqlplus", "-S", "scott/{pw}@orcl"}, []string{"-u oracle", "@orcl"}},
		{[]string{"env", "ORACLE_SID=x", "sqlplus", "system/{pw}"}, []string{"ORACLE_SID=x", "system/"}},
		{[]string{"timeout", "-s", "KILL", "30", "sqlplus", "scott/{pw}@orcl"}, []string{"30 sqlplus scott/"}},
		{[]string{"nice", "-n", "5", "nohup", "sqlplus", "-L", "scott/{pw}@orcl"}, nil},
		{[]string{"cmd", "/c", "sqlplus.exe", "scott/{pw}@orcl"}, nil},
		{[]string{"ls", "&&", "sqlplus", "scott/{pw}@orcl"}, nil},
		{[]string{"kubectl", "exec", "pod", "--", "sqlplus", "scott/{pw}"}, nil},
		{[]string{"sqlplus", "-M", "HTML ON", "scott/{pw}@orcl"}, []string{"HTML ON"}},
		{[]string{"/u01/app/oracle/bin/sqlplus", "scott/{pw}@orcl", "@run.sql", "out/dir"}, []string{"@run.sql out/dir"}},
		// Quoted passwords: everything up to the closing quote.
		{[]string{"sqlplus", `scott/"Pa@{pw}"@orcl`}, []string{"scott/", "@orcl"}},
		{[]string{"sqlplus", `scott/"{pw} x@y"@//db.internal:1521/svc as sysdba`}, []string{"@//db.internal:1521/svc as sysdba"}},
		{[]string{"sqlplus", `scott/"{pw}`}, nil},
	} {
		argv, used := g.fill(c.tmpl)
		argsLeak(t, argv, used[0], c.keep...)
	}
	// The same shape elsewhere is not a logon.
	argsKept(t, "grep", "sqlplus", "src/main")
	argsKept(t, "grep", "-r", "sqlplus", "src/main")
	argsKept(t, "echo", "sqlplus", "a/b")
	argsKept(t, "sqlplus", "-s", "/nolog", "@run.sql", "out/dir")
	argsKept(t, "sqlplus", "/", "as", "sysdba")
	argsKept(t, "sudo", "sqlplus", "@run.sql", "a/b")
}

// TestRedactArgsOptionLists: every secret-named pair of an option list is
// redacted. Only the first NAME= used to be unpacked, so the canonical
// mount.cifs "-o username=bob,password=PW" was left to the free-text gate,
// which drops letters-only passwords under 10 characters; and when the
// secret pair came first the pairs after it were swallowed into its marker.
func TestRedactArgsOptionLists(t *testing.T) {
	const pw = "letmein" // letters only: no pattern, only the structure finds it
	for _, c := range []struct {
		argv []string
		keep []string
	}{
		{[]string{"mount", "-t", "cifs", "//h/s", "/mnt", "-o", "username=bob,password=" + pw}, []string{"username=bob,password=[REDACTED:password:"}},
		{[]string{"mount.cifs", "//h/s", "/mnt", "-o", "user=bob,pass=" + pw}, []string{"user=bob,pass=[REDACTED:password:"}},
		{[]string{"mount", "-o", "rw,username=bob,password=" + pw + ",uid=1000,vers=3.0"}, []string{"rw,username=bob,password=", ",uid=1000,vers=3.0"}},
		{[]string{"mount", "-o", "password=" + pw + ",username=bob"}, []string{",username=bob"}},
		{[]string{"mount", "-o", "password=" + pw + ",x,username=bob"}, []string{",username=bob"}},
		{[]string{"helm", "install", "x", "--set", "a.b=1,db.password=" + pw + ",c=2"}, []string{"--set a.b=1,db.password=", ",c=2"}},
		{[]string{"tool", "-ouser=bob;pass=" + pw}, []string{"-ouser=bob;pass="}},
		{[]string{"tool", "--opts=domain=CORP;password=" + pw + ";timeout=5"}, []string{"domain=CORP;password=", ";timeout=5"}},
	} {
		argsLeak(t, c.argv, pw, c.keep...)
	}
	argsKept(t, "mount", "-o", "rw,noatime,vers=3.0,credentials=/root/.smbcred", "//h/s", "/mnt")
	argsKept(t, "tool", "a=1,b=2;c=3")
	argsKept(t, "tool", "Hello, world=1")
	argsKept(t, "tool", "--set", "image.tag=1.2,replicas=3")
}

// TestRedactArgsNetPasswords: Windows "net use \\host\share PASSWORD" and
// "net user NAME PASSWORD" carry the password as an operand (so does Samba's
// "net [rpc] user add NAME PASSWORD").
func TestRedactArgsNetPasswords(t *testing.T) {
	g := newCanaryGen()
	for _, c := range []struct {
		tmpl []string
		keep []string
	}{
		{[]string{"net", "use", `\\h\s`, "{pw}", "/user:bob"}, []string{`\\h\s`, "/user:bob"}},
		{[]string{"net.exe", "use", "Z:", `\\h\s`, "/user:CORP\\bob", "{pw}", "/persistent:no"}, []string{"Z:", "/persistent:no"}},
		{[]string{"net", "use", "Z:", "https://dav.internal/x", "{pw}", "/user:bob"}, []string{"https://dav.internal/x"}},
		{[]string{"net.exe", "user", "bob", "{pw}", "/add"}, []string{"user bob", "/add"}},
		{[]string{`C:\Windows\System32\NET.EXE`, "USER", "bob", "{pw}"}, []string{"USER bob"}},
		{[]string{"net1", "user", "bob", "{pw}", "/domain"}, nil},
		{[]string{"net", "rpc", "user", "add", "bob", "{pw}", "-S", "h"}, []string{"add bob", "-S h"}},
		{[]string{"net", "user", "password", "bob", "{pw}"}, []string{"password bob"}},
		{[]string{"net", "rpc", "password", "bob", "{pw}"}, []string{"password bob"}},
	} {
		argv, used := g.fill(c.tmpl)
		argsLeak(t, argv, used[0], c.keep...)
	}
	argsKept(t, "net", "use", `\\h\s`, "*", "/user:bob")
	argsKept(t, "net", "use", "Z:", "/delete")
	argsKept(t, "net", "use", `\\h\IPC$`, "", "/user:bob")
	argsKept(t, "net", "user", "bob", "/delete")
	argsKept(t, "net", "user", "bob", "/active:no")
	argsKept(t, "net", "user", "bob")
	argsKept(t, "net", "rpc", "user", "delete", "bob")
	argsKept(t, "net", "rpc", "user", "info", "bob")
	argsKept(t, "net", "view", `\\fileserver`)
	argsKept(t, "echo", "user", "bob", "x")
}

// TestRedactArgsDoubleDashPassThrough: a plain "--" ends the options of the
// programs before it, not flag recognition. It used to end flag parsing
// for the rest of the vector, so flags a runner passes through to the
// program it starts were never seen as flags.
func TestRedactArgsDoubleDashPassThrough(t *testing.T) {
	g := newCanaryGen()
	for _, tmpl := range [][]string{
		{"dotnet", "run", "--", "--password", "{pw}"},
		{"make", "run", "--", "--token", "{pw}"},
		{"python3", "app.py", "--", "--db-pass={pw}"},
		{"gradle", "run", "--args", "x", "--", "/password:{pw}"},
		{"tool", "--", "x", "--", "--api-key", "{pw}"},
	} {
		argv, used := g.fill(tmpl)
		argsLeak(t, argv, used[0], "--")
	}
	argsKept(t, "git", "log", "--", "src/a")
	argsKept(t, "grep", "--", "-p", "file")
	argsKept(t, "rm", "--", "-rf")
	// "--" ends sqlcmd's options: its -P grammar no longer applies.
	argsKept(t, "sqlcmd", "-S", "db", "--", "app", "-P", "8080")
}

// TestRedactArgsPasswordNamedFlagKeepsPath: after a flag that is a password
// only by its name, a file path is the file that holds the credential
// (openvpn --auth-user-pass FILE) and is kept; where a program's grammar
// puts the password, a path is still redacted.
func TestRedactArgsPasswordNamedFlagKeepsPath(t *testing.T) {
	argsKept(t, "openvpn", "--config", "c.ovpn", "--auth-user-pass", "/etc/openvpn/creds.txt")
	argsKept(t, "tool", "--password", "/run/secrets/db_password")
	argsKept(t, "tool", "--db-pass=./secrets/db.txt")
	argsKept(t, "tool", "--admin-password", `C:\secrets\pw.txt`)
	argsKept(t, "run.exe", `/password:C:\creds\pw.txt`)
	argsKept(t, "run.exe", "/password", `..\creds\pw.txt`)
	argsKept(t, "keytool", "-list", "-storepass:~/.keystore-pw")
	for _, argv := range [][]string{
		{"mysql", "-p/etc/x/y", "db"},
		{"sshpass", "-p", "/a/b", "ssh", "h"},
		{"curl", "-u", "bob:/a/b", "https://h.internal"},
		{"tool", "--password", "/x"},
		{"tool", "--password", "/a b/c"},
		{"redis-cli", "-a", "./pw", "ping"},
	} {
		if out := RedactArgs(argv); strings.Join(out, " ") == strings.Join(argv, " ") {
			t.Errorf("RedactArgs(%q) kept the password", argv)
		}
	}
	for v, want := range map[string]bool{
		"/etc/openvpn/creds.txt": true, "./pw": true, "../pw": true, "~/pw": true, `C:\pw\x`: true, "c:/pw": true, `.\pw`: true,
		"/x": false, "/x/": false, "//": false, "./": false, "/a b/c": false, "pw/x": false, "C:x": false, "": false,
	} {
		if got := filePathValue(v); got != want {
			t.Errorf("filePathValue(%q) = %v, want %v", v, got, want)
		}
	}
}
