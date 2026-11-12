package classify

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

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
		Marker(KindPassword, "1a2b3c4d"): true,
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
		// kubectl makes each "--" start a nested command line (a plain "--"
		// would end option parsing for the rest of the vector).
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
