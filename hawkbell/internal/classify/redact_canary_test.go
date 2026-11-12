package classify

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

// canaryGen hands out synthetic credentials assembled at run time, so no
// credential-shaped literal is committed. Every canary contains "Canary";
// the seeded suffix makes them look like the passwords people type.
type canaryGen struct {
	n   int
	rng *rand.Rand
}

func newCanaryGen() *canaryGen { return &canaryGen{rng: rand.New(rand.NewPCG(7, 11))} }

func (g *canaryGen) next() string {
	const alnum = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	g.n++
	b := []byte("Canary" + "Pw" + strconv.Itoa(g.n))
	for i := 0; i < 5; i++ {
		b = append(b, alnum[g.rng.IntN(len(alnum))])
	}
	return string(b)
}

// fill replaces every "{pw}" in a template with a fresh canary and returns
// the argument vector and the canaries used.
func (g *canaryGen) fill(tmpl []string) (argv, used []string) {
	argv = make([]string, len(tmpl))
	for i, a := range tmpl {
		for strings.Contains(a, "{pw}") {
			c := g.next()
			used = append(used, c)
			a = strings.Replace(a, "{pw}", c, 1)
		}
		for strings.Contains(a, "{dotted}") {
			// A password that is a dotted word: keepAsWritten would take it
			// for a member access, a password position must not.
			// Letters only: a dotted word with a digit is not taken for
			// code anyway.
			g.n++
			c := "Canary." + "dotted." + string(rune('a'+g.n%26)) + string(rune('a'+g.n/26%26)) + "pw"
			used = append(used, c)
			a = strings.Replace(a, "{dotted}", c, 1)
		}
		argv[i] = a
	}
	return argv, used
}

// wellFormedMarkers reports whether every "[REDACTED:" in s opens a
// complete marker: no marker inside or around another.
func wellFormedMarkers(s string) bool {
	for off := 0; ; {
		i := strings.Index(s[off:], markerOpen)
		if i < 0 {
			return true
		}
		i += off
		n := markerLen(s[i:])
		if n == 0 {
			return false
		}
		off = i + n
	}
}

// TestRedactArgsCanaryCorpus is the privacy red team's command-line corpus,
// extended with every rule of the privacy tier's own argument table
// (internal/privacy/argrules.go), which RedactArgs now applies for all
// callers: every synthetic credential must disappear, and the benign parts
// that detection needs (hosts, digests, paths, flags) must survive. The
// measured rates are reported so a regression is visible.
func TestRedactArgsCanaryCorpus(t *testing.T) {
	g := newCanaryGen()
	secret := []struct {
		argv []string
		keep []string
	}{
		{[]string{"mysql", "-p{pw}", "-u", "root", "db"}, []string{"-u root db"}},
		{[]string{"curl", "-u", "alice:{pw}", "https://x.example"}, []string{"alice:"}},
		{[]string{"sshpass", "-p", "{pw}", "ssh", "u@h"}, []string{"ssh u@h"}},
		{[]string{"docker", "login", "-p", "{pw}", "-u", "me", "reg.example"}, []string{"-u me reg.example"}},
		{[]string{"redis-cli", "-a", "{pw}", "ping"}, []string{"ping"}},
		{[]string{"7z", "x", "-p{pw}", "a.7z"}, []string{"a.7z"}},
		{[]string{"openssl", "enc", "-d", "-k", "{pw}", "-in", "x"}, []string{"-in x"}},
		{[]string{"curl", "--proxy-user", "bob:{pw}", "https://x.example"}, nil},
		{[]string{"openssl", "pkcs12", "-passin", "pass:{pw}", "-in", "a.p12"}, []string{"pass:"}},
		{[]string{"kubectl", "exec", "pod", "--", "mysql", "-p{pw}"}, nil},
		{[]string{"aws", "configure", "set", "aws_secret_access_key", "{pw}"}, nil},
		{[]string{"curl", "-H", "Authorization: Bearer {pw}abcdefghijkl", "https://x.example"}, []string{"Authorization: Bearer "}},
		{[]string{"git", "clone", "https://bob:{pw}@github.com/a/b"}, []string{"github.com/a/b"}},
		{[]string{"psql", "postgres://admin:{pw}@db.example/prod"}, []string{"db.example/prod"}},
		{[]string{"export", "API_TOKEN={pw}"}, []string{"API_TOKEN="}},
		{[]string{"curl", "-H", "X-Api-Key: {pw}xyz", "https://x.example"}, nil},
		{[]string{"curl", "-d", "password={pw}&user=a", "https://x.example/login"}, []string{"&user=a"}},
		{[]string{"npm", "config", "set", "//registry.npmjs.org/:_authToken", "{pw}"}, nil},
		{[]string{"vault", "login", "-method=userpass", "username=a", "password={pw}"}, []string{"username=a"}},
		{[]string{"docker", "run", "--rm", "app", "--", "mysql", "-p{pw}"}, nil},

		// The privacy tier's table, rule by rule. Password attached or next:
		{[]string{"sshpass", "-p{pw}", "ssh", "deploy@h"}, []string{"ssh deploy@h"}},
		{[]string{"sshpass", "-p", "{pw}", "ssh", "-p", "22", "h"}, []string{"ssh -p 22 h"}},
		{[]string{"sshpass", "-P", "passphrase", "-p", "{pw}", "ssh", "-i", "k", "h"}, []string{"-P passphrase", "ssh -i k h"}},
		{[]string{"sshpass", "-d", "3", "-p{pw}", "scp", "f", "h:"}, []string{"-d 3", "scp f h:"}},
		{[]string{"sqlcmd", "-S", "db", "-U", "sa", "-P", "{pw}", "-Q", "select 1"}, []string{"-S db -U sa -P", "-Q"}},
		{[]string{"sqlcmd", "-S", "db", "-P{pw}"}, []string{"-S db"}},
		{[]string{"bcp", "t", "out", "f.dat", "-S", "db", "-U", "sa", "-P", "{pw}"}, []string{"f.dat"}},
		{[]string{"bcp", "t", "in", "f.dat", "-P{pw}"}, nil},
		{[]string{"osql", "-S", "db", "-U", "sa", "-P", "{pw}"}, nil},
		{[]string{"osql", "-P{pw}", "-Q", "q"}, nil},
		{[]string{"ssh-keygen", "-t", "ed25519", "-N", "{pw}", "-f", "id"}, []string{"-f id"}},
		{[]string{"ssh-keygen", "-p", "-P", "{pw}", "-N", "{pw}", "-f", "id"}, []string{"-p -P", "-f id"}},
		{[]string{"ssh-keygen", "-N{pw}", "-f", "id"}, nil},
		{[]string{"psexec", `\\h`, "-u", "bob", "-p", "{pw}", "cmd"}, []string{`\\h -u bob -p`, "cmd"}},
		{[]string{`C:\Tools\PsExec64.exe`, `\\h`, "-p{pw}", "cmd"}, nil},
		{[]string{"paexec", `\\h`, "-u", "bob", "-p", "{pw}", "cmd"}, nil},
		// Next argument only, case-insensitive:
		{[]string{"schtasks", "/create", "/tn", "t", "/tr", "x.exe", "/ru", "bob", "/rp", "{pw}"}, []string{"/ru bob /rp"}},
		{[]string{"SCHTASKS.EXE", "/Create", "/S", "h", "/U", "bob", "/P", "{pw}", "/TN", "t"}, []string{"/TN t"}},
		{[]string{"keytool", "-storepasswd", "-new", "{pw}", "-keystore", "k.jks"}, []string{"-keystore k.jks"}},
		{[]string{"keytool", "-keypasswd", "-alias", "a", "-New", "{pw}"}, nil},
		// Attached only:
		{[]string{"rar", "a", "-p{pw}", "b.rar", "docs"}, []string{"b.rar docs"}},
		{[]string{"unrar", "x", "-p{pw}", "b.rar"}, nil},
		{[]string{"WinRAR.exe", "a", "-hp{pw}", "b.rar"}, nil},
		// Samba user%password:
		{[]string{"smbclient", "-U", "bob%{pw}", "//h/share"}, []string{"bob%", "//h/share"}},
		{[]string{"smbclient", "-Ubob%{pw}", "//h/share"}, []string{"-Ubob%"}},
		{[]string{"rpcclient", "--user=bob%{pw}", "h"}, []string{"--user=bob%"}},
		{[]string{"smbcacls", "-U", "bob%{pw}", "//h/s", "f"}, nil},
		{[]string{"smbget", "-U", "bob%{pw}", "smb://h/s/f"}, nil},
		{[]string{"smbtree", "-U", "bob%{pw}"}, nil},
		{[]string{"smbmap", "-U", "bob%{pw}", "-H", "h"}, nil},
		{[]string{"smbmap", "-u", "bob", "-p", "{pw}", "-H", "h"}, []string{"-H h"}},
		{[]string{"smbpasswd", "-U", "bob%{pw}", "-r", "h"}, nil},
		{[]string{"net", "rpc", "user", "-U", "admin%{pw}", "-S", "h"}, []string{"-S h"}},
		{[]string{"winexe", "-U", "dom/admin%{pw}", "//h", "cmd"}, []string{"dom/admin%"}},
		{[]string{"samba-tool", "user", "list", "--user", "admin%{pw}"}, nil},
		// lftp user,password:
		{[]string{"lftp", "-u", "bob,{pw}", "sftp://h"}, []string{"bob,", "sftp://h"}},
		// Positional:
		{[]string{"sqlplus", "scott/{pw}@orcl", "@script.sql"}, []string{"scott/", "@orcl @script.sql"}},
		{[]string{"sqlplus", "-s", "scott/{pw}@orcl"}, nil},
		{[]string{"sqlplus", "scott/{pw}"}, []string{"scott/"}},
		{[]string{"vault", "login", "{pw}"}, []string{"vault login"}},
		{[]string{"vault", "login", "-no-print", "{pw}"}, nil},
		{[]string{"sudo", "vault", "login", "{pw}"}, nil},
		{[]string{"sudo", "-u", "oracle", "sqlplus", "-S", "scott/{pw}@orcl"}, []string{"-u oracle", "@orcl"}},
		{[]string{"rlwrap", "sqlplus", `scott/"Pa@{pw}"@orcl`}, []string{"@orcl"}},
		{[]string{"net", "use", `\\h\share`, "{pw}", "/user:bob"}, []string{`\\h\share`, "/user:bob"}},
		{[]string{"net.exe", "user", "bob", "{pw}", "/add"}, []string{"user bob", "/add"}},
		{[]string{"mount", "-t", "cifs", "//h/s", "/mnt", "-o", "rw,username=bob,password={pw},uid=1000"}, []string{"rw,username=bob,password=", ",uid=1000"}},
		{[]string{"dotnet", "run", "--", "--password", "{pw}"}, []string{"dotnet run -- --password"}},
		{[]string{"openssl", "pkcs12", "-passin", "{pw}", "-in", "a.p12"}, []string{"-in a.p12"}},
		// Flags named like a password:
		{[]string{"deploytool", "--admin-pass", "{pw}", "--target", "prod"}, []string{"--target prod"}},
		{[]string{"keytool", "-genkeypair", "-storepass", "{pw}", "-keypass", "{pw}", "-alias", "a"}, []string{"-alias a"}},
		{[]string{"jarsigner", "-storepass", "{pw}", "app.jar", "alias"}, []string{"app.jar alias"}},
		{[]string{"keytool", "-importkeystore", "-srcstorepass", "{pw}", "-deststorepass", "{pw}"}, []string{"-srcstorepass", "-deststorepass"}},
		{[]string{"keytool", "-list", "-storepass:{pw}", "-keystore", "k.jks"}, []string{"-storepass:", "k.jks"}},
		{[]string{"tool", "--db-pass={pw}"}, []string{"--db-pass="}},
		{[]string{"tool", "--db-pass", "{pw}", "--db-host", "h"}, []string{"--db-host h"}},
		{[]string{"tool", "--passphrase", "{pw}"}, nil},
		{[]string{"tool", "--passcode", "{pw}"}, nil},
		{[]string{"tool", "--db-pass", "-{pw}!"}, nil},
		{[]string{"run.exe", "/password", "{pw}"}, []string{"/password"}},
		{[]string{"run.exe", "/storepass:{pw}"}, []string{"/storepass:"}},
		// A tool behind wrappers or inside another command line:
		{[]string{"sudo", "-u", "ops", "sshpass", "-p{pw}", "ssh", "h"}, []string{"sudo -u ops sshpass -p", "ssh h"}},
		{[]string{"kubectl", "exec", "pod", "--", "sqlcmd", "-P", "{pw}"}, []string{"-- sqlcmd -P"}},
		{[]string{"nohup", "keytool", "-list", "-storepass", "{pw}"}, []string{"-storepass"}},
		// Two tools with the same flag: each -p belongs to the nearer one.
		{[]string{"sshpass", "-p{pw}", "mysql", "-p{pw}"}, nil},
		// Password positions redact dotted words that keepAsWritten keeps.
		{[]string{"mysql", "-p{dotted}", "db"}, []string{"db"}},
		{[]string{"curl", "-u", "bob:{dotted}", "https://x.example"}, []string{"bob:"}},
		{[]string{"redis-cli", "-a", "{dotted}", "ping"}, nil},
		{[]string{"tool", "--admin-password", "{dotted}"}, nil},
	}
	leaks, lost, total := 0, 0, 0
	for _, c := range secret {
		argv, used := g.fill(c.argv)
		out := RedactArgs(argv)
		if len(out) != len(argv) {
			t.Fatalf("%q: %d results for %d arguments", argv, len(out), len(argv))
		}
		joined := strings.Join(out, " ")
		total += len(used)
		for _, u := range used {
			if strings.Contains(joined, u) {
				leaks++
				t.Errorf("leak %q: %q -> %s", u, argv, joined)
			}
		}
		if strings.Contains(joined, "Canary") {
			t.Errorf("canary fragment: %q -> %s", argv, joined)
		}
		if !wellFormedMarkers(joined) {
			t.Errorf("marker inside a marker: %s", joined)
		}
		for _, k := range c.keep {
			if !strings.Contains(joined, k) {
				lost++
				t.Errorf("over-redacted %q in %q -> %s", k, argv, joined)
			}
		}
	}
	benign := []struct {
		in   []string
		keep []string
	}{
		{[]string{"git", "clone", "https://github.com/a/b"}, []string{"https://github.com/a/b"}},
		{[]string{"docker", "pull", "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, []string{"sha256:0123456789abcdef"}},
		{[]string{"cat", "/home/bob/projects/acme/src/main.go"}, []string{"/home/bob/projects/acme/src/main.go"}},
		{[]string{"curl", "https://api.example.com/v1/items?page=2"}, []string{"api.example.com", "page=2"}},
		{[]string{"openssl", "enc", "-d", "-in", "x.enc", "-out", "x"}, []string{"x.enc"}},
		{[]string{"kubectl", "get", "pods", "-n", "prod"}, []string{"prod"}},
		{[]string{"go", "test", "-run", "TestRedact", "./..."}, []string{"TestRedact"}},
		{[]string{"curl", "-d", "@payload.json", "http://localhost:4318/v1/logs"}, []string{"@payload.json", "localhost:4318"}},
		// The new rules must not eat what they only resemble.
		{[]string{"curl", "--bypass-cache", "/data/x"}, []string{"--bypass-cache /data/x"}},
		{[]string{"tool", "--no-pass", "file.txt"}, []string{"--no-pass file.txt"}},
		{[]string{"tool", "--ask-vault-pass", "site.yml"}, []string{"site.yml"}},
		{[]string{"tool", "--password-file", "/run/secrets/pw"}, []string{"/run/secrets/pw"}},
		{[]string{"openssl", "enc", "-pass", "env:ENC_PASS", "-in", "f"}, []string{"env:ENC_PASS"}},
		{[]string{"keytool", "-list", "-storepass:env", "STOREPW", "-keystore", "k.jks"}, []string{"-storepass:env STOREPW", "k.jks"}},
		{[]string{"tool", "--password=stdin"}, []string{"--password=stdin"}},
		{[]string{"tool", "--db-pass", "$DB_PASS"}, []string{"$DB_PASS"}},
		{[]string{"sqlplus", "/", "as", "sysdba"}, []string{"sqlplus / as sysdba"}},
		{[]string{"grep", "-r", "sqlplus", "src/main"}, []string{"src/main"}},
		{[]string{"vault", "login", "-method=oidc", "role=dev"}, []string{"-method=oidc role=dev"}},
		{[]string{"vault", "login", "-method", "userpass", "username=bob"}, []string{"-method userpass username=bob"}},
		{[]string{"vault", "login", "-"}, []string{"vault login -"}},
		{[]string{"schtasks", "/create", "/ru", "bob", "/rp", "*", "/sc", "daily"}, []string{"/rp * /sc daily"}},
		{[]string{"schtasks", "/create", "/ru", "bob", "/rp", "/sc", "daily"}, []string{"/rp /sc daily"}},
		{[]string{"rar", "x", "-p", "b.rar"}, []string{"-p b.rar"}},
		{[]string{"rar", "x", "-p-", "b.rar"}, []string{"-p- b.rar"}},
		{[]string{"mysql", "-p", "db"}, []string{"-p db"}},
		{[]string{"mongosh", "-p", "--host", "h"}, []string{"-p --host h"}},
		{[]string{"ssh-keygen", "-p", "-f", "id"}, []string{"-p -f id"}},
		{[]string{"sshpass", "-f", "/run/pw", "ssh", "h"}, []string{"/run/pw"}},
		{[]string{"lftp", "-u", "bob", "sftp://h"}, []string{"-u bob sftp://h"}},
		{[]string{"smbclient", "-U", "%SMBUSER%", "//h/s"}, []string{"%SMBUSER%"}},
		{[]string{"docker", "run", "-p", "8080:80", "nginx"}, []string{"-p 8080:80 nginx"}},
		{[]string{"claude", "-p", "fix the failing test"}, []string{"fix the failing test"}},
		{[]string{"net", "view", `\\fileserver`}, []string{`\\fileserver`}},
		{[]string{"net", "user", "bob", "/delete"}, []string{"net user bob /delete"}},
		{[]string{"net", "use", `\\h\s`, "*", "/user:bob"}, []string{`\\h\s * /user:bob`}},
		{[]string{"mount", "-o", "rw,noatime,vers=3.0", "//h/s", "/mnt"}, []string{"rw,noatime,vers=3.0"}},
		{[]string{"openvpn", "--config", "c.ovpn", "--auth-user-pass", "/etc/openvpn/creds.txt"}, []string{"/etc/openvpn/creds.txt"}},
		{[]string{"sshpass", "-P", "passphrase", "-f", "/run/pw", "ssh", "-p", "2222", "h"}, []string{"ssh -p 2222 h", "/run/pw"}},
		{[]string{"git", "log", "--", "src/main.go"}, []string{"-- src/main.go"}},
	}
	over := 0
	for _, b := range benign {
		out := strings.Join(RedactArgs(b.in), " ")
		for _, k := range b.keep {
			if !strings.Contains(out, k) {
				over++
				t.Errorf("over-redacted %q in %v -> %s", k, b.in, out)
			}
		}
	}
	t.Logf("leak rate %d/%d canaries in %d vectors, over-redaction %d benign keeps lost (+%d keeps lost in secret vectors)",
		leaks, total, len(secret), over, lost)
}
