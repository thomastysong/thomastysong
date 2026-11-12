package privacy

import (
	"strings"
	"testing"
)

// TestSudoStdin: only sudo's own -S / --stdin counts, also when another
// option with a value comes first; the command's own -S does not.
func TestSudoStdin(t *testing.T) {
	for in, want := range map[string]bool{
		"sudo -S ls":             true,
		"sudo --stdin ls":        true,
		"sudo -kS ls":            true,
		"sudo -u bob -S id":      true,
		"sudo --user=bob -S id":  true,
		"sudo --user bob -S id":  true,
		"sudo -s":                false,
		"sudo ls -S":             false,
		"sudo -u S id":           false,
		"sudo -- -S":             false,
		"sudo -pS id":            false, // -p takes the rest as its prompt
		"sudo -E -H -n make all": false,
	} {
		if got := sudoStdin(strings.Fields(in)[1:]); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestFormatSecrets(t *testing.T) {
	isKey := func(k string) bool { return k == "password" || k == "token" }
	for format, want := range map[string]string{
		`user=%s\npassword=%s\n`:            "01",
		`machine %s login %s password %s\n`: "001",
		`token: %s`:                         "1",
		`%s %s\n`:                           "",
		`100%% done, password=%-10s`:        "1",
		`password=%*s`:                      "01", // the width argument comes first
		`no conversions`:                    "",
	} {
		var got strings.Builder
		for _, b := range formatSecrets(format, isKey) {
			got.WriteString(map[bool]string{true: "1", false: "0"}[b])
		}
		if got.String() != want {
			t.Errorf("%q: %q, want %q", format, got.String(), want)
		}
	}
}

func TestPassFlag(t *testing.T) {
	for in, want := range map[string]bool{
		"--db-pass": true, "-storepass": true, "-keypass": true, "--admin-password": true,
		"--passphrase": true, "/password:x": true, "--pass=x": true,
		"--bypass": false, "--bypass-cache": false, "--compass": false, "--no-pass": false,
		"--ask-pass": false, "--askpass": false, "--ask-vault-pass": false, "--password-file": false,
		"--passes": false, "-storepass:env": false, "--password=stdin": false,
		"/etc/nginx/.htpasswd": false, "-p": false, "pass": false,
	} {
		if _, _, got := passFlag(in); got != want {
			t.Errorf("passFlag(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestMoreArgSecrets: the package's own flag table, on argument vectors
// (process args and MCP launch lines reach it without a shell line).
func TestMoreArgSecrets(t *testing.T) {
	cases := []struct {
		argv []string
		gone string
		keep []string
	}{
		{[]string{"sshpass", "-pArgPw1", "ssh", "h"}, "ArgPw1", []string{"sshpass", "ssh", "h"}},
		{[]string{"keytool", "-importkeystore", "-srcstorepass", "ArgPw2", "-deststorepass", "ArgPw2"}, "ArgPw2", []string{"-srcstorepass", "-deststorepass"}},
		{[]string{"sqlcmd", "-S", "db", "-PArgPw3"}, "ArgPw3", []string{"-S", "db"}},
		{[]string{"ssh-keygen", "-p", "-P", "ArgPw4", "-N", "ArgPw5", "-f", "id"}, "ArgPw", []string{"-f", "id"}},
		{[]string{"lftp", "-u", "bob,ArgPw6", "h"}, "ArgPw6", []string{"bob,"}},
		{[]string{"smbclient", "-Ubob%ArgPw7", "//h/s"}, "ArgPw7", []string{"-Ubob%", "//h/s"}},
		{[]string{"rpcclient", "--user=bob%ArgPw8", "h"}, "ArgPw8", []string{"--user=bob%"}},
		{[]string{"SCHTASKS.EXE", "/Create", "/RU", "bob", "/RP", "ArgPw9"}, "ArgPw9", []string{"/RU", "bob"}},
		{[]string{"sqlplus", "-s", "scott/ArgPw10@orcl"}, "ArgPw10", []string{"scott/", "@orcl"}},
		{[]string{"vault", "login", "ArgPw11"}, "ArgPw11", []string{"vault", "login"}},
		{[]string{"tool", "--db-pass", "ArgPw12", "--db-host", "h"}, "ArgPw12", []string{"--db-host", "h"}},
		{[]string{"tool", "--db-pass=ArgPw13"}, "ArgPw13", []string{"--db-pass="}},
		{[]string{"tool", "--db-pass", "$DB_PASS"}, "", []string{"$DB_PASS"}},
		{[]string{"schtasks", "/create", "/ru", "bob", "/rp", "*"}, "", []string{"/rp *"}},
	}
	for _, c := range cases {
		out := strings.Join(redactArgs(c.argv), " ")
		if c.gone != "" && strings.Contains(out, c.gone) {
			t.Errorf("%q: %q survived: %s", c.argv, c.gone, out)
		}
		for _, k := range c.keep {
			if !strings.Contains(out, k) {
				t.Errorf("%q: lost %q: %s", c.argv, k, out)
			}
		}
	}
}

// TestFlattenNested (review P9): classify.RedactArgs nests a database-URL
// marker around the userinfo marker it wrote first.
func TestFlattenNested(t *testing.T) {
	for _, in := range []string{
		"postgres://[REDACTED:database_url_with_password:[REDACTED:password:9d40c010]",
		"x [REDACTED:a:[REDACTED:b:[REDACTED:c:12345678]]] y",
		"[REDACTED:a:hmac=[REDACTED:b:12345678]] tail",
		"[REDACTED:[REDACTED:b:12345678]]",
	} {
		out := flattenNested(in)
		if nestedMarkerRe.MatchString(out) || strings.Count(out, markerOpen) != 1 {
			t.Errorf("%q -> %q", in, out)
		}
		if len(classifyMarkers(out)) != 1 {
			t.Errorf("%q -> %q: not one parseable marker", in, out)
		}
		if strings.HasSuffix(in, " tail") && !strings.HasSuffix(out, " tail") || strings.HasSuffix(in, " y") && !strings.HasSuffix(out, "] y") {
			t.Errorf("%q -> %q: text after the marker lost", in, out)
		}
	}
	for _, in := range []string{"plain", "[REDACTED:a:12345678] and [REDACTED:b:12345678]", "[TRUNCATED:12B]"} {
		if out := flattenNested(in); out != in {
			t.Errorf("%q changed to %q", in, out)
		}
	}
	red := redactArgs([]string{"postgres://app:Sommer2026x@db/x"})
	if len(red) != 1 || nestedMarkerRe.MatchString(red[0]) || strings.Contains(red[0], "Sommer2026x") {
		t.Errorf("redactArgs: %q", red)
	}
}
