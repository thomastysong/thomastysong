package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func emitAll(t *testing.T, e *event.Event) map[string]string {
	t.Helper()
	res := map[string]string{}
	for _, prof := range Profiles {
		for _, key := range [][]byte{nil, testKey} {
			p := &Policy{Profile: prof, Key: key}
			out, _, ok := p.Emit(e)
			if !ok {
				continue
			}
			res[string(prof)+"/"+map[bool]string{true: "key", false: "nokey"}[key != nil]] = line(t, out)
		}
	}
	return res
}

// Review: a command whose secret sits after the lexer's token cap and
// shellx's command cap, in a line too long for the syntax-blind view.
func TestReviewTokenCapLeak(t *testing.T) {
	cmd := strings.Repeat("true\n", 32768) + "mysql -u root -pSommerZQ2026x -h db prod"
	e := shellEvent(cmd)
	for name, l := range emitAll(t, e) {
		if strings.Contains(l, "SommerZQ2026x") {
			t.Errorf("%s: secret leaked past the token cap", name)
		}
	}
}

func TestReviewTokenCapLeakContext(t *testing.T) {
	cmd := strings.Repeat("true\n", 32768) + "mysql -u root -pSommerZQ2026x -h db prod"
	e := shellEvent(cmd)
	det := activity(event.TypeDetectionFinding)
	det.Kind = event.KindDetection
	det.Detection = &event.Detection{RuleID: "R1", Title: "t", Severity: "high"}
	p := &Policy{} // minimal: context is what ships
	for _, c := range p.Context([]*event.Event{e, det}, 5) {
		l := line(t, c)
		if strings.Contains(l, "SommerZQ2026x") {
			i := strings.Index(l, "SommerZQ2026x")
			t.Errorf("minimal context (shipped) leaks the secret: ...%s...", l[max(0, i-80):min(len(l), i+60)])
		}
	}
}

func TestReviewObfuscations(t *testing.T) {
	const pw = "SommerZQ2026x"
	cases := []string{
		"mysql${IFS}-p" + pw + "${IFS}db",
		"{mysql,-p" + pw + ",db}",
		"mysql -p\\\n" + pw + " db",
		"m\\ysql -p" + pw + " db",
		"mysql -p" + pw[:6] + "''" + pw[6:] + " db",
		"mysql --password " + pw + " db",
		"mysql --pass=" + pw + " db",
		"PW=" + pw + " mysql db",
		"sshpass -p" + pw + " ssh host",
		"docker login --password=" + pw + " reg",
		"psql postgresql://app:" + pw + "@db/x",
		"x=-p" + pw + "; mysql $x db",
		"mysql -p$'" + pw + "' db",
		"mysql -p\"$(printf " + pw + ")\" db",
		"curl -u admin:" + pw + " https://h/",
		"curl --user=admin:" + pw + " https://h/",
		"wget --password=" + pw + " https://h/",
		"wget --http-password " + pw + " https://h/",
		"sudo -S <<< " + pw + " ls",
		"echo " + pw + " | sudo -S ls",
		"mongo -u admin -p " + pw + " db",
		"mongosh mongodb://admin:" + pw + "@h/db",
		"ldapsearch -w " + pw + " -D cn=admin",
		"smbclient //h/s -U admin%" + pw,
		"rclone config create r s3 secret_access_key " + pw,
		"vault login " + pw,
		"az login -u a -p " + pw,
		"heroku auth:token " + pw,
		"git -c http.extraheader='Authorization: Basic " + pw + "' clone https://h/r",
		"zip -P " + pw + " a.zip f",
		"unzip -P " + pw + " a.zip",
		"gpg --batch --passphrase " + pw + " -d f",
		"openssl rsa -passin env:X -passout pass:" + pw,
		"mysqldump -u root --password=" + pw + " db",
		"PGPASSWORD=" + pw + " psql",
		"htpasswd -bc f u " + pw,
		"echo -n " + pw + " | base64",
		"export MYSQL_PWD=" + pw,
		"set -- " + pw + "; mysql -p$1",
	}
	for _, c := range cases {
		out, _ := redactCommand(c, "")
		if strings.Contains(out, pw) {
			t.Errorf("leak: %q -> %q", c, out)
		}
	}
}
