package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/hookio"
	"strings"
	"testing"
	"time"

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

func TestReviewPerfManyTokensManyPairs(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 250; i++ {
		b.WriteString("mysql -pS" + rnd(int64(i), 12) + " db;")
	}
	b.WriteString("echo ")
	b.WriteString(strings.Repeat("a ", 60000))
	cmd := b.String()
	start := time.Now()
	e := shellEvent(cmd)
	p := &Policy{Profile: ProfileStandard, Key: testKey}
	out, _, _ := p.Emit(e)
	d := time.Since(start)
	t.Logf("len=%d took %v, cmdlen=%d", len(cmd), d, len(out.Target.Command))
	if d > 2*time.Second {
		t.Errorf("Emit took %v for one %d-byte command", d, len(cmd))
	}
}

func TestReviewPerfEncodedRuns(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 120; i++ {
		b.WriteString("mysql -pS" + rnd(int64(i), 12) + " db;")
	}
	b.WriteString("echo ")
	inner := b64(b64(rnd(99, 36)))
	for b.Len() < 250<<10 {
		b.WriteString(inner)
		b.WriteString(" ")
	}
	cmd := b.String()
	start := time.Now()
	e := shellEvent(cmd)
	p := &Policy{Profile: ProfileStandard, Key: testKey}
	out, _, _ := p.Emit(e)
	d := time.Since(start)
	t.Logf("len=%d took %v, cmdlen=%d", len(cmd), d, len(out.Target.Command))
	if d > 2*time.Second {
		t.Errorf("Emit took %v for one %d-byte command", d, len(cmd))
	}
}

// Review: sudo -S reads the password from stdin; the literal fed to it is
// a credential exactly like a --password-stdin feeder.
func TestReviewSudoStdinLeak(t *testing.T) {
	const pw = "Sommer2026!x"
	for _, c := range []string{
		"echo '" + pw + "' | sudo -S apt-get install -y jq",
		"echo " + pw + " | sudo --stdin systemctl restart nginx",
		"sudo -S <<< '" + pw + "' whoami",
		"printf '%s\\n' " + pw + " | sudo -S -k ls /root",
	} {
		for name, l := range emitAll(t, shellEvent(c)) {
			if strings.Contains(l, pw) {
				t.Errorf("%s: %q leaks the sudo password", name, c)
				break
			}
		}
	}
}

// Review: hookio's normalized failure summary carries an unkeyed SHA-256
// prefix of the tool's error text ("tool error fp:<8 hex>"). It is a
// content-derived digest and must be keyed or removed before it leaves.
func TestReviewUnkeyedErrorFingerprint(t *testing.T) {
	d, ok := hookio.Get("claude")
	if !ok {
		t.Skip("no claude dialect")
	}
	errText := "Error: permission denied for secret store"
	payload := `{"hook_event_name":"PostToolUseFailure","session_id":"s1","cwd":"/home/bob/w","tool_name":"Read","tool_input":{"file_path":"/home/bob/w/a"},"tool_use_id":"tu1","error":"` + errText + `"}`
	evs, _, err := d.Parse([]byte(payload), nil)
	if err != nil || len(evs) == 0 {
		t.Fatalf("parse: %v %d", err, len(evs))
	}
	sum := sha256.Sum256([]byte(errText))
	fp := hex.EncodeToString(sum[:])[:8]
	for _, prof := range Profiles {
		for _, key := range [][]byte{nil, testKey} {
			p := &Policy{Profile: prof, Key: key}
			out, ship, ok := p.Emit(evs[0])
			if !ok {
				continue
			}
			if l := line(t, out); strings.Contains(l, fp) {
				t.Errorf("%s key=%v ship=%v: unkeyed fingerprint of tool error text %s emitted: outcome=%+v", prof, key != nil, ship, fp, out.Outcome)
			}
		}
		// minimal: the context record ships.
		det := activity(event.TypeDetectionFinding)
		det.Kind = event.KindDetection
		det.Session.ID = evs[0].Session.ID
		det.Detection = &event.Detection{RuleID: "R", Title: "t", Severity: "high"}
		for _, c := range (&Policy{}).Context([]*event.Event{evs[0], det}, 3) {
			if strings.Contains(line(t, c), fp) {
				t.Errorf("minimal context: unkeyed fingerprint %s shipped", fp)
			}
		}
	}
}

// Review: evidence that arrives on a detection record for a content field
// is withheld unless it "looks numeric"; a numeric prompt or tool output
// (an OTP, a PIN, a card number) then ships in minimal and standard.
func TestReviewEvidenceNumericContentBypass(t *testing.T) {
	d := activity(event.TypeDetectionFinding)
	d.Kind = event.KindDetection
	d.Detection = &event.Detection{RuleID: "R", Title: "t", Severity: "high",
		Evidence: map[string]string{"tool.output": "4111111111111111", "prompt.text": "829104", "content.file_content": "31415926535"}}
	for _, prof := range []Profile{ProfileMinimal, ProfileStandard} {
		out, _, _ := (&Policy{Profile: prof}).Emit(d)
		for k, v := range out.Detection.Evidence {
			if v != Withheld {
				t.Errorf("%s: content evidence %s=%q shipped (allowlist says never outside full)", prof, k, v)
			}
		}
	}
}

// Review: names in the input's Truncated list bypass the safety pass.
func TestReviewTruncatedBypassesSafetyPass(t *testing.T) {
	tok := "ghp_" + rnd(7, 36)
	e := shellEvent("ls")
	e.Truncated = []string{tok}
	for name, l := range emitAll(t, e) {
		if strings.Contains(l, tok[:30]) {
			t.Errorf("%s: token in input truncated list emitted verbatim", name)
		}
	}
}

func TestReviewProbeValues(t *testing.T) {
	r := &run{p: &Policy{}, s: (&Policy{}).settings(), home: newHomeRewriter("", "linux", nil)}
	for _, v := range []string{
		"https://h/x?token=hunter2pass",
		"https://mcp.example.com/sse?api_key=abc123def",
		"postgres://app:Sommer2026x@db/x",
		"Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l",
		"--password Sommer2026x",
		"password: Sommer2026x",
		"git@github.com:acme/app.git",
		"https://github.com/acme/app.git",
	} {
		t.Logf("value %q -> %q", v, r.valueStr(v, "x", 4096))
		t.Logf("url   %q -> %q", v, r.urlStr(v, "x", false, 4096))
	}
}

func TestReviewProbeNested(t *testing.T) {
	v := "postgres://app:Sommer2026x@db/x"
	t.Logf("classify.RedactArgs: %q", classify.RedactArgs([]string{v}))
	t.Logf("redactArgs: %q", redactArgs([]string{v}))
	for _, k := range [][]byte{nil, testKey} {
		e := shellEvent("ls")
		e.Labels = map[string]string{"db": v}
		e.Repo = &event.Repo{Branch: v}
		e.Check = &event.Check{ID: "c", Status: "fail", Actual: v}
		out, _, _ := (&Policy{Profile: ProfileStandard, Key: k}).Emit(e)
		l := line(t, out)
		t.Logf("key=%v: labels=%q branch=%q actual=%q", k != nil, out.Labels["db"], out.Repo.Branch, out.Check.Actual)
		if nestedMarkerRe.MatchString(l) {
			t.Errorf("key=%v: nested marker emitted", k != nil)
		}
		if unkeyedMarkerRe.MatchString(l) {
			t.Errorf("key=%v: unkeyed marker emitted: %v", k != nil, unkeyedMarkerRe.FindAllString(l, -1))
		}
	}
}

// Review: protected slots are never cut and the skeleton is not re-checked,
// so a record made of long escaped identifiers exceeds MaxLine.
func TestReviewLineCapSkeletonOverBudget(t *testing.T) {
	lt := strings.Repeat("<", 4000)
	e := activity(event.TypeToolPre)
	e.Kind = event.KindDetection
	e.ID, e.Type, e.Writer, e.Dedupe = lt, lt, lt, lt
	e.Source, e.Fidelity, e.Integrity = event.Source(lt), event.Fidelity(lt), event.Integrity(lt)
	e.Session.ID = lt
	e.Host.ID, e.Host.OS, e.Host.Arch = lt, lt, lt
	e.Agent.ID = lt
	e.Detection = &event.Detection{RuleID: lt, Title: lt, Class: lt, Severity: lt}
	for _, ml := range []int{0, MinMaxLine, 4096} {
		p := &Policy{Profile: ProfileStandard, MaxLine: ml}
		out, _, ok := p.Emit(e)
		if !ok {
			t.Fatal("dropped")
		}
		l := line(t, out)
		want := p.settings().maxLine - LineHeadroom
		if len(l) > want {
			t.Errorf("MaxLine=%d: encoded line is %d bytes, over %d (labels %v)", ml, len(l), want, out.Labels)
		}
	}
}

func TestReviewHeredocCredentialFiles(t *testing.T) {
	const pw = "Sommer2026x"
	cases := []string{
		"cat > ~/.netrc <<EOF\nmachine git.internal login bob password " + pw + "\nEOF",
		"cat > ~/.pgpass <<'EOF'\ndb.internal:5432:app:app:" + pw + "\nEOF\nchmod 600 ~/.pgpass",
		"cat > .env <<EOF\nDB_PASSWORD=" + pw + "\nEOF",
		"cat > ~/.aws/credentials <<EOF\n[default]\naws_secret_access_key = " + pw + "\nEOF",
		"cat > config.yaml <<EOF\ndb:\n  password: " + pw + "\nEOF",
		"tee ~/.my.cnf <<EOF\n[client]\npassword=" + pw + "\nEOF",
		"echo 'machine h login u password " + pw + "' >> ~/.netrc",
		"echo 'db:5432:app:app:" + pw + "' > ~/.pgpass",
		"printf 'user=app\\npassword=%s\\n' " + pw + " > db.conf",
	}
	for _, c := range cases {
		for name, l := range emitAll(t, shellEvent(c)) {
			if strings.Contains(l, pw) && strings.HasPrefix(name, "standard") {
				t.Errorf("%s: %q leaks", name, c)
			}
		}
	}
}

func TestReviewProbeCorpus(t *testing.T) {
	const pw = "Sommer2026x"
	cases := []string{
		"echo " + pw + " | passwd --stdin bob",
		"echo 'bob:" + pw + "' | chpasswd",
		"echo " + pw + " | docker login -u ci --password-stdin",
		"cat <<< " + pw + " | docker login --password-stdin",
		"echo -n " + pw + " | gh secret set DB_PASS",
		"echo " + pw + " | gpg --batch --passphrase-fd 0 -d f.gpg",
		"echo '" + pw + "' | kinit bob@CORP",
		"echo " + pw + " | openssl enc -pass stdin -in f",
		"echo " + pw + " | vault login -",
		"echo " + pw + " | npx wrangler secret put API_KEY",
		"echo " + pw + " | az acr login -n r --password-stdin",
		"printf '%s' '" + pw + "' | podman login --password-stdin quay.io",
		"yes " + pw + " | passwd",
		"(echo " + pw + "; echo " + pw + ") | passwd",
		"echo -e '" + pw + "\\n" + pw + "' | passwd bob",
		"mysql -uroot -p'" + pw + "' -e 'select 1'",
		"mysql --user=root --password='" + pw + "' db",
		"MYSQL_PWD=" + pw + " mysql -uroot",
		"PGPASSWORD='" + pw + "' pg_dump -h db app > d.sql",
		"redis-cli -h r -a '" + pw + "' --no-auth-warning ping",
		"curl -s -u \"admin:" + pw + "\" https://h/api",
		"curl -s -H 'X-Auth-Token: " + pw + "' https://h/api",
		"curl -s --data 'username=a&password=" + pw + "' https://h/login",
		"curl -s -d '{\"password\":\"" + pw + "\"}' https://h/login",
		"http POST h/login password=" + pw,
		"wget --user=a --password='" + pw + "' https://h/f",
		"ssh-keygen -t ed25519 -N '" + pw + "' -f k",
		"openssl req -x509 -passout pass:" + pw + " -keyout k",
		"keytool -genkey -storepass " + pw + " -keypass " + pw,
		"jarsigner -storepass " + pw + " a.jar alias",
		"pip install --index-url https://u:" + pw + "@pypi.internal/simple x",
		"npm config set //registry.npmjs.org/:_authToken " + pw,
		"git config --global credential.helper 'store' && echo 'https://bob:" + pw + "@github.com' > ~/.git-credentials",
		"kubectl create secret generic s --from-literal=password=" + pw,
		"docker run -e POSTGRES_PASSWORD=" + pw + " postgres",
		"docker run --env DB_PASS=" + pw + " app",
		"helm install x c --set auth.password=" + pw,
		"terraform apply -var 'db_password=" + pw + "'",
		"ansible-playbook p.yml -e 'ansible_become_pass=" + pw + "'",
		"az login --service-principal -u id -p " + pw + " --tenant t",
		"gcloud auth activate-service-account --key-file=k.json",
		"sqlcmd -S h -U sa -P " + pw,
		"psql \"host=db user=app password=" + pw + "\"",
		"mongodump --uri mongodb://u:" + pw + "@h/db",
		"rsync -e 'sshpass -p " + pw + " ssh' a h:b",
		"lftp -u bob," + pw + " sftp://h",
		"ftp -n h <<EOF\nuser bob " + pw + "\nEOF",
		"smbclient -U 'bob%" + pw + "' //h/s",
		"mount -t cifs //h/s /mnt -o username=bob,password=" + pw,
		"$cred = New-Object PSCredential('bob', (ConvertTo-SecureString '" + pw + "' -AsPlainText -Force))",
		"$password = '" + pw + "'",
		"Set-Item env:API_KEY '" + pw + "'",
		"[Environment]::SetEnvironmentVariable('API_TOKEN','" + pw + "','User')",
		"setx API_TOKEN " + pw,
		"runas /user:admin cmd",
		"cmdkey /add:h /user:bob /pass:" + pw,
		"net use \\\\h\\s " + pw + " /user:bob",
		"schtasks /create /tn t /tr x /ru bob /rp " + pw,
		"sshpass -p" + pw + " ssh h",
		"export AWS_SECRET_ACCESS_KEY=" + pw,
		"export DATABASE_URL=postgres://u:" + pw + "@h/db",
	}
	n := 0
	for _, c := range cases {
		out, _ := redactCommand(c, "")
		if strings.Contains(out, pw) {
			n++
			t.Logf("leak: %q -> %q", c, out)
		}
	}
	t.Logf("%d of %d leak", n, len(cases))
}
