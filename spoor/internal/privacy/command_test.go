package privacy

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/shellx"
)

func TestRedactCommandStructural(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		gone   []string // must not appear
		keep   []string // must appear
		dialet shellx.Dialect
	}{
		{name: "mysql quoted attached", in: `mysql -u root -p'Berlin#1989' -h db prod`, gone: []string{"Berlin#1989"}, keep: []string{"mysql -u root -p", "-h db prod"}},
		{name: "mysql escaped in double quotes", in: `mysql -p"Pa\$\$word" db`, gone: []string{"Pa$$word", `Pa\$\$word`}, keep: []string{"db"}},
		{name: "prefix assignment", in: `API_TOKEN=xyzzy123 ./run.sh --verbose`, gone: []string{"xyzzy123"}, keep: []string{"API_TOKEN=", "./run.sh --verbose"}},
		{name: "bash -c nested", in: `bash -c "mysql -pS3cretPw && echo ok"`, gone: []string{"S3cretPw"}, keep: []string{`bash -c "mysql -p`, "&& echo ok"}},
		{name: "bash -c short secret", in: `bash -c 'sshpass -p X ssh deploy@10.0.0.5'`, gone: []string{" -p X "}, keep: []string{"deploy@10.0.0.5"}},
		{name: "nested twice", in: `sh -c "bash -c 'mysql -pDeepPw42'"`, gone: []string{"DeepPw42"}},
		{name: "curl user pass", in: `curl -u alice:Winter2026 https://api.internal/v1/users | jq .`, gone: []string{"Winter2026"}, keep: []string{"alice:", "https://api.internal/v1/users", "| jq ."}},
		{name: "curl proxy-user", in: `curl --proxy-user bob:ProxyPw9 https://x.example`, gone: []string{"ProxyPw9"}, keep: []string{"--proxy-user bob:"}},
		{name: "openssl passin passout", in: `openssl pkcs12 -passin pass:Pkcs12Pw -passout pass:OutPw77 -in a.p12`, gone: []string{"Pkcs12Pw", "OutPw77"}, keep: []string{"-passin pass:", "-in a.p12"}},
		{name: "openssl env ref kept", in: `openssl pkcs12 -passin env:P12PASS -in a.p12`, keep: []string{"env:P12PASS"}},
		{name: "kubectl nested after --", in: `kubectl exec -it pod -- mysql -pS3cr3tK`, gone: []string{"S3cr3tK"}, keep: []string{"kubectl exec -it pod -- mysql -p"}},
		{name: "aws configure set", in: `aws configure set aws_secret_access_key Wjalr123XUtnFEMI`, gone: []string{"Wjalr123XUtnFEMI"}, keep: []string{"aws configure set aws_secret_access_key"}},
		{name: "password-stdin echo", in: `echo 'Tr0ub4dor' | docker login -u ci --password-stdin reg.io`, gone: []string{"Tr0ub4dor"}, keep: []string{"docker login -u ci --password-stdin reg.io"}},
		{name: "password-stdin printf filter", in: `printf '%s' "Tr0ub4dor" | tr -d '\n' | docker login --password-stdin`, gone: []string{"Tr0ub4dor"}, keep: []string{"printf '%s'", "tr -d"}},
		{name: "password-stdin herestring", in: `docker login -u ci --password-stdin <<< 'Tr0ub4dor'`, gone: []string{"Tr0ub4dor"}, keep: []string{"<<<"}},
		{name: "password-stdin heredoc", in: "cat <<EOF | docker login --password-stdin\nMyHeredocPw\nEOF\necho done", gone: []string{"MyHeredocPw"}, keep: []string{"<<EOF", "\nEOF\necho done"}},
		{name: "password-stdin variable kept", in: `echo "$REG_PW" | docker login --password-stdin`, keep: []string{"$REG_PW"}},
		{name: "gh with-token", in: `echo ghtok123secret | gh auth login --with-token`, gone: []string{"ghtok123secret"}},
		{name: "chpasswd", in: `echo 'bob:NewPw2026' | chpasswd`, gone: []string{"NewPw2026"}},
		{name: "base64 decoded payload", in: `echo ` + b64("mysql -pB64Secret9 db") + ` | base64 -d | sh`, gone: []string{"B64Secret9", b64("mysql -pB64Secret9 db")}, keep: []string{"| base64 -d | sh"}},
		{name: "eval", in: `eval "mysql -pEvalPw77"`, gone: []string{"EvalPw77"}, keep: []string{"eval"}},
		{name: "substitution", in: `echo $(mysql -pSubstPw88 -e 'select 1')`, gone: []string{"SubstPw88"}, keep: []string{"echo $(mysql -p", "-e 'select 1')"}},
		{name: "backticks", in: "echo `mysql -pTickPw99 -e 'select 1'`", gone: []string{"TickPw99"}},
		{name: "git clone userinfo", in: `git clone https://bob:CloneTok55@github.com/acme/app.git`, gone: []string{"CloneTok55"}, keep: []string{"github.com/acme/app.git"}},
		{name: "header bearer", in: `curl -H "Authorization: Bearer abcXYZ987tokenvalue" https://h`, gone: []string{"abcXYZ987tokenvalue"}, keep: []string{"Authorization: Bearer"}},
		{name: "env reference kept", in: `curl -H "Authorization: Bearer $TOKEN" https://h`, keep: []string{"$TOKEN"}},
		{name: "python inline header", in: `python3 -c "import requests; requests.get('https://x', headers={'Authorization':'Bearer abc123def456'})"`, gone: []string{"abc123def456"}},
		{name: "powershell env", in: `$env:API_KEY="abcPw1"; Invoke-WebRequest -Uri https://x`, gone: []string{"abcPw1"}, keep: []string{"$env:API_KEY=", "Invoke-WebRequest"}},
		{name: "powershell assignment", in: `$password = 'P@ss-w0rd'; Connect-Thing -Credential $c`, gone: []string{"P@ss-w0rd"}, keep: []string{"$password =", "Connect-Thing"}},
		// classify's pattern pass reads "password = Read-Host" as an
		// assignment and redacts the cmdlet name: over-redaction, kept as a
		// known classify behaviour.
		{name: "powershell cmdlet value", in: `$password = Read-Host -AsSecureString`, keep: []string{"$password =", "-AsSecureString"}},
		{name: "securestring", in: `$sec = ConvertTo-SecureString "Hunter2x" -AsPlainText -Force`, gone: []string{"Hunter2x"}, keep: []string{"ConvertTo-SecureString", "-AsPlainText"}},
		{name: "powershell hashtable header", in: `Invoke-WebRequest -Uri https://x -Headers @{Authorization="Bearer zzQQ99ww"}`, gone: []string{"zzQQ99ww"}},
		{name: "cmd set and flag", in: `cmd /c "set PASSWORD=abcpw && run.exe /password:hunter22"`, gone: []string{"abcpw", "hunter22"}, keep: []string{"cmd /c", "run.exe"}},
		{name: "net user", in: `net user bob Sup3rS3cret /add`, gone: []string{"Sup3rS3cret"}, keep: []string{"net user bob", "/add"}},
		{name: "net user prompt", in: `net user bob * /add`, keep: []string{"net user bob * /add"}},
		{name: "setx", in: `setx API_TOKEN tok999value`, gone: []string{"tok999value"}, keep: []string{"setx API_TOKEN"}},
		{name: "htpasswd batch", in: `htpasswd -bc /etc/nginx/.htpasswd admin HtPw4321`, gone: []string{"HtPw4321"}, keep: []string{"/etc/nginx/.htpasswd admin"}},
		{name: "reversed", in: `echo 'WPTERCESp- lqsym' | rev | sh`, gone: []string{}},
		{name: "hex escapes", in: `printf '\x6d\x79\x73\x71\x6c\x20\x2d\x70\x48\x65\x78\x50\x77\x31\x32' | sh`, gone: []string{}},
		{name: "benign", in: `git commit -m "fix the password check" && ls -la /tmp`, keep: []string{`git commit -m "fix the password check" && ls -la /tmp`}},
		{name: "benign pipeline", in: `curl -fsSL https://get.example.sh | bash -s -- --yes`, keep: []string{`curl -fsSL https://get.example.sh | bash -s -- --yes`}},
		{name: "redirects", in: `make build > /tmp/build.log 2>&1 < /dev/null`, keep: []string{`make build > /tmp/build.log 2>&1 < /dev/null`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _ := redactCommand(c.in, c.dialet)
			for _, g := range c.gone {
				if g != "" && strings.Contains(out, g) {
					t.Errorf("secret %q survived:\n in: %s\nout: %s", g, c.in, out)
				}
			}
			for _, k := range c.keep {
				if !strings.Contains(out, k) {
					t.Errorf("lost %q:\n in: %s\nout: %s", k, c.in, out)
				}
			}
			// Idempotent: redacting the output again changes nothing.
			if again, _ := redactCommand(out, c.dialet); again != out {
				t.Errorf("not idempotent:\n1: %s\n2: %s", out, again)
			}
		})
	}
}

// TestRedactCommandDecodedSecretOnlyEncoded: a credential that only
// exists inside a decoded payload must be removed in its encoded form.
func TestRedactCommandDecodedSecretOnlyEncoded(t *testing.T) {
	payload := "mysql -pOnlyInPayload1 db"
	for _, in := range []string{
		"echo " + b64(payload) + " | base64 -d | bash",
		"echo " + b64(payload) + " | base64 --decode | sh",
		"bash -c \"$(echo " + b64(payload) + " | base64 -d)\"",
		"pwsh -EncodedCommand " + b64utf16(`$env:API_KEY="OnlyInPayload2"; x`),
	} {
		out, _ := redactCommand(in, "")
		if strings.Contains(out, "OnlyInPayload") || strings.Contains(out, b64(payload)) {
			t.Errorf("encoded secret survived:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestRedactCommandUnresolvedSkeleton: when a structurally found secret
// cannot be located, the command collapses to program and flag names.
func TestRedactCommandUnresolvedSkeleton(t *testing.T) {
	r := newCmdRedactor("tool --flag value", shellx.Posix)
	r.topLevel()
	r.addPair(&pair{oldVal: "-pQ", newVal: "-p" + newMarker("password", "Q"), secrets: []secret{{value: "Q", marker: newMarker("password", "Q")}}})
	r.applyPairs()
	if !r.unresolved() {
		t.Fatal("pair with a short secret that was never placed must be unresolved")
	}
	sk := r.skeleton()
	if !strings.Contains(sk, "tool --flag") || strings.Contains(sk, "value") || !strings.Contains(sk, kindUnresolved) {
		t.Errorf("skeleton = %q", sk)
	}
}

func TestRedactCommandHostile(t *testing.T) {
	huge := strings.Repeat("a", maxCommandScan+1000) + " -pX"
	deep := strings.Repeat("$(", 5000) + "x" + strings.Repeat(")", 5000)
	cases := map[string]string{
		"huge":          huge,
		"huge with pw":  "mysql -pHugePw1 " + strings.Repeat("arg ", 100000),
		"deep":          deep,
		"deep quotes":   strings.Repeat(`"'`, 20000),
		"invalid utf8":  "mysql -p\xff\xfeBadUtf8Pw db \xc3\x28",
		"nul bytes":     "mysql\x00 -pNulPw1\x00 db",
		"unterminated":  `echo "abc 'def $(ghi`,
		"only ops":      strings.Repeat("|&;", 30000),
		"heredoc storm": strings.Repeat("cat <<E\n", 2000),
		"many pairs":    strings.Repeat("mysql -pP1 && ", 2000),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			out, pre := redactCommand(in, "")
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %v", d)
			}
			if name == "huge" && !pre {
				t.Error("input over the scan cap must report precapped")
			}
			for _, s := range []string{"HugePw1", "NulPw1", "BadUtf8Pw"} {
				if strings.Contains(out, s) {
					t.Errorf("%s leaked", s)
				}
			}
			_ = utf8.ValidString(out) // invalid input may stay invalid here; Emit cleans it
		})
	}
}

func TestLexSegments(t *testing.T) {
	toks := lex("A=1 cmd -x 'a b' 2>/dev/null | tee out.txt; echo $(x y) <<< here", shellx.Posix)
	segs := segments(toks)
	if len(segs) != 3 {
		t.Fatalf("segments = %d, want 3", len(segs))
	}
	var words []string
	for _, w := range segs[0].words {
		words = append(words, toks[w].val)
	}
	if got := strings.Join(words, "|"); got != "A=1|cmd|-x|a b" {
		t.Errorf("segment 0 words = %q", got)
	}
	if segs[1].pipeFrom != 0 {
		t.Errorf("segment 1 pipeFrom = %d", segs[1].pipeFrom)
	}
	if len(segs[2].herestr) != 1 || toks[segs[2].herestr[0]].val != "here" {
		t.Errorf("here-string not recorded: %+v", segs[2])
	}
	if toks[segs[2].words[1]].val != "$(x y)" {
		t.Errorf("substitution split: %q", toks[segs[2].words[1]].val)
	}
}

func TestRequoteRoundTrip(t *testing.T) {
	for _, d := range []shellx.Dialect{shellx.Posix, shellx.PowerShell, shellx.Cmd} {
		for _, v := range []string{"plain", "with space", `it's`, `say "hi"`, "$HOME", "[REDACTED:password]", "back`tick"} {
			for _, style := range []byte{0, '\'', '"'} {
				q := requote(v, d, style)
				toks := lex(q, d)
				if d == shellx.Cmd && strings.ContainsAny(v, `"`) {
					continue // cmd has no reliable quote escape
				}
				if len(toks) != 1 || toks[0].val != v {
					t.Errorf("%s style %q: %q -> %q -> %+v", d, style, v, q, toks)
				}
			}
		}
	}
}

func TestAlignSecrets(t *testing.T) {
	old := "-pS3cret"
	red := "-p" + newMarker("password", "S3cret")
	got := alignSecrets(old, red)
	if len(got) != 1 || got[0].value != "S3cret" {
		t.Fatalf("got %+v", got)
	}
	old = "a=SECRET1&b=x&c=SECRET2"
	red = "a=" + newMarker("password", "SECRET1") + "&b=x&c=" + newMarker("password", "SECRET2")
	got = alignSecrets(old, red)
	if len(got) != 2 || got[0].value != "SECRET1" || got[1].value != "SECRET2" {
		t.Fatalf("got %+v", got)
	}
}

// TestRedactCommandManySecretsBounded: a line with thousands of distinct
// credentials (an agent can write one) must not cost seconds per event
// (it took 5.5 s before the search budget), must not leak, and a line
// with a realistic number of secrets must keep its full structure.
func TestRedactCommandManySecretsBounded(t *testing.T) {
	gen := func(format string, size int) string {
		var b strings.Builder
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, format, i, i)
		}
		return b.String()
	}
	cases := map[string]string{
		"mysql":  gen("mysql -pManyPw%06d db%d; ", 250<<10),
		"export": gen("export A_TOKEN_%d=ManyPw%08d; ", 250<<10),
		"bearer": gen("curl -H 'Authorization: Bearer ManyPw%010dabcdefghij' https://h%d.x ", 250<<10),
	}
	for name, in := range cases {
		start := time.Now()
		out, _ := redactCommand(in, "")
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
		if strings.Contains(out, "ManyPw") {
			t.Errorf("%s: leaked", name)
		}
		// Either the fail-closed skeleton (bounded) or, when the line was
		// cut where a structural view stopped (the bearer line is one
		// command with thousands of arguments, more than shellx records),
		// a fully redacted head of at most the scan cap.
		skel := strings.Contains(out, kindUnresolved) || out == markerOpen+kindCommand+"]"
		if skel && len(out) > maxSkeleton+256 {
			t.Errorf("%s: skeleton is %d bytes", name, len(out))
		}
		if !skel && (!strings.Contains(out, truncOpen) || len(out) > 2*maxCommandScan) {
			t.Errorf("%s: %d bytes, neither a skeleton nor a cut head", name, len(out))
		}
	}
	moderate := gen("curl -H 'Authorization: Bearer ManyPw%010dabcdefghij' https://h%d.x ; ", 4<<10)
	out, _ := redactCommand(moderate, "")
	if strings.Contains(out, "ManyPw") || strings.Contains(out, kindUnresolved) || !strings.Contains(out, "https://h3.x") {
		t.Errorf("moderate line lost structure or leaked:\n%.400s", out)
	}
}
