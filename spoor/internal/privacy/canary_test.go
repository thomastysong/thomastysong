package privacy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// canary is one synthetic credential planted in one surface. Every canary
// value contains "Canary" and nothing else in the corpus does, so a leak
// check is a substring search for "Canary" in everything written.
type canary struct {
	name  string
	build func() *event.Event
}

func canaryCorpus() []canary {
	var cs []canary
	cmd := func(name, c string) {
		cs = append(cs, canary{name: "command/" + name, build: func() *event.Event { return shellEvent(c) }})
	}
	tok := func(seed int64) string { return "Canary" + rnd(seed, 26) }

	// Commands: the privacy red team's structural cases plus the C
	// addendum table (proxy-user, -passin/-passout, nested after --,
	// aws configure set, --password-stdin literals).
	cmd("mysql-attached", "mysql -u root -pCanaryPw01 -h db.internal prod")
	cmd("curl-userpass", "curl -u alice:CanaryPw02 https://api.internal/v1/users")
	cmd("sshpass", "sshpass -p 'CanaryPw03' ssh deploy@10.0.0.5")
	cmd("docker-login-p", "docker login -u ci -p CanaryPw04 registry.internal")
	cmd("redis-a", "redis-cli -a CanaryPw05 ping")
	cmd("7z", "7z a -pCanaryPw06 backup.7z ~/Documents")
	cmd("openssl-k", "openssl enc -aes-256-cbc -k CanaryPw07 -in a -out b")
	cmd("curl-proxy-user", "curl --proxy-user bob:CanaryPw08 https://x.internal")
	cmd("openssl-passin-passout", "openssl pkcs12 -passin pass:CanaryPw09 -in a.p12 -passout pass:CanaryPw10")
	cmd("kubectl-nested", "kubectl exec -it pod -- mysql -pCanaryPw11")
	cmd("aws-configure-set", "aws configure set aws_secret_access_key CanaryPw12")
	cmd("password-stdin-echo", "echo 'CanaryPw13' | docker login -u ci --password-stdin reg.io")
	cmd("password-stdin-herestring", `docker login --password-stdin <<< "CanaryPw14"`)
	cmd("bash-c-assignment", `bash -c "PGPASSWORD=CanaryPw15 psql -h db -U app"`)
	cmd("export", "export API_TOKEN=CanaryPw16 && ./deploy.sh")
	cmd("bearer-header", `curl -H "Authorization: Bearer `+tok(17)+`" https://api.internal/x`)
	cmd("git-clone-userinfo", "git clone https://bob:CanaryPw18@github.com/acme/app.git")
	cmd("base64-decoded", "echo "+b64("mysql -pCanaryPw19 db")+" | base64 -d | sh")
	cmd("powershell-env", `$env:OPENAI_API_KEY="CanaryPw20"; python app.py`)
	cmd("cmd-set-and-flag", `cmd /c "set DB_PASSWORD=CanaryPw21 && run.exe /password:CanaryPw22"`)
	cmd("net-user", "net user svc CanaryPw23 /add")
	cmd("eval", `eval "mysql -pCanaryPw24 prod"`)
	cmd("gh-with-token", "printf '%s' CanaryPw25 | gh auth login --with-token")
	cmd("heredoc-stdin", "cat <<EOF | docker login --password-stdin reg.io\nCanaryPw26\nEOF")
	cmd("substitution", "echo $(mysql -pCanaryPw27 -e 'select 1')")
	cmd("ps-securestring", `$p = ConvertTo-SecureString "CanaryPw28" -AsPlainText -Force`)

	// Review P2: literals fed on stdin to consumers that read a password
	// there without a --password-stdin style flag.
	cmd("sudo-S-pipe", "echo 'CanarySu01!x' | sudo -S apt-get install -y jq")
	cmd("sudo-stdin-long", "echo CanarySu02 | sudo --stdin systemctl restart nginx")
	cmd("sudo-S-herestring", "sudo -S <<< 'CanarySu03' whoami")
	cmd("sudo-u-then-S", "printf '%s\\n' CanarySu04 | sudo -u root -S -k ls /root")
	cmd("passwd-no-stdin-flag", "echo -e 'CanarySu05\\nCanarySu05' | passwd bob")
	cmd("kinit", "echo 'CanarySu06' | kinit bob@CORP.EXAMPLE")
	cmd("openssl-pass-stdin", "echo CanarySu07 | openssl enc -d -pass stdin -in f.enc")
	cmd("vault-login-stdin", "echo CanarySu08 | vault login -")
	cmd("yes-feeder", "yes CanarySu09 | passwd bob")
	cmd("htpasswd-i", "echo CanarySu10 | htpasswd -Bi /etc/nginx/.htpasswd admin")

	// Review P4: flags and PowerShell setters classify's tables miss.
	cmd("sshpass-attached", "sshpass -pCanaryFl01 ssh deploy@h")
	cmd("keytool", "keytool -genkeypair -storepass CanaryFl02 -keypass CanaryFl03 -alias a")
	cmd("jarsigner", "jarsigner -storepass CanaryFl04 app.jar alias")
	cmd("sqlcmd", "sqlcmd -S db -U sa -P CanaryFl05 -Q 'select 1'")
	cmd("ssh-keygen-N", "ssh-keygen -t ed25519 -N 'CanaryFl06' -f id")
	cmd("lftp-u", "lftp -u bob,CanaryFl07 sftp://h")
	cmd("smbclient-U", "smbclient -U 'bob%CanaryFl08' //h/share")
	cmd("schtasks-rp", "schtasks /create /tn t /tr x.exe /ru bob /rp CanaryFl09")
	cmd("ps-set-item-env", "Set-Item env:API_KEY 'CanaryFl10'")
	cmd("ps-setenvironmentvariable", "[Environment]::SetEnvironmentVariable('API_TOKEN','CanaryFl11','User')")
	cmd("ps-setenvironmentvariable-spaced", "[Environment]::SetEnvironmentVariable('API_TOKEN', 'CanaryFl12', 'Machine')")
	cmd("sqlplus", "sqlplus scott/CanaryFl13@orcl @script.sql")
	cmd("psexec-p", `psexec \\h -u bob -p CanaryFl14 cmd`)
	cmd("generic-pass-flag", "deploytool --admin-pass CanaryFl15 --target prod")
	cmd("rar-p", "rar a -pCanaryFl16 backup.rar docs")
	cmd("vault-login-token", "vault login CanaryFl17")

	// Review P5: credentials written into credential files by the shell.
	cmd("heredoc-netrc", "cat > ~/.netrc <<EOF\nmachine git.internal login bob password CanaryWr01\nEOF")
	cmd("heredoc-pgpass", "cat > ~/.pgpass <<'EOF'\ndb.internal:5432:app:app:CanaryWr02\nEOF\nchmod 600 ~/.pgpass")
	cmd("echo-append-netrc", "echo 'machine h login u password CanaryWr03' >> ~/.netrc")
	cmd("echo-pgpass", "echo 'db:5432:app:app:CanaryWr04' > ~/.pgpass")
	cmd("printf-format-key", "printf 'user=app\\npassword=%s\\n' CanaryWr05 > db.conf")
	cmd("printf-netrc-format", "printf 'machine %s login %s password %s\\n' h bob CanaryWr06")
	cmd("tee-credentials", "echo 'aws_secret_access_key = CanaryWr07' | sudo tee -a ~/.aws/credentials")
	cmd("heredoc-dotenv", "cat <<EOF > .env\nDB_URL=db.internal\nSESSION=CanaryWr08\nEOF")
	cmd("ps-set-content-netrc", "Set-Content -Path ~/.netrc -Value 'machine h login u password CanaryWr09'")
	cmd("ps-out-file", "'CanaryWr10' | Out-File ~/.git-credentials")

	// Process arguments.
	proc := func(name string, args ...string) {
		cs = append(cs, canary{name: "process/" + name, build: func() *event.Event {
			e := activity(event.TypeProcessExec)
			e.Source = event.SourceProcess
			e.Process = &event.Process{PID: 4242, PPID: 1, Name: args[0], Exe: "/usr/bin/" + args[0], Args: args, User: "bob"}
			return e
		}})
	}
	proc("mysql", "mysql", "-pCanaryPA29", "db")
	proc("header", "curl", "-H", "X-Api-Key: CanaryPA30", "https://x.internal")
	proc("bash-c", "bash", "-c", "mysql -pCanaryPA31 db")
	proc("flag-eq", "node", "server.js", "--api-key=CanaryPA32")
	proc("env-assign", "env", "DB_PASSWORD=CanaryPA33", "app")
	proc("pwsh-encoded", "pwsh", "-EncodedCommand", b64utf16(`$env:API_KEY="CanaryPA34"; Invoke-Thing`))

	// URLs.
	url := func(name, u string, kind event.ToolKind) {
		cs = append(cs, canary{name: "url/" + name, build: func() *event.Event {
			e := activity(event.TypeToolPre)
			e.Tool = &event.Tool{Name: "WebFetch", Kind: kind}
			e.Target = &event.Target{URL: u, Host: "internal.host"}
			return e
		}})
	}
	url("userinfo", "https://bob:CanaryU35@internal.host/p", event.ToolWebFetch)
	url("query-token", "https://api.internal/v1?token=CanaryU36&q=1", event.ToolWebFetch)
	url("slack-webhook", "https://hooks.slack.com/services/T0CANRY01/B0CANRY01/Canary"+rnd(37, 20), event.ToolWebFetch)
	cs = append(cs, canary{name: "url/repo-remote", build: func() *event.Event {
		e := shellEvent("git push")
		e.Repo = &event.Repo{Root: "/home/bob/work/acme", Remote: "https://x-access-token:CanaryU38@github.com/acme/app.git", Branch: "main"}
		return e
	}})

	// Tool inputs (shipped redacted in full only).
	input := func(name string, kind event.ToolKind, in map[string]any) {
		cs = append(cs, canary{name: "tool_input/" + name, build: func() *event.Event {
			e := activity(event.TypeToolPre)
			e.Tool = &event.Tool{Name: "T", Kind: kind}
			e.Content = &event.Content{ToolInput: in}
			e.Tool.Input = in
			return e
		}})
	}
	input("bash-command", event.ToolShell, map[string]any{"command": "mysql -pCanaryTI39 db", "description": "connect"})
	input("url", event.ToolWebFetch, map[string]any{"url": "https://u:CanaryTI40@x.internal/a"})
	input("headers", event.ToolMCP, map[string]any{"headers": map[string]any{"Authorization": "Bearer " + tok(41)}})
	input("env", event.ToolMCP, map[string]any{"env": map[string]any{"API_KEY": "CanaryTI42"}})
	input("args", event.ToolMCP, map[string]any{"args": []any{"--password", "CanaryTI43"}})
	input("content-assignment", event.ToolFileWrite, map[string]any{"file_path": "/home/bob/.env", "content": "AWS_SECRET_ACCESS_KEY=" + tok(44) + "\n"})
	input("key-is-token", event.ToolMCP, map[string]any{"ghp_Canary" + rnd(45, 30): 1.0})
	input("codex-argv", event.ToolShell, map[string]any{"command": []any{"bash", "-lc", "redis-cli -a CanaryTI46 ping"}})

	// Prompts (shipped redacted in full only).
	prompt := func(name, text string) {
		cs = append(cs, canary{name: "prompt/" + name, build: func() *event.Event {
			e := activity(event.TypePromptSubmit)
			e.Prompt = &event.Prompt{Len: len(text), SHA256: sha256Hex(text)}
			e.Content = &event.Content{PromptText: text}
			return e
		}})
	}
	prompt("assignment", "deploy it with password=CanaryPr47 please")
	prompt("anthropic-key", "use this key sk-ant-api03-Canary"+rnd(48, 60)+" for the call")
	prompt("github-pat", "the token is ghp_Canary"+rnd(49, 30))
	prompt("dsn", "connect to postgres://admin:CanaryPr50@db.internal/prod")
	prompt("bearer", "header was Authorization: Bearer "+tok(51))

	// MCP configuration (inventory) and posture.
	mcp := func(name string, m *event.MCP, detail map[string]string) {
		cs = append(cs, canary{name: "mcp/" + name, build: func() *event.Event {
			e := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
			e.Host = &event.Host{ID: "host-1", OS: "linux"}
			e.Asset = &event.Asset{ID: "a1", Kind: event.AssetMCPServer, Name: "acme", Parent: "cursor",
				Path: "/home/bob/.cursor/mcp.json", Scope: event.ScopeUser, Owner: "bob", MCP: m, Detail: detail,
				SHA256: sha256Hex("definition with CanaryHashInput")}
			return e
		}})
	}
	mcp("args-flag", &event.MCP{Transport: "stdio", Command: "npx", Args: []string{"-y", "@acme/mcp", "--api-key", "CanaryM52"}}, nil)
	mcp("args-header", &event.MCP{Transport: "stdio", Command: "npx", Args: []string{"--header", "Authorization: Bearer " + tok(53)}}, nil)
	mcp("detail-env", &event.MCP{Transport: "stdio", Command: "/home/bob/bin/srv"}, map[string]string{"env": "GITHUB_TOKEN=CanaryM54"})
	mcp("bash-c", &event.MCP{Transport: "stdio", Command: "bash", Args: []string{"-c", "API_KEY=CanaryM55 npx -y @acme/mcp"}}, nil)
	mcp("url-path", &event.MCP{Transport: "http", URLHost: "hooks.slack.com", URLPath: "/services/T0CANRY02/B0CANRY02/Canary" + rnd(56, 20)}, nil)
	cs = append(cs, canary{name: "posture/actual", build: func() *event.Event {
		e := event.New(event.KindPosture, event.TypePostureCheck, event.SourceScan)
		e.Check = &event.Check{ID: "SPR-POS-001", Status: "fail", Subject: "/home/bob/.claude/settings.json", Actual: "env.ANTHROPIC_API_KEY=CanaryC57", Owner: "bob"}
		return e
	}})

	// classify's RedactArgs corpus (internal/classify/redact_canary_test.go),
	// pushed through every surface an argument vector can reach: a shell
	// line, process arguments, a Codex-style argv tool input and an MCP
	// launch line.
	for i, argv := range classifyArgvCorpus {
		argv := argv
		id := fmt.Sprintf("classify-%02d", i+1)
		cmd(id, shellJoin(argv))
		proc(id, argv...)
		input("argv/"+id, event.ToolShell, map[string]any{"command": toAny(argv)})
		mcp("argv/"+id, &event.MCP{Transport: "stdio", Command: argv[0], Args: argv[1:]}, nil)
	}

	// Credentials in identifiers and paths (pattern pass).
	cs = append(cs,
		canary{name: "path/token-in-path", build: func() *event.Event {
			e := activity(event.TypeToolPre)
			e.Tool = &event.Tool{Name: "Read", Kind: event.ToolFileRead}
			e.Target = &event.Target{Path: "/home/bob/dl/ghp_Canary" + rnd(66, 30) + ".txt"}
			return e
		}},
		canary{name: "labels/key", build: func() *event.Event {
			e := shellEvent("ls")
			e.Labels = map[string]string{"ghp_Canary" + rnd(67, 30): "x"}
			return e
		}},
		canary{name: "repo/branch", build: func() *event.Event {
			e := shellEvent("git status")
			e.Repo = &event.Repo{Root: "/home/bob/r", Remote: "git@github.com:acme/app.git", Branch: "token=CanaryB68"}
			return e
		}},
	)

	// Free-text fields on other records.
	cs = append(cs,
		canary{name: "outcome/error", build: func() *event.Event {
			e := shellEvent("psql")
			e.Outcome = &event.Outcome{Status: "error", Error: "auth failed for password=CanaryE58"}
			return e
		}},
		canary{name: "labels/value", build: func() *event.Event {
			e := shellEvent("ls")
			e.Labels = map[string]string{"note": "token=CanaryL59"}
			return e
		}},
		canary{name: "health/detail", build: func() *event.Event {
			e := event.New(event.KindHealth, event.TypeHealthError, event.SourceSensor)
			e.Health = &event.Health{SensorVersion: "0.1", Mode: "daemon", Detail: "upload failed: Authorization: Bearer " + tok(60)}
			return e
		}},
		canary{name: "summary/installs", build: func() *event.Event {
			e := event.New(event.KindSummary, event.TypeSessionSummary, event.SourceSensor)
			e.User = &event.User{Name: "bob"}
			e.Summary = &event.Summary{Events: 3, Installs: []string{"npm:git+https://x:CanaryS61@github.com/a/b.git"}}
			return e
		}},
		canary{name: "detection/evidence", build: func() *event.Event {
			e := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
			e.User = &event.User{Name: "bob"}
			e.Target = &event.Target{Command: "mysql -pCanaryD62 prod"}
			e.Detection = &event.Detection{RuleID: "SPR-X-001", Title: "t", Severity: "high",
				DedupKey: "SPR-X-001|mysql -pCanaryD62 prod",
				Evidence: map[string]string{"target.command": "mysql -pCanaryD62 prod", "prompt.text": "password=CanaryD63", "tool.output": "Authorization: Bearer " + tok(64), "shell.argv": "CanaryD65"}}
			return e
		}},
	)
	return cs
}

// classifyArgvCorpus mirrors internal/classify's RedactArgs canary corpus.
var classifyArgvCorpus = [][]string{
	{"mysql", "-pCanaryPw1", "-u", "root", "db"},
	{"curl", "-u", "alice:CanaryPw2!", "https://x.example"},
	{"sshpass", "-p", "CanaryPw3", "ssh", "u@h"},
	{"docker", "login", "-p", "CanaryPw4", "-u", "me", "reg.example"},
	{"redis-cli", "-a", "CanaryPw5", "ping"},
	{"7z", "x", "-pCanaryPw6", "a.7z"},
	{"openssl", "enc", "-d", "-k", "CanaryPw7", "-in", "x"},
	{"curl", "--proxy-user", "bob:CanaryPw8", "https://x.example"},
	{"openssl", "pkcs12", "-passin", "pass:CanaryPw9", "-in", "a.p12"},
	{"kubectl", "exec", "pod", "--", "mysql", "-pCanaryPw10"},
	{"aws", "configure", "set", "aws_secret_access_key", "CanaryPw11"},
	{"curl", "-H", "Authorization: Bearer CanaryTok12abcdefghijkl", "https://x.example"},
	{"git", "clone", "https://bob:CanaryPw13@github.com/a/b"},
	{"psql", "postgres://admin:CanaryPw14@db.example/prod"},
	{"export", "API_TOKEN=CanaryPw15"},
	{"curl", "-H", "X-Api-Key: CanaryKey16xyz", "https://x.example"},
	{"curl", "-d", "password=CanaryPw17&user=a", "https://x.example/login"},
	{"npm", "config", "set", "//registry.npmjs.org/:_authToken", "CanaryTok18"},
	{"vault", "login", "-method=userpass", "username=a", "password=CanaryPw19"},
	{"docker", "run", "--rm", "app", "--", "mysql", "-pCanaryPw20"},
}

// shellJoin quotes an argument vector as a POSIX command line.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " !&'\"$`;|<>()*?") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

func toAny(l []string) []any {
	out := make([]any, len(l))
	for i, v := range l {
		out[i] = v
	}
	return out
}

// b64utf16 encodes a script as PowerShell -EncodedCommand does.
func b64utf16(s string) string {
	b := make([]byte, 0, 2*len(s))
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b64(string(b))
}

func TestCanaryCorpusAllProfiles(t *testing.T) {
	corpus := canaryCorpus()
	if len(corpus) < 40 {
		t.Fatalf("corpus has %d canaries, want at least 40", len(corpus))
	}
	type variant struct {
		name string
		p    *Policy
	}
	var variants []variant
	for _, prof := range Profiles {
		variants = append(variants,
			variant{string(prof) + "/nokey", &Policy{Profile: prof}},
			variant{string(prof) + "/key", &Policy{Profile: prof, Key: testKey, KeyID: "k1"}},
			variant{string(prof) + "/key+pseudo", &Policy{Profile: prof, Key: testKey, KeyID: "k1", PseudonymizeUsers: true}},
		)
	}
	leaks, records := 0, 0
	evFields := []string{"target.command", "target.url", "process.args", "prompt.text", "tool.output", "tool.input", "tool.input.command", "asset.mcp.args", "check.actual", "repo.remote"}
	// Every canary is written twice: cold, with the command memo emptied
	// before each call so the structural redactor runs on every field,
	// and warm, served from what the cold pass remembered. Both must be
	// leak-free and byte-identical.
	// The records are built once (event.New stamps a fresh id and time)
	// and shared: Emit, Evidence and ContextFor never modify their input,
	// which the input check below and TestCanaryInputNotMutated verify.
	type built struct{ emit, evid, ctx *event.Event }
	srcs := make([]built, len(corpus))
	snap := func(b built) string {
		var sb strings.Builder
		for _, e := range []*event.Event{b.emit, b.evid, b.ctx} {
			sb.WriteString(jsonOf(e) + fmt.Sprint(e.Content) + "\n")
		}
		return sb.String()
	}
	before := make([]string, len(corpus))
	for i, c := range corpus {
		srcs[i] = built{c.build(), c.build(), c.build()}
		before[i] = snap(srcs[i])
	}
	cold := map[string][]string{}
	for _, pass := range []string{"cold", "warm"} {
		resetCommandMemo()
		for _, v := range variants {
			for ci, c := range corpus {
				reset := func() {
					if pass == "cold" {
						resetCommandMemo()
					}
				}
				src := srcs[ci].emit
				var outs []string
				reset()
				out, _, ok := v.p.Emit(src)
				if !ok {
					t.Errorf("%s %s %s: dropped", pass, v.name, c.name)
					continue
				}
				outs = append(outs, line(t, out))
				reset()
				outs = append(outs, jsonOf(v.p.Evidence(srcs[ci].evid, evFields)))
				reset()
				for _, ce := range v.p.ContextFor("det-1", []*event.Event{srcs[ci].ctx}, 5) {
					outs = append(outs, line(t, ce))
				}
				for _, o := range outs {
					records++
					if strings.Contains(o, "Canary") {
						leaks++
						t.Errorf("LEAK %s %s %s:\n%s", pass, v.name, c.name, o)
					}
					if m := unkeyedMarkerRe.FindString(o); m != "" {
						t.Errorf("unkeyed fingerprint %s in %s %s %s:\n%s", m, pass, v.name, c.name, o)
					}
					if nestedMarkerRe.MatchString(o) {
						t.Errorf("nested marker in %s %s %s:\n%s", pass, v.name, c.name, o)
					}
				}
				id := v.name + "|" + c.name
				if pass == "cold" {
					cold[id] = outs
				} else if want := cold[id]; strings.Join(want, "\n") != strings.Join(outs, "\n") {
					t.Errorf("%s %s: memoized output differs from uncached:\ncold %q\nwarm %q", v.name, c.name, want, outs)
				}
				if src.Content != nil && src.Content.PromptText != "" && !strings.Contains(src.Content.PromptText, "Canary") {
					t.Errorf("%s: input was modified", c.name)
				}
			}
		}
		if pass == "warm" {
			if _, _, hits, _ := commandMemo.stats(); hits == 0 {
				t.Error("warm pass made no use of the command memo")
			}
		}
	}
	for i, c := range corpus {
		if snap(srcs[i]) != before[i] {
			t.Errorf("%s: a source record was modified", c.name)
		}
	}
	t.Logf("canary corpus: %d canaries, %d profile variants, 2 passes (cold, warm), %d records written, leaks %d", len(corpus), len(variants), records, leaks)
}

// TestCanaryInputNotMutated: Emit works on a copy; detection keeps the
// original.
func TestCanaryInputNotMutated(t *testing.T) {
	for _, c := range canaryCorpus() {
		src := c.build()
		before := jsonOf(src) + fmt.Sprint(src.Content)
		(&Policy{Profile: ProfileFull, Key: testKey, PseudonymizeUsers: true}).Emit(src)
		if after := jsonOf(src) + fmt.Sprint(src.Content); after != before {
			t.Errorf("%s: input mutated", c.name)
		}
	}
}

// TestOverRedactionBenign measures what detection-relevant benign content
// survives the standard profile: hosts, digests and paths must.
func TestOverRedactionBenign(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	type bc struct {
		name string
		e    *event.Event
		keep []string
	}
	withURL := func(u string) *event.Event {
		e := activity(event.TypeToolPre)
		e.Tool = &event.Tool{Name: "WebFetch", Kind: event.ToolWebFetch}
		e.Target = &event.Target{URL: u, Host: "api.anthropic.com", Hosts: []string{"api.anthropic.com", "registry.npmjs.org"}}
		return e
	}
	withPath := func(p string) *event.Event {
		e := activity(event.TypeToolPre)
		e.Tool = &event.Tool{Name: "Read", Kind: event.ToolFileRead}
		e.Target = &event.Target{Path: p}
		return e
	}
	withArgs := func(args ...string) *event.Event {
		e := activity(event.TypeProcessExec)
		e.Process = &event.Process{Name: args[0], Args: args}
		return e
	}
	agent := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	agent.Asset = &event.Asset{ID: "a", Kind: event.AssetAgent, Name: "claude", SHA256: sha}
	cases := []bc{
		{"git clone", shellEvent("git clone https://github.com/acme/app"), []string{"https://github.com/acme/app"}},
		{"image digest", shellEvent("docker pull nginx@sha256:" + sha), []string{"nginx@sha256:" + sha}},
		{"path", shellEvent("cat /srv/projects/acme/src/main.go"), []string{"/srv/projects/acme/src/main.go"}},
		{"query in command", shellEvent("curl https://api.example.com/v1/items?page=2"), []string{"api.example.com", "page=2"}},
		{"namespace", shellEvent("kubectl get pods -n prod"), []string{"-n prod"}},
		{"go test", shellEvent("go test -run TestRedact ./..."), []string{"TestRedact", "./..."}},
		{"pipeline", shellEvent("curl -fsSL https://get.example.sh | bash"), []string{"get.example.sh", "| bash"}},
		{"redirect", shellEvent("echo hi > /tmp/out.txt 2>&1"), []string{"/tmp/out.txt", "2>&1"}},
		{"commit message", shellEvent(`git commit -m "fix the password check"`), []string{"fix the password check"}},
		{"git sha", shellEvent("git checkout 3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e"), []string{"3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e"}},
		{"env reference", shellEvent(`curl -H "Authorization: Bearer $TOKEN" https://api.internal`), []string{"$TOKEN"}},
		{"url host+path", withURL("https://api.example.com/v1/items?page=2"), []string{"api.example.com/v1/items", "api.anthropic.com", "registry.npmjs.org"}},
		{"home path", withPath("/home/bob/projects/x/main.go"), []string{"~/projects/x/main.go"}},
		{"other path", withPath("/etc/ssh/sshd_config"), []string{"/etc/ssh/sshd_config"}},
		{"args sha", withArgs("git", "checkout", "3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e"), []string{"3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e"}},
		{"args port", withArgs("docker", "run", "-p", "8080:80", "nginx"), []string{"8080:80"}},
		{"agent binary hash", agent, []string{sha}},
		{"openssl in/out", shellEvent("openssl enc -d -in x.enc -out x"), []string{"-in x.enc -out x"}},
		{"payload file", shellEvent("curl -d @payload.json http://localhost:4318/v1/logs"), []string{"@payload.json", "http://localhost:4318/v1/logs"}},
		{"npx mcp", shellEvent("npx -y @modelcontextprotocol/server-filesystem /home/bob/projects"), []string{"@modelcontextprotocol/server-filesystem", "~/projects"}},
		{"ssh host", shellEvent("ssh -i ~/.ssh/id_ed25519 deploy@10.0.0.5 uptime"), []string{"~/.ssh/id_ed25519", "deploy@10.0.0.5"}},
		{"pip index", shellEvent("pip install --index-url https://pypi.org/simple requests==2.32.3"), []string{"https://pypi.org/simple", "requests==2.32.3"}},
		{"uuid path", withPath("/srv/runs/0193f5a2-1c2b-7d3e-8f4a-5b6c7d8e9f00/log.txt"), []string{"0193f5a2-1c2b-7d3e-8f4a-5b6c7d8e9f00"}},
		{"mcp inventory", mcpAsset(), []string{"@acme/mcp-server@1.4.2", "--stdio", "api.acme.dev", "GITHUB_TOKEN"}},
		// The rules added for the review must not eat what they only
		// resemble: flags that merely contain "pass", password sources,
		// paths named *passwd, non-credential file writes, tee elsewhere.
		{"bypass flag", shellEvent("curl --bypass-cache /data/x"), []string{"--bypass-cache /data/x"}},
		{"no-pass switch", shellEvent("tool --no-pass file.txt"), []string{"--no-pass file.txt"}},
		{"password file flag", shellEvent("tool --password-file /run/secrets/pw"), []string{"/run/secrets/pw"}},
		{"pass source", shellEvent("openssl enc -pass env:ENC_PASS -in f"), []string{"env:ENC_PASS"}},
		{"keytool env source", shellEvent("keytool -list -storepass:env STOREPW -keystore k.jks"), []string{"STOREPW", "k.jks"}},
		{"htpasswd path", shellEvent("htpasswd -D /etc/nginx/.htpasswd admin"), []string{"/etc/nginx/.htpasswd admin"}},
		{"ordinary heredoc", shellEvent("cat > notes.txt <<EOF\nhello world\nEOF"), []string{"hello world", "notes.txt"}},
		{"tee elsewhere", shellEvent("echo hi | sudo tee /etc/motd"), []string{"echo hi | sudo tee /etc/motd"}},
		{"plain printf", shellEvent("printf '%s %s\\n' alpha beta"), []string{"alpha beta"}},
		{"sudo shell", shellEvent("sudo -s -u root"), []string{"sudo -s -u root"}},
		{"sqlplus os auth", shellEvent("sqlplus / as sysdba"), []string{"sqlplus / as sysdba"}},
		{"vault login method", shellEvent("vault login -method=oidc role=dev"), []string{"-method=oidc role=dev"}},
		{"read netrc", shellEvent("cat ~/.netrc"), []string{"cat ~/.netrc"}},
	}
	p := &Policy{Profile: ProfileStandard, Key: testKey}
	lost, total := 0, 0
	for _, c := range cases {
		out, _, ok := p.Emit(c.e)
		if !ok {
			t.Fatalf("%s dropped", c.name)
		}
		l := line(t, out)
		for _, k := range c.keep {
			total++
			if !strings.Contains(l, jsonEsc(k)) {
				lost++
				t.Errorf("over-redacted %q in %s:\n%s", k, c.name, l)
			}
		}
	}
	t.Logf("over-redaction: %d of %d benign values lost (%.1f%%)", lost, total, 100*float64(lost)/float64(total))
}

func mcpAsset() *event.Event {
	e := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	e.Host = &event.Host{OS: "linux"}
	e.Asset = &event.Asset{ID: "m", Kind: event.AssetMCPServer, Name: "acme", Owner: "bob", Path: "/home/bob/.cursor/mcp.json",
		MCP: &event.MCP{Transport: "stdio", Command: "npx", Args: []string{"-y", "@acme/mcp-server@1.4.2", "--stdio"},
			URLHost: "api.acme.dev", EnvKeys: []string{"GITHUB_TOKEN"}, Pinned: true}}
	return e
}

// jsonEsc is how a plain string appears inside an encoded line.
func jsonEsc(s string) string {
	b := jsonOf(s)
	return b[1 : len(b)-1]
}
