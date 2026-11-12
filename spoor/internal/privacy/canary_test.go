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
	for _, v := range variants {
		for _, c := range corpus {
			src := c.build()
			var outs []string
			out, _, ok := v.p.Emit(src)
			if !ok {
				t.Errorf("%s %s: dropped", v.name, c.name)
				continue
			}
			outs = append(outs, line(t, out))
			outs = append(outs, jsonOf(v.p.Evidence(c.build(), evFields)))
			for _, ce := range v.p.ContextFor("det-1", []*event.Event{c.build()}, 5) {
				outs = append(outs, line(t, ce))
			}
			for _, o := range outs {
				records++
				if strings.Contains(o, "Canary") {
					leaks++
					t.Errorf("LEAK %s %s:\n%s", v.name, c.name, o)
				}
				if m := unkeyedMarkerRe.FindString(o); m != "" {
					t.Errorf("unkeyed fingerprint %s in %s %s:\n%s", m, v.name, c.name, o)
				}
				if nestedMarkerRe.MatchString(o) {
					t.Errorf("nested marker in %s %s:\n%s", v.name, c.name, o)
				}
			}
			if src.Content != nil && src.Content.PromptText != "" && !strings.Contains(src.Content.PromptText, "Canary") {
				t.Errorf("%s: input was modified", c.name)
			}
		}
	}
	t.Logf("canary corpus: %d canaries, %d profile variants, %d records written, leaks %d", len(corpus), len(variants), records, leaks)
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

// jsonEsc is how a plain string appears inside an encoded line.
func jsonEsc(s string) string {
	b := jsonOf(s)
	return b[1 : len(b)-1]
}
