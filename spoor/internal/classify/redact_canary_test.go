package classify

import (
	"strings"
	"testing"
)

// TestRedactArgsCanaryCorpus is the privacy red team's command-line
// corpus: every synthetic credential (all contain "Canary") must disappear,
// and the benign parts that detection needs (hosts, digests, paths) must
// survive. The measured rates are reported so a regression is visible.
func TestRedactArgsCanaryCorpus(t *testing.T) {
	secret := [][]string{
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
	leaks := 0
	for _, c := range secret {
		out := strings.Join(RedactArgs(c), " ")
		if strings.Contains(out, "Canary") {
			leaks++
			t.Errorf("leak: %v -> %s", c, out)
		}
		if strings.Contains(out, "[REDACTED:[REDACTED") {
			t.Errorf("nested marker: %s", out)
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
	t.Logf("leak rate %d/%d, over-redaction %d benign keeps lost", leaks, len(secret), over)
}
