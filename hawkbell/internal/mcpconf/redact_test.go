package mcpconf

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// emitted renders everything that can leave the machine for a server.
func emitted(t *testing.T, s Server) string {
	t.Helper()
	b, err := json.Marshal(Normalize(s))
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n" + strings.Join(RiskFlags(s), ",") + "\n" + DefinitionHash(s)
}

// TestCanarySecretsNeverEmitted plants a distinct synthetic credential in
// every slot a declaration has and searches the output for each of them.
// These slots are redacted by structure, so the test holds with or without
// the pattern scanner.
func TestCanarySecretsNeverEmitted(t *testing.T) {
	n := 0
	var canaries []string
	c := func() string {
		n++
		v := "cnry" + synth("canary"+string(rune('a'+n%26))+strings.Repeat("x", n), 28, base62)
		canaries = append(canaries, v)
		return v
	}
	// The PEM header is split so the source holds no key-shaped literal.
	pem := "-----BEGIN " + "PRIVATE KEY-----\nMIIE" + c() + "\n" + c()

	servers := []Server{
		{Name: "flags", Transport: "stdio", Command: "server", Args: []string{
			"--api-key", c(), "--token=" + c(), "--password", c(), "-p", "8080", "--client-secret", c(),
			"--access-token", c(), "--github-personal-access-token=" + c(), "PASSWORD=" + c(), "DB_PASSWORD=" + c(),
		}},
		{Name: "headers-as-args", Transport: "stdio", Command: "npx", Args: []string{
			"-y", "mcp-remote@0.1.29", "https://r.example/sse?token=" + c(),
			"--header", "Authorization: Bearer " + c(), "-H", "X-Api-Key: " + c(), "--header=Cookie: sid=" + c(),
			"--header", "X-Custom-Auth:" + c(),
		}},
		{Name: "docker-env", Transport: "stdio", Command: "docker", Args: []string{
			"run", "-i", "--rm", "-e", "SETTING=" + c(), "--env", "OTHER=" + c(), "--env=THIRD=" + c(),
			"-eFOURTH=" + c(), "-e", "PASSTHROUGH", "ghcr.io/o/i:1",
		}},
		{Name: "podman-wrapped", Transport: "stdio", Command: "sudo", Args: []string{
			"podman", "run", "-i", "-e", "SETTING=" + c(), "img",
		}},
		{Name: "env-and-headers", Transport: "http", URL: "https://x.example/mcp",
			Env:     map[string]string{"ANY_NAME": c(), "API_KEY": c(), "NODE_OPTIONS": "--require /tmp/x.js --token=" + c()},
			Headers: map[string]string{"Authorization": "Bearer " + c(), "X-Whatever": c()},
		},
		{Name: "url", Transport: "http", URL: "https://user:" + c() + "@mcp.example.com/api/s/" + c() + "/mcp?access_token=" + c() + "&sig=" + c() + "#" + c()},
		{Name: "url-token-userinfo", Transport: "sse", URL: "https://" + c() + "@mcp.example.com/sse"},
		{Name: "urls-in-args", Transport: "stdio", Command: "npx", Args: []string{
			"-y", "@modelcontextprotocol/server-postgres@1.0.0", "postgresql://admin:" + c() + "@db.example.com:5432/prod",
			"--webhook", "https://hooks.example.com/services/x?token=" + c(),
			"--mirror=https://" + c() + "@git.example.com/o/r.git",
			"redis://:" + c() + "@cache.example.com:6379/0",
		}},
		{Name: "inline-script", Transport: "stdio", Command: "sh", Args: []string{
			"-c", "export API_TOKEN=" + c() + "; SECRET_KEY='" + c() + "' curl -H \"Authorization: Bearer " + c() + "\" https://u:" + c() + "@x.example/ | cat; exec server --password=" + c(),
		}},
		{Name: "windows-script", Transport: "stdio", Command: "cmd", Args: []string{
			"/c", "set API_TOKEN=" + c() + "&& npx -y pkg --token=" + c(),
		}},
		{Name: "command-line", Transport: "stdio", Command: "server --token " + c() + " --api-key=" + c() + " https://u:" + c() + "@h.example/x"},
		{Name: "package-specs", Transport: "stdio", Command: "uvx", Args: []string{
			"--from", "git+https://" + c() + "@github.com/o/r@main", "--index-url", "https://u:" + c() + "@pypi.corp.example/simple", "cmd",
		}},
		{Name: "npm-url-spec", Transport: "stdio", Command: "npx", Args: []string{"-y", "https://u:" + c() + "@npm.corp.example/pkg.tgz"}},
		{Name: "npm-alias-url", Transport: "stdio", Command: "npx", Args: []string{"-y", "alias@https://u:" + c() + "@npm.corp.example/pkg.tgz"}},
		{Name: "pem", Transport: "stdio", Command: "server", Args: []string{"--stdio", pem, "--cert", "x " + pem}},
		{Name: "opaque-positional", Transport: "stdio", Command: "server", Args: []string{c() + c()}},
		{Name: "helper-and-oauth", Transport: "http", URL: "https://x.example/mcp", oauth: true,
			headersHelper: "echo '{\"Authorization\": \"Bearer " + c() + "\"}'", oauthSecret: c()},
		{Name: "bridge-url", Transport: "stdio", Command: "npx", Args: []string{"-y", "mcp-remote", "https://svc:" + c() + "@r.example/s/" + c() + c() + "/sse?key=" + c()}},
		{Name: "docker-image-userinfo", Transport: "stdio", Command: "docker", Args: []string{"run", "--mount", "type=bind,src=/a,dst=/b", "--label", "token=" + c(), "img"}},
	}
	if len(canaries) < 50 {
		t.Fatalf("only %d canaries planted", len(canaries))
	}
	for _, s := range servers {
		out := emitted(t, s)
		if hit := contains(out, canaries...); hit != "" {
			t.Errorf("%s: canary %q reached the output:\n%s", s.Name, hit, out)
		}
	}

	// And through Parse: the same holds for a file, including its errors.
	doc := `{"mcpServers": {"a": {"command": "docker", "args": ["run", "-e", "K=` + c() + `", "--api-key", "` + c() + `", "img"],
	  "env": {"X": "` + c() + `"}}, "b": {"url": "https://u:` + c() + `@h.example/mcp?token=` + c() + `", "headers": {"Authorization": "Bearer ` + c() + `"}}}}`
	for _, s := range mustParse(t, "/a.json", doc, FormatAuto) {
		if hit := contains(emitted(t, s), canaries...); hit != "" {
			t.Errorf("parsed %s: canary %q reached the output", s.Name, hit)
		}
	}
	_, err := Parse("/a.json", []byte(doc[:len(doc)-40]), FormatAuto)
	if err == nil {
		t.Fatal("truncated document parsed")
	}
	if hit := contains(err.Error(), canaries...); hit != "" {
		t.Errorf("error leaks canary %q", hit)
	}
}

func TestCanarySecretsFoundByScanner(t *testing.T) {
	requireClassify(t)
	// Slots with no structure to go by: only the scanner can know.
	aws := synthAWSKeyID("canary")
	gh := synthGitHubPAT("canary")
	servers := []Server{
		{Name: "positional", Transport: "stdio", Command: "server", Args: []string{"--stdio", aws, "prefix:" + gh}},
		{Name: "env-name-is-a-value", Transport: "stdio", Command: "server", Env: map[string]string{gh: ""}},
		{Name: "header-name-is-a-value", Transport: "http", URL: "https://x.example/mcp", Headers: map[string]string{aws: ""}},
		{Name: "url-path", Transport: "http", URL: "https://x.example/hook/" + gh},
		{Name: "package-position", Transport: "stdio", Command: "npx", Args: []string{"-y", "pkg@" + gh}},
		{Name: "command", Transport: "stdio", Command: "/opt/" + gh + "/server"},
	}
	for _, s := range servers {
		if hit := contains(emitted(t, s), aws, gh); hit != "" {
			t.Errorf("%s: %q reached the output:\n%s", s.Name, hit, emitted(t, s))
		}
	}
}

func TestRedactionKeepsWhatIsNotSecret(t *testing.T) {
	tok := synth("keep", 40, base62)
	s := Server{Transport: "stdio", Command: "docker", Args: []string{
		"run", "-i", "--rm", "-e", "API_TOKEN=" + tok, "-e", "LOG_LEVEL", "-v", "/srv/data:/data:ro",
		"--name", "mcp-thing", "ghcr.io/o/i:1.2.3", "--api-key", tok, "--port", "8080", "--max-tokens", "4096",
		"--url", "https://api.example.com/v1?region=eu&token=" + tok,
	}}
	got := Normalize(s).Args
	fp := fp8(tok)
	want := []string{
		"run", "-i", "--rm", "-e", "API_TOKEN=[REDACTED:env:" + fp + "]", "-e", "LOG_LEVEL", "-v", "/srv/data:/data:ro",
		"--name", "mcp-thing", "ghcr.io/o/i:1.2.3", "--api-key", "[REDACTED:arg:" + fp + "]", "--port", "8080", "--max-tokens", "4096",
		"--url", "https://api.example.com/v1?region=eu&token=[REDACTED:",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if i == len(want)-1 {
			if !strings.HasPrefix(got[i], want[i]) {
				t.Errorf("arg %d: %q, want prefix %q", i, got[i], want[i])
			}
			continue
		}
		if got[i] != want[i] {
			t.Errorf("arg %d: %q, want %q", i, got[i], want[i])
		}
	}
	// The same secret carries the same fingerprint wherever it shows up, and
	// the marker has the house format.
	re := regexp.MustCompile(`\[REDACTED:[a-z_]+:[0-9a-f]{8}\]`)
	for _, i := range []int{4, 13, 19} {
		if !re.MatchString(got[i]) {
			t.Errorf("arg %d: no well-formed marker in %q", i, got[i])
		}
	}

	// References and prompts are not credentials and stay readable.
	refs := []string{"${API_KEY}", "${env:API_KEY}", "${input:api-key}", "$API_KEY", "%API_KEY%", "{env:API_KEY}", "${{ secrets.API_KEY }}", "Bearer ${TOKEN}"}
	for _, r := range refs {
		s := Server{Transport: "stdio", Command: "docker", Args: []string{"run", "-e", "K=" + r, "--api-key", r, "--header", "Authorization: " + r, "img"}}
		args := Normalize(s).Args
		if args[2] != "K="+r || args[4] != r || !strings.HasSuffix(args[6], r) {
			t.Errorf("reference %q was redacted: %q", r, args)
		}
		if !isReference(r) {
			t.Errorf("isReference(%q) = false", r)
		}
	}
	// A default value is a literal and is scanned like one.
	for _, lit := range []string{"${API_KEY:-fallback-value}", "prefix-${API_KEY}", "literal", "$", "${}", "%%", "${a b}"} {
		if isReference(lit) {
			t.Errorf("isReference(%q) = true", lit)
		}
	}
}

func TestSecretNames(t *testing.T) {
	yes := []string{"token", "API_KEY", "apiKey", "X-Api-Key", "x-api-key", "GITHUB_PERSONAL_ACCESS_TOKEN", "client_secret",
		"clientSecret", "PASSWORD", "db_passwd", "Authorization", "AWS_SECRET_ACCESS_KEY", "private-key", "SESSIONTOKEN",
		"auth_token", "bearer", "OPENAI_APIKEY", "ssh_key", "Cookie", "SIGNING_KEY", "credentials"}
	no := []string{"max_tokens", "maxTokens", "tokenizer", "path", "port", "keyboard", "KEY_FILE_FORMAT", "primary_key_column",
		"author", "region", "LOG_LEVEL", "pattern", "cache_key_prefix", "monkey", "design", ""}
	for _, n := range yes {
		if !isSecretName(n) {
			t.Errorf("isSecretName(%q) = false", n)
		}
	}
	for _, n := range no {
		if isSecretName(n) {
			t.Errorf("isSecretName(%q) = true", n)
		}
	}
	// Query parameters use shorter names.
	for _, n := range []string{"key", "sig", "auth", "signature", "access_token", "X-Amz-Signature"} {
		if !isSecretParam(n) {
			t.Errorf("isSecretParam(%q) = false", n)
		}
	}
	for _, n := range []string{"keyword", "page", "v", "signal", "authority"} {
		if isSecretParam(n) {
			t.Errorf("isSecretParam(%q) = true", n)
		}
	}
}

func TestSplitURL(t *testing.T) {
	cases := []struct {
		raw                                       string
		scheme, userinfo, host, port, path, query string
	}{
		{"https://mcp.example.com/mcp", "https", "", "mcp.example.com", "", "/mcp", ""},
		{"HTTPS://User:Pw@MCP.Example.COM:8443/a/b?x=1&y=2#f", "https", "User:Pw", "mcp.example.com", "8443", "/a/b", "x=1&y=2"},
		{"http://[::1]:3000/mcp", "http", "", "::1", "3000", "/mcp", ""},
		{"http://[fe80::1%25eth0]/mcp", "http", "", "fe80::1%25eth0", "", "/mcp", ""},
		{"wss://h.example", "wss", "", "h.example", "", "", ""},
		{"mcp.example.com/path", "", "", "mcp.example.com", "", "/path", ""},
		{"http://${HOST:-localhost}:8080/mcp", "http", "", "${host:-localhost}", "8080", "/mcp", ""},
		{`http://good.example\@evil.example/x`, "http", "", "good.example", "", `\@evil.example/x`, ""},
		{"http://a@b@c.example/", "http", "a@b", "c.example", "", "/", ""},
		{"  https://h.example/p  ", "https", "", "h.example", "", "/p", ""},
		{"", "", "", "", "", "", ""},
		{"://", "", "", "", "", "//", ""},
		{"https://h.example?only=query", "https", "", "h.example", "", "", "only=query"},
	}
	for _, c := range cases {
		u := splitURL(c.raw)
		got := []string{u.scheme, u.userinfo, u.host, u.port, u.path, u.query}
		want := []string{c.scheme, c.userinfo, c.host, c.port, c.path, c.query}
		eq(t, "splitURL("+c.raw+")", got, want)
	}
	eq(t, "sanitized", sanitizedURL("HTTPS://u:p@H.example:8443/a?token=x#f"), "https://h.example:8443/a")
	eq(t, "sanitized v6", sanitizedURL("http://[::1]:3000/mcp?x=1"), "http://[::1]:3000/mcp")
	eq(t, "sanitized empty", sanitizedURL("  "), "")
}
