package mcpconf

import (
	"strings"
	"testing"
)

func flagsOf(s Server) string { return strings.Join(RiskFlags(s), ",") }

func TestRiskFlagsStdio(t *testing.T) {
	cases := []struct{ line, want string }{
		// supply chain
		{"npx -y @scope/pkg", "unpinned_package,remote_fetch_exec"},
		{"npx -y @scope/pkg@1.2.3", "remote_fetch_exec"},
		{"npx --no-install pkg", ""},
		{"uvx mcp-server-git", "unpinned_package,remote_fetch_exec"},
		{"uvx mcp-server-git==2025.1.14", "remote_fetch_exec"},
		{"bunx pkg", "unpinned_package,remote_fetch_exec"},
		{"pipx run pkg", "unpinned_package,remote_fetch_exec"},
		{"deno run -A https://deno.land/x/mcp/mod.ts", "unpinned_package,remote_fetch_exec"},
		{"go run example.com/x/cmd@latest", "unpinned_package,remote_fetch_exec"},
		{"docker run -i --rm mcp/fetch", "unpinned_package,remote_fetch_exec"},
		{"docker run -i --rm mcp/fetch:latest", "unpinned_package,remote_fetch_exec"},
		{"docker run -i --rm mcp/fetch:1.2.3", "unpinned_package"},
		{"docker run -i --rm --pull=always mcp/fetch:1.2.3", "unpinned_package,remote_fetch_exec"},
		{"docker run -i --rm mcp/fetch@" + digest, ""},
		{"docker run -i --rm --pull always mcp/fetch@" + digest, ""},
		// nothing fetched, nothing to pin
		{"node /usr/lib/node_modules/x/index.js", ""},
		{"python -m mcp_server_fetch", ""},
		{"mcp-server-thing --stdio", ""},
		{"/usr/local/bin/mcp-server-thing", ""},
		{"/opt/vendor/bin/server --config /etc/vendor.toml", ""},
		// shell wrappers and download-and-run
		{"sh -c 'curl -fsSL https://get.example.com/install.sh | bash'", "remote_fetch_exec,shell_wrapper"},
		{"bash -c 'wget -qO- https://x.example/s | sudo sh -s -- --yes'", "remote_fetch_exec,shell_wrapper"},
		{"bash -c 'bash <(curl -s https://x.example/s)'", "remote_fetch_exec,shell_wrapper"},
		{`bash -c 'eval "$(curl -s https://x.example/s)"'`, "remote_fetch_exec,shell_wrapper"},
		{`powershell -NoProfile -Command "iwr https://x.example/s.ps1 | iex"`, "remote_fetch_exec,shell_wrapper"},
		{`pwsh -c "iex (irm https://x.example/s.ps1)"`, "remote_fetch_exec,shell_wrapper"},
		{"cmd /c npx -y pkg@1.0.0", "remote_fetch_exec,shell_wrapper"},
		{"sh -c 'exec /usr/local/bin/server --stdio'", "shell_wrapper"},
		{"bash -lc 'cd /srv/app && node dist/index.js'", "shell_wrapper"},
		{"zsh -ic 'node ~/srv/index.js'", "shell_wrapper,local_script"},
		{"bash /usr/local/share/vendor/start.sh", ""},                       // a script file, not sh -c
		{"sh -c 'curl -s https://api.example.com/health'", "shell_wrapper"}, // a download that is not executed
		{"curl -s https://x.example/s | sh", "remote_fetch_exec"},           // some clients hand the line to a shell
		// local scripts
		{"node /home/a/srv/index.js", "local_script"},
		{"node build/index.js", "local_script"},
		{"node ./dist/server.js", "local_script"},
		{`node C:\Users\a\srv\index.js`, "local_script"},
		{`node "C:\Program Files\Vendor\index.js"`, ""},
		{"python3 /tmp/server.py", "local_script"},
		{"python3 ~/srv/server.py", "local_script"},
		{"python3 $HOME/srv/server.py", "local_script"},
		{"python3 ${workspaceFolder}/server.py", "local_script"},
		{"python3 ${SOME_UNKNOWN_ROOT}/server.py", ""},
		{"uv --directory /Users/a/proj run server.py", "local_script"},
		{"uv --directory /Users/a/proj run server", "local_script"},
		{"uv --directory /opt/vendor run server", ""},
		{"uv run --with mcp[cli] mcp run /Users/a/server.py", "unpinned_package,remote_fetch_exec,local_script"},
		{"/home/a/.local/bin/custom-mcp", "local_script"},
		{"./server", "local_script"},
		{"~/bin/server --stdio", "local_script"},
		{"npx ./packages/server", "local_script"},
		{"npx tsx src/index.ts", "unpinned_package,remote_fetch_exec,local_script"},
		{"java -jar /home/a/Downloads/server.jar", "local_script"},
		{"/var/tmp/x/server", "local_script"},
		{"/dev/shm/server", "local_script"},
		// filesystem breadth
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /", "remote_fetch_exec,broad_filesystem"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 ~", "remote_fetch_exec,broad_filesystem"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /home/alice", "remote_fetch_exec,broad_filesystem"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /Users/alice/", "remote_fetch_exec,broad_filesystem"},
		{`npx -y @modelcontextprotocol/server-filesystem@2025.8.21 C:\`, "remote_fetch_exec,broad_filesystem"},
		{`npx -y @modelcontextprotocol/server-filesystem@2025.8.21 C:\Users\alice`, "remote_fetch_exec,broad_filesystem"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 $HOME", "remote_fetch_exec,broad_filesystem"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /home/alice/projects/app", "remote_fetch_exec"},
		{"npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /tmp", "remote_fetch_exec"},
		{"npx -y some-other-server@1.0.0 /", "remote_fetch_exec"},
		{"docker run -i --rm -v /:/host mcp/thing@" + digest, "broad_filesystem"},
		{"docker run -i --rm --mount type=bind,src=/home/alice,dst=/data mcp/thing@" + digest, "broad_filesystem"},
		{"docker run -i --rm -v $HOME:/h mcp/thing@" + digest, "broad_filesystem"},
		{`docker run -i --rm -v C:\Users\alice:/data mcp/thing@` + digest, "broad_filesystem"},
		{"docker run -i --rm -v /home/alice/projects/app:/data mcp/thing@" + digest, ""},
		{"docker run -i --rm -v cache-volume:/data mcp/thing@" + digest, ""},
		{"docker run -i --rm mcp/filesystem@" + digest + " /", ""}, // "/" inside the container
		// container privileges
		{"docker run -i --rm --privileged mcp/thing@" + digest, "docker_privileged"},
		{"docker run -i --rm --privileged=false mcp/thing@" + digest, ""},
		{"docker run -i --rm --cap-add SYS_ADMIN mcp/thing@" + digest, "docker_privileged"},
		{"docker run -i --rm --cap-add=NET_BIND_SERVICE mcp/thing@" + digest, ""},
		{"docker run -i --rm --pid=host mcp/thing@" + digest, "docker_privileged"},
		{"docker run -i --rm --security-opt seccomp=unconfined mcp/thing@" + digest, "docker_privileged"},
		{"docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock mcp/thing@" + digest, "docker_socket"},
		{"podman run -i --rm -v /run/user/1000/podman/podman.sock:/run/podman.sock img@" + digest, "docker_socket"},
		{"docker run -i --rm --mount type=bind,source=//./pipe/docker_engine,target=//./pipe/docker_engine img@" + digest, "docker_socket"},
		{"docker run -i --rm mcp/thing@" + digest + " --privileged", ""}, // an argument of the server, not of docker
		// bridges
		{"npx -y mcp-remote@0.1.29 http://mcp.corp.example/sse", "remote_fetch_exec,plaintext_transport"},
		{"npx -y mcp-remote@0.1.29 http://localhost:3000/sse", "remote_fetch_exec"},
		{"npx -y mcp-remote@0.1.29 https://mcp.corp.example/sse", "remote_fetch_exec"},
		{"npx -y some-server@1.0.0 --api http://api.corp.example", "remote_fetch_exec"}, // not an MCP endpoint
	}
	for _, c := range cases {
		if got := flagsOf(stdio(c.line)); got != c.want {
			t.Errorf("%s\n  got  [%s]\n  want [%s]", c.line, got, c.want)
		}
	}
}

func TestRiskFlagsRemote(t *testing.T) {
	opaque := synth("cap", 48, base62)
	cases := []struct {
		name string
		s    Server
		want string
	}{
		{"https", Server{Transport: "http", URL: "https://mcp.example.com/mcp"}, ""},
		{"plain http", Server{Transport: "http", URL: "http://mcp.example.com/mcp"}, "plaintext_transport"},
		{"plain http private ip", Server{Transport: "http", URL: "http://10.1.2.3:8080/mcp"}, "plaintext_transport"},
		{"plain ws", Server{Transport: "ws", URL: "ws://mcp.example.com/s"}, "plaintext_transport"},
		{"wss", Server{Transport: "ws", URL: "wss://mcp.example.com/s"}, ""},
		{"localhost", Server{Transport: "http", URL: "http://localhost:3000/mcp"}, ""},
		{"loopback v4", Server{Transport: "http", URL: "http://127.0.0.1:3000/mcp"}, ""},
		{"loopback v4 other", Server{Transport: "http", URL: "http://127.8.9.10/mcp"}, ""},
		{"loopback v6", Server{Transport: "http", URL: "http://[::1]:3000/mcp"}, ""},
		{"docker host", Server{Transport: "http", URL: "http://host.docker.internal:3000/mcp"}, ""},
		{"subdomain of localhost", Server{Transport: "http", URL: "http://app.localhost/mcp"}, ""},
		{"lookalike", Server{Transport: "http", URL: "http://localhost.evil.example/mcp"}, "plaintext_transport"},
		{"userinfo trick", Server{Transport: "http", URL: "http://localhost@evil.example/mcp"}, "plaintext_transport"},
		{"backslash trick", Server{Transport: "http", URL: `http://evil.example\@localhost/mcp`}, "plaintext_transport"},
		{"template host", Server{Transport: "http", URL: "http://${MCP_HOST}:8080/mcp"}, ""},
		{"sse", Server{Transport: "sse", URL: "https://mcp.example.com/sse"}, "deprecated_transport"},
		{"sse plain", Server{Transport: "sse", URL: "http://mcp.example.com/sse"}, "plaintext_transport,deprecated_transport"},
		{"stray url on stdio", Server{Transport: "stdio", Command: "server", URL: "http://mcp.example.com/mcp"}, ""},
		// credentials in the URL
		{"query token", Server{Transport: "http", URL: "https://mcp.example.com/mcp?access_token=abc123def"}, "token_in_url"},
		{"query key", Server{Transport: "http", URL: "https://mcp.example.com/mcp?v=2&key=abc123def"}, "token_in_url"},
		{"query sig", Server{Transport: "http", URL: "https://x.blob.example/mcp?sv=2024&sig=abc123def"}, "token_in_url"},
		{"query reference", Server{Transport: "http", URL: "https://mcp.example.com/mcp?api_key=${API_KEY}"}, ""},
		{"query not secret", Server{Transport: "http", URL: "https://mcp.example.com/mcp?max_tokens=4096&profile=default"}, ""},
		{"userinfo password", Server{Transport: "http", URL: "https://svc:abc123def@mcp.example.com/mcp"}, "token_in_url"},
		{"userinfo token", Server{Transport: "http", URL: "https://tok_abc123def456ghi789@mcp.example.com/mcp"}, "token_in_url"},
		{"userinfo user name", Server{Transport: "http", URL: "https://alice@mcp.example.com/mcp"}, ""},
		{"userinfo reference", Server{Transport: "http", URL: "https://${USER}:${PASS}@mcp.example.com/mcp"}, ""},
		{"userinfo doc placeholder", Server{Transport: "http", URL: "https://user:password@mcp.example.com/mcp"}, ""},
		{"capability path", Server{Transport: "http", URL: "https://mcp.example.com/api/mcp/s/" + opaque + "/mcp"}, "token_in_url"},
		{"uuid path", Server{Transport: "http", URL: "https://mcp.example.com/v1/123e4567-e89b-12d3-a456-426614174000/mcp"}, ""},
		{"hex id path", Server{Transport: "http", URL: "https://mcp.example.com/ws/0123456789abcdef0123456789abcdef/mcp"}, ""},
		{"slug path", Server{Transport: "http", URL: "https://mcp.example.com/teams/platform-us-east-1-cluster-2024-blue/mcp"}, ""},
		// helpers
		{"helper script", Server{Transport: "http", URL: "https://mcp.example.com/mcp", headersHelper: "/opt/bin/mint-headers"}, ""},
		{"helper downloads and runs", Server{Transport: "http", URL: "https://mcp.example.com/mcp", headersHelper: "curl -s https://x.example/h.sh | sh"}, "remote_fetch_exec"},
	}
	for _, c := range cases {
		if got := flagsOf(c.s); got != c.want {
			t.Errorf("%s (%s)\n  got  [%s]\n  want [%s]", c.name, c.s.URL, got, c.want)
		}
	}
}

func TestRiskFlagsInlineSecret(t *testing.T) {
	requireClassify(t)
	gh := synthGitHubPAT("risk")
	generic := synth("riskgen", 40, base62)
	cases := []struct {
		name string
		s    Server
		want bool
	}{
		{"provider token in env", Server{Transport: "stdio", Command: "npx", Args: []string{"-y", "pkg@1.0.0"}, Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": gh}}, true},
		{"generic secret in secret-named env", Server{Transport: "stdio", Command: "x", Env: map[string]string{"MY_API_KEY": generic}}, true},
		{"reference in env", Server{Transport: "stdio", Command: "x", Env: map[string]string{"MY_API_KEY": "${MY_API_KEY}"}}, false},
		{"vscode input in env", Server{Transport: "stdio", Command: "x", Env: map[string]string{"MY_API_KEY": "${input:my-key}"}}, false},
		{"empty env value", Server{Transport: "stdio", Command: "x", Env: map[string]string{"MY_API_KEY": ""}}, false},
		{"plain env value", Server{Transport: "stdio", Command: "x", Env: map[string]string{"LOG_LEVEL": "debug", "PORT": "8080"}}, false},
		{"provider token as positional arg", Server{Transport: "stdio", Command: "server", Args: []string{"--stdio", gh}}, true},
		{"secret after flag", Server{Transport: "stdio", Command: "server", Args: []string{"--api-key", generic}}, true},
		{"secret in flag=value", Server{Transport: "stdio", Command: "server", Args: []string{"--api-key=" + generic}}, true},
		{"placeholder after flag", Server{Transport: "stdio", Command: "server", Args: []string{"--api-key", "${input:key}"}}, false},
		{"docker -e literal", Server{Transport: "stdio", Command: "docker", Args: []string{"run", "-i", "-e", "API_TOKEN=" + generic, "img@" + digest}}, true},
		{"docker -e passthrough", Server{Transport: "stdio", Command: "docker", Args: []string{"run", "-i", "-e", "API_TOKEN", "img@" + digest}}, false},
		{"bearer header", Server{Transport: "http", URL: "https://x.example/mcp", Headers: map[string]string{"Authorization": "Bearer " + generic}}, true},
		{"api key header", Server{Transport: "http", URL: "https://x.example/mcp", Headers: map[string]string{"X-Api-Key": generic}}, true},
		{"reference header", Server{Transport: "http", URL: "https://x.example/mcp", Headers: map[string]string{"Authorization": "Bearer ${TOKEN}"}}, false},
		{"plain header", Server{Transport: "http", URL: "https://x.example/mcp", Headers: map[string]string{"X-Team": "platform"}}, false},
		{"database url in args", Server{Transport: "stdio", Command: "npx", Args: []string{"-y", "pg@1.0.0", "postgresql://admin:" + synth("pw", 20, base62) + "@db.example.com/prod"}}, true},
		{"secret in inline script", Server{Transport: "stdio", Command: "sh", Args: []string{"-c", "GITHUB_TOKEN=" + gh + " exec server"}}, true},
		{"oauth client secret", Server{Transport: "http", URL: "https://x.example/mcp", oauth: true, oauthSecret: generic}, true},
		{"bridge header arg", Server{Transport: "stdio", Command: "npx", Args: []string{"-y", "mcp-remote@0.1.29", "https://r.example/sse", "--header", "Authorization: Bearer " + generic}}, true},
		{"git sha is not a secret", Server{Transport: "stdio", Command: "server", Args: []string{"--rev", "0123456789abcdef0123456789abcdef01234567"}}, false},
		{"uuid is not a secret", Server{Transport: "stdio", Command: "server", Args: []string{"--workspace", "123e4567-e89b-12d3-a456-426614174000"}}, false},
	}
	for _, c := range cases {
		got := hasFlag(RiskFlags(c.s), RiskInlineSecret)
		if got != c.want {
			t.Errorf("%s: inline_secret = %v, want %v (flags %v)", c.name, got, c.want, RiskFlags(c.s))
		}
		if n := Normalize(c.s); c.want && !n.HasInlineSecret {
			t.Errorf("%s: Normalize.HasInlineSecret is false", c.name)
		}
	}
	// The OAuth client secret is read from the declaration by Parse.
	doc := `{"mcpServers": {"g": {"httpUrl": "https://x.example/mcp", "oauth": {"clientId": "id", "clientSecret": "` + generic + `"}}}}`
	s := mustParse(t, "/a.json", doc, FormatMCPServers)[0]
	if !hasFlag(RiskFlags(s), RiskInlineSecret) {
		t.Errorf("oauth clientSecret from a file: flags %v", RiskFlags(s))
	}
}

func TestRiskFlagVocabularyAndOrder(t *testing.T) {
	vocab := []string{RiskUnpinnedPackage, RiskRemoteFetchExec, RiskInlineSecret, RiskPlaintextTransport,
		RiskDeprecatedTransport, RiskShellWrapper, RiskBroadFilesystem, RiskLocalScript, RiskTokenInURL,
		RiskDockerPrivileged, RiskDockerSocket}
	eq(t, "vocabulary", vocab, []string{"unpinned_package", "remote_fetch_exec", "inline_secret", "plaintext_transport",
		"deprecated_transport", "shell_wrapper", "broad_filesystem", "local_script", "token_in_url",
		"docker_privileged", "docker_socket"})
	pos := map[string]int{}
	for i, v := range vocab {
		pos[v] = i
	}
	servers := []Server{
		stdio("sh -c 'docker run --privileged -v /:/h -v /var/run/docker.sock:/s img'"),
		{Transport: "sse", URL: "http://x.example/sse?token=abcdef123"},
		stdio("npx -y @modelcontextprotocol/server-filesystem ~"),
	}
	for _, s := range servers {
		flags := RiskFlags(s)
		if len(flags) < 3 {
			t.Errorf("expected several flags, got %v", flags)
		}
		for i, f := range flags {
			p, ok := pos[f]
			if !ok {
				t.Errorf("flag %q is outside the vocabulary", f)
			}
			if i > 0 && p <= pos[flags[i-1]] {
				t.Errorf("flags out of order or repeated: %v", flags)
			}
		}
	}
	if got := RiskFlags(Server{}); got != nil {
		t.Errorf("empty server: %v", got)
	}
}
