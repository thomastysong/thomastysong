package mcpconf

import (
	"strings"
	"testing"
)

var digest = "sha256:" + strings.Repeat("ab", 32)

// TestLaunchMatrix is the launch-form matrix for runner detection and
// pinning. Each line is given the way a config writes it; the split form
// (command + args) is checked against the one-line form below.
func TestLaunchMatrix(t *testing.T) {
	cases := []struct {
		line                      string
		runner, eco, pkg, version string
		pinned                    bool
	}{
		// npm family
		{"npx -y @scope/pkg", "npx", "npm", "@scope/pkg", "", false},
		{"npx -y @scope/pkg@1.2.3", "npx", "npm", "@scope/pkg", "1.2.3", true},
		{"npx -y @scope/pkg@1.2.3-beta.1+build.5", "npx", "npm", "@scope/pkg", "1.2.3-beta.1+build.5", true},
		{"npx -y pkg@v2.0.0", "npx", "npm", "pkg", "v2.0.0", true},
		{"npx -y @scope/pkg@latest", "npx", "npm", "@scope/pkg", "latest", false},
		{"npx pkg@next", "npx", "npm", "pkg", "next", false},
		{"npx @scope/pkg@^1.2.0", "npx", "npm", "@scope/pkg", "^1.2.0", false},
		{"npx pkg@~1.2.0", "npx", "npm", "pkg", "~1.2.0", false},
		{"npx pkg@1", "npx", "npm", "pkg", "1", false},     // x-range
		{"npx pkg@1.2", "npx", "npm", "pkg", "1.2", false}, // x-range
		{"npx pkg@1.2.x", "npx", "npm", "pkg", "1.2.x", false},
		{"npx pkg@>=1.0.0", "npx", "npm", "pkg", ">=1.0.0", false},
		{"npx pkg@*", "npx", "npm", "pkg", "*", false},
		// -p names the package; the first bare word is then the command.
		{"npx -y -p pkg@2.0.0 cmd --port 1", "npx", "npm", "pkg", "2.0.0", true},
		{"npx --package pkg cmd", "npx", "npm", "pkg", "", false},
		{"npx --package=@a/b@1.0.0 -- b serve", "npx", "npm", "@a/b", "1.0.0", true},
		{"npx --registry https://npm.corp.example -y pkg@3.0.0", "npx", "npm", "pkg", "3.0.0", true},
		{"npx -y github:user/repo", "npx", "npm", "github:user/repo", "", false},
		{"npx -y user/repo#main", "npx", "npm", "user/repo", "main", false},
		{"npx -y user/repo#0123456789abcdef0123456789abcdef01234567", "npx", "npm", "user/repo", "0123456789abcdef0123456789abcdef01234567", true},
		{"npx -y https://example.com/pkg.tgz", "npx", "npm", "https://example.com/pkg.tgz", "", false},
		{"npx.cmd -y pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"pnpm dlx pkg@3.1.4", "npx", "npm", "pkg", "3.1.4", true},
		{"pnpm dlx pkg", "npx", "npm", "pkg", "", false},
		{"yarn dlx -p pkg@1.0.0 bin", "npx", "npm", "pkg", "1.0.0", true},
		{"npm exec --package=pkg@1.2.3 -- bin a", "npx", "npm", "pkg", "1.2.3", true},
		{"npm exec -- pkg@next a", "npx", "npm", "pkg", "next", false},
		{"bunx pkg@0.0.1", "bunx", "npm", "pkg", "0.0.1", true},
		{"bunx --bun pkg", "bunx", "npm", "pkg", "", false},
		{"bun x pkg@latest", "bunx", "npm", "pkg", "latest", false},
		{`node C:\Users\a\AppData\Roaming\npm\node_modules\npm\bin\npx-cli.js -y pkg@1.0.0`, "npx", "npm", "pkg", "1.0.0", true},
		// Python family
		{"uvx mcp-server-git", "uvx", "pypi", "mcp-server-git", "", false},
		{"uvx mcp-server-git@2025.1.14", "uvx", "pypi", "mcp-server-git", "2025.1.14", true},
		{"uvx mcp-server-git@latest", "uvx", "pypi", "mcp-server-git", "latest", false},
		{"uvx --from mcp-server-git==2025.1.14 mcp-server-git --repository /x", "uvx", "pypi", "mcp-server-git", "2025.1.14", true},
		{"uvx --from 'Mcp_Server.Git[extra]>=1.0' cmd", "uvx", "pypi", "mcp-server-git", ">=1.0", false},
		{"uvx --from pkg~=1.4 cmd", "uvx", "pypi", "pkg", "~=1.4", false},
		{"uvx --from pkg==1.4.* cmd", "uvx", "pypi", "pkg", "1.4.*", false},
		{"uvx --from 'pkg==1.4,<2' cmd", "uvx", "pypi", "pkg", "1.4,<2", false},
		{"uvx --from pkg==1.0.0rc1.post2+local.7 cmd", "uvx", "pypi", "pkg", "1.0.0rc1.post2+local.7", true},
		{"uvx --python 3.12 --index-url https://pypi.corp.example/simple pkg==2.0", "uvx", "pypi", "pkg", "2.0", true},
		// An unpinned extra requirement floats just like an unpinned package.
		{"uvx --with pandas --from pkg==1.0 cmd", "uvx", "pypi", "pkg", "1.0", false},
		{"uvx --with pandas==2.2.0,numpy==2.0.0 pkg==1.0", "uvx", "pypi", "pkg", "1.0", true},
		{"uvx --from git+https://github.com/org/repo cmd", "uvx", "pypi", "git+https://github.com/org/repo", "", false},
		{"uvx --from git+https://github.com/org/repo@v1.2.0 cmd", "uvx", "pypi", "git+https://github.com/org/repo", "v1.2.0", false},
		{"uvx --from git+https://github.com/org/repo@0123456789abcdef0123456789abcdef01234567 cmd", "uvx", "pypi", "git+https://github.com/org/repo", "0123456789abcdef0123456789abcdef01234567", true},
		{"uv tool run pkg==1.0.0", "uvx", "pypi", "pkg", "1.0.0", true},
		{"uv --quiet tool run --from pkg cmd", "uvx", "pypi", "pkg", "", false},
		{"uv run --with mcp[cli] mcp run /Users/a/server.py", "python", "pypi", "mcp", "", false},
		{"uv run --with fastmcp==2.1.0 fastmcp run server.py:app", "python", "pypi", "fastmcp", "2.1.0", true},
		{"uv --directory /opt/srv run server", "python", "", "", "", false},
		{"uv run python -m foo", "python", "", "", "", false},
		{"pipx run pkg==1.2.3", "pipx", "pypi", "pkg", "1.2.3", true},
		{"pipx run --spec pkg==1.2.3 app", "pipx", "pypi", "pkg", "1.2.3", true},
		{"pipx run pkg", "pipx", "pypi", "pkg", "", false},
		{"python -m mcp_server_fetch", "python", "", "", "", false},
		{"python3.12 -u /home/a/s.py --x", "python", "", "", "", false},
		{`py -3 C:\tools\s.py`, "python", "", "", "", false},
		// JavaScript runtimes
		{"node /usr/lib/node_modules/x/dist/index.js", "node", "", "", "", false},
		{"node --require ./pre.js build/index.js", "node", "", "", "", false},
		{"bun run /home/a/s.ts", "node", "", "", "", false},
		{"tsx src/index.ts", "node", "", "", "", false},
		{"deno run -A npm:@scope/pkg@1.2.3", "deno", "npm", "@scope/pkg", "1.2.3", true},
		{"deno run --allow-net npm:pkg", "deno", "npm", "pkg", "", false},
		{"deno run --allow-net jsr:@std/mcp@1.0.0", "deno", "", "jsr:@std/mcp", "1.0.0", true},
		{"deno run -A https://deno.land/x/mcp/mod.ts", "deno", "", "https://deno.land/x/mcp/mod.ts", "", false},
		{"deno run --allow-read ./main.ts", "deno", "", "", "", false},
		// Containers: only a digest pins.
		{"docker run -i --rm mcp/fetch", "docker", "oci", "mcp/fetch", "", false},
		{"docker run -i --rm mcp/fetch:latest", "docker", "oci", "mcp/fetch", "latest", false},
		{"docker run -i --rm mcp/fetch:1.2.3", "docker", "oci", "mcp/fetch", "1.2.3", false},
		{"docker run -i --rm ghcr.io/o/i@" + digest, "docker", "oci", "ghcr.io/o/i", digest, true},
		{"docker run -i --rm ghcr.io/o/i:1.2@" + digest, "docker", "oci", "ghcr.io/o/i", digest, true},
		{"docker run -i --rm ghcr.io/o/i@sha256:abcd", "docker", "oci", "ghcr.io/o/i", "sha256:abcd", false}, // truncated digest
		// The image is the first bare word after options that take values.
		{"docker run -i --rm -e K=V -v /a:/b --name x --network host img:2", "docker", "oci", "img", "2", false},
		{"docker run -ie K=V -v/a:/b img:2", "docker", "oci", "img", "2", false},
		{"docker run --env=K=V --rm img:2 --flag-for-server", "docker", "oci", "img", "2", false},
		{"docker run -i --rm registry.local:5000/team/img", "docker", "oci", "registry.local:5000/team/img", "", false},
		{"docker --context remote run -i img:1", "docker", "oci", "img", "1", false},
		{"docker container run -i img:1", "docker", "oci", "img", "1", false},
		{"podman run -i --rm quay.io/o/i:v2", "podman", "oci", "quay.io/o/i", "v2", false},
		{"docker exec -i ctr server", "docker", "", "", "", false},
		// Go
		{"go run github.com/o/r/cmd/x@v1.2.3", "binary", "", "github.com/o/r/cmd/x", "v1.2.3", true},
		{"go run github.com/o/r/cmd/x@latest", "binary", "", "github.com/o/r/cmd/x", "latest", false},
		{"go run ./cmd/x", "binary", "", "", "", false},
		// Wrappers are looked through.
		{"env FOO=bar npx -y pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"/usr/bin/env -u X uvx pkg", "uvx", "pypi", "pkg", "", false},
		{"sudo -u svc docker run -i img", "docker", "oci", "img", "", false},
		{"nohup nice -n 5 npx pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"timeout 30 npx -y pkg", "npx", "npm", "pkg", "", false},
		{"op run --env-file=.env -- npx -y pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"op run --env-file=.env npx", "binary", "", "", "", false}, // no "--": the wrapped command is not guessed
		{"doppler run -- uvx pkg==1.0", "uvx", "pypi", "pkg", "1.0", true},
		{"corepack pnpm dlx pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"wsl -d Ubuntu -- npx -y pkg", "npx", "npm", "pkg", "", false},
		{"wsl.exe npx -y pkg@1.0.0", "npx", "npm", "pkg", "1.0.0", true},
		{"cmd /c npx -y pkg", "npx", "npm", "pkg", "", false},
		{`cmd.exe /d /s /c "npx -y pkg@1.2.3"`, "npx", "npm", "pkg", "1.2.3", true},
		{`C:\Windows\System32\cmd.exe /C npx -y pkg@1.2.3`, "npx", "npm", "pkg", "1.2.3", true},
		{"bash -lc 'cd /srv/app && exec npx -y pkg@1.2.3 --flag'", "npx", "npm", "pkg", "1.2.3", true},
		{"sh -c 'pip install foo && python -m foo'", "pip", "pypi", "foo", "", false},
		{"sh -c 'FOO=1 (uvx pkg==1.0)'", "uvx", "pypi", "pkg", "1.0", true},
		{`powershell -NoProfile -ExecutionPolicy Bypass -Command "npx -y pkg"`, "npx", "npm", "pkg", "", false},
		// Plain programs
		{"mcp-thing --stdio", "binary", "", "", "", false},
		{"/home/a/.local/bin/mcp-thing --stdio", "binary", "", "", "", false},
		{"/Applications/My App.app/Contents/MacOS/server", "binary", "", "", "", false},
		{"java -jar /opt/x/server.jar", "binary", "", "", "", false},
		{`"C:\Program Files\nodejs\npx.cmd" -y pkg@1.2.3`, "npx", "npm", "pkg", "1.2.3", true},
		{`C:\Program Files\nodejs\npx.cmd -y pkg@1.2.3`, "npx", "npm", "pkg", "1.2.3", true},
		{"npx", "npx", "", "", "", false},
		{"docker", "docker", "", "", "", false},
		{"uvx --from", "uvx", "", "", "", false},
	}
	if len(cases) < 25 {
		t.Fatalf("matrix shrank to %d forms", len(cases))
	}
	for _, c := range cases {
		check := func(how string, s Server) {
			m := Normalize(s)
			if m.Runner != c.runner || m.Ecosystem != c.eco || m.Package != c.pkg || m.Version != c.version || m.Pinned != c.pinned {
				t.Errorf("%s [%s]\n  got  runner=%q eco=%q pkg=%q version=%q pinned=%v\n  want runner=%q eco=%q pkg=%q version=%q pinned=%v",
					c.line, how, m.Runner, m.Ecosystem, m.Package, m.Version, m.Pinned, c.runner, c.eco, c.pkg, c.version, c.pinned)
			}
		}
		check("one line", stdio(c.line))
		// The same launch as command + args, when the line splits cleanly.
		if !strings.ContainsAny(c.line, `'"`) && !strings.Contains(c.line, "My App") && !strings.Contains(c.line, "Program Files") {
			f := strings.Fields(c.line)
			check("argv", Server{Name: "t", Transport: "stdio", Command: f[0], Args: f[1:]})
		}
	}
}

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		line string
		cmd  string
		args []string
	}{
		{"npx -y pkg", "npx", []string{"-y", "pkg"}},
		{`"C:\Program Files\nodejs\node.exe" "C:\my srv\index.js"`, `C:\Program Files\nodejs\node.exe`, []string{`C:\my srv\index.js`}},
		{`C:\Program Files\nodejs\node.exe C:\srv\index.js`, `C:\Program Files\nodejs\node.exe`, []string{`C:\srv\index.js`}},
		{"/Applications/My App.app/Contents/MacOS/server", "/Applications/My App.app/Contents/MacOS/server", nil},
		{"/opt/My Tools/bin/srv --stdio", "/opt/My", []string{"Tools/bin/srv", "--stdio"}}, // ambiguous without the filesystem; the first word wins
		{`/usr/bin/python3 "/home/a/my server.py" --x`, "/usr/bin/python3", []string{"/home/a/my server.py", "--x"}},
		{`sh -c "echo 'a b' && npx x"`, "sh", []string{"-c", "echo 'a b' && npx x"}},
		{`path/with\ space arg`, "path/with space", []string{"arg"}},
		{`"quoted only"`, "quoted only", nil},
	}
	for _, c := range cases {
		cmd, args := splitCommandLine(c.line)
		if cmd != c.cmd {
			t.Errorf("%s: cmd %q, want %q", c.line, cmd, c.cmd)
		}
		eq(t, c.line+" args", args, c.args)
	}
	// A command with a space is left alone when args are given: the client
	// executes it as one path.
	s := Server{Transport: "stdio", Command: "/Applications/My App.app/Contents/MacOS/npx", Args: []string{"-y", "pkg"}}
	eq(t, "command with args", Normalize(s).Command, "/Applications/My App.app/Contents/MacOS/npx")
	eq(t, "runner by basename", Normalize(s).Runner, "npx")
}

func TestNormalizeFieldsAndBridge(t *testing.T) {
	en := true
	s := Server{
		Name: "gh", Transport: "stdio", Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"},
		Env:     map[string]string{"ZED": "1", "GITHUB_PERSONAL_ACCESS_TOKEN": "${GH}", "A": ""},
		Enabled: &en,
	}
	m := Normalize(s)
	eq(t, "command", m.Command, "npx")
	eq(t, "args", m.Args, []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"})
	eq(t, "env keys sorted", m.EnvKeys, []string{"A", "GITHUB_PERSONAL_ACCESS_TOKEN", "ZED"})
	eq(t, "enabled copied", *m.Enabled, true)
	en = false
	eq(t, "enabled is a copy", *m.Enabled, true)

	remote := Server{Transport: "http", URL: "HTTPS://User:pw@MCP.Example.com:8443/v1/mcp?x=1#frag", Headers: map[string]string{"X-B": "1", "Authorization": "Bearer ${T}"}}
	r := Normalize(remote)
	eq(t, "remote", []any{r.Transport, r.URLHost, r.URLPath, r.Runner, r.Command, r.Pinned}, []any{"http", "mcp.example.com", "/v1/mcp", "", "", false})
	eq(t, "header keys", r.HeaderKeys, []string{"Authorization", "X-B"})

	// A stdio bridge is inventoried with the endpoint it forwards to.
	for _, line := range []string{
		"npx -y mcp-remote https://mcp.remote.example/sse --transport sse-only",
		"npx -y mcp-remote@0.1.29 https://mcp.remote.example/sse",
		"npx -y supergateway --sse https://mcp.remote.example/sse",
		"uvx mcp-proxy https://mcp.remote.example/sse",
		"mcp-remote https://mcp.remote.example/sse",
	} {
		b := Normalize(stdio(line))
		eq(t, line, []any{b.Transport, b.URLHost, b.URLPath}, []any{"stdio", "mcp.remote.example", "/sse"})
	}
	// Only known bridges: a URL argument of another server is its data.
	eq(t, "not a bridge", Normalize(stdio("npx -y some-server --api https://api.example.com/v1")).URLHost, "")

	// A Server built by hand without a transport still normalizes.
	eq(t, "inferred stdio", Normalize(Server{Command: "x"}).Transport, "stdio")
	eq(t, "inferred http", Normalize(Server{URL: "https://x.example/mcp"}).Transport, "http")
	eq(t, "inferred ws", Normalize(Server{URL: "wss://x.example/s"}).Transport, "ws")
	eq(t, "empty", Normalize(Server{}).Transport, "stdio")
}

func TestNormalizeOutputBounds(t *testing.T) {
	args := make([]string, 300)
	for i := range args {
		args[i] = "a"
	}
	args[1] = strings.Repeat("é", 4000)
	env := map[string]string{}
	for i := 0; i < 500; i++ {
		env["K"+strings.Repeat("x", i%7)+string(rune('A'+i%26))+strings.Repeat("y", i/26)] = "v"
	}
	env[strings.Repeat("LONG", 200)] = "v"
	s := Server{Transport: "stdio", Command: "/opt/" + strings.Repeat("d/", 2000) + "srv", Args: args, Env: env}
	m := Normalize(s)
	if len(m.Args) != maxOutArgs+1 || m.Args[maxOutArgs] != "[+236 more]" {
		t.Errorf("args not capped visibly: %d elements, last %q", len(m.Args), m.Args[len(m.Args)-1])
	}
	for _, a := range m.Args {
		if len(a) > maxOutArg {
			t.Errorf("arg of %d bytes", len(a))
		}
	}
	if !strings.Contains(m.Args[1], "~") {
		t.Errorf("cut argument carries no fingerprint: %q", m.Args[1][len(m.Args[1])-20:])
	}
	if len(m.Command) > maxOutCommand {
		t.Errorf("command of %d bytes", len(m.Command))
	}
	if len(m.EnvKeys) != maxOutKeys+1 || !strings.HasPrefix(m.EnvKeys[maxOutKeys], "[+") {
		t.Errorf("env keys not capped visibly: %d", len(m.EnvKeys))
	}
	for _, k := range m.EnvKeys {
		if len(k) > maxOutKey {
			t.Errorf("env key of %d bytes", len(k))
		}
	}
	// The hash still covers everything that was cut from the record.
	s2 := s
	s2.Args = append([]string(nil), args...)
	s2.Args[299] = "b"
	if DefinitionHash(s) == DefinitionHash(s2) {
		t.Error("a change beyond the output cap did not change the definition hash")
	}
}

func BenchmarkNormalize(b *testing.B) {
	s := Server{Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"},
		Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Normalize(s)
	}
}
