package mcpconf

import (
	"regexp"
	"strings"
	"testing"
)

func TestDefinitionHashStableUnderReordering(t *testing.T) {
	a := `{"mcpServers": {
	  "s": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"A": "1", "B": "2", "C": "3"}, "type": "stdio"},
	  "r": {"type": "http", "url": "https://x.example/mcp", "headers": {"Authorization": "Bearer one", "X-Team": "a"}}
	}}`
	b := `{"mcpServers": {
	  "r": {"headers": {"X-Team": "a", "Authorization": "Bearer one"}, "url": "https://x.example/mcp", "type": "http"},
	  "s": {"type": "stdio", "env": {"C": "3", "A": "1", "B": "2"}, "args": ["-y", "pkg@1.0.0"], "command": "npx"}
	}}`
	sa := index(t, mustParse(t, "/a/.mcp.json", a, FormatMCPServers))
	sb := index(t, mustParse(t, "/b/elsewhere.json", b, FormatAuto))
	for _, name := range []string{"s", "r"} {
		ha, hb := DefinitionHash(sa["/a|"+name]), DefinitionHash(sb[name])
		if ha != hb {
			t.Errorf("%s: hash differs under key reordering / other source file: %s vs %s", name, ha, hb)
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(ha) {
			t.Errorf("%s: hash %q is not 64 hex digits", name, ha)
		}
	}
	// Hashing is repeatable (map iteration order must not leak in).
	for i := 0; i < 50; i++ {
		if DefinitionHash(sa["/a|s"]) != DefinitionHash(sb["s"]) {
			t.Fatal("hash is not deterministic")
		}
	}
}

func TestDefinitionHashSensitivity(t *testing.T) {
	tok1, tok2 := synth("rot1", 40, base62), synth("rot2", 40, base62)
	base := Server{
		Name: "s", SourcePath: "/a", Transport: "stdio", Command: "npx",
		Args: []string{"-y", "pkg@1.0.0", "--api-key", tok1, "--mode", "ro"},
		Env:  map[string]string{"TOKEN": tok1, "REGION": "eu"},
	}
	remote := Server{
		Transport: "http", URL: "https://user:" + tok1 + "@x.example:8443/mcp?access_token=" + tok1 + "&v=1",
		Headers: map[string]string{"Authorization": "Bearer " + tok1},
	}
	docker := Server{Transport: "stdio", Command: "docker", Args: []string{"run", "-i", "-e", "API_TOKEN=" + tok1, "--env", "MODE=" + tok1, "img:1"}}

	type mut func(s *Server)
	same := []struct {
		name string
		base Server
		f    mut
	}{
		{"env value rotates", base, func(s *Server) { s.Env = map[string]string{"TOKEN": tok2, "REGION": "eu"} }},
		{"env value of a non-secret changes", base, func(s *Server) { s.Env = map[string]string{"TOKEN": tok1, "REGION": "us"} }},
		{"secret flag value rotates", base, func(s *Server) { s.Args = []string{"-y", "pkg@1.0.0", "--api-key", tok2, "--mode", "ro"} }},
		{"name changes", base, func(s *Server) { s.Name = "renamed" }},
		{"source and project change", base, func(s *Server) { s.SourcePath, s.Project = "/b", "/p" }},
		{"enabled changes", base, func(s *Server) { off := false; s.Enabled = &off }},
		{"header value rotates", remote, func(s *Server) { s.Headers = map[string]string{"Authorization": "Bearer " + tok2} }},
		{"header name case", remote, func(s *Server) { s.Headers = map[string]string{"authorization": "Bearer " + tok1} }},
		{"url userinfo rotates", remote, func(s *Server) { s.URL = strings.Replace(s.URL, "user:"+tok1, "user:"+tok2, 1) }},
		{"url query rotates", remote, func(s *Server) { s.URL = strings.Replace(s.URL, "access_token="+tok1, "access_token="+tok2, 1) }},
		{"url fragment", remote, func(s *Server) { s.URL += "#x" }},
		{"docker -e value rotates", docker, func(s *Server) {
			s.Args = []string{"run", "-i", "-e", "API_TOKEN=" + tok2, "--env", "MODE=" + tok2, "img:1"}
		}},
	}
	for _, c := range same {
		m := c.base
		c.f(&m)
		if DefinitionHash(c.base) != DefinitionHash(m) {
			t.Errorf("%s: hash changed, a rotation would read as drift", c.name)
		}
	}

	differ := []struct {
		name string
		base Server
		f    mut
	}{
		{"command", base, func(s *Server) { s.Command = "bunx" }},
		{"package version", base, func(s *Server) { s.Args = []string{"-y", "pkg@1.0.1", "--api-key", tok1, "--mode", "ro"} }},
		{"plain flag value", base, func(s *Server) { s.Args = []string{"-y", "pkg@1.0.0", "--api-key", tok1, "--mode", "rw"} }},
		{"arg added", base, func(s *Server) { s.Args = append(append([]string{}, s.Args...), "--allow-all") }},
		{"arg order", base, func(s *Server) { s.Args = []string{"pkg@1.0.0", "-y", "--api-key", tok1, "--mode", "ro"} }},
		{"arg removed", base, func(s *Server) { s.Args = s.Args[:5] }},
		{"env name added", base, func(s *Server) { s.Env = map[string]string{"TOKEN": tok1, "REGION": "eu", "NODE_OPTIONS": ""} }},
		{"env name renamed", base, func(s *Server) { s.Env = map[string]string{"TOKEN2": tok1, "REGION": "eu"} }},
		{"transport", base, func(s *Server) { s.Transport = "http" }},
		{"url appears", base, func(s *Server) { s.URL = "https://x.example/mcp" }},
		{"url host", remote, func(s *Server) { s.URL = strings.Replace(s.URL, "x.example", "y.example", 1) }},
		{"url port", remote, func(s *Server) { s.URL = strings.Replace(s.URL, ":8443", ":9443", 1) }},
		{"url path", remote, func(s *Server) { s.URL = strings.Replace(s.URL, "/mcp", "/mcp2", 1) }},
		{"url scheme", remote, func(s *Server) { s.URL = strings.Replace(s.URL, "https://", "http://", 1) }},
		{"header name added", remote, func(s *Server) {
			s.Headers = map[string]string{"Authorization": "Bearer " + tok1, "X-Forward-To": "evil"}
		}},
		{"headers helper", remote, func(s *Server) { s.headersHelper = "/tmp/helper.sh" }},
		{"docker image", docker, func(s *Server) {
			s.Args = []string{"run", "-i", "-e", "API_TOKEN=" + tok1, "--env", "MODE=" + tok1, "img:2"}
		}},
		{"docker env name", docker, func(s *Server) {
			s.Args = []string{"run", "-i", "-e", "OTHER=" + tok1, "--env", "MODE=" + tok1, "img:1"}
		}},
		{"docker privilege", docker, func(s *Server) { s.Args = append([]string{"run", "--privileged"}, s.Args[1:]...) }},
	}
	for _, c := range differ {
		m := c.base
		c.f(&m)
		if DefinitionHash(c.base) == DefinitionHash(m) {
			t.Errorf("%s: hash did not change, drift would go unseen", c.name)
		}
	}
}

func TestDefinitionHashLoaderVariables(t *testing.T) {
	// The value of a code-loading variable is the hijack, so it counts.
	for _, name := range []string{"NODE_OPTIONS", "LD_PRELOAD", "PYTHONPATH", "PATH", "DYLD_INSERT_LIBRARIES", "node_options", "HTTPS_PROXY", "ANTHROPIC_BASE_URL"} {
		a := Server{Transport: "stdio", Command: "node", Args: []string{"s.js"}, Env: map[string]string{name: ""}}
		b := a
		b.Env = map[string]string{name: "--require=/tmp/evil.js"}
		if DefinitionHash(a) == DefinitionHash(b) {
			t.Errorf("%s: value change not reflected in the hash", name)
		}
	}
	// ...but a credential inside such a value still does not.
	a := Server{Transport: "stdio", Command: "uvx", Args: []string{"pkg"}, Env: map[string]string{"PIP_INDEX_URL": "https://u:" + synth("p1", 20, base62) + "@pypi.corp.example/simple"}}
	b := a
	b.Env = map[string]string{"PIP_INDEX_URL": "https://u:" + synth("p2", 20, base62) + "@pypi.corp.example/simple"}
	if DefinitionHash(a) != DefinitionHash(b) {
		t.Error("PIP_INDEX_URL: rotating the index password changed the hash")
	}
	c := a
	c.Env = map[string]string{"PIP_INDEX_URL": "https://u:x@pypi.evil.example/simple"}
	if DefinitionHash(a) == DefinitionHash(c) {
		t.Error("PIP_INDEX_URL: pointing at another index did not change the hash")
	}
	// Inline code is not a credential slot, even after a flag named -e.
	n1 := Server{Transport: "stdio", Command: "node", Args: []string{"-e", "x=require('fs')"}}
	n2 := Server{Transport: "stdio", Command: "node", Args: []string{"-e", "x=require('child_process')"}}
	if DefinitionHash(n1) == DefinitionHash(n2) {
		t.Error("node -e: inline code change not reflected in the hash")
	}
}

func TestDefinitionHashFraming(t *testing.T) {
	pairs := [][2]Server{
		{{Command: "x", Args: []string{"ab", "c"}}, {Command: "x", Args: []string{"a", "bc"}}},
		{{Command: "x", Args: []string{"a"}}, {Command: "x a"}},
		{{Command: "x", Args: []string{""}}, {Command: "x"}},
		{{Command: "x", Env: map[string]string{"A": "", "B": ""}}, {Command: "x", Env: map[string]string{"AB": ""}}},
		{{Command: "x", Env: map[string]string{"A": ""}}, {Command: "x", Args: []string{"A"}}},
		{{URL: "https://x.example/", Headers: map[string]string{"a": ""}}, {URL: "https://x.example/a"}},
	}
	for i, p := range pairs {
		if DefinitionHash(p[0]) == DefinitionHash(p[1]) {
			t.Errorf("pair %d: different declarations share a hash", i)
		}
	}
	if DefinitionHash(Server{}) == "" {
		t.Error("empty server has no hash")
	}
}

func TestDefinitionHashFromRotatedFile(t *testing.T) {
	// End to end: the same config with every credential rotated.
	doc := func(tok string) string {
		return `{"mcpServers": {
		  "a": {"command": "npx", "args": ["-y", "pkg@1.0.0", "--token", "` + tok + `"], "env": {"API_KEY": "` + tok + `"}},
		  "b": {"type": "http", "url": "https://x.example/mcp?key=` + tok + `", "headers": {"X-Api-Key": "` + tok + `"}},
		  "c": {"command": "npx", "args": ["-y", "mcp-remote", "https://r.example/sse", "--header", "Authorization: Bearer ` + tok + `"]},
		  "d": {"command": "sh", "args": ["-c", "API_TOKEN=` + tok + ` exec npx -y pkg@1.0.0"]}
		}}`
	}
	one := mustParse(t, "/a.json", doc(synth("f1", 40, base62)), FormatMCPServers)
	two := mustParse(t, "/a.json", doc(synth("f2", 40, base62)), FormatMCPServers)
	for i := range one {
		if DefinitionHash(one[i]) != DefinitionHash(two[i]) {
			t.Errorf("%s: hash changed when only the credential rotated", one[i].Name)
		}
	}
}
