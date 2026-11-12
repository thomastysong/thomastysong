package mcpconf

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// within fails the test when f takes longer than limit. The limits are far
// above normal run time; they exist to catch quadratic behaviour, not to
// benchmark.
func within(t *testing.T, what string, limit time.Duration, f func()) {
	t.Helper()
	start := time.Now()
	f()
	if d := time.Since(start); d > limit {
		t.Errorf("%s took %s (limit %s)", what, d, limit)
	}
}

// TestHostileNesting feeds inputs that crash or exhaust naive use of the
// decoders. Each must come back as an error, quickly.
func TestHostileNesting(t *testing.T) {
	const deep = 3_000_000 // enough to overflow the stack of an unguarded recursive decoder
	cases := []struct{ name, path, doc string }{
		{"json arrays", "/a.json", strings.Repeat("[", deep)},
		{"json objects", "/a.json", strings.Repeat(`{"a":`, deep/5)},
		{"toml arrays", "/a.toml", "a = " + strings.Repeat("[", deep)},
		{"toml arrays on lines", "/a.toml", "a = [\n" + strings.Repeat("[\n", deep/2)},
		{"toml inline tables", "/a.toml", "a = " + strings.Repeat("{b=", deep/3)},
		{"toml mixed", "/a.toml", "a = " + strings.Repeat("[{b=", deep/4)},
		// A scanner that mis-tracks strings can be made to skip the brackets.
		{"toml after 4-quote close", "/a.toml", `a = ["""x"""", ` + strings.Repeat("[", deep)},
		{"toml after 5-quote close", "/a.toml", `a = ['''x''''', ` + strings.Repeat("[", deep)},
		{"toml after escaped quote", "/a.toml", `a = ["\"", ` + strings.Repeat("[", deep)},
		{"toml after escaped backslash", "/a.toml", `a = ["\\", ` + strings.Repeat("[", deep)},
		{"toml after literal backslash", "/a.toml", `a = ['\', ` + strings.Repeat("[", deep)},
		{"toml after hash in string", "/a.toml", `a = ["#", ` + strings.Repeat("[", deep)},
		{"toml after quoted key", "/a.toml", `"a#b" = ` + strings.Repeat("[", deep)},
		{"toml after comment with quote", "/a.toml", "# it's\na = " + strings.Repeat("[", deep)},
		{"toml after empty strings", "/a.toml", `a = ["", '', ` + strings.Repeat("[", deep)},
		// Quadratic memory in the decoder: 64 KiB of dotted key costs gigabytes.
		{"toml dotted key", "/a.toml", strings.Repeat("a.", 40_000) + "a = 1\n"},
		{"toml dotted header", "/a.toml", "[" + strings.Repeat("a.", 40_000) + "a]\n"},
		{"toml dotted array header", "/a.toml", "[[" + strings.Repeat("a.", 40_000) + "a]]\n"},
		{"toml dotted quoted key", "/a.toml", strings.Repeat(`"a".`, 40_000) + "a = 1\n"},
		{"toml dotted spaced key", "/a.toml", strings.Repeat("a . ", 40_000) + "a = 1\n"},
		{"toml dotted inline key", "/a.toml", "x = {" + strings.Repeat("a.", 40_000) + "a = 1}\n"},
		{"toml dotted key after value", "/a.toml", "x = 1\n\n  " + strings.Repeat("a.", 40_000) + "a = 1\n"},
		{"toml dotted key after array", "/a.toml", "x = [1,\n2]\n" + strings.Repeat("a.", 40_000) + "a = 1\n"},
		{"toml dotted key after comment", "/a.toml", "x = 1 # c\n" + strings.Repeat("a.", 40_000) + "a = 1\n"},
		{"toml dotted key after inline table", "/a.toml", "x = {a = {b = 1}, " + strings.Repeat("c.", 40_000) + "c = 2}\n"},
		{"yaml flow", "/a.yaml", "a: " + strings.Repeat("[", deep)},
		{"yaml block", "/a.yaml", strings.Repeat("- ", 20_000) + "x"},
		{"yaml alias bomb", "/a.yaml", yamlBomb(9, 12)},
		{"yaml alias chain", "/a.yaml", yamlChain(40, 400)},
		{"yaml wide alias", "/a.yaml", yamlWide(20_000, 99)},
		{"yaml big scalar behind aliases", "/a.yaml", yamlBigScalar(256<<10, 500)},
		{"yaml self reference", "/a.yaml", "a: &a [*a]\n"},
		{"yaml unknown alias", "/a.yaml", "a: *nope\n"},
		// Linear but large: a budget on the number of values.
		{"json many values", "/a.json", "[" + strings.Repeat("[],", 2_100_000) + "[]]"},
		{"toml many values", "/a.toml", "a = [" + strings.Repeat("1,", 2_100_000) + "1]\n"},
		{"yaml many values", "/a.yaml", "a: [" + strings.Repeat("x,", 600_000) + "x]\n"},
	}
	for _, c := range cases {
		within(t, c.name, 20*time.Second, func() {
			for _, f := range []Format{FormatAuto, FormatCodexTOML, FormatGoose, FormatMCPServers} {
				ss, err := Parse(c.path, []byte(c.doc), f)
				var se *SyntaxError
				if !errors.As(err, &se) || ss != nil {
					t.Errorf("%s (%q): got (%d servers, %v), want a *SyntaxError", c.name, f, len(ss), err)
				}
			}
		})
	}
}

func yamlBomb(width, depth int) string {
	var b strings.Builder
	b.WriteString("a0: &a0 [" + strings.TrimSuffix(strings.Repeat("x,", width), ",") + "]\n")
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*a%d,", i-1), width), ","))
	}
	return b.String()
}

func yamlChain(anchors, depth int) string {
	var b strings.Builder
	b.WriteString("a0: &a0 " + strings.Repeat("[", depth) + "x" + strings.Repeat("]", depth) + "\n")
	for i := 1; i < anchors; i++ {
		fmt.Fprintf(&b, "a%d: &a%d %s*a%d%s\n", i, i, strings.Repeat("[", depth), i-1, strings.Repeat("]", depth))
	}
	return b.String()
}

func yamlWide(n, refs int) string {
	var b strings.Builder
	b.WriteString("big: &big [" + strings.TrimSuffix(strings.Repeat("x,", n), ",") + "]\n")
	for i := 0; i < refs; i++ {
		fmt.Fprintf(&b, "r%d: *big\n", i)
	}
	return b.String()
}

func yamlBigScalar(size, refs int) string {
	var b strings.Builder
	b.WriteString("big: &big \"" + strings.Repeat("s", size) + "\"\nmcpServers:\n")
	for i := 0; i < refs; i++ {
		fmt.Fprintf(&b, "  s%d: {command: x, args: [*big], env: {K: *big}}\n", i)
	}
	return b.String()
}

// TestGuardsDoNotRejectRealConfigs checks the other direction: brackets and
// dots that are not nesting, and legitimate uses of what the guards bound.
func TestGuardsDoNotRejectRealConfigs(t *testing.T) {
	toml := `# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[
title = "` + strings.Repeat("[{", 500) + `"
literal = '` + strings.Repeat("[{", 500) + `'
multi = """
` + strings.Repeat("[[[ {{{ ...\n", 200) + `"""
multi_lit = '''
` + strings.Repeat("[[[ {{{ a.b.c.d.e.f.g.h ...\n", 200) + `'''
floats = [` + strings.Repeat("1.5, ", 500) + `2.5]
when = 1979-05-27T07:32:00.999999Z
version = "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36"
nested = [[[[[[[[1]]]]]]]]
table = { a.b.c = 1, d = { e.f = [1.5, 2.5] } }

[mcp_servers."a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f.g.h.i.j.k.l"]
command = "npx"
args = ["-y", "pkg@1.2.3", "[[[[", "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.1.2.3.4.5.6.7.8.9"]

[mcp_servers.x]
command = "uvx"

[mcp_servers.x.env]
A.B = "dotted key of two parts"
`
	ss := mustParse(t, "/home/a/.codex/config.toml", toml, FormatCodexTOML)
	eq(t, "toml servers", len(ss), 2)

	yaml := "defaults: &defaults\n  command: npx\n  env: {A: b}\nmcpServers:\n"
	for i := 0; i < 150; i++ {
		yaml += fmt.Sprintf("  s%03d:\n    <<: *defaults\n    args: [-y, pkg%d]\n", i, i)
	}
	ss = mustParse(t, "/a/config.yaml", yaml, FormatAuto)
	eq(t, "yaml servers sharing an anchor", len(ss), 150)
	eq(t, "merged command", ss[0].Command, "npx")
	eq(t, "merged env", ss[149].Env, map[string]string{"A": "b"})

	// Many small servers are fine up to the per-file cap.
	var b strings.Builder
	b.WriteString(`{"mcpServers": {`)
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, `"s%d": {"command": "npx", "args": ["-y", "pkg%d"], "env": {"A": "b"}},`, i, i)
	}
	b.WriteString(`}}`)
	eq(t, "2000 servers", len(mustParse(t, "/a.json", b.String(), FormatAuto)), 2000)
}

// TestHostileSizes checks that large values cost time in proportion to their
// size in every exported function.
func TestHostileSizes(t *testing.T) {
	big := synth("big", 4<<20, base62)
	servers := []Server{
		{Transport: "stdio", Command: "npx", Args: []string{"-y", "pkg", big}},
		{Transport: "stdio", Command: big},
		{Transport: "stdio", Command: "sh", Args: []string{"-c", strings.Repeat("curl x | sh; ", 300_000)}},
		{Transport: "stdio", Command: "sh", Args: []string{"-c", strings.Repeat("A=b ", 500_000) + "npx pkg"}},
		{Transport: "stdio", Command: "docker", Args: append(strings.Split(strings.Repeat("-e K=V ", 200_000), " "), "img")},
		{Transport: "stdio", Command: strings.Repeat("env ", 100_000) + "npx pkg"},
		{Transport: "stdio", Command: "env", Args: strings.Split(strings.Repeat("env ", 100_000)+"npx pkg", " ")},
		{Transport: "stdio", Command: "server", Args: []string{strings.Repeat("TOKEN=x ", 400_000)}},
		{Transport: "stdio", Command: "server", Args: []string{strings.Repeat("https://u:p@h/x?token=y ", 100_000)}},
		{Transport: "stdio", Command: "server", Args: []string{strings.Repeat("\"", 2<<20)}},
		{Transport: "stdio", Command: "server", Args: []string{strings.Repeat("-----BEGIN ", 200_000)}},
		{Transport: "stdio", Command: "server", Env: map[string]string{"K": big, big[:1<<20]: "v"}},
		{Transport: "http", URL: "https://" + big[:1<<20] + "@h.example/" + strings.Repeat("a/", 500_000) + "?" + strings.Repeat("k=v&", 500_000)},
		{Transport: "http", URL: strings.Repeat("@", 1<<20), Headers: map[string]string{big[:1<<20]: big}},
		{Transport: "http", URL: "https://h.example/mcp", headersHelper: big, oauthSecret: big},
		{Name: big, SourcePath: big, Project: big, Transport: big[:1<<20], Command: "x"},
	}
	for i, s := range servers {
		within(t, fmt.Sprintf("server %d", i), 30*time.Second, func() {
			m := Normalize(s)
			flags := RiskFlags(s)
			h := DefinitionHash(s)
			if len(h) != 64 {
				t.Errorf("server %d: hash %q", i, h)
			}
			if len(m.Args) > maxOutArgs+1 || len(m.Command) > maxOutCommand || len(m.URLPath) > maxOutPath || len(m.URLHost) > maxOutHost || len(m.Package) > maxOutPackage || len(m.Version) > maxOutVersion {
				t.Errorf("server %d: unbounded output", i)
			}
			for _, a := range m.Args {
				if len(a) > maxOutArg {
					t.Errorf("server %d: argument of %d bytes emitted", i, len(a))
				}
			}
			for _, k := range append(append([]string{}, m.EnvKeys...), m.HeaderKeys...) {
				if len(k) > maxOutKey {
					t.Errorf("server %d: key of %d bytes emitted", i, len(k))
				}
			}
			for _, f := range flags {
				if !knownFlag(f) {
					t.Errorf("server %d: unknown flag %q", i, f)
				}
			}
		})
	}

	// A near-limit file of ordinary shape parses in reasonable time.
	var b strings.Builder
	b.WriteString(`{"history": ["`)
	b.WriteString(big)
	b.WriteString(`"], "mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg", "`)
	b.WriteString(big)
	b.WriteString(`"]}}}`)
	within(t, "8 MiB file", 20*time.Second, func() {
		ss := mustParse(t, "/home/a/.claude.json", b.String(), FormatClaudeJSON)
		if len(ss) != 1 || len(ss[0].Args) != 3 {
			t.Errorf("got %d servers", len(ss))
		}
	})
}

func knownFlag(f string) bool {
	switch f {
	case RiskUnpinnedPackage, RiskRemoteFetchExec, RiskInlineSecret, RiskPlaintextTransport, RiskDeprecatedTransport,
		RiskShellWrapper, RiskBroadFilesystem, RiskLocalScript, RiskTokenInURL, RiskDockerPrivileged, RiskDockerSocket:
		return true
	}
	return false
}

// prng is a small deterministic generator so failures reproduce.
type prng uint64

func (p *prng) next() uint64 {
	*p = *p*6364136223846793005 + 1442695040888963407
	return uint64(*p >> 17)
}
func (p *prng) intn(n int) int { return int(p.next() % uint64(n)) }

var fuzzAlphabet = []string{
	"{", "}", "[", "]", ":", ",", "\"", "'", "\\", "\n", "\r\n", " ", "\t", "#", "//", "/*", "*/", "=", ".", "-", "&", "*", "!", "|", ">", "<", "%", "@", "`", "?", "~", "$", "(", ")", ";",
	"\x00", "\xff", "\xfe", "\xef\xbb\xbf", "\xc3", "\xed\xa0\x80", "\u202e", "\U000e0041",
	"mcpServers", "mcp_servers", "servers", "mcp", "context_servers", "extensions", "projects", "command", "cmd", "args", "env", "envs", "url", "uri", "type",
	"headers", "transport", "stdio", "http", "sse", "true", "false", "null", "0", "1e999", "-0", "npx", "docker", "run", "-e", "-v", "-y", "--", "sh", "-c", "cmd", "/c",
	"<<", "&a", "*a", "---", "...", "!!binary", "!!python/object", "0x", "\"\"\"", "'''", "[[", "]]", "@sha256:", "@latest", "==", "://", "${", "}}", "%s", "../",
}

func randomDoc(p *prng, n int) []byte {
	var b []byte
	for i := 0; i < n; i++ {
		if p.intn(4) == 0 {
			b = append(b, byte(p.next()))
		} else {
			b = append(b, fuzzAlphabet[p.intn(len(fuzzAlphabet))]...)
		}
	}
	return b
}

func mutate(p *prng, doc []byte) []byte {
	out := append([]byte(nil), doc...)
	for k := 0; k < 1+p.intn(6) && len(out) > 0; k++ {
		i := p.intn(len(out))
		switch p.intn(6) {
		case 0:
			out[i] = byte(p.next())
		case 1:
			out = out[:i]
		case 2:
			out = append(out[:i:i], out[p.intn(len(out)-i)+i:]...)
		case 3:
			tok := fuzzAlphabet[p.intn(len(fuzzAlphabet))]
			out = append(out[:i:i], append([]byte(tok), out[i:]...)...)
		case 4:
			j := p.intn(len(out))
			out[i], out[j] = out[j], out[i]
		case 5:
			out = append(out, out[i:]...)
		}
	}
	return out
}

var allFormats = []Format{FormatAuto, FormatMCPServers, FormatClaudeJSON, FormatVSCode, FormatZed, FormatCodexTOML, FormatOpenCode, FormatContinue, FormatGoose}

var fuzzPaths = []string{"/a/.mcp.json", "/a/config.toml", "/a/config.yaml", "/a/settings.jsonc", "/a/noext", `C:\a\.vscode\mcp.json`, ""}

// exercise runs everything a caller would run on a document. It returns
// nothing: the assertion is that it returns at all, without a panic.
func exercise(t *testing.T, path string, doc []byte, f Format) {
	t.Helper()
	ss, err := Parse(path, doc, f)
	if err != nil && !errors.Is(err, ErrTooManyServers) && ss != nil {
		t.Fatalf("servers returned together with error %v", err)
	}
	if len(ss) > MaxServers {
		t.Fatalf("%d servers", len(ss))
	}
	for _, s := range ss {
		if s.SourcePath != path {
			t.Fatalf("SourcePath %q", s.SourcePath)
		}
		switch s.Transport {
		case "stdio", "http", "sse", "ws":
		default:
			t.Fatalf("transport %q outside the vocabulary", s.Transport)
		}
		if strings.TrimSpace(s.Command) == "" && s.URL == "" && len(s.Env) == 0 {
			t.Fatalf("server %q declares nothing", s.Name)
		}
		m := Normalize(s)
		for _, f := range RiskFlags(s) {
			if !knownFlag(f) {
				t.Fatalf("flag %q outside the vocabulary", f)
			}
		}
		if h := DefinitionHash(s); len(h) != 64 {
			t.Fatalf("hash %q", h)
		}
		switch m.AuthMode {
		case "none", "env", "header", "oauth", "inherited":
		default:
			t.Fatalf("auth mode %q outside the vocabulary", m.AuthMode)
		}
		switch m.Runner {
		case "", "npx", "bunx", "uvx", "pipx", "pip", "docker", "podman", "node", "python", "deno", "binary":
		default:
			t.Fatalf("runner %q outside the vocabulary", m.Runner)
		}
		switch m.Ecosystem {
		case "", "npm", "pypi", "oci":
		default:
			t.Fatalf("ecosystem %q outside the vocabulary", m.Ecosystem)
		}
	}
}

// TestRandomDocuments is the fuzz-style test: random bytes and mutated
// fixtures through every format, with a bound on total time.
func TestRandomDocuments(t *testing.T) {
	seeds := [][]byte{
		[]byte(fixtureMCPServers), []byte(fixtureClaudeJSON), []byte(fixtureJSONC), []byte(fixtureVSCode),
		[]byte(fixtureZed), []byte(fixtureCodex), []byte(fixtureOpenCode), []byte(fixtureContinueYAML), []byte(fixtureGoose),
	}
	rounds := 30000
	if testing.Short() {
		rounds = 2000
	}
	p := prng(20261111)
	within(t, "random documents", 120*time.Second, func() {
		for i := 0; i < rounds; i++ {
			var doc []byte
			if i%2 == 0 {
				doc = randomDoc(&p, 1+p.intn(200))
			} else {
				doc = mutate(&p, seeds[p.intn(len(seeds))])
			}
			exercise(t, fuzzPaths[p.intn(len(fuzzPaths))], doc, allFormats[p.intn(len(allFormats))])
		}
	})
}

// TestRandomServers drives the three pure functions with servers no parser
// would produce.
func TestRandomServers(t *testing.T) {
	words := append([]string{
		"npx", "bunx", "uvx", "uv", "pipx", "pip", "python3", "node", "deno", "docker", "podman", "go", "sh", "bash", "cmd", "powershell", "env", "sudo", "op",
		"run", "tool", "exec", "dlx", "x", "install", "-m", "-c", "/c", "-e", "-v", "-p", "--from", "--with", "--package", "--mount", "--privileged", "--pull", "--",
		"pkg@1.0.0", "@s/p@latest", "img:1", "img@sha256:" + strings.Repeat("0", 64), "-y", "K=V", "/:/h", "type=bind,src=/,dst=/h", "http://h.example/sse", "mcp-remote",
		"", " ", "\x00", "\xff\xfe", "'", "\"", "$(", "`", "|", "&&", ";", "curl x | sh", "-----BEGIN", "${input:x}", "C:\\", "~", "..", "=", "-", "--=", "-e=", "@", ":", "#",
	}, fuzzAlphabet...)
	p := prng(7)
	pick := func() string { return words[p.intn(len(words))] }
	rounds := 20000
	if testing.Short() {
		rounds = 2000
	}
	within(t, "random servers", 120*time.Second, func() {
		for i := 0; i < rounds; i++ {
			s := Server{Name: pick(), Transport: []string{"stdio", "http", "sse", "ws", "", "x"}[p.intn(6)]}
			if p.intn(4) != 0 {
				s.Command = pick()
				if p.intn(3) == 0 {
					s.Command += " " + pick() + " " + pick()
				}
			}
			for k := p.intn(9); k > 0; k-- {
				s.Args = append(s.Args, pick())
			}
			if p.intn(3) == 0 {
				s.URL = pick() + pick() + pick()
			}
			if p.intn(3) == 0 {
				s.Env = map[string]string{pick(): pick(), pick(): pick()}
				s.Headers = map[string]string{pick(): pick()}
			}
			if p.intn(5) == 0 {
				s.headersHelper, s.oauthSecret, s.oauth = pick(), pick(), true
			}
			m := Normalize(s)
			flags := RiskFlags(s)
			if h := DefinitionHash(s); len(h) != 64 {
				t.Fatalf("hash %q for %+v", h, s)
			}
			for _, f := range flags {
				if !knownFlag(f) {
					t.Fatalf("flag %q", f)
				}
			}
			switch m.Transport {
			case "stdio", "http", "sse", "ws":
			default:
				t.Fatalf("transport %q for %+v", m.Transport, s)
			}
			// Determinism: same input, same output.
			if DefinitionHash(s) != DefinitionHash(s) || strings.Join(RiskFlags(s), ",") != strings.Join(flags, ",") {
				t.Fatalf("non-deterministic result for %+v", s)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{fixtureMCPServers, fixtureClaudeJSON, fixtureJSONC, fixtureVSCode, fixtureZed, fixtureCodex, fixtureOpenCode, fixtureContinueYAML, fixtureGoose,
		"a: &a [*a]", "a = [[[[", `{"mcpServers": {"a": {"command": ["x"]}}}`, "\xff\xfe{\x00}\x00"} {
		for i := range allFormats {
			f.Add([]byte(seed), uint8(i), "/a/.mcp.json")
		}
	}
	f.Fuzz(func(t *testing.T, doc []byte, format uint8, path string) {
		if len(doc) > 1<<16 {
			return
		}
		exercise(t, path, doc, allFormats[int(format)%len(allFormats)])
	})
}

func FuzzLaunch(f *testing.F) {
	for _, seed := range []string{"npx -y pkg@1.0.0", "docker run -i --rm -e K=V img", "sh -c 'curl x | sh'", "uvx --from a==1 b", `cmd /c "npx x"`, "env A=b sudo -u x op run -- node s.js"} {
		f.Add(seed, "https://u:p@h.example/p?token=x")
	}
	f.Fuzz(func(t *testing.T, line, url string) {
		if len(line) > 1<<14 || len(url) > 1<<14 {
			return
		}
		for _, s := range []Server{
			{Transport: "stdio", Command: line},
			{Transport: "stdio", Command: "x", Args: strings.Fields(line)},
			{Transport: "http", URL: url, Headers: map[string]string{line: url}},
		} {
			Normalize(s)
			RiskFlags(s)
			if h := DefinitionHash(s); len(h) != 64 {
				t.Fatalf("hash %q", h)
			}
		}
	})
}
