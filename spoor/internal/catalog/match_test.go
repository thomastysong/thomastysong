package catalog

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func mustLoad(t testing.TB) *Catalog {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestMatchProcess(t *testing.T) {
	c := mustLoad(t)
	tests := []struct {
		desc string
		name string
		exe  string
		args []string
		want string // product id, "" for no match
		ev   string // an evidence class that must be reported, "" to skip
	}{
		// --- the cases named in the spec -------------------------------
		{"goose in /usr/games is a game, not an agent",
			"goose", "/usr/games/goose", []string{"goose"}, "", ""},
		{"node running the claude-code package entry point",
			"node", "/usr/bin/node", []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, "claude-code", EvidencePackagePath},

		// --- claude -----------------------------------------------------
		{"native install: comm is the symlink name, exe the version file",
			"claude", "/home/dev/.local/share/claude/versions/2.1.322", []string{"claude", "-p", "hi"}, "claude-code", EvidencePath},
		{"native install without exe (unreadable /proc/pid/exe)",
			"claude", "", []string{"claude"}, "claude-code", EvidenceProcessName},
		{"npm install: native binary inside the package",
			"claude", "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", []string{"claude"}, "claude-code", EvidencePackagePath},
		{"npm platform package",
			"node", "/usr/bin/node", []string{"node", "/opt/n/lib/node_modules/@anthropic-ai/claude-code-linux-x64/cli.js"}, "claude-code", EvidenceArgs},
		{"windows native install",
			"claude.exe", `C:\Users\dev\.local\bin\claude.exe`, []string{`C:\Users\dev\.local\bin\claude.exe`}, "claude-code", EvidencePath},
		{"Claude Desktop on macOS wins on exact case and path",
			"Claude", "/Applications/Claude.app/Contents/MacOS/Claude", nil, "claude-desktop", EvidencePath},
		{"Claude Desktop helper process",
			"Claude Helper (Renderer)", "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)", nil, "claude-desktop", EvidencePath},
		{"Claude Desktop in ~/Applications",
			"Claude", "/Users/dev/Applications/Claude.app/Contents/MacOS/Claude", nil, "claude-desktop", EvidencePath},
		{"claude.exe with no path prefers the agent",
			"claude.exe", "", nil, "claude-code", ""},
		{"bundled CLI of the Claude Agent SDK",
			"python3", "/usr/bin/python3.12", []string{"python3", "-c", "x", "/app/.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude"}, "claude-agent-sdk", EvidenceArgs},
		{"editor opening the package file is not the agent",
			"vim", "/usr/bin/vim", []string{"vim", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, "", ""},
		{"cat of a transcript is not the agent",
			"cat", "/usr/bin/cat", []string{"cat", "/home/dev/.claude/projects/x/y.jsonl"}, "", ""},

		// --- codex, copilot, gemini --------------------------------------
		{"codex native", "codex", "/opt/homebrew/Caskroom/codex/0.167.1/bin/codex", []string{"codex", "exec", "x"}, "codex", EvidencePackagePath},
		{"codex via npm shim", "node", "/usr/local/bin/node", []string{"node", "/usr/local/bin/codex", "--yolo"}, "codex", EvidenceScriptName},
		{"codex via npx", "node", "/usr/bin/node", []string{"node", "/usr/bin/npx", "-y", "@openai/codex@latest"}, "codex", EvidenceArgs},
		{"npm exec with rewritten title", "npm exec @opena", "/usr/bin/node", []string{"npm exec @openai/codex"}, "codex", EvidenceArgs},
		{"ChatGPT.app", "ChatGPT", "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", nil, "chatgpt", EvidencePath},
		{"copilot alone is ambiguous (AWS Copilot CLI)", "copilot", "/usr/local/bin/copilot", []string{"copilot", "svc", "deploy"}, "", ""},
		{"copilot from the GitHub cask", "copilot", "/opt/homebrew/Caskroom/copilot-cli/1.0.109/copilot", []string{"copilot"}, "copilot-cli", EvidencePackagePath},
		{"copilot from the npm package", "node", "/usr/bin/node", []string{"node", "/usr/lib/node_modules/@github/copilot/npm-loader.js"}, "copilot-cli", EvidencePackagePath},
		{"copilot via npm shim", "node", "/usr/bin/node", []string{"node", "/usr/local/bin/copilot", "--allow-all"}, "copilot-cli", EvidenceScriptName},
		{"copilot from winget", "copilot.exe", `C:\Users\dev\AppData\Local\Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe`, nil, "copilot-cli", EvidencePackagePath},
		{"gemini alone is ambiguous (MacPaw Gemini)", "Gemini", "/Applications/Gemini 2.app/Contents/MacOS/Gemini", nil, "", ""},
		{"Google Gemini desktop app", "Gemini", "/Applications/Gemini.app/Contents/MacOS/Gemini", nil, "gemini-app", EvidencePath},
		{"gemini cli via npm shim", "node", "/usr/bin/node", []string{"node", "/home/dev/.nvm/versions/node/v22.1.0/bin/gemini", "--yolo"}, "gemini-cli", EvidenceScriptName},
		{"gemini cli bundle", "node", "/usr/bin/node", []string{"node", "--no-warnings", "/usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js"}, "gemini-cli", EvidencePackagePath},
		{"somebody's gemini.js is not Gemini CLI", "node", "/usr/bin/node", []string{"node", "gemini.js"}, "", ""},
		{"python script named gemini is not the npm CLI", "python3", "/usr/bin/python3", []string{"python3", "/home/dev/bin/gemini"}, "", ""},

		// --- cursor ---------------------------------------------------------
		{"Cursor IDE", "Cursor", "/Applications/Cursor.app/Contents/MacOS/Cursor", nil, "cursor", EvidencePath},
		{"Cursor on Windows", "Cursor.exe", `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`, nil, "cursor", EvidenceProcessName},
		{"cursor-agent", "cursor-agent", "/home/dev/.local/share/cursor-agent/versions/2026.10.01/cursor-agent", nil, "cursor-agent", EvidencePath},
		{"agent alone is ambiguous", "agent", "/usr/local/bin/agent", []string{"agent"}, "", ""},
		{"agent under cursor-agent versions", "agent", "/home/dev/.local/share/cursor-agent/versions/2026.10.01/agent", nil, "cursor-agent", EvidencePath},
		{"agent under ~/.grok/bin is Grok Build", "agent", "/home/dev/.grok/bin/agent", nil, "grok-build", EvidencePath},

		// --- ambiguous short names ------------------------------------------
		{"goose from the Block formula", "goose", "/opt/homebrew/Cellar/block-goose-cli/1.9.0/bin/goose", []string{"goose", "session"}, "goose", EvidencePackagePath},
		{"goose the migration tool", "goose", "/opt/homebrew/Cellar/goose/3.24.1/bin/goose", []string{"goose", "up"}, "", ""},
		{"goose from the install script", "goose", "/home/dev/.local/bin/goose", []string{"goose"}, "goose", EvidencePath},
		{"Goose desktop on Windows", "Goose.exe", `C:\Users\dev\AppData\Local\Programs\Goose\Goose.exe`, nil, "goose-desktop", EvidencePath},
		{"amp the editor", "amp", "/opt/homebrew/bin/amp", []string{"amp", "file.txt"}, "", ""},
		{"amp the agent via npm shim", "node", "/usr/bin/node", []string{"node", "/usr/local/bin/amp"}, "amp", EvidenceScriptName},
		{"amp the agent, package path", "node", "/usr/bin/node", []string{"node", "/usr/lib/node_modules/@ampcode/cli/dist/main.js"}, "amp", EvidencePackagePath},
		{"q the DNS client", "q", "/opt/homebrew/bin/q", []string{"q", "example.com"}, "", ""},
		{"two-letter names are always ambiguous", "cn", "/usr/local/bin/cn", nil, "", ""},
		{"cn via its npm package", "node", "/usr/bin/node", []string{"node", "/usr/lib/node_modules/@continuedev/cli/dist/index.js"}, "continue-cli", EvidencePackagePath},
		{"zed the ZFS daemon", "zed", "/usr/sbin/zed", []string{"/usr/sbin/zed", "-F"}, "", ""},
		{"Zed the editor", "zed", "/Applications/Zed.app/Contents/MacOS/zed", nil, "zed", EvidencePath},
		{"code shim of another editor", "code", "/usr/local/bin/code", nil, "", ""},
		{"VS Code", "Code", "/Applications/Visual Studio Code.app/Contents/MacOS/Code", nil, "vscode", EvidencePath},
		{"VS Code main process is called Electron on macOS", "Electron", "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", nil, "vscode", EvidenceBundleExe},
		{"a tool bundled deep inside the app is not the app", "rg", "/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg", nil, "", ""},
		{"Electron from an unknown bundle", "Electron", "/Applications/Slack.app/Contents/MacOS/Electron", nil, "", ""},
		{"bundle executable in ~/Applications", "whatever", "/Users/dev/Applications/Cursor.app/Contents/MacOS/whatever", nil, "cursor", EvidenceBundleExe},
		{"a look-alike bundle under /tmp earns no path credit", "whatever", "/tmp/Applications/Cursor.app/Contents/MacOS/whatever", nil, "", ""},
		{"JetBrains Air: ambiguous name, bundle decides", "Air", "/Applications/Air.app/Contents/MacOS/Air", nil, "jetbrains-air", EvidenceBundleExe},
		{"air the Go live-reload tool", "air", "/home/dev/go/bin/air", nil, "", ""},
		{"VS Code helper", "Code Helper (Plugin)", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)", nil, "vscode", EvidencePath},
		{"dia the diagram editor", "dia", "/usr/bin/dia", nil, "", ""},
		{"Dia the browser", "Dia", "/Applications/Dia.app/Contents/MacOS/Dia", nil, "dia", EvidencePath},
		{"hermes the JS engine", "hermes", "/usr/local/bin/hermes", []string{"hermes", "bundle.js"}, "", ""},
		{"hermes agent in a pipx venv", "python3", "/home/dev/.local/share/pipx/venvs/hermes-agent/bin/python", []string{"python", "/home/dev/.local/bin/hermes", "gateway"}, "hermes", EvidenceScriptName},

		// --- unambiguous long tail ------------------------------------------
		{"aider console script", "python3.12", "/usr/bin/python3.12", []string{"/usr/bin/python3.12", "/home/dev/.local/bin/aider", "--yes-always"}, "aider", EvidenceScriptName},
		{"aider as a module", "python", "/usr/bin/python3", []string{"python", "-m", "aider"}, "aider", EvidenceScriptName},
		{"aider via uvx", "uvx", "/home/dev/.local/bin/uvx", []string{"uvx", "--from", "aider-chat", "aider"}, "aider", EvidenceArgs},
		{"aider via uv tool run with a pin", "uv", "/usr/bin/uv", []string{"uv", "tool", "run", "aider-chat==0.86.2"}, "aider", EvidenceArgs},
		{"opencode", "opencode", "/home/dev/.opencode/bin/opencode", nil, "opencode", EvidencePath},
		{"OpenCode desktop", "OpenCode", "/Applications/OpenCode.app/Contents/MacOS/OpenCode", nil, "opencode-desktop", EvidencePath},
		{"kiro-cli", "kiro-cli", "/home/dev/.local/bin/kiro-cli", nil, "kiro-cli", EvidencePath},
		{"qwen", "qwen", "", []string{"qwen"}, "qwen-code", EvidenceProcessName},
		{"ollama", "ollama", "/usr/local/bin/ollama", []string{"ollama", "serve"}, "ollama", EvidencePath},
		{"Ollama app on Windows", "ollama app.exe", `C:\Users\dev\AppData\Local\Programs\Ollama\ollama app.exe`, nil, "ollama", EvidencePath},
		{"llama-server", "llama-server", "/opt/homebrew/bin/llama-server", []string{"llama-server", "-m", "x.gguf"}, "llama-cpp", EvidenceProcessName},
		{"a process called server is nothing", "server", "/usr/local/bin/server", nil, "", ""},
		{"LM Studio", "LM Studio", "/Applications/LM Studio.app/Contents/MacOS/LM Studio", nil, "lm-studio", EvidencePath},
		{"mlx_lm server module", "python3", "/usr/bin/python3", []string{"python3", "-m", "mlx_lm.server", "--port", "8080"}, "mlx-lm", EvidenceArgs},
		{"vllm module", "python", "/usr/bin/python3", []string{"python", "-m", "vllm.entrypoints.openai.api_server"}, "vllm", EvidenceArgs},
		{"text-generation-webui", "python", "/usr/bin/python3", []string{"python", "/home/dev/text-generation-webui/server.py", "--api"}, "text-generation-webui", EvidenceArgs},
		{"any other server.py is nothing", "python", "/usr/bin/python3", []string{"python", "server.py"}, "", ""},
		{"docker model runner", "docker", "/usr/bin/docker", []string{"docker", "model", "run", "ai/smollm2"}, "docker-model-runner", EvidenceArgs},
		{"docker run of an unrelated image", "docker", "/usr/bin/docker", []string{"docker", "run", "--rm", "nginx:latest"}, "", ""},
		{"openhands container", "docker", "/usr/bin/docker", []string{"docker", "run", "--rm", "-it", "-e", "K=V", "-p", "8000:8000", "ghcr.io/openhands/agent-canvas:1.38"}, "openhands", EvidenceArgs},
		{"comm truncated to 15 bytes", "claude-agent-ac", "", nil, "claude-agent-acp", EvidenceProcessName},
		{"nested package: the vendored CLI is what runs", "node", "/usr/bin/node", []string{"node", "/usr/lib/node_modules/openclaw/node_modules/@anthropic-ai/claude-code/cli.js"}, "claude-code", EvidencePackagePath},

		// --- nothing ----------------------------------------------------------
		{"empty everything", "", "", nil, "", ""},
		{"bash", "bash", "/bin/bash", []string{"bash", "-c", "echo claude"}, "", ""},
		{"node with an ordinary script", "node", "/usr/bin/node", []string{"node", "server.js"}, "", ""},
		{"path alone never identifies", "rg", "/usr/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/rg", []string{"rg", "foo"}, "", ""},
		{"a mention in arguments is not identity", "grep", "/usr/bin/grep", []string{"grep", "-r", "@anthropic-ai/claude-code/", "."}, "", ""},
		{"an install dir of a different product does not vouch for a name", "goose", "/home/dev/.grok/bin/goose", nil, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			m, ok := c.MatchProcessDetail(tc.name, tc.exe, tc.args)
			got := ""
			if ok {
				got = m.Product.ID
			}
			if got != tc.want {
				t.Fatalf("MatchProcess(%q, %q, %q) = %q (evidence %v), want %q", tc.name, tc.exe, tc.args, got, m.Evidence, tc.want)
			}
			if tc.ev != "" && !contains(m.Evidence, tc.ev) {
				t.Errorf("evidence = %v, want it to include %q", m.Evidence, tc.ev)
			}
			if ok && (m.Classes < 1 || m.Classes > 3 || len(m.Evidence) == 0) {
				t.Errorf("classes = %d, evidence = %v", m.Classes, m.Evidence)
			}
			// The plain API must agree with the detailed one.
			p, ok2 := c.MatchProcess(tc.name, tc.exe, tc.args)
			if ok2 != ok || p.ID != m.Product.ID {
				t.Errorf("MatchProcess disagrees with MatchProcessDetail: %q %v", p.ID, ok2)
			}
		})
	}
}

// Every ambiguous name that a product lists must fail to match when nothing
// corroborates it. This is the property the catalog promises, checked over
// the data rather than over a hand-picked list.
func TestAmbiguousNamesNeverMatchAlone(t *testing.T) {
	c := mustLoad(t)
	n := 0
	for _, p := range c.Products() {
		for _, name := range append(append([]string{}, p.Binaries...), p.ProcessNames...) {
			if !c.IsAmbiguousName(name) {
				continue
			}
			n++
			for _, exe := range []string{"", "/usr/bin/" + name, "/usr/games/" + name, `C:\tools\` + name + ".exe"} {
				if got, ok := c.MatchProcess(name, exe, []string{name}); ok {
					t.Errorf("ambiguous name %q (product %s) matched %s with exe %q", name, p.ID, got.ID, exe)
				}
			}
		}
	}
	for _, want := range []string{"goose", "amp", "q", "agent", "gemini"} {
		if !c.IsAmbiguousName(want) {
			t.Errorf("%q must be ambiguous", want)
		}
	}
	if n < 20 {
		t.Errorf("only %d ambiguous names are listed by products; the check is not exercising much", n)
	}
	if c.IsAmbiguousName("claude") || c.IsAmbiguousName("codex") {
		t.Error("claude and codex are distinctive names")
	}
}

// Every unambiguous binary must be found by name alone, otherwise the entry
// is dead data.
func TestUnambiguousBinariesMatchByName(t *testing.T) {
	c := mustLoad(t)
	for _, p := range c.Products() {
		for _, name := range p.Binaries {
			if c.IsAmbiguousName(name) {
				continue
			}
			got, ok := c.MatchProcess(name, "", nil)
			if !ok {
				t.Errorf("%s: binary %q does not match by name", p.ID, name)
				continue
			}
			// A shared name may resolve to the sibling, which must then be
			// declared in aliases.
			if got.ID != p.ID && !lists(p.Aliases, got.ID) {
				t.Errorf("%s: binary %q resolved to unrelated product %s", p.ID, name, got.ID)
			}
		}
	}
}

func TestMatchProcessHostileInput(t *testing.T) {
	c := mustLoad(t)
	huge := strings.Repeat("A", 4<<20)
	manyArgs := make([]string, 100000)
	for i := range manyArgs {
		manyArgs[i] = "--x=" + strings.Repeat("y", 64)
	}
	cases := []struct {
		desc string
		name string
		exe  string
		args []string
	}{
		{"huge name", huge, "", nil},
		{"huge exe", "claude", huge, nil},
		{"huge single arg", "node", "/usr/bin/node", []string{"node", huge}},
		{"huge module name", "python3", "/usr/bin/python3", []string{"python3", "-m", huge}},
		{"huge package spec", "npx", "/usr/bin/npx", []string{"npx", "-y", huge}},
		{"huge docker image", "docker", "/usr/bin/docker", []string{"docker", "run", huge}},
		{"huge title-rewritten argv", "node", "/usr/bin/node", []string{"npm exec " + strings.Repeat("x ", 8000)}},
		{"script path at the cap", "node", "/usr/bin/node", []string{"node", strings.Repeat("/node_modules/a", maxCmdline/15)}},
		{"many args", "node", "/usr/bin/node", manyArgs},
		{"invalid utf-8", "\xff\xfe\xfd", "/\xff/\xfe", []string{"\xc3\x28", "\xa0\xa1"}},
		{"NULs", "cla\x00ude", "/usr/bin/\x00", []string{"\x00", "\x00\x00"}},
		{"path traversal", "claude", "/home/dev/.local/share/claude/versions/../../../../etc/passwd", nil},
		{"only separators", "///", `\\\`, []string{"/", `\`}},
		{"regex metacharacters", "(((", "[[[", []string{"node", "(?i)(a+)+$", strings.Repeat("a", 5000) + "!"}},
		{"launcher with nothing after it", "npx", "/usr/bin/npx", []string{"npx"}},
		{"launcher flags only", "uvx", "/usr/bin/uvx", []string{"uvx", "--from"}},
		{"-m at the end", "python3", "/usr/bin/python3", []string{"python3", "-m"}},
		{"-- at the end", "node", "/usr/bin/node", []string{"node", "--"}},
		{"empty args", "node", "/usr/bin/node", []string{"", "", ""}},
		{"one space-only arg", "node", "/usr/bin/node", []string{"     "}},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			start := time.Now()
			c.MatchProcess(tc.name, tc.exe, tc.args) // must not panic
			// The work is bounded by the caps, not by the input size: a
			// 4 MiB argument must cost about what a 16 KiB one does.
			if d := time.Since(start); d > 250*time.Millisecond {
				t.Errorf("took %v", d)
			}
		})
	}
	// The traversal case must not be credited with path evidence it did
	// not earn: the name still matches, which is all that is claimed.
	m, ok := c.MatchProcessDetail("claude", "/home/dev/.local/share/claude/versions/1/../../../evil/claude", nil)
	if !ok || m.Product.ID != "claude-code" {
		t.Fatalf("name match lost: %v %v", m.Product.ID, ok)
	}
	if contains(m.Evidence, EvidencePath) || contains(m.Evidence, EvidencePackagePath) || m.Classes != 1 {
		t.Errorf("a path with .. elements earned path evidence: %v", m.Evidence)
	}
	// Borrowing a package directory through ".." must not identify a script.
	if p, ok := c.MatchProcess("node", "/usr/bin/node", []string{"node", "/tmp/node_modules/@google/gemini-cli/../../../evil.js"}); ok {
		t.Errorf("script outside the package matched %s", p.ID)
	}
	// Nor may it lend an ambiguous name its second class of evidence.
	if p, ok := c.MatchProcess("goose", "/opt/homebrew/Cellar/block-goose-cli/1.0/../../../../tmp/goose", nil); ok {
		t.Errorf("ambiguous name matched %s through a .. path", p.ID)
	}
}

func TestMatchProcessRandomBytes(t *testing.T) {
	c := mustLoad(t)
	rng := rand.New(rand.NewSource(20261111))
	randStr := func(max int) string {
		b := make([]byte, rng.Intn(max))
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		return string(b)
	}
	seeds := []string{"node", "python3", "npx", "uvx", "docker", "claude", "goose", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "-m", "--", "run", "exec"}
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < 20000; i++ {
		args := make([]string, rng.Intn(8))
		for j := range args {
			if rng.Intn(3) == 0 {
				args[j] = seeds[rng.Intn(len(seeds))]
			} else {
				args[j] = randStr(200)
			}
		}
		name, exe := randStr(40), randStr(120)
		if rng.Intn(4) == 0 {
			name = seeds[rng.Intn(len(seeds))]
		}
		c.MatchProcess(name, exe, args)
		if time.Now().After(deadline) {
			t.Fatalf("random inputs took too long (%d iterations)", i)
		}
	}
}

func BenchmarkMatchProcessMiss(b *testing.B) {
	c := mustLoad(b)
	args := []string{"/usr/lib/systemd/systemd-journald"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.MatchProcess("systemd-journal", "/usr/lib/systemd/systemd-journald", args)
	}
}

func BenchmarkMatchProcessNode(b *testing.B) {
	c := mustLoad(b)
	args := []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "-p", "hello"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.MatchProcess("node", "/usr/bin/node", args)
	}
}

// BenchmarkLoadCold measures what a fresh process pays for the first Load.
func BenchmarkLoadCold(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := loadEmbedded(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadCached(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Load(); err != nil {
			b.Fatal(err)
		}
	}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
