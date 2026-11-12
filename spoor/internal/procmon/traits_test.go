package procmon

import (
	"reflect"
	"strings"
	"testing"
)

func TestTraits(t *testing.T) {
	tests := []struct {
		agent    string
		args     []string
		env      map[string]string
		headless bool
		bare     bool
		hookFree bool
		persist  bool
	}{
		{"claude-code", []string{"claude", "-p", "hi"}, nil, true, false, false, false},
		{"claude-code", []string{"claude", "--print"}, nil, true, false, false, false},
		{"claude-code", []string{"claude", "--output-format", "stream-json", "--input-format", "stream-json"}, nil, true, false, false, false},
		{"claude-code", []string{"claude", "--output-format=text"}, nil, false, false, false, false},
		{"claude-code", []string{"claude", "--", "-p"}, nil, false, false, false, false},
		{"claude-code", []string{"claude", "--bare"}, nil, false, true, false, false},
		{"claude-code", []string{"claude"}, map[string]string{"CLAUDE_CODE_SIMPLE": "1"}, false, true, false, false},
		{"claude-code", []string{"claude"}, map[string]string{"CLAUDE_CODE_SIMPLE": "0"}, false, false, false, false},
		{"claude-code", []string{"claude", "--no-session-persistence"}, nil, false, false, false, true},
		{"claude-code", []string{"claude"}, map[string]string{"CLAUDE_CODE_SKIP_PROMPT_HISTORY": "true"}, false, false, false, true},
		{"codex", []string{"codex", "exec", "fix"}, nil, true, false, false, false},
		{"codex", []string{"codex", "-m", "exec", "fix"}, nil, false, false, false, false}, // "exec" is the model name here
		{"codex", []string{"codex", "-c", "x=1", "--yolo", "exec", "--ephemeral"}, nil, true, false, false, true},
		{"codex", []string{"node", "/usr/lib/node_modules/@openai/codex/bin/codex.js", "exec"}, nil, true, false, false, false},
		{"codex", []string{"npx", "@openai/codex", "exec"}, nil, true, false, false, false},
		{"codex", []string{"codex", "please exec the tests"}, nil, false, false, false, false},
		{"codex", []string{"codex", "--dangerously-bypass-hook-trust"}, nil, false, false, true, false},
		{"gemini-cli", []string{"gemini", "-p", "x"}, nil, true, false, false, false},
		{"gemini-cli", []string{"gemini", "--output-format", "json"}, nil, true, false, false, false},
		{"gemini-cli", []string{"gemini"}, nil, false, false, false, false},
		{"copilot-cli", []string{"copilot", "-p", "x", "--allow-all-tools"}, nil, true, false, false, false},
		{"copilot-cli", []string{"copilot", "--prompt=no"}, nil, true, false, false, false}, // the prompt is the value, not a boolean
		{"copilot-cli", []string{"copilot", "--prompt", "0"}, nil, true, false, false, false},
		{"copilot-cli", []string{"copilot", "--acp"}, nil, false, false, false, false},
		{"gemini-cli", []string{"gemini", "--prompt=false"}, nil, true, false, false, false},
		{"gemini-cli", []string{"gemini", "--", "-p"}, nil, false, false, false, false},
		{"claude-code", []string{"claude", "--print=false"}, nil, false, false, false, false},
		{"cursor-agent", []string{"cursor-agent", "--print", "x"}, nil, true, false, false, false},
		{"kiro-cli", []string{"q", "chat", "--trust-all-tools", "--no-interactive"}, nil, true, false, false, false},
		{"opencode", []string{"opencode", "-p", "x"}, nil, false, false, false, false}, // no table entry
	}
	for _, tc := range tests {
		tr := traitsByAgent[tc.agent]
		ops := operands(tc.args)
		got := []bool{tr.headless(ops), tr.bare(ops, tc.env), tr.hookFree(ops), tr.persistenceFree(ops, tc.env)}
		want := []bool{tc.headless, tc.bare, tc.hookFree, tc.persist}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s %q %v: got %v, want %v", tc.agent, tc.args, tc.env, got, want)
		}
	}
}

func TestRiskyFlagsFromCatalog(t *testing.T) {
	cat := loadCatalog(t)
	tests := []struct {
		id   string
		args []string
		want []string
	}{
		{"claude-code", []string{"claude", "--permission-mode=bypassPermissions", "--dangerously-skip-permissions"},
			[]string{"--dangerously-skip-permissions", "--permission-mode bypassPermissions"}},
		{"claude-code", []string{"claude", "--permission-mode", "plan"}, nil},
		{"claude-code", []string{"claude", "-p", "--", "--dangerously-skip-permissions"}, nil},
		{"codex", []string{"codex", "--sandbox", "danger-full-access", "--ask-for-approval=never"},
			[]string{"--sandbox danger-full-access", "--ask-for-approval never"}},
		{"gemini-cli", []string{"gemini", "--approval-mode=yolo"}, []string{"--approval-mode yolo"}},
	}
	for _, tc := range tests {
		p, ok := cat.Get(tc.id)
		if !ok {
			t.Fatalf("no %s in catalog", tc.id)
		}
		if got := p.RiskyArgs(operands(tc.args)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %q: got %q, want %q", tc.id, tc.args, got, tc.want)
		}
	}
}

func TestLifecycleParent(t *testing.T) {
	anc := func(name string, args ...string) ancestor {
		return ancestor{name: name, args: append([]string{name}, args...)}
	}
	tests := []struct {
		name string
		env  map[string]string
		anc  []ancestor
		want string
	}{
		{"env npm", map[string]string{"npm_lifecycle_event": "postinstall", "npm_config_user_agent": "npm/10.8.2 node/v22"}, nil, LifecycleNPM},
		{"env yarn", map[string]string{"npm_lifecycle_event": "prepare", "npm_config_user_agent": "yarn/1.22.22 npm/? node/v20"}, nil, LifecycleYarn},
		{"env pnpm", map[string]string{"npm_lifecycle_event": "install", "npm_config_user_agent": "pnpm/9.12.0 npm/? node/v22"}, nil, LifecyclePNPM},
		{"env bun", map[string]string{"npm_lifecycle_event": "postinstall", "npm_config_user_agent": "bun/1.1.30 npm/? node/v22"}, nil, LifecycleBun},
		{"env execpath only", map[string]string{"npm_lifecycle_event": "postinstall", "npm_execpath": "/usr/lib/node_modules/pnpm/bin/pnpm.cjs"}, nil, LifecyclePNPM},
		{"env default npm", map[string]string{"npm_lifecycle_event": "build"}, nil, LifecycleNPM},
		{"ancestor npm install", nil, []ancestor{anc("sh", "-c", "node x.js"), anc("npm", "install")}, LifecycleNPM},
		{"process.title", nil, []ancestor{{name: "npm install left-pad", args: []string{"npm install left-pad"}}}, LifecycleNPM},
		{"node npm-cli.js", nil, []ancestor{{name: "node", exe: "/usr/bin/node", args: []string{"node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "ci"}}}, LifecycleNPM},
		{"npx is a runner", nil, []ancestor{anc("npm", "exec", "@openai/codex"), anc("bash")}, ""},
		{"pnpm dlx is a runner", nil, []ancestor{anc("pnpm", "dlx", "x")}, ""},
		{"yarn add", nil, []ancestor{anc("yarn", "add", "x")}, LifecycleYarn},
		{"bun run is not install", nil, []ancestor{anc("bun", "run", "dev")}, ""},
		{"bun install", nil, []ancestor{anc("bun", "install")}, LifecycleBun},
		{"pip", nil, []ancestor{anc("pip3.12", "install", "x")}, LifecyclePip},
		{"python -m pip", nil, []ancestor{anc("python3", "-m", "pip", "install", ".")}, LifecyclePip},
		{"setup.py", nil, []ancestor{anc("python3", "-u", "/tmp/pkg/setup.py", "install")}, LifecycleSetupPy},
		{"python script", nil, []ancestor{anc("python3", "app.py")}, ""},
		{"remote extension host", nil, []ancestor{anc("node", "/srv/vscode-server/out/server-main.js", "--type=extensionHost")}, LifecycleExtensionHost},
		{"mac plugin helper", nil, []ancestor{{name: "Code Helper (Plugin)"}}, LifecycleExtensionHost},
		{"utility extension host", nil, []ancestor{anc("bash"), {name: "code", args: []string{"code", "--type=utility", "--utility-sub-type=node.mojom.NodeService"}, utilityType: "extensionHost"}}, LifecycleExtensionHost},
		// The integrated terminal's pty host has the same command line as
		// the extension host; only its environment tells them apart.
		{"terminal pty host", nil, []ancestor{anc("bash"), {name: "code", args: []string{"code", "--type=utility", "--utility-sub-type=node.mojom.NodeService"}, utilityType: "ptyHost"}, anc("code")}, ""},
		{"utility with unreadable env", nil, []ancestor{{name: "code", args: []string{"code", "--type=utility", "--utility-sub-type=node.mojom.NodeService"}}}, ""},
		{"inherited extension host env", map[string]string{"VSCODE_CRASH_REPORTER_PROCESS_TYPE": "extensionHost"}, []ancestor{anc("sh")}, LifecycleExtensionHost},
		{"inherited pty host env", map[string]string{"VSCODE_CRASH_REPORTER_PROCESS_TYPE": "ptyHost"}, []ancestor{anc("bash")}, ""},
		{"npm script under an extension", map[string]string{"VSCODE_CRASH_REPORTER_PROCESS_TYPE": "extensionHost", "npm_lifecycle_event": "postinstall"}, nil, LifecycleNPM},
		{"windows node path with spaces", nil, []ancestor{{name: "node.exe", exe: `C:\Program Files\nodejs\node.exe`,
			args: []string{`C:\Program Files\nodejs\node.exe`, `C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js`, "install"}}}, LifecycleNPM},
		{"xdg-open", nil, []ancestor{anc("bash"), anc("xdg-open", "claude-cli://x")}, LifecycleURLHandler},
		{"windows url.dll", nil, []ancestor{{name: "rundll32.exe", args: []string{"rundll32.exe", "url.dll,FileProtocolHandler", "x"}}}, LifecycleURLHandler},
		{"nearest wins", nil, []ancestor{anc("pip", "install"), anc("npm", "install")}, LifecyclePip},
		{"plain terminal", nil, []ancestor{anc("bash"), anc("gnome-terminal-server"), anc("systemd")}, ""},
	}
	for _, tc := range tests {
		if got := lifecycleParent(tc.env, tc.anc); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestExpandTitle(t *testing.T) {
	tests := []struct {
		in, want []string
	}{
		{[]string{"npm exec @openai/codex --yolo"}, []string{"npm", "exec", "@openai/codex", "--yolo"}},
		{[]string{"npm install left-pad", "x"}, []string{"npm", "install", "left-pad", "x"}},
		{[]string{"/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "--type=utility"}, nil},
		{[]string{`C:\Program Files\nodejs\node.exe`, "cli.js"}, nil},
		{[]string{"claude", "-p", "a prompt with spaces"}, nil},
		{[]string{"   "}, nil},
		{nil, nil},
		{[]string{strings.Repeat("a ", 3000)}, nil}, // over the size bound
	}
	for _, tc := range tests {
		want := tc.want
		if want == nil {
			want = tc.in
		}
		if got := expandTitle(tc.in); !reflect.DeepEqual(got, want) {
			t.Errorf("expandTitle(%q) = %q, want %q", tc.in, got, want)
		}
	}
	if got := expandTitle([]string{strings.Repeat("x ", 100)}); len(got) != 64 {
		t.Errorf("title fields not capped: %d", len(got))
	}
}

func TestEnvScan(t *testing.T) {
	ix := buildIndex(loadCatalog(t))
	f := ix.scanEnv(map[string]string{
		"PATH":                          "/usr/bin",
		"CLAUDECODE":                    "1",
		"CLAUDE_CODE_REMOTE_SESSION_ID": "remote-1",
		"CLAUDE_CODE_SESSION_ID":        "6f1c2a9e-0d3b-4e57-9a10-2b7c3d4e5f60",
		"CODEX_THREAD_ID":               "/etc/passwd", // not an identifier: dropped
	})
	if !f.known || f.product == "" || !f.strong {
		t.Fatalf("facts = %+v", f)
	}
	if got := f.session("claude-code"); got != "6f1c2a9e-0d3b-4e57-9a10-2b7c3d4e5f60" {
		t.Errorf("claude session = %q (catalog order must prefer CLAUDE_CODE_SESSION_ID)", got)
	}
	if got := f.session("codex"); got != "" {
		t.Errorf("hostile codex session kept: %q", got)
	}
	if !contains(f.markers, "CLAUDECODE") || contains(f.markers, "PATH") {
		t.Errorf("markers = %v", f.markers)
	}
	weak := ix.scanEnv(map[string]string{"COPILOT_MODEL": "gpt-5"})
	if weak.product != "copilot-cli" || weak.strong {
		t.Errorf("weak = %+v", weak)
	}
	if none := ix.scanEnv(nil); none.known {
		t.Error("nil env is unknown, not empty")
	}
	for in, want := range map[string]string{
		"abc-123_X.y:z":          "abc-123_X.y:z",
		" spaced ":               "spaced",
		"a b":                    "",
		"x\ny":                   "",
		"ghp_" + "x/y":           "",
		strings.Repeat("a", 200): "",
		"":                       "",
	} {
		if got := cleanSessionID(in); got != want {
			t.Errorf("cleanSessionID(%q) = %q", in, got)
		}
	}
	if got := configHome([]string{"CLAUDE_CONFIG_DIR"}, map[string]string{"CLAUDE_CONFIG_DIR": "/srv/cc\n"}); got != "/srv/cc" {
		t.Errorf("configHome trims: %q", got)
	}
	if got := configHome([]string{"CLAUDE_CONFIG_DIR"}, map[string]string{"CLAUDE_CONFIG_DIR": "/a\x01b"}); got != "" {
		t.Errorf("configHome control char: %q", got)
	}
	if got := configHome([]string{"CLAUDE_CONFIG_DIR"}, map[string]string{"CLAUDE_CONFIG_DIR": strings.Repeat("a", 2000)}); got != "" {
		t.Errorf("configHome size: %q", got)
	}
}

func TestIsRunner(t *testing.T) {
	cases := map[string]bool{
		"npx|/usr/bin/node|npx -y @openai/codex":                           true,
		"npm exec @open|/usr/bin/node|npm exec @openai/codex":              true,
		"node|/usr/bin/node|node /usr/lib/node_modules/npm/bin/npx-cli.js": true,
		"uvx|/home/u/.local/bin/uvx|uvx aider-chat":                        true,
		"codex|/usr/local/bin/codex|codex":                                 false,
		"node|/usr/bin/node|node /x/codex.js":                              false,
	}
	for spec, want := range cases {
		parts := strings.SplitN(spec, "|", 3)
		rec := procRec(parts[0], parts[1], strings.Fields(parts[2]))
		if got := isRunner(rec); got != want {
			t.Errorf("isRunner(%s) = %v", spec, got)
		}
	}
}
