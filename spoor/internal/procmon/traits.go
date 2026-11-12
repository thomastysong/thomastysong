package procmon

import (
	"strings"
)

// agentTraits describes how one agent's command line and environment reveal
// a non-interactive run, bare mode, a hook-free mode or a mode that writes
// no transcript. The catalog records risky flags but not these modes, so the
// table lives here; every entry names where it comes from.
type agentTraits struct {
	headlessFlags []string            // exact tokens (also "--flag=<value>")
	headlessSub   []string            // first plain positional argument
	headlessKV    map[string][]string // flag -> values that imply headless
	bareFlags     []string
	bareEnv       []string
	hookFreeFlags []string
	persistFlags  []string
	persistEnv    []string
	// valueFlags take a separate value; their value is not a positional.
	valueFlags []string
}

var traitsByAgent = map[string]agentTraits{
	// research/agent-surfaces-a.md section 2 (code.claude.com headless.md,
	// cli-reference.md, env-vars.md): "claude -p"; --bare skips hook
	// discovery and sets CLAUDE_CODE_SIMPLE; --no-session-persistence and
	// CLAUDE_CODE_SKIP_PROMPT_HISTORY suppress the transcript.
	// UNVERIFIED: that --output-format/--input-format stream-json without -p
	// (as the Agent SDK passes them) is a non-interactive run.
	"claude-code": {
		headlessFlags: []string{"-p", "--print"},
		headlessKV:    map[string][]string{"--output-format": {"json", "stream-json"}, "--input-format": {"stream-json"}},
		bareFlags:     []string{"--bare"},
		bareEnv:       []string{"CLAUDE_CODE_SIMPLE"},
		persistFlags:  []string{"--no-session-persistence"},
		persistEnv:    []string{"CLAUDE_CODE_SKIP_PROMPT_HISTORY"},
		valueFlags: []string{"--model", "--permission-mode", "--settings", "--mcp-config", "--output-format", "--input-format",
			"--allowedTools", "--disallowedTools", "--add-dir", "--append-system-prompt", "--system-prompt", "-r", "--resume",
			"--session-id", "--agents", "--plugin-dir", "--fallback-model", "--max-turns"},
	},
	// research/agent-surfaces-a.md section 3 (openai/codex main source):
	// headless "codex exec", --ephemeral ("Run without persisting session
	// files to disk"), --dangerously-bypass-hook-trust.
	"codex": {
		headlessSub:   []string{"exec"},
		hookFreeFlags: []string{"--dangerously-bypass-hook-trust"},
		persistFlags:  []string{"--ephemeral"},
		valueFlags: []string{"-c", "--config", "-m", "--model", "-p", "--profile", "-C", "--cd", "-s", "--sandbox",
			"-a", "--ask-for-approval", "-i", "--image", "--enable", "--disable", "--local-provider", "--add-dir"},
	},
	// research/agent-surfaces-a.md section 5 (gemini-cli docs/cli/headless.md):
	// "-p or non-TTY, --output-format json|stream-json". A non-TTY run
	// without those flags cannot be seen from the command line.
	// UNVERIFIED: the long spelling --prompt.
	"gemini-cli": {
		headlessFlags: []string{"-p", "--prompt"},
		headlessKV:    map[string][]string{"--output-format": {"json", "stream-json"}},
	},
	// research/agent-surfaces-a.md section 4: managed settings "apply in
	// interactive, -p, --acp and --server modes". UNVERIFIED: --prompt.
	"copilot-cli": {
		headlessFlags: []string{"-p", "--prompt"},
	},
	// UNVERIFIED (cursor.com unreachable during research): -p/--print.
	"cursor-agent": {
		headlessFlags: []string{"-p", "--print"},
	},
	// research/threats.md incident 1 (s1ngularity): "q chat
	// --trust-all-tools --no-interactive". UNVERIFIED: flag spelling.
	"kiro-cli": {
		headlessFlags: []string{"--no-interactive"},
	},
}

// operands returns the arguments after the program, stopping at "--" after
// which everything is an operand of the agent (a prompt), never a flag.
func operands(args []string) []string {
	if len(args) <= 1 {
		return nil
	}
	rest := args[1:]
	if len(rest) > maxRawArgs {
		rest = rest[:maxRawArgs]
	}
	for i, a := range rest {
		if a == "--" {
			return rest[:i]
		}
	}
	return rest
}

func hasFlag(args, flags []string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f {
				return true
			}
			if v, ok := strings.CutPrefix(a, f+"="); ok && strings.HasPrefix(f, "--") && !isFalse(v) {
				return true
			}
		}
	}
	return false
}

func hasEnv(env map[string]string, names []string) bool {
	for _, n := range names {
		if v, ok := env[n]; ok && !isFalse(strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func isFalse(v string) bool {
	switch strings.ToLower(v) {
	case "", "false", "0", "no", "off":
		return true
	}
	return false
}

// flagValue returns the value of "--flag value" or "--flag=value".
func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

func (t agentTraits) headless(ops []string) bool {
	if hasFlag(ops, t.headlessFlags) {
		return true
	}
	for flag, vals := range t.headlessKV {
		if v, ok := flagValue(ops, flag); ok && contains(vals, v) {
			return true
		}
	}
	if len(t.headlessSub) > 0 {
		if sub := firstPlainPositional(ops, t.valueFlags); sub != "" && contains(t.headlessSub, sub) {
			return true
		}
	}
	return false
}

// firstPlainPositional returns the first argument that is neither a flag,
// nor the value of a value-taking flag, nor a path (script paths and package
// specs of interpreter-launched agents contain a slash).
func firstPlainPositional(ops, valueFlags []string) string {
	skip := false
	for _, a := range ops {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") && contains(valueFlags, a) {
				skip = true
			}
			continue
		}
		if strings.ContainsAny(a, `/\`) {
			continue
		}
		return a
	}
	return ""
}

func (t agentTraits) bare(ops []string, env map[string]string) bool {
	return hasFlag(ops, t.bareFlags) || hasEnv(env, t.bareEnv)
}

func (t agentTraits) hookFree(ops []string) bool { return hasFlag(ops, t.hookFreeFlags) }

func (t agentTraits) persistenceFree(ops []string, env map[string]string) bool {
	return hasFlag(ops, t.persistFlags) || hasEnv(env, t.persistEnv)
}
