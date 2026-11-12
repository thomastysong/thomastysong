package transcript

import (
	"path/filepath"

	"github.com/thomastysong/spoor/internal/event"
)

// ConfigRoots returns the roots that cover one agent's configuration
// directory: the default (~/.claude, ~/.codex, ~/.copilot, ~/.gemini) or
// wherever CLAUDE_CONFIG_DIR, CODEX_HOME or COPILOT_HOME moved it. For
// Gemini CLI dir is the ".gemini" directory itself (GEMINI_CLI_HOME names
// its parent). format is a format id or an agent id; an unknown one yields
// no roots.
func ConfigRoots(format, dir string, user event.User) []Root {
	p, ok := ForFormat(format)
	if !ok || dir == "" {
		return nil
	}
	var globs []string
	switch formatOf(p) {
	case FormatClaude:
		globs = []string{
			filepath.Join(dir, "projects", "*", "*.jsonl"),
			// Subagents nest: <session>/subagents/agent-<id>.jsonl and
			// <session>/subagents/workflows/<run>/agent-<id>.jsonl.
			filepath.Join(dir, "projects", "*", "*", "subagents", "**", "agent-*.jsonl"),
		}
	case FormatCodex:
		globs = []string{
			// "*.jsonl*" also takes the .jsonl.zst archives.
			filepath.Join(dir, "sessions", "**", "rollout-*.jsonl*"),
			filepath.Join(dir, "archived_sessions", "**", "rollout-*.jsonl*"),
		}
	case FormatCopilot:
		globs = []string{filepath.Join(dir, "session-state", "*", "events.jsonl")}
	case FormatGemini:
		globs = []string{
			filepath.Join(dir, "tmp", "*", "chats", "session-*.json*"),
			filepath.Join(dir, "tmp", "*", "chats", "*", "*.jsonl"),
		}
	}
	roots := make([]Root, len(globs))
	for i, g := range globs {
		roots[i] = Root{Glob: g, Parser: p, User: user}
	}
	return roots
}

// HomeRoots returns the roots for every built-in format at its default
// location under a home directory. Relocated configuration directories
// (found, for example, in a running agent's environment) are added with
// ConfigRoots.
func HomeRoots(home string, user event.User) []Root {
	if home == "" {
		return nil
	}
	var roots []Root
	roots = append(roots, ConfigRoots(FormatClaude, filepath.Join(home, ".claude"), user)...)
	roots = append(roots, ConfigRoots(FormatCodex, filepath.Join(home, ".codex"), user)...)
	roots = append(roots, ConfigRoots(FormatCopilot, filepath.Join(home, ".copilot"), user)...)
	roots = append(roots, ConfigRoots(FormatGemini, filepath.Join(home, ".gemini"), user)...)
	// Under the macOS sandbox Gemini CLI keeps the same layout in
	// ~/.cache/.gemini (Fleet ai_agent_sessions).
	roots = append(roots, ConfigRoots(FormatGemini, filepath.Join(home, ".cache", ".gemini"), user)...)
	return roots
}
