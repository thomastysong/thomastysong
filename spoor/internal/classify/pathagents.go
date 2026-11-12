package classify

import (
	"strings"
	"sync"
)

// agentDirs are the state and configuration directories of AI agents, as
// component sequences that may appear at any depth (user home, project root,
// another user's home, a container mount). What a file inside one of them IS
// follows from the layout convention the agents share: skills/, commands/,
// agents/, plugins/ hold instructions the agent can run; rules/ and memory/
// hold instructions it always loads; hooks/ holds commands it executes;
// projects/ and sessions/ hold transcripts; the rest is configuration.
//
// Sources: research/agent-surfaces-a.md (Claude Code, Codex, Copilot, Gemini
// CLI, Cursor) and research/agent-surfaces-b.md section 1 (the long tail).
// Entries the research marks "?" are kept: a wrong entry only labels a
// directory that does not exist.
// UNVERIFIED: every directory the research table marks with "?" (among them
// ~/.kiro subpaths, ~/.config/opencode, ~/.config/kilo, ~/.augment, ~/.vibe,
// ~/.config/amp plugin paths, .kilocode, .windsurf).
var agentDirs = [][]string{
	// Claude Code and Claude Desktop.
	{".claude"},
	{"Library", "Application Support", "Claude"}, {"AppData", "Roaming", "Claude"}, {".config", "Claude"},
	// OpenAI Codex and the ChatGPT app.
	{".codex"},
	{"Library", "Application Support", "Codex"}, {"Library", "Application Support", "OpenAI", "Codex"},
	// GitHub Copilot.
	{".copilot"}, {".config", "github-copilot"}, {"AppData", "Local", "github-copilot"},
	// Google: Gemini CLI, Antigravity.
	{".gemini"}, {".antigravity"}, {".antigravity-ide"}, {".antigravity-ide-server"},
	// Cursor.
	{".cursor"}, {".config", "cursor-agent"}, {".local", "share", "cursor-agent"},
	{"Library", "Application Support", "Cursor"}, {"AppData", "Roaming", "Cursor"}, {".config", "Cursor"},
	// Windsurf / Devin Desktop.
	{".codeium"}, {".windsurf"}, {".devin"}, {"Library", "Application Support", "Devin"},
	{"Library", "Application Support", "Windsurf"},
	// Kiro and Amazon Q.
	{".kiro"}, {".amazonq"}, {".aws", "amazonq"}, {"Library", "Application Support", "Kiro"},
	// opencode, Kilo, Crush, Amp, goose.
	{".opencode"}, {".config", "opencode"}, {".local", "share", "opencode"},
	{".kilocode"}, {".config", "kilo"},
	{".crush"}, {".config", "crush"}, {".local", "share", "crush"}, {"AppData", "Local", "crush"},
	{".amp"}, {".config", "amp"}, {"AppData", "Roaming", "amp"},
	{".config", "goose"}, {".local", "share", "goose"}, {"AppData", "Roaming", "Block", "goose"},
	// Cline, Roo/Zoo, Continue, Zed.
	{".cline"}, {".roo"}, {".continue"}, {".zed"}, {".config", "zed"}, {"AppData", "Roaming", "Zed"},
	{"globalStorage", "saoudrizwan.claude-dev"}, {"globalStorage", "rooveterinaryinc.roo-cline"},
	{"globalStorage", "zoocodeorganization.zoo-code"}, {"globalStorage", "kilocode.kilo-code"},
	{"globalStorage", "github.copilot-chat"}, {"globalStorage", "github.copilot"},
	{"globalStorage", "continue.continue"},
	// Other terminal agents.
	{".qwen"}, {".factory"}, {".junie"}, {".local", "share", "junie"}, {".kimi-code"}, {".vibe"},
	{".grok"}, {".pi", "agent"}, {".augment"}, {".hermes"}, {"AppData", "Local", "hermes"},
	{".openclaw"}, {".clawdbot"}, {".openhands"},
	// Cross-agent convention directories.
	{".agents"}, {".config", "agents"},
	// Desktop apps and orchestrators that host agents.
	{".lmstudio"}, {".warp"}, {".trae"}, {".qoder"}, {".codebuddy"}, {".zcode"}, {".conductor"},
	{".aionui"}, {".t3"},
}

type agentDirIndex struct {
	byFirst map[string][][]string // lower-cased first component -> lower-cased sequences
	exact   map[string][][]string // same, original case, parallel order
}

var (
	agentOnce sync.Once
	agentIdx  agentDirIndex
)

func agentIndex() *agentDirIndex {
	agentOnce.Do(func() {
		agentIdx.byFirst = map[string][][]string{}
		agentIdx.exact = map[string][][]string{}
		for _, seq := range agentDirs {
			low := make([]string, len(seq))
			for i, s := range seq {
				low[i] = strings.ToLower(s)
			}
			agentIdx.byFirst[low[0]] = append(agentIdx.byFirst[low[0]], low)
			agentIdx.exact[low[0]] = append(agentIdx.exact[low[0]], seq)
		}
	})
	return &agentIdx
}

// findAgentDir returns the index of the first component BELOW the outermost
// agent directory in the path, or -1.
func findAgentDir(lp *lexPath) int {
	idx := agentIndex()
	for i, seg := range lp.lsegs {
		cands := idx.byFirst[seg]
		if cands == nil {
			if !lp.wild[i] {
				continue
			}
			// "~/.clau*": compare the wildcard against every directory name.
			if end := findAgentDirWild(lp, i); end >= 0 {
				return end
			}
			continue
		}
		best := -1
		for c, low := range cands {
			if i+len(low) > len(lp.segs) {
				continue
			}
			ok := true
			for j := range low {
				if lp.fold {
					ok = lp.lsegs[i+j] == low[j]
				} else {
					ok = lp.segs[i+j] == idx.exact[seg][c][j]
				}
				if !ok {
					break
				}
			}
			if ok && i+len(low) > best {
				best = i + len(low)
			}
		}
		if best >= 0 {
			return best
		}
	}
	return -1
}

func findAgentDirWild(lp *lexPath, i int) int {
	if literalLen(lp.segs[i]) < 3 {
		return -1
	}
	for _, seq := range agentDirs {
		if len(seq) != 1 {
			continue
		}
		sp := segPat{lit: seq[0], low: strings.ToLower(seq[0])}
		if ok, firm := matchSeg(&sp, lp, i, lp.fold); ok && firm {
			return i + 1
		}
	}
	return -1
}

var (
	agentSkillDirs = map[string]bool{
		"skills": true, "plugins": true, "commands": true, "agents": true,
		"extensions": true, "prompts": true, "workflows": true,
		"output-styles": true, "recipes": true, "powers": true, "modes": true,
		"dev-mods": true, "mods": true, "plugin": true, "chatmodes": true,
	}
	agentMemoryDirs = map[string]bool{
		"rules": true, "memory": true, "memories": true, "agent-memory": true,
		"steering": true, "guidelines.md": true, "memory-bank": true,
	}
	agentHookDirs = map[string]bool{"hooks": true, "hooks.json": true}
	// agentTranscriptDirs: Claude Code projects/ and history.jsonl, Codex
	// sessions/ and archived_sessions/, Copilot session-state/, and the
	// equivalents in other agents.
	agentTranscriptDirs = map[string]bool{
		"projects": true, "sessions": true, "archived_sessions": true,
		"session-state": true, "chats": true, "conversations": true,
		"transcripts": true, "history.jsonl": true, "session-store.db": true,
		"file-history": true, "history": true,
	}
	// agentNestedDirs are product directories one level inside a shared
	// vendor directory (~/.codeium/windsurf, ~/.gemini/antigravity).
	agentNestedDirs = map[string]bool{
		"windsurf": true, "antigravity": true, "antigravity-cli": true,
		"antigravity-ide": true, "config": true, "settings": true, "user": true,
	}
)

// agentSubclass classifies a path by its position inside an agent directory.
// rest holds the lower-cased components below the directory.
func agentSubclass(rest []string) pathClass {
	if len(rest) == 0 {
		return pcAgentConfig
	}
	r0 := rest[0]
	switch {
	case agentSkillDirs[r0]:
		return pcAgentSkill
	case agentMemoryDirs[r0] || strings.HasPrefix(r0, "rules-"):
		return pcAgentMemory
	case agentHookDirs[r0]:
		return pcAgentHook
	case r0 == "projects":
		// ~/.claude/projects/<project>/memory/ is auto memory;
		// <session>/tool-results/ holds spilled tool output the agent is told
		// to read back, so reading it is ordinary and it is not classed as a
		// transcript (code.claude.com/docs/en/claude-directory.md).
		if len(rest) >= 3 && rest[2] == "memory" {
			return pcAgentMemory
		}
		for _, r := range rest[1:] {
			if r == "tool-results" {
				return pcAgentConfig
			}
		}
		return pcAgentTranscript
	case agentTranscriptDirs[r0], strings.HasPrefix(r0, "state_") && strings.HasSuffix(r0, ".sqlite"):
		return pcAgentTranscript
	case r0 == "tmp":
		// Gemini CLI: ~/.gemini/tmp/<project_hash>/chats/.
		for _, r := range rest[1:] {
			if r == "chats" {
				return pcAgentTranscript
			}
		}
		return pcAgentConfig
	case agentNestedDirs[r0] && len(rest) > 1:
		return agentSubclass(rest[1:])
	}
	return pcAgentConfig
}
