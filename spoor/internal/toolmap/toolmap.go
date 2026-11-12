// Package toolmap normalizes each agent's own tool names to event.ToolKind.
// Hook dialects and transcript parsers both use it so the two surfaces agree
// on what a tool call is; disagreement would break cross-surface correlation.
//
// Sources for the tables (read 2026-11-11):
//   - Claude Code: https://code.claude.com/docs/en/tools-reference.md
//   - Codex: openai/codex main, codex-rs/core/src/tools/handlers/*_spec.rs and
//     codex-rs/protocol/src/models.rs (ResponseItem variants)
//   - Gemini CLI: google-gemini/gemini-cli main,
//     packages/core/src/tools/definitions/base-declarations.ts, tool-names.ts
//     and mcp-tool.ts
//   - Copilot CLI and Cursor: tool names confirmed by captures in Fleet's
//     orbit/pkg/table/ai_agent_sessions/target.go (MIT); the rest are marked
//     UNVERIFIED below.
//
// Every built-in tool of a known agent is listed explicitly, including the
// ones that map to "other": the name heuristic is only a fallback for tools
// this table has never heard of, and a heuristic guess on a known tool
// (TodoWrite is not a file write) would be a false signal.
package toolmap

import (
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Canonical agent ids (catalog ids) the tables are keyed by.
const (
	AgentClaude  = "claude-code"
	AgentCodex   = "codex"
	AgentGemini  = "gemini-cli"
	AgentCopilot = "copilot-cli"
	AgentCursor  = "cursor"
)

// aliases maps hook dialect ids and close relatives to a table key, so a
// caller holding "claude" (dialect) and one holding "claude-code" (catalog)
// classify identically.
var aliases = map[string]string{
	"claude":           AgentClaude,
	"claude-code":      AgentClaude,
	"claude-agent-sdk": AgentClaude,
	"claude-desktop":   AgentClaude,
	"codex":            AgentCodex,
	"codex-cli":        AgentCodex,
	"gemini":           AgentGemini,
	"gemini-cli":       AgentGemini,
	"qwen-code":        AgentGemini, // fork of Gemini CLI, same tool names
	"copilot":          AgentCopilot,
	"copilot-cli":      AgentCopilot,
	"github-copilot":   AgentCopilot,
	"cursor":           AgentCursor,
	"cursor-agent":     AgentCursor,
	"cursor-cli":       AgentCursor,
}

// Canonical returns the table key for an agent id, or the id itself when it
// is not a known alias.
func Canonical(agentID string) string {
	if c, ok := aliases[strings.ToLower(agentID)]; ok {
		return c
	}
	return agentID
}

// exact holds per-agent exact-name tables. Keys are lower-cased tool names.
var exact = map[string]map[string]event.ToolKind{
	AgentClaude: {
		// Shell. Monitor runs a command in the background and shares Bash's
		// permission rules. BashOutput and KillShell are pre-2.1 names.
		"bash": event.ToolShell, "powershell": event.ToolShell, "monitor": event.ToolShell,
		"bashoutput": event.ToolShell, "killshell": event.ToolShell,
		// Files. LSP reads code through a language server and is governed by
		// Read permission rules.
		"read": event.ToolFileRead, "notebookread": event.ToolFileRead, "lsp": event.ToolFileRead,
		"write": event.ToolFileWrite,
		"edit":  event.ToolFileEdit, "multiedit": event.ToolFileEdit, "notebookedit": event.ToolFileEdit,
		"glob": event.ToolFileList, "grep": event.ToolFileList, "ls": event.ToolFileList,
		// Network.
		"webfetch": event.ToolWebFetch, "websearch": event.ToolWebSearch,
		// Subagents. Task is the pre-2.1 name of Agent; Workflow orchestrates
		// many subagents from a script.
		"agent": event.ToolSubagent, "task": event.ToolSubagent, "workflow": event.ToolSubagent,
		// MCP plumbing tools: the server is in the input, not the name.
		"listmcpresourcestool": event.ToolMCP, "readmcpresourcetool": event.ToolMCP,
		// Everything else in the tools reference has no cross-agent class.
		"artifact": event.ToolOther, "askuserquestion": event.ToolOther,
		"croncreate": event.ToolOther, "crondelete": event.ToolOther, "cronlist": event.ToolOther,
		"endconversation": event.ToolOther, "enterplanmode": event.ToolOther, "exitplanmode": event.ToolOther,
		"enterworktree": event.ToolOther, "exitworktree": event.ToolOther,
		"listagents": event.ToolOther, "pushnotification": event.ToolOther, "remotetrigger": event.ToolOther,
		"reportfindings": event.ToolOther, "schedulewakeup": event.ToolOther, "sendfeedback": event.ToolOther,
		"sendmessage": event.ToolOther, "senduserfile": event.ToolOther, "shareonboardingguide": event.ToolOther,
		"skill": event.ToolOther, "subagenthandback": event.ToolOther,
		// StructuredOutput is the Agent SDK's result tool (seen in 2.1.322 logs).
		"structuredoutput": event.ToolOther,
		"taskcreate":       event.ToolOther, "taskget": event.ToolOther, "tasklist": event.ToolOther,
		"taskoutput": event.ToolOther, "taskstop": event.ToolOther, "taskupdate": event.ToolOther,
		"todowrite": event.ToolOther, "toolsearch": event.ToolOther, "waitformcpservers": event.ToolOther,
	},
	AgentCodex: {
		// exec_command/write_stdin are the unified exec tools on main; shell,
		// shell_command, local_shell and container.exec are older or
		// model-specific names still present in rollouts.
		"exec_command": event.ToolShell, "write_stdin": event.ToolShell,
		"shell": event.ToolShell, "shell_command": event.ToolShell, "local_shell": event.ToolShell,
		"local_shell_call": event.ToolShell, "unified_exec": event.ToolShell, "container.exec": event.ToolShell,
		"apply_patch": event.ToolFileEdit,
		"view_image":  event.ToolFileRead, "read_file": event.ToolFileRead,
		"list_dir": event.ToolFileList, "grep_files": event.ToolFileList,
		"web_search": event.ToolWebSearch, "web_search_call": event.ToolWebSearch, "web_fetch": event.ToolWebFetch,
		// Multi-agent tools that hand instructions to another agent.
		"spawn_agent": event.ToolSubagent, "resume_agent": event.ToolSubagent, "send_input": event.ToolSubagent,
		"send_message": event.ToolSubagent, "followup_task": event.ToolSubagent,
		"wait_agent": event.ToolOther, "list_agents": event.ToolOther, "close_agent": event.ToolOther,
		"interrupt_agent":    event.ToolOther,
		"list_mcp_resources": event.ToolMCP, "list_mcp_resource_templates": event.ToolMCP, "read_mcp_resource": event.ToolMCP,
		"update_plan": event.ToolOther, "request_permissions": event.ToolOther, "request_user_input": event.ToolOther,
		"tool_search": event.ToolOther, "tool_search_call": event.ToolOther,
	},
	AgentGemini: {
		"run_shell_command": event.ToolShell,
		"read_file":         event.ToolFileRead, "read_many_files": event.ToolFileRead,
		"write_file": event.ToolFileWrite,
		"replace":    event.ToolFileEdit, "edit": event.ToolFileEdit,
		// search_file_content is the legacy alias of grep_search.
		"glob": event.ToolFileList, "list_directory": event.ToolFileList, "grep_search": event.ToolFileList,
		"search_file_content": event.ToolFileList, "grep": event.ToolFileList,
		"web_fetch": event.ToolWebFetch, "google_web_search": event.ToolWebSearch,
		"invoke_agent":      event.ToolSubagent,
		"read_mcp_resource": event.ToolMCP, "list_mcp_resources": event.ToolMCP,
		"write_todos": event.ToolOther, "get_internal_docs": event.ToolOther, "activate_skill": event.ToolOther,
		"ask_user": event.ToolOther, "enter_plan_mode": event.ToolOther, "exit_plan_mode": event.ToolOther,
		"update_topic": event.ToolOther, "complete_task": event.ToolOther,
		"tracker_create_task": event.ToolOther, "tracker_update_task": event.ToolOther, "tracker_get_task": event.ToolOther,
		"tracker_list_tasks": event.ToolOther, "tracker_add_dependency": event.ToolOther, "tracker_visualize": event.ToolOther,
	},
	AgentCopilot: {
		"bash": event.ToolShell, "powershell": event.ToolShell, "local_shell": event.ToolShell, "shell": event.ToolShell,
		// UNVERIFIED: write_bash/read_bash/stop_bash (interactive shell session tools).
		"write_bash": event.ToolShell, "read_bash": event.ToolShell, "stop_bash": event.ToolShell,
		"view": event.ToolFileRead, "read": event.ToolFileRead,
		"create": event.ToolFileWrite, "write": event.ToolFileWrite,
		// str_replace_editor is an edit unless its input says command=view;
		// KindWithInput refines that case.
		"edit": event.ToolFileEdit, "str_replace": event.ToolFileEdit, "str_replace_editor": event.ToolFileEdit,
		"apply_patch": event.ToolFileEdit,
		"glob":        event.ToolFileList, "grep": event.ToolFileList, "rg": event.ToolFileList,
		"web_fetch": event.ToolWebFetch, "fetch": event.ToolWebFetch, "web_search": event.ToolWebSearch,
		"task": event.ToolSubagent,
		// UNVERIFIED names, listed so the heuristic does not misread them.
		"report_intent": event.ToolOther, "update_todo": event.ToolOther, "ask_user": event.ToolOther,
		"read_agent": event.ToolOther, "list_agents": event.ToolOther, "store_memory": event.ToolOther,
		"skill": event.ToolOther, "sql": event.ToolOther,
	},
	AgentCursor: {
		// Read/Write/Glob/Grep/Shell/WebFetch are confirmed by Fleet's
		// captures; the snake_case names are older composer tool names.
		// UNVERIFIED: run_terminal_cmd, terminal, read_file, edit_file,
		// search_replace, delete_file, list_dir, codebase_search, fetch, task.
		"shell": event.ToolShell, "run_terminal_cmd": event.ToolShell, "terminal": event.ToolShell,
		"read": event.ToolFileRead, "read_file": event.ToolFileRead,
		"write": event.ToolFileWrite,
		"edit":  event.ToolFileEdit, "edit_file": event.ToolFileEdit, "search_replace": event.ToolFileEdit,
		"delete_file": event.ToolFileEdit,
		"grep":        event.ToolFileList, "glob": event.ToolFileList, "list_dir": event.ToolFileList,
		"codebase_search": event.ToolFileList,
		"websearch":       event.ToolWebSearch, "web_search": event.ToolWebSearch,
		"webfetch": event.ToolWebFetch, "fetch": event.ToolWebFetch,
		"task": event.ToolSubagent,
	},
}

// fallbackOrder is the table order tried for an unknown agent id. Many
// agents and SDK harnesses reuse Claude Code's or Codex's tool names.
var fallbackOrder = []string{AgentClaude, AgentCodex, AgentGemini, AgentCopilot, AgentCursor}

// Kind maps an agent's tool name to a normalized kind. For MCP tools it also
// returns the server and tool parts. Unknown agents and names fall back to
// name heuristics so a new tool is classified approximately rather than lost.
func Kind(agentID, toolName string) (kind event.ToolKind, mcpServer, mcpTool string) {
	if toolName == "" {
		return event.ToolOther, "", ""
	}
	agentID = Canonical(agentID)
	if s, t, ok := SplitMCP(agentID, toolName); ok {
		return event.ToolMCP, s, t
	}
	lower := strings.ToLower(toolName)
	if tbl, ok := exact[agentID]; ok {
		if k, ok := tbl[lower]; ok {
			return k, "", ""
		}
	} else {
		for _, id := range fallbackOrder {
			if k, ok := exact[id][lower]; ok {
				return k, "", ""
			}
		}
	}
	return heuristic(toolName), "", ""
}

// Known reports whether the tool name is in the agent's exact table (or is
// an MCP-qualified name), that is, whether Kind's answer is authoritative
// rather than a heuristic guess.
func Known(agentID, toolName string) bool {
	agentID = Canonical(agentID)
	if _, _, ok := SplitMCP(agentID, toolName); ok {
		return true
	}
	_, ok := exact[agentID][strings.ToLower(toolName)]
	return ok
}

// SplitMCP recognizes MCP tool naming conventions:
// "mcp__<server>__<tool>" (Claude Code, Codex, Copilot's Claude-compatible
// payloads) and "mcp_<server>_<tool>" (Gemini CLI). Gemini's own parser takes
// everything up to the first "_" as the server, so a server whose name
// contains "_" is split short there too; callers that have a better source
// (Gemini's transcript displayName, Copilot's mcpServerName) should prefer it.
func SplitMCP(agentID, toolName string) (server, tool string, ok bool) {
	if rest, found := strings.CutPrefix(toolName, "mcp__"); found {
		if i := strings.Index(rest, "__"); i > 0 {
			return rest[:i], rest[i+2:], true
		}
		return rest, "", rest != ""
	}
	switch Canonical(agentID) {
	case AgentGemini:
		if rest, found := strings.CutPrefix(toolName, "mcp_"); found {
			if i := strings.Index(rest, "_"); i > 0 && i < len(rest)-1 {
				return rest[:i], rest[i+1:], true
			}
		}
	}
	return "", "", false
}

// SplitMCPNamespace handles Codex's split form, where a function call carries
// the tool in "name" and the server in "namespace" as "mcp__<server>__".
func SplitMCPNamespace(namespace, name string) (server, tool string, ok bool) {
	rest, found := strings.CutPrefix(namespace, "mcp__")
	if !found {
		return "", "", false
	}
	server = strings.TrimSuffix(rest, "__")
	if server == "" || name == "" {
		return "", "", false
	}
	return server, name, true
}
