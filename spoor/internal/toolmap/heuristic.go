package toolmap

import (
	"strings"
	"unicode"

	"github.com/thomastysong/spoor/internal/event"
)

// maxNameLen bounds how much of a tool name the heuristic looks at. Names
// come from agent output, which an attacker can influence.
const maxNameLen = 256

// words splits a tool name into lower-case words at separators and camelCase
// boundaries: "run_terminal_cmd" -> run, terminal, cmd; "WriteFile" -> write,
// file; "HTTPGet" -> http, get. Matching whole words instead of substrings
// keeps "tools" from matching "ls" and "TaskList" from matching "list" as a
// suffix of something else.
func words(name string) []string {
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
			continue
		case unicode.IsUpper(r) && len(cur) > 0:
			prev := cur[len(cur)-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			// Break "fooBar" before B, and "HTTPGet" before G.
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

// heuristic guesses a kind from the words of a tool name. Order matters:
// more specific classes are tested first.
func heuristic(name string) event.ToolKind {
	ws := words(name)
	if len(ws) == 0 {
		return event.ToolOther
	}
	set := make(map[string]bool, len(ws))
	for _, w := range ws {
		set[w] = true
	}
	has := func(list ...string) bool {
		for _, w := range list {
			if set[w] {
				return true
			}
		}
		return false
	}
	joined := strings.Join(ws, "_")

	switch {
	case has("browser", "navigate", "click", "screenshot", "puppeteer", "playwright", "chrome"):
		return event.ToolBrowser
	case has("websearch") || (has("search") && has("web", "google", "bing", "brave", "internet", "duckduckgo")):
		return event.ToolWebSearch
	case has("fetch", "webfetch", "http", "https", "url", "curl", "wget", "download", "browse"):
		return event.ToolWebFetch
	case has("bash", "shell", "sh", "zsh", "exec", "execute", "terminal", "command", "cmd", "powershell", "pwsh", "subprocess"):
		return event.ToolShell
	case has("subagent", "delegate", "spawn") || joined == "task" || joined == "agent" || joined == "new_task":
		return event.ToolSubagent
	case has("todo", "todos", "plan", "memory", "stdin", "question", "user"):
		// Bookkeeping tools often contain write/read/list words
		// (write_todos, ask_user, update_plan) without touching files.
		return event.ToolOther
	case has("patch", "edit", "replace", "sed", "modify") || strings.Contains(joined, "str_replace"):
		return event.ToolFileEdit
	case has("write", "save", "append") || (has("create") && has("file", "files", "notebook")):
		return event.ToolFileWrite
	case has("glob", "grep", "rg", "find", "ls", "list", "search", "tree", "dir", "directory"):
		return event.ToolFileList
	case has("read", "view", "cat", "open", "head", "tail"):
		return event.ToolFileRead
	}
	return event.ToolOther
}
