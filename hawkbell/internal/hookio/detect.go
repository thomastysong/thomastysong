package hookio

import (
	"errors"
	"strings"
)

// Event names that exist in exactly one dialect. A payload naming one of
// them is identified without looking further.
var (
	geminiOnly = set("BeforeTool", "AfterTool", "BeforeAgent", "AfterAgent", "BeforeModel", "AfterModel", "BeforeToolSelection", "PreCompress")
	cursorOnly = set("beforeSubmitPrompt", "beforeShellExecution", "afterShellExecution", "beforeMCPExecution", "afterMCPExecution",
		"beforeReadFile", "afterFileEdit", "afterAgentResponse", "afterAgentThought", "beforeTabFileRead", "afterTabFileEdit")
	claudeOnly = set("Setup", "InstructionsLoaded", "UserPromptExpansion", "MessageDisplay", "PermissionDenied", "PostToolBatch",
		"TaskCreated", "TaskCompleted", "StopFailure", "TeammateIdle", "ConfigChange", "CwdChanged", "DirectoryAdded", "FileChanged",
		"WorktreeCreate", "WorktreeRemove", "PreModelSwitch", "PostModelSwitch", "Elicitation", "ElicitationResult")
	codexOnly   = set("Interrupt", "PreModelRequest", "PostModelRequest")
	copilotOnly = set("ErrorOccurred", "errorOccurred", "userPromptSubmitted", "userPromptTransformed", "agentStop")
	// Fields only Claude Code sends (hooks reference, common input fields
	// and per-event inputs); none of them is in Codex's closed schemas.
	claudeFields = []string{"prompt_id", "scratchpad_dir", "effort", "mcp_server", "background_tasks", "session_crons", "permission_suggestions"}
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Detect guesses the dialect from the payload when --agent was not given.
//
// The payload is trusted over the environment: it is written by the agent
// that invoked the hook, whereas environment variables are inherited, so an
// agent started from inside another agent's shell tool carries both agents'
// markers. The environment only breaks ties the payload leaves open (Claude
// Code and Codex send identical SessionEnd payloads) and stands in when the
// payload cannot be read at all.
func Detect(stdin []byte, env map[string]string) (d Dialect, ok bool) {
	defer func() {
		if recover() != nil {
			d, ok = nil, false
		}
	}()
	m, _, err := decodeObject(stdin)
	if err != nil && (errors.Is(err, ErrTooLarge) || errors.Is(err, ErrTooDeep)) {
		m = salvage(stdin)
	}
	id := detectPayload(obj(m), env)
	if id == "" {
		id = detectEnv(env)
	}
	if id == "" {
		return nil, false
	}
	return Get(id)
}

func detectPayload(p obj, env map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	name := p.str("hook_event_name")

	// Cursor stamps every payload with its version and conversation ids.
	if p.has("cursor_version") || (p.has("conversation_id") && (p.has("generation_id") || p.has("workspace_roots"))) || cursorOnly[name] {
		return "cursor"
	}
	if geminiOnly[name] {
		return "gemini"
	}
	// camelCase keys are Copilot's native format; no other dialect uses
	// them. (Checked after Cursor, whose events are camelCase but whose
	// fields are snake_case.)
	if p.has("sessionId") || p.has("toolName") || p.has("toolArgs") || copilotOnly[name] {
		return "copilot"
	}
	if claudeOnly[name] {
		return "claude"
	}
	if codexOnly[name] {
		return "codex"
	}
	if name == "" {
		return ""
	}
	if name[0] >= 'a' && name[0] <= 'z' {
		// A camelCase event name without Cursor's markers: Copilot naming.
		if _, known := copilotKinds[strings.ToLower(name)]; known {
			return "copilot"
		}
		return ""
	}

	// From here on the name is one that several snake_case dialects share
	// (SessionStart, PreToolUse, Stop ...).
	hasTimestamp := p.has("timestamp")
	// Gemini's base input always has both timestamp and transcript_path;
	// Copilot's SessionStart/SessionEnd have a timestamp but no transcript
	// path, and Claude Code and Codex send no timestamp at all.
	if hasTimestamp && p.has("transcript_path") && (name == "SessionStart" || name == "SessionEnd" || name == "Notification") {
		return "gemini"
	}
	// turn_id is a Codex extension present on every turn-scoped event.
	if p.has("turn_id") {
		return "codex"
	}
	for _, f := range claudeFields {
		if p.has(f) {
			return "claude"
		}
	}
	// Copilot's VS Code-compatible payloads carry an ISO timestamp and never
	// a permission mode.
	if hasTimestamp && !p.has("permission_mode") {
		return "copilot"
	}
	// Where the transcript lives names the agent: Codex writes
	// rollout-<time>-<id>.jsonl under $CODEX_HOME/sessions, Claude Code
	// writes under ~/.claude/projects.
	switch transcriptOwner(p.str("transcript_path")) {
	case "codex":
		return "codex"
	case "claude":
		return "claude"
	}
	// Session id equality is the strongest environment evidence: the agent
	// that wrote the payload also exported its id to the hook process.
	if sid := p.str("session_id"); sid != "" {
		if sid == envGet(env, "CLAUDE_CODE_SESSION_ID") {
			return "claude"
		}
		if sid == envGet(env, "CODEX_SESSION_ID") || sid == envGet(env, "CODEX_THREAD_ID") {
			return "codex"
		}
	}
	if p.has("permission_mode") {
		// Codex requires model on every event and permission_mode on
		// SessionStart; Claude Code sends model only on SessionStart and
		// documents no permission_mode there.
		if name == "SessionStart" || p.has("model") {
			return "codex"
		}
	}
	codexEnv := envGet(env, "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_VERSION") != ""
	claudeEnv := envGet(env, "CLAUDECODE", "CLAUDE_CODE_SESSION_ID") != ""
	if codexEnv && !claudeEnv {
		return "codex"
	}
	if _, known := claudeTypes[name]; known {
		// The wire originated with Claude Code and it is the most widely
		// deployed speaker of it.
		return "claude"
	}
	return ""
}

// detectEnv identifies the agent from hook-process environment markers
// alone. It answers only when exactly one agent's markers are present.
func detectEnv(env map[string]string) string {
	var found []string
	if envGet(env, "CURSOR_VERSION") != "" {
		found = append(found, "cursor")
	}
	if envGet(env, "GEMINI_SESSION_ID", "GEMINI_PROJECT_DIR", "GEMINI_CWD") != "" {
		found = append(found, "gemini")
	}
	if envGet(env, "COPILOT_CLI") != "" || strings.HasPrefix(envGet(env, "AI_AGENT"), "github_copilot_") {
		found = append(found, "copilot")
	}
	if envGet(env, "CODEX_THREAD_ID", "CODEX_SESSION_ID") != "" {
		found = append(found, "codex")
	}
	if envGet(env, "CLAUDECODE", "CLAUDE_CODE_SESSION_ID") != "" {
		found = append(found, "claude")
	}
	if len(found) == 1 {
		return found[0]
	}
	if len(found) == 0 && envGet(env, "CLAUDE_PROJECT_DIR") != "" {
		// Cursor and Gemini export CLAUDE_PROJECT_DIR as an alias, but they
		// also set their own markers, which are absent here.
		return "claude"
	}
	return ""
}

// transcriptOwner classifies a transcript path by the agent's storage
// layout. Both separators are checked because Windows payloads carry
// backslashes.
func transcriptOwner(tp string) string {
	if tp == "" {
		return ""
	}
	norm := strings.ReplaceAll(tp, "\\", "/")
	base := norm
	if i := strings.LastIndexByte(norm, '/'); i >= 0 {
		base = norm[i+1:]
	}
	switch {
	case strings.HasPrefix(base, "rollout-"):
		return "codex"
	case strings.Contains(norm, "/.claude/"):
		return "claude"
	case strings.Contains(norm, "/.codex/"):
		return "codex"
	}
	return ""
}
