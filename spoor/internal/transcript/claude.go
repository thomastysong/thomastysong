package transcript

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// claudeParser reads Claude Code session logs.
//
// Layout (code.claude.com/docs/en/claude-directory): one JSONL file per
// session under <config>/projects/<slug>/<session-id>.jsonl, subagents in
// <session-id>/subagents/agent-<agentId>.jsonl. The vendor documents the
// entry format as internal and unstable; the record shapes used here are the
// ones confirmed by Fleet's ai_agent_sessions table (MIT) and uber/ADR's
// claude_parser.py (Apache-2.0) against real captures.
type claudeParser struct{}

func (claudeParser) AgentID() string { return toolmap.AgentClaude }
func (claudeParser) Format() string  { return FormatClaude }

func (claudeParser) Match(path string) bool {
	p := slashPath(path)
	if !strings.HasSuffix(p, ".jsonl") || !strings.Contains(p, "/projects/") {
		return false
	}
	// Spilled tool outputs live next to the transcript and are not logs.
	return !strings.Contains(p, "/tool-results/")
}

func (p claudeParser) ParseLine(line []byte, st *FileState) ([]*event.Event, error) {
	return parseGuard(p.AgentID(), line, st, parseClaude)
}

type claudeRecord struct {
	Type           string `json:"type"`
	Subtype        string `json:"subtype"`
	Timestamp      string `json:"timestamp"`
	SessionID      string `json:"sessionId"`
	AgentID        string `json:"agentId"`
	CWD            string `json:"cwd"`
	Version        string `json:"version"`
	PermissionMode string `json:"permissionMode"`
	ToolDenialKind string `json:"toolDenialKind"`
	IsSidechain    bool   `json:"isSidechain"`
	IsMeta         bool   `json:"isMeta"`
	IsCompact      bool   `json:"isCompactSummary"`
	Message        struct {
		Model   string          `json:"model"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	CompactMetadata struct {
		Trigger string `json:"trigger"`
	} `json:"compactMetadata"`
}

type claudeBlock struct {
	Type      string          `json:"type"`
	Text      json.RawMessage `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	IsError   bool            `json:"is_error"`
	Content   json.RawMessage `json:"content"`
}

// claudeBookkeeping are record types that carry no activity. The list is
// uber/ADR's _METADATA_RECORD_TYPES; anything outside it and the three
// conversation types counts as unknown, which is how schema drift shows up.
var claudeBookkeeping = map[string]bool{
	"summary": true, "progress": true, "attachment": true, "file-history-snapshot": true,
	"queue-operation": true, "custom-title": true, "ai-title": true, "tag": true,
	"agent-name": true, "agent-color": true, "last-prompt": true, "permission-mode": true,
	"pr-link": true, "content-replacement": true,
}

// claudeInjected are prefixes of user records the CLI writes itself: slash
// commands and their output, and "!" shell commands. They look like prompts
// but nobody typed them to the model. (Fleet ai_agent_sessions.)
var claudeInjected = []string{
	"<command-message>", "<command-name>", "<local-command-stdout>", "<local-command-caveat>",
	"<bash-input>", "<bash-stdout>", "<bash-stderr>", "<system-reminder>",
}

// claudeSubagentPath reports whether a transcript path is a subagent's own
// file: <session>/subagents/agent-<id>.jsonl, or (older) a flat
// agent-<id>.jsonl in the project directory.
func claudeSubagentPath(path string) bool {
	p := slashPath(path)
	return strings.Contains(p, "/subagents/") || strings.HasPrefix(baseName(p), "agent-")
}

func claudeIsInjected(text string) bool {
	text = strings.TrimLeft(head(text, 256), " \t\r\n")
	for _, p := range claudeInjected {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return false
}

// claudeModes maps Claude Code's permission_mode values to the event
// vocabulary (default | plan | accept_edits | auto | dont_ask | bypass).
var claudeModes = map[string]string{
	"default": "default", "plan": "plan", "acceptEdits": "accept_edits",
	"auto": "auto", "dontAsk": "dont_ask", "bypassPermissions": "bypass",
}

func parseClaude(c *lineCtx) error {
	var rec claudeRecord
	if err := decode(c.line, &rec); err != nil {
		return err
	}
	st := c.st
	ts := parseTime(rec.Timestamp)

	if rec.SessionID != "" {
		st.SessionID = clip(rec.SessionID, maxIDLen)
	}
	// Subagent turns live in their own file, or (older versions) in the
	// session's file flagged isSidechain.
	sub := rec.IsSidechain || (rec.AgentID != "" && claudeSubagentPath(st.Path))
	if !sub {
		if rec.CWD != "" {
			st.CWD = clip(rec.CWD, maxCWDLen)
		}
	} else if st.CWD == "" && rec.CWD != "" {
		st.CWD = clip(rec.CWD, maxCWDLen)
	}
	if rec.Version != "" {
		st.Version = clip(rec.Version, maxVersionLen)
	}
	c.claudeMode(rec, ts)

	evs0 := len(c.out)
	switch rec.Type {
	case "user":
		c.claudeUser(rec, ts, sub)
	case "assistant":
		c.claudeAssistant(rec, ts, sub)
	case "system":
		// UNVERIFIED: the compact_boundary subtype and compactMetadata
		// field follow the Agent SDK's SDKCompactBoundaryMessage; the
		// on-disk spelling was not confirmed against a capture.
		if rec.Subtype == "compact_boundary" {
			e := c.newEvent(event.TypeCompact, ts)
			switch rec.CompactMetadata.Trigger {
			case "auto", "manual":
				c.label(e, "trigger", rec.CompactMetadata.Trigger)
			}
		}
	default:
		if !claudeBookkeeping[rec.Type] {
			st.Unknown++
		}
	}
	if sub {
		for _, e := range c.out[evs0:] {
			if e.Session != nil {
				e.Session.SubagentID = clip(rec.AgentID, maxIDLen)
				if e.Session.SubagentID == "" {
					// Older in-file sidechains carry no agent id; the
					// marker still has to say "not the main agent".
					e.Session.SubagentID = "sidechain"
				}
			}
		}
	}
	return nil
}

// claudeMode tracks the session permission mode. The "permission-mode"
// record and the permissionMode field on user records both carry it.
// UNVERIFIED: the field name on the permission-mode record (ADR only lists
// the record type); the same camelCase name as on user records is assumed.
func (c *lineCtx) claudeMode(rec claudeRecord, ts time.Time) {
	if rec.PermissionMode == "" {
		return
	}
	mode, ok := claudeModes[rec.PermissionMode]
	if !ok {
		return
	}
	prev := c.st.PermissionMode
	c.st.PermissionMode = mode
	// The first sighting sets the baseline; only a change is an event, so
	// a switch to bypass is visible even if no tool call follows it.
	if prev != "" && prev != mode {
		e := c.newEvent(event.TypeConfigChange, ts)
		c.label(e, "change", "permission_mode")
		c.label(e, "from", prev)
		c.label(e, "to", mode)
	}
}

func (c *lineCtx) claudeUser(rec claudeRecord, ts time.Time, sub bool) {
	body := rec.Message.Content
	switch rawKind(body) {
	case '"':
		text := rawString(body)
		c.claudeUserText(rec, ts, sub, text)
	case '[':
		var blocks []claudeBlock
		if decode(body, &blocks) != nil {
			c.st.Unknown++
			return
		}
		var texts []string
		for i := range blocks {
			b := &blocks[i]
			switch b.Type {
			case "text":
				if t := rawString(b.Text); t != "" && !claudeIsInjected(t) {
					texts = append(texts, t)
				}
			case "tool_result":
				c.claudeResult(rec, ts, b)
			}
			// Images, documents and other blocks carry no activity.
		}
		if len(texts) > 0 {
			c.claudeUserText(rec, ts, sub, strings.Join(texts, "\n"))
		}
	}
}

func (c *lineCtx) claudeUserText(rec claudeRecord, ts time.Time, sub bool, text string) {
	if text == "" || rec.IsMeta || rec.IsCompact || claudeIsInjected(text) {
		return
	}
	// UNVERIFIED: Claude Code records an interrupt as a user record whose
	// text starts with this marker.
	if strings.HasPrefix(text, "[Request interrupted by user") {
		e := c.newEvent(event.TypeTurnEnd, ts)
		e.Outcome = &event.Outcome{Status: statusInterrupted}
		return
	}
	if sub {
		// A subagent's "user" is the parent agent handing over its task.
		// The first such record marks the subagent's start; its text is
		// the instruction, kept for local injection scanning.
		key := "sub:" + rec.AgentID
		if !c.st.remember(key) {
			e := c.newEvent(event.TypeSubagentStart, ts)
			e.Content = &event.Content{PromptText: text}
			e.Prompt = &event.Prompt{Len: len(text)}
		}
		return
	}
	c.prompt(ts, text)
}

func (c *lineCtx) claudeAssistant(rec claudeRecord, ts time.Time, sub bool) {
	model := rec.Message.Model
	if strings.HasPrefix(model, "<") { // "<synthetic>" is not a model
		model = ""
	}
	model = clip(model, maxModelLen)
	if model != "" && !sub {
		c.st.Model = model
	}
	if rawKind(rec.Message.Content) != '[' {
		return
	}
	var blocks []claudeBlock
	if decode(rec.Message.Content, &blocks) != nil {
		c.st.Unknown++
		return
	}
	for i := range blocks {
		b := &blocks[i]
		switch b.Type {
		case "tool_use", "server_tool_use":
			input := rawObject(b.Input)
			kind, server, tool := toolmap.KindWithInput(c.agent, b.Name, input)
			e := c.toolPre(ts, b.Name, b.ID, kind, server, tool, input)
			if model != "" {
				e.Session.Model = model
			}
			if kind == event.ToolSubagent {
				if s, _ := input["subagent_type"].(string); s != "" {
					c.label(e, "subagent_type", clip(s, maxNameLen))
				}
			}
		default:
			// Server tools report their result in the assistant message
			// itself, as a *_tool_result block naming the call.
			if strings.HasSuffix(b.Type, "_tool_result") && b.ToolUseID != "" {
				c.toolPost(ts, b.ToolUseID, textOf(b.Content), &event.Outcome{Status: statusOK})
			}
		}
	}
}

// claudeResult turns a tool_result block into tool.post.
func (c *lineCtx) claudeResult(rec claudeRecord, ts time.Time, b *claudeBlock) {
	text := textOf(b.Content)
	var name string
	var mcp bool
	if pre := c.st.Pending[b.ToolUseID]; pre != nil && pre.Tool != nil {
		name, mcp = pre.Tool.Name, pre.Tool.Kind == event.ToolMCP
	}
	oc := claudeOutcome(rec.ToolDenialKind, b.IsError, text, mcp)
	if oc.Status == statusError && !mcp && strings.EqualFold(name, "Bash") {
		if code, ok := exitCodeAfter(head(text, 256), false, "Exit code "); ok {
			oc.ExitCode = intPtr(code)
			oc.Error = "exit_code"
		}
	}
	c.toolPost(ts, b.ToolUseID, text, oc)
}

// claudeOutcome maps a tool result to an outcome. Every refusal and failure
// is marked is_error; newer transcripts name the kind of refusal in
// toolDenialKind, older ones only in the result text. An MCP server words
// its own errors and could word one like a refusal, so for MCP calls the
// text is never read as a denial. (Decision table from Fleet's
// ai_agent_sessions claudeDecision.)
func claudeOutcome(denialKind string, isError bool, text string, mcp bool) *event.Outcome {
	switch {
	case denialKind == "user-rejected":
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "user", Error: "user_rejected"}
	case denialKind == "permission-rule":
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "policy", Error: "permission_rule"}
	case strings.HasPrefix(denialKind, "automode-"):
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "policy", Error: "auto_mode"}
	case denialKind == "interrupted" || denialKind == "cancelled":
		return &event.Outcome{Status: statusInterrupted, Error: denialKind}
	case !isError:
		return &event.Outcome{Status: statusOK}
	case denialKind != "" || mcp:
		return &event.Outcome{Status: statusError, Error: "tool_error"}
	}
	first := firstLine(text, 256)
	switch {
	case strings.HasPrefix(first, "The user doesn't want to proceed"),
		strings.HasPrefix(first, "The user doesn't want to take this action"):
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "user", Error: "user_rejected"}
	case strings.HasPrefix(first, "Permission to use"),
		strings.HasPrefix(first, "Permission for this action"):
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "policy", Error: "permission_rule"}
	case strings.HasPrefix(first, "Hook PreToolUse:") && strings.Contains(first, "denied this tool"),
		strings.HasPrefix(first, "Blocked by hook"),
		strings.HasPrefix(first, "Permission denied by hook"):
		return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "hook", Error: "hook_denied"}
	case strings.HasPrefix(first, "[Request interrupted by user"):
		return &event.Outcome{Status: statusInterrupted, Error: "interrupted"}
	}
	return &event.Outcome{Status: statusError, Error: "tool_error"}
}
