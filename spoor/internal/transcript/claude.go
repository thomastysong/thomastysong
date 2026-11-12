package transcript

import (
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// claudeParser reads Claude Code session logs.
//
// Layout (code.claude.com/docs/en/claude-directory): one JSONL file per
// session under <config>/projects/<slug>/<session-id>.jsonl, subagents in
// <session-id>/subagents/[...]/agent-<agentId>.jsonl. The vendor documents
// the entry format as internal and unstable; the record shapes used here are
// the ones confirmed by Fleet's ai_agent_sessions table (MIT) and uber/ADR's
// claude_parser.py (Apache-2.0) against real captures, and checked against
// the logs of Claude Code 2.1.322 (2026-11-11): 9,900 records, none
// unrecognized. Fields noted "2.1.322 capture" below come from that check.
type claudeParser struct{}

func (claudeParser) AgentID() string { return toolmap.AgentClaude }
func (claudeParser) Format() string  { return FormatClaude }

func (claudeParser) Match(path string) bool {
	p := slashPath(path)
	i := strings.LastIndex(p, "/projects/")
	if i < 0 || !strings.HasSuffix(p, ".jsonl") {
		return false
	}
	rest := p[i+len("/projects/"):]
	if strings.Contains(rest, "/subagents/") {
		// Workflow runs keep a journal.jsonl beside their agents'
		// transcripts; only agent-<id>.jsonl is a session log.
		return strings.HasPrefix(baseName(rest), "agent-")
	}
	// <slug>/<session>.jsonl and nothing deeper: spilled tool outputs
	// (<session>/tool-results/) are not logs.
	return strings.Count(rest, "/") == 1
}

func (p claudeParser) ParseLine(line []byte, st *FileState) ([]*event.Event, error) {
	return parseGuard(p.AgentID(), line, st, parseClaude)
}

// claudeRecord is decoded in one pass. message.content is left generic (a
// string or a list of blocks): the blocks are navigated as decoded values
// instead of being re-parsed, which matters on tool results of many KiB.
// Large fields this parser has no use for (toolUseResult, usage, snapshots)
// are not declared and so are skipped without allocation.
type claudeRecord struct {
	Type           string `json:"type"`
	Subtype        string `json:"subtype"`
	UUID           string `json:"uuid"`
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
	Entrypoint     string `json:"entrypoint"`
	Message        struct {
		Model   string `json:"model"`
		Content any    `json:"content"`
	} `json:"message"`
	CompactMetadata struct {
		Trigger string `json:"trigger"`
	} `json:"compactMetadata"`
	// 2.1.322 capture: who a user record came from ({"kind":"human"} or
	// {"kind":"task-notification",...}).
	Origin *claudeOrigin `json:"origin"`
	// 2.1.322 capture: on the user record carrying a tool result, how the
	// call was authorized: {"decision":"accept"|"reject","source":"config",
	// "reasonType":"rule"|"classifier"|"mode"|"safetyCheck",...}.
	PermissionDecision *struct {
		Decision   string `json:"decision"`
		Source     string `json:"source"`
		ReasonType string `json:"reasonType"`
	} `json:"permissionDecision"`
	// 2.1.322 capture: a prompt delivered while the agent was busy is an
	// attachment of type "queued_command", not a user record.
	Attachment *struct {
		Type   string        `json:"type"`
		Prompt any           `json:"prompt"`
		Origin *claudeOrigin `json:"origin"`
	} `json:"attachment"`
}

type claudeOrigin struct {
	Kind string `json:"kind"`
}

func (o *claudeOrigin) label() string {
	if o == nil || o.Kind == "" || o.Kind == "human" {
		return ""
	}
	return safeToken(o.Kind)
}

// claudeSurface maps the record's entrypoint to the event surface
// vocabulary. The values are those of the app.entrypoint telemetry attribute
// (code.claude.com monitoring-usage) plus "remote_mobile" seen in a capture.
func claudeSurface(entrypoint string) string {
	switch {
	case entrypoint == "cli":
		return "cli"
	case strings.HasPrefix(entrypoint, "sdk"):
		return "sdk"
	case entrypoint == "claude-vscode":
		return "ide"
	case entrypoint == "claude-desktop":
		return "desktop"
	case strings.HasPrefix(entrypoint, "remote"):
		return "cloud"
	}
	return ""
}

// claudeBookkeeping are record types that carry no activity. The list is
// uber/ADR's _METADATA_RECORD_TYPES plus atis-latch and tools-used from the
// 2.1.322 capture; anything outside it and the conversation types counts as
// unknown, which is how schema drift shows up.
var claudeBookkeeping = map[string]bool{
	"summary": true, "progress": true, "file-history-snapshot": true,
	"queue-operation": true, "custom-title": true, "ai-title": true, "tag": true,
	"agent-name": true, "agent-color": true, "last-prompt": true, "permission-mode": true,
	"pr-link": true, "content-replacement": true, "atis-latch": true, "tools-used": true,
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
	// Conversation records carry a random uuid: every user, assistant,
	// system and attachment record of a 2.1.322 capture (105 files, about
	// 31,500 such records, none repeated) had one. It is the record's
	// identity (eventIDs); bookkeeping records without one fall back to a
	// keyed digest of the line.
	c.record("u:", rec.UUID)

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
	if s := claudeSurface(rec.Entrypoint); s != "" {
		st.setExtra("surface", s)
	}
	c.claudeMode(rec, ts)

	evs0 := len(c.out)
	switch rec.Type {
	case "user":
		c.claudeUser(rec, ts, sub)
	case "assistant":
		c.claudeAssistant(rec, ts, sub)
	case "attachment":
		// Most attachments are context the CLI adds for the model. A
		// queued command is a prompt that arrived mid-turn.
		if a := rec.Attachment; a != nil && a.Type == "queued_command" && !sub {
			if text := anyText(a.Prompt); text != "" {
				e := c.prompt(ts, text)
				c.label(e, "queued", "true")
				c.label(e, "origin", a.Origin.label())
			}
		}
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
	switch body := rec.Message.Content.(type) {
	case string:
		c.claudeUserText(rec, ts, sub, body)
	case []any:
		var texts []string
		for _, raw := range body {
			b := anyObject(raw)
			switch anyString(b["type"]) {
			case "text":
				if t := anyString(b["text"]); t != "" && !claudeIsInjected(t) {
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
	// A record whose origin is not the human (a background task's
	// notification, say) is still input to the model and is scanned like a
	// prompt; the label keeps it from being counted as something typed.
	e := c.prompt(ts, text)
	c.label(e, "origin", rec.Origin.label())
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
	blocks, _ := rec.Message.Content.([]any)
	for _, raw := range blocks {
		b := anyObject(raw)
		switch typ := anyString(b["type"]); typ {
		case "tool_use", "server_tool_use":
			input := anyObject(b["input"])
			name := anyString(b["name"])
			kind, server, tool := toolmap.KindWithInput(c.agent, name, input)
			e := c.toolPre(ts, name, anyString(b["id"]), kind, server, tool, input)
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
			if id := anyString(b["tool_use_id"]); id != "" && strings.HasSuffix(typ, "_tool_result") {
				c.toolPost(ts, id, anyText(b["content"]), &event.Outcome{Status: statusOK})
			}
		}
	}
}

// claudeResult turns a tool_result block into tool.post.
func (c *lineCtx) claudeResult(rec claudeRecord, ts time.Time, b map[string]any) {
	text := anyText(b["content"])
	useID := anyString(b["tool_use_id"])
	var name string
	var mcp bool
	if pre := c.st.Pending[useID]; pre != nil && pre.Tool != nil {
		name, mcp = pre.Tool.Name, pre.Tool.Kind == event.ToolMCP
	}
	oc := claudeOutcome(rec.ToolDenialKind, anyBool(b["is_error"]), text, mcp)
	if oc.Status == statusError && !mcp && strings.EqualFold(name, "Bash") {
		if code, ok := exitCodeAfter(head(text, 256), false, "Exit code "); ok {
			oc.ExitCode = intPtr(code)
			oc.Error = "exit_code"
		}
	}
	if pd := rec.PermissionDecision; pd != nil {
		switch pd.Decision {
		case "accept":
			if oc.Decision == "" {
				oc.Decision = "allow"
			}
		case "reject":
			oc.Decision = "deny"
		}
		if oc.Decision != "" && oc.DecisionSource == "" {
			oc.DecisionSource = claudeDecisionSource(pd.Source, pd.ReasonType)
		}
	}
	e := c.toolPost(ts, useID, text, oc)
	if pd := rec.PermissionDecision; pd != nil {
		c.label(e, "permission_reason", safeToken(pd.ReasonType))
	}
}

// claudeDecisionSource maps permissionDecision to the event vocabulary
// (user | policy | hook). The capture only shows source "config" (rules,
// the auto-mode classifier, the mode itself, safety checks), which is
// policy. UNVERIFIED: the values written for an interactive approval and
// for a hook decision; they are recognized by name.
func claudeDecisionSource(source, reasonType string) string {
	s := strings.ToLower(head(source, 32) + " " + head(reasonType, 32))
	switch {
	case strings.Contains(s, "hook"):
		return "hook"
	case strings.Contains(s, "user") || strings.Contains(s, "interactive") || strings.Contains(s, "prompt"):
		return "user"
	}
	return "policy"
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
