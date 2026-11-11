package transcript

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// codexParser reads Codex CLI rollouts.
//
// Layout (openai/codex main, codex-rs/rollout): one file per thread at
// $CODEX_HOME/sessions/YYYY/MM/DD/rollout-<time>-<thread-uuid>.jsonl, moved
// to archived_sessions/ and zstd-compressed to .jsonl.zst after a week.
// Each line is {"timestamp","type","payload"} (recorder.rs RolloutLineRef);
// the item shapes are codex-rs/protocol/src/{protocol,models}.rs. The oldest
// rollouts wrote response items at the top level without the envelope.
type codexParser struct{}

func (codexParser) AgentID() string { return toolmap.AgentCodex }
func (codexParser) Format() string  { return FormatCodex }

func (codexParser) Match(path string) bool {
	b := baseName(path)
	return strings.HasPrefix(b, "rollout-") && (strings.HasSuffix(b, ".jsonl") || strings.HasSuffix(b, ".jsonl.zst"))
}

func (codexParser) mode(path string) fileMode {
	if strings.HasSuffix(path, ".zst") {
		return modeZstd
	}
	return modeTail
}

func (p codexParser) ParseLine(line []byte, st *FileState) ([]*event.Event, error) {
	return parseGuard(p.AgentID(), line, st, parseCodex)
}

type codexLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

type codexMeta struct {
	ID             string          `json:"id"`
	SessionID      string          `json:"session_id"`
	ParentThreadID string          `json:"parent_thread_id"`
	ForkedFromID   string          `json:"forked_from_id"`
	Timestamp      string          `json:"timestamp"`
	CWD            string          `json:"cwd"`
	CLIVersion     string          `json:"cli_version"`
	Source         json.RawMessage `json:"source"`
	ThreadSource   string          `json:"thread_source"`
	AgentRole      string          `json:"agent_role"`
	AgentType      string          `json:"agent_type"` // serde alias of agent_role
}

type codexItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	CallID    string          `json:"call_id"`
	Status    string          `json:"status"`
	Content   json.RawMessage `json:"content"`
	Arguments json.RawMessage `json:"arguments"`
	Input     json.RawMessage `json:"input"`
	Output    json.RawMessage `json:"output"`
	Action    json.RawMessage `json:"action"`
}

// Top-level rollout item types that carry nothing this parser emits.
// UNVERIFIED: the exact tags of the newer variants; they are the snake_case
// of the RolloutItem variants named in codex-rs/rollout/src/policy.rs.
var codexTopKnown = map[string]bool{
	"token_usage_record": true, "world_state": true, "retained_context": true,
	"security_risk_score": true, "dynamic_tools_updated": true, "realtime_item": true,
	"inter_agent_communication": true, "inter_agent_communication_metadata": true,
}

// Response item types (models.rs ResponseItem) that are not tool activity.
var codexItemKnown = map[string]bool{
	"message": true, "agent_message": true, "reasoning": true, "tool_search_call": true,
	"tool_search_output": true, "image_generation_call": true, "additional_tools": true,
	"configuration_update": true, "compaction": true, "compaction_summary": true,
	"compaction_trigger": true, "context_compaction": true, "other": true,
}

// codexEventKnown is every EventMsg tag in protocol.rs (generated from the
// enum, including the task_/turn_ renames). Tags outside it count as
// unknown records.
var codexEventKnown = toSet(`error warning auth_recovery_started auth_recovery_completed guardian_warning
realtime_conversation_started realtime_conversation_realtime realtime_conversation_closed realtime_conversation_sdp
model_reroute model_verification turn_moderation_metadata safety_buffering context_compacted thread_rolled_back
task_started turn_started thread_settings_applied task_complete turn_complete token_count agent_message user_message
agent_reasoning agent_reasoning_raw_content agent_reasoning_section_break session_configured environment_connected
environment_disconnected thread_goal_updated thread_queue_changed mcp_startup_update mcp_startup_complete
mcp_tool_call_begin mcp_tool_call_end web_search_begin web_search_end image_generation_begin image_generation_end
exec_command_begin exec_command_output_delta terminal_interaction exec_command_end view_image_tool_call
exec_approval_request network_approval_resolved request_permissions request_user_input dynamic_tool_call_request
dynamic_tool_call_response elicitation_request elicitation_abandoned apply_patch_approval_request guardian_assessment
deprecation_notice stream_error patch_apply_begin patch_apply_updated patch_apply_end turn_diff
realtime_conversation_list_voices_response plan_update turn_aborted shutdown_complete entered_review_mode
exited_review_mode raw_response_item raw_response_completed private_session_event item_started item_completed
hook_started hook_completed agent_message_content_delta plan_delta reasoning_content_delta
reasoning_raw_content_delta collab_agent_spawn_begin collab_agent_spawn_end collab_agent_interaction_begin
collab_agent_interaction_end collab_waiting_begin collab_waiting_end collab_close_begin collab_close_end
collab_resume_begin collab_resume_end sub_agent_activity`)

func toSet(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

func parseCodex(c *lineCtx) error {
	var rec codexLine
	if err := decode(c.line, &rec); err != nil {
		return err
	}
	st := c.st
	ts := parseTime(rec.Timestamp)

	// A fork's rollout opens with a copy of its parent's history, carrying
	// the original timestamps. Those records are the parent's activity and
	// were (or will be) read from the parent's own rollout.
	if fs := st.extra("fork_start"); fs != "" && rec.Type != "session_meta" {
		if start := parseTime(fs); !ts.IsZero() && ts.Before(start) {
			return nil
		}
	}

	switch rec.Type {
	case "session_meta":
		c.codexMeta(rec, ts)
	case "turn_context":
		c.codexTurnContext(rec, ts)
	case "response_item":
		var it codexItem
		if decode(rec.Payload, &it) != nil {
			st.Unknown++
			return nil
		}
		c.codexItem(&it, ts, false)
	case "event_msg":
		c.codexEvent(rec.Payload, ts)
	case "compacted":
		c.newEvent(event.TypeCompact, ts)
	case "turn_aborted":
		c.codexTurnEnd(rec.Payload, ts, true)
	default:
		if codexTopKnown[rec.Type] {
			return nil
		}
		// The oldest rollouts have no envelope: the line is the item, or
		// a bare session header {"id","timestamp",...}.
		if rawKind(rec.Payload) == 0 {
			var it codexItem
			_ = decode(c.line, &it)
			switch {
			case codexIsItem(it.Type):
				c.codexItem(&it, ts, true)
				return nil
			case rec.Type == "" && it.ID != "" && st.SessionID == "":
				st.SessionID = clip(it.ID, maxIDLen)
				return nil
			}
		}
		st.Unknown++
	}
	return nil
}

func codexIsItem(t string) bool {
	switch t {
	case "function_call", "custom_tool_call", "local_shell_call", "web_search_call",
		"function_call_output", "custom_tool_call_output":
		return true
	}
	return codexItemKnown[t]
}

func (c *lineCtx) codexMeta(rec codexLine, ts time.Time) {
	var m codexMeta
	if decode(rec.Payload, &m) != nil || m.ID == "" {
		c.st.Unknown++
		return
	}
	st := c.st
	id := clip(m.ID, maxIDLen)
	again := st.SessionID == id && st.extra("meta") == "1"
	st.SessionID = id
	st.setExtra("meta", "1")
	if m.CWD != "" {
		st.CWD = clip(m.CWD, maxCWDLen)
	}
	if m.CLIVersion != "" {
		st.Version = clip(m.CLIVersion, maxVersionLen)
	}
	source := codexSource(m.Source)
	role := m.AgentRole
	if role == "" {
		role = m.AgentType
	}
	sub := m.ParentThreadID != "" || source == "subagent" || m.ThreadSource == "subagent"
	if sub {
		parent := m.ParentThreadID
		if parent == "" && m.SessionID != m.ID {
			parent = m.SessionID // session_id is the root thread's id
		}
		st.ParentSessionID = clip(parent, maxIDLen)
		st.setExtra("subagent_id", id)
		st.setExtra("subagent_type", clip(role, maxNameLen))
	}
	if m.ForkedFromID != "" {
		if start := parseTime(m.Timestamp); !start.IsZero() {
			st.setExtra("fork_start", m.Timestamp)
		} else if !ts.IsZero() {
			st.setExtra("fork_start", rec.Timestamp)
		}
	}
	if again {
		return // a resumed thread rewrites its header; one start is enough
	}
	typ := event.TypeSessionStart
	if sub {
		typ = event.TypeSubagentStart
	}
	e := c.newEvent(typ, ts)
	switch source {
	case "cli", "exec":
		e.Agent.Surface = "cli"
	case "vscode":
		e.Agent.Surface = "ide"
	case "mcp":
		e.Agent.Surface = "sdk"
	}
	c.label(e, "codex_source", source)
	if m.ForkedFromID != "" {
		c.label(e, "forked_from", clip(m.ForkedFromID, maxIDLen))
	}
}

// codexSource reduces SessionSource to a closed vocabulary. Unit variants
// serialize as a string; SubAgent and Custom as single-key objects.
func codexSource(raw json.RawMessage) string {
	s := strings.ToLower(rawString(raw))
	switch s {
	case "cli", "vscode", "exec", "mcp", "unknown":
		return s
	case "":
		if rawKind(raw) == '{' && bytes.Contains(bytes.ToLower(head2(raw, 256)), []byte("subagent")) {
			return "subagent"
		}
		if rawKind(raw) == '{' {
			return "custom"
		}
		return ""
	}
	return "other"
}

func head2(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func (c *lineCtx) codexTurnContext(rec codexLine, ts time.Time) {
	var tc struct {
		TurnID            string          `json:"turn_id"`
		CWD               string          `json:"cwd"`
		Model             string          `json:"model"`
		ApprovalPolicy    json.RawMessage `json:"approval_policy"`
		SandboxPolicy     json.RawMessage `json:"sandbox_policy"`
		PermissionProfile json.RawMessage `json:"permission_profile"`
	}
	if decode(rec.Payload, &tc) != nil {
		c.st.Unknown++
		return
	}
	st := c.st
	if tc.TurnID != "" {
		st.setExtra("turn_id", clip(tc.TurnID, maxIDLen))
	}
	if tc.CWD != "" {
		st.CWD = clip(tc.CWD, maxCWDLen)
	}
	if tc.Model != "" {
		st.Model = clip(tc.Model, maxModelLen)
	}
	approval := codexApproval(tc.ApprovalPolicy)
	sandbox := codexSandbox(tc.SandboxPolicy, tc.PermissionProfile)
	if approval == "" && sandbox == "" {
		return
	}
	prevA, prevS := st.extra("approval_policy"), st.extra("sandbox")
	if approval != "" {
		st.setExtra("approval_policy", approval)
	}
	if sandbox != "" {
		st.setExtra("sandbox", sandbox)
	}
	prevMode := st.PermissionMode
	st.PermissionMode = codexMode(st.extra("approval_policy"), st.extra("sandbox"))
	changed := (prevA != "" && approval != "" && prevA != approval) || (prevS != "" && sandbox != "" && prevS != sandbox)
	if changed {
		e := c.newEvent(event.TypeConfigChange, ts)
		c.label(e, "change", "permission_mode")
		c.label(e, "from", prevMode)
		c.label(e, "to", st.PermissionMode)
		c.codexPosture(e)
	}
}

// codexApproval reduces AskForApproval to its tag: untrusted | on-request |
// on-failure | never | granular.
func codexApproval(raw json.RawMessage) string {
	s := rawString(raw)
	if s == "" && rawKind(raw) == '{' {
		for k := range rawObject(raw) {
			s = k
			break
		}
	}
	switch s {
	case "untrusted", "on-request", "on-failure", "never", "granular":
		return s
	case "":
		return ""
	}
	return "other"
}

// codexSandbox reduces the sandbox setting to read-only | workspace-write |
// danger-full-access | external-sandbox | other. Older rollouts carry
// sandbox_policy {"type"|"mode": ...}.
// UNVERIFIED: the shape of the newer permission_profile object; a named
// preset is looked for under the usual keys, and as a last resort the
// "danger-full-access" literal anywhere in its first 4 KiB.
func codexSandbox(policy, profile json.RawMessage) string {
	known := func(s string) string {
		switch strings.ReplaceAll(strings.TrimPrefix(s, ":"), "_", "-") {
		case "read-only":
			return "read-only"
		case "workspace-write", "workspace":
			return "workspace-write"
		case "danger-full-access", "danger-no-sandbox", "full-access":
			return "danger-full-access"
		case "external-sandbox":
			return "external-sandbox"
		}
		return ""
	}
	for _, raw := range []json.RawMessage{policy, profile} {
		if s := rawString(raw); s != "" {
			if k := known(s); k != "" {
				return k
			}
			return "other"
		}
		if m := rawObject(raw); m != nil {
			for _, key := range []string{"type", "mode", "name", "id", "preset", "kind"} {
				if s, _ := m[key].(string); s != "" {
					if k := known(s); k != "" {
						return k
					}
				}
			}
			if bytes.Contains(head2(raw, 4096), []byte("danger-full-access")) {
				return "danger-full-access"
			}
			return "other"
		}
	}
	return ""
}

// codexMode maps Codex's two knobs onto the event permission vocabulary:
// never ask plus no sandbox is the documented bypass
// (--dangerously-bypass-approvals-and-sandbox); never ask alone is dont_ask.
func codexMode(approval, sandbox string) string {
	switch {
	case approval == "never" && sandbox == "danger-full-access":
		return "bypass"
	case approval == "never":
		return "dont_ask"
	case approval == "" && sandbox == "":
		return ""
	}
	return "default"
}

// codexPosture labels an event with the raw (closed-vocabulary) knobs, so a
// rule can tell "no sandbox" from "never ask".
func (c *lineCtx) codexPosture(e *event.Event) {
	c.label(e, "approval_policy", c.st.extra("approval_policy"))
	c.label(e, "sandbox", c.st.extra("sandbox"))
}

func (c *lineCtx) codexItem(it *codexItem, ts time.Time, flat bool) {
	switch it.Type {
	case "function_call", "custom_tool_call":
		var input map[string]any
		text := rawString(it.Arguments)
		if it.Type == "custom_tool_call" {
			text = rawString(it.Input)
		}
		if text == "" && rawKind(it.Arguments) == '{' {
			input = rawObject(it.Arguments) // already an object in some captures
		} else if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{") {
			input = rawObject(json.RawMessage(text))
		}
		if input == nil && text != "" {
			// Freeform tools (apply_patch) take plain text.
			input = map[string]any{"input": text}
		}
		name := it.Name
		var e *event.Event
		if server, tool, ok := toolmap.SplitMCPNamespace(it.Namespace, it.Name); ok {
			e = c.toolPre(ts, it.Namespace+it.Name, it.CallID, event.ToolMCP, server, tool, input)
		} else {
			if it.Namespace != "" && it.Namespace != "functions" {
				name = it.Namespace + it.Name // ToolName's Display form
			}
			kind, server, tool := toolmap.KindWithInput(c.agent, name, input)
			e = c.toolPre(ts, name, it.CallID, kind, server, tool, input)
		}
		c.codexPosture(e)
	case "local_shell_call":
		id := it.CallID
		if id == "" {
			id = it.ID
		}
		e := c.toolPre(ts, "local_shell", id, event.ToolShell, "", "", rawObject(it.Action))
		c.codexPosture(e)
	case "web_search_call":
		// Runs on the provider side and is recorded once, complete.
		input := rawObject(it.Action)
		kind := event.ToolWebSearch
		if t, _ := input["type"].(string); t == "open_page" || t == "find_in_page" {
			kind = event.ToolWebFetch
		}
		id := it.CallID
		if id == "" {
			id = it.ID
		}
		e := c.newEvent(event.TypeToolPost, ts)
		e.Tool = &event.Tool{Name: "web_search", Kind: kind, UseID: clip(id, maxIDLen),
			InputSHA256: toolmap.InputHash(input), InputKeys: toolmap.InputKeys(input)}
		e.Content = &event.Content{ToolInput: input}
		e.Target = toolmap.Target(c.agent, "web_search", kind, input)
		status := statusUnknown
		switch it.Status {
		case "completed":
			status = statusOK
		case "failed":
			status = statusError
		}
		e.Outcome = &event.Outcome{Status: status}
	case "function_call_output", "custom_tool_call_output":
		text := codexOutputText(it.Output)
		mcp := false
		if pre := c.st.Pending[it.CallID]; pre != nil && pre.Tool != nil {
			mcp = pre.Tool.Kind == event.ToolMCP
		}
		oc := codexOutcome(it.Output, text, mcp)
		if h := c.st.takeHint(it.CallID); h != nil {
			if h.exit != nil {
				oc.ExitCode = h.exit
				if *h.exit != 0 && oc.Status == statusOK {
					oc.Status, oc.Error = statusError, "exit_code"
				}
			}
			if h.durMS > 0 {
				oc.DurationMS = h.durMS
			}
			if h.failed != nil && *h.failed && oc.Status == statusOK {
				oc.Status, oc.Error = statusError, "tool_error"
			}
		}
		c.toolPost(ts, it.CallID, text, oc)
	case "message":
		// In enveloped rollouts user-role messages are mostly context the
		// CLI injects (AGENTS.md, environment); the typed prompt arrives as
		// an event_msg. The flat format has only this record.
		if flat && it.Role == "user" {
			if text := textOf(it.Content); text != "" && !codexInjected(text) {
				c.codexPrompt(ts, text)
			}
		}
	default:
		if !codexItemKnown[it.Type] {
			c.st.Unknown++
		}
	}
}

func codexInjected(text string) bool {
	t := strings.TrimLeft(head(text, 128), " \t\r\n")
	return strings.HasPrefix(t, "<environment_context>") || strings.HasPrefix(t, "<user_instructions>") ||
		strings.HasPrefix(t, "<turn_aborted>") || strings.HasPrefix(t, "<permissions")
}

func (c *lineCtx) codexPrompt(ts time.Time, text string) {
	if text == "" {
		return
	}
	if c.st.extra("subagent_id") != "" {
		// A subagent thread's "user" is its parent agent.
		return
	}
	c.prompt(ts, text)
}

// codexOutputText flattens a tool output: a string, content items, or an
// object carrying them.
func codexOutputText(raw json.RawMessage) string {
	if t := textOf(raw); t != "" {
		return t
	}
	var o struct {
		Content json.RawMessage `json:"content"`
		Output  json.RawMessage `json:"output"`
	}
	if rawKind(raw) == '{' && json.Unmarshal(raw, &o) == nil {
		if t := textOf(o.Content); t != "" {
			return t
		}
		if t := textOf(o.Output); t != "" {
			return t
		}
	}
	return ""
}

// codexOutcome maps a tool output to an outcome from the fixed messages
// Codex writes for refusals and failures (table from Fleet's
// ai_agent_sessions codexDecision). An MCP server's output is its own text,
// so only its structured flags count.
func codexOutcome(raw json.RawMessage, text string, mcp bool) *event.Outcome {
	t := strings.TrimSpace(head(text, 4096))
	if !mcp {
		switch {
		case t == "exec command rejected by user", t == "patch rejected by user", t == "user rejected MCP tool call":
			return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "user", Error: "user_rejected"}
		case strings.HasPrefix(t, "rejected by configuration"):
			return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "policy", Error: "permission_rule"}
		case strings.HasPrefix(t, "automatic approval review denied the action"):
			return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "policy", Error: "auto_review"}
		case strings.HasPrefix(t, "aborted by user"):
			return &event.Outcome{Status: statusInterrupted, Error: "interrupted"}
		}
		if code, ok := exitCodeAfter(t, false, "Process exited with code ", "Exit code: "); ok {
			if code != 0 {
				return &event.Outcome{Status: statusError, Error: "exit_code", ExitCode: intPtr(code)}
			}
			return &event.Outcome{Status: statusOK, ExitCode: intPtr(code)}
		}
	}
	// Structured flags: the oldest rollouts wrote {"output","metadata":
	// {"exit_code"}} as a JSON string, MCP results carry isError, and
	// structured outputs a success flag.
	for _, doc := range []string{t, string(head2(bytes.TrimSpace(raw), 4096))} {
		if !strings.HasPrefix(doc, "{") {
			continue
		}
		var o struct {
			Metadata *struct {
				ExitCode        *int    `json:"exit_code"`
				DurationSeconds float64 `json:"duration_seconds"`
			} `json:"metadata"`
			IsError bool  `json:"isError"`
			Success *bool `json:"success"`
		}
		if decode([]byte(doc), &o) != nil {
			continue
		}
		oc := &event.Outcome{Status: statusOK}
		if o.Metadata != nil {
			if o.Metadata.ExitCode != nil {
				oc.ExitCode = o.Metadata.ExitCode
				if *o.Metadata.ExitCode != 0 {
					oc.Status, oc.Error = statusError, "exit_code"
				}
			}
			if d := o.Metadata.DurationSeconds; d > 0 && d < 1e9 {
				oc.DurationMS = int64(d * 1000)
			}
		}
		if o.IsError || (o.Success != nil && !*o.Success) {
			oc.Status, oc.Error = statusError, "tool_error"
		}
		if oc.Status != statusOK || oc.ExitCode != nil {
			return oc
		}
	}
	return &event.Outcome{Status: statusOK}
}

func (c *lineCtx) codexEvent(raw json.RawMessage, ts time.Time) {
	var ev struct {
		Type    string          `json:"type"`
		Message json.RawMessage `json:"message"`
		Kind    string          `json:"kind"`
		TurnID  string          `json:"turn_id"`
		CallID  string          `json:"call_id"`
		Item    *struct {
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		} `json:"item"`
		ExitCode   *int            `json:"exit_code"`
		Duration   json.RawMessage `json:"duration"`
		Success    *bool           `json:"success"`
		Invocation *struct {
			Server string `json:"server"`
			Tool   string `json:"tool"`
		} `json:"invocation"`
		Result json.RawMessage `json:"result"`
	}
	if decode(raw, &ev) != nil {
		c.st.Unknown++
		return
	}
	st := c.st
	switch ev.Type {
	case "user_message":
		// Legacy history mode. Older builds tagged injected context with
		// a kind other than "plain".
		if ev.Kind == "" || ev.Kind == "plain" {
			c.codexPrompt(ts, rawString(ev.Message))
		}
	case "item_completed":
		// Paginated history mode records the typed prompt as a turn item.
		if ev.Item != nil && ev.Item.Type == "UserMessage" {
			c.codexPrompt(ts, textOf(ev.Item.Content))
		}
	case "task_started", "turn_started":
		if ev.TurnID != "" {
			st.setExtra("turn_id", clip(ev.TurnID, maxIDLen))
		}
	case "task_complete", "turn_complete":
		c.codexTurnEnd(raw, ts, false)
	case "turn_aborted":
		c.codexTurnEnd(raw, ts, true)
	case "context_compacted":
		// The top-level "compacted" item already reports the compaction.
	case "exec_command_end":
		if ev.CallID != "" {
			h := st.hint(ev.CallID)
			h.exit = ev.ExitCode
			h.durMS = rustDuration(ev.Duration)
		}
	case "patch_apply_end":
		if ev.CallID != "" && ev.Success != nil {
			failed := !*ev.Success
			st.hint(ev.CallID).failed = &failed
		}
	case "mcp_tool_call_end":
		if ev.CallID != "" {
			h := st.hint(ev.CallID)
			h.durMS = rustDuration(ev.Duration)
			// result is Result<CallToolResult, String>: {"Ok":{...,
			// "isError":bool}} or {"Err":"..."}.
			var res struct {
				Ok *struct {
					IsError bool `json:"isError"`
				} `json:"Ok"`
				Err json.RawMessage `json:"Err"`
			}
			if decode(ev.Result, &res) == nil {
				failed := rawKind(res.Err) != 0 || (res.Ok != nil && res.Ok.IsError)
				h.failed = &failed
			}
		}
	default:
		if !codexEventKnown[ev.Type] {
			st.Unknown++
		}
	}
}

func (c *lineCtx) codexTurnEnd(raw json.RawMessage, ts time.Time, aborted bool) {
	var p struct {
		TurnID string `json:"turn_id"`
		Reason string `json:"reason"`
	}
	_ = decode(raw, &p)
	e := c.newEvent(event.TypeTurnEnd, ts)
	if p.TurnID != "" {
		e.Session.TurnID = clip(p.TurnID, maxIDLen)
	}
	if !aborted {
		e.Outcome = &event.Outcome{Status: statusOK}
		return
	}
	e.Outcome = &event.Outcome{Status: statusInterrupted}
	switch p.Reason {
	case "interrupted", "replaced", "review_ended", "budget_limited":
		e.Outcome.Error = p.Reason
	}
}
