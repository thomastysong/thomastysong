package transcript

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// geminiParser reads Gemini CLI chat recordings.
//
// Layout (google-gemini/gemini-cli main,
// packages/core/src/services/chatRecordingService.ts and
// chatRecordingTypes.ts): <home>/tmp/<project>/chats/session-<time>-<id8>.jsonl
// for the main agent and chats/<parent-session-id>/<session-id>.jsonl for
// subagents. The journal is append-only: a metadata record, then message
// records, {"$set":...} metadata updates, {"$rewindTo":id} and
// {"$patch":...}. The same message is appended again whenever it gains
// tool results or token counts, so calls are deduplicated by id. Versions up
// to 0.38 wrote one JSON document (session-*.json) instead; it is rewritten
// whole on every change and is read as a document.
type geminiParser struct{}

func (geminiParser) AgentID() string { return toolmap.AgentGemini }
func (geminiParser) Format() string  { return FormatGemini }

func (geminiParser) Match(path string) bool {
	p := slashPath(path)
	i := strings.LastIndex(p, "/chats/")
	if i < 0 {
		return false
	}
	rest := p[i+len("/chats/"):]
	switch strings.Count(rest, "/") {
	case 0: // chats/session-*.jsonl or legacy chats/session-*.json
		return strings.HasPrefix(rest, "session-") && (strings.HasSuffix(rest, ".jsonl") || strings.HasSuffix(rest, ".json"))
	case 1: // chats/<parent>/<id>.jsonl
		return strings.HasSuffix(rest, ".jsonl")
	}
	return false
}

func (geminiParser) mode(path string) fileMode {
	if strings.HasSuffix(path, ".json") {
		return modeDocument
	}
	return modeTail
}

func (p geminiParser) ParseLine(line []byte, st *FileState) ([]*event.Event, error) {
	return parseGuard(p.AgentID(), line, st, parseGemini)
}

// Records are decoded in one pass; args, content and results are left
// generic and navigated as decoded values.
type geminiToolCall struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DisplayName   string `json:"displayName"`
	Args          any    `json:"args"`
	Status        string `json:"status"`
	Timestamp     string `json:"timestamp"`
	AgentID       string `json:"agentId"`
	Result        any    `json:"result"`
	ResultDisplay any    `json:"resultDisplay"`
}

type geminiMessage struct {
	ID        string           `json:"id"`
	Timestamp string           `json:"timestamp"`
	Type      string           `json:"type"`
	Model     string           `json:"model"`
	Content   any              `json:"content"`
	ToolCalls []geminiToolCall `json:"toolCalls"`
}

type geminiMeta struct {
	SessionID string `json:"sessionId"`
	StartTime string `json:"startTime"`
	Kind      string `json:"kind"`
}

type geminiSet struct {
	geminiMeta
	Messages []geminiMessage `json:"messages"`
}

type geminiMsgPatch struct {
	ID        string `json:"id"`
	ToolCalls []struct {
		ID     string `json:"id"`
		Result any    `json:"result"`
	} `json:"toolCalls"`
}

type geminiPatch struct {
	geminiMsgPatch
	Updates []geminiMsgPatch `json:"updates"`
}

type geminiRecord struct {
	geminiMessage
	geminiMeta
	Messages []geminiMessage `json:"messages"` // legacy single-document sessions
	RewindTo *string         `json:"$rewindTo"`
	Set      *geminiSet      `json:"$set"`
	Patch    *geminiPatch    `json:"$patch"`
}

// maxGeminiMessages bounds how many messages one record (a legacy document
// or a $set checkpoint) may expand to.
const maxGeminiMessages = 100_000

func parseGemini(c *lineCtx) error {
	var rec geminiRecord
	if err := decode(c.line, &rec); err != nil {
		return err
	}
	st := c.st
	switch {
	case rec.RewindTo != nil:
		// The user rewound the conversation. The journal keeps what was
		// rewound, and its events were already emitted.
	case rec.Set != nil:
		c.geminiMetaRecord(rec.Set.geminiMeta)
		c.geminiMessages(rec.Set.Messages)
	case rec.Patch != nil:
		c.geminiPatch(rec.Patch)
	case rec.geminiMessage.ID != "" && rec.geminiMessage.Type != "":
		c.geminiMessage(&rec.geminiMessage)
	case rec.SessionID != "":
		c.geminiMetaRecord(rec.geminiMeta)
		c.geminiMessages(rec.Messages)
	default:
		st.Unknown++
	}
	return nil
}

func (c *lineCtx) geminiMessages(msgs []geminiMessage) {
	if len(msgs) > maxGeminiMessages {
		msgs = msgs[:maxGeminiMessages]
	}
	for i := range msgs {
		c.geminiMessage(&msgs[i])
	}
}

// geminiMetaRecord handles the session header and $set updates of it.
func (c *lineCtx) geminiMetaRecord(m geminiMeta) {
	st := c.st
	if m.SessionID != "" {
		st.SessionID = clip(m.SessionID, maxIDLen)
	}
	if m.Kind == "subagent" && st.extra("subagent_id") == "" && st.SessionID != "" {
		st.setExtra("subagent_id", st.SessionID)
		st.ParentSessionID = geminiParentFromPath(st.Path)
	}
	// The start is remembered in the id set, like messages and calls, so a
	// journal that Gemini CLI rewrites does not announce the session twice.
	if st.SessionID == "" || m.StartTime == "" || st.remember("start:"+st.SessionID) {
		return
	}
	typ := event.TypeSessionStart
	if st.extra("subagent_id") != "" {
		typ = event.TypeSubagentStart
	}
	c.newEvent(typ, parseTime(m.StartTime))
}

// geminiParentFromPath reads the parent session id from a subagent path:
// .../chats/<parent-session-id>/<session-id>.jsonl.
func geminiParentFromPath(path string) string {
	p := slashPath(path)
	i := strings.LastIndex(p, "/chats/")
	if i < 0 {
		return ""
	}
	rest := p[i+len("/chats/"):]
	if j := strings.IndexByte(rest, '/'); j > 0 {
		return clip(rest[:j], maxIDLen)
	}
	return ""
}

func (c *lineCtx) geminiMessage(m *geminiMessage) {
	st := c.st
	ts := parseTime(m.Timestamp)
	switch m.Type {
	case "user":
		// Since v0.44 tool results are also recorded as user messages; the
		// calls already carry them. A subagent's "user" is its parent.
		if st.extra("subagent_id") != "" || geminiHasFunctionResponse(m.Content) {
			return
		}
		if m.ID != "" && st.remember("m:"+clip(m.ID, maxIDLen)) {
			return
		}
		if text := anyText(m.Content); text != "" {
			c.prompt(ts, text)
		}
	case "gemini":
		if m.Model != "" {
			st.Model = clip(m.Model, maxModelLen)
		}
		for i := range m.ToolCalls {
			c.geminiToolCall(m, &m.ToolCalls[i], i, ts)
		}
	case "info", "error", "warning":
		// The CLI's own notices.
	default:
		st.Unknown++
	}
}

func (c *lineCtx) geminiToolCall(m *geminiMessage, tc *geminiToolCall, idx int, ts time.Time) {
	st := c.st
	id := clip(tc.ID, maxIDLen)
	if id == "" {
		// No call id: fall back to the position in the message so a
		// re-appended message still does not repeat its calls.
		id = clip(m.ID, maxIDLen) + "#" + strconv.Itoa(idx)
	}
	if t := parseTime(tc.Timestamp); !t.IsZero() {
		ts = t
	}
	if !st.remember("t:" + id) {
		input := anyObject(tc.Args)
		var e *event.Event
		if server, tool, ok := geminiMCP(tc.DisplayName); ok {
			e = c.toolPre(ts, tc.Name, id, event.ToolMCP, server, tool, input)
		} else {
			kind, server, tool := toolmap.KindWithInput(c.agent, tc.Name, input)
			e = c.toolPre(ts, tc.Name, id, kind, server, tool, input)
		}
		if tc.AgentID != "" && e.Session.SubagentID == "" {
			e.Session.SubagentID = clip(tc.AgentID, maxIDLen)
		}
	}
	switch tc.Status {
	case "success", "error", "cancelled":
		if st.remember("r:" + id) {
			return
		}
		text := geminiResult(tc.Result, tc.ResultDisplay)
		e := c.toolPost(ts, id, text, geminiOutcome(tc, text))
		if tc.AgentID != "" && e.Session.SubagentID == "" {
			e.Session.SubagentID = clip(tc.AgentID, maxIDLen)
		}
	}
}

// geminiPatch handles {"$patch":...}: late tool results attached to calls
// that were first recorded without one.
func (c *lineCtx) geminiPatch(p *geminiPatch) {
	all := append([]geminiMsgPatch{p.geminiMsgPatch}, p.Updates...)
	if len(all) > maxGeminiMessages {
		all = all[:maxGeminiMessages]
	}
	for _, u := range all {
		for _, tp := range u.ToolCalls {
			id := clip(tp.ID, maxIDLen)
			if id == "" || tp.Result == nil {
				continue
			}
			// Only complete a call this file opened and has not closed.
			if !c.st.wasSeen("t:"+id) || c.st.remember("r:"+id) {
				continue
			}
			text := geminiResult(tp.Result, nil)
			oc := &event.Outcome{Status: statusOK}
			if geminiResponseHasError(tp.Result) {
				oc.Status, oc.Error = statusError, "tool_error"
			}
			c.toolPost(time.Time{}, id, text, oc)
		}
	}
}

func geminiHasFunctionResponse(content any) bool {
	for _, p := range geminiParts(content) {
		if anyObject(p["functionResponse"]) != nil {
			return true
		}
	}
	return false
}

// geminiMCP reads an MCP call's server and tool from its display name
// ("<tool> (<server> MCP Server)"), the one place every version records them
// unambiguously: the qualified name mcp_<server>_<tool> cannot be split when
// the server name itself contains an underscore. (Fleet ai_agent_sessions.)
func geminiMCP(displayName string) (server, tool string, ok bool) {
	const suffix = " MCP Server)"
	if len(displayName) > 2*maxNameLen || !strings.HasSuffix(displayName, suffix) {
		return "", "", false
	}
	body := strings.TrimSuffix(displayName, suffix)
	i := strings.LastIndex(body, " (")
	if i <= 0 || i+2 >= len(body) {
		return "", "", false
	}
	return body[i+2:], body[:i], true
}

// geminiParts views a PartListUnion (a part, or a list of parts and
// strings) as a list of part objects.
func geminiParts(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		parts := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m := anyObject(e); m != nil {
				parts = append(parts, m)
			}
		}
		return parts
	}
	return nil
}

func geminiResponse(part map[string]any) map[string]any {
	return anyObject(anyObject(part["functionResponse"])["response"])
}

// geminiResult is a tool call's output: the function responses sent back to
// the model, else what the CLI displayed.
func geminiResult(result, display any) string {
	var out []string
	for _, p := range geminiParts(result) {
		if t := anyString(p["text"]); t != "" {
			out = append(out, t)
		}
		resp := geminiResponse(p)
		for _, k := range []string{"output", "error"} {
			switch v := resp[k].(type) {
			case nil:
			case string:
				out = append(out, v)
			default:
				if b, err := json.Marshal(v); err == nil {
					out = append(out, string(b))
				}
			}
		}
	}
	if len(out) > 0 {
		return strings.Join(out, "\n")
	}
	if s := anyString(result); s != "" {
		return s
	}
	return anyString(display)
}

func geminiResponseHasError(result any) bool {
	for _, p := range geminiParts(result) {
		if geminiResponse(p)["error"] != nil {
			return true
		}
	}
	return false
}

const geminiShellTool = "run_shell_command"

// geminiOutcome maps a tool call's final status to an outcome. Failed shell
// commands are recorded as successful; only the output says, and the shell
// tool ends its output with the exit code. A command can print the same
// words earlier, so the last occurrence counts, and for any other tool the
// line means nothing. (Fleet ai_agent_sessions geminiDecision.)
func geminiOutcome(tc *geminiToolCall, output string) *event.Outcome {
	switch tc.Status {
	case "cancelled":
		for _, t := range []string{output, anyString(tc.ResultDisplay)} {
			if strings.HasPrefix(strings.TrimSpace(head(t, 256)), "User denied execution.") {
				return &event.Outcome{Status: statusDenied, Decision: "deny", DecisionSource: "user", Error: "user_rejected"}
			}
		}
		return &event.Outcome{Status: statusInterrupted, Error: "cancelled"}
	case "error":
		return &event.Outcome{Status: statusError, Error: "tool_error"}
	}
	if tc.Name == geminiShellTool {
		if code, ok := exitCodeAfter(output, true, "Exit Code: "); ok {
			if code != 0 {
				return &event.Outcome{Status: statusError, Error: "exit_code", ExitCode: intPtr(code)}
			}
			return &event.Outcome{Status: statusOK, ExitCode: intPtr(code)}
		}
	}
	return &event.Outcome{Status: statusOK}
}
