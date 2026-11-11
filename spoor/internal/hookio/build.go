package hookio

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// newEvent starts an activity event from a hook invocation.
func newEvent(agentID, typ, hookName string, raw []byte) *event.Event {
	ev := event.New(event.KindActivity, typ, event.SourceHook)
	ev.Fidelity = event.FidelityObserved
	ev.Agent = &event.Agent{ID: agentID}
	ev.Session = &event.Session{}
	ev.Content = &event.Content{}
	if raw != nil {
		// Copy: the caller owns stdin and may reuse the buffer.
		ev.Content.Raw = append(json.RawMessage(nil), raw...)
	}
	label(ev, "hook_event", hookName)
	return ev
}

// sessionFields is the per-dialect extraction of session context, already
// resolved against the payload and the environment fallbacks.
type sessionFields struct {
	id, turnID, cwd, transcript, model string
	permissionMode                     string // agent vocabulary, mapped by permMode
	subagentID, subagentType, parentID string
	projectDir                         string // session start directory, when the agent exposes it
	agentVersion, agentSurface         string
	parentAgentID                      string
}

func applySession(ev *event.Event, s sessionFields) {
	se := ev.Session
	se.ID = field(ev, "session.id", s.id, maxID)
	se.ParentID = field(ev, "session.parent_id", s.parentID, maxID)
	se.TurnID = field(ev, "session.turn_id", s.turnID, maxID)
	se.CWD = pathField(ev, "session.cwd", s.cwd)
	se.Transcript = pathField(ev, "session.transcript", s.transcript)
	se.Model = field(ev, "session.model", s.model, maxName)
	se.PermissionMode = permMode(s.permissionMode)
	se.SubagentID = field(ev, "session.subagent_id", s.subagentID, maxID)
	se.SubagentType = field(ev, "session.subagent_type", s.subagentType, maxName)
	if se.CWD == "" && s.projectDir != "" {
		se.CWD = pathField(ev, "session.cwd", s.projectDir)
	} else if s.projectDir != "" && s.projectDir != s.cwd {
		// The agent may have changed directory since the session started;
		// the start directory is what repository attribution needs.
		labelPath(ev, "project_dir", s.projectDir)
	}
	ev.Agent.Version = field(ev, "agent.version", s.agentVersion, 64)
	ev.Agent.Surface = s.agentSurface
	if s.parentAgentID != "" {
		v, _ := cleanID(s.parentAgentID, maxLabel)
		label(ev, "parent_agent_id", v)
	}
}

// permMode maps an agent's permission mode to the event vocabulary:
// default | plan | accept_edits | auto | dont_ask | bypass. The input enum is
// Claude Code's, which Codex reuses (codex-rs/hooks/schema/generated). An
// unknown value is passed through as a snake_case token so a new mode shows
// up downstream instead of vanishing.
func permMode(s string) string {
	switch s {
	case "":
		return ""
	case "default", "manual":
		return "default"
	case "plan":
		return "plan"
	case "acceptEdits":
		return "accept_edits"
	case "auto":
		return "auto"
	case "dontAsk":
		return "dont_ask"
	case "bypassPermissions":
		return "bypass"
	}
	var sb strings.Builder
	for i, r := range s {
		if i >= 64 {
			break
		}
		switch {
		case r >= 'A' && r <= 'Z':
			if sb.Len() > 0 {
				sb.WriteByte('_')
			}
			sb.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

// toolArgs normalizes a tool-argument value to an object. Agents usually
// send an object, but Copilot and Cursor may send a JSON-encoded string and
// nothing stops a payload from sending a scalar; those are wrapped so the
// content still reaches detection.
func toolArgs(v any) map[string]any {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]any:
		return t
	case string:
		if m, ok := decodeEmbedded(t); ok {
			return m
		}
		if t == "" {
			return nil
		}
		return map[string]any{"_raw": t}
	default:
		return map[string]any{"_raw": t}
	}
}

// setTool fills Tool, Target and the tool part of Content.
func setTool(ev *event.Event, agentID, name string, args any, useID string) {
	in := toolArgs(args)
	t := &event.Tool{}
	t.Name = field(ev, "tool.name", name, maxName)
	t.UseID = field(ev, "tool.use_id", useID, maxID)
	if t.Name != "" {
		kind, server, tool := toolmap.Kind(agentID, t.Name)
		t.Kind = kind
		t.MCPServer, _ = cleanID(server, maxName)
		t.MCPTool, _ = cleanID(tool, maxName)
	}
	if in != nil {
		t.InputKeys = inputKeys(in)
		t.InputSHA256 = canonicalSHA256(in)
		ev.Content.ToolInput = in
	}
	ev.Tool = t
	setTarget(ev, in)
}

// forceKind overrides the classification when the hook itself says what the
// call is (Cursor's beforeShellExecution, Gemini's mcp_context), which is
// stronger evidence than a tool name.
func forceKind(ev *event.Event, kind event.ToolKind) {
	if ev.Tool == nil {
		ev.Tool = &event.Tool{}
	}
	if ev.Tool.Kind == kind {
		return
	}
	ev.Tool.Kind = kind
	ev.Target = nil
	setTarget(ev, ev.Content.ToolInput)
}

func inputKeys(in map[string]any) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	for i, k := range keys {
		keys[i], _ = cleanID(k, maxLabel)
	}
	return keys
}

// canonicalSHA256 hashes encoding/json's serialization of a decoded value.
// Map keys are emitted sorted, so the same arguments hash the same whatever
// order the agent wrote them in.
func canonicalSHA256(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// setOutput records tool output for local detection and its size and hash
// for emission. The text itself is never placed in a serialized field here.
func setOutput(ev *event.Event, v any) {
	text := outputText(v)
	if text == "" {
		return
	}
	ev.Content.ToolOutput = text
	if ev.Tool == nil {
		return
	}
	ev.Tool.OutputLen = len(text)
	ev.Tool.OutputSHA256 = sha256Hex(text)
}

// outputText flattens the many shapes a tool result takes into text:
// a plain string; Claude Code's {stdout,stderr}; Copilot's
// {textResultForLlm}; Gemini's {llmContent,returnDisplay,error}; MCP content
// blocks [{type:"text",text}]; anything else as compact JSON.
func outputText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		if s, ok := joinBlocks(t); ok {
			return s
		}
	case map[string]any:
		o := obj(t)
		var parts []string
		add := func(v any) {
			if s := leafText(v); s != "" {
				parts = append(parts, s)
			}
		}
		if o.has("stdout") || o.has("stderr") {
			add(o["stdout"])
			add(o["stderr"])
		} else {
			for _, k := range []string{"textResultForLlm", "text_result_for_llm", "llmContent", "output", "content", "result", "text", "returnDisplay"} {
				if o.has(k) {
					add(o[k])
					break
				}
			}
		}
		add(o["error"])
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// leafText renders one field of a tool result.
func leafText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		if s, ok := joinBlocks(t); ok {
			return s
		}
	case map[string]any:
		if s := obj(t).str("message", "text"); s != "" {
			return s
		}
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" || string(b) == "{}" || string(b) == "[]" {
		return ""
	}
	return string(b)
}

// joinBlocks concatenates content blocks ({type:"text",text:"..."}) or plain
// strings. It reports false when the array holds anything else.
func joinBlocks(a []any) (string, bool) {
	if len(a) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(a))
	for _, it := range a {
		switch b := it.(type) {
		case string:
			parts = append(parts, b)
		case map[string]any:
			s, ok := b["text"].(string)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		default:
			return "", false
		}
	}
	return strings.Join(parts, "\n"), true
}

// setPrompt records a submitted prompt: the text for local detection, the
// length for emission. The hash is left to the redaction stage because it
// must be keyed with the tenant key to resist guessing short prompts.
func setPrompt(ev *event.Event, text string) {
	ev.Content.PromptText = text
	ev.Prompt = &event.Prompt{Len: len(text)}
}

// durationMS reads a millisecond duration, rejecting negatives and values
// that do not fit.
func durationMS(o obj, keys ...string) int64 {
	f, ok := o.num(keys...)
	if !ok || f < 0 || f > math.MaxInt32*1000.0 {
		return 0
	}
	return int64(f)
}

// failure builds the Outcome for a failed tool call. errText is tool output
// under the model's influence and may quote file content or credentials, so
// it is kept only in Content.ToolOutput; the serialized Outcome.Error is a
// fixed-format summary. Claude Code documents "Exit code N" as the first
// line for shell failures (hooks reference, PostToolUseFailure input).
func failure(ev *event.Event, errText string, interrupted bool) *event.Outcome {
	out := &event.Outcome{Status: "error"}
	if interrupted {
		out.Status = "interrupted"
	}
	if errText == "" {
		return out
	}
	if ev.Content.ToolOutput == "" {
		ev.Content.ToolOutput = errText
		if ev.Tool != nil {
			ev.Tool.OutputLen = len(errText)
			ev.Tool.OutputSHA256 = sha256Hex(errText)
		}
	}
	if code, ok := exitCode(errText); ok {
		out.ExitCode = &code
		out.Error = "exit code " + strconv.Itoa(code)
		return out
	}
	out.Error = "tool error fp:" + sha256Hex(errText)[:8]
	return out
}

// exitCode parses a leading "Exit code N" line.
func exitCode(s string) (int, bool) {
	line := s
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	const prefix = "exit code "
	if len(line) <= len(prefix) || len(line) > len(prefix)+6 || !strings.EqualFold(line[:len(prefix)], prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(line[len(prefix):])
	if err != nil {
		return 0, false
	}
	return n, true
}

// token reduces a short machine code from the payload (an error class, a
// status) to a safe serialized value.
func token(s string) string {
	v := labelValue(s)
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// unknownEvent is the fallback for an event name the dialect has no mapping
// for: keep it as a notification and flag it, so new agent events surface as
// schema drift instead of being lost.
func unknownEvent(ev *event.Event) {
	ev.Type = event.TypeNotification
	label(ev, "hook_unmapped", "1")
}

// responseOutcome derives a tool.post outcome from the result value when it
// carries a recognizable status: an exit code (top level or under metadata,
// as in Codex function-call output), success:false, MCP's isError, or
// Claude Code's interrupted flag. def is the status when nothing says
// otherwise.
func responseOutcome(resp any, def string) *event.Outcome {
	out := &event.Outcome{Status: def}
	m, ok := resp.(map[string]any)
	if !ok {
		return out
	}
	o := obj(m)
	meta := o.sub("metadata")
	if f, ok := firstNum(o, meta, "exit_code", "exitCode"); ok && f == math.Trunc(f) && math.Abs(f) < 1<<31 {
		code := int(f)
		out.ExitCode = &code
		if code == 0 {
			out.Status = "ok"
		} else {
			out.Status = "error"
			out.Error = "exit code " + strconv.Itoa(code)
		}
	}
	if okFlag, present := o.boolean("success"); present && !okFlag {
		out.Status = "error"
	}
	if bad, _ := o.boolean("isError", "is_error"); bad {
		out.Status = "error"
	}
	if stopped, _ := o.boolean("interrupted"); stopped {
		out.Status = "interrupted"
	}
	if secs, ok := meta.num("duration_seconds"); ok && secs >= 0 && secs < math.MaxInt32 {
		out.DurationMS = int64(secs * 1000)
	}
	return out
}

func firstNum(a, b obj, keys ...string) (float64, bool) {
	if f, ok := a.num(keys...); ok {
		return f, true
	}
	return b.num(keys...)
}

// denialReason normalizes the reason Claude Code's auto mode gives for a
// denial. A classifier verdict names the matched rule in square brackets
// ("[Data Exfiltration]"); that label is kept. The documented fixed texts
// map to codes, and any other text is reduced to a fingerprint because it is
// free text that may describe the call.
func denialReason(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(s, "Auto mode could not evaluate"):
		return "no_verdict"
	case s == "Classifier unavailable":
		return "classifier_unavailable"
	}
	if s[0] == '[' {
		if end := strings.IndexByte(s, ']'); end > 1 && end <= 80 {
			name := s[1:end]
			clean := true
			for _, r := range name {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ' ' || r == '_' || r == '-' || r == '/' || r == '&') {
					clean = false
					break
				}
			}
			if clean {
				return name
			}
		}
	}
	return "denied fp:" + sha256Hex(s)[:8]
}
