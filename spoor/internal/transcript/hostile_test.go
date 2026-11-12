package transcript

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// hostileLines are inputs an attacker who controls agent output can put in
// a session log. No parser may panic, hang or emit an unbounded field.
func hostileLines() map[string]string {
	deep := strings.Repeat("[", 20_000) + strings.Repeat("]", 20_000)
	deepObj := strings.Repeat(`{"a":`, 12_000) + "1" + strings.Repeat("}", 12_000)
	long := strings.Repeat("x", 300_000)
	return map[string]string{
		"empty":             "",
		"spaces":            "   \t  ",
		"nul padding":       "\x00\x00\x00\x00",
		"not json":          "hello world",
		"array":             `[1,2,3]`,
		"number":            `42`,
		"string":            `"type"`,
		"null":              `null`,
		"truncated":         `{"type":"user","message":{"content":"abc`,
		"trailing garbage":  `{"type":"user"} trailing`,
		"two objects":       `{"type":"user"}{"type":"assistant"}`,
		"invalid utf8":      "{\"type\":\"user\",\"sessionId\":\"\xff\xfe\",\"message\":{\"content\":\"\xc3\x28 \xf0\x28\x8c\xbc\"}}",
		"bom":               "\xef\xbb\xbf" + `{"type":"user","sessionId":"s","message":{"content":"with bom"}}`,
		"crlf":              `{"type":"user","sessionId":"s","message":{"content":"crlf"}}` + "\r",
		"deep array":        `{"type":"user","message":{"content":` + deep + `}}`,
		"deep object":       `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t","name":"Bash","input":` + deepObj + `}]}}`,
		"wrong types":       `{"type":7,"timestamp":{"a":1},"sessionId":[1],"cwd":false,"message":"str","isSidechain":"yes","payload":"p","data":3}`,
		"wrong types 2":     `{"type":"assistant","message":{"model":5,"content":[{"type":"tool_use","id":9,"name":["x"],"input":"notobj"},7,"s",null]}}`,
		"wrong types 3":     `{"type":"response_item","timestamp":5,"payload":{"type":"function_call","name":{"a":1},"arguments":{"cmd":"ls"},"call_id":7}}`,
		"wrong types 4":     `{"type":"tool.execution_start","data":{"toolCallId":{},"toolName":3,"arguments":[1,2]}}`,
		"wrong types 5":     `{"id":"g","type":"gemini","toolCalls":[{"id":3,"name":4,"args":"x","status":5,"result":7},"s",null]}`,
		"payload array":     `{"type":"response_item","payload":[1,2]}`,
		"payload null":      `{"type":"event_msg","payload":null}`,
		"data null":         `{"type":"tool.execution_complete","data":null}`,
		"huge ids":          `{"type":"assistant","sessionId":"` + long + `","cwd":"` + long + `","version":"` + long + `","message":{"model":"` + long + `","content":[{"type":"tool_use","id":"` + long + `","name":"` + long + `","input":{"file_path":"` + long + `"}}]}}`,
		"huge codex":        `{"type":"session_meta","payload":{"id":"` + long + `","cwd":"` + long + `","cli_version":"` + long + `","agent_role":"` + long + `","parent_thread_id":"` + long + `"}}`,
		"huge copilot":      `{"type":"tool.execution_start","agentId":"` + long + `","data":{"toolCallId":"` + long + `","toolName":"` + long + `","mcpServerName":"` + long + `","mcpToolName":"` + long + `","turnId":"` + long + `","model":"` + long + `"}}`,
		"huge gemini":       `{"id":"` + long + `","type":"gemini","model":"` + long + `","toolCalls":[{"id":"` + long + `","name":"` + long + `","displayName":"` + long + ` (` + long + ` MCP Server)","agentId":"` + long + `","status":"success"}]}`,
		"huge number":       `{"type":"event_msg","payload":{"type":"exec_command_end","call_id":"c","exit_code":1e999,"duration":{"secs":1e308,"nanos":-5}}}`,
		"negative duration": `{"type":"subagent.completed","data":{"toolCallId":"t","durationMs":-1e30}}`,
		"many blocks":       `{"type":"user","message":{"content":[` + strings.TrimSuffix(strings.Repeat(`{"type":"tool_result","tool_use_id":"x","content":"y"},`, 20_000), ",") + `]}}`,
		"many tool calls":   `{"id":"g","type":"gemini","toolCalls":[` + strings.TrimSuffix(strings.Repeat(`{"id":"","name":"run_shell_command","args":{"command":"x"},"status":"success"},`, 20_000), ",") + `]}`,
		"patch bomb":        `{"$patch":{"updates":[` + strings.TrimSuffix(strings.Repeat(`{"id":"m","toolCalls":[{"id":"c","result":[{"text":"x"}]}]},`, 20_000), ",") + `]}}`,
		"path traversal id": `{"type":"session.start","data":{"sessionId":"../../../../etc/passwd","context":{"cwd":"../../.."}}}`,
		"newline in fields": `{"type":"user","sessionId":"a\nb","cwd":"c\r\nd","message":{"content":"x"}}`,
		"script in name":    `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t","name":"<script>alert(1)</script>","input":{}}]}}`,
		"timestamp garbage": `{"type":"user","timestamp":"` + strings.Repeat("9", 5000) + `","message":{"content":"x"}}`,
		"timestamp far":     `{"type":"user","timestamp":"9999-12-31T23:59:59.999999999Z","message":{"content":"x"}}`,
		"timestamp ancient": `{"type":"user","timestamp":"0001-01-01T00:00:00Z","message":{"content":"x"}}`,
	}
}

func TestParsersSurviveHostileLines(t *testing.T) {
	for _, p := range Parsers() {
		st := &FileState{Path: "/h/x.jsonl"}
		for name, line := range hostileLines() {
			start := time.Now()
			evs, err := p.ParseLine([]byte(line), st)
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("%s/%s: took %v", p.AgentID(), name, d)
			}
			if err != nil && !errors.Is(err, ErrMalformed) {
				t.Errorf("%s/%s: unexpected error type: %v", p.AgentID(), name, err)
			}
			for _, e := range evs {
				checkBounded(t, p.AgentID()+"/"+name, e)
				b, merr := e.MarshalLine()
				if merr != nil {
					t.Errorf("%s/%s: marshal: %v", p.AgentID(), name, merr)
				}
				if strings.Count(string(b), "\n") != 1 {
					t.Errorf("%s/%s: event is not one line", p.AgentID(), name)
				}
			}
		}
		if st.Lines != uint64(len(hostileLines())) {
			t.Errorf("%s: lines=%d", p.AgentID(), st.Lines)
		}
		if len(st.Pending) > maxPending || len(st.Extra) > maxExtra || len(st.seen) > maxSeen+1 || len(st.hints) > maxHints {
			t.Errorf("%s: state grew past its bounds", p.AgentID())
		}
		for _, s := range []string{st.SessionID, st.ParentSessionID, st.Model, st.Version} {
			if len(s) > maxIDLen {
				t.Errorf("%s: state string of %d bytes", p.AgentID(), len(s))
			}
		}
		if len(st.CWD) > maxCWDLen {
			t.Errorf("%s: cwd of %d bytes", p.AgentID(), len(st.CWD))
		}
	}
}

// checkBounded asserts that no serialized field carries an attacker-sized
// value. Target.Command and Content are exempt: the first is the command as
// written (the redaction stage truncates it), the second never leaves.
func checkBounded(t *testing.T, where string, e *event.Event) {
	t.Helper()
	check := func(field, s string, max int) {
		if len(s) > max {
			t.Errorf("%s: %s is %d bytes", where, field, len(s))
		}
	}
	if e.Session != nil {
		check("session.id", e.Session.ID, maxIDLen)
		check("session.parent_id", e.Session.ParentID, maxIDLen)
		check("session.turn_id", e.Session.TurnID, maxIDLen)
		check("session.cwd", e.Session.CWD, maxCWDLen)
		check("session.model", e.Session.Model, maxModelLen)
		check("session.subagent_id", e.Session.SubagentID, maxIDLen)
		check("session.subagent_type", e.Session.SubagentType, maxNameLen)
	}
	if e.Agent != nil {
		check("agent.version", e.Agent.Version, maxVersionLen)
	}
	if e.Tool != nil {
		check("tool.name", e.Tool.Name, maxNameLen)
		check("tool.use_id", e.Tool.UseID, maxIDLen)
		check("tool.mcp_server", e.Tool.MCPServer, maxNameLen)
		check("tool.mcp_tool", e.Tool.MCPTool, maxNameLen)
		if len(e.Tool.InputKeys) > 64 {
			t.Errorf("%s: %d input keys", where, len(e.Tool.InputKeys))
		}
	}
	if e.Target != nil {
		check("target.path", e.Target.Path, 4096)
		check("target.url", e.Target.URL, 8192)
		check("target.query", e.Target.Query, 4096)
	}
	if e.Outcome != nil {
		check("outcome.error", e.Outcome.Error, 64)
	}
	for k, v := range e.Labels {
		check("label "+k, v, maxIDLen)
	}
}

func TestParsersSurviveRandomBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(20261111))
	seeds := append(append(append(append([]string{}, claudeMain...), codexMain...), copilotMain...), geminiMain...)
	deadline := time.Now().Add(4 * time.Second)
	for _, p := range Parsers() {
		st := &FileState{Path: "/fuzz"}
		for i := 0; i < 6000 && time.Now().Before(deadline); i++ {
			var line []byte
			if i%3 == 0 {
				line = make([]byte, rng.Intn(300))
				rng.Read(line)
			} else {
				// Mutate a real record: flip, delete or duplicate bytes.
				line = []byte(seeds[rng.Intn(len(seeds))])
				for m := rng.Intn(6); m >= 0 && len(line) > 2; m-- {
					at := rng.Intn(len(line))
					switch rng.Intn(4) {
					case 0:
						line[at] = byte(rng.Intn(256))
					case 1:
						line = append(line[:at], line[at+1:]...)
					case 2:
						line = append(line[:at], append([]byte{line[at], line[at]}, line[at+1:]...)...)
					case 3:
						line = line[:at]
					}
				}
			}
			evs, _ := p.ParseLine(line, st)
			for _, e := range evs {
				if _, err := e.MarshalLine(); err != nil {
					t.Fatalf("%s: marshal after %q: %v", p.AgentID(), line, err)
				}
			}
		}
	}
}

func TestParseLineContract(t *testing.T) {
	for _, p := range Parsers() {
		if _, err := p.ParseLine([]byte(`{}`), nil); err == nil {
			t.Errorf("%s: nil state must be an error, not a panic", p.AgentID())
		}
		st := &FileState{}
		if evs, err := p.ParseLine(nil, st); err != nil || len(evs) != 0 || st.Malformed != 0 {
			t.Errorf("%s: empty line: %v %v", p.AgentID(), evs, err)
		}
		if _, err := p.ParseLine([]byte("garbage"), st); !errors.Is(err, ErrMalformed) || st.Malformed != 1 {
			t.Errorf("%s: garbage: err=%v malformed=%d", p.AgentID(), err, st.Malformed)
		}
		if _, err := p.ParseLine([]byte(`{"type":`), st); !errors.Is(err, ErrMalformed) || st.Malformed != 2 {
			t.Errorf("%s: torn JSON: err=%v malformed=%d", p.AgentID(), err, st.Malformed)
		}
		if st.Lines != 3 {
			t.Errorf("%s: lines=%d", p.AgentID(), st.Lines)
		}
		// The line buffer may be reused by the caller.
		buf := []byte(claudePrompt("s", 0, "kept"))
		evs, _ := p.ParseLine(buf, &FileState{})
		for i := range buf {
			buf[i] = 'X'
		}
		for _, e := range evs {
			if e.Content != nil && strings.Contains(e.Content.PromptText, "X") {
				t.Errorf("%s: event aliases the line buffer", p.AgentID())
			}
		}
	}
}

func TestRegistry(t *testing.T) {
	ps := Parsers()
	if len(ps) != 4 {
		t.Fatalf("parsers = %d", len(ps))
	}
	want := map[string]string{FormatClaude: "claude-code", FormatCodex: "codex", FormatCopilot: "copilot-cli", FormatGemini: "gemini-cli"}
	for format, agent := range want {
		p, ok := ForFormat(format)
		if !ok || p.AgentID() != agent {
			t.Errorf("ForFormat(%q) = %v %v", format, p, ok)
		}
		if p2, ok := ForFormat(agent); !ok || p2.AgentID() != agent {
			t.Errorf("ForFormat(%q) by agent id failed", agent)
		}
	}
	if _, ok := ForFormat("cursor-sqlite"); ok {
		t.Error("unexpected parser")
	}
	for path, agent := range map[string]string{claudeMainPath: "claude-code", codexPath: "codex", copilotPath: "copilot-cli", geminiPath: "gemini-cli"} {
		if p, ok := ForPath(path); !ok || p.AgentID() != agent {
			t.Errorf("ForPath(%q) = %v", path, p)
		}
	}
	if _, ok := ForPath("/etc/passwd"); ok {
		t.Error("ForPath matched /etc/passwd")
	}
	if k, s, tool := ToolKindFor("claude-code", "mcp__github__create_issue"); k != event.ToolMCP || s != "github" || tool != "create_issue" {
		t.Errorf("ToolKindFor = %v %v %v", k, s, tool)
	}
	if k, _, _ := ToolKindFor("gemini-cli", "run_shell_command"); k != event.ToolShell {
		t.Errorf("ToolKindFor = %v", k)
	}
}

func TestStateBounds(t *testing.T) {
	p, _ := ForFormat(FormatClaude)
	st := &FileState{Path: claudeMainPath}
	// Calls opened and never closed.
	for i := 0; i < 3*maxPending; i++ {
		line := fmt.Sprintf(`{"type":"assistant","sessionId":"s","message":{"content":[{"type":"tool_use","id":"t%d","name":"Bash","input":{"command":"x"}}]}}`, i)
		if _, err := p.ParseLine([]byte(line), st); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.Pending) != maxPending || len(st.pendOrder) > 2*maxPending+1 {
		t.Fatalf("pending=%d order=%d", len(st.Pending), len(st.pendOrder))
	}
	if st.Pending[fmt.Sprintf("t%d", 3*maxPending-1)] == nil || st.Pending["t0"] != nil {
		t.Error("the oldest calls must be the ones dropped")
	}
	// A caller-filled Pending map (no arrival order) is bounded too.
	st2 := &FileState{Pending: map[string]*event.Event{}}
	for i := 0; i < maxPending+50; i++ {
		st2.Pending[fmt.Sprintf("x%d", i)] = &event.Event{}
	}
	st2.addPending("new", &event.Event{})
	if len(st2.Pending) > maxPending || st2.Pending["new"] == nil {
		t.Errorf("caller-filled pending = %d", len(st2.Pending))
	}

	st3 := &FileState{}
	for i := 0; i < 3*maxSeen; i++ {
		st3.remember(fmt.Sprintf("k%d", i))
	}
	if len(st3.seen) > maxSeen || len(st3.seenRing) > maxSeen || !st3.wasSeen(fmt.Sprintf("k%d", 3*maxSeen-1)) {
		t.Errorf("seen=%d ring=%d", len(st3.seen), len(st3.seenRing))
	}
	for i := 0; i < 3*maxHints; i++ {
		st3.hint(fmt.Sprintf("h%d", i))
	}
	if len(st3.hints) > maxHints {
		t.Errorf("hints=%d", len(st3.hints))
	}
	for i := 0; i < 3*maxExtra; i++ {
		st3.setExtra(fmt.Sprintf("e%d", i), "v")
	}
	if len(st3.Extra) > maxExtra {
		t.Errorf("extra=%d", len(st3.Extra))
	}
}

func TestEventTimeFallbacks(t *testing.T) {
	p, _ := ForFormat(FormatClaude)
	st := &FileState{Path: claudeMainPath}
	// No timestamp anywhere: the event gets the current time, a label
	// saying so, and an id that does not depend on when it was read.
	line := `{"type":"user","sessionId":"s","message":{"content":"no clock"}}`
	a, _ := p.ParseLine([]byte(line), st)
	time.Sleep(2 * time.Millisecond)
	b, _ := p.ParseLine([]byte(line), &FileState{Path: claudeMainPath})
	if len(a) != 1 || a[0].ID != b[0].ID || a[0].Labels["ts_source"] != "sensor" || time.Since(a[0].TS.Time) > time.Minute {
		t.Fatalf("no-timestamp event: id %s vs %s labels=%v ts=%s", a[0].ID, b[0].ID, a[0].Labels, a[0].TS)
	}
	// After a dated record, an undated one inherits its time.
	evs := parseInto(t, p, st, claudePrompt("s", 5, "dated"), line)
	if evs[1].TS.String() != evs[0].TS.String() {
		t.Errorf("undated record time = %s, want %s", evs[1].TS, evs[0].TS)
	}
}
