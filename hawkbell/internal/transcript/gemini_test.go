package transcript

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const geminiPath = "/home/alice/.gemini/tmp/repo-slug/chats/session-2026-11-01T08-00-7b1c2d3e.jsonl"
const geminiSubPath = "/home/alice/.gemini/tmp/repo-slug/chats/7b1c2d3e-0000-4000-8000-000000000001/sub-55aa.jsonl"

var geminiMain = []string{
	`{"sessionId":"7b1c2d3e-0000-4000-8000-000000000001","projectHash":"abc","startTime":"2026-11-01T08:00:00.000Z","lastUpdated":"2026-11-01T08:00:00.000Z","kind":"main"}`,
	`{"id":"u1","timestamp":"2026-11-01T08:00:05.000Z","type":"user","content":[{"text":"list files, key is AIzaSECRET"}]}`,
	`{"$set":{"lastUpdated":"2026-11-01T08:00:05.000Z"}}`,
	// The call is first recorded while executing ...
	`{"id":"g1","timestamp":"2026-11-01T08:00:06.000Z","type":"gemini","model":"gemini-3-pro","content":"","toolCalls":[{"id":"c1","name":"run_shell_command","args":{"command":"ls -la"},"status":"executing","timestamp":"2026-11-01T08:00:06.500Z","displayName":"Shell"}]}`,
	// ... then the same message is appended again with the result ...
	`{"id":"g1","timestamp":"2026-11-01T08:00:06.000Z","type":"gemini","model":"gemini-3-pro","content":"","toolCalls":[{"id":"c1","name":"run_shell_command","args":{"command":"ls -la"},"status":"success","timestamp":"2026-11-01T08:00:06.500Z","displayName":"Shell","result":[{"functionResponse":{"id":"c1","name":"run_shell_command","response":{"output":"Output: a.go secret-output\nExit Code: 0"}}}],"resultDisplay":"a.go"}]}`,
	// ... and once more with token counts.
	`{"id":"g1","timestamp":"2026-11-01T08:00:06.000Z","type":"gemini","model":"gemini-3-pro","content":"","tokens":{"input":10,"output":5,"cached":0,"total":15},"toolCalls":[{"id":"c1","name":"run_shell_command","args":{"command":"ls -la"},"status":"success","timestamp":"2026-11-01T08:00:06.500Z","result":[{"functionResponse":{"id":"c1","name":"run_shell_command","response":{"output":"Output: a.go secret-output\nExit Code: 0"}}}]}]}`,
	`{"id":"g2","timestamp":"2026-11-01T08:00:10.000Z","type":"gemini","model":"gemini-3-pro","content":[{"text":"ok"}],"toolCalls":[` +
		`{"id":"c2","name":"read_file","args":{"file_path":"/work/repo/a.go"},"status":"success","timestamp":"2026-11-01T08:00:10.100Z","result":[{"functionResponse":{"id":"c2","name":"read_file","response":{"output":"package a\n// Exit Code: 7"}}}]},` +
		`{"id":"c3","name":"mcp_github_create_issue","displayName":"create_issue (github MCP Server)","args":{"title":"x"},"status":"error","timestamp":"2026-11-01T08:00:10.200Z","result":[{"functionResponse":{"id":"c3","name":"mcp_github_create_issue","response":{"error":"401"}}}]},` +
		`{"id":"c4","name":"write_file","args":{"file_path":"/work/repo/.env","content":"TOKEN=abc"},"status":"cancelled","timestamp":"2026-11-01T08:00:10.300Z","resultDisplay":"User denied execution."},` +
		`{"id":"c5","name":"run_shell_command","args":{"command":"echo 'Exit Code: 0'; exit 3"},"status":"success","timestamp":"2026-11-01T08:00:10.400Z","result":[{"functionResponse":{"id":"c5","name":"run_shell_command","response":{"output":"Output: Exit Code: 0\nExit Code: 3"}}}]},` +
		`{"id":"c6","name":"web_fetch","args":{"prompt":"summarize https://tok:pw@docs.example/a and https://b.example/c"},"status":"executing","timestamp":"2026-11-01T08:00:10.500Z"},` +
		`{"id":"c7","name":"invoke_agent","args":{"agent":"codebase_investigator","prompt":"dig"},"status":"cancelled","timestamp":"2026-11-01T08:00:10.600Z"}]}`,
	// Since v0.44 tool results are also written as user messages.
	`{"id":"u2","timestamp":"2026-11-01T08:00:11.000Z","type":"user","content":[{"functionResponse":{"id":"c2","name":"read_file","response":{"output":"package a"}}}]}`,
	`{"$rewindTo":"u2"}`,
	`{"$patch":{"id":"g2","toolCalls":[{"id":"c6","result":[{"functionResponse":{"id":"c6","name":"web_fetch","response":{"output":"summary text"}}}]},{"id":"c2","result":[]},{"id":"never-opened","result":[{"text":"x"}]}]}}`,
	`{"id":"i1","timestamp":"2026-11-01T08:00:12.000Z","type":"info","content":"Update available"}`,
	`{"id":"h1","timestamp":"2026-11-01T08:00:13.000Z","type":"hologram","content":"?"}`,
	`{"nothing":"recognisable"}`,
	// A user message appended twice (resume) is one prompt.
	`{"id":"u1","timestamp":"2026-11-01T08:00:05.000Z","type":"user","content":[{"text":"list files, key is AIzaSECRET"}]}`,
}

func TestGeminiSession(t *testing.T) {
	p, ok := ForFormat(FormatGemini)
	if !ok {
		t.Fatal("no gemini parser")
	}
	evs, st := parseLines(t, p, geminiPath, geminiMain...)
	wantSeq(t, evs,
		"session.start",
		"prompt.submit",
		"tool.pre run_shell_command",
		"tool.post run_shell_command ok",
		"tool.pre read_file",
		"tool.post read_file ok",
		"tool.pre mcp_github_create_issue",
		"tool.post mcp_github_create_issue error",
		"tool.pre write_file",
		"tool.post write_file denied deny",
		"tool.pre run_shell_command",
		"tool.post run_shell_command error",
		"tool.pre web_fetch",
		"tool.pre invoke_agent",
		"tool.post invoke_agent interrupted",
		"tool.post web_fetch ok",
	)
	checkCommon(t, evs, "gemini-cli", geminiPath)

	if st.SessionID != "7b1c2d3e-0000-4000-8000-000000000001" || st.Model != "gemini-3-pro" {
		t.Errorf("state = %+v", st)
	}
	if st.Unknown != 2 || st.Malformed != 0 {
		t.Errorf("unknown=%d malformed=%d", st.Unknown, st.Malformed)
	}
	if got := evs[0].TS.String(); got != "2026-11-01T08:00:00.000000Z" {
		t.Errorf("session start time = %s", got)
	}
	if !strings.Contains(evs[1].Content.PromptText, "list files") {
		t.Errorf("prompt = %+v", evs[1].Content)
	}

	sh := find(t, evs, event.TypeToolPre, "c1")
	if sh.Tool.Kind != event.ToolShell || sh.Target.Command != "ls -la" || sh.TS.String() != "2026-11-01T08:00:06.500000Z" {
		t.Errorf("shell = %+v %+v %s", sh.Tool, sh.Target, sh.TS)
	}
	if o := find(t, evs, event.TypeToolPost, "c1"); o.Outcome.ExitCode == nil || *o.Outcome.ExitCode != 0 || !strings.Contains(o.Content.ToolOutput, "a.go") {
		t.Errorf("shell post = %+v %+v", o.Outcome, o.Content)
	}
	// "Exit Code:" inside a file's content means nothing for a non-shell tool.
	if o := find(t, evs, event.TypeToolPost, "c2").Outcome; o.Status != "ok" || o.ExitCode != nil {
		t.Errorf("read outcome = %+v", o)
	}
	mcp := find(t, evs, event.TypeToolPre, "c3")
	if mcp.Tool.Kind != event.ToolMCP || mcp.Tool.MCPServer != "github" || mcp.Tool.MCPTool != "create_issue" {
		t.Errorf("mcp = %+v", mcp.Tool)
	}
	wr := find(t, evs, event.TypeToolPost, "c4")
	if wr.Outcome.DecisionSource != "user" || wr.Tool.Kind != event.ToolFileWrite || wr.Target.Path != "/work/repo/.env" {
		t.Errorf("denied write = %+v %+v", wr.Outcome, wr.Tool)
	}
	// The command printed "Exit Code: 0" itself; the tool's last line wins.
	if o := find(t, evs, event.TypeToolPost, "c5").Outcome; *o.ExitCode != 3 || o.Status != "error" {
		t.Errorf("exit code = %+v", o)
	}
	fetch := find(t, evs, event.TypeToolPre, "c6")
	if fetch.Tool.Kind != event.ToolWebFetch || fetch.Target.Host != "docs.example" || len(fetch.Target.Hosts) != 1 || strings.Contains(fetch.Target.URL, "pw") {
		t.Errorf("fetch = %+v", fetch.Target)
	}
	if fp := find(t, evs, event.TypeToolPost, "c6"); fp.Content.ToolOutput != "summary text" || fp.Tool.Name != "web_fetch" {
		t.Errorf("patched result = %+v %+v", fp.Content, fp.Tool)
	}
	if a := find(t, evs, event.TypeToolPre, "c7"); a.Tool.Kind != event.ToolSubagent {
		t.Errorf("invoke_agent = %+v", a.Tool)
	}

	out := wire(t, evs)
	for _, secret := range []string{"AIzaSECRET", "secret-output", "TOKEN=abc", "tok:pw", "summary text"} {
		if strings.Contains(out, secret) {
			t.Errorf("wire output leaks %q", secret)
		}
	}
	again, _ := parseLines(t, p, geminiPath, geminiMain...)
	if !sameIDs(evs, again) {
		t.Error("event ids are not deterministic")
	}
}

func TestGeminiSubagentFile(t *testing.T) {
	p, _ := ForFormat(FormatGemini)
	evs, st := parseLines(t, p, geminiSubPath,
		`{"sessionId":"sub-55aa","projectHash":"abc","startTime":"2026-11-01T08:01:00.000Z","lastUpdated":"2026-11-01T08:01:00.000Z","kind":"subagent","directories":["/work/repo"]}`,
		`{"id":"u1","timestamp":"2026-11-01T08:01:01.000Z","type":"user","content":[{"text":"dig into the parser"}]}`,
		`{"id":"g1","timestamp":"2026-11-01T08:01:02.000Z","type":"gemini","model":"gemini-3-flash","content":"","toolCalls":[{"id":"s1","name":"grep_search","args":{"pattern":"TODO","dir_path":"src"},"status":"success","timestamp":"2026-11-01T08:01:02.500Z","result":[{"functionResponse":{"id":"s1","name":"grep_search","response":{"output":"src/a.go"}}}]}]}`,
	)
	wantSeq(t, evs, "subagent.start", "tool.pre grep_search", "tool.post grep_search ok")
	if st.ParentSessionID != "7b1c2d3e-0000-4000-8000-000000000001" {
		t.Errorf("parent = %q", st.ParentSessionID)
	}
	for i, e := range evs {
		if e.Session.ID != "sub-55aa" || e.Session.SubagentID != "sub-55aa" || e.Session.ParentID != "7b1c2d3e-0000-4000-8000-000000000001" {
			t.Errorf("event %d session = %+v", i, e.Session)
		}
	}
	if evs[1].Tool.Kind != event.ToolFileList || evs[1].Target.Path != "src" {
		t.Errorf("grep = %+v %+v", evs[1].Tool, evs[1].Target)
	}
}

func TestGeminiLegacyDocumentAndCheckpoint(t *testing.T) {
	p, _ := ForFormat(FormatGemini)
	doc := `{
  "sessionId": "legacy-1",
  "projectHash": "h",
  "startTime": "2025-09-01T08:00:00.000Z",
  "lastUpdated": "2025-09-01T08:00:09.000Z",
  "messages": [
    {"id": "u1", "timestamp": "2025-09-01T08:00:01.000Z", "type": "user", "content": "hello"},
    {"id": "g1", "timestamp": "2025-09-01T08:00:02.000Z", "type": "gemini", "model": "gemini-2.5-pro", "content": "",
     "toolCalls": [{"id": "c1", "name": "replace", "args": {"file_path": "a.go", "old_string": "x", "new_string": "y"}, "status": "success", "timestamp": "2025-09-01T08:00:03.000Z", "result": "ok"}]}
  ]
}`
	st := &FileState{Path: strings.TrimSuffix(geminiPath, "l")}
	evs := parseInto(t, p, st, doc)
	wantSeq(t, evs, "session.start", "prompt.submit", "tool.pre replace", "tool.post replace ok")
	if evs[2].Tool.Kind != event.ToolFileEdit || evs[2].Content.FileContent != "y" || evs[3].Content.ToolOutput != "ok" {
		t.Errorf("replace = %+v %+v", evs[2].Tool, evs[2].Content)
	}
	// The document is rewritten whole with one more message: only that one is new.
	grown := strings.Replace(doc, `"result": "ok"}]}`, `"result": "ok"}]},
    {"id": "u2", "timestamp": "2025-09-01T08:00:08.000Z", "type": "user", "content": "again"}`, 1)
	evs = parseInto(t, p, st, grown)
	wantSeq(t, evs, "prompt.submit")
	// A $set carrying a full legacy checkpoint is deduplicated the same way.
	evs = parseInto(t, p, st, `{"$set":{"messages":[{"id":"u2","timestamp":"2025-09-01T08:00:08.000Z","type":"user","content":"again"},{"id":"u3","timestamp":"2025-09-01T08:00:09.000Z","type":"user","content":"third"}]}}`)
	wantSeq(t, evs, "prompt.submit")
	if evs[0].Content.PromptText != "third" {
		t.Errorf("prompt = %q", evs[0].Content.PromptText)
	}
}

func TestGeminiMCPDisplayName(t *testing.T) {
	cases := []struct {
		in, server, tool string
		ok               bool
	}{
		{"create_issue (github MCP Server)", "github", "create_issue", true},
		{"do (it) (my_server MCP Server)", "my_server", "do (it)", true},
		{"Shell", "", "", false},
		{" (x MCP Server)", "", "", false},
		{"t ( MCP Server)", "", "", false},
		{strings.Repeat("a", 5000) + " (s MCP Server)", "", "", false},
	}
	for _, c := range cases {
		s, tool, ok := geminiMCP(c.in)
		if ok != c.ok || s != c.server || tool != c.tool {
			t.Errorf("geminiMCP(%.40q) = %q,%q,%v", c.in, s, tool, ok)
		}
	}
}

func TestGeminiMatch(t *testing.T) {
	p, _ := ForFormat(FormatGemini)
	for _, s := range []string{geminiPath, geminiSubPath, strings.TrimSuffix(geminiPath, "l"), `C:\Users\a\.gemini\tmp\h\chats\session-x.jsonl`} {
		if !p.Match(s) {
			t.Errorf("Match(%q) = false", s)
		}
	}
	for _, s := range []string{
		"/home/a/.gemini/tmp/h/logs.json",
		"/home/a/.gemini/tmp/h/chats/notes.jsonl",
		"/home/a/.gemini/tmp/h/chats/p/q/deep.jsonl",
		"/home/a/.gemini/tmp/h/chats/p/sub.json",
		claudeMainPath,
	} {
		if p.Match(s) {
			t.Errorf("Match(%q) = true", s)
		}
	}
}
