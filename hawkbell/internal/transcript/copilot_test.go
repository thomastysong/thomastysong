package transcript

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const copilotPath = "/home/alice/.copilot/session-state/8f14e45f-ceea-4672-a1b2-0123456789ab/events.jsonl"

var copilotMain = []string{
	`{"id":"e1","parentId":null,"timestamp":"2026-11-01T09:00:00.000Z","type":"session.start","data":{"sessionId":"8f14e45f-ceea-4672-a1b2-0123456789ab","version":1,"producer":"copilot-agent","copilotVersion":"1.0.40","startTime":"2026-11-01T09:00:00.000Z","selectedModel":"claude-sonnet-4.6","context":{"cwd":"/work/repo","branch":"main","repository":"acme/repo"}}}`,
	`{"id":"e2","parentId":"e1","timestamp":"2026-11-01T09:00:05.000Z","type":"user.message","data":{"content":"run the tests, db password is hunter2","source":"user","agentMode":"interactive"}}`,
	`{"id":"e3","parentId":"e2","timestamp":"2026-11-01T09:00:06.000Z","type":"assistant.message_delta","ephemeral":true,"data":{"deltaContent":"I"}}`,
	`{"id":"e4","parentId":"e3","timestamp":"2026-11-01T09:00:07.000Z","type":"tool.execution_start","data":{"toolCallId":"tc1","toolName":"bash","arguments":{"command":"npm test","description":"run tests"},"turnId":"t1","model":"claude-sonnet-4.6"}}`,
	`{"id":"e5","parentId":"e4","timestamp":"2026-11-01T09:00:07.100Z","type":"permission.requested","data":{"requestId":"r1","permissionMode":"manual","permissionRequest":{"kind":"shell","toolCallId":"tc1","fullCommandText":"npm test","intention":"run tests","commands":[],"possiblePaths":[],"possibleUrls":[],"hasWriteFileRedirection":false,"canOfferSessionApproval":true}}}`,
	`{"id":"e6","parentId":"e5","timestamp":"2026-11-01T09:00:09.000Z","type":"permission.completed","data":{"requestId":"r1","toolCallId":"tc1","result":{"kind":"approved"},"decisionSource":"human_response"}}`,
	`{"id":"e7","parentId":"e6","timestamp":"2026-11-01T09:00:12.000Z","type":"tool.execution_complete","data":{"toolCallId":"tc1","success":true,"result":{"content":"12 passing secret-output","detailedContent":"12 passing secret-output"},"shellExecution":{"exitCode":0},"turnId":"t1"}}`,
	`{"id":"e8","parentId":"e7","timestamp":"2026-11-01T09:00:13.000Z","type":"tool.execution_start","data":{"toolCallId":"tc2","toolName":"str_replace_editor","arguments":{"command":"view","path":"/work/repo/package.json"}}}`,
	`{"id":"e9","parentId":"e8","timestamp":"2026-11-01T09:00:13.500Z","type":"tool.execution_complete","data":{"toolCallId":"tc2","success":true,"result":{"content":"{}"}}}`,
	`{"id":"e10","parentId":"e9","timestamp":"2026-11-01T09:00:14.000Z","type":"tool.execution_start","data":{"toolCallId":"tc3","toolName":"github-mcp-server-list_issues","mcpServerName":"github-mcp-server","mcpToolName":"list_issues","arguments":{"owner":"acme","repo":"repo"}}}`,
	`{"id":"e11","parentId":"e10","timestamp":"2026-11-01T09:00:15.000Z","type":"tool.execution_complete","data":{"toolCallId":"tc3","success":false,"error":{"message":"401 bad credentials","code":"mcp_error"}}}`,
	`{"id":"e12","parentId":"e11","timestamp":"2026-11-01T09:00:16.000Z","type":"tool.execution_start","data":{"toolCallId":"tc4","toolName":"bash","arguments":{"command":"false"}}}`,
	`{"id":"e13","parentId":"e12","timestamp":"2026-11-01T09:00:17.000Z","type":"tool.execution_complete","data":{"toolCallId":"tc4","success":true,"result":{"content":"","contents":[{"type":"terminal","text":"<exited with exit code 2>"},{"type":"shell_exit","exitCode":2}]}}}`,
	`{"id":"e14","parentId":"e13","timestamp":"2026-11-01T09:00:18.000Z","type":"tool.execution_start","data":{"toolCallId":"tc5","toolName":"create","arguments":{"path":"/home/alice/.ssh/authorized_keys","file_text":"ssh-ed25519 AAAA attacker"}}}`,
	`{"id":"e15","parentId":"e14","timestamp":"2026-11-01T09:00:18.100Z","type":"permission.requested","data":{"requestId":"r2","permissionMode":"manual","permissionRequest":{"kind":"write","toolCallId":"tc5","fileName":"/home/alice/.ssh/authorized_keys","diff":"+ssh-ed25519","intention":"add key","canOfferSessionApproval":false}}}`,
	`{"id":"e16","parentId":"e15","timestamp":"2026-11-01T09:00:20.000Z","type":"permission.completed","data":{"requestId":"r2","result":{"kind":"denied-interactively-by-user"},"decisionSource":"human_response"}}`,
	`{"id":"e17","parentId":"e16","timestamp":"2026-11-01T09:00:20.100Z","type":"tool.execution_complete","data":{"toolCallId":"tc5","success":false,"error":{"message":"The user rejected this tool call."}}}`,
	`{"id":"e18","parentId":"e17","timestamp":"2026-11-01T09:00:21.000Z","type":"tool.execution_start","data":{"toolCallId":"tc6","toolName":"task","arguments":{"description":"explore","prompt":"find TODOs","agent_type":"explore"}}}`,
	`{"id":"e19","parentId":"e18","timestamp":"2026-11-01T09:00:21.100Z","type":"subagent.started","data":{"toolCallId":"tc6","agentName":"explore","agentDisplayName":"Explore","agentDescription":"Explores code"}}`,
	`{"id":"e20","parentId":"e19","timestamp":"2026-11-01T09:00:21.200Z","type":"user.message","agentId":"agent-1","data":{"content":"find TODOs","source":"agent-explore"}}`,
	`{"id":"e21","parentId":"e20","timestamp":"2026-11-01T09:00:22.000Z","type":"tool.execution_start","agentId":"agent-1","data":{"toolCallId":"tc7","toolName":"grep","arguments":{"pattern":"TODO"},"parentToolCallId":"tc6"}}`,
	`{"id":"e22","parentId":"e21","timestamp":"2026-11-01T09:00:22.500Z","type":"tool.execution_complete","agentId":"agent-1","data":{"toolCallId":"tc7","success":true,"result":{"content":"a.go:1"}}}`,
	`{"id":"e23","parentId":"e22","timestamp":"2026-11-01T09:00:23.000Z","type":"subagent.completed","data":{"toolCallId":"tc6","agentName":"explore","agentDisplayName":"Explore","durationMs":1900,"totalToolCalls":1}}`,
	`{"id":"e24","parentId":"e23","timestamp":"2026-11-01T09:00:23.100Z","type":"tool.execution_complete","data":{"toolCallId":"tc6","success":true,"result":{"content":"1 TODO"}}}`,
	`{"id":"e25","parentId":"e24","timestamp":"2026-11-01T09:00:24.000Z","type":"session.mode_changed","data":{"previousMode":"interactive","newMode":"autopilot"}}`,
	`{"id":"e26","parentId":"e25","timestamp":"2026-11-01T09:00:25.000Z","type":"user.message","data":{"content":"keep going","isAutopilotContinuation":true}}`,
	`{"id":"e27","parentId":"e26","timestamp":"2026-11-01T09:00:26.000Z","type":"permission.requested","data":{"requestId":"r3","permissionMode":"allow-all","permissionRequest":{"kind":"url","url":"https://x.example"}}}`,
	`{"id":"e28","parentId":"e27","timestamp":"2026-11-01T09:00:26.100Z","type":"permission.completed","data":{"requestId":"r3","result":{"kind":"approved-for-session"},"decisionSource":"host_policy"}}`,
	`{"id":"e29","parentId":"e28","timestamp":"2026-11-01T09:00:27.000Z","type":"assistant.turn_end","data":{"turnId":"t1"}}`,
	`{"id":"e30","parentId":"e29","timestamp":"2026-11-01T09:00:28.000Z","type":"session.compaction_complete","data":{"outcome":"success"}}`,
	`{"id":"e31","parentId":"e30","timestamp":"2026-11-01T09:00:29.000Z","type":"abort","data":{"reason":"user initiated"}}`,
	`{"id":"e32","parentId":"e31","timestamp":"2026-11-01T09:00:30.000Z","type":"brand.new_event","data":{}}`,
	`{"id":"e33","parentId":"e32","timestamp":"2026-11-01T09:00:31.000Z","type":"session.model_change","data":{"newModel":"gpt-5.2"}}`,
	`{"id":"e34","parentId":"e33","timestamp":"2026-11-01T09:00:32.000Z","type":"session.shutdown","data":{"shutdownType":"routine","totalPremiumRequests":3,"modelMetrics":{},"codeChanges":{}}}`,
}

func TestCopilotSession(t *testing.T) {
	p, ok := ForFormat(FormatCopilot)
	if !ok {
		t.Fatal("no copilot parser")
	}
	evs, st := parseLines(t, p, copilotPath, copilotMain...)
	wantSeq(t, evs,
		"session.start",
		"prompt.submit",
		"tool.pre bash",
		"permission.decision bash allow",
		"tool.post bash ok",
		"tool.pre str_replace_editor",
		"tool.post str_replace_editor ok",
		"tool.pre github-mcp-server-list_issues",
		"tool.post github-mcp-server-list_issues error",
		"tool.pre bash",
		"tool.post bash error",
		"tool.pre create",
		"permission.decision create deny",
		"tool.post create denied deny",
		"tool.pre task",
		"subagent.start",
		"tool.pre grep",
		"tool.post grep ok",
		"subagent.stop ok",
		"tool.post task ok",
		"config.change",
		"config.change",
		"permission.decision allow",
		"turn.end ok",
		"context.compact",
		"turn.end interrupted",
		"session.end ok",
	)
	checkCommon(t, evs, "copilot-cli", copilotPath)

	if st.SessionID != "8f14e45f-ceea-4672-a1b2-0123456789ab" || st.Version != "1.0.40" || st.CWD != "/work/repo" || st.Model != "gpt-5.2" {
		t.Errorf("state = %+v", st)
	}
	if st.Unknown != 1 || st.Malformed != 0 {
		t.Errorf("unknown=%d malformed=%d", st.Unknown, st.Malformed)
	}
	if st.PermissionMode != "bypass" {
		t.Errorf("permission mode = %q", st.PermissionMode)
	}
	if evs[0].Agent.Version != "1.0.40" || evs[0].Session.Model != "claude-sonnet-4.6" {
		t.Errorf("start = %+v %+v", evs[0].Agent, evs[0].Session)
	}

	bash := find(t, evs, event.TypeToolPre, "tc1")
	if bash.Tool.Kind != event.ToolShell || bash.Target.Command != "npm test" || bash.Session.TurnID != "t1" {
		t.Errorf("bash = %+v %+v %+v", bash.Tool, bash.Target, bash.Session)
	}
	dec := find(t, evs, event.TypePermissionDecision, "tc1")
	if dec.Outcome.DecisionSource != "user" || dec.Labels["result"] != "approved" || dec.Labels["request"] != "shell" || dec.Tool.Kind != event.ToolShell {
		t.Errorf("decision = %+v %v %+v", dec.Outcome, dec.Labels, dec.Tool)
	}
	if o := find(t, evs, event.TypeToolPost, "tc1").Outcome; o.ExitCode == nil || *o.ExitCode != 0 {
		t.Errorf("bash outcome = %+v", o)
	}
	// str_replace_editor with command=view is a read, not an edit.
	if v := find(t, evs, event.TypeToolPre, "tc2"); v.Tool.Kind != event.ToolFileRead || v.Target.Path != "/work/repo/package.json" {
		t.Errorf("view = %+v %+v", v.Tool, v.Target)
	}
	mcp := find(t, evs, event.TypeToolPre, "tc3")
	if mcp.Tool.Kind != event.ToolMCP || mcp.Tool.MCPServer != "github-mcp-server" || mcp.Tool.MCPTool != "list_issues" {
		t.Errorf("mcp = %+v", mcp.Tool)
	}
	// A failed command is recorded as a successful tool call; the exit code says otherwise.
	if o := find(t, evs, event.TypeToolPost, "tc4").Outcome; o.Status != "error" || *o.ExitCode != 2 || o.Error != "exit_code" {
		t.Errorf("failed command = %+v", o)
	}
	create := find(t, evs, event.TypeToolPre, "tc5")
	if create.Tool.Kind != event.ToolFileWrite || create.Content.FileContent != "ssh-ed25519 AAAA attacker" {
		t.Errorf("create = %+v %+v", create.Tool, create.Content)
	}
	deny := find(t, evs, event.TypePermissionDecision, "tc5")
	if deny.Outcome.DecisionSource != "user" || deny.Target == nil || deny.Target.Path != "/home/alice/.ssh/authorized_keys" {
		t.Errorf("deny = %+v %+v", deny.Outcome, deny.Target)
	}
	if o := find(t, evs, event.TypeToolPost, "tc5").Outcome; o.DecisionSource != "user" || o.Error != "permission_denied" {
		t.Errorf("denied post = %+v", o)
	}

	sub := find(t, evs, event.TypeSubagentStart, "tc6")
	if sub.Session.SubagentType != "explore" || sub.Session.SubagentID != "tc6" {
		t.Errorf("subagent start = %+v", sub.Session)
	}
	if g := find(t, evs, event.TypeToolPre, "tc7"); g.Session.SubagentID != "agent-1" || g.Tool.Kind != event.ToolFileList {
		t.Errorf("subagent tool = %+v %+v", g.Session, g.Tool)
	}
	if g := find(t, evs, event.TypeToolPost, "tc7"); g.Session.SubagentID != "agent-1" {
		t.Errorf("subagent tool result = %+v", g.Session)
	}
	if s := find(t, evs, event.TypeSubagentStop, "tc6"); s.Outcome.DurationMS != 1900 {
		t.Errorf("subagent stop = %+v", s.Outcome)
	}
	var changes []string
	for _, e := range evs {
		if e.Type == event.TypeConfigChange {
			changes = append(changes, e.Labels["from"]+">"+e.Labels["to"])
		}
	}
	if strings.Join(changes, ",") != "default>auto,auto>bypass" {
		t.Errorf("mode changes = %v", changes)
	}

	out := wire(t, evs)
	for _, secret := range []string{"hunter2", "secret-output", "bad credentials", "attacker", "find TODOs", "keep going"} {
		if strings.Contains(out, secret) {
			t.Errorf("wire output leaks %q", secret)
		}
	}
	again, _ := parseLines(t, p, copilotPath, copilotMain...)
	if !sameIDs(evs, again) {
		t.Error("event ids are not deterministic")
	}
}

func TestCopilotSessionIDFromPathAndPermissionKinds(t *testing.T) {
	p, _ := ForFormat(FormatCopilot)
	evs, st := parseLines(t, p, copilotPath,
		`{"timestamp":"2026-11-01T09:00:00.000Z","type":"tool.execution_start","data":{"toolCallId":"a","toolName":"bash","arguments":"not an object"}}`,
		`{"timestamp":"2026-11-01T09:00:01.000Z","type":"permission.completed","data":{"requestId":"x","toolCallId":"a","result":{"kind":"denied-by-rules","rules":[]}}}`,
		`{"timestamp":"2026-11-01T09:00:02.000Z","type":"permission.completed","data":{"requestId":"y","result":{"kind":"denied-by-permission-request-hook"}}}`,
		`{"timestamp":"2026-11-01T09:00:03.000Z","type":"permission.completed","data":{"requestId":"z","result":{"kind":"cancelled"}}}`,
		`{"timestamp":"2026-11-01T09:00:04.000Z","type":"permission.completed","data":{"requestId":"w","result":{"kind":"denied-by-something-new"}}}`,
		`{"timestamp":"2026-11-01T09:00:05.000Z","type":"permission.completed","data":{"requestId":"v","result":{"kind":"granted-by-magic"}}}`,
		`{"timestamp":"2026-11-01T09:00:06.000Z","type":"tool.execution_complete","data":{"toolCallId":"a","result":{"content":"x"}}}`,
		`{"timestamp":"2026-11-01T09:00:07.000Z","type":"session.shutdown","data":{"shutdownType":"error","errorReason":"boom"}}`,
	)
	wantSeq(t, evs,
		"tool.pre bash",
		"permission.decision bash deny",
		"permission.decision deny",
		"permission.decision interrupted",
		"permission.decision deny",
		"tool.post bash denied deny",
		"session.end error",
	)
	if st.SessionID != "8f14e45f-ceea-4672-a1b2-0123456789ab" {
		t.Errorf("session id from path = %q", st.SessionID)
	}
	if evs[1].Outcome.DecisionSource != "policy" || evs[2].Outcome.DecisionSource != "hook" || evs[4].Labels["result"] != "" {
		t.Errorf("decision sources: %+v %+v labels=%v", evs[1].Outcome, evs[2].Outcome, evs[4].Labels)
	}
	if st.Unknown != 1 { // granted-by-magic
		t.Errorf("unknown = %d", st.Unknown)
	}
	if evs[0].Content.ToolInput["input"] != "not an object" {
		t.Errorf("string arguments = %+v", evs[0].Content.ToolInput)
	}
}

func TestCopilotMatch(t *testing.T) {
	p, _ := ForFormat(FormatCopilot)
	if !p.Match(copilotPath) || !p.Match(`C:\Users\a\.copilot\session-state\x\events.jsonl`) {
		t.Error("expected match")
	}
	for _, s := range []string{"/home/a/.copilot/session-state/x/workspace.yaml", "/home/a/.copilot/logs/events.jsonl", claudeMainPath} {
		if p.Match(s) {
			t.Errorf("Match(%q) = true", s)
		}
	}
}
