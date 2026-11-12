package hookio

import (
	"bytes"
	"strings"
	"testing"
)

// Every recorded payload must be attributed to its own agent from the
// payload alone. Copilot camelCase payloads are detected without the event
// name (Detect runs before anything knows it).
func TestDetectEveryFixture(t *testing.T) {
	// Payloads that two agents send byte-for-byte identically cannot be told
	// apart without the environment; they are covered in TestDetectTies.
	for _, tc := range allFixtures(t) {
		d, ok := Detect(fixture(t, tc.file), nil)
		if !ok {
			t.Errorf("%s: not detected", tc.file)
			continue
		}
		if d.ID() != tc.dialect {
			t.Errorf("%s: detected %s, want %s", tc.file, d.ID(), tc.dialect)
		}
	}
}

func TestDetectPayloadBeatsInheritedEnvironment(t *testing.T) {
	// Gemini CLI started from inside Claude Code's Bash tool inherits
	// Claude's markers; the payload still says Gemini. And the reverse.
	claudeEnv := map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "x", "CLAUDE_PROJECT_DIR": "/p"}
	geminiEnv := map[string]string{"GEMINI_SESSION_ID": "g", "GEMINI_PROJECT_DIR": "/p", "CLAUDE_PROJECT_DIR": "/p"}
	cursorEnv := map[string]string{"CURSOR_VERSION": "2", "CLAUDE_PROJECT_DIR": "/p"}
	for _, tc := range []struct {
		file string
		env  map[string]string
		want string
	}{
		{"gemini/BeforeTool.json", claudeEnv, "gemini"},
		{"gemini/SessionStart.json", claudeEnv, "gemini"},
		{"claude/PreToolUse.json", geminiEnv, "claude"},
		{"claude/PreToolUse.json", cursorEnv, "claude"},
		{"codex/PreToolUse.json", claudeEnv, "codex"},
		{"cursor/preToolUse.json", claudeEnv, "cursor"},
		{"copilot/PreToolUse.snake.json", claudeEnv, "copilot"},
		{"copilot/preToolUse.camel.json", cursorEnv, "copilot"},
	} {
		d, ok := Detect(fixture(t, tc.file), tc.env)
		if !ok || d.ID() != tc.want {
			t.Errorf("%s with foreign env: got %v, want %s", tc.file, d, tc.want)
		}
	}
}

func TestDetectTies(t *testing.T) {
	// Claude Code and Codex send the same SessionEnd keys. With no
	// transcript hint the environment decides; with none, Claude.
	const sessionEnd = `{"cwd":"/w","hook_event_name":"SessionEnd","reason":"other","session_id":"sid-1","transcript_path":null}`
	for _, tc := range []struct {
		name string
		in   string
		env  map[string]string
		want string
	}{
		{"no evidence", sessionEnd, nil, "claude"},
		{"codex env only", sessionEnd, map[string]string{"CODEX_THREAD_ID": "t"}, "codex"},
		{"claude env only", sessionEnd, map[string]string{"CLAUDECODE": "1"}, "claude"},
		{"both envs, codex owns the session id", sessionEnd, map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "other", "CODEX_THREAD_ID": "sid-1"}, "codex"},
		{"both envs, claude owns the session id", sessionEnd, map[string]string{"CODEX_THREAD_ID": "other", "CLAUDE_CODE_SESSION_ID": "sid-1"}, "claude"},
		{"codex transcript path", `{"hook_event_name":"SessionEnd","session_id":"s","transcript_path":"C:\\Users\\u\\.codex\\sessions\\2026\\11\\11\\rollout-x.jsonl"}`, map[string]string{"CLAUDECODE": "1"}, "codex"},
		{"claude transcript path", `{"hook_event_name":"SessionEnd","session_id":"s","transcript_path":"/home/u/.claude/projects/p/s.jsonl"}`, map[string]string{"CODEX_THREAD_ID": "t"}, "claude"},
		{"codex session start carries permission_mode", `{"hook_event_name":"SessionStart","session_id":"s","source":"startup","model":"m","permission_mode":"default","transcript_path":null,"cwd":"/"}`, nil, "codex"},
		{"claude session start does not", `{"hook_event_name":"SessionStart","session_id":"s","source":"startup","model":"m","cwd":"/"}`, nil, "claude"},
		{"claude-only field", `{"hook_event_name":"PreToolUse","session_id":"s","permission_mode":"default","model":"m","prompt_id":"p","tool_name":"Bash","tool_input":{}}`, nil, "claude"},
		{"copilot timestamp without permission mode", `{"hook_event_name":"PreToolUse","session_id":"s","timestamp":"2026-11-11T00:00:00Z","cwd":"/","tool_name":"Bash","tool_input":{}}`, nil, "copilot"},
		{"cursor by version stamp alone", `{"hook_event_name":"preToolUse","cursor_version":"2.0","tool_name":"Shell"}`, nil, "cursor"},
		{"camel event name, no markers", `{"hook_event_name":"preToolUse","tool_name":"x"}`, nil, "copilot"},
	} {
		d, ok := Detect([]byte(tc.in), tc.env)
		if !ok || d.ID() != tc.want {
			t.Errorf("%s: got %v (ok=%v), want %s", tc.name, d, ok, tc.want)
		}
	}
}

func TestDetectFromEnvironmentOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		env  map[string]string
		want string // "" = not detected
	}{
		{"unreadable payload, cursor env", "not json", map[string]string{"CURSOR_VERSION": "2", "CLAUDE_PROJECT_DIR": "/p"}, "cursor"},
		{"empty payload, gemini env", "", map[string]string{"GEMINI_SESSION_ID": "g", "CLAUDE_PROJECT_DIR": "/p"}, "gemini"},
		{"empty object, copilot env", "{}", map[string]string{"COPILOT_CLI": "1"}, "copilot"},
		{"empty object, copilot vscode env", "{}", map[string]string{"AI_AGENT": "github_copilot_vscode_agent"}, "copilot"},
		{"empty object, codex env", "{}", map[string]string{"CODEX_THREAD_ID": "t"}, "codex"},
		{"empty object, claude env", "{}", map[string]string{"CLAUDECODE": "1"}, "claude"},
		{"project dir alias alone", "{}", map[string]string{"CLAUDE_PROJECT_DIR": "/p"}, "claude"},
		{"two agents' markers: refuse to guess", "{}", map[string]string{"CLAUDECODE": "1", "CODEX_THREAD_ID": "t"}, ""},
		{"nothing at all", "{}", nil, ""},
		{"no event, no env", `{"session_id":"s"}`, nil, ""},
		{"unknown pascal event", `{"hook_event_name":"TotallyNew","session_id":"s"}`, nil, ""},
		{"unknown camel event", `{"hook_event_name":"totallyNew"}`, nil, ""},
		{"array payload", `[1,2,3]`, nil, ""},
	} {
		d, ok := Detect([]byte(tc.in), tc.env)
		got := ""
		if ok {
			got = d.ID()
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
		if ok != (d != nil) {
			t.Errorf("%s: ok=%v but dialect=%v", tc.name, ok, d)
		}
	}
}

// Oversized and over-nested payloads are still attributed, from the
// salvaged top-level fields.
func TestDetectOversized(t *testing.T) {
	big := []byte(`{"session_id":"s","turn_id":"t","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` +
		strings.Repeat("A", MaxInput) + `"}}`)
	d, ok := Detect(big, nil)
	if !ok || d.ID() != "codex" {
		t.Fatalf("oversized codex payload: got %v", d)
	}
	deep := []byte(`{"conversation_id":"c","generation_id":"g","hook_event_name":"preToolUse","tool_input":` +
		strings.Repeat("[", MaxDepth+5) + strings.Repeat("]", MaxDepth+5) + `}`)
	d, ok = Detect(deep, nil)
	if !ok || d.ID() != "cursor" {
		t.Fatalf("over-nested cursor payload: got %v", d)
	}
}

func TestDetectNeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil, {}, []byte("{"), []byte(`{"hook_event_name":`), []byte(`{"hook_event_name":5}`),
		[]byte(`{"hook_event_name":{"a":1},"session_id":[1]}`), bytes.Repeat([]byte("["), 1<<16),
		[]byte("\xff\xfe\x00"), []byte(`{"hook_event_name":"\ud800"}`),
	}
	for _, in := range inputs {
		Detect(in, nil)
		Detect(in, map[string]string{"CLAUDECODE": "1"})
	}
}
