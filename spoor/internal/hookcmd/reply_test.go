package hookcmd

import (
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/hookio"
)

func TestValidReply(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 2000) + "1" + strings.Repeat("}", 2000)
	cases := []struct {
		name, in string
		ok, empty bool
	}{
		{"empty", "", true, true},
		{"whitespace", " \n\t\r\n", true, true},
		{"object", `{"hookSpecificOutput":{"permissionDecision":"deny"}}` + "\n", true, false},
		{"object with spaces", "  {\"a\":1}  \n", true, false},
		{"partial", `{"hookSpecificOutput":{"permissionDecision":"de`, false, false},
		{"prefix closed early", `{"a":{"b":1}`, false, false},
		{"two objects", `{"a":1}{"b":2}`, false, false},
		{"two lines", "{\"a\":1}\n{\"b\":2}\n", false, false},
		{"trailing garbage", `{"a":1} x`, false, false},
		{"array", `[{"a":1}]`, false, false},
		{"string", `"deny"`, false, false},
		{"number", `2`, false, false},
		{"go panic text", "panic: boom\n\ngoroutine 1 [running]:\n", false, false},
		{"too big", `{"a":"` + strings.Repeat("x", MaxReply) + `"}`, false, false},
		{"deep but small", deep, true, false},
		{"invalid utf8 inside", "{\"a\":\"\xff\"}", false, false},
	}
	for _, c := range cases {
		r, ok := validReply([]byte(c.in), MaxReply)
		if ok != c.ok || (ok && (len(r) == 0) != c.empty) {
			t.Errorf("%s: ok=%v len=%d, want ok=%v empty=%v", c.name, ok, len(r), c.ok, c.empty)
		}
		if ok && len(r) > 0 && r[len(r)-1] != '\n' {
			t.Errorf("%s: reply not newline-terminated", c.name)
		}
	}
}

func TestTopLevelStrings(t *testing.T) {
	cases := []struct {
		name, in string
		want     map[string]string
	}{
		{"plain", `{"hook_event_name":"PreToolUse","session_id":"s1"}`, map[string]string{"hook_event_name": "PreToolUse", "session_id": "s1"}},
		{"nested key ignored", `{"tool_input":{"hook_event_name":"Stop"},"x":1}`, map[string]string{}},
		{"nested array ignored", `{"a":[{"hook_event_name":"Stop"}],"hook_event_name":"PreToolUse"}`, map[string]string{"hook_event_name": "PreToolUse"}},
		{"escapes", `{"hook_event_name":"PreToolUse","s\"k":"v"}`, map[string]string{"hook_event_name": "PreToolUse"}},
		{"braces in strings", `{"a":"}{[","b":{"c":"}}}"},"hook_event_name":"X"}`, map[string]string{"hook_event_name": "X"}},
		{"last wins", `{"hook_event_name":"A","hook_event_name":"B"}`, map[string]string{"hook_event_name": "B"}},
		{"non-string value", `{"hook_event_name":42}`, map[string]string{}},
		{"truncated", `{"session_id":"s1","hook_event_name":"Pre`, map[string]string{"session_id": "s1"}},
		{"bom", "\xef\xbb\xbf{\"hook_event_name\":\"Stop\"}", map[string]string{"hook_event_name": "Stop"}},
		{"not an object", `["hook_event_name","x"]`, map[string]string{}},
		{"garbage", "\x00\x01{{{", map[string]string{}},
		{"huge nesting", `{"a":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `,"hook_event_name":"Deep"}`, map[string]string{"hook_event_name": "Deep"}},
		{"unterminated nesting", `{"a":` + strings.Repeat("[", 200000), map[string]string{}},
		{"oversize value skipped", `{"hook_event_name":"` + strings.Repeat("x", 5000) + `"}`, map[string]string{}},
	}
	for _, c := range cases {
		start := time.Now()
		got := topLevelStrings([]byte(c.in), "hook_event_name", "session_id")
		if time.Since(start) > time.Second {
			t.Errorf("%s: slow", c.name)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s=%q want %q", c.name, k, got[k], v)
			}
		}
	}
}

func TestEventNameAndFallbackRequest(t *testing.T) {
	get := func(k string) string {
		if k == hookio.EnvHookEvent {
			return "preToolUse"
		}
		return ""
	}
	if n := eventNameOf([]byte(`{"hook_event_name":"PreToolUse"}`), "", get); n != "PreToolUse" {
		t.Fatalf("payload name: %q", n)
	}
	if n := eventNameOf([]byte(`{"toolName":"bash"}`), "", get); n != "preToolUse" {
		t.Fatalf("env name: %q", n)
	}
	if n := eventNameOf([]byte(`{"toolName":"bash"}`), "PreToolUse", get); n != "PreToolUse" {
		t.Fatalf("flag name: %q", n)
	}
	if n := eventNameOf([]byte(`{"hook_event_name":"Pre ToolUse\n"}`), "", nil); n != "" {
		t.Fatalf("free text accepted as an event name: %q", n)
	}
	copilot, _ := hookio.Get("copilot")
	if r := fallbackRequest(copilot, "preToolUse"); r == nil || !r.Blocking || r.AgentID != "copilot-cli" {
		t.Fatalf("copilot camelCase: %+v", r)
	}
	claude, _ := hookio.Get("claude")
	if r := fallbackRequest(claude, "PostToolUse"); r == nil || r.Blocking {
		t.Fatalf("PostToolUse must not be blocking: %+v", r)
	}
	if fallbackRequest(nil, "PreToolUse") != nil || fallbackRequest(claude, "") != nil {
		t.Fatal("nil dialect or empty name must give no request")
	}
}

func TestReplyCarries(t *testing.T) {
	cases := []struct {
		reply, action string
		want          bool
	}{
		{`{"hookSpecificOutput":{"permissionDecision":"deny"}}`, "deny", true},
		{`{"hookSpecificOutput":{"permissionDecision":"ask"}}`, "ask", true},
		{`{"hookSpecificOutput":{"permissionDecision":"ask"}}`, "deny", false},
		{`{"hookSpecificOutput":{"decision":{"behavior":"deny"}}}`, "deny", true},
		{`{"decision":"block","reason":"r"}`, "deny", true},
		{`{"decision":"deny","reason":"r"}`, "deny", true},
		{`{"permission":"ask"}`, "ask", true},
		{`{"continue":false,"user_message":"r"}`, "deny", true},
		{`{"behavior":"deny"}`, "deny", true},
		{`{"systemMessage":"spoor: r"}`, "ask", false},
		{`{"systemMessage":"spoor: r"}`, "deny", false},
		{``, "deny", false},
		{`not json`, "deny", false},
	}
	for _, c := range cases {
		if got := replyCarries([]byte(c.reply), c.action); got != c.want {
			t.Errorf("%s %s: %v", c.reply, c.action, got)
		}
	}
}

func TestParseArgs(t *testing.T) {
	o := parseArgs([]string{"--agent", "codex", "--config=/etc/x.yaml", "-event", "PreToolUse", "--unknown", "v", "positional", "--worker", "--ppid", "42", "--t0", "1700000000000000000", "--deadline", "nope"})
	if o.agent != "codex" || o.config != "/etc/x.yaml" || o.event != "PreToolUse" || !o.worker || o.ppid != 42 || o.t0.UnixNano() != 1700000000000000000 || !o.deadline.IsZero() {
		t.Fatalf("%+v", o)
	}
	if o := parseArgs([]string{"--agent"}); o.agent != "" {
		t.Fatalf("dangling flag: %+v", o)
	}
}

func TestHardDeadline(t *testing.T) {
	c := config.Default("/d")
	if d := hardDeadline(c, mode{enabled: true}); d != observeDeadline {
		t.Fatalf("observe %v", d)
	}
	g := mode{enabled: true, guard: true}
	c.Guard.Deadline = config.Duration(10 * time.Millisecond)
	if d := hardDeadline(c, g); d != MinGuardDeadline {
		t.Fatalf("floor %v", d)
	}
	c.Guard.Deadline = config.Duration(250 * time.Millisecond)
	if d := hardDeadline(c, g); d != 250*time.Millisecond {
		t.Fatalf("configured %v", d)
	}
	c.Guard.Deadline = config.Duration(time.Hour)
	if d := hardDeadline(c, g); d != maxGuardDeadline {
		t.Fatalf("cap %v", d)
	}
}

func TestSuppressionsFromConfig(t *testing.T) {
	sup, degraded := suppressions([]config.Suppression{
		{Rule: "SPR-A-*", Expires: "2027-01-02"},
		{Rule: "SPR-B-001", Expires: "2027-01-02T03:04:05Z"},
		{Rule: "SPR-C-001"},
		{Rule: "SPR-D-001", Expires: "next tuesday"},
	})
	if !degraded || len(sup) != 3 || !sup[0].Expires.Equal(time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)) || !sup[2].Expires.IsZero() {
		t.Fatalf("%v %+v", degraded, sup)
	}
}

func TestTokenAndCleanID(t *testing.T) {
	if token("PreToolUse", 64) != "PreToolUse" || token("a b", 64) != "other" || token(strings.Repeat("a", 65), 64) != "other" || token("", 64) != "" {
		t.Fatal("token")
	}
	if s, cut := cleanID("ab\x00c​d\xff", 10); s != "abcd" || cut {
		t.Fatalf("cleanID %q %v", s, cut)
	}
	if s, cut := cleanID("ééééé", 3); s != "é" || !cut {
		t.Fatalf("cleanID cut %q %v", s, cut)
	}
}
