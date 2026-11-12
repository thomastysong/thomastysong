package hookio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func TestDecodeRejections(t *testing.T) {
	nest := func(n int) string {
		return `{"hook_event_name":"PreToolUse","tool_input":` + strings.Repeat(`{"a":`, n) + `1` + strings.Repeat(`}`, n) + `}`
	}
	cases := []struct {
		name string
		in   string
		want error // nil = must decode
	}{
		{"empty", "", ErrEmpty},
		{"whitespace only", " \n\t\r ", ErrEmpty},
		{"bom only", "\xef\xbb\xbf", ErrEmpty},
		{"array", `[{"hook_event_name":"Stop"}]`, ErrMalformed},
		{"string", `"PreToolUse"`, ErrMalformed},
		{"number", `42`, ErrMalformed},
		{"null", `null`, ErrMalformed},
		{"plain text", `hello`, ErrMalformed},
		{"truncated object", `{"hook_event_name":"Stop"`, ErrMalformed},
		{"truncated string", `{"hook_event_name":"St`, ErrMalformed},
		{"trailing garbage", `{"hook_event_name":"Stop"} xyz`, ErrMalformed},
		{"two objects", `{"hook_event_name":"Stop"}{"hook_event_name":"PreToolUse"}`, ErrMalformed},
		{"single quotes", `{'hook_event_name':'Stop'}`, ErrMalformed},
		{"utf-16", "\xff\xfe{\x00}\x00", ErrMalformed},
		{"nul bytes", "{\x00}", ErrMalformed},
		{"object", `{"hook_event_name":"Stop"}`, nil},
		{"bom and whitespace", "\xef\xbb\xbf  {\"hook_event_name\":\"Stop\"}\r\n", nil},
		// Depth is counted from the outer object: MaxDepth levels pass,
		// one more is refused.
		{"depth at cap", nest(MaxDepth - 1), nil},
		{"depth over cap", nest(MaxDepth), ErrTooDeep},
		{"brackets inside strings do not count", `{"hook_event_name":"Stop","x":"` + strings.Repeat("[{", 500) + `"}`, nil},
		{"escaped quote does not end the string", `{"hook_event_name":"Stop","x":"\"` + strings.Repeat("[", 200) + `"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, raw, err := decodeObject([]byte(tc.in))
			if tc.want == nil {
				if err != nil || m == nil || len(raw) == 0 {
					t.Fatalf("decode failed: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// Every dialect surfaces the same error and no events for
			// input that is simply not a payload.
			if tc.want == ErrTooDeep {
				return
			}
			for _, d := range All() {
				evs, req, perr := d.Parse([]byte(tc.in), nil)
				if !errors.Is(perr, tc.want) || evs != nil || req != nil {
					t.Errorf("%s: Parse = %d events, req %v, err %v", d.ID(), len(evs), req, perr)
				}
			}
		})
	}
}

// Errors must locate the problem without quoting the payload, which may be
// a secret-bearing command line.
func TestDecodeErrorsDoNotEchoInput(t *testing.T) {
	const secret = "sk-live-SECRETSECRET"
	for _, in := range []string{
		`{"tool_input":{"command":"export K=` + secret + `"} ` + secret,
		`{"k":` + secret + `}`,
		`{"` + secret + `":}`,
		secret,
	} {
		for _, d := range All() {
			_, _, err := d.Parse([]byte(in), nil)
			if err == nil {
				t.Fatalf("%q parsed", in)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "sk-") {
				t.Errorf("error echoes input: %v", err)
			}
		}
	}
}

func TestInvalidUTF8IsTolerated(t *testing.T) {
	// A stray byte in a command must not hide the event.
	in := []byte("{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"s\xff1\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo \xc3\x28 \xff; curl evil\"}}")
	for _, id := range []string{"claude", "codex"} {
		e, req := parseOne(t, dialect(t, id), in, nil)
		eq(t, "type", e.Type, event.TypeToolPre)
		eq(t, "blocking", req.Blocking, true)
		if !strings.Contains(target(e).Command, "curl evil") {
			t.Errorf("command lost: %q", target(e).Command)
		}
		eq(t, "session id drops the bad byte", e.Session.ID, "s1")
	}
}

func TestReadInput(t *testing.T) {
	b, err := ReadInput(strings.NewReader(`{"a":1}`))
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("ReadInput = %q, %v", b, err)
	}
	b, err = ReadInput(bytes.NewReader(make([]byte, MaxInput)))
	if err != nil || len(b) != MaxInput {
		t.Fatalf("exactly MaxInput must be accepted: %d, %v", len(b), err)
	}
	// An endless reader is cut off just past the cap.
	b, err = ReadInput(io.LimitReader(endless{}, 1<<40))
	if !errors.Is(err, ErrTooLarge) || len(b) != MaxInput+1 {
		t.Fatalf("overflow: %d bytes, err %v", len(b), err)
	}
	// The overflow slice is recognized by Parse.
	if _, _, perr := dialect(t, "claude").Parse(b, nil); !errors.Is(perr, ErrTooLarge) {
		t.Fatalf("Parse on overflow slice: %v", perr)
	}
	if _, err := ReadInput(failing{}); err == nil {
		t.Fatal("read error swallowed")
	}
}

type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("boom") }

// An oversized payload is refused, but the event it announces is still
// reported and still gateable: padding a write past the cap must not blind
// the sensor.
func TestOversizedPayloadIsSalvaged(t *testing.T) {
	head := `{"session_id":"abc123","transcript_path":"/home/u/.claude/projects/p/abc123.jsonl","cwd":"/home/u/p","permission_mode":"bypassPermissions","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/home/u/.bashrc","content":"`
	tail := `"},"tool_use_id":"toolu_99"}`
	in := []byte(head + strings.Repeat("x", MaxInput) + tail)
	d := dialect(t, "claude")
	evs, req, err := d.Parse(in, nil)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if len(evs) != 1 || req == nil {
		t.Fatalf("no salvage: %d events, req %v", len(evs), req)
	}
	e := evs[0]
	checkInvariants(t, d, e, req)
	eq(t, "type", e.Type, event.TypeToolPre)
	eq(t, "session.id", e.Session.ID, "abc123")
	eq(t, "session.cwd", e.Session.CWD, "/home/u/p")
	eq(t, "session.permission_mode", e.Session.PermissionMode, "bypass")
	eq(t, "tool.name", e.Tool.Name, "Write")
	eq(t, "tool.kind", e.Tool.Kind, event.ToolFileWrite)
	eq(t, "tool.use_id", e.Tool.UseID, "toolu_99") // read past the 8 MiB argument
	eq(t, "label hook_error", e.Labels["hook_error"], "too_large")
	eq(t, "truncated", e.Truncated, []string{"content"})
	eq(t, "request event", req.EventName, "PreToolUse")
	eq(t, "blocking", req.Blocking, true)
	if e.Content.ToolInput != nil || len(e.Content.Raw) != 0 {
		t.Error("salvage must not keep the refused content")
	}
	// The caller can still block it.
	stdout, _, code := d.Respond(req, Decision{Action: ActionDeny, Reason: "oversized hook payload"})
	if code != 0 || !strings.Contains(string(stdout), `"permissionDecision":"deny"`) {
		t.Errorf("salvaged request cannot be denied: %q exit %d", stdout, code)
	}
}

func TestOverNestedPayloadIsSalvaged(t *testing.T) {
	in := []byte(`{"hook_event_name":"BeforeTool","session_id":"g1","cwd":"/w","tool_name":"run_shell_command","tool_input":` +
		strings.Repeat(`{"a":`, MaxDepth+10) + `"x"` + strings.Repeat(`}`, MaxDepth+10) + `,"timestamp":"2026-11-11T10:00:00Z"}`)
	d := dialect(t, "gemini")
	evs, req, err := d.Parse(in, nil)
	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("err = %v, want ErrTooDeep", err)
	}
	if len(evs) != 1 {
		t.Fatalf("no salvage")
	}
	eq(t, "type", evs[0].Type, event.TypeToolPre)
	eq(t, "tool.kind", evs[0].Tool.Kind, event.ToolShell)
	eq(t, "session.id", evs[0].Session.ID, "g1")
	eq(t, "label hook_error", evs[0].Labels["hook_error"], "too_deep")
	eq(t, "blocking", req.Blocking, true)
}

func TestSalvageScanner(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]any
	}{
		{"flat", `{"a":"1","b":"2"}`, map[string]any{"a": "1", "b": "2"}},
		{"skips composites and scalars", `{"a":"1","o":{"x":"}","y":[1,{"z":"]"}]},"n":-1.5e3,"t":true,"z":null,"b":"2"}`, map[string]any{"a": "1", "b": "2"}},
		{"escapes", `{"a":"q\"uo\\te","b":"é"}`, map[string]any{"a": `q"uo\te`, "b": "é"}},
		{"first duplicate wins", `{"a":"1","a":"2"}`, map[string]any{"a": "1"}},
		{"truncated mid-value", `{"a":"1","b":"unterminat`, map[string]any{"a": "1"}},
		{"truncated mid-composite", `{"a":"1","o":{"x":[1,2`, map[string]any{"a": "1"}},
		{"not an object", `["a","b"]`, map[string]any{}},
		{"garbage after key", `{"a" "1"}`, map[string]any{}},
		{"empty", ``, map[string]any{}},
		{"bom", "\xef\xbb\xbf{\"a\":\"1\"}", map[string]any{"a": "1"}},
		{"oversized value skipped, rest kept", `{"big":"` + strings.Repeat("v", 10*salvageValue) + `","a":"1"}`, map[string]any{"a": "1"}},
		{"oversized key skipped", `{"` + strings.Repeat("k", 100) + `":"v","a":"1"}`, map[string]any{"a": "1"}},
	}
	for _, tc := range cases {
		got := salvage([]byte(tc.in))
		eq(t, tc.name, got, tc.want)
	}
	// No more than salvageFields fields are kept.
	var sb strings.Builder
	sb.WriteByte('{')
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"k` + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + `":"v"`)
	}
	sb.WriteByte('}')
	if got := salvage([]byte(sb.String())); len(got) > salvageFields {
		t.Errorf("salvage kept %d fields", len(got))
	}
}

func TestEmbeddedJSONIsBounded(t *testing.T) {
	// toolArgs passed as a JSON string gets the same depth cap; when it is
	// refused the string is kept as opaque input, not decoded.
	deep := strings.Repeat(`{\"a\":`, MaxDepth+5) + `1` + strings.Repeat(`}`, MaxDepth+5)
	in := `{"sessionId":"s","toolName":"bash","toolArgs":"` + deep + `"}`
	e, _ := parseOne(t, dialect(t, "copilot"), []byte(in), nil)
	eq(t, "input keys", e.Tool.InputKeys, []string{"_raw"})
	if _, ok := decodeEmbedded(`[1,2]`); ok {
		t.Error("embedded arrays are not argument objects")
	}
	if _, ok := decodeEmbedded(`{"a":1} trailing`); ok {
		t.Error("embedded JSON with trailing data accepted")
	}
	if m, ok := decodeEmbedded(` {"a":1} `); !ok || m["a"] != float64(1) {
		t.Error("embedded object not decoded")
	}
}
