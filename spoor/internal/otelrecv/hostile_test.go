package otelrecv

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// The OTLP specification's own example request: a valid export from a
// sender that is not an agent. It must convert to nothing, without error.
func TestSpecExampleFromUnknownSender(t *testing.T) {
	body, err := os.ReadFile("testdata/otlp_spec_example.json")
	if err != nil {
		t.Fatal(err)
	}
	res := mustConvert(t, body)
	eq(t, "records", res.Records, 1)
	eq(t, "events", len(res.Events), 0)
	if len(res.Unknown) != 1 {
		t.Errorf("unknown = %v", res.Unknown)
	}
	evs, err := Convert(body)
	if err != nil || len(evs) != 0 {
		t.Errorf("Convert = %v, %v", evs, err)
	}
}

func TestSpecExampleAttributeTypes(t *testing.T) {
	body, _ := os.ReadFile("testdata/otlp_spec_example.json")
	req, err := decodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	lr := req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	a := decodeAttrs(lr.Attributes, 0)
	eq(t, "string", a.str("string.attribute"), "some string")
	if b, ok := a.boolean("boolean.attribute"); !ok || !b {
		t.Error("boolean.attribute")
	}
	if n, ok := a.integer("int.attribute"); !ok || n != 10 {
		t.Errorf("int.attribute = %d %v", n, ok)
	}
	if f, ok := a["double.attribute"].(float64); !ok || f != 637.704 {
		t.Errorf("double.attribute = %v", a["double.attribute"])
	}
	if got := a.names("array.attribute"); len(got) != 2 || got[0] != "many" {
		t.Errorf("array.attribute = %v", got)
	}
	if m, ok := a["map.attribute"].(attrs); !ok || m.str("some.map.key") != "some value" {
		t.Errorf("map.attribute = %#v", a["map.attribute"])
	}
	ts, ok := nanoTime(lr.TimeUnixNano)
	if !ok || ts.Year() != 2018 {
		t.Errorf("time = %v %v", ts, ok)
	}
}

func TestMalformedBodies(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"whitespace":      " \n\t",
		"not json":        "resourceLogs=1",
		"array":           `[{"resourceLogs":[]}]`,
		"string":          `"hello"`,
		"truncated":       `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"claude_code.tool_res`,
		"wrong top type":  `{"resourceLogs":"nope"}`,
		"wrong mid type":  `{"resourceLogs":[{"scopeLogs":{"logRecords":[]}}]}`,
		"other signal":    `{"resourceSpans":[{"scopeSpans":[]}]}`,
		"trailing junk":   `{"resourceLogs":[]} {"resourceLogs":[]}`,
		"nul bytes":       "{\"resourceLogs\":[]}\x00\x00",
		"protobuf-ish":    "\x0a\x9c\x01\x0a\x25\x0a\x23\x0a\x0cservice.name\x12\x13",
		"invalid utf8":    "{\"resourceLogs\":\xff\xfe}",
		"number overflow": `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":{"a":1}}]}]}], "x":1e999}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			evs, err := Convert([]byte(body))
			if name == "number overflow" {
				// The unknown member is skipped; the odd timestamp reads as missing.
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error, events=%d", len(evs))
			}
			if len(evs) != 0 {
				t.Errorf("events returned with an error")
			}
			// Error text goes back to the sender: it must not echo the body.
			if len(err.Error()) > 200 || strings.ContainsAny(err.Error(), "\x00\xff") {
				t.Errorf("error text not bounded/clean: %q", err.Error())
			}
		})
	}
}

func TestEmptyExportsAreValid(t *testing.T) {
	for _, body := range []string{`{}`, `{"resourceLogs":[]}`, `{"resourceLogs":null}`, "\xef\xbb\xbf{\"resource_logs\":[]}",
		`{"resourceLogs":[{}]}`, `{"resourceLogs":[{"scopeLogs":[{"logRecords":[]}]}]}`} {
		res, err := ConvertDetail([]byte(body))
		if err != nil || len(res.Events) != 0 || res.Records != 0 {
			t.Errorf("%q: %v %+v", body, err, res)
		}
	}
}

func TestTooLarge(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxConvertBytes+1)
	if _, err := Convert(big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestDeepNestingDoesNotPanic(t *testing.T) {
	// 1. An AnyValue nested far beyond the cap: the attribute is dropped.
	deep := strings.Repeat(`{"kvlistValue":{"values":[{"key":"k","value":`, 500) + `{"stringValue":"x"}` + strings.Repeat(`}]}}`, 500)
	body := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},` +
		`"scopeLogs":[{"logRecords":[{"timeUnixNano":"1794417000000000000","body":{"stringValue":"claude_code.tool_result"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_result"}},{"key":"tool_name","value":{"stringValue":"Bash"}},` +
		`{"key":"deep","value":` + deep + `}]}]}]}]}`
	res, err := convert([]byte(body), fixedNow)
	if err != nil || len(res.Events) != 1 {
		t.Fatalf("err=%v events=%v", err, res)
	}
	// 2. JSON nested beyond what encoding/json accepts: an error, not a crash.
	bomb := `{"resourceLogs":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`
	if _, err := Convert([]byte(bomb)); err == nil {
		t.Error("200k-deep array accepted")
	}
	// 3. A deeply nested document inside tool_input: kept as raw text only.
	nested := strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000)
	ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{"tool_name": "Bash", "tool_input": nested, "tool_parameters": nested})))
	if _, ok := ev.Content.ToolInput["_raw"].(string); !ok || len(ev.Content.ToolInput) != 1 {
		t.Errorf("over-nested arguments were decoded: %d keys", len(ev.Content.ToolInput))
	}
	if !depthWithin(`{"a":"}}}}{{{{[[[[","b":[1,{"c":"\"]"}]}`, 3) || depthWithin(`[[[[1]]]]`, 3) {
		t.Error("depthWithin")
	}
}

func TestHostileFieldValues(t *testing.T) {
	long := strings.Repeat("A", 5000)
	ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_decision", kv{
		"tool_name":          long,
		"tool_use_id":        "toolu_\x00\x1b[31m‮evil\nid",
		"session.id":         "sess\r\n{\"kind\":\"detection\"}",
		"decision":           "accept",
		"source":             "config\n\"injected\": true",
		"tool_source":        "<script>alert(1)</script>",
		"classifier_verdict": strings.Repeat("x", 4000),
		"permission_mode":    "plan; rm -rf /",
		"user.email":         "a@b@evil.example\n",
		"app.version":        strings.Repeat("9", 300),
	})))
	if len(ev.Tool.Name) != maxName {
		t.Errorf("tool name len = %d", len(ev.Tool.Name))
	}
	want := map[string]bool{"tool.name": true, "agent.version": true}
	for _, f := range ev.Truncated {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Errorf("truncations not recorded: missing %v in %v", want, ev.Truncated)
	}
	eq(t, "use id", ev.Tool.UseID, "toolu_[31mevilid")
	eq(t, "session", ev.Session.ID, `sess{"kind":"detection"}`)
	if len(ev.Labels["classifier_verdict"]) > maxLabel {
		t.Error("label not capped")
	}
	eq(t, "mode token", ev.Session.PermissionMode, "plan__rm__rf__")
	line := wire(t, ev)
	if strings.Count(line, "\n") != 1 || strings.Contains(line, "<script>") || strings.Contains(line, `"injected"`) {
		t.Errorf("unsafe line: %s", line)
	}
	// One line, one object, and the forged kind did not escape its string.
	var back map[string]any
	if err := json.Unmarshal([]byte(line), &back); err != nil || back["kind"] != "activity" {
		t.Errorf("round trip: %v kind=%v", err, back["kind"])
	}
}

func TestInvalidUTF8IsRepaired(t *testing.T) {
	// encoding/json replaces invalid UTF-8 in strings; make sure nothing
	// downstream reintroduces it and the line stays valid.
	body := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"1794417000000000000","body":{"stringValue":"claude_code.tool_result"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_result"}},` +
		`{"key":"tool_name","value":{"stringValue":"Ba` + "\xff\xfe" + `sh"}},` +
		`{"key":"session.id","value":{"stringValue":"` + "\xc3\x28" + `"}}]}]}]}]}`)
	res, err := convert(body, fixedNow)
	if err != nil || len(res.Events) != 1 {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	ev := res.Events[0]
	if !utf8.ValidString(ev.Tool.Name) || !utf8.ValidString(ev.Session.ID) {
		t.Errorf("invalid UTF-8 kept: %q %q", ev.Tool.Name, ev.Session.ID)
	}
	checkInvariants(t, ev)
}

func TestWrongAttributeTypes(t *testing.T) {
	// Every attribute has an unexpected type, some AnyValues are malformed.
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
		"tool_name":        []string{"Bash"},
		"tool_use_id":      12345,
		"success":          1.5,
		"duration_ms":      "not a number",
		"tool_parameters":  true,
		"tool_input":       kv{"command": "ls"},
		"decision_source":  7,
		"error_type":       raw(`{"bytesValue":"AAEC"}`),
		"error":            raw(`{"stringValue":42}`),
		"mcp_server_scope": raw(`{"intValue":"99999999999999999999999"}`),
		"odd":              raw(`{"nopeValue":1}`),
		"two":              raw(`{"intValue":"5","stringValue":"first wins"}`),
	})))
	eq(t, "type", ev.Type, event.TypeToolPost)
	eq(t, "name", ev.Tool.Name, "")
	eq(t, "use id from number", ev.Tool.UseID, "12345")
	eq(t, "status", ev.Outcome.Status, "unknown")
	eq(t, "duration", ev.Outcome.DurationMS, int64(0))
	if ev.Target != nil {
		t.Errorf("target from a non-string tool_input: %+v", ev.Target)
	}
}

func TestDuplicateAttributeFirstWins(t *testing.T) {
	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"1794417000000000000","body":{"stringValue":"claude_code.tool_decision"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"tool_decision"}},` +
		`{"key":"decision","value":{"stringValue":"reject"}},` +
		`{"key":"decision","value":{"stringValue":"accept"}},` +
		`{"key":"tool_name","value":{"stringValue":"Bash"}}]}]}]}]}`
	ev := one(t, []byte(body))
	eq(t, "decision", ev.Outcome.Decision, "deny")
}

func TestCapsOnCounts(t *testing.T) {
	t.Run("records per request", func(t *testing.T) {
		recs := make([]map[string]any, 0, MaxRecords+7)
		for i := 0; i < MaxRecords+7; i++ {
			recs = append(recs, logRec(baseNano+int64(i), "claude_code.tool_result",
				kv{"event.name": "tool_result", "tool_name": "Bash", "event.sequence": i}))
		}
		res := mustConvert(t, otlpBody(claudeRes, "", recs...))
		eq(t, "records", res.Records, MaxRecords+7)
		eq(t, "events", len(res.Events), MaxRecords)
		eq(t, "dropped", res.Dropped, 7)
		seen := map[string]bool{}
		for _, ev := range res.Events {
			seen[ev.ID] = true
		}
		eq(t, "unique ids", len(seen), MaxRecords)
	})
	t.Run("attributes per record", func(t *testing.T) {
		a := kv{"event.name": "tool_result", "tool_name": "Bash"}
		for i := 0; i < 2000; i++ {
			a["pad."+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)] = "v"
		}
		req, err := decodeRequest(otlpBody(claudeRes, "", logRec(baseNano, "claude_code.tool_result", a)))
		if err != nil {
			t.Fatal(err)
		}
		got := decodeAttrs(req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes, 0)
		if len(got) > maxAttrs {
			t.Errorf("attrs = %d", len(got))
		}
	})
	t.Run("unknown names", func(t *testing.T) {
		recs := make([]map[string]any, 0, 300)
		for i := 0; i < 300; i++ {
			recs = append(recs, claudeRec("novel_"+strings.Repeat("z", i%150)+string(rune('a'+i%26)), kv{}))
		}
		res := mustConvert(t, otlpBody(claudeRes, "", recs...))
		if len(res.Unknown) > maxUnknownNames+1 {
			t.Errorf("unknown names = %d", len(res.Unknown))
		}
		total := 0
		for _, n := range res.Unknown {
			total += n
		}
		eq(t, "total unknown", total, 300)
	})
	t.Run("list label", func(t *testing.T) {
		names := make([]string, 400)
		for i := range names {
			names[i] = "server-" + strings.Repeat("n", 20) + string(rune('a'+i%26))
		}
		ev := one(t, otlpBody(codexRes, "", codexRec("conversation_starts", kv{"mcp_servers": strings.Join(names, ", ")})))
		v := ev.Labels["mcp_servers"]
		if len(v) > maxList || !strings.Contains(v, ",+") {
			t.Errorf("list label len=%d %q", len(v), v[max(0, len(v)-20):])
		}
	})
}

func TestTimestampSources(t *testing.T) {
	attrsOnly := kv{"event.name": "tool_result", "tool_name": "Bash", "event.timestamp": "2026-11-11T17:20:00.123Z"}
	t.Run("event.timestamp attribute", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", logRec(0, "claude_code.tool_result", attrsOnly)))
		eq(t, "ts", ev.TS.String(), "2026-11-11T17:20:00.123000Z")
		if _, ok := ev.Labels["ts_source"]; ok {
			t.Error("ts_source set for an agent-stamped record")
		}
	})
	t.Run("observed time", func(t *testing.T) {
		r := logRec(0, "claude_code.tool_result", kv{"event.name": "tool_result", "tool_name": "Bash"})
		r["observedTimeUnixNano"] = "1794417005000000000"
		ev := one(t, otlpBody(claudeRes, "", r))
		eq(t, "ts", ev.TS.String(), "2026-11-11T17:10:05.000000Z")
	})
	t.Run("nothing usable", func(t *testing.T) {
		for _, nano := range []string{"0", "12", "99999999999999999999", `"abc"`} {
			r := logRec(0, "claude_code.tool_result", kv{"event.name": "tool_result", "tool_name": "Bash", "event.timestamp": "yesterday"})
			r["timeUnixNano"] = json.RawMessage(nano)
			ev := one(t, otlpBody(claudeRes, "", r))
			if !ev.TS.Time.Equal(fixedNow()) {
				t.Errorf("nano=%s ts=%v", nano, ev.TS)
			}
			eq(t, "ts_source", ev.Labels["ts_source"], "sensor")
		}
	})
	t.Run("number and snake case spellings", func(t *testing.T) {
		body := `{"resource_logs":[{"resource":{"attributes":[{"key":"service.name","value":{"string_value":"codex-cli"}}]},` +
			`"scope_logs":[{"log_records":[{"time_unix_nano":1794417000000000000,"attributes":[` +
			`{"key":"event.name","value":{"string_value":"codex.user_prompt"}},` +
			`{"key":"conversation.id","value":{"string_value":"c-1"}},` +
			`{"key":"prompt_length","value":{"int_value":9}}]}]}]}]}`
		ev := one(t, []byte(body))
		eq(t, "agent", ev.Agent.ID, "codex")
		eq(t, "len", ev.Prompt.Len, 9)
		if ev.TS.Time.Year() != 2026 {
			t.Errorf("ts = %v", ev.TS)
		}
	})
	if _, ok := parseStamp("2026-11-11T17:20:00+02:00"); !ok {
		t.Error("offset timestamps must parse")
	}
	if _, ok := nanoTime(flexUint(time.Date(1971, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())); ok {
		t.Error("1971 accepted")
	}
}

// FuzzConvert checks the two properties that matter for a network-facing
// parser: it never panics, and whatever it emits is a valid event line.
func FuzzConvert(f *testing.F) {
	for _, name := range []string{"testdata/claude_tool_result.json", "testdata/otlp_spec_example.json"} {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
	f.Add(otlpBody(geminiRes, "", geminiRec("tool_call", "", kv{"function_name": "run_shell_command",
		"function_args": `{"command":"id"}`, "decision": "accept", "success": true})))
	f.Add(otlpBody(codexRes, "", codexRec("tool_result", kv{"tool_name": "shell", "arguments": `{"command":["ls"]}`, "success": "true"})))
	f.Add([]byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"arrayValue":{"values":[{"kvlistValue":{}}]}}}]}]}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		res, err := convert(body, fixedNow)
		if err != nil {
			return
		}
		for _, ev := range res.Events {
			line, err := ev.MarshalLine()
			if err != nil || !json.Valid(line) {
				t.Fatalf("bad line: %v %q", err, line)
			}
			if ev.Source != event.SourceOTel || ev.Kind != event.KindActivity || ev.ID == "" {
				t.Fatalf("bad envelope: %+v", ev)
			}
		}
	})
}
