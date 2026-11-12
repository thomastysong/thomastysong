package otelrecv

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// kv is an attribute set in test notation; values are encoded by Go type.
type kv map[string]any

// anyValue renders a Go value as an OTLP/JSON AnyValue.
func anyValue(v any) map[string]any {
	switch t := v.(type) {
	case string:
		return map[string]any{"stringValue": t}
	case bool:
		return map[string]any{"boolValue": t}
	case int:
		return map[string]any{"intValue": strconv.Itoa(t)} // canonical: int64 as string
	case int64:
		return map[string]any{"intValue": t} // tolerated: plain number
	case float64:
		return map[string]any{"doubleValue": t}
	case []string:
		vals := make([]any, len(t))
		for i, s := range t {
			vals[i] = anyValue(s)
		}
		return map[string]any{"arrayValue": map[string]any{"values": vals}}
	case kv:
		return map[string]any{"kvlistValue": map[string]any{"values": attrList(t)}}
	case json.RawMessage:
		var m map[string]any
		_ = json.Unmarshal(t, &m)
		return m
	}
	panic("anyValue: unsupported type")
}

func attrList(a kv) []any {
	out := make([]any, 0, len(a))
	for k, v := range a {
		out = append(out, map[string]any{"key": k, "value": anyValue(v)})
	}
	return out
}

// baseNano is 2026-11-11T17:10:00Z, the fixed clock of the tests.
const baseNano = int64(1794417000) * 1e9

var fixedNow = func() time.Time { return time.Unix(1794417999, 0).UTC() }

// logRec builds one LogRecord. A zero nano omits the timestamp.
func logRec(nano int64, body string, a kv) map[string]any {
	r := map[string]any{"attributes": attrList(a)}
	if nano != 0 {
		r["timeUnixNano"] = strconv.FormatInt(nano, 10)
	}
	if body != "" {
		r["body"] = anyValue(body)
	}
	return r
}

// otlpBody wraps records in one resource and scope.
func otlpBody(resource kv, scope string, records ...map[string]any) []byte {
	b, err := json.Marshal(map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": attrList(resource)},
			"scopeLogs": []any{map[string]any{
				"scope":      map[string]any{"name": scope},
				"logRecords": records,
			}},
		}},
	})
	if err != nil {
		panic(err)
	}
	return b
}

var (
	claudeRes = kv{"service.name": "claude-code", "service.version": "2.1.310", "os.type": "linux", "host.arch": "arm64"}
	codexRes  = kv{"service.name": "codex-cli", "service.version": "0.130.0"}
	geminiRes = kv{"service.name": "gemini-cli", "service.version": "0.34.0"}
)

// claudeRec builds a Claude Code record the way the agent sends it: the
// prefixed name in the body and the bare name in event.name.
func claudeRec(name string, a kv) map[string]any {
	full := kv{"event.name": name, "session.id": "sess-claude-1", "prompt.id": "prompt-1", "event.sequence": 7}
	for k, v := range a {
		full[k] = v
	}
	return logRec(baseNano, "claude_code."+name, full)
}

func codexRec(name string, a kv) map[string]any {
	full := kv{"event.name": "codex." + name, "conversation.id": "conv-codex-1", "app.version": "0.130.0",
		"originator": "codex_cli_rs", "terminal.type": "xterm", "model": "gpt-5.6-codex", "slug": "gpt-5.6-codex"}
	for k, v := range a {
		full[k] = v
	}
	return logRec(baseNano, "", full)
}

func geminiRec(name, body string, a kv) map[string]any {
	full := kv{"event.name": "gemini_cli." + name, "session.id": "sess-gemini-1", "installation.id": "inst-1", "interactive": true}
	for k, v := range a {
		full[k] = v
	}
	return logRec(baseNano, body, full)
}

func mustConvert(t *testing.T, body []byte) *Result {
	t.Helper()
	res, err := convert(body, fixedNow)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return res
}

// one converts a body expected to yield exactly one event.
func one(t *testing.T, body []byte) *event.Event {
	t.Helper()
	res := mustConvert(t, body)
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1 (unknown=%v ignored=%d)", len(res.Events), res.Unknown, res.Ignored)
	}
	checkInvariants(t, res.Events[0])
	return res.Events[0]
}

// checkInvariants asserts what must hold for every event this package emits.
func checkInvariants(t *testing.T, ev *event.Event) {
	t.Helper()
	if ev.V != event.SchemaVersion || ev.Kind != event.KindActivity || ev.Source != event.SourceOTel {
		t.Errorf("envelope: v=%d kind=%q source=%q", ev.V, ev.Kind, ev.Source)
	}
	if ev.Integrity != event.IntegrityUser {
		t.Errorf("integrity = %q, want user", ev.Integrity)
	}
	if len(ev.ID) != 36 || ev.TS.IsZero() || ev.Type == "" {
		t.Errorf("id=%q ts=%v type=%q", ev.ID, ev.TS, ev.Type)
	}
	if ev.Dedupe != "" {
		t.Errorf("dedupe must be left to the engine, got %q", ev.Dedupe)
	}
	if ev.Labels[LabelEvent] == "" {
		t.Errorf("missing %s label", LabelEvent)
	}
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !json.Valid(line) || strings.Count(string(line), "\n") != 1 {
		t.Errorf("not one valid JSON line: %q", line)
	}
	for k, v := range ev.Labels {
		if len(v) > maxList || strings.ContainsAny(v, " \n\t\"'<>{}$`\\") {
			t.Errorf("label %s=%q is not a safe token", k, v)
		}
	}
}

func wire(t *testing.T, ev *event.Event) string {
	t.Helper()
	b, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}
