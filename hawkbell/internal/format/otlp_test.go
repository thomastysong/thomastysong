package format

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// fromAnyValue is the inverse of otlpValue for the generic JSON form, used
// to prove the body is the native event.
func fromAnyValue(t *testing.T, v map[string]any) any {
	t.Helper()
	if len(v) == 0 {
		return nil
	}
	if len(v) != 1 {
		t.Fatalf("AnyValue with %d members: %v", len(v), v)
	}
	for k, x := range v {
		switch k {
		case "stringValue":
			return x.(string)
		case "boolValue":
			return x.(bool)
		case "intValue":
			s, ok := x.(string)
			if !ok {
				t.Fatalf("intValue must be a decimal string, got %T", x)
			}
			return json.Number(s)
		case "doubleValue":
			f, err := x.(json.Number).Float64()
			if err != nil {
				t.Fatalf("doubleValue %v: %v", x, err)
			}
			return f
		case "arrayValue":
			var out []any
			vals, _ := x.(map[string]any)["values"].([]any)
			out = make([]any, 0, len(vals))
			for _, c := range vals {
				out = append(out, fromAnyValue(t, c.(map[string]any)))
			}
			return out
		case "kvlistValue":
			out := map[string]any{}
			vals, _ := x.(map[string]any)["values"].([]any)
			for _, c := range vals {
				kv := c.(map[string]any)
				out[kv["key"].(string)] = fromAnyValue(t, kv["value"].(map[string]any))
			}
			return out
		default:
			t.Fatalf("unknown AnyValue member %q", k)
		}
	}
	return nil
}

func attrMap(t *testing.T, list any) map[string]string {
	t.Helper()
	out := map[string]string{}
	arr, _ := list.([]any)
	for _, a := range arr {
		kv := a.(map[string]any)
		out[kv["key"].(string)] = kv["value"].(map[string]any)["stringValue"].(string)
	}
	return out
}

func decodeOTLP(t *testing.T, raw []byte) (resource map[string]string, scope map[string]any, records []map[string]any) {
	t.Helper()
	var req map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	rl, _ := req["resourceLogs"].([]any)
	if len(rl) != 1 {
		t.Fatalf("want one resource, got %d", len(rl))
	}
	r := rl[0].(map[string]any)
	resource = attrMap(t, r["resource"].(map[string]any)["attributes"])
	sl := r["scopeLogs"].([]any)
	if len(sl) != 1 {
		t.Fatalf("want one scope, got %d", len(sl))
	}
	scope = sl[0].(map[string]any)["scope"].(map[string]any)
	for _, lr := range sl[0].(map[string]any)["logRecords"].([]any) {
		records = append(records, lr.(map[string]any))
	}
	return resource, scope, records
}

func TestOTLPLogs(t *testing.T) {
	all := cases()
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	events := make([]*event.Event, 0, len(names)+1)
	for _, n := range names {
		events = append(events, all[n])
	}
	events = append(events, nil) // skipped

	raw, err := OTLPLogs(events, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	// lowerCamelCase keys only; snake_case is rejected by receivers.
	for _, bad := range []string{`"resource_logs"`, `"scope_logs"`, `"log_records"`, `"time_unix_nano"`, `"severity_number"`} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("snake_case key %s in output", bad)
		}
	}
	resource, scope, records := decodeOTLP(t, raw)
	wantRes := map[string]string{"service.name": "hawkbell", "service.version": "0.1.0", "host.id": "6F1D2C3B-0000-4000-8000-ABCDEF012345",
		"host.name": "dev-mbp-042", "os.type": "darwin", "host.arch": "arm64"}
	if !reflect.DeepEqual(resource, wantRes) {
		t.Errorf("resource = %v", resource)
	}
	if scope["name"] != "hawkbell" || scope["version"] != "0.1.0" {
		t.Errorf("scope = %v", scope)
	}
	if len(records) != len(names) {
		t.Fatalf("records = %d, want %d", len(records), len(names))
	}
	wantNano := strconv.FormatInt(testTime.UnixNano(), 10)
	for i, rec := range records {
		e := all[names[i]]
		if rec["timeUnixNano"] != wantNano || rec["observedTimeUnixNano"] != wantNano {
			t.Errorf("%s: timeUnixNano = %v (%T)", names[i], rec["timeUnixNano"], rec["timeUnixNano"])
		}
		if rec["eventName"] != "hawkbell."+e.Type {
			t.Errorf("%s: eventName = %v", names[i], rec["eventName"])
		}
		if _, ok := rec["severityNumber"].(json.Number); !ok {
			t.Errorf("%s: severityNumber must be an integer, got %T", names[i], rec["severityNumber"])
		}
		// The body is the native event, exactly.
		native, err := Native(e)
		if err != nil {
			t.Fatal(err)
		}
		body := fromAnyValue(t, rec["body"].(map[string]any))
		if !reflect.DeepEqual(body, any(normalize(native))) {
			t.Errorf("%s: body is not the native event\n got %v\nwant %v", names[i], body, native)
		}
		attrs := attrMap(t, rec["attributes"])
		if attrs["event.name"] != "hawkbell."+e.Type || attrs["hawkbell.kind"] != string(e.Kind) || attrs["hawkbell.stream"] != e.Kind.Stream() || attrs["log.record.uid"] != e.ID {
			t.Errorf("%s: attributes = %v", names[i], attrs)
		}
		if e.Agent != nil && attrs["gen_ai.agent.name"] != "claude-code" {
			t.Errorf("%s: gen_ai.agent.name = %q", names[i], attrs["gen_ai.agent.name"])
		}
		if e.Agent == nil && attrs["gen_ai.agent.name"] != "" {
			t.Errorf("%s: gen_ai.agent.name set without an agent", names[i])
		}
		if e.Session != nil && attrs["gen_ai.conversation.id"] != e.Session.ID {
			t.Errorf("%s: gen_ai.conversation.id = %q", names[i], attrs["gen_ai.conversation.id"])
		}
		if e.Tool != nil && attrs["gen_ai.tool.name"] != e.Tool.Name {
			t.Errorf("%s: gen_ai.tool.name = %q", names[i], attrs["gen_ai.tool.name"])
		}
	}
	sev := func(name string) string {
		for i, n := range names {
			if n == name {
				return records[i]["severityNumber"].(json.Number).String()
			}
		}
		return ""
	}
	for name, want := range map[string]string{"detection_blocked": "17", "detection_observed_minimal": "14", "tool_pre_shell": "9",
		"posture_fail": "17", "posture_pass": "9", "health_error": "14"} {
		if got := sev(name); got != want {
			t.Errorf("%s: severityNumber = %s, want %s", name, got, want)
		}
	}
}

// normalize rewrites the native object the way the OTLP round trip does:
// null members are dropped, integers that fit int64 stay exact, any other
// number becomes a float64.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, c := range t {
			if c != nil {
				out[k] = normalize(c)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = normalize(c)
		}
		return out
	case json.Number:
		if _, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return t
		}
		f, _ := strconv.ParseFloat(t.String(), 64)
		return f
	}
	return v
}

func TestOTLPValueTypes(t *testing.T) {
	enc := func(v any) string {
		b, err := json.Marshal(otlpValue(v))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, tc := range []struct {
		in   any
		want string
	}{
		{"x", `{"stringValue":"x"}`},
		{true, `{"boolValue":true}`},
		{false, `{"boolValue":false}`},
		{json.Number("42"), `{"intValue":"42"}`},
		{json.Number("-9223372036854775808"), `{"intValue":"-9223372036854775808"}`},
		{json.Number("18446744073709551615"), `{"doubleValue":18446744073709552000}`},
		{json.Number("1.5"), `{"doubleValue":1.5}`},
		{json.Number("0"), `{"intValue":"0"}`},
		{float64(2.25), `{"doubleValue":2.25}`},
		{math.Inf(1), `{"stringValue":"+Inf"}`},
		{nil, `{}`},
		{[]any{"a", nil, json.Number("1")}, `{"arrayValue":{"values":[{"stringValue":"a"},{},{"intValue":"1"}]}}`},
		{[]any{}, `{"arrayValue":{"values":[]}}`},
		{map[string]any{"b": "2", "a": nil, "c": map[string]any{}}, `{"kvlistValue":{"values":[{"key":"b","value":{"stringValue":"2"}},{"key":"c","value":{"kvlistValue":{"values":[]}}}]}}`},
		{struct{ X int }{1}, `{"stringValue":"{1}"}`},
	} {
		if got := enc(tc.in); got != tc.want {
			t.Errorf("otlpValue(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestOTLPEdgeCases(t *testing.T) {
	raw, err := OTLPLogs(nil, "1")
	if err != nil || string(raw) != `{"resourceLogs":[]}` {
		t.Errorf("empty input: %s %v", raw, err)
	}
	raw, err = OTLPLogs([]*event.Event{nil, nil}, "1")
	if err != nil || string(raw) != `{"resourceLogs":[]}` {
		t.Errorf("nil events: %s %v", raw, err)
	}

	// No time: the fields are omitted so the receiver uses ingestion time.
	e := &event.Event{ID: "x", Kind: event.KindActivity, Type: event.TypeTurnEnd}
	raw, err = OTLPLogs([]*event.Event{e}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "timeUnixNano") || strings.Contains(string(raw), "service.version") {
		t.Errorf("zero time or empty version emitted: %s", raw)
	}
	res, _, recs := decodeOTLP(t, raw)
	if len(res) != 1 || res["service.name"] != "hawkbell" || len(recs) != 1 {
		t.Errorf("resource without host: %v", res)
	}

	// The resource host comes from the first event that has one.
	e2 := base(event.KindActivity, event.TypeTurnEnd, event.SourceHook)
	raw, err = OTLPLogs([]*event.Event{e, e2}, "")
	if err != nil {
		t.Fatal(err)
	}
	res, _, _ = decodeOTLP(t, raw)
	if res["host.name"] != "dev-mbp-042" {
		t.Errorf("host not taken from later event: %v", res)
	}

	// Hostile content stays valid JSON on one line and deterministic.
	e3 := base(event.KindActivity, event.TypeToolPre, event.SourceHook)
	e3.Tool = &event.Tool{Name: "a\nb\xff ", Kind: event.ToolOther, Input: map[string]any{"k": []any{map[string]any{"deep": nil}}}}
	a, err := OTLPLogs([]*event.Event{e3}, "v")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := OTLPLogs([]*event.Event{e3}, "v")
	if string(a) != string(b) || !json.Valid(a) || strings.ContainsAny(string(a), "\n\r") {
		t.Errorf("not deterministic single-line JSON: %s", a)
	}
}
