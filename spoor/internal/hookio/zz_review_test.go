package hookio

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

func dump(t *testing.T, id string, in string, env map[string]string) {
	t.Helper()
	d := dialect(t, id)
	evs, req, err := d.Parse([]byte(in), env)
	t.Logf("---- %s err=%v nevs=%d", id, err, len(evs))
	for _, e := range evs {
		b, _ := json.Marshal(e)
		t.Logf("  ev: %.1500s", b)
		if e.Content != nil {
			in, _ := json.Marshal(e.Content.ToolInput)
			t.Logf("  content: prompt=%q toolinput=%.300s tooloutput=%.200q file=%.200q", e.Content.PromptText, in, e.Content.ToolOutput, e.Content.FileContent)
		}
	}
	if req != nil {
		t.Logf("  req: agent=%s event=%q blocking=%v", req.AgentID, req.EventName, req.Blocking)
		for _, a := range []string{"deny", "ask", "allow"} {
			so, se, c := d.Respond(req, Decision{Action: a, Reason: "r", RuleID: "R1"})
			t.Logf("  %s -> stdout=%q stderr=%q code=%d", a, so, se, c)
		}
	}
}

func peak(t *testing.T, name string, in []byte, id string) {
	d := dialect(t, id)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	evs, _, err := d.Parse(in, nil)
	el := time.Since(start)
	runtime.ReadMemStats(&m1)
	t.Logf("%s: in=%d bytes err=%v nevs=%d time=%v totalAlloc=%d MiB heapInuseAfter=%d MiB mallocs=%d", name, len(in), err, len(evs), el,
		(m1.TotalAlloc-m0.TotalAlloc)>>20, m1.HeapInuse>>20, m1.Mallocs-m0.Mallocs)
	runtime.KeepAlive(evs)
}

func TestZZMem(t *testing.T) {
	n := (MaxInput - 200) / 3
	peak(t, "empty objects", []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x","a":[`+strings.Repeat("{},", n-1)+`{}]}}`), "claude")
	peak(t, "empty arrays", []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x","a":[`+strings.Repeat("[],", n-1)+`[]]}}`), "claude")
	n2 := (MaxInput - 200) / 2
	peak(t, "numbers", []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x","a":[`+strings.Repeat("1,", n2-1)+`1]}}`), "claude")
	// batch: 256 calls each ~32KiB
	peak(t, "posttool resp", []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"x"},"tool_response":[`+strings.Repeat("{},", n-1)+`{}]}`), "claude")
	// nested 64 deep repeated
	unit := strings.Repeat("[", 60) + strings.Repeat("]", 60) + ","
	k := (MaxInput - 200) / len(unit)
	peak(t, "deep units", []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"x","a":[`+strings.Repeat(unit, k-1)+`1]}}`), "claude")
}
