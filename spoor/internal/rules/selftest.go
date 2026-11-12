package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// TestResult is the outcome of one inline rule test.
type TestResult struct {
	RuleID string
	Name   string
	OK     bool
	Got    string // match | no_match | error
	Want   string
	Detail string // why, when OK is false
}

// testEpoch is the fixed clock inline tests run on; consecutive events are
// one second apart.
var testEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const testHome = "/home/tester"

// RunTests runs every inline test of every rule (disabled rules included)
// against a fresh engine built from the whole set, so rules that set flags
// for other rules are exercised together. A test passes when the rule
// fired (its predicate held, flags and threshold included; emission,
// suppression and dedup do not matter) exactly when the test expects it.
func (s *Set) RunTests() []TestResult {
	run := s.clone()
	run.disabled = map[string]bool{}
	var out []TestResult
	for _, r := range s.rules {
		tests, err := r.testList()
		if err != nil {
			// A rule from the embedded cache whose body or tests do not
			// compile (see lazy.go): one failed result says why.
			out = append(out, TestResult{RuleID: r.ID, Name: "(compile)", Got: "error", Want: "match", Detail: err.Error()})
			continue
		}
		for i := range tests {
			out = append(out, runTest(run, r, &tests[i]))
		}
	}
	return out
}

func runTest(set *Set, r *rule, t *rawTest) (res TestResult) {
	res = TestResult{RuleID: r.ID, Name: t.Name, Want: t.Expect}
	defer func() {
		if p := recover(); p != nil {
			res.OK, res.Got, res.Detail = false, "error", fmt.Sprintf("panic: %v", p)
		}
	}()
	evs, err := testEvents(t)
	if err != nil {
		res.Got, res.Detail = "error", err.Error()
		return res
	}
	last := evs[len(evs)-1]
	osName := "linux"
	if last.ev.Host != nil && last.ev.Host.OS != "" {
		osName = last.ev.Host.OS
	}
	clock := testEpoch
	eng := NewEngine(set, Options{
		Now:      func() time.Time { return clock },
		Deadline: 10 * time.Second,
		Home:     testHome,
		OS:       osName,
	})
	if len(t.Flags) > 0 {
		st := eng.session(SessionKey(last.ev), clock)
		thread := ""
		if last.ev.Session != nil {
			thread = last.ev.Session.SubagentID
		}
		for _, f := range t.Flags {
			st.setFlag(thread, ScopeThread, f, 24*time.Hour, clock, "test-preset")
		}
	}
	var fired map[string]bool
	for i, te := range evs {
		clock = testEpoch.Add(time.Duration(i) * time.Second)
		if te.ev.TS.IsZero() {
			te.ev.TS = event.At(clock)
		}
		if len(te.feat) > 0 {
			features.Compute(te.ev, features.Context{Home: testHome, OS: osName})
			for k, v := range te.feat {
				te.ev.Feat[k] = v
			}
		}
		fired = map[string]bool{}
		eng.evaluate(te.ev, fired)
	}
	res.Got = "no_match"
	if fired[r.ID] {
		res.Got = "match"
	}
	res.OK = res.Got == res.Want
	if !res.OK {
		res.Detail = diagnose(eng, r, last.ev)
	}
	return res
}

// diagnose explains which part of a rule decided the outcome on ev.
func diagnose(e *Engine, r *rule, ev *event.Event) string {
	fields := features.Fields(ev)
	ctx := &evalCtx{lists: e.lists}
	var parts []string
	if !isActivity(ev) && r.Kind == KindActivity {
		parts = append(parts, fmt.Sprintf("event kind %q is not activity", ev.Kind))
	}
	if r.Kind == KindInventory && ev.Kind != event.KindInventory {
		parts = append(parts, "inventory rule on a non-inventory event")
	}
	if r.when != nil {
		parts = append(parts, fmt.Sprintf("when=%v", r.when.eval(fields, ctx)))
	}
	if len(r.require)+len(r.requireAny) > 0 {
		have, _ := fields["session.flags"].([]string)
		parts = append(parts, fmt.Sprintf("flags require=%v require_any=%v present=%v", r.require, r.requireAny, have))
	}
	parts = append(parts, fmt.Sprintf("match=%v", r.match.eval(fields, ctx)))
	if r.allow != nil {
		parts = append(parts, fmt.Sprintf("allow=%v", r.allow.eval(fields, ctx)))
	}
	if r.threshold != nil {
		parts = append(parts, fmt.Sprintf("threshold count=%d", r.threshold.count))
	}
	return strings.Join(parts, "; ")
}

type testEvent struct {
	ev   *event.Event
	feat map[string]any
}

func testEvents(t *rawTest) ([]testEvent, error) {
	nodes := t.Events
	if t.Event.Kind != 0 {
		nodes = []yaml.Node{t.Event}
	}
	out := make([]testEvent, 0, len(nodes))
	for i := range nodes {
		var extraContent, extraFeat *yaml.Node
		if i == len(nodes)-1 {
			extraContent, extraFeat = &t.Content, &t.Feat
		}
		te, err := testEventFrom(&nodes[i], i, extraContent, extraFeat)
		if err != nil {
			return nil, fmt.Errorf("event %d: %v", i+1, err)
		}
		out = append(out, te)
	}
	return out, nil
}

var contentKeys = map[string]bool{"prompt_text": true, "tool_input": true, "tool_output": true, "file_content": true}

// testEventFrom decodes a partial event in the JSON shape of
// internal/event (strictly: an unknown key is an error) plus optional
// content and feat blocks, and fills what a source would always set.
func testEventFrom(n *yaml.Node, idx int, extraContent, extraFeat *yaml.Node) (testEvent, error) {
	var m map[string]any
	if err := n.Decode(&m); err != nil {
		return testEvent{}, err
	}
	if m == nil {
		m = map[string]any{}
	}
	content, _ := m["content"].(map[string]any)
	feat, _ := m["feat"].(map[string]any)
	if _, ok := m["content"]; ok && content == nil {
		return testEvent{}, fmt.Errorf("content must be a mapping")
	}
	if _, ok := m["feat"]; ok && feat == nil {
		return testEvent{}, fmt.Errorf("feat must be a mapping")
	}
	delete(m, "content")
	delete(m, "feat")
	if extraContent != nil && extraContent.Kind != 0 {
		var c map[string]any
		if err := extraContent.Decode(&c); err != nil {
			return testEvent{}, fmt.Errorf("content: %v", err)
		}
		if content == nil {
			content = map[string]any{}
		}
		for k, v := range c {
			content[k] = v
		}
	}
	if extraFeat != nil && extraFeat.Kind != 0 {
		var f map[string]any
		if err := extraFeat.Decode(&f); err != nil {
			return testEvent{}, fmt.Errorf("feat: %v", err)
		}
		if feat == nil {
			feat = map[string]any{}
		}
		for k, v := range f {
			feat[k] = v
		}
	}
	b, err := json.Marshal(jsonable(m))
	if err != nil {
		return testEvent{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	ev := &event.Event{}
	if err := dec.Decode(ev); err != nil {
		return testEvent{}, err
	}
	if len(content) > 0 {
		ev.Content = &event.Content{}
		for k, v := range content {
			if !contentKeys[k] {
				return testEvent{}, fmt.Errorf("content: unknown key %q", k)
			}
			switch k {
			case "prompt_text":
				ev.Content.PromptText, _ = v.(string)
			case "tool_output":
				ev.Content.ToolOutput, _ = v.(string)
			case "file_content":
				ev.Content.FileContent, _ = v.(string)
			case "tool_input":
				in, ok := jsonable(v).(map[string]any)
				if !ok {
					return testEvent{}, fmt.Errorf("content.tool_input must be a mapping")
				}
				// Round-trip through JSON so numbers are float64, as a
				// hook payload decoded with encoding/json would be.
				jb, _ := json.Marshal(in)
				var norm map[string]any
				_ = json.Unmarshal(jb, &norm)
				ev.Content.ToolInput = norm
			}
		}
	}
	fillTestDefaults(ev, idx)
	te := testEvent{ev: ev}
	if len(feat) > 0 {
		te.feat = map[string]any{}
		for k, v := range feat {
			v = jsonable(v)
			switch x := v.(type) {
			case int:
				v = float64(x)
			case []any:
				ss := make([]string, 0, len(x))
				for _, e := range x {
					s, ok := e.(string)
					if !ok {
						return testEvent{}, fmt.Errorf("feat.%s: lists hold strings", k)
					}
					ss = append(ss, s)
				}
				v = ss
			}
			te.feat[k] = v
		}
	}
	return te, nil
}

func fillTestDefaults(ev *event.Event, idx int) {
	if ev.V == 0 {
		ev.V = event.SchemaVersion
	}
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("test-event-%d", idx+1)
	}
	if ev.Kind == "" {
		switch ev.Type {
		case event.TypeInventoryAsset:
			ev.Kind = event.KindInventory
		case event.TypePostureCheck:
			ev.Kind = event.KindPosture
		default:
			ev.Kind = event.KindActivity
		}
	}
	if ev.User == nil {
		ev.User = &event.User{ID: "1000", Name: "tester"}
	}
	if ev.Agent == nil {
		ev.Agent = &event.Agent{ID: "test-agent"}
	}
	if ev.Kind == event.KindActivity {
		if ev.Session == nil {
			ev.Session = &event.Session{}
		}
		if ev.Session.ID == "" {
			ev.Session.ID = "test-session"
		}
		if ev.Session.CWD == "" {
			ev.Session.CWD = testHome + "/project"
		}
	}
	var input map[string]any
	if ev.Content != nil {
		input = ev.Content.ToolInput
	}
	if ev.Tool != nil && ev.Tool.Kind == "" && ev.Tool.Name != "" {
		ev.Tool.Kind, ev.Tool.MCPServer, ev.Tool.MCPTool = toolmap.KindWithInput(ev.Agent.ID, ev.Tool.Name, input)
	}
	if ev.Tool != nil && ev.Target == nil && len(input) > 0 {
		ev.Target = toolmap.Target(ev.Agent.ID, ev.Tool.Name, ev.Tool.Kind, input)
	}
	if ev.Type == event.TypePromptSubmit && ev.Prompt == nil && ev.Content != nil && ev.Content.PromptText != "" {
		ev.Prompt = &event.Prompt{Len: len(ev.Content.PromptText)}
	}
}
