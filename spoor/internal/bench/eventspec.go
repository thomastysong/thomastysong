package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// scenarioEpoch is the clock scenarios run on; consecutive events are one
// second apart, as in inline rule tests.
var scenarioEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Defaults filled into every scenario event, matching inline rule tests so
// a scenario and a rule test describe the same world.
const (
	scenarioHome = "/home/tester"
	scenarioCWD  = scenarioHome + "/project"
)

var contentKeys = map[string]bool{"prompt_text": true, "tool_input": true, "tool_output": true, "file_content": true}

// built is a decoded scenario event with its feature overrides.
type built struct {
	ev       *event.Event
	feat     map[string]any
	surfaces []string
}

// build decodes the spec into a fresh event. idx numbers the event within
// its sequence (ids and timestamps); source, when set, is stamped unless
// the spec names its own.
func (s EventSpec) build(idx int, source event.Source) (b built, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error decoding event: %v", r)
		}
	}()
	var m map[string]any
	if err := s.node.Decode(&m); err != nil {
		return b, err
	}
	if m == nil {
		m = map[string]any{}
	}
	delete(m, "surfaces")
	content, hasContent := m["content"]
	feat, hasFeat := m["feat"]
	delete(m, "content")
	delete(m, "feat")
	cm, _ := jsonable(content).(map[string]any)
	if hasContent && cm == nil {
		return b, fmt.Errorf("content must be a mapping")
	}
	fm, _ := jsonable(feat).(map[string]any)
	if hasFeat && fm == nil {
		return b, fmt.Errorf("feat must be a mapping")
	}
	raw, err := json.Marshal(jsonable(m))
	if err != nil {
		return b, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	ev := &event.Event{}
	if err := dec.Decode(ev); err != nil {
		return b, err
	}
	if len(cm) > 0 {
		ev.Content = &event.Content{}
		for k, v := range cm {
			if !contentKeys[k] {
				return b, fmt.Errorf("content: unknown key %q", k)
			}
			switch k {
			case "prompt_text":
				ev.Content.PromptText, _ = v.(string)
			case "tool_output":
				ev.Content.ToolOutput, _ = v.(string)
			case "file_content":
				ev.Content.FileContent, _ = v.(string)
			case "tool_input":
				in, ok := v.(map[string]any)
				if !ok {
					return b, fmt.Errorf("content.tool_input must be a mapping")
				}
				// Round-trip so numbers are float64, as a hook payload
				// decoded with encoding/json would be.
				jb, _ := json.Marshal(in)
				var norm map[string]any
				_ = json.Unmarshal(jb, &norm)
				ev.Content.ToolInput = norm
			}
		}
	}
	if len(fm) > 0 {
		b.feat = map[string]any{}
		for k, v := range fm {
			switch x := v.(type) {
			case int:
				v = float64(x)
			case []any:
				ss := make([]string, 0, len(x))
				for _, e := range x {
					str, ok := e.(string)
					if !ok {
						return b, fmt.Errorf("feat.%s: lists hold strings", k)
					}
					ss = append(ss, str)
				}
				v = ss
			}
			b.feat[k] = v
		}
	}
	fillDefaults(ev, idx, source)
	b.ev = ev
	b.surfaces = s.Surfaces
	if len(b.surfaces) == 0 {
		b.surfaces = defaultSurfaces(ev.Type)
	}
	return b, nil
}

// defaultSurfaces says which collection surfaces observe an event type when
// the scenario does not say: tool calls and prompts reach both the hook
// and the session log; process and inventory records come only from the
// OS plane.
func defaultSurfaces(typ string) []string {
	switch typ {
	case event.TypeProcessExec, event.TypeAgentProcessStart, event.TypeAgentProcessStop:
		return []string{SurfaceProcess}
	case event.TypeInventoryAsset, event.TypePostureCheck:
		return []string{SurfaceScan}
	case event.TypeConfigChange:
		return []string{SurfaceHook}
	}
	return []string{SurfaceHook, SurfaceTranscript}
}

func fillDefaults(ev *event.Event, idx int, source event.Source) {
	if ev.V == 0 {
		ev.V = event.SchemaVersion
	}
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("bench-event-%d", idx+1)
	}
	if ev.TS.IsZero() {
		ev.TS = event.At(scenarioEpoch.Add(time.Duration(idx) * time.Second))
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
	if ev.Source == "" {
		switch {
		case source != "":
			ev.Source = source
		case ev.Kind == event.KindInventory:
			ev.Source = event.SourceScan
		case ev.Type == event.TypeProcessExec || ev.Type == event.TypeAgentProcessStart || ev.Type == event.TypeAgentProcessStop:
			ev.Source = event.SourceProcess
		default:
			ev.Source = event.SourceHook
		}
	}
	if ev.User == nil {
		ev.User = &event.User{ID: "1000", Name: "tester"}
	}
	if ev.Agent == nil {
		ev.Agent = &event.Agent{ID: "claude-code"}
	}
	if ev.Kind == event.KindActivity {
		if ev.Session == nil {
			ev.Session = &event.Session{}
		}
		if ev.Session.ID == "" {
			ev.Session.ID = "bench-session"
		}
		if ev.Session.CWD == "" {
			ev.Session.CWD = scenarioCWD
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

// applyFeat computes features with the evaluator's context and then lays
// the scenario's overrides over them (the evaluator's own Compute call is
// then a no-op).
func applyFeat(b built, home, osName string) {
	if len(b.feat) == 0 {
		return
	}
	features.Compute(b.ev, features.Context{Home: home, OS: osName})
	for k, v := range b.feat {
		b.ev.Feat[k] = v
	}
}

// jsonable converts YAML-decoded values into what encoding/json accepts.
func jsonable(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = jsonable(x)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = jsonable(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonable(x)
		}
		return out
	}
	return v
}
