package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// MaxDepth is the deepest nesting kept inside Tool.Input. Anything below it
// is replaced by DepthMarker. Agent tool arguments are attacker-influenced
// JSON, and every consumer after us (msgpack-c in Fluent Bit, OTLP receivers,
// SIEM JSON parsers) recurses on nesting, so the bound is applied once here
// rather than trusting each of them.
const MaxDepth = 32

// DepthMarker replaces a subtree that was nested deeper than MaxDepth.
const DepthMarker = "[hawkbell: nesting too deep, subtree removed]"

// ErrNilEvent is returned when a nil event is passed to an encoder.
var ErrNilEvent = errors.New("format: nil event")

// NativeJSON returns the event as one compact JSON object (no trailing
// newline). It differs from json.Marshal(e) only for hostile input: nesting
// inside Tool.Input is cut at MaxDepth, and if Tool.Input still cannot be
// encoded (a NaN, a cycle, a channel put there by a buggy source) it is
// dropped and "tool.input" is recorded in Truncated, so one bad argument map
// never costs the whole event. The caller's event is never modified.
func NativeJSON(e *event.Event) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("format: encode event: %v", r)
		}
	}()
	if e == nil {
		return nil, ErrNilEvent
	}
	e = boundInput(e)
	b, err = json.Marshal(e)
	if err == nil {
		return b, nil
	}
	if e.Tool == nil || e.Tool.Input == nil {
		return nil, fmt.Errorf("format: encode event: %w", err)
	}
	b, err = json.Marshal(withInput(e, nil))
	if err != nil {
		return nil, fmt.Errorf("format: encode event: %w", err)
	}
	return b, nil
}

// Native returns the event as the generic JSON object that sinks without a
// typed schema serialize (Forward records, OTLP bodies, unmapped.hawkbell).
// Numbers are json.Number so 64-bit sequence numbers and counters survive
// the round trip exactly.
func Native(e *event.Event) (map[string]any, error) {
	b, err := NativeJSON(e)
	if err != nil {
		return nil, err
	}
	return decodeObject(b)
}

func decodeObject(b []byte) (m map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, fmt.Errorf("format: decode event: %v", r)
		}
	}()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("format: decode event: %w", err)
	}
	return m, nil
}

// boundInput returns e unchanged when Tool.Input is within MaxDepth (the
// overwhelmingly common case, so no allocation), otherwise a clone whose
// input has the deep subtrees replaced.
func boundInput(e *event.Event) *event.Event {
	if e.Tool == nil || e.Tool.Input == nil || !deeperThan(e.Tool.Input, MaxDepth) {
		return e
	}
	cut, _ := cutDepth(e.Tool.Input, MaxDepth).(map[string]any)
	return withInput(e, cut)
}

// withInput returns a shallow copy of e whose Tool.Input is replaced and
// whose Truncated list records it. It deliberately avoids Event.Clone: Clone
// deep-copies Tool.Input with unbounded recursion, which is exactly the value
// we do not trust here.
func withInput(e *event.Event, in map[string]any) *event.Event {
	c := *e
	t := *e.Tool
	t.Input = in
	c.Tool = &t
	c.Truncated = appendUnique(append([]string(nil), e.Truncated...), "tool.input")
	return &c
}

// deeperThan reports whether v nests containers more than limit levels deep.
// The recursion itself is bounded by limit, so a cyclic structure built by a
// buggy caller terminates too.
func deeperThan(v any, limit int) bool {
	switch t := v.(type) {
	case map[string]any:
		if limit <= 0 {
			return true
		}
		for _, c := range t {
			if deeperThan(c, limit-1) {
				return true
			}
		}
	case []any:
		if limit <= 0 {
			return true
		}
		for _, c := range t {
			if deeperThan(c, limit-1) {
				return true
			}
		}
	}
	return false
}

// cutDepth copies v, replacing any container found below limit levels.
func cutDepth(v any, limit int) any {
	switch t := v.(type) {
	case map[string]any:
		if limit <= 0 {
			return DepthMarker
		}
		out := make(map[string]any, len(t))
		for k, c := range t {
			out[k] = cutDepth(c, limit-1)
		}
		return out
	case []any:
		if limit <= 0 {
			return DepthMarker
		}
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = cutDepth(c, limit-1)
		}
		return out
	default:
		return v
	}
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// SeverityID returns the OCSF severity_id (0 Unknown, 1 Informational, 2 Low,
// 3 Medium, 4 High, 5 Critical) for any event. Only detections and failed
// posture checks carry a real severity; everything else is informational,
// except sensor errors, which rank Medium because a blind sensor must not
// look like a quiet endpoint.
func SeverityID(e *event.Event) int {
	if e == nil {
		return 0
	}
	switch {
	case e.Kind == event.KindDetection && e.Detection != nil:
		return event.SeverityRank(e.Detection.Severity)
	case e.Kind == event.KindPosture && e.Check != nil:
		if e.Check.Status == "fail" {
			return event.SeverityRank(e.Check.Severity)
		}
		return 1
	case e.Type == event.TypeHealthError:
		return 3
	default:
		return 1
	}
}
