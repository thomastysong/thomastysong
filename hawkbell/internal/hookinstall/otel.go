package hookinstall

import (
	"reflect"
	"strings"
)

// Native OpenTelemetry is the third surface an agent reports on (after hooks
// and the transcript). It is opt-in here because each agent has a single
// OTLP destination per signal: writing ours over an existing one would take
// over a pipeline somebody else depends on. Every write below is therefore
// preceded by a check for an existing destination, and a conflict turns the
// request into an "unsupported" plan instead.

// otelSpec is the set of members to place in one object of a JSON settings
// file.
//
// Uninstall must remove what install added and nothing else, but the file
// keeps no record of which members were added. Install therefore only
// proceeds when every member it writes was absent (or already held exactly
// hawkbell's settings, from an earlier install), with two exceptions: soft
// members, whose existing value is the owner's choice and is left alone,
// and shared switches, which other signals rely on too (Claude Code's
// CLAUDE_CODE_ENABLE_TELEMETRY also gates metrics and traces). Uninstall
// then removes every member that still holds hawkbell's value, except a
// shared switch that a remaining member still needs.
type otelSpec struct {
	key string // the object that holds them: "env" or "telemetry"
	set jobj
	// soft members are written when missing but an existing value of any
	// kind is the owner's, not a conflict.
	soft map[string]bool
	// shared members may already hold hawkbell's value (another export uses
	// them); any other value is a conflict.
	shared map[string]bool
	// pins are members, not written by hawkbell, whose presence with any
	// value means a destination is already configured.
	pins []string
	// anchor is the member that carries the endpoint. Uninstall removes the
	// set only when the anchor still holds our endpoint.
	anchor string
	// needs reports a member name, outside the set, that depends on the
	// shared switches: it is configured but dormant while they are off.
	needs func(key string) bool
}

// claudeOTel uses the per-signal log variables rather than the generic
// OTEL_EXPORTER_OTLP_ENDPOINT: the generic one, set in managed settings,
// makes Claude Code strip every developer-set endpoint for all signals,
// which is exactly the takeover this package must not perform.
// OTEL_LOG_TOOL_DETAILS adds command lines and MCP tool names to tool
// events (the receiver needs tool_parameters.full_command); prompt and
// tool content gates stay off.
// VERIFIED: code.claude.com/docs/en/monitoring-usage.md, "Common
// configuration variables" and "How managed settings lock the OTLP
// destination", read 2026-11-11.
func claudeOTel(ep otelEndpoint) otelSpec {
	return otelSpec{
		key: "env",
		set: jobj{
			{"CLAUDE_CODE_ENABLE_TELEMETRY", "1"},
			{"OTEL_LOGS_EXPORTER", "otlp"},
			{"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/json"},
			{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", ep.logs},
			{"OTEL_LOG_TOOL_DETAILS", "1"},
		},
		soft:   map[string]bool{"OTEL_LOG_TOOL_DETAILS": true},
		shared: map[string]bool{"CLAUDE_CODE_ENABLE_TELEMETRY": true},
		pins:   []string{"OTEL_EXPORTER_OTLP_ENDPOINT"},
		anchor: "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		// OTEL_METRICS_EXPORTER, OTEL_TRACES_EXPORTER: exports that run
		// only while CLAUDE_CODE_ENABLE_TELEMETRY is on.
		needs: func(k string) bool { return strings.HasPrefix(k, "OTEL_") && strings.HasSuffix(k, "_EXPORTER") },
	}
}

// geminiOTel points Gemini CLI's single OTLP endpoint at the receiver. With
// otlpProtocol "http" the CLI posts to <endpoint>/v1/logs (and /v1/traces,
// /v1/metrics). logPrompts defaults to true in Gemini CLI, so it is switched
// off unless the owner already chose a value. Gemini has one destination
// for every signal, so "enabled" or "target" already being set means a
// pipeline exists (to the default endpoint, a file or Google Cloud).
// VERIFIED: google-gemini/gemini-cli docs/cli/telemetry.md and
// packages/core/src/telemetry/sdk.ts, read 2026-11-11.
func geminiOTel(ep otelEndpoint) otelSpec {
	return otelSpec{
		key: "telemetry",
		set: jobj{
			{"enabled", true},
			{"target", "local"},
			{"otlpEndpoint", ep.base},
			{"otlpProtocol", "http"},
			{"logPrompts", false},
		},
		soft:   map[string]bool{"logPrompts": true},
		pins:   []string{"outfile", "useCollector"},
		anchor: "otlpEndpoint",
	}
}

// jsonOTel returns the settings for a dialect, if it keeps them in the same
// JSON file as its hooks.
func jsonOTel(dialect string, ep otelEndpoint) (otelSpec, bool) {
	switch dialect {
	case "claude":
		return claudeOTel(ep), true
	case "gemini":
		return geminiOTel(ep), true
	}
	return otelSpec{}, false
}

func (s otelSpec) inSet(k string) bool {
	for _, f := range s.set {
		if f.k == k {
			return true
		}
	}
	return false
}

// conflicts names the members that show a destination or a choice hawkbell
// would override.
func (s otelSpec) conflicts(d *jsonDoc) []string {
	_, obj := d.root.member(s.key)
	if obj == nil {
		return nil
	}
	if obj.kind != kindObject {
		return []string{s.key}
	}
	ours := s.ours(obj)
	var out []string
	switchOff := false
	for _, f := range s.set {
		_, v := obj.member(f.k)
		if v == nil {
			if s.shared[f.k] {
				switchOff = true
			}
			continue
		}
		equal := reflect.DeepEqual(v.value(), plain(f.v))
		switch {
		case s.soft[f.k]:
		case s.shared[f.k]:
			if !equal {
				out = append(out, s.key+"."+f.k)
			}
		case !ours || !equal:
			// Present before hawkbell's endpoint was: somebody configured
			// this signal, and uninstall could not tell their member from
			// hawkbell's.
			out = append(out, s.key+"."+f.k)
		}
	}
	for _, k := range s.pins {
		if _, v := obj.member(k); v != nil {
			out = append(out, s.key+"."+k)
		}
	}
	if switchOff && s.needs != nil {
		for _, m := range obj.members {
			if !s.inSet(m.key) && s.needs(m.key) {
				out = append(out, s.key+"."+safeName(m.key)+" (dormant until telemetry is switched on)")
				break
			}
		}
	}
	return out
}

// apply adds the missing members. It must only be called when conflicts
// returned nothing.
func (s otelSpec) apply(src []byte) ([]byte, error) {
	for i := 0; i <= len(s.set); i++ {
		d, err := parseJSON(src)
		if err != nil {
			return nil, err
		}
		_, obj := d.root.member(s.key)
		if obj == nil {
			return d.addMember(d.root, s.key, s.set), nil
		}
		missing := -1
		for j, f := range s.set {
			if _, v := obj.member(f.k); v == nil {
				missing = j
				break
			}
		}
		if missing < 0 {
			return src, nil
		}
		src = d.addMember(obj, s.set[missing].k, s.set[missing].v)
	}
	return src, nil
}

// remove deletes the members this package wrote and returns the shared
// switches it left because a remaining member needs them. A member with
// another value is somebody else's and stays, unless anyValue is set (the
// file is hawkbell's own drop-in).
func (s otelSpec) remove(src []byte, anyValue bool) ([]byte, []string, error) {
	d, err := parseJSON(src)
	if err != nil {
		return nil, nil, err
	}
	objIdx, obj := d.root.member(s.key)
	if obj == nil || obj.kind != kindObject {
		return src, nil, nil
	}
	if !anyValue && !s.ours(obj) {
		return src, nil, nil
	}
	gone := map[int]bool{}
	var shared []int
	for _, f := range s.set {
		j, v := obj.member(f.k)
		if v == nil || (!anyValue && !reflect.DeepEqual(v.value(), plain(f.v))) {
			continue
		}
		if s.shared[f.k] && !anyValue {
			shared = append(shared, j)
			continue
		}
		gone[j] = true
	}
	needed := false
	if s.needs != nil {
		for j, m := range obj.members {
			if !gone[j] && !s.inSet(m.key) && s.needs(m.key) {
				needed = true
			}
		}
	}
	var kept []string
	for _, j := range shared {
		if needed {
			kept = append(kept, obj.members[j].key)
			continue
		}
		gone[j] = true
	}
	if len(gone) == 0 {
		return src, kept, nil
	}
	idx := make([]int, 0, len(gone))
	for j := range obj.members {
		if gone[j] {
			idx = append(idx, j)
		}
	}
	m := d.model(obj, nil)
	removed := 0
	for _, j := range idx {
		if len(m.kids) == 1 && !m.holdsComment() {
			// Nothing else is left in the object: it goes as a whole.
			return d.drop(d.root, objIdx), kept, nil
		}
		m.drop(j - removed)
		removed++
	}
	return d.splice(obj.start, obj.end, m.render()), kept, nil
}

// ours reports whether the endpoint member holds the endpoint of this spec.
func (s otelSpec) ours(obj *node) bool {
	_, v := obj.member(s.anchor)
	if v == nil {
		return false
	}
	for _, f := range s.set {
		if f.k == s.anchor {
			return reflect.DeepEqual(v.value(), plain(f.v))
		}
	}
	return false
}
