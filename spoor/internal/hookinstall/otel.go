package hookinstall

import (
	"reflect"
)

// Native OpenTelemetry is the third surface an agent reports on (after hooks
// and the transcript). It is opt-in here because each agent has a single
// OTLP destination per signal: writing ours over an existing one would take
// over a pipeline somebody else depends on. Every write below is therefore
// preceded by a check for an existing destination, and a conflict turns the
// request into an "unsupported" plan instead.

// otelSpec is the set of members to place in one object of a JSON settings
// file.
type otelSpec struct {
	key string // the object that holds them: "env" or "telemetry"
	set jobj
	// soft members are written when missing but an existing different value
	// is the owner's choice, not a conflict.
	soft map[string]bool
	// pins are members whose presence with any value means a destination
	// is already configured.
	pins []string
	// anchor is the member that carries the endpoint. Uninstall removes the
	// set only when the anchor still holds our endpoint: "enabled": true on
	// its own may well be the owner's.
	anchor string
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
		pins:   []string{"OTEL_EXPORTER_OTLP_ENDPOINT"},
		anchor: "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	}
}

// geminiOTel points Gemini CLI's single OTLP endpoint at the receiver. With
// otlpProtocol "http" the CLI posts to <endpoint>/v1/logs (and /v1/traces,
// /v1/metrics). logPrompts defaults to true in Gemini CLI, so it is switched
// off unless the owner already chose a value.
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
		pins:   []string{"outfile"},
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

// conflicts names the members that already point somewhere else.
func (s otelSpec) conflicts(d *jsonDoc) []string {
	_, obj := d.root.member(s.key)
	if obj == nil {
		return nil
	}
	if obj.kind != kindObject {
		return []string{s.key}
	}
	var out []string
	for _, f := range s.set {
		if s.soft[f.k] {
			continue
		}
		if _, v := obj.member(f.k); v != nil && !reflect.DeepEqual(v.value(), plain(f.v)) {
			out = append(out, s.key+"."+f.k)
		}
	}
	for _, k := range s.pins {
		if _, v := obj.member(k); v != nil {
			out = append(out, s.key+"."+k)
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

// remove deletes the members this package wrote. A member with another
// value is somebody else's and stays, unless anyValue is set (the file is
// spoor's own drop-in).
func (s otelSpec) remove(src []byte, anyValue bool) ([]byte, error) {
	for i := 0; i <= len(s.set); i++ {
		d, err := parseJSON(src)
		if err != nil {
			return nil, err
		}
		objIdx, obj := d.root.member(s.key)
		if obj == nil || obj.kind != kindObject {
			return src, nil
		}
		if i == 0 && !anyValue && !s.ours(obj) {
			return src, nil
		}
		hit := -1
		for _, f := range s.set {
			j, v := obj.member(f.k)
			if v != nil && (anyValue || reflect.DeepEqual(v.value(), plain(f.v))) {
				hit = j
				break
			}
		}
		if hit < 0 {
			return src, nil
		}
		if len(obj.members) == 1 {
			src = d.drop(d.root, objIdx)
			continue
		}
		src = d.drop(obj, hit)
	}
	return src, nil
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
