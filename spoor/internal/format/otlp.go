package format

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	"github.com/thomastysong/spoor/internal/event"
)

// The OTLP/HTTP JSON encoding (opentelemetry-proto docs/specification.md):
// keys are lowerCamelCase, 64-bit integers are decimal strings, enums are
// integers. The structs below fix the key order so output is deterministic.

type otlpRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKV `json:"attributes"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	TimeUnixNano         string   `json:"timeUnixNano,omitempty"`
	ObservedTimeUnixNano string   `json:"observedTimeUnixNano,omitempty"`
	SeverityNumber       int      `json:"severityNumber"`
	SeverityText         string   `json:"severityText,omitempty"`
	EventName            string   `json:"eventName,omitempty"`
	Body                 otlpAny  `json:"body"`
	Attributes           []otlpKV `json:"attributes,omitempty"`
}

type otlpKV struct {
	Key   string  `json:"key"`
	Value otlpAny `json:"value"`
}

// otlpAny is AnyValue: exactly one member is set. With none set it encodes
// as {}, which is how OTLP spells an empty value.
type otlpAny struct {
	StringValue *string     `json:"stringValue,omitempty"`
	BoolValue   *bool       `json:"boolValue,omitempty"`
	IntValue    *string     `json:"intValue,omitempty"`
	DoubleValue *float64    `json:"doubleValue,omitempty"`
	ArrayValue  *otlpArray  `json:"arrayValue,omitempty"`
	KvlistValue *otlpKvlist `json:"kvlistValue,omitempty"`
}

type otlpArray struct {
	Values []otlpAny `json:"values"`
}

type otlpKvlist struct {
	Values []otlpKV `json:"values"`
}

func otlpString(s string) otlpAny { return otlpAny{StringValue: &s} }

// otlpSeverity maps the OCSF-style severity id (see SeverityID) to an OTLP
// SeverityNumber: INFO, WARN, WARN2, ERROR, FATAL. Unknown stays UNSPECIFIED.
var otlpSeverity = [...]int{0, 9, 13, 14, 17, 21}

var otlpSeverityText = [...]string{"", event.SevInfo, event.SevLow, event.SevMedium, event.SevHigh, event.SevCritical}

// OTLPLogs encodes events as one OTLP/HTTP JSON ExportLogsServiceRequest.
//
// There is one resource (service.name "spoor", plus host.id, host.name,
// os.type and host.arch taken from the first event that has a host: a sensor
// reports for one endpoint), one scope, and one log record per event.
//
// The record body is the complete native event as a kvlistValue. Fluent
// Bit's opentelemetry input turns a kvlist body into the record map itself,
// and most non-OTLP outputs serialize only the body, so everything a
// detection consumer needs has to be in it. Attributes repeat only routing
// keys: event.name (spoor.<type>), spoor.kind, spoor.stream, log.record.uid,
// and where applicable gen_ai.agent.name, gen_ai.conversation.id,
// gen_ai.tool.name, gen_ai.tool.call.id, spoor.rule_id and spoor.severity.
//
// timeUnixNano is the event time as a decimal string; events without a time
// omit it so the receiver falls back to ingestion time instead of 1970. JSON
// null has no AnyValue counterpart: null members of a map are omitted and
// null array elements become empty values. nil events are skipped. An empty
// input yields {"resourceLogs":[]}.
func OTLPLogs(events []*event.Event, serviceVersion string) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("format: encode otlp: %v", r)
		}
	}()
	records := make([]otlpLogRecord, 0, len(events))
	var host *event.Host
	for _, e := range events {
		if e == nil {
			continue
		}
		if host == nil && e.Host != nil {
			host = e.Host
		}
		rec, err := otlpRecord(e)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	req := otlpRequest{ResourceLogs: []otlpResourceLogs{}}
	if len(records) > 0 {
		res := []otlpKV{{Key: "service.name", Value: otlpString(productName)}}
		add := func(k, v string) {
			if v != "" {
				res = append(res, otlpKV{Key: k, Value: otlpString(v)})
			}
		}
		add("service.version", serviceVersion)
		if host != nil {
			add("host.id", host.ID)
			add("host.name", host.Name)
			add("os.type", host.OS)
			add("host.arch", host.Arch)
		}
		req.ResourceLogs = append(req.ResourceLogs, otlpResourceLogs{
			Resource: otlpResource{Attributes: res},
			ScopeLogs: []otlpScopeLogs{{
				Scope:      otlpScope{Name: productName, Version: serviceVersion},
				LogRecords: records,
			}},
		})
	}
	out, err = json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("format: encode otlp: %w", err)
	}
	return out, nil
}

func otlpRecord(e *event.Event) (otlpLogRecord, error) {
	native, err := Native(e)
	if err != nil {
		return otlpLogRecord{}, err
	}
	sev := SeverityID(e)
	rec := otlpLogRecord{
		SeverityNumber: otlpSeverity[sev],
		SeverityText:   otlpSeverityText[sev],
		EventName:      productName + "." + e.Type,
		Body:           otlpValue(native),
	}
	if !e.TS.IsZero() {
		ns := strconv.FormatInt(e.TS.UnixNano(), 10)
		// The sensor is the observer, so observed time equals event time;
		// setting it keeps the request deterministic for a given input.
		rec.TimeUnixNano, rec.ObservedTimeUnixNano = ns, ns
	}
	attr := func(k, v string) {
		if v != "" {
			rec.Attributes = append(rec.Attributes, otlpKV{Key: k, Value: otlpString(v)})
		}
	}
	attr("event.name", productName+"."+e.Type)
	attr("spoor.kind", string(e.Kind))
	attr("spoor.stream", e.Kind.Stream())
	attr("log.record.uid", e.ID)
	if e.Agent != nil {
		attr("gen_ai.agent.name", firstNonEmpty(e.Agent.ID, e.Agent.Name))
	}
	if e.Session != nil {
		attr("gen_ai.conversation.id", e.Session.ID)
	}
	if e.Tool != nil {
		attr("gen_ai.tool.name", e.Tool.Name)
		attr("gen_ai.tool.call.id", e.Tool.UseID)
	}
	if e.Kind == event.KindDetection && e.Detection != nil {
		attr("spoor.rule_id", e.Detection.RuleID)
		attr("spoor.severity", e.Detection.Severity)
	}
	return rec, nil
}

// otlpValue converts a decoded JSON value to AnyValue. Input comes from
// Native, so nesting is already bounded by MaxDepth plus the fixed depth of
// the event schema.
func otlpValue(v any) otlpAny {
	switch t := v.(type) {
	case nil:
		return otlpAny{}
	case string:
		return otlpAny{StringValue: &t}
	case bool:
		return otlpAny{BoolValue: &t}
	case json.Number:
		return otlpNumber(t)
	case float64:
		return otlpFloat(t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k, c := range t {
			if c != nil {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		kv := make([]otlpKV, 0, len(keys))
		for _, k := range keys {
			kv = append(kv, otlpKV{Key: k, Value: otlpValue(t[k])})
		}
		return otlpAny{KvlistValue: &otlpKvlist{Values: kv}}
	case []any:
		vals := make([]otlpAny, 0, len(t))
		for _, c := range t {
			vals = append(vals, otlpValue(c))
		}
		return otlpAny{ArrayValue: &otlpArray{Values: vals}}
	default:
		s := fmt.Sprint(t)
		return otlpAny{StringValue: &s}
	}
}

// otlpNumber keeps integers exact (intValue is an int64 carried as a decimal
// string) and falls back to a double, then to the literal text, for values
// an int64 cannot hold.
func otlpNumber(n json.Number) otlpAny {
	s := n.String()
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		is := strconv.FormatInt(i, 10)
		return otlpAny{IntValue: &is}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return otlpFloat(f)
	}
	return otlpAny{StringValue: &s}
}

func otlpFloat(f float64) otlpAny {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// JSON cannot carry these, and a request that fails to encode
		// would lose the whole batch.
		s := strconv.FormatFloat(f, 'g', -1, 64)
		return otlpAny{StringValue: &s}
	}
	return otlpAny{DoubleValue: &f}
}
