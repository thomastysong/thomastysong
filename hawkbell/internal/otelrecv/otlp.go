package otelrecv

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// Bounds on what one request may make the converter do. The body itself is
// capped by the caller (Options.MaxBody in the receiver, MaxConvertBytes in
// Convert); these caps bound the work done per decoded element.
const (
	// MaxConvertBytes is the largest body Convert accepts.
	MaxConvertBytes = 16 << 20
	// MaxRecords is the number of log records converted per request; the
	// rest are counted in Result.Dropped and reported to the sender as a
	// partial success.
	MaxRecords = 5000

	maxAttrs      = 256 // attributes kept per record or resource
	maxKeyLen     = 256
	maxAnyDepth   = 8   // nesting of array and key-value AnyValues
	maxAnyItems   = 256 // elements kept per array or key-value list
	maxEmbedBytes = 1 << 20
	maxEmbedDepth = 64 // nesting accepted in a JSON document carried inside an attribute
)

// The OTLP/JSON mapping uses lowerCamelCase names; the proto3 JSON mapping
// also lets a sender use the original snake_case field names, so both are
// read. Everything not needed for conversion is left undecoded.
type exportRequest struct {
	ResourceLogs      []resourceLogs `json:"resourceLogs"`
	ResourceLogsSnake []resourceLogs `json:"resource_logs"`
}

type resourceLogs struct {
	Resource       *wireResource `json:"resource"`
	ScopeLogs      []scopeLogs   `json:"scopeLogs"`
	ScopeLogsSnake []scopeLogs   `json:"scope_logs"`
}

type wireResource struct {
	Attributes kvList `json:"attributes"`
}

type scopeLogs struct {
	Scope           *wireScope  `json:"scope"`
	LogRecords      []logRecord `json:"logRecords"`
	LogRecordsSnake []logRecord `json:"log_records"`
}

type wireScope struct {
	Name    flexString `json:"name"`
	Version flexString `json:"version"`
}

type logRecord struct {
	TimeUnixNano          flexUint        `json:"timeUnixNano"`
	TimeUnixNanoSnake     flexUint        `json:"time_unix_nano"`
	ObservedTimeUnixNano  flexUint        `json:"observedTimeUnixNano"`
	ObservedTimeNanoSnake flexUint        `json:"observed_time_unix_nano"`
	EventName             flexString      `json:"eventName"`
	EventNameSnake        flexString      `json:"event_name"`
	Body                  json.RawMessage `json:"body"`
	Attributes            kvList          `json:"attributes"`
}

type keyValue struct {
	Key   flexString      `json:"key"`
	Value json.RawMessage `json:"value"`
}

// kvList decodes an attribute array leniently: a value of the wrong type
// reads as no attributes instead of failing the whole request, because one
// drifted record must not cost the rest of the batch.
type kvList []keyValue

func (l *kvList) UnmarshalJSON(b []byte) error {
	var items []keyValue
	if err := json.Unmarshal(b, &items); err != nil {
		*l = nil
		return nil
	}
	*l = items
	return nil
}

// flexString accepts a JSON string and reads anything else as empty.
type flexString string

func (s *flexString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || b[0] != '"' {
		*s = ""
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		*s = ""
		return nil
	}
	*s = flexString(v)
	return nil
}

// flexUint accepts the two spellings OTLP/JSON allows for a 64-bit integer:
// a decimal string (the canonical form, because JSON numbers lose precision
// above 2^53) and a plain number. Anything else reads as zero.
type flexUint uint64

func (u *flexUint) UnmarshalJSON(b []byte) error {
	*u = 0
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		*u = flexUint(v)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f < math.MaxUint64 {
		*u = flexUint(f)
	}
	return nil
}

// errNotOTLP is returned for a body that is JSON but not an export request.
var errNotOTLP = errors.New("otelrecv: body is not an OTLP logs export request (no resourceLogs)")

// decodeRequest parses a request body. A body without resourceLogs is an
// error unless it is the empty object, which the OTLP specification allows
// as an empty export.
func decodeRequest(body []byte) (*exportRequest, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if len(trimmed) == 0 {
		return nil, errors.New("otelrecv: empty body")
	}
	if trimmed[0] != '{' {
		return nil, errors.New("otelrecv: body is not a JSON object")
	}
	var req exportRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return nil, errors.New("otelrecv: invalid OTLP JSON: " + jsonErrText(err))
	}
	if req.ResourceLogs == nil && req.ResourceLogsSnake == nil {
		var probe map[string]json.RawMessage
		_ = json.Unmarshal(trimmed, &probe)
		_, camel := probe["resourceLogs"]
		_, snake := probe["resource_logs"]
		if len(probe) != 0 && !camel && !snake {
			return nil, errNotOTLP
		}
	}
	return &req, nil
}

// jsonErrText keeps decoder errors short and free of payload bytes: the text
// goes back to the sender and into logs.
func jsonErrText(err error) string {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return "syntax error at offset " + strconv.FormatInt(syn.Offset, 10)
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		return "unexpected " + typ.Value + " for field " + labelValue(typ.Field, 64)
	}
	return "malformed document"
}

// anyKeys lists the AnyValue alternatives in a fixed order. AnyValue is a
// oneof, but nothing stops a hostile sender from setting several; reading
// them in a fixed order keeps the conversion deterministic.
var anyKeys = [...][2]string{
	{"stringValue", "string_value"},
	{"boolValue", "bool_value"},
	{"intValue", "int_value"},
	{"doubleValue", "double_value"},
	{"arrayValue", "array_value"},
	{"kvlistValue", "kvlist_value"},
}

// decodeAny converts an OTLP AnyValue into a Go value: string, bool, int64,
// float64, []any or map[string]any. bytesValue and anything malformed or
// nested deeper than maxAnyDepth reads as absent.
func decodeAny(raw json.RawMessage, depth int) (any, bool) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	for i, names := range anyKeys {
		v, ok := m[names[0]]
		if !ok {
			if v, ok = m[names[1]]; !ok {
				continue
			}
		}
		switch i {
		case 0:
			var s string
			if json.Unmarshal(v, &s) == nil {
				return strings.ToValidUTF8(s, "�"), true
			}
		case 1:
			var b bool
			if json.Unmarshal(v, &b) == nil {
				return b, true
			}
		case 2:
			s := strings.Trim(string(v), `"`)
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				return n, true
			}
			if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && math.Abs(f) < 1<<63 {
				return int64(f), true
			}
		case 3:
			var f float64
			if json.Unmarshal(v, &f) == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f, true
			}
		case 4:
			if depth >= maxAnyDepth {
				return nil, false
			}
			var arr struct {
				Values []json.RawMessage `json:"values"`
			}
			if json.Unmarshal(v, &arr) != nil {
				return nil, false
			}
			out := make([]any, 0, min(len(arr.Values), maxAnyItems))
			for _, it := range arr.Values {
				if len(out) >= maxAnyItems {
					break
				}
				if e, ok := decodeAny(it, depth+1); ok {
					out = append(out, e)
				}
			}
			return out, true
		case 5:
			if depth >= maxAnyDepth {
				return nil, false
			}
			var kv struct {
				Values kvList `json:"values"`
			}
			if json.Unmarshal(v, &kv) != nil {
				return nil, false
			}
			return decodeAttrs(kv.Values, depth+1), true
		}
		return nil, false
	}
	return nil, false
}

// decodeAttrs builds the attribute map of a record or resource. The first
// occurrence of a key wins: OTLP requires unique keys, and letting a later
// duplicate override would let a sender show one value to a collector that
// keeps the first and another to hawkbell.
func decodeAttrs(list kvList, depth int) attrs {
	out := make(attrs, min(len(list), maxAttrs))
	for _, kv := range list {
		if len(out) >= maxAttrs {
			break
		}
		k := string(kv.Key)
		if k == "" || len(k) > maxKeyLen {
			continue
		}
		if _, dup := out[k]; dup {
			continue
		}
		if v, ok := decodeAny(kv.Value, depth); ok {
			out[k] = v
		}
	}
	return out
}

// Timestamps outside this window are treated as missing. An agent's clock
// can be wrong, but a record stamped 1970 or 2200 is a bug or a forgery, and
// event ids embed the time.
var (
	minTime = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

func saneTime(t time.Time) bool {
	return !t.Before(minTime) && t.Before(maxTime)
}

func nanoTime(n flexUint) (time.Time, bool) {
	if n == 0 || uint64(n) > math.MaxInt64 {
		return time.Time{}, false
	}
	t := time.Unix(0, int64(n)).UTC()
	return t, saneTime(t)
}

// parseStamp reads the ISO 8601 "event.timestamp" attribute the agents set.
func parseStamp(s string) (time.Time, bool) {
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	t = t.UTC()
	return t, saneTime(t)
}

// embeddedObject parses a JSON object that an agent serialized into a string
// attribute (tool_parameters, tool_input, arguments, function_args). The
// text is model-influenced, so size and nesting are checked before it reaches
// the decoder. Numbers decode as float64 (no UseNumber) so toolmap.InputHash
// produces the value the hook and transcript surfaces produce.
func embeddedObject(s string) (map[string]any, bool) {
	if len(s) < 2 || len(s) > maxEmbedBytes {
		return nil, false
	}
	t := strings.TrimLeft(s, " \t\r\n")
	if t == "" || t[0] != '{' {
		return nil, false
	}
	if !depthWithin(t, maxEmbedDepth) {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(t), &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// depthWithin reports whether the bracket nesting of a JSON text stays at or
// below limit. It is a lexical scan (strings and escapes are skipped) and
// does not validate the document.
func depthWithin(s string, limit int) bool {
	depth := 0
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > limit {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}
