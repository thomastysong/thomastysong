package otelrecv

import (
	"math"
	"strconv"
	"strings"
)

// attrs is the decoded attribute set of a log record or resource. Values are
// string, bool, int64, float64, []any or map[string]any (see decodeAny).
//
// The accessors are deliberately loose about types. The agents' exporters
// disagree with their own documentation on them: Claude Code documents
// success as the string "true" and duration_ms as a number, Codex formats
// most fields through Display (so numbers and booleans arrive as strings),
// and Gemini CLI sends real booleans and numbers. A value of an unusable
// type reads as absent, never as an error.
type attrs map[string]any

// str returns the first non-empty value among keys as a string. Numbers and
// booleans are rendered, because ids and counters may arrive as either.
func (a attrs) str(keys ...string) string {
	for _, k := range keys {
		switch v := a[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case int64:
			return strconv.FormatInt(v, 10)
		case float64:
			if v == math.Trunc(v) && math.Abs(v) < 1e15 {
				return strconv.FormatInt(int64(v), 10)
			}
			return strconv.FormatFloat(v, 'g', -1, 64)
		case bool:
			return strconv.FormatBool(v)
		}
	}
	return ""
}

// text returns the first string-typed value among keys, empty included.
func (a attrs) text(keys ...string) (string, bool) {
	for _, k := range keys {
		if s, ok := a[k].(string); ok {
			return s, true
		}
	}
	return "", false
}

func (a attrs) has(key string) bool {
	_, ok := a[key]
	return ok
}

// boolean reads a bool or the strings "true"/"false" (any case).
func (a attrs) boolean(keys ...string) (value, ok bool) {
	for _, k := range keys {
		switch v := a[k].(type) {
		case bool:
			return v, true
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true":
				return true, true
			case "false":
				return false, true
			}
		}
	}
	return false, false
}

// integer reads an int64, an integral or fractional float (truncated), or a
// decimal string.
func (a attrs) integer(keys ...string) (int64, bool) {
	for _, k := range keys {
		switch v := a[k].(type) {
		case int64:
			return v, true
		case float64:
			if !math.IsNaN(v) && math.Abs(v) < 1<<62 {
				return int64(v), true
			}
		case string:
			s := strings.TrimSpace(v)
			if s == "" || len(s) > 32 {
				continue
			}
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				return n, true
			}
			if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && math.Abs(f) < 1<<62 {
				return int64(f), true
			}
		}
	}
	return 0, false
}

// count reads a non-negative integer that fits an int.
func (a attrs) count(keys ...string) (int, bool) {
	n, ok := a.integer(keys...)
	if !ok || n < 0 || n > math.MaxInt32 {
		return 0, false
	}
	return int(n), true
}

// names reads a list of names: an array of strings, or one string holding a
// comma-separated list (Codex and Gemini CLI join their MCP server names).
func (a attrs) names(key string) []string {
	switch v := a[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitNames(v)
	}
	return nil
}

// strOf reads a string member of a decoded JSON object.
func strOf(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// truthy reads a boolean member of a decoded JSON object, accepting the
// string spellings as well.
func truthy(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}
