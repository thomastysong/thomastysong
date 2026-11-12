package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// decode unmarshals data into v. A field of an unexpected JSON type is
// skipped rather than failing the record: session log schemas drift, and one
// renamed or retyped field must not hide the rest of the line. Only JSON
// that does not parse at all is an error.
func decode(data []byte, v any) error {
	err := json.Unmarshal(data, v)
	if err == nil {
		return nil
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return nil
	}
	return errSyntax
}

// rawKind returns the first significant byte of a JSON value: '"', '{', '[',
// 't', 'f', 'n', a digit or '-', or 0 for an absent value.
func rawKind(raw json.RawMessage) byte {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 {
		return 0
	}
	return raw[0]
}

// rawObject returns raw decoded as a JSON object, or nil when it is not one.
func rawObject(raw json.RawMessage) map[string]any {
	if rawKind(raw) != '{' {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// textDepth bounds how deep anyText looks into nested values. Real content
// nests at most twice (a list of blocks whose content is a list of blocks);
// the bound keeps a hostile, deeply nested value from being rescanned once
// per level.
const textDepth = 3

// parseTime accepts the RFC 3339 forms the agents write. Anything else is
// the zero time, which callers treat as "no timestamp on this record".
func parseTime(s string) time.Time {
	if s == "" || len(s) > 64 {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	// A bare local form without zone ("2026-08-11T13:27:08.788").
	if t, err := time.Parse("2006-01-02T15:04:05.999999999", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// firstLine returns the first line of s, at most n bytes of it.
func firstLine(s string, n int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clip(strings.TrimRight(s, "\r"), n)
}

// head returns at most n bytes of s, for bounded pattern scans.
func head(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// exitCodeAfter finds "<marker><int>" at the start of a line within s and
// returns the integer. last selects the final occurrence instead of the
// first (a command can print the marker itself; the tool appends the real
// one at the end).
func exitCodeAfter(s string, last bool, markers ...string) (int, bool) {
	found := false
	code := 0
	for len(s) > 0 {
		line := s
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			line, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		for _, m := range markers {
			rest, ok := strings.CutPrefix(line, m)
			if !ok {
				continue
			}
			rest = strings.TrimSpace(rest)
			end := 0
			for end < len(rest) && (rest[end] == '-' && end == 0 || rest[end] >= '0' && rest[end] <= '9') {
				end++
			}
			if n, err := strconv.Atoi(rest[:end]); err == nil && end <= 11 {
				code, found = n, true
				if !last {
					return code, true
				}
			}
		}
	}
	return code, found
}

func intPtr(n int) *int { return &n }

// The parsers decode each line once, into a typed envelope whose polymorphic
// parts are `any`. The helpers below read those generic values without
// re-parsing; every recursive one is depth-bounded because encoding/json
// accepts nesting up to 10,000 levels.

func anyString(v any) string {
	s, _ := v.(string)
	return s
}

func anyObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func anyBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// anyInt returns v as an int when it is a JSON number with an integral value
// in a sane range.
func anyInt(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) || f > 1<<31 || f < -(1<<31) {
		return 0, false
	}
	return int(f), true
}

// anyText flattens a decoded message body to text: a string, an object with
// a "text" field (or a nested "content"), or an array of either.
func anyText(v any) string { return anyTextDepth(v, textDepth) }

func anyTextDepth(v any, depth int) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["text"].(string); ok && s != "" {
			return s
		}
		if c, ok := t["content"]; ok && depth > 0 {
			return anyTextDepth(c, depth-1)
		}
	case []any:
		if depth == 0 {
			return ""
		}
		if len(t) == 1 {
			return anyTextDepth(t[0], depth-1)
		}
		var parts []string
		for _, b := range t {
			if s := anyTextDepth(b, depth-1); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// anyContains reports whether needle occurs in any string within v, looking
// at most depth levels down and at a bounded number of values.
func anyContains(v any, needle string, depth int, budget *int) bool {
	if *budget <= 0 {
		return false
	}
	*budget--
	switch t := v.(type) {
	case string:
		return strings.Contains(t, needle)
	case map[string]any:
		if depth == 0 {
			return false
		}
		for k, e := range t {
			if strings.Contains(k, needle) || anyContains(e, needle, depth-1, budget) {
				return true
			}
		}
	case []any:
		if depth == 0 {
			return false
		}
		for _, e := range t {
			if anyContains(e, needle, depth-1, budget) {
				return true
			}
		}
	}
	return false
}

// anyDuration decodes a serde-serialized std::time::Duration
// ({"secs":1,"nanos":5}) to milliseconds.
func anyDuration(v any) int64 {
	m := anyObject(v)
	if m == nil {
		return 0
	}
	secs, _ := m["secs"].(float64)
	nanos, _ := m["nanos"].(float64)
	ms := secs*1000 + nanos/1e6
	if !(ms >= 0 && ms <= 1e15) {
		return 0
	}
	return int64(ms)
}
