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

// rawString returns raw decoded as a JSON string, or "" when it is not one.
func rawString(raw json.RawMessage) string {
	if rawKind(raw) != '"' {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
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

// textDepth bounds how deep textOf looks into nested arrays. Real content
// nests at most twice (a list of blocks whose content is a list of blocks);
// the bound keeps a hostile, deeply nested value from being rescanned once
// per level.
const textDepth = 3

// textOf flattens a message body to text: a string, an object with a "text"
// field, or an array of either. Images and unknown shapes yield nothing.
func textOf(raw json.RawMessage) string { return textOfDepth(raw, textDepth) }

func textOfDepth(raw json.RawMessage, depth int) string {
	switch rawKind(raw) {
	case '"':
		return rawString(raw)
	case '{':
		var b struct {
			Text    json.RawMessage `json:"text"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &b) != nil {
			return ""
		}
		if s := rawString(b.Text); s != "" {
			return s
		}
		if depth > 0 && rawKind(b.Content) != 0 {
			return textOfDepth(b.Content, depth-1)
		}
		return ""
	case '[':
		if depth == 0 {
			return ""
		}
		var blocks []json.RawMessage
		if json.Unmarshal(raw, &blocks) != nil {
			return ""
		}
		var parts []string
		for _, b := range blocks {
			if t := textOfDepth(b, depth-1); t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

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

// rustDuration decodes a serde-serialized std::time::Duration
// ({"secs":1,"nanos":5}) to milliseconds.
func rustDuration(raw json.RawMessage) int64 {
	var d struct {
		Secs  float64 `json:"secs"`
		Nanos float64 `json:"nanos"`
	}
	if rawKind(raw) != '{' || json.Unmarshal(raw, &d) != nil {
		return 0
	}
	ms := d.Secs*1000 + d.Nanos/1e6
	if ms < 0 || ms > 1e15 {
		return 0
	}
	return int64(ms)
}
