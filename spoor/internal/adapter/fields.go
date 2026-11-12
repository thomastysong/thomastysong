package adapter

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Length caps for values copied into serialized event fields; the same as
// the hook dialects use, so a converted record reads like a native one.
const (
	maxID       = 256
	maxName     = 256
	maxPath     = 4096
	maxLabel    = 128
	maxList     = 512
	maxEvidence = 1024 // one value in Detection.Evidence
	maxIDs      = 64   // ids kept in a list (cited events, findings, rules)
)

// cutUTF8 shortens s to at most max bytes without splitting a rune.
func cutUTF8(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// cleanID drops control and non-printing characters from an identifier-like
// value, trims it and caps it. It reports whether the value was cut.
func cleanID(s string, max int) (string, bool) {
	if s == "" {
		return "", false
	}
	clean := true
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || !unicode.IsPrint(r) {
			clean = false
			break
		}
	}
	if !clean {
		var sb strings.Builder
		sb.Grow(len(s))
		for _, r := range s {
			if r == utf8.RuneError || unicode.IsControl(r) || !unicode.IsPrint(r) {
				continue
			}
			sb.WriteRune(r)
		}
		s = sb.String()
	}
	return cutUTF8(strings.TrimSpace(s), max)
}

// field copies an identifier-like value into an event field and records a
// truncation under the given field name.
func field(ev *event.Event, name, value string, max int) string {
	v, cut := cleanID(value, max)
	if cut {
		ev.Truncated = appendUnique(ev.Truncated, name)
	}
	return v
}

// pathField copies a path byte-for-byte apart from NUL: detection must see
// traversal sequences and odd characters as the agent will resolve them.
func pathField(ev *event.Event, name, value string) string {
	if strings.IndexByte(value, 0) >= 0 {
		value = strings.ReplaceAll(value, "\x00", "")
	}
	v, cut := cutUTF8(strings.ToValidUTF8(value, "�"), maxPath)
	if cut {
		ev.Truncated = appendUnique(ev.Truncated, name)
	}
	return v
}

// oneLine flattens text to a single printable line of at most max bytes.
func oneLine(s string, max int) string {
	var sb strings.Builder
	sb.Grow(min(len(s), max+8))
	space := false
	for _, r := range s {
		if sb.Len() > max {
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			space = true
			continue
		}
		if space && sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		space = false
		sb.WriteRune(r)
	}
	out, _ := cutUTF8(sb.String(), max)
	return out
}

// labelValue reduces a value to a short token over a fixed alphabet. Labels
// are serialized at every privacy tier, so they must not be able to carry
// sentences, secrets or markup.
func labelValue(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s, _ = cutUTF8(s, max)
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.', r == ':', r == '/', r == '@', r == '+':
			sb.WriteRune(r)
		default:
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

func setLabel(ev *event.Event, key, value string) {
	v := labelValue(value, maxLabel)
	if v == "" {
		return
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	ev.Labels[key] = v
}

// setListLabel stores names as one comma-separated label, each sanitized on
// its own and the list cut at a name boundary; a trailing "+N" says how many
// did not fit.
func setListLabel(ev *event.Event, key string, items []string) {
	var sb strings.Builder
	kept, total := 0, 0
	for _, it := range items {
		v := labelValue(it, maxLabel)
		if v == "" {
			continue
		}
		total++
		if sb.Len()+len(v)+1 > maxList-8 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(v)
		kept++
	}
	if sb.Len() == 0 {
		return
	}
	if total > kept {
		sb.WriteString(",+")
		sb.WriteString(strconv.Itoa(total - kept))
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	ev.Labels[key] = sb.String()
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// The lenient scalar types below make the typed decode immune to drift and
// to hostile values: a member of the wrong JSON type reads as absent instead
// of failing the whole record, which would turn one odd field into a way to
// hide a record from spoor.

// lstr accepts a string; a number is rendered (ids are sometimes numeric);
// anything else reads as "".
type lstr string

func (s *lstr) UnmarshalJSON(b []byte) error {
	*s = ""
	if len(b) == 0 {
		return nil
	}
	switch c := b[0]; {
	case c == '"':
		var v string
		if json.Unmarshal(b, &v) == nil {
			*s = lstr(v)
		}
	case c == '-' || (c >= '0' && c <= '9'):
		if len(b) <= 32 {
			*s = lstr(b)
		}
	}
	return nil
}

// lint accepts an integral JSON number or a decimal string.
type lint struct {
	v  int64
	ok bool
}

func (n *lint) UnmarshalJSON(b []byte) error {
	*n = lint{}
	s := strings.Trim(string(b), `"`)
	if s == "" || len(s) > 32 {
		return nil
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*n = lint{v, true}
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == math.Trunc(f) && math.Abs(f) < 1<<62 {
		*n = lint{int64(f), true}
	}
	return nil
}

// lbool accepts true or false.
type lbool struct{ v, ok bool }

func (l *lbool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true":
		*l = lbool{true, true}
	case "false":
		*l = lbool{false, true}
	default:
		*l = lbool{}
	}
	return nil
}

// lstrs accepts an array and keeps its string elements, at most maxIDs.
type lstrs []string

func (l *lstrs) UnmarshalJSON(b []byte) error {
	*l = nil
	if len(b) == 0 || b[0] != '[' {
		return nil
	}
	var raw []json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := make([]string, 0, min(len(raw), maxIDs))
	for _, r := range raw {
		if len(out) >= maxIDs {
			break
		}
		var s string
		if len(r) > 0 && r[0] == '"' && json.Unmarshal(r, &s) == nil && s != "" {
			out = append(out, s)
		}
	}
	*l = out
	return nil
}

// Timestamps outside this window are treated as missing.
var (
	minTime = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

func parseTime(s string) (time.Time, bool) {
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	t = t.UTC()
	return t, !t.Before(minTime) && t.Before(maxTime)
}

// depthWithin reports whether the bracket nesting of a JSON text stays at or
// below limit (a lexical scan; it does not validate the document).
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
