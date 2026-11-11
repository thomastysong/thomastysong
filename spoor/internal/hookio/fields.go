package hookio

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Length caps for values copied into serialized event fields. Identifiers
// and names are short by nature; anything longer is abuse or a bug, and the
// cut is recorded in Event.Truncated.
const (
	maxID    = 256
	maxName  = 256
	maxPath  = 4096
	maxLabel = 128
	maxKeys  = 64
)

// obj is a decoded JSON object with accessors that treat a missing key and a
// value of the wrong type the same way, so a hostile or drifted payload can
// only lose fields, never crash the parser.
type obj map[string]any

func (o obj) has(key string) bool {
	_, ok := o[key]
	return ok
}

// raw returns the first present, non-null value among keys.
func (o obj) raw(keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := o[k]; ok && v != nil {
			return v, true
		}
	}
	return nil, false
}

// str returns the first non-empty string among keys. Integral numbers are
// accepted too, because some agents emit numeric ids.
func (o obj) str(keys ...string) string {
	for _, k := range keys {
		switch v := o[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			if v == math.Trunc(v) && math.Abs(v) < 1e15 {
				return strconv.FormatInt(int64(v), 10)
			}
		}
	}
	return ""
}

func (o obj) isString(key string) bool {
	_, ok := o[key].(string)
	return ok
}

func (o obj) isObject(key string) bool {
	_, ok := o[key].(map[string]any)
	return ok
}

// sub returns the first object-valued key, or an empty obj.
func (o obj) sub(keys ...string) obj {
	for _, k := range keys {
		if m, ok := o[k].(map[string]any); ok {
			return obj(m)
		}
	}
	return obj{}
}

func (o obj) arr(keys ...string) []any {
	for _, k := range keys {
		if a, ok := o[k].([]any); ok {
			return a
		}
	}
	return nil
}

func (o obj) boolean(keys ...string) (value, ok bool) {
	for _, k := range keys {
		if b, isBool := o[k].(bool); isBool {
			return b, true
		}
	}
	return false, false
}

func (o obj) num(keys ...string) (float64, bool) {
	for _, k := range keys {
		if f, ok := o[k].(float64); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	}
	return 0, false
}

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

// cleanID normalizes an identifier-like value: control and other
// non-printing characters are dropped (they have no place in an id and are a
// log-forging vector downstream), surrounding space is trimmed and the result
// is capped. It reports whether the value was cut.
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

// field copies an identifier-like payload value into an event field and
// records a truncation under the given field name.
func field(ev *event.Event, name, value string, max int) string {
	v, cut := cleanID(value, max)
	if cut {
		ev.Truncated = appendUnique(ev.Truncated, name)
	}
	return v
}

// pathField copies a path. Paths are kept byte-for-byte (detection must see
// traversal sequences and odd characters exactly as the agent will resolve
// them); only NUL is dropped and the length capped.
func pathField(ev *event.Event, name, value string) string {
	if strings.IndexByte(value, 0) >= 0 {
		value = strings.ReplaceAll(value, "\x00", "")
	}
	v, cut := cutUTF8(value, maxPath)
	if cut {
		ev.Truncated = appendUnique(ev.Truncated, name)
	}
	return v
}

// labelValue reduces a payload value to a safe label: a short token over a
// fixed alphabet. Labels are serialized at every privacy tier, so they must
// not be able to carry sentences, secrets or markup.
func labelValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s, _ = cutUTF8(s, maxLabel)
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

// label sets a sanitized label, skipping empty values.
func label(ev *event.Event, key, value string) {
	v := labelValue(value)
	if v == "" {
		return
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	ev.Labels[key] = v
}

// labelPath sets a label whose value is a filesystem path (kept verbatim
// apart from control characters, capped like any other path).
func labelPath(ev *event.Event, key, value string) {
	v, _ := cleanID(value, maxPath)
	if v == "" {
		return
	}
	if ev.Labels == nil {
		ev.Labels = map[string]string{}
	}
	ev.Labels[key] = v
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// envGet reads the first non-empty variable; a nil map is fine.
func envGet(env map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := env[k]; v != "" {
			return v
		}
	}
	return ""
}

// oneLine flattens free text to a single printable line of at most max
// bytes. It is used for text spoor itself sends to an agent (reasons), never
// for payload content.
func oneLine(s string, max int) string {
	var sb strings.Builder
	sb.Grow(len(s))
	space := false
	for _, r := range s {
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
