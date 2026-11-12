package otelrecv

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Length caps for values copied into serialized event fields. They match the
// hook dialects (internal/hookio) so the same tool call reads the same on
// both surfaces. Raw material for local detection goes to Event.Content,
// which is never serialized and is bounded by the request body cap instead.
const (
	maxID    = 256
	maxName  = 256
	maxLabel = 128
	maxList  = 512 // a label holding a comma-separated list of names
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

// cleanID normalizes an identifier-like value: control and non-printing
// characters are dropped (they are a log-forging vector downstream),
// surrounding space is trimmed and the result is capped. It reports whether
// the value was cut.
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

// field copies an identifier-like attribute into an event field and records
// a truncation under the given field name.
func field(ev *event.Event, name, value string, max int) string {
	v, cut := cleanID(value, max)
	if cut {
		ev.Truncated = appendUnique(ev.Truncated, name)
	}
	return v
}

// labelValue reduces a value to a short token over a fixed alphabet. Labels
// are serialized at every privacy tier, so they must not be able to carry
// sentences, secrets or markup: anything outside the alphabet becomes "_".
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

// setLabel sets a sanitized label, skipping empty values.
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

// setListLabel stores names as one comma-separated label. Each name is
// sanitized on its own, so a name cannot smuggle a separator, and the list is
// cut at a name boundary; "+N" at the end says how many names did not fit.
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
		sb.WriteString(itoa(int64(total - kept)))
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

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	var buf [20]byte
	i := len(buf)
	u := uint64(n)
	if neg {
		u = uint64(-n)
	}
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// splitNames splits a human-formatted list ("a, b, c" or "a,b") into names.
func splitNames(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// emailDomain returns the lower-cased domain of an address, or "". Only the
// domain is ever used: it tells a corporate account from a personal one
// without identifying the person.
func emailDomain(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[i+1:])
}
