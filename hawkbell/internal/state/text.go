package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TimeFormat is the layout of every timestamp column: RFC 3339 in UTC with a
// six-digit fraction, always 27 characters, so text comparison orders them
// correctly (ATC columns are TEXT).
const TimeFormat = event.TimeLayout

// Limits on stored text. Values originate in files and process tables the
// monitored user controls, and every byte stored is a byte osquery loads on
// each ATC query.
const (
	maxID    = 128
	maxName  = 256
	maxText  = 512
	maxPath  = 1024
	maxList  = 1024
	maxItems = 64
)

// futureSlack is how far ahead of the local clock a timestamp may be before
// it is treated as wrong. A far-future time would never age out and would
// always sort as newest, pinning a hostile row in a capped table.
const futureSlack = 5 * time.Minute

// FormatTime renders t as a timestamp column value: TimeFormat in UTC, or the
// empty string for the zero time and for years outside 1970..9999, which
// would break the fixed width.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	t = t.UTC()
	if y := t.Year(); y < 1970 || y > 9999 {
		return ""
	}
	return t.Format(TimeFormat)
}

// stamp formats an event time, substituting now when it is unset, malformed
// or implausibly far in the future.
func stamp(t time.Time, now time.Time) string {
	if t.IsZero() || t.After(now.Add(futureSlack)) {
		t = now
	}
	if s := FormatTime(t); s != "" {
		return s
	}
	return FormatTime(now)
}

// optStamp is stamp for optional times: the zero time stays empty.
func optStamp(t time.Time, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	return stamp(t, now)
}

// SessionRef is the only form in which a session is identified in the state
// database: the first 16 hex digits of SHA-256 over user id, agent id and
// the agent's session id. The same three inputs must be used by every
// writer for the tables to join. An empty session id gives an empty ref.
func SessionRef(userID, agentID, sessionID string) string {
	if sessionID == "" {
		return ""
	}
	h := sha256.New()
	for _, p := range []string{userID, agentID, sessionID} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// clip returns s as valid UTF-8 without control or invisible formatting
// characters, at most max bytes long (cut on a rune boundary).
func clip(s string, max int) string {
	if len(s) <= max && isPlain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(min(len(s), max))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if (r == utf8.RuneError && size <= 1) || !printable(r) {
			r = utf8.RuneError
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			// Non-ASCII takes the slow path, which validates it.
			return false
		}
	}
	return true
}

// printable rejects what must not reach an operator's table or a log line:
// control characters, and the invisible bidirectional and zero-width
// characters that make one name render as another.
func printable(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return false
	case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return false
	case r == 0x2028, r == 0x2029, r == 0xfeff, r == 0x061c:
		return false
	}
	return true
}

// joinList renders a list column: cleaned items separated by commas. A comma
// inside an item (possible in attacker-chosen names such as environment
// variable keys) is replaced so it cannot forge an extra element. When the
// list is cut, the last element is "..." so truncation is visible.
func joinList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, it := range items {
		it = strings.ReplaceAll(clip(strings.TrimSpace(it), maxName), ",", "�")
		if it == "" {
			continue
		}
		if n >= maxItems || b.Len()+len(it)+5 > maxList {
			b.WriteString(",...")
			break
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(it)
		n++
	}
	return b.String()
}

// baseName returns the last path element for either separator, so a Windows
// path stored by a scan of a mounted image is handled on any OS.
func baseName(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// fingerprint digests the descriptive values of a row so a later write can
// tell whether anything an operator would care about changed.
func fingerprint(vals ...any) string {
	h := sha256.New()
	for _, v := range vals {
		fmt.Fprintf(h, "%v\x00", v)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// userOf returns the account name to show and the id to key on. Either may
// be all an event carries, so each falls back to the other.
func userOf(u *event.User) (name, id string) {
	if u == nil {
		return "", ""
	}
	name, id = clip(u.Name, maxName), clip(u.ID, maxName)
	if name == "" {
		name = id
	}
	if id == "" {
		id = name
	}
	return name, id
}
