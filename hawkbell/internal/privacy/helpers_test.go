package privacy

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// testKey is a synthetic tenant key.
var testKey = []byte("0123456789abcdef-test-tenant-key")

// rnd returns n deterministic random alphanumerics that contain none of
// classify's placeholder substrings, so pattern detectors treat the value
// as a real credential.
func rnd(seed int64, n int) string {
	r := rand.New(rand.NewSource(seed))
	const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	for {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[r.Intn(len(alpha))]
		}
		s := string(b)
		bad := false
		for _, p := range []string{"example", "abcdefg", "1234567", "xxxx", "fake", "dummy", "sample", "test", "insert", "here"} {
			if strings.Contains(strings.ToLower(s), p) {
				bad = true
			}
		}
		if !bad {
			return s
		}
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// unkeyedMarkerRe matches classify's marker with an unkeyed fingerprint,
// which must never be emitted.
var unkeyedMarkerRe = regexp.MustCompile(`\[REDACTED:[a-z0-9_]+:[0-9a-f]{8}\]`)

func line(t *testing.T, e *event.Event) string {
	t.Helper()
	if e == nil {
		return ""
	}
	b, err := e.MarshalLine()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func activity(typ string) *event.Event {
	e := event.New(event.KindActivity, typ, event.SourceHook)
	e.Host = &event.Host{ID: "host-1", Name: "ws-17", OS: "linux", Arch: "amd64"}
	e.User = &event.User{Name: "bob", ID: "1000"}
	e.Agent = &event.Agent{ID: "claude-code", Version: "2.1.0"}
	e.Session = &event.Session{ID: "sess-1", CWD: "/home/bob/work/acme", Transcript: "/home/bob/.claude/projects/x/sess-1.jsonl"}
	return e
}

func shellEvent(cmd string) *event.Event {
	e := activity(event.TypeToolPre)
	e.Tool = &event.Tool{Name: "Bash", Kind: event.ToolShell}
	e.Target = &event.Target{Command: cmd}
	e.Content = &event.Content{ToolInput: map[string]any{"command": cmd}}
	return e
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// nestedMarkerRe matches a marker inside a marker.
var nestedMarkerRe = regexp.MustCompile(`\[REDACTED:(?:[a-z0-9_]+:)?(?:hmac=)?\[REDACTED`)
