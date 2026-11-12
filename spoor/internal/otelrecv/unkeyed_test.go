package otelrecv

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

// noFingerprint fails when the serialized event carries a prefix of an
// unkeyed SHA-256 of text, or the "fp:" summary form this package used to
// write for error text.
func noFingerprint(t *testing.T, ev *event.Event, text string) {
	t.Helper()
	w := wire(t, ev)
	sum := sha256.Sum256([]byte(text))
	if strings.Contains(w, "fp:") || strings.Contains(w, hex.EncodeToString(sum[:])[:6]) {
		t.Errorf("fingerprint of %q on the wire: %s", text, w)
	}
	if strings.Contains(w, text) {
		t.Errorf("text %q on the wire: %s", text, w)
	}
}

// An error without a category is summarized by a closed-vocabulary class
// and its byte length, never by a hash of the message, on every agent.
func TestErrorWithoutCategoryHasNoFingerprint(t *testing.T) {
	cases := []struct {
		name, msg, class string
		body             func(msg string) []byte
	}{
		{"claude tool_result", "ENOENT: no such file /home/dev/.aws/credentials", hookio.ErrClassNotFound, func(msg string) []byte {
			return otlpBody(claudeRes, "", claudeRec("tool_result", kv{
				"tool_name": "Read", "tool_use_id": "toolu_e1", "success": "false", "error": msg,
			}))
		}},
		{"claude mcp connection", "connect ECONNREFUSED 127.0.0.1:7777 token=abc", hookio.ErrClassNetwork, func(msg string) []byte {
			return otlpBody(claudeRes, "", claudeRec("mcp_server_connection", kv{
				"status": "failed", "transport_type": "stdio", "error": msg,
			}))
		}},
		{"gemini tool_call", "Command timed out after 120s: curl https://paste.example/x", hookio.ErrClassTimeout, func(msg string) []byte {
			return otlpBody(geminiRes, "", geminiRec("tool_call", "", kv{
				"function_name": "run_shell_command", "success": false, "tool_type": "native", "error": msg,
			}))
		}},
		{"gemini error.message", "hunter2 was rejected", hookio.ErrClassRejected, func(msg string) []byte {
			return otlpBody(geminiRes, "", geminiRec("tool_call", "", kv{
				"function_name": "read_file", "success": false, "tool_type": "native", "error.message": msg,
			}))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustConvert(t, c.body(c.msg))
			var ev *event.Event
			for _, e := range res.Events {
				if e.Outcome != nil && e.Outcome.Error != "" {
					ev = e
				}
			}
			if ev == nil {
				t.Fatalf("no event with an error among %d", len(res.Events))
			}
			checkInvariants(t, ev)
			eq(t, "error", ev.Outcome.Error, "tool error class:"+c.class+" len:"+strconv.Itoa(len(c.msg)))
			eq(t, "same summary as the hook surface", ev.Outcome.Error, hookio.ErrorSummary(c.msg))
			if ev.Content == nil || ev.Content.ToolOutput != c.msg {
				t.Errorf("message not kept for local detection: %+v", ev.Content)
			}
			noFingerprint(t, ev, c.msg)
		})
	}
}

// unkeyedRecordKey is the formula recordKey used before it was keyed.
func unkeyedRecordKey(lr *logRecord, a attrs) string {
	h := sha256.New()
	b, _ := json.Marshal(map[string]any(a))
	h.Write(b)
	h.Write([]byte{0})
	h.Write(lr.Body)
	fmt.Fprintf(h, "\x00%d", uint64(lr.TimeUnixNano)|uint64(lr.TimeUnixNanoSnake))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func firstRecord(t *testing.T, body []byte) (*logRecord, attrs) {
	t.Helper()
	req, err := decodeRequest(body)
	if err != nil || len(req.ResourceLogs) == 0 || len(req.ResourceLogs[0].ScopeLogs) == 0 || len(req.ResourceLogs[0].ScopeLogs[0].LogRecords) == 0 {
		t.Fatalf("decode: %v", err)
	}
	lr := &req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	return lr, decodeAttrs(lr.Attributes, 0)
}

// The event id derives from the whole record, prompt text included. It is
// keyed with a per-process secret, so holding a record does not let anyone
// test guesses of the text against its id.
func TestRecordKeyIsKeyed(t *testing.T) {
	prompt := func(text string) []byte {
		return otlpBody(claudeRes, "", claudeRec("user_prompt", kv{"prompt": text, "prompt_length": len(text)}))
	}
	body := prompt("deploy with the key in ~/.aws")
	lr, a := firstRecord(t, body)
	key := recordKey(lr, a)
	if len(key) != 32 {
		t.Fatalf("key %q", key)
	}
	if key == unkeyedRecordKey(lr, a) {
		t.Fatal("record key is the unkeyed hash of the record")
	}
	// The secret is fixed for the process: a retried export gets the same
	// ids, and different text different ones.
	eq(t, "stable within the process", recordKey(lr, a), key)
	secret := recordSecret()
	if len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) || !bytes.Equal(recordSecret(), secret) {
		t.Fatalf("secret %x", secret)
	}
	m := hmac.New(sha256.New, secret)
	b, _ := json.Marshal(map[string]any(a))
	m.Write(b)
	m.Write([]byte{0})
	m.Write(lr.Body)
	fmt.Fprintf(m, "\x00%d", uint64(lr.TimeUnixNano)|uint64(lr.TimeUnixNanoSnake))
	eq(t, "definition", key, hex.EncodeToString(m.Sum(nil)[:16]))

	ev := one(t, body)
	eq(t, "retry id", one(t, body).ID, ev.ID)
	if other := one(t, prompt("deploy with the key in ~/.ssh")); other.ID == ev.ID {
		t.Error("records differing only in prompt text share an id")
	}
	// An id computed the old way from a guessed text does not match.
	guess := event.StableID(ev.TS.Time, "otel", "claude-code", "claude_code.user_prompt", ev.Type, unkeyedRecordKey(lr, a))
	if guess == ev.ID {
		t.Fatal("id is reproducible without the secret")
	}

	// Another process (another secret) derives other ids from the same record.
	saved := recordSecret
	defer func() { recordSecret = saved }()
	recordSecret = func() []byte { return bytes.Repeat([]byte{1}, 32) }
	if one(t, body).ID == ev.ID {
		t.Error("id does not depend on the secret")
	}
}
