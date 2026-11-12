package hookio_test

// What hookio's events look like after the privacy stage, and after the
// user spool that carries them there. These guard properties of the
// serialized record that only show once those stages have run.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/spool"
)

var testKey = bytes.Repeat([]byte{7}, 32)

func parseClaude(t *testing.T, payload string) *event.Event {
	t.Helper()
	d, _ := hookio.Get("claude")
	evs, _, err := d.Parse([]byte(payload), nil)
	if err != nil || len(evs) != 1 {
		t.Fatalf("parse: %v (%d events)", err, len(evs))
	}
	return evs[0]
}

// The privacy stage rounds content lengths up to a power of four outside
// the full profile ("an exact length narrows a dictionary attack on the
// value and is itself a fingerprint of short prompts") and passes
// Outcome.Error through, so the error and denial summaries must not carry
// the exact length that tool.output_len rounds. Detection context always
// uses the standard field policy, minimal profile included. (Review
// finding PP-1.)
func TestErrorSummaryLengthNotShipped(t *testing.T) {
	errText := "cat: /home/u/.config/app/token.txt: Permission denied 0" // 55 bytes: rounds to 64
	failed := parseClaude(t, `{"hook_event_name":"PostToolUseFailure","session_id":"s1","tool_name":"Bash","tool_use_id":"tu1",`+
		`"tool_input":{"command":"cat ~/.config/app/token.txt"},"error":`+strconv.Quote(errText)+`}`)
	reason := strings.Repeat("x", 23) + " would read credentials"
	denied := parseClaude(t, `{"hook_event_name":"PermissionDenied","session_id":"s1","tool_name":"Bash","tool_use_id":"tu2",`+
		`"tool_input":{"command":"ls"},"reason":`+strconv.Quote(reason)+`}`)

	for _, prof := range []privacy.Profile{privacy.ProfileMinimal, privacy.ProfileStandard} {
		p := &privacy.Policy{Profile: prof, Key: testKey}
		for _, c := range []struct {
			ev        *event.Event
			text      string
			wantError string
		}{
			{failed, errText, "tool error class:permission_denied"},
			{denied, reason, "denied class:other"},
		} {
			out, _, ok := p.Emit(c.ev)
			if !ok || out.Outcome == nil {
				t.Fatalf("%s: emit ok=%v outcome=%v", prof, ok, out.Outcome)
			}
			if out.Outcome.Error != c.wantError {
				t.Errorf("%s: outcome.error = %q, want %q", prof, out.Outcome.Error, c.wantError)
			}
			if out.Tool != nil && out.Tool.OutputLen == len(c.text) {
				t.Fatalf("%s: precondition: privacy no longer rounds output_len", prof)
			}
			b, _ := json.Marshal(out)
			if strings.Contains(string(b), "len:") {
				t.Errorf("%s: a length summary is on the wire: %s", prof, b)
			}
		}
	}
}

// On the hook path tool output reaches the privacy stage through the user
// spool, which keeps the first and last 32 KiB of an output when a record
// exceeds its line cap. The shipped output digest must still describe the
// whole output: two outputs that share head and tail must not share it,
// and it must equal what the privacy stage derives from the uncut event.
func TestOutputDigestSurvivesSpoolCut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the spool reader's ownership check uses POSIX uids")
	}
	head := strings.Repeat("h", 40<<10)
	tail := strings.Repeat("t", 40<<10)
	outputs := map[string]string{}
	mk := func(mid string) *event.Event {
		out := head + strings.Repeat(mid, 1200<<10) + tail
		outputs["tu-"+mid] = out
		return parseClaude(t, `{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"Bash","tool_use_id":"tu-`+mid+`",`+
			`"tool_input":{"command":"cat big.log"},"tool_response":{"stdout":`+strconv.Quote(out)+`,"stderr":""}}`)
	}
	a, b := mk("A"), mk("B")
	p := &privacy.Policy{Profile: privacy.ProfileStandard, Key: testKey}
	direct := map[string]string{}
	for _, e := range []*event.Event{a, b} {
		sum := sha256.Sum256([]byte(outputs[e.Tool.UseID]))
		if e.Tool.OutputSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: output_sha256 is not the digest of the whole output", e.Tool.UseID)
		}
		out, _, _ := p.Emit(e)
		direct[e.Tool.UseID] = out.Tool.OutputSHA256
	}

	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := spool.OpenWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*event.Event{a, b} {
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	uid := strconv.Itoa(os.Getuid())
	r := spool.NewReader(spool.ReaderOptions{
		Roots:      func() []spool.Root { return []spool.Root{{Dir: dir, UID: uid, User: event.User{ID: uid}}} },
		Checkpoint: filepath.Join(t.TempDir(), "cp.json"),
	})
	got, probs, err := r.Poll(t.Context())
	if err != nil || len(got) != 2 {
		t.Fatalf("poll: %v %d %v", err, len(got), probs)
	}
	shipped := map[string]string{}
	for _, e := range got {
		if e.Content == nil || len(e.Content.ToolOutput) >= len(outputs[e.Tool.UseID]) {
			t.Fatalf("precondition: the spool no longer cuts a %d-byte output", len(outputs[e.Tool.UseID]))
		}
		out, _, _ := p.Emit(e)
		if out.Tool.OutputSHA256 == "" {
			t.Fatalf("%s: no output digest shipped", e.Tool.UseID)
		}
		if out.Tool.OutputSHA256 != direct[e.Tool.UseID] {
			t.Errorf("%s: output_sha256 after the spool %s, from the uncut event %s", e.Tool.UseID, out.Tool.OutputSHA256, direct[e.Tool.UseID])
		}
		shipped[e.Tool.UseID] = out.Tool.OutputSHA256
	}
	if shipped["tu-A"] == shipped["tu-B"] {
		t.Errorf("two different tool outputs ship the same output_sha256 %s", shipped["tu-A"])
	}
}
