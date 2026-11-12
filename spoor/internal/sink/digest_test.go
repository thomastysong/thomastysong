package sink

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// assertNoDigestOf fails when line carries anything a reader could use to
// confirm a guess about full: the head of a common unkeyed digest of it in
// hex, or the label key that once held one.
func assertNoDigestOf(t *testing.T, line []byte, full string) {
	t.Helper()
	text := strings.ToLower(string(line))
	if strings.Contains(text, "command.sha256") {
		t.Errorf("a command digest label reached the line: %.200s", line)
	}
	b := []byte(full)
	s256, s512, s1, m5 := sha256.Sum256(b), sha512.Sum512(b), sha1.Sum(b), md5.Sum(b)
	for name, sum := range map[string][]byte{"sha256": s256[:], "sha512": s512[:], "sha1": s1[:], "md5": m5[:]} {
		// Four bytes are already a usable oracle against a dictionary.
		if h := hex.EncodeToString(sum[:4]); strings.Contains(text, h) {
			t.Errorf("the line carries the head of the %s of the full command (%s)", name, h)
		}
	}
}

// Whatever path the shrinker takes, the full command is described by its
// length only: an unkeyed digest of it would let a log reader recover the
// cut tail by hashing guesses.
func TestShrinkShipsNoDigestOfCutCommand(t *testing.T) {
	const max = 8 << 10
	// The tail holds what a guesser is after; the head is ordinary.
	secretTail := "sk-" + strings.Repeat("Q7", 20)
	cmd := "deploy --verbose " + strings.Repeat("x", 30000) + " --token " + secretTail
	type tc struct {
		max int
		mk  func() *event.Event
	}
	cases := map[string]tc{
		// Step 2: only the command is large.
		"command_tail": {max, func() *event.Event {
			e := testEvent("tail", 0)
			e.Target.Command = cmd
			return e
		}},
		// Step 3: other fields are large too, so the general passes cut
		// the command along with them.
		"general_passes": {max, func() *event.Event {
			e := testEvent("passes", 0)
			e.Target.Command = cmd
			e.Target.Paths = make([]string, 400)
			for i := range e.Target.Paths {
				e.Target.Paths[i] = fmt.Sprintf("/srv/%04d/%s", i, strings.Repeat("p", 60))
			}
			e.Outcome = &event.Outcome{Error: strings.Repeat("e", 9000)}
			return e
		}},
		// Step 4: a limit only the identity skeleton fits under.
		"skeleton": {1536, func() *event.Event {
			e := testEvent("skel", 0)
			e.Target.Command = cmd
			e.Labels = map[string]string{}
			for i := 0; i < 2000; i++ {
				e.Labels[fmt.Sprintf("k%05d", i)] = strings.Repeat("v", 200)
			}
			return e
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, f := range []string{FormatNative, FormatOCSF} {
				e := c.mk()
				line, err := fitLine(e, f, c.max)
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				if len(line) > c.max {
					t.Fatalf("%s: line is %d bytes", f, len(line))
				}
				if name == "skeleton" && f == FormatNative && !strings.Contains(string(line), `"truncated":["*"]`) {
					t.Errorf("expected the skeleton: %.200s", line)
				}
				assertNoDigestOf(t, line, cmd)
				if strings.Contains(string(line), secretTail) {
					t.Errorf("%s: the cut tail itself was kept", f)
				}
			}
		})
	}
}

// The length label replaces the old digest label: present when the command
// was cut, absent when it was not, and identical for every writer process.
func TestCommandLengthLabel(t *testing.T) {
	const max = 8 << 10
	e := testEvent("len", 0)
	e.Target.Command = "make " + strings.Repeat("y", 20000)
	line, err := fitLine(e, FormatNative, max)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeLine(t, line)
	if got.Labels[LabelCommandLen] != fmt.Sprint(len(e.Target.Command)) {
		t.Errorf("length label = %q, want %d", got.Labels[LabelCommandLen], len(e.Target.Command))
	}
	again, err := fitLine(e, FormatNative, max)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(line) {
		t.Error("shrinking the same event twice gave different lines")
	}

	short := testEvent("short", 64)
	line, err = fitLine(short, FormatNative, max)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeLine(t, line); got.Labels[LabelCommandLen] != "" {
		t.Errorf("an uncut command got a length label: %v", got.Labels)
	}
}
