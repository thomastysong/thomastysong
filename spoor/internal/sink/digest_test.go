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

// truncTail parses the "[TRUNCATED:<n>B]" marker a cut value ends in.
func truncTail(s string) (n int, ok bool) {
	i := strings.LastIndex(s, "[TRUNCATED:")
	if i < 0 || !strings.HasSuffix(s, "B]") {
		return 0, false
	}
	_, err := fmt.Sscanf(s[i:], "[TRUNCATED:%dB]", &n)
	return n, err == nil
}

// The event contract (event.Event.Truncated): a cut value ends in a
// "[TRUNCATED:<n>B]" marker stating how many bytes went, except
// target.command, whose full length is in Labels instead, and no digest
// of the cut text is kept. The general passes and the skeleton used to cut
// without a marker, and the skeleton dropped the command's length.
func TestShrinkCutsCarryContractMarker(t *testing.T) {
	big := strings.Repeat("A", 30000)
	cmd := "make " + strings.Repeat("y", 30000)
	e := kindEvent(event.KindDetection, "mark")
	e.Target.Command = cmd
	e.Prompt = &event.Prompt{Text: big}
	e.Outcome = &event.Outcome{Status: "error", Error: big}
	e.Labels["blob"] = big
	line, err := fitLine(e, FormatNative, 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeLine(t, line)
	if has(got.Truncated, "*") {
		t.Fatalf("needed the skeleton: %v", got.Truncated)
	}
	for name, v := range map[string]string{"prompt.text": got.Prompt.Text, "outcome.error": got.Outcome.Error, "labels.blob": got.Labels["blob"]} {
		n, ok := truncTail(v)
		if !ok || len(v) > 4096 {
			t.Errorf("%s: %d bytes, no contract marker: %.40q", name, len(v), v[max(0, len(v)-40):])
			continue
		}
		if head := v[:strings.LastIndex(v, "[TRUNCATED:")]; len(head)+n != len(big) || !strings.HasPrefix(big, head) {
			t.Errorf("%s: marker says %d bytes cut, head is %d of %d", name, n, len(head), len(big))
		}
	}
	if _, ok := truncTail(got.Target.Command); ok || !strings.HasPrefix(cmd, got.Target.Command) {
		t.Errorf("target.command should be a plain head: %.40q", got.Target.Command)
	}
	if got.Labels[LabelCommandLen] != fmt.Sprint(len(cmd)) {
		t.Errorf("length label %q", got.Labels[LabelCommandLen])
	}

	// Step 4: the skeleton keeps the command's length, and a value it
	// clips ends in the marker too.
	e = kindEvent(event.KindDetection, "skel-"+strings.Repeat("i", 200))
	e.Target.Command = cmd
	for i := 0; i < 2000; i++ {
		e.Labels[fmt.Sprintf("k%05d", i)] = strings.Repeat("v", 200)
	}
	line, err = fitLine(e, FormatNative, 1536)
	if err != nil {
		t.Fatal(err)
	}
	if len(line) > 1536 {
		t.Fatalf("line is %d bytes", len(line))
	}
	got = decodeLine(t, line)
	if !has(got.Truncated, "*") {
		t.Fatalf("expected the skeleton: %.200s", line)
	}
	if got.Labels[LabelCommandLen] != fmt.Sprint(len(cmd)) || len(got.Labels) != 1 {
		t.Errorf("skeleton labels %v", got.Labels)
	}
	if n, ok := truncTail(got.ID); !ok || len(got.ID) > 64 || len(e.ID)-n != strings.LastIndex(got.ID, "[TRUNCATED:") {
		t.Errorf("skeleton id %q", got.ID)
	}
}

func TestSkelString(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 16, "short"},
		{"a\x01b", 16, "a_b"},
		{strings.Repeat("x", 100), 64, strings.Repeat("x", 48) + "[TRUNCATED:52B]"},
		// An enum field too small for the marker still gets one.
		{strings.Repeat("x", 20000), 16, "[TRUNCATED:20000B]"},
	}
	for _, c := range cases {
		if got := skelString(c.in, c.n); got != c.want {
			t.Errorf("skelString(%.10q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestCutString(t *testing.T) {
	orig := strings.Repeat("a", 30000)
	// Repeated passes: the count is always relative to the original.
	v := orig
	for _, n := range []int{4096, 1024, 256} {
		v = cutString(v, n)
		c, ok := truncTail(v)
		head := v[:strings.LastIndex(v, "[TRUNCATED:")]
		if !ok || len(v) > n || len(head)+c != len(orig) {
			t.Fatalf("n=%d: %d bytes, head %d + count %d != %d", n, len(v), len(head), c, len(orig))
		}
	}
	// A value privacy cut in the middle: a marker that falls in the cut
	// part adds what it stood for; one that stays is kept whole.
	mid := strings.Repeat("h", 300) + "[TRUNCATED:5000B]" + strings.Repeat("t", 300)
	want := 300 + 5000 + 300
	for n := 256; n < len(mid); n++ {
		got := cutString(mid, n)
		if len(got) > n {
			t.Fatalf("n=%d: %d bytes", n, len(got))
		}
		total := 0
		for _, sp := range markerSpans(got) {
			total += sp.count - (sp.end - sp.start)
		}
		if total+len(got) != want {
			t.Fatalf("n=%d: %q stands for %d bytes, want %d", n, got[max(0, len(got)-60):], total+len(got), want)
		}
		if k := strings.LastIndex(got[:strings.LastIndex(got, "[TRUNCATED:")], "["); k >= 0 && !strings.Contains(got[k:], "]") {
			t.Fatalf("n=%d: split marker %q", n, got[k:])
		}
	}
	// A redaction marker is never split.
	red := strings.Repeat("r", 230) + "[REDACTED:generic_secret:hmac=k1:0123456789abcdef]" + strings.Repeat("s", 300)
	for n := 256; n < 320; n++ {
		got := cutString(red, n)
		if i := strings.Index(got, "[REDACTED"); i >= 0 && !strings.HasPrefix(got[i:], "[REDACTED:generic_secret:hmac=k1:0123456789abcdef]") {
			t.Fatalf("n=%d: split redaction marker %q", n, got[i:])
		}
	}
	// Hostile: a value full of '[' costs linear time and still gets a
	// marker; a forged count cannot overflow.
	hostile := strings.Repeat("[", 1<<20) + "[TRUNCATED:9999999999999999999B]"
	if got := cutString(hostile, 1024); len(got) > 1024 {
		t.Fatalf("%d bytes", len(got))
	} else if _, ok := truncTail(got); !ok {
		t.Fatalf("no marker: %q", got[len(got)-30:])
	}
}
