package privacy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// FuzzRedactCommand: never panics, never grows without bound, and a
// planted structural secret never survives.
func FuzzRedactCommand(f *testing.F) {
	for _, s := range []string{
		"mysql -pX", `bash -c "a 'b' $(c)"`, "echo `x`", "a <<E\nb\nE", "$env:A='b'", `cmd /c "x"`,
		"echo " + b64("mysql -pFz1"), "\x00\xff", strings.Repeat("(", 100), `"'\`, "a=b c=d e", "#000000000",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		out, _ := redactCommand(s, "")
		if len(out) > 4*len(s)+4096 {
			t.Fatalf("output grew to %d from %d", len(out), len(s))
		}
		planted := s + " ; mysql -pFuzzCanary1 db"
		out, _ = redactCommand(planted, "")
		if strings.Contains(out, "FuzzCanary1") {
			t.Fatalf("planted secret survived:\n%q\n%q", planted, out)
		}
	})
}

// FuzzEmit: arbitrary strings in every common field never break the line
// cap, UTF-8 or the planted-secret guarantee.
func FuzzEmit(f *testing.F) {
	f.Add("ls", "/home/bob/x", "https://h/p?q=1", "prompt", "out", "k", "v")
	f.Add("\xff\x00<>&", "\\\\", "data:,x", " ", "\x01", "\xfe", "")
	f.Fuzz(func(t *testing.T, cmd, path, url, prompt, output, lk, lv string) {
		e := shellEvent(cmd + " && mysql -pFuzzCanary2 db")
		e.Target.Path = path
		e.Target.URL = url
		e.Content.PromptText = prompt + " password=FuzzCanary3"
		e.Content.ToolOutput = output
		e.Prompt = &event.Prompt{Len: len(prompt)}
		e.Labels = map[string]string{lk: lv}
		for _, prof := range Profiles {
			p := &Policy{Profile: prof, Key: testKey, MaxLine: 4096}
			out, _, ok := p.Emit(e)
			if !ok {
				t.Fatal("dropped")
			}
			l := line(t, out)
			if len(l) > 4096-LineHeadroom {
				t.Fatalf("line %d bytes", len(l))
			}
			if !utf8.ValidString(l) {
				t.Fatal("invalid UTF-8 in output")
			}
			if strings.Contains(l, "FuzzCanary") {
				t.Fatalf("planted secret survived:\n%s", l)
			}
			if unkeyedMarkerRe.MatchString(l) {
				t.Fatalf("unkeyed fingerprint:\n%s", l)
			}
		}
	})
}
