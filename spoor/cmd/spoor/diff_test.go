package main

import (
	"math/rand"
	"strings"
	"testing"
)

func TestRedactedDiffShowsOnlyChangesAndRedacts(t *testing.T) {
	secret := fakeToken("ghp_", 36, 7)
	before := "{\n  \"env\": {\"GITHUB_TOKEN\": \"" + secret + "\"},\n  \"model\": \"sonnet\"\n}\n"
	after := "{\n  \"env\": {\"GITHUB_TOKEN\": \"" + secret + "\"},\n  \"model\": \"sonnet\",\n  \"hooks\": {\"PreToolUse\": []}\n}\n"
	d := redactedDiff([]byte(before), []byte(after))
	joined := strings.Join(d, "\n")
	if strings.Contains(joined, secret) {
		t.Fatalf("secret in diff:\n%s", joined)
	}
	if !strings.Contains(joined, `+  "hooks"`) || !strings.Contains(joined, `-  "model": "sonnet"`) {
		t.Fatalf("diff:\n%s", joined)
	}
	if strings.Contains(joined, "GITHUB_TOKEN") {
		t.Fatalf("unchanged line shown:\n%s", joined)
	}
	if !strings.HasPrefix(d[0], "@@ -3,1 +3,2 @@") {
		t.Fatalf("hunk header %q", d[0])
	}

	// A changed line that carries a secret is shown redacted.
	b2 := strings.Replace(after, "sonnet", "opus", 1)
	b2 = strings.Replace(b2, "\"PreToolUse\": []", "\"PreToolUse\": [], \"token\": \""+secret+"\"", 1)
	joined = strings.Join(redactedDiff([]byte(after), []byte(b2)), "\n")
	if strings.Contains(joined, secret) || !strings.Contains(joined, "REDACTED") {
		t.Fatalf("changed secret line not redacted:\n%s", joined)
	}
	if redactedDiff([]byte(after), []byte(after)) != nil {
		t.Fatal("identical inputs produced a diff")
	}
	if d := redactedDiff(nil, []byte("a\nb\n")); len(d) != 3 || d[0] != "@@ -1,0 +1,2 @@" {
		t.Fatalf("new file: %q", d)
	}
}

// The edit script must turn a into b exactly, for random inputs.
func TestLCSDiffReconstructs(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	words := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("{"), []byte("}")}
	gen := func() [][]byte {
		n := r.Intn(30)
		out := make([][]byte, n)
		for i := range out {
			out[i] = words[r.Intn(len(words))]
		}
		return out
	}
	for i := 0; i < 500; i++ {
		a, b := gen(), gen()
		ops := lcsDiff(a, b)
		var got [][]byte
		ai, bi := 0, 0
		for _, op := range ops {
			switch op {
			case opKeep:
				if string(a[ai]) != string(b[bi]) {
					t.Fatal("keep of unequal lines")
				}
				got = append(got, a[ai])
				ai++
				bi++
			case opDel:
				ai++
			case opAdd:
				got = append(got, b[bi])
				bi++
			}
		}
		if ai != len(a) || bi != len(b) || len(got) != len(b) {
			t.Fatalf("script does not consume both inputs")
		}
		for k := range got {
			if string(got[k]) != string(b[k]) {
				t.Fatalf("reconstruction differs at %d", k)
			}
		}
	}
}

func TestRedactedDiffLargeInput(t *testing.T) {
	a := strings.Repeat("x\n", 5000)
	b := strings.Repeat("y\n", 5000)
	d := redactedDiff([]byte(a), []byte(b))
	if len(d) != 10001 {
		t.Fatalf("got %d lines", len(d))
	}
}
