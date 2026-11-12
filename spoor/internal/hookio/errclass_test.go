package hookio

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

var errClasses = map[string]bool{
	ErrClassInterrupted: true, ErrClassTimeout: true, ErrClassRateLimited: true,
	ErrClassPermissionDenied: true, ErrClassRejected: true, ErrClassBlocked: true,
	ErrClassNotFound: true, ErrClassAlreadyExists: true, ErrClassConflict: true,
	ErrClassNetwork: true, ErrClassTooLarge: true, ErrClassInvalidInput: true,
	ErrClassUnsupported: true, ErrClassCrashed: true, ErrClassOther: true,
}

func TestErrorClass(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"[Request interrupted by user for tool use]", ErrClassInterrupted},
		{"The operation was aborted", ErrClassInterrupted},
		{"Command timed out after 2m 0s", ErrClassTimeout},
		{"context deadline exceeded", ErrClassTimeout},
		{"connect ETIMEDOUT 10.0.0.1:443", ErrClassTimeout},
		{"429 Too Many Requests", ErrClassRateLimited},
		{"rate limit exceeded, retry later", ErrClassRateLimited},
		{"bash: /etc/shadow: Permission denied", ErrClassPermissionDenied},
		{"EACCES: permission denied, open '/root/x'", ErrClassPermissionDenied},
		{"HTTP 403 Forbidden", ErrClassPermissionDenied},
		{"The user doesn't want to proceed with this tool use. The tool use was rejected", ErrClassRejected},
		{"User denied the request", ErrClassRejected},
		{"spoor: blocked by policy [SP-1]", ErrClassBlocked},
		{"Permission to use Bash has been denied.", ErrClassBlocked},
		{"command rejected by sandbox", ErrClassRejected},
		{"write outside the sandbox", ErrClassBlocked},
		{"String to replace not found in file.", ErrClassNotFound},
		{"ENOENT: no such file or directory", ErrClassNotFound},
		{"bash: kubectl: command not found", ErrClassNotFound},
		{"EEXIST: file already exists", ErrClassAlreadyExists},
		{"File has been modified since read, either by the user or by a linter.", ErrClassConflict},
		{"connect ECONNREFUSED 127.0.0.1:5432", ErrClassNetwork},
		{"getaddrinfo ENOTFOUND registry.example", ErrClassNetwork},
		{"x509: certificate signed by unknown authority", ErrClassNetwork},
		{"File content (300KB) exceeds maximum allowed size (256KB)", ErrClassTooLarge},
		{"InputValidationError: file_path is required", ErrClassInvalidInput},
		{"SyntaxError: Unexpected token } in JSON", ErrClassInvalidInput},
		{"operation not supported on socket", ErrClassUnsupported},
		{"Segmentation fault (core dumped)", ErrClassCrashed},
		{"Killed", ErrClassCrashed},
		{"something odd happened", ErrClassOther},
		{"token abc123 was rejected? no: hunter2", ErrClassRejected},
		{"PERMISSION DENIED", ErrClassPermissionDenied},  // case-insensitive
		{"\xff\xfe\x00 timed out \xc3", ErrClassTimeout}, // invalid UTF-8 is fine
		{"\x00\x01\x02", ErrClassOther},
	}
	for _, c := range cases {
		eq(t, "ErrorClass("+strconv.Quote(c.in)+")", ErrorClass(c.in), c.want)
	}
	// Every class except other is reachable from the table.
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.want] = true
	}
	for cl := range errClasses {
		if !seen[cl] {
			t.Errorf("class %q has no test case", cl)
		}
	}
	for _, r := range errClassRules {
		if !errClasses[r.class] {
			t.Errorf("rule class %q is not in the documented vocabulary", r.class)
		}
		for _, p := range r.phrases {
			if p != strings.ToLower(p) || p == "" {
				t.Errorf("phrase %q must be non-empty lower case", p)
			}
		}
	}
}

// The class is decided from a bounded head, so a huge error costs the same
// as a short one and a phrase buried past the bound does not count.
func TestErrorClassBounded(t *testing.T) {
	huge := strings.Repeat("x", 8<<20) + " permission denied"
	start := time.Now()
	eq(t, "buried phrase", ErrorClass(huge), ErrClassOther)
	if time.Since(start) > time.Second {
		t.Errorf("slow on 8 MiB: %v", time.Since(start))
	}
	eq(t, "head phrase", ErrorClass("timed out "+strings.Repeat("y", 8<<20)), ErrClassTimeout)
	eq(t, "summary length is the whole text", ErrorSummary(huge), "tool error class:other len:"+strconv.Itoa(len(huge)))
	// A phrase cut by the bound is not matched, and a bound that falls
	// inside a multi-byte rune does no harm.
	edge := "a" + strings.Repeat("é", errClassScan/2) + "timed out"
	eq(t, "phrase across the bound", ErrorClass(edge), ErrClassOther)
}

// Whatever the text, the summary is one of a closed set of words plus a
// number: never a byte of the text and never a hash of it.
func TestErrorSummaryNeverCarriesText(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	alphabet := []byte("abcdefghijklmnopqrstuvwxyz0123456789 :/._-=\x00\xff\n")
	for i := 0; i < 2000; i++ {
		b := make([]byte, 1+r.Intn(200))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		text := string(b)
		s := ErrorSummary(text)
		rest, ok := strings.CutPrefix(s, "tool error class:")
		if !ok {
			t.Fatalf("summary %q", s)
		}
		class, n, ok := strings.Cut(rest, " len:")
		if !ok || !errClasses[class] || n != strconv.Itoa(len(text)) {
			t.Fatalf("summary %q for %q", s, text)
		}
		noHashOf(t, s, text)
	}
	eq(t, "empty", ErrorSummary(""), "")
}

// No event of any recorded payload serializes an unkeyed hash of free text:
// no output digest (the privacy stage derives a keyed one) and no "fp:"
// fingerprint summary. Content is never serialized, so the raw texts are
// checked against the wire form too.
func TestNoUnkeyedTextHashOnTheWire(t *testing.T) {
	for _, tc := range allFixtures(t) {
		evs, _, err := dialect(t, tc.dialect).Parse(fixture(t, tc.file), tc.env)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for _, e := range evs {
			b, err := e.MarshalLine()
			if err != nil {
				t.Fatalf("%s: %v", tc.file, err)
			}
			line := string(b)
			if strings.Contains(line, "output_sha256") || strings.Contains(line, "fp:") {
				t.Errorf("%s: unkeyed text hash on the wire: %s", tc.file, line)
			}
			for _, text := range []string{e.Content.ToolOutput, e.Content.PromptText} {
				if len(text) >= 8 && strings.Contains(line, sha256Hex(text)[:8]) {
					t.Errorf("%s: fingerprint of content on the wire: %s", tc.file, line)
				}
			}
		}
	}
}
