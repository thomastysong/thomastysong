package hookio

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
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
		{"hawkbell: blocked by policy [HB-1]", ErrClassBlocked},
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
	for _, r := range append(append([]errRule(nil), osErrRules...), errClassRules...) {
		if !errClasses[r.class] {
			t.Errorf("rule class %q is not in the documented vocabulary", r.class)
		}
		for _, p := range r.phrases {
			if p != strings.ToLower(p) || p == "" {
				t.Errorf("phrase %q must be non-empty lower case", p)
			}
		}
	}
	for _, l := range errLeads {
		if !errClasses[l.class] || l.prefix == "" {
			t.Errorf("lead %+v", l)
		}
	}
}

// The class follows the cause a message states, not the words it quotes:
// the path, command, string or server message the call was about is
// worded by the model. (Review finding: the old priority-ordered scan let
// a quoted "sandbox", "quota", "policy" or "timeout" decide.)
func TestErrorClassFollowsStatedCause(t *testing.T) {
	cases := []struct{ in, want string }{
		// Quoted or path-shaped operands are not read for the cause.
		{"ENOENT: no such file or directory, open '/home/dev/sandbox/app.json'", ErrClassNotFound},
		{"cat: /srv/quota-svc/config.yaml: No such file or directory", ErrClassNotFound},
		{"EACCES: permission denied, open '/var/lib/network-manager/conn'", ErrClassPermissionDenied},
		{`Error: "timeout" is invalid here`, ErrClassInvalidInput},
		{`unknown key "timeout"`, ErrClassTimeout}, // nothing outside the quotes: they decide
		{"fetch https://api.example/ratelimit/policy failed: socket hang up", ErrClassNetwork},
		{`C:\Users\dev\sandbox\quota.txt: Access is denied.`, ErrClassPermissionDenied},
		// The OS text outranks an operand without a separator.
		{"cat: quota.txt: No such file or directory", ErrClassNotFound},
		{"rm: cannot remove policy.lock: Operation not permitted", ErrClassPermissionDenied},
		// Whole words only.
		{"String to replace not found in file.\nString: retry_policy = 3", ErrClassNotFound},
		{"Unterminated quotation mark", ErrClassOther},
		{"read_timeout_ms must be set", ErrClassOther},
		{"grpc: DEADLINE_EXCEEDED", ErrClassTimeout},
		{"rpc error: code = PERMISSION_DENIED desc = caller lacks role", ErrClassPermissionDenied},
		{"openai: rate_limit_exceeded", ErrClassRateLimited},
		{"error_code=file_not_found_x", ErrClassNotFound},
		// Inflections and camelCase humps still count.
		{"java.net.SocketTimeoutException: connect", ErrClassTimeout},
		{"KeyboardInterrupt", ErrClassInterrupted},
		{"requests are being rate limited", ErrClassRateLimited},
		{"TIMEOUTS EXHAUSTED", ErrClassTimeout},
		// The earliest stated cause wins over a later generic word.
		{"request timed out; the sandbox log is attached", ErrClassTimeout},
		{"Blocked: write to the network share is not allowed", ErrClassBlocked},
		// Claude Code's fixed leads decide whatever the command says.
		{"Permission to use Bash with command timeout 5 make test has been denied.", ErrClassBlocked},
		{"Permission to use mcp__workspace__bash has been denied.", ErrClassBlocked},
		{"Permission denied by hook: hawkbell", ErrClassBlocked},
		{"Hook PreToolUse:Bash denied this tool: quota exceeded", ErrClassBlocked},
		{"The user doesn't want to take this action right now. timeout 30 curl x", ErrClassRejected},
		{"[Request interrupted by user for tool use] rate limit", ErrClassInterrupted},
		// A Python traceback states its cause on the last line; the frames
		// above quote model-written code.
		{"Traceback (most recent call last):\n  File \"x.py\", line 3, in <module>\n    requests.get(u, timeout=5)\n" +
			"PermissionError: [Errno 13] Permission denied: '/etc/shadow'\n", ErrClassPermissionDenied},
		{"Traceback (most recent call last):\n  File \"x.py\", line 9\n    sandbox_policy()\nKeyboardInterrupt", ErrClassInterrupted},
		{"building quota report\nTraceback (most recent call last):\n  File \"r.py\", line 2\n    quota()\nFileNotFoundError: [Errno 2] No such file or directory: 'q.csv'",
			ErrClassNotFound},
		// When the only words are quoted (a JSON error body), they decide.
		{`{"error":{"code":429,"message":"Rate limit reached"}}`, ErrClassRateLimited},
		{"'not found'", ErrClassNotFound},
		// An apostrophe inside a word opens no quoted span.
		{"can't find module; it isn't installed", ErrClassNotFound},
	}
	for _, c := range cases {
		eq(t, "ErrorClass("+strconv.Quote(c.in)+")", ErrorClass(c.in), c.want)
	}
	// A traceback longer than the scan bound is still read at its end.
	long := pyTraceback + "\n" + strings.Repeat("  File \"a.py\", line 1, in f\n    sandbox()\n", 4000) + "TimeoutError: timed out"
	eq(t, "long traceback", ErrorClass(long), ErrClassTimeout)
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
	eq(t, "summary of a huge text", ErrorSummary(huge), "tool error class:other")
	// Quote and boundary handling stay linear on a hostile head: quote
	// characters, slashes and near-miss phrases fill the scanned window.
	for _, hostile := range []string{
		strings.Repeat("'a", 4<<20), strings.Repeat("\"", 8<<20), strings.Repeat("/", 8<<20),
		strings.Repeat("deniedx", 1<<20), strings.Repeat("xtimeout_", 1<<20), strings.Repeat("aB", 4<<20),
		pyTraceback + strings.Repeat("\n", 8<<20),
	} {
		start := time.Now()
		_ = ErrorClass(hostile)
		if d := time.Since(start); d > time.Second {
			t.Errorf("slow on hostile %q...: %v", hostile[:8], d)
		}
	}
	// A phrase cut by the bound is not matched, and a bound that falls
	// inside a multi-byte rune does no harm.
	edge := "a" + strings.Repeat("é", errClassScan/2) + "timed out"
	eq(t, "phrase across the bound", ErrorClass(edge), ErrClassOther)
}

// Whatever the text, the summary is one of a closed set of words: never a
// byte of the text, a hash of it or its length.
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
		class, ok := strings.CutPrefix(s, "tool error class:")
		if !ok || !errClasses[class] {
			t.Fatalf("summary %q for %q", s, text)
		}
		noHashOf(t, s, text)
	}
	eq(t, "empty", ErrorSummary(""), "")
}

// No event of any recorded payload serializes an unkeyed hash of free text:
// no output digest (the privacy stage derives a keyed one; the recorded
// outputs are all far below fullDigestAbove) and no "fp:" fingerprint
// summary. Content is never serialized, so the raw texts are checked
// against the wire form too.
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

// Tool.OutputSHA256 is recorded only for an output the spool may cut on
// its way to the privacy stage, and then it is the digest of all of it.
func TestOutputDigestOnlyForLongOutput(t *testing.T) {
	for _, n := range []int{1, 64, fullDigestAbove - 1, fullDigestAbove, fullDigestAbove + 1, 3 << 20} {
		text := strings.Repeat("o", n)
		for name, ev := range map[string]*event.Event{
			"post":    {Content: &event.Content{}, Tool: &event.Tool{}},
			"failure": {Content: &event.Content{}, Tool: &event.Tool{}},
		} {
			if name == "post" {
				setOutput(ev, map[string]any{"stdout": text, "stderr": ""})
			} else {
				failure(ev, text, false)
			}
			eq(t, name+" output len", ev.Tool.OutputLen, n)
			want := ""
			if n > fullDigestAbove {
				want = sha256Hex(text)
			}
			eq(t, name+" output_sha256 for "+strconv.Itoa(n)+" bytes", ev.Tool.OutputSHA256, want)
		}
	}
	// No Tool, no digest (a turn's final message).
	ev := &event.Event{Content: &event.Content{}}
	setOutput(ev, strings.Repeat("o", fullDigestAbove+1))
	if ev.Tool != nil {
		t.Errorf("tool invented: %+v", ev.Tool)
	}
}
