package hookio

import "strings"

// Error classes: the closed vocabulary of ErrorClass. A failed tool call's
// error text is model-influenced (it quotes paths, file content, command
// output, sometimes credentials), so the serialized record carries only
// one of these words: not the text, not a hash of it and not its exact
// length (see ErrorSummary).
const (
	ErrClassInterrupted      = "interrupted"       // cancelled or interrupted by the user or the agent
	ErrClassTimeout          = "timeout"           // timed out, deadline exceeded
	ErrClassRateLimited      = "rate_limited"      // rate limit, quota, too many requests
	ErrClassPermissionDenied = "permission_denied" // OS or service refused access (EACCES, 403, unauthorized)
	ErrClassRejected         = "rejected"          // the user declined the call
	ErrClassBlocked          = "blocked"           // a hook, sandbox or policy blocked the call
	ErrClassNotFound         = "not_found"         // missing file, command, string or resource
	ErrClassAlreadyExists    = "already_exists"    // EEXIST and the like
	ErrClassConflict         = "conflict"          // stale state: file changed since read, not read yet
	ErrClassNetwork          = "network"           // connection, DNS or TLS failure
	ErrClassTooLarge         = "too_large"         // size or length limit exceeded
	ErrClassInvalidInput     = "invalid_input"     // arguments failed validation or parsing
	ErrClassUnsupported      = "unsupported"       // operation not supported or not implemented
	ErrClassCrashed          = "crashed"           // killed, out of memory, segfault, panic
	ErrClassOther            = "other"             // none of the above
)

// errClassScan bounds how much of an error text is examined. The class is a
// hint, and error text can be megabytes of tool output; the cause is almost
// always stated in the first lines (a Python traceback, which states it
// last, is read from its own last bounded window).
const errClassScan = 4 << 10

type errRule struct {
	class   string
	phrases []string
}

// errLeads are the fixed texts Claude Code starts a refusal or an
// interruption with. What follows the lead is the tool name and the
// command, file or argument the call was about, all worded by the model
// ("Permission to use Bash with command timeout 5 make test has been
// denied."), so the lead alone decides. Same table as
// internal/transcript's claudeOutcome (Fleet's ai_agent_sessions
// claudeDecision); "Permission to use <tool> has been denied" is quoted in
// the Claude Code docs (code.claude.com/docs/en/permissions and
// /tools-reference, read 2026-11).
var errLeads = []struct {
	prefix, contains, class string
}{
	{"The user doesn't want to proceed", "", ErrClassRejected},
	{"The user doesn't want to take this action", "", ErrClassRejected},
	{"Permission to use", "", ErrClassBlocked},
	{"Permission for this action", "", ErrClassBlocked},
	{"Hook PreToolUse:", "denied this tool", ErrClassBlocked},
	{"Blocked by hook", "", ErrClassBlocked},
	{"Permission denied by hook", "", ErrClassBlocked},
	{"[Request interrupted by user", "", ErrClassInterrupted},
}

// pyTraceback is CPython's fixed traceback header, written at the start of
// a line. The frames below it quote source lines (model-written code), and
// the exception line that states the cause comes last; an uncaught
// exception ends the process, so it is the last line of the text.
const pyTraceback = "Traceback (most recent call last):"

// osErrRules are texts the operating system or the shell writes, not the
// model: errno names, their strerror(3) wording, Windows' "Access is
// denied" and bash's "command not found". Unix tools print
// "program: operand: message", so the operand (a file name, a command,
// any word the model chose) comes before the cause; one of these texts
// anywhere in the examined text therefore outranks a generic word earlier
// in it.
var osErrRules = []errRule{
	{ErrClassTimeout, []string{"etimedout", "connection timed out"}},
	{ErrClassPermissionDenied, []string{"eacces", "eperm", "permission denied", "operation not permitted",
		"access is denied"}},
	{ErrClassNotFound, []string{"enoent", "no such file or directory", "command not found"}},
	{ErrClassAlreadyExists, []string{"eexist", "file exists"}},
	{ErrClassNetwork, []string{"econnrefused", "econnreset", "enetunreach", "ehostunreach", "enotfound",
		"eai_again", "connection refused", "connection reset by peer", "network is unreachable",
		"no route to host"}},
	{ErrClassTooLarge, []string{"e2big", "efbig", "argument list too long", "file too large"}},
	{ErrClassCrashed, []string{"enomem", "cannot allocate memory", "segmentation fault"}},
}

// errClassRules are generic words, consulted when no OS text is present.
// The earliest match in the text wins, because a message states its cause
// first and quotes what it was about after; a tie at one position goes to
// the longer phrase, then to the earlier rule ("denied by the user" is
// rejected, not blocked). Underscore spellings are status codes (gRPC's
// DEADLINE_EXCEEDED, an HTTP API's rate_limit_exceeded).
var errClassRules = []errRule{
	{ErrClassInterrupted, []string{"interrupt", "cancelled", "canceled", "aborted"}},
	{ErrClassTimeout, []string{"timed out", "timeout", "time out", "deadline exceeded", "deadline_exceeded"}},
	{ErrClassRateLimited, []string{"rate limit", "rate-limit", "ratelimit", "rate_limit", "too many requests",
		"quota", "resource_exhausted"}},
	{ErrClassPermissionDenied, []string{"permission denied", "permission_denied", "access denied", "forbidden",
		"unauthorized", "unauthenticated", "not authorized"}},
	{ErrClassRejected, []string{"rejected", "declined", "user denied", "denied by the user", "denied by user",
		"doesn't want to proceed", "does not want to proceed"}},
	{ErrClassBlocked, []string{"blocked", "not allowed", "disallowed", "sandbox", "policy", "denied"}},
	{ErrClassNotFound, []string{"not found", "not_found", "no such", "does not exist", "doesn't exist",
		"cannot find", "can't find", "could not find", "unable to find"}},
	{ErrClassAlreadyExists, []string{"already exists", "already_exists"}},
	{ErrClassConflict, []string{"modified since", "has been modified", "has not been read", "conflict"}},
	{ErrClassNetwork, []string{"connection reset", "could not resolve", "getaddrinfo", "unreachable", "network",
		"tls handshake", "x509", "certificate", "socket hang up"}},
	{ErrClassTooLarge, []string{"too large", "too long", "too big", "exceeds", "exceeded"}},
	{ErrClassInvalidInput, []string{"invalid", "invalid_argument", "validation", "malformed", "missing required",
		"is required", "syntax error", "parse error", "failed to parse", "unexpected token", "bad request",
		"unknown option", "unrecognized"}},
	{ErrClassUnsupported, []string{"not supported", "unsupported", "not implemented", "unimplemented"}},
	{ErrClassCrashed, []string{"sigsegv", "sigkill", "killed", "out of memory", "core dumped", "panic:"}},
}

// ErrorClass maps a tool's error text to one word of a closed vocabulary
// (the ErrClass* constants). It is a triage hint, not a parse, and text
// that matches nothing is ErrClassOther. The result never contains any of
// the text, so it is safe to serialize at every privacy tier.
//
// Error text quotes what the call was about (a path, a command, the string
// an edit looked for, an MCP server's message), and that part is worded by
// the model. So the class follows the stated cause, in this order: a fixed
// agent lead (errLeads); an OS text (osErrRules); the earliest generic
// phrase (errClassRules). Phrases match whole words only (so retry_policy
// is not "policy"), and quoted spans and path or URL tokens are skipped
// unless nothing outside them matches.
func ErrorClass(text string) string {
	if text == "" {
		return ""
	}
	if c := leadClass(text); c != "" {
		return c
	}
	head := text
	if len(head) > errClassScan {
		head = head[:errClassScan]
	}
	if i := strings.Index(head, pyTraceback); i == 0 || i > 0 && head[i-1] == '\n' {
		head = lastLine(text)
	}
	masked := maskQuoted(head)
	for i, s := range []string{masked, head} {
		if i == 1 && s == masked {
			break
		}
		lower := asciiLower(s)
		if c := matchClass(s, lower, osErrRules); c != "" {
			return c
		}
		if c := matchClass(s, lower, errClassRules); c != "" {
			return c
		}
	}
	return ErrClassOther
}

func leadClass(text string) string {
	first := strings.TrimLeft(text, " \t\r\n")
	if len(first) > 512 {
		first = first[:512]
	}
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	for _, l := range errLeads {
		if strings.HasPrefix(first, l.prefix) && (l.contains == "" || strings.Contains(first, l.contains)) {
			return l.class
		}
	}
	return ""
}

// lastLine returns the last non-blank line within the final errClassScan
// bytes of text.
func lastLine(text string) string {
	if len(text) > errClassScan {
		text = text[len(text)-errClassScan:]
	}
	text = strings.TrimRight(text, " \t\r\n")
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	}
	return text
}

// maskQuoted blanks what a message quotes rather than states: spans in
// '...', "..." or `...` that open at the start of a word and close on the
// same line, and whitespace-separated tokens holding a path separator
// (paths and URLs). An apostrophe inside a word ("doesn't") opens nothing.
func maskQuoted(s string) string {
	var b []byte
	blank := func(i, j int) {
		if b == nil {
			b = []byte(s)
		}
		for k := i; k < j; k++ {
			b[k] = ' '
		}
	}
	// open[q] is where the last failed search for a closing q stopped (the
	// end of its line): no later opener on that line can close either, so
	// it is not searched again and the pass stays linear.
	var open [3]int
	for i := 0; i < len(s); i++ {
		k := strings.IndexByte("'\"`", s[i])
		if k < 0 || i > 0 && isWordByte(s[i-1]) || i < open[k] {
			continue
		}
		j, eol := closeQuote(s, i+1, s[i])
		if j < 0 {
			open[k] = eol
			continue
		}
		blank(i, j+1)
		i = j
	}
	for i := 0; i < len(s); {
		if isSpace(s[i]) {
			i++
			continue
		}
		j, sep := i, false
		for ; j < len(s) && !isSpace(s[j]); j++ {
			sep = sep || s[j] == '/' || s[j] == '\\'
		}
		if sep {
			blank(i, j)
		}
		i = j
	}
	if b == nil {
		return s
	}
	return string(b)
}

// closeQuote finds the quote q that closes a span opened before from: on
// the same line and not followed by a word byte. Without one it returns
// -1 and the end of the line.
func closeQuote(s string, from int, q byte) (int, int) {
	for j := from; j < len(s); j++ {
		switch s[j] {
		case '\n':
			return -1, j
		case q:
			if j+1 == len(s) || !isWordByte(s[j+1]) {
				return j, 0
			}
		}
	}
	return -1, len(s)
}

// matchClass returns the class of the earliest whole-word phrase of rules
// in s (lower is s lower-cased byte for byte), or "" for none.
func matchClass(s, lower string, rules []errRule) string {
	best, bestPos, bestLen := "", len(s), 0
	for _, r := range rules {
		for _, p := range r.phrases {
			pos := findWord(s, lower, p, bestPos)
			if pos < 0 {
				continue
			}
			if pos < bestPos || pos == bestPos && len(p) > bestLen {
				best, bestPos, bestLen = r.class, pos, len(p)
			}
		}
	}
	return best
}

// findWord returns the first offset at or before limit where phrase p
// occurs in lower as a whole word of s, or -1.
func findWord(s, lower, p string, limit int) int {
	// A phrase spelled with an underscore is a status code
	// (DEADLINE_EXCEEDED, rate_limit_exceeded), so an underscore next to
	// it separates words; elsewhere it joins them (retry_policy).
	snake := strings.IndexByte(p, '_') >= 0
	for off := 0; off <= limit && off < len(lower); {
		i := strings.Index(lower[off:], p)
		if i < 0 {
			return -1
		}
		i += off
		if i > limit {
			return -1
		}
		if wordStart(s, i, snake) && wordEnd(s, i+len(p), snake) {
			return i
		}
		off = i + 1
	}
	return -1
}

// wordStart reports whether a word begins at s[i]: after a byte that is
// not a letter, digit or underscore, or at a camelCase hump
// ("SocketTimeoutException").
func wordStart(s string, i int, snake bool) bool {
	if i == 0 || !isWordByte(s[i]) || snake && s[i-1] == '_' {
		return true
	}
	return !isWordByte(s[i-1]) || isLowerByte(s[i-1]) && isUpperByte(s[i])
}

// wordEnd reports whether a phrase ending before s[end] ends a word,
// allowing an inflection ("interrupted", "timeouts", "rate limiting") but
// not a longer word ("quotation" is not "quota").
func wordEnd(s string, end int, snake bool) bool {
	if end == len(s) || !isWordByte(s[end-1]) || !isWordByte(s[end]) || snake && s[end] == '_' {
		return true
	}
	if isLowerByte(s[end-1]) && isUpperByte(s[end]) {
		return true // TimeoutError
	}
	j := end
	for j < len(s) && isLetter(s[j]) && !(j > end && isLowerByte(s[j-1]) && isUpperByte(s[j])) {
		j++
	}
	if j < len(s) && isWordByte(s[j]) && !(isLowerByte(s[j-1]) && isUpperByte(s[j])) {
		return false // the word goes on with a digit or underscore
	}
	switch asciiLower(s[end:j]) {
	case "s", "es", "ed", "ing", "ion", "ions":
		return true
	}
	return false
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if isUpperByte(s[i]) {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if isUpperByte(b[j]) {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func isUpperByte(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLowerByte(c byte) bool { return c >= 'a' && c <= 'z' }
func isLetter(c byte) bool    { return isUpperByte(c) || isLowerByte(c) }
func isWordByte(c byte) bool  { return isLetter(c) || c >= '0' && c <= '9' || c == '_' }

// ErrorSummary is what Outcome.Error holds for a failed tool call whose
// error text is not emitted: "tool error class:<ErrorClass>", and "" for
// empty text. It carries no hash of the text (an unkeyed hash of a short
// error message is recovered with a dictionary and links the same text
// across tenants) and no length: the privacy stage rounds content lengths
// up to a power of four outside the full profile and passes Outcome.Error
// through as it is, so an exact length here would undo that, and on a
// failed call the error text is the tool output whose length
// Tool.OutputLen already reports.
func ErrorSummary(text string) string {
	if text == "" {
		return ""
	}
	return "tool error class:" + ErrorClass(text)
}
