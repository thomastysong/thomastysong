package hookio

import (
	"strconv"
	"strings"
)

// Error classes: the closed vocabulary of ErrorClass. A failed tool call's
// error text is model-influenced (it quotes paths, file content, command
// output, sometimes credentials), so the serialized record carries only
// one of these words and the byte length of the text.
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
// always stated in the first lines.
const errClassScan = 4 << 10

// errClassRules is checked in order and the first class with a matching
// phrase wins, so more specific phrases sit in earlier classes:
// "deadline exceeded" is a timeout before "exceeded" can mean too_large,
// "permission denied" is permission_denied before "denied" means blocked.
// Phrases are lower case and matched as substrings of the lower-cased text.
var errClassRules = []struct {
	class   string
	phrases []string
}{
	{ErrClassInterrupted, []string{"interrupt", "cancelled", "canceled", "aborted"}},
	{ErrClassTimeout, []string{"timed out", "timeout", "time out", "deadline exceeded", "etimedout"}},
	{ErrClassRateLimited, []string{"rate limit", "rate-limit", "ratelimit", "too many requests", "quota"}},
	{ErrClassPermissionDenied, []string{"permission denied", "eacces", "eperm", "operation not permitted",
		"access denied", "access is denied", "forbidden", "unauthorized", "unauthenticated", "not authorized"}},
	{ErrClassRejected, []string{"rejected", "declined", "user denied", "denied by the user", "denied by user",
		"doesn't want to proceed", "does not want to proceed"}},
	{ErrClassBlocked, []string{"blocked", "not allowed", "disallowed", "sandbox", "policy", "denied"}},
	{ErrClassNotFound, []string{"not found", "no such", "enoent", "does not exist", "doesn't exist",
		"cannot find", "can't find", "could not find", "unable to find"}},
	{ErrClassAlreadyExists, []string{"already exists", "eexist", "file exists"}},
	{ErrClassConflict, []string{"modified since", "has been modified", "has not been read", "conflict"}},
	{ErrClassNetwork, []string{"connection refused", "econnrefused", "connection reset", "econnreset",
		"enotfound", "eai_again", "could not resolve", "getaddrinfo", "unreachable", "network",
		"tls handshake", "x509", "certificate", "socket hang up"}},
	{ErrClassTooLarge, []string{"too large", "too long", "too big", "exceeds", "exceeded", "e2big", "efbig"}},
	{ErrClassInvalidInput, []string{"invalid", "validation", "malformed", "missing required", "is required",
		"syntax error", "parse error", "failed to parse", "unexpected token", "bad request",
		"unknown option", "unrecognized"}},
	{ErrClassUnsupported, []string{"not supported", "unsupported", "not implemented"}},
	{ErrClassCrashed, []string{"segmentation fault", "sigsegv", "sigkill", "killed", "out of memory",
		"enomem", "core dumped", "panic:"}},
}

// ErrorClass maps a tool's error text to one word of a closed vocabulary
// (the ErrClass* constants) by phrase matching on its first few KiB. The
// result never contains any of the text, so it is safe to serialize at
// every privacy tier; it is a triage hint, not a parse, and text that
// matches nothing is ErrClassOther.
func ErrorClass(text string) string {
	if text == "" {
		return ""
	}
	if len(text) > errClassScan {
		text = text[:errClassScan]
	}
	lower := strings.ToLower(text)
	for _, r := range errClassRules {
		for _, p := range r.phrases {
			if strings.Contains(lower, p) {
				return r.class
			}
		}
	}
	return ErrClassOther
}

// ErrorSummary is what Outcome.Error holds for a failed tool call whose
// error text is not emitted: "tool error class:<ErrorClass> len:<bytes>".
// It replaces a fingerprint of the text: an unkeyed hash of a short error
// message is recovered with a dictionary, links the same text across
// tenants, and these records also land in the local spool and state where
// the privacy stage's keyed rewrite does not reach. Correlating identical
// errors, if wanted, belongs to the privacy stage, which holds the tenant
// key. Empty text gives "".
func ErrorSummary(text string) string {
	return summary("tool error", ErrorClass(text), len(text))
}

func summary(prefix, class string, n int) string {
	if n <= 0 {
		return ""
	}
	return prefix + " class:" + class + " len:" + strconv.Itoa(n)
}
