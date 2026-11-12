package adapter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// Keys for records without an id of their own.
//
// A numbat record that carries no event, finding or decision id still needs
// a hawkbell id, and the obvious one, a SHA-256 of the line, is a guessing
// oracle once it is shipped: the id is a pure function of the record's
// content, so a log reader who can enumerate candidate records (a short
// prompt, a command with a password in it) recomputes ids until one
// matches. The privacy red team recovered 4 of 6 prompts from a 1,600-entry
// dictionary that way.
//
// Such records are therefore keyed with HMAC-SHA-256 under runKey: 32
// random bytes drawn once per process, held only in memory and never
// written anywhere. The same line converted twice in one run gets the same
// id, which is all at-least-once delivery inside one tailer needs; the same
// line converted by another process (a restarted daemon re-reading a file)
// gets a different id and is not collapsed downstream. That is the price:
// records with numbat ids, the normal case, are unaffected.
var runKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	// crypto/rand.Read does not return on failure (Go 1.24+): the process
	// aborts, so a zero key is never used.
	_, _ = rand.Read(k)
	return k
})

// runDigest is the hex HMAC-SHA-256 of data under runKey, separated by
// domain so a value keyed for one purpose never equals the same value
// keyed for another, cut to 16 bytes (128 bits).
func runDigest(domain string, data []byte) string {
	m := hmac.New(sha256.New, runKey())
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// Digest domains.
const (
	domLine        = "hawkbell/adapter/numbat-line"
	domProjectPath = "hawkbell/adapter/numbat-project-path"
	domIndicator   = "hawkbell/adapter/numbat-indicator"
)

// maxProjectHash bounds the numbat value that is keyed; numbat writes
// "sha256:" and 64 hex digits.
const maxProjectHash = 128

// projectPathKey replaces numbat's project_path_hash, which numbat documents
// as a stable, unsalted SHA-256 of the project path ("not anonymization"),
// with a keyed digest of it. A path under a home directory is easy to guess
// (user names are known, project names often are), so the unkeyed value is
// a lookup key for the path that numbat deliberately left out of findings
// and indicators. The keyed value still joins a finding to the indicators
// of the same project within one hawkbell process. Values that are not
// numbat's "sha256:<hex>" form are dropped.
func projectPathKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	h, ok := strings.CutPrefix(v, "sha256:")
	if !ok || len(v) > maxProjectHash || len(h) != 64 || !isHex(h) {
		return ""
	}
	return runDigest(domProjectPath, []byte(h))
}
