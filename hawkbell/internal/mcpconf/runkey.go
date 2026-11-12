package mcpconf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// runKey keys the digest that marks a value capString cut.
//
// That digest used to be fp8, an unkeyed SHA-256 of the whole value, and it
// reaches inventory records (server name, command, arguments, package,
// URL). An unkeyed digest of a value whose head is shown is a guessing
// oracle for its tail: a reader hashes candidate completions until one
// matches. The key is 32 random bytes drawn once per process, held only in
// memory and never written anywhere, so two different cut values still
// differ within a run (a declaration cannot hide behind another with the
// same head), and nothing can be recomputed from the log. A value cut this
// way reads differently in the next process, so it is used only for
// reported fields (command, arguments, package, URL, key names). The
// fields that identify an asset, Server.Name and Server.Project, are cut
// without any digest by builder.cutIdentity, the same in every process.
var runKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	// crypto/rand.Read does not return on failure (Go 1.24+): the process
	// aborts, so a zero key is never used.
	_, _ = rand.Read(k)
	return k
})

// runFP8 is the first 8 hex digits of HMAC-SHA-256(runKey, s).
func runFP8(s string) string {
	m := hmac.New(sha256.New, runKey())
	m.Write([]byte("hawkbell/mcpconf/cut\x00"))
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil)[:4])
}
