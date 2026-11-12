package osqexec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// runKey keys the identity of a row that has no usable event id.
//
// Such a row is identified by its content (time, pid, path and the raw,
// unredacted command line), and that identity reaches the shipped
// process.exec id. A plain hash there would be a guessing oracle: time,
// pid and path ship in the same record, so a log reader who suspects a
// password on the command line hashes candidates until the id matches. The
// key is 32 random bytes drawn once per process, held only in memory and
// never written anywhere, so the id is stable for the life of the Source
// (the seen set and replayed pages still collapse) and cannot be recomputed
// from the log. A restarted sensor that re-reads the same row inside its
// lookback gives it a new id; rows with an event id, the normal case, keep
// ids that are stable across restarts.
var runKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	// crypto/rand.Read does not return on failure (Go 1.24+): the process
	// aborts, so a zero key is never used.
	_, _ = rand.Read(k)
	return k
})

// contentRowKey is the seen-set key of a row without a usable eid: a keyed
// digest of the fields that tell two execs apart.
func contentRowKey(fields ...string) string {
	m := hmac.New(sha256.New, runKey())
	m.Write([]byte("spoor/osqexec/row\x00"))
	for _, f := range fields {
		m.Write([]byte(f))
		m.Write([]byte{0})
	}
	return "h" + hex.EncodeToString(m.Sum(nil)[:12])
}
