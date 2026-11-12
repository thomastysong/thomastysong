package hookcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"sync"
	"time"
)

// inputResult is what readBounded got from stdin.
type inputResult struct {
	b        []byte // at most max+1 bytes: one more than max means "over the cap"
	eof      bool   // the writer closed stdin
	timedOut bool   // stdin was still open when the wait ran out
	err      error  // a read error other than EOF
	// total counts every byte read, including those drained past the cap;
	// sum is the hex SHA-256 of all of them, set only when total exceeds
	// the cap (otherwise b is the whole payload and its own digest).
	total int64
	sum   string
}

// readBounded reads one hook payload: at most max+1 bytes, waiting at most
// wait for the writer to close stdin. An agent that never closes stdin
// costs one wait per call instead of hanging the hook (there is no portable
// read deadline on an inherited pipe, so the read runs in a goroutine and
// is abandoned when the process exits). Bytes past the cap are drained so
// a writer blocked on a full pipe can finish and see a clean close; they
// are counted and hashed, so an anomaly record reports the size and digest
// of the payload the agent sent, not of the prefix that was kept. Hashing
// starts only once the cap is passed: an ordinary payload costs nothing
// extra.
func readBounded(r io.Reader, max int, wait time.Duration) inputResult {
	var (
		mu   sync.Mutex
		buf  = make([]byte, 0, min(max+1, 64<<10))
		res  inputResult
		h    hash.Hash
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				mu.Lock()
				res.err = errPanic
				mu.Unlock()
			}
		}()
		chunk := make([]byte, 32<<10)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				mu.Lock()
				take := min(n, max0i(max+1-len(buf)))
				buf = append(buf, chunk[:take]...)
				res.total += int64(n)
				if res.total > int64(max) {
					// Once over the cap the buffer is full, so every later
					// chunk goes to the hash whole.
					if h == nil {
						h = sha256.New()
						h.Write(buf)
					}
					h.Write(chunk[take:n])
				}
				mu.Unlock()
			}
			if err != nil {
				mu.Lock()
				if err == io.EOF {
					res.eof = true
				} else {
					res.err = err
				}
				mu.Unlock()
				return
			}
		}
	}()
	t := time.NewTimer(max0(wait))
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
	mu.Lock()
	defer mu.Unlock()
	out := res
	out.b = append([]byte(nil), buf...)
	out.timedOut = !out.eof && out.err == nil
	if h != nil {
		out.sum = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

// rawDigest is the size and hex SHA-256 of the payload the agent sent: the
// counted total when more was read than kept, else the kept bytes.
func (in inputResult) rawDigest() (int64, string) {
	if in.sum != "" && in.total > int64(len(in.b)) {
		return in.total, in.sum
	}
	sum := sha256.Sum256(in.b)
	return int64(len(in.b)), hex.EncodeToString(sum[:])
}

func max0i(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func max0(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errPanic = constErr("hookcmd: panic while reading stdin")
