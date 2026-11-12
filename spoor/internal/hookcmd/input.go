package hookcmd

import (
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
}

// readBounded reads one hook payload: at most max+1 bytes, waiting at most
// wait for the writer to close stdin. An agent that never closes stdin
// costs one wait per call instead of hanging the hook (there is no portable
// read deadline on an inherited pipe, so the read runs in a goroutine and
// is abandoned when the process exits). Bytes past the cap are drained so
// a writer blocked on a full pipe can finish and see a clean close.
func readBounded(r io.Reader, max int, wait time.Duration) inputResult {
	var (
		mu   sync.Mutex
		buf  = make([]byte, 0, min(max+1, 64<<10))
		res  inputResult
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
				if room := max + 1 - len(buf); room > 0 {
					buf = append(buf, chunk[:min(n, room)]...)
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
	return out
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
