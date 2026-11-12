//go:build linux

package platform

import (
	"io"
	"os"
	"sync"
)

// capPrivileged reports whether this process's effective capability set
// holds CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE (see readerCaps). It is read
// once: hawkbell never raises or drops capabilities after start, and the hook
// path calls IsPrivileged on every invocation. A process whose /proc is not
// readable counts as not having them.
var capPrivileged = sync.OnceValue(func() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStatusRead))
	if err != nil {
		return false
	}
	return readerCapsIn(b)
})
