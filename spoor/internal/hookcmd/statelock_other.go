//go:build !(linux || darwin || freebsd || openbsd || netbsd || windows)

package hookcmd

import "time"

// tryLock is unsupported here: session state is saved without the lock
// (last writer wins) and the records say so (hook_state=unlocked).
func tryLock(string, time.Duration) (func(), bool) { return nil, false }
