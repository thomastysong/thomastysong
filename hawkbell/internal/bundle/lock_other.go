//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package bundle

import "sync"

// Platforms without flock(2) or Win32 share modes get a lock that only
// serialises installers inside one process (see the package comment).
var (
	heldMu sync.Mutex
	held   = map[string]bool{}
)

func tryLock(path string) (release func(), ok bool, err error) {
	heldMu.Lock()
	defer heldMu.Unlock()
	if held[path] {
		return nil, false, nil
	}
	held[path] = true
	return func() {
		heldMu.Lock()
		delete(held, path)
		heldMu.Unlock()
	}, true, nil
}
