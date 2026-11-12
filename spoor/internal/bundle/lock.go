package bundle

import "time"

// lockName is never removed: deleting a lock file while another process
// holds it would let a third one lock a fresh file under the same name.
const lockName = ".lock"

// acquire takes the install lock of a destination, polling so that a wait
// can be bounded on every platform. The lock belongs to an open file handle,
// so the operating system drops it when a process dies: a crashed installer
// never leaves the destination locked.
func acquire(path string, timeout time.Duration) (release func(), err error) {
	deadline := time.Now().Add(timeout)
	for wait := 2 * time.Millisecond; ; {
		release, ok, err := tryLock(path)
		if err != nil {
			return nil, err
		}
		if ok {
			return release, nil
		}
		if !time.Now().Before(deadline) {
			return nil, ErrBusy
		}
		time.Sleep(wait)
		if wait < 64*time.Millisecond {
			wait *= 2
		}
	}
}
