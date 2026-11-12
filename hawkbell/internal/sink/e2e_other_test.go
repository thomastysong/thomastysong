//go:build !linux

package sink

import "os/exec"

// stopWithParent is a no-op where there is no parent-death signal; the
// test's cleanup still removes the container on a normal exit.
func stopWithParent(*exec.Cmd) {}
