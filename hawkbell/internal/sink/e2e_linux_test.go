//go:build linux

package sink

import (
	"os/exec"
	"syscall"
)

// stopWithParent has the kernel signal the child when the test process
// dies, so a killed test run does not leave its container behind.
func stopWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
