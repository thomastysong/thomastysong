package hookcmd

import "syscall"

// sysProcAttr is the worker's process attributes. Nothing special is
// needed on any platform: the worker inherits the supervisor's session and
// process group, so an agent that kills the hook's process group on its own
// timeout takes the worker with it, and the worker's watchdog covers the
// rest.
func sysProcAttr() *syscall.SysProcAttr { return nil }
