//go:build darwin

package platform

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ioregPath = "/usr/sbin/ioreg"

func platformHostID() (id, src string) {
	if id := hostUUIDSyscall(); id != "" {
		return id, HostIDSourceGetHostUUID
	}
	if id := hostUUIDIOReg(); id != "" {
		return id, HostIDSourceIOReg
	}
	return "", HostIDSourceNone
}

// hostUUIDSyscall calls gethostuuid(2), the same call osquery makes
// (osquery/core/system.cpp), so the result matches system_info.uuid byte for
// byte. It is tried first because spawning ioreg costs tens of milliseconds
// and the hook process pays that on every tool call.
//
// UNVERIFIED: not executed on macOS in the build environment. A failure or an
// all-zero answer falls back to ioreg.
func hostUUIDSyscall() string {
	var buf [16]byte
	// osquery waits at most 5 seconds for IOKit to publish the UUID.
	wait := unix.Timespec{Sec: 5}
	_, _, errno := unix.Syscall(unix.SYS_GETHOSTUUID,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&wait)), 0)
	if errno != 0 {
		return ""
	}
	// uuid_unparse on macOS prints upper case.
	return cleanHardwareUUID(formatUUID(buf[:], false, true))
}

// hostUUIDIOReg reads IOPlatformUUID, the registry property gethostuuid
// returns, through the system ioreg tool. The path is absolute and the
// environment empty so nothing the user controls can redirect the lookup.
func hostUUIDIOReg() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ioregPath, "-rd1", "-c", "IOPlatformExpertDevice")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return ""
	}
	if err := cmd.Start(); err != nil {
		return ""
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, io.LimitReader(out, 1<<20))
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return ""
	}
	return parseIORegUUID(buf.Bytes())
}
