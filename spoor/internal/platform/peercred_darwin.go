//go:build darwin

package platform

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// PeerCred returns the effective uid and the pid of the process on the other
// end of a unix socket (LOCAL_PEERCRED and LOCAL_PEERPID). pid is 0 when the
// kernel does not report one.
//
// UNVERIFIED: compiled and vetted for darwin, not executed in the build
// environment. The option names and levels are the ones x/sys/unix tests.
func PeerCred(c net.Conn) (uid string, pid int, err error) {
	defer guard(&err)
	raw, err := unixRawConn(c)
	if err != nil {
		return "", 0, err
	}
	var cred *unix.Xucred
	var credErr, pidErr error
	var peerPID int
	if cerr := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		peerPID, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); cerr != nil {
		return "", 0, fmt.Errorf("platform: peer credentials: %w", cerr)
	}
	if credErr != nil {
		return "", 0, fmt.Errorf("platform: peer credentials: %w", credErr)
	}
	if cred == nil {
		return "", 0, fmt.Errorf("platform: peer credentials unavailable")
	}
	if pidErr == nil && peerPID > 0 {
		pid = peerPID
	}
	return strconv.FormatUint(uint64(cred.Uid), 10), pid, nil
}
