//go:build linux

package platform

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// PeerCred returns the uid and pid of the process on the other end of a unix
// socket, as recorded by the kernel when the peer called connect(2). The
// peer cannot forge them. pid is 0 when the peer lives in a pid namespace
// this process cannot see, and the uid is the kernel's overflow uid (65534)
// when the peer's user namespace has no mapping here. The pid may have been
// reused since the connection was made, so check the process start time
// before trusting anything looked up by it.
func PeerCred(c net.Conn) (uid string, pid int, err error) {
	defer guard(&err)
	raw, err := unixRawConn(c)
	if err != nil {
		return "", 0, err
	}
	var cred *unix.Ucred
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil {
		return "", 0, fmt.Errorf("platform: peer credentials: %w", cerr)
	}
	if serr != nil {
		return "", 0, fmt.Errorf("platform: peer credentials: %w", serr)
	}
	// uid -1 is what the kernel reports for a socket that never had a peer.
	if cred == nil || cred.Uid == ^uint32(0) {
		return "", 0, fmt.Errorf("platform: peer credentials unavailable")
	}
	if cred.Pid > 0 {
		pid = int(cred.Pid)
	}
	return strconv.FormatUint(uint64(cred.Uid), 10), pid, nil
}
