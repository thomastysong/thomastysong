//go:build !linux && !darwin

package platform

import "net"

// PeerCred is not available here. On Windows an AF_UNIX socket can report
// the peer's pid (SIO_AF_UNIX_GETPEERPID) but not its identity, and a pid
// alone is not a credential, so the answer is ErrUnsupported: authenticate
// Windows hook clients by other means (socket file ACL).
func PeerCred(c net.Conn) (uid string, pid int, err error) {
	return "", 0, ErrUnsupported
}
