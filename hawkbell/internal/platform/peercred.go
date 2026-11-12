package platform

import (
	"errors"
	"net"
	"syscall"
)

var errNotUnixConn = errors.New("platform: peer credentials need a connected unix stream socket")

// unixRawConn returns the raw descriptor access of c when c is a connected
// AF_UNIX stream (or seqpacket) socket. Datagram sockets and TCP have no
// peer credentials worth trusting, so they are refused up front rather than
// answered with zeros.
func unixRawConn(c net.Conn) (syscall.RawConn, error) {
	if c == nil {
		return nil, errNotUnixConn
	}
	addr := c.LocalAddr()
	if addr == nil || (addr.Network() != "unix" && addr.Network() != "unixpacket") {
		return nil, errNotUnixConn
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, errNotUnixConn
	}
	return sc.SyscallConn()
}
