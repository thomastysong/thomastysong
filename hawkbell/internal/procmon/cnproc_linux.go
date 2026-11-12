//go:build linux

package procmon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// linuxCN is a NETLINK_CONNECTOR socket subscribed to CN_IDX_PROC.
type linuxCN struct {
	fd   int
	port uint32
}

const (
	cnRecvBuf     = 8 << 20
	cnReadTimeout = 250 * time.Millisecond
	cnAckWait     = time.Second
)

// openCNProc opens the process connector and waits for the kernel to
// acknowledge LISTEN. Before Linux 6.6 binding to the group needs
// CAP_NET_ADMIN; from 6.6 on it does not. The socket exists only in the
// initial network namespace, and the kernel ignores LISTEN (without an
// acknowledgement) from outside the initial user and pid namespaces, so a
// missing acknowledgement means "unsupported here".
func openCNProc() (cnConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, fmt.Errorf("procmon: netlink socket: %w", err)
	}
	c := &linuxCN{fd: fd}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	// A burst of execs (a parallel build) must not overrun the socket
	// before the reader drains it. SO_RCVBUFFORCE needs CAP_NET_ADMIN; the
	// plain option is capped by net.core.rmem_max.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, cnRecvBuf) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, cnRecvBuf)
	}
	tv := unix.NsecToTimeval(cnReadTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("procmon: netlink timeout: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return nil, fmt.Errorf("procmon: netlink bind: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("procmon: netlink getsockname: %w", err)
	}
	if nl, isNL := sa.(*unix.SockaddrNetlink); isNL {
		c.port = nl.Pid
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	seq := binary.LittleEndian.Uint32(nonce[0:4])
	ack := binary.LittleEndian.Uint32(nonce[4:8]) &^ 1
	if err := unix.Sendto(fd, cnControl(seq, ack, c.port, procCnMcastListen), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("procmon: netlink LISTEN: %w", err)
	}
	buf := make([]byte, 64<<10)
	deadline := time.Now().Add(cnAckWait)
	var evs []cnEvent
	for time.Now().Before(deadline) {
		n, err := c.recv(buf)
		if err != nil {
			if errors.Is(err, errCNTimeout) || errors.Is(err, errCNOverflow) {
				continue
			}
			return nil, err
		}
		evs = parseCN(buf[:n], evs[:0])
		for _, e := range evs {
			// The kernel echoes ack+1; seq is overwritten with its own
			// per-CPU counter, so only ack identifies our request.
			if e.what == procEventNone && e.ack == ack+1 {
				if e.err != 0 {
					return nil, fmt.Errorf("procmon: process connector refused LISTEN: %w", unix.Errno(e.err))
				}
				ok = true
				return c, nil
			}
		}
	}
	return nil, errCNNoAck
}

// recv reads one datagram and drops anything that does not come from the
// kernel (netlink port id 0): a local process must not be able to inject
// exec events.
func (c *linuxCN) recv(buf []byte) (int, error) {
	for {
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EINTR):
				return 0, errCNTimeout
			case errors.Is(err, unix.ENOBUFS):
				return 0, errCNOverflow
			}
			return 0, fmt.Errorf("procmon: netlink recv: %w", err)
		}
		if nl, ok := from.(*unix.SockaddrNetlink); ok && nl.Pid == 0 {
			return n, nil
		}
	}
}

// close unsubscribes before closing: the kernel counts listeners and keeps
// building proc events for every fork and exec while the count is above
// zero, and closing the socket alone does not decrement it.
func (c *linuxCN) close() {
	_ = unix.Sendto(c.fd, cnControl(0, 0, c.port, procCnMcastIgnore), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	_ = unix.Close(c.fd)
}

// monotonicToWall converts a proc_event timestamp (ktime_get_ns, i.e.
// CLOCK_MONOTONIC) to wall-clock time.
func monotonicToWall(ns uint64) time.Time {
	var ts unix.Timespec
	now := time.Now()
	if ns == 0 || unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return now
	}
	d := ts.Nano() - int64(ns)
	if d < 0 || d > int64(time.Hour) {
		return now
	}
	return now.Add(-time.Duration(d))
}
