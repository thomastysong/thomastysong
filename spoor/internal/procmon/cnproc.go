package procmon

import (
	"encoding/binary"
	"errors"
)

// Linux process connector wire format (include/uapi/linux/connector.h and
// cn_proc.h). The parser is pure so that it is tested on every build host.
const (
	cnIdxProc = 1
	cnValProc = 1

	procCnMcastListen = 1
	procCnMcastIgnore = 2

	procEventNone     = 0x00000000
	procEventFork     = 0x00000001
	procEventExec     = 0x00000002
	procEventUID      = 0x00000004
	procEventGID      = 0x00000040
	procEventSID      = 0x00000080
	procEventPtrace   = 0x00000100
	procEventComm     = 0x00000200
	procEventCoredump = 0x40000000
	procEventExit     = 0x80000000

	nlmsgHdrLen  = 16 // struct nlmsghdr
	cnMsgLen     = 20 // struct cn_msg without data
	procEvHdrLen = 16 // what, cpu, timestamp_ns
	nlmsgDone    = 3
)

// Errors a cnConn.recv returns in place of OS-specific errnos.
var (
	errCNTimeout  = errors.New("procmon: netlink receive timeout")
	errCNOverflow = errors.New("procmon: netlink receive buffer overrun")
	errCNNoAck    = errors.New("procmon: process connector did not acknowledge LISTEN (not in the initial user and pid namespace?)")
)

// cnConn is an open process-connector socket.
type cnConn interface {
	// recv returns one datagram from the kernel. It returns errCNTimeout
	// when nothing arrived within the read timeout and errCNOverflow when
	// the kernel dropped messages because the socket buffer was full.
	recv(buf []byte) (int, error)
	close()
}

// cnEvent is one decoded proc_event.
type cnEvent struct {
	what     uint32
	ts       uint64 // ns since boot (CLOCK_MONOTONIC)
	seq, ack uint32 // from cn_msg; an acknowledgement carries the request's ack+1
	// fork: parent and child; exec, exit, comm and the rest: pid and tgid.
	parentPID, parentTGID int
	childPID, childTGID   int
	pid, tgid             int
	exitCode, exitSignal  uint32
	err                   uint32 // PROC_EVENT_NONE acknowledgement status
}

// parseCN decodes every connector message in one netlink datagram. Messages
// that are malformed, from another connector, or truncated are skipped;
// parsing never reads past the buffer.
func parseCN(b []byte, out []cnEvent) []cnEvent {
	ne := binary.NativeEndian
	for len(b) >= nlmsgHdrLen {
		l := ne.Uint32(b[0:4])
		typ := ne.Uint16(b[4:6])
		if l < nlmsgHdrLen || uint64(l) > uint64(len(b)) {
			break
		}
		msg := b[nlmsgHdrLen:l]
		if typ == nlmsgDone && len(msg) >= cnMsgLen {
			idx, val := ne.Uint32(msg[0:4]), ne.Uint32(msg[4:8])
			dlen := int(ne.Uint16(msg[16:18]))
			if idx == cnIdxProc && val == cnValProc && dlen >= procEvHdrLen && dlen <= len(msg)-cnMsgLen {
				if ev, ok := parseProcEvent(msg[cnMsgLen : cnMsgLen+dlen]); ok {
					ev.seq, ev.ack = ne.Uint32(msg[8:12]), ne.Uint32(msg[12:16])
					out = append(out, ev)
				}
			}
		}
		adv := (int(l) + 3) &^ 3 // NLMSG_ALIGN
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

func parseProcEvent(d []byte) (cnEvent, bool) {
	ne := binary.NativeEndian
	ev := cnEvent{what: ne.Uint32(d[0:4]), ts: ne.Uint64(d[8:16])}
	data := d[procEvHdrLen:]
	i32 := func(off int) int { return int(int32(ne.Uint32(data[off : off+4]))) }
	switch ev.what {
	case procEventNone:
		if len(data) < 4 {
			return ev, false
		}
		ev.err = ne.Uint32(data[0:4])
	case procEventFork:
		if len(data) < 16 {
			return ev, false
		}
		ev.parentPID, ev.parentTGID, ev.childPID, ev.childTGID = i32(0), i32(4), i32(8), i32(12)
	case procEventExit:
		if len(data) < 16 {
			return ev, false
		}
		ev.pid, ev.tgid = i32(0), i32(4)
		ev.exitCode, ev.exitSignal = ne.Uint32(data[8:12]), ne.Uint32(data[12:16])
		if len(data) >= 24 {
			ev.parentPID, ev.parentTGID = i32(16), i32(20)
		}
	default:
		// exec, uid, gid, sid, ptrace, comm, coredump: pid and tgid first.
		if len(data) < 8 {
			return ev, false
		}
		ev.pid, ev.tgid = i32(0), i32(4)
	}
	return ev, true
}

// cnControl builds the message that switches proc events on (LISTEN) or off
// (IGNORE) for this socket. The kernel's acknowledgement carries ack+1
// (verified on 6.18: seq is replaced by the kernel's per-CPU event
// counter), which is how the monitor tells its own LISTEN acknowledgement
// from another listener's.
func cnControl(seq, ack, portID, op uint32) []byte {
	b := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:4], uint32(len(b)))
	ne.PutUint16(b[4:6], nlmsgDone)
	ne.PutUint16(b[6:8], 0)
	ne.PutUint32(b[8:12], seq)
	ne.PutUint32(b[12:16], portID)
	m := b[nlmsgHdrLen:]
	ne.PutUint32(m[0:4], cnIdxProc)
	ne.PutUint32(m[4:8], cnValProc)
	ne.PutUint32(m[8:12], seq)
	ne.PutUint32(m[12:16], ack)
	ne.PutUint16(m[16:18], 4)
	ne.PutUint16(m[18:20], 0)
	ne.PutUint32(m[20:24], op)
	return b
}
