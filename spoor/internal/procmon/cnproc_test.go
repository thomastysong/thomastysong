package procmon

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// cnMessage builds one netlink connector datagram carrying a proc_event.
func cnMessage(what uint32, ts uint64, data []uint32) []byte {
	ne := binary.NativeEndian
	ev := make([]byte, procEvHdrLen+4*len(data))
	ne.PutUint32(ev[0:4], what)
	ne.PutUint32(ev[4:8], 3)
	ne.PutUint64(ev[8:16], ts)
	for i, v := range data {
		ne.PutUint32(ev[procEvHdrLen+4*i:], v)
	}
	b := make([]byte, nlmsgHdrLen+cnMsgLen+len(ev))
	ne.PutUint32(b[0:4], uint32(len(b)))
	ne.PutUint16(b[4:6], nlmsgDone)
	m := b[nlmsgHdrLen:]
	ne.PutUint32(m[0:4], cnIdxProc)
	ne.PutUint32(m[4:8], cnValProc)
	ne.PutUint32(m[8:12], 77)
	ne.PutUint32(m[12:16], 5)
	ne.PutUint16(m[16:18], uint16(len(ev)))
	copy(m[cnMsgLen:], ev)
	return b
}

func TestParseCN(t *testing.T) {
	fork := cnMessage(procEventFork, 10, []uint32{100, 100, 101, 101})
	exec := cnMessage(procEventExec, 11, []uint32{101, 101})
	exit := cnMessage(procEventExit, 12, []uint32{101, 101, 256, 17, 100, 100})
	oldExit := cnMessage(procEventExit, 13, []uint32{102, 102, 9, 17}) // pre-4.x layout, no parent
	ack := cnMessage(procEventNone, 0, []uint32{0})
	comm := cnMessage(procEventComm, 14, []uint32{101, 101, 0x41414141, 0, 0, 0})

	var datagram []byte
	for _, m := range [][]byte{fork, exec, exit, oldExit, ack, comm} {
		datagram = append(datagram, m...)
		for len(datagram)%4 != 0 {
			datagram = append(datagram, 0)
		}
	}
	evs := parseCN(datagram, nil)
	if len(evs) != 6 {
		t.Fatalf("parsed %d events: %+v", len(evs), evs)
	}
	if e := evs[0]; e.what != procEventFork || e.parentTGID != 100 || e.childPID != 101 || e.childTGID != 101 || e.ts != 10 {
		t.Errorf("fork = %+v", e)
	}
	if e := evs[1]; e.what != procEventExec || e.pid != 101 || e.tgid != 101 {
		t.Errorf("exec = %+v", e)
	}
	if e := evs[2]; e.what != procEventExit || e.exitCode != 256 || e.parentTGID != 100 {
		t.Errorf("exit = %+v", e)
	}
	if e := evs[3]; e.what != procEventExit || e.exitCode != 9 || e.parentTGID != 0 {
		t.Errorf("old exit = %+v", e)
	}
	if e := evs[4]; e.what != procEventNone || e.ack != 5 || e.seq != 77 {
		t.Errorf("ack = %+v", e)
	}
	if exitFromStatus(256).code != 1 || exitFromStatus(9).signal != 9 || exitFromStatus(0).code != 0 {
		t.Error("exit status decoding")
	}
}

func TestParseCNHostile(t *testing.T) {
	ne := binary.NativeEndian
	good := cnMessage(procEventExec, 1, []uint32{5, 5})
	cases := map[string][]byte{
		"empty":        nil,
		"short header": good[:10],
		"length past buffer": func() []byte {
			b := append([]byte(nil), good...)
			ne.PutUint32(b[0:4], 4096)
			return b
		}(),
		"length below header": func() []byte {
			b := append([]byte(nil), good...)
			ne.PutUint32(b[0:4], 3)
			return b
		}(),
		"other connector": func() []byte {
			b := append([]byte(nil), good...)
			ne.PutUint32(b[nlmsgHdrLen:], 9)
			return b
		}(),
		"not NLMSG_DONE": func() []byte {
			b := append([]byte(nil), good...)
			ne.PutUint16(b[4:6], 2)
			return b
		}(),
		"data length past message": func() []byte {
			b := append([]byte(nil), good...)
			ne.PutUint16(b[nlmsgHdrLen+16:], 4000)
			return b
		}(),
		"truncated fork": cnMessage(procEventFork, 1, []uint32{1, 1}),
		"truncated exec": cnMessage(procEventExec, 1, []uint32{1}),
	}
	for name, b := range cases {
		if evs := parseCN(b, nil); len(evs) != 0 {
			t.Errorf("%s: parsed %+v", name, evs)
		}
	}
	// The control message the monitor sends is not mistaken for an event.
	if evs := parseCN(cnControl(1, 2, 3, procCnMcastListen), nil); len(evs) != 0 {
		t.Errorf("control parsed as %+v", evs)
	}
}

func FuzzParseCN(f *testing.F) {
	f.Add(cnMessage(procEventFork, 10, []uint32{100, 100, 101, 101}))
	f.Add(cnMessage(procEventExit, 12, []uint32{101, 101, 256, 17, 100, 100}))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, e := range parseCN(b, nil) {
			_ = e
		}
	})
}

// fakeCN replays datagrams, then reports timeouts.
type fakeCN struct {
	msgs   chan []byte
	closed atomic.Bool
}

func (f *fakeCN) recv(buf []byte) (int, error) {
	select {
	case m, ok := <-f.msgs:
		if !ok {
			return 0, errors.New("socket closed")
		}
		if m == nil {
			return 0, errCNOverflow
		}
		return copy(buf, m), nil
	case <-time.After(20 * time.Millisecond):
		return 0, errCNTimeout
	}
}

func (f *fakeCN) close() { f.closed.Store(true) }

// TestCNEventsOnFixture drives the connector path against a fixture tree:
// a fork and exec under an agent root become a process.exec event, the
// root's exit becomes a stop event with the exit status, and an overrun
// asks for a resync.
func TestCNEventsOnFixture(t *testing.T) {
	h := newFakeHost(t)
	h.add(fakeProc{pid: 1, comm: "init", ticks: 1, args: []string{"/sbin/init"}, exe: "/sbin/init", uid: "0"})
	h.add(fakeProc{pid: 300, ppid: 1, comm: "codex", ticks: 100, args: []string{"codex", "--yolo"}, exe: "/usr/local/bin/codex"})
	m, _ := newFixtureMonitor(t, h)
	m.monoWall = func(uint64) time.Time { return time.Unix(fixtureBoot+20_000, 0) }
	m.fullScan(m.now())
	drain(m)

	fc := &fakeCN{msgs: make(chan []byte, 16)}
	stop := &atomic.Bool{}
	done := make(chan error, 1)
	go func() { done <- m.cnLoop(t.Context(), fc, stop) }()

	// fork 300 -> 301, then 301 execs git.
	fc.msgs <- cnMessage(procEventFork, 1, []uint32{300, 300, 301, 301})
	// A thread creation is not a process.
	fc.msgs <- cnMessage(procEventFork, 1, []uint32{300, 300, 399, 300})
	h.add(fakeProc{pid: 301, ppid: 300, comm: "git", ticks: 200, args: []string{"git", "push", "--force"}, exe: "/usr/bin/git",
		env: map[string]string{"CODEX_THREAD_ID": "th-1"}})
	fc.msgs <- cnMessage(procEventExec, 2, []uint32{301, 301})
	fc.msgs <- nil // overrun
	fc.msgs <- cnMessage(procEventExit, 3, []uint32{300, 300, 2 << 8, 17, 1, 1})

	deadline := time.Now().Add(5 * time.Second)
	var evs []*event.Event
	for time.Now().Before(deadline) {
		evs = append(evs, drain(m)...)
		if len(ofType(evs, event.TypeAgentProcessStop)) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop.Store(true)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ex := byPID(ofType(evs, event.TypeProcessExec), 301)
	if ex == nil || ex.Agent.PID != 300 || ex.Labels["exec_source"] != "cn_proc" || ex.Session == nil || ex.Session.ID != "th-1" {
		t.Fatalf("exec event = %+v", ex)
	}
	if !ex.TS.Equal(time.Unix(fixtureBoot+20_000, 0)) {
		t.Errorf("exec TS = %v", ex.TS)
	}
	stop1 := ofType(evs, event.TypeAgentProcessStop)
	if len(stop1) != 1 || stop1[0].Outcome == nil || stop1[0].Outcome.Status != "error" || *stop1[0].Outcome.ExitCode != 2 {
		t.Fatalf("stop = %+v", stop1)
	}
	if !m.resyncRq.Load() || m.Stats().Overflows != 1 {
		t.Error("overrun did not request a resync")
	}
	if m.nodes[399] != nil {
		t.Error("thread was recorded as a process")
	}
	// The exit mark keeps a stale listing from resurrecting the agent.
	m.mu.Lock()
	_, marked := m.exitMark[300]
	m.mu.Unlock()
	if !marked {
		t.Error("no exit mark")
	}
}

func TestCNLoopErrors(t *testing.T) {
	m, _ := newFixtureMonitor(t, newFakeHost(t))
	fc := &fakeCN{msgs: make(chan []byte)}
	close(fc.msgs)
	if err := m.cnLoop(t.Context(), fc, &atomic.Bool{}); err == nil {
		t.Fatal("a failing socket must end the reader with an error")
	}
}
