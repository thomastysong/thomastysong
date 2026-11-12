//go:build linux || darwin

package platform

import (
	"net"
	"os"
	"strconv"
	"testing"
)

// listenUnix listens on a socket inside a fresh temporary directory. It
// enters that directory and binds a relative name, because the absolute path
// of a test's temp dir can exceed the 104-byte sockaddr_un limit on macOS.
func listenUnix(t *testing.T) (l net.Listener, dir, name string) {
	t.Helper()
	dir = t.TempDir()
	t.Chdir(dir)
	name = "hook.sock"
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, dir, name
}

func TestPeerCred(t *testing.T) {
	l, _, sock := listenUnix(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer server.Close()

	wantUID := strconv.Itoa(os.Getuid())
	for name, c := range map[string]net.Conn{"server side": server, "client side": client} {
		uid, pid, err := PeerCred(c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if uid != wantUID {
			t.Errorf("%s: uid = %q, want %q", name, uid, wantUID)
		}
		// Both ends are this process.
		if pid != os.Getpid() {
			t.Errorf("%s: pid = %d, want %d", name, pid, os.Getpid())
		}
	}

	// A wrapper that hides the socket cannot be asked.
	if _, _, err := PeerCred(wrappedConn{server}); err == nil {
		t.Error("PeerCred answered for a connection without descriptor access")
	}
	server.Close()
	if _, _, err := PeerCred(server); err == nil {
		t.Error("PeerCred answered for a closed connection")
	}
}

type wrappedConn struct{ net.Conn }

func TestPeerCredFromChildProcess(t *testing.T) {
	// The peer is a different process: the pid must be the child's, which
	// is what the hook server uses to find the calling agent.
	l, dir, sock := listenUnix(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	// The child starts in the socket's directory and dials the same
	// relative name.
	cmd := startHelper(t, dir, helperSockEnv+"="+sock)
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer server.Close()
	uid, pid, err := PeerCred(server)
	if err != nil {
		t.Fatal(err)
	}
	if uid != strconv.Itoa(os.Getuid()) {
		t.Errorf("uid = %q, want %d", uid, os.Getuid())
	}
	if pid != cmd.Process.Pid {
		t.Errorf("pid = %d, want the child's pid %d (own pid is %d)", pid, cmd.Process.Pid, os.Getpid())
	}
	// The pid leads back to the process table entry of the caller.
	p, err := ProcessByPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.PPID != os.Getpid() || p.UID != uid {
		t.Errorf("peer process = %+v", p)
	}
}

func TestPeerCredRefusesNonUnixConns(t *testing.T) {
	if _, _, err := PeerCred(nil); err == nil {
		t.Error("nil connection accepted")
	}
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if _, _, err := PeerCred(p1); err == nil {
		t.Error("in-memory pipe accepted")
	}
	// A datagram socket has no connection, hence no peer to vouch for.
	t.Chdir(t.TempDir())
	addr := &net.UnixAddr{Name: "d.sock", Net: "unixgram"}
	dg, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Skipf("unixgram: %v", err)
	}
	defer dg.Close()
	if _, _, err := PeerCred(dg); err == nil {
		t.Error("datagram socket accepted")
	}
}
