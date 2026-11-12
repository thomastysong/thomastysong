//go:build unix

package osqexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	osqgen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/transport"
)

// thriftManager is a minimal osquery extension manager: it speaks the real
// wire protocol on a real unix socket and answers queries from a fake.
type thriftManager struct {
	fake *fakeOsquery
	mu   sync.Mutex
	n    int
}

func (m *thriftManager) Ping(context.Context) (*osqgen.ExtensionStatus, error) {
	return &osqgen.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

func (m *thriftManager) Call(context.Context, string, string, osqgen.ExtensionPluginRequest) (*osqgen.ExtensionResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *thriftManager) Shutdown(context.Context) error { return nil }

func (m *thriftManager) Extensions(context.Context) (osqgen.InternalExtensionList, error) {
	return osqgen.InternalExtensionList{}, nil
}

func (m *thriftManager) Options(context.Context) (osqgen.InternalOptionList, error) {
	return osqgen.InternalOptionList{}, nil
}

func (m *thriftManager) RegisterExtension(context.Context, *osqgen.InternalExtensionInfo, osqgen.ExtensionRegistry) (*osqgen.ExtensionStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *thriftManager) DeregisterExtension(context.Context, osqgen.ExtensionRouteUUID) (*osqgen.ExtensionStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *thriftManager) Query(ctx context.Context, sql string) (*osqgen.ExtensionResponse, error) {
	m.mu.Lock()
	m.n++
	m.mu.Unlock()
	rows, err := m.fake.QueryRowsContext(ctx, sql)
	if err != nil {
		// osqueryd reports SQL errors in the status, not as a transport error.
		return &osqgen.ExtensionResponse{Status: &osqgen.ExtensionStatus{Code: 1, Message: err.Error()}}, nil
	}
	return &osqgen.ExtensionResponse{Status: &osqgen.ExtensionStatus{Code: 0, Message: "OK"}, Response: rows}, nil
}

func (m *thriftManager) GetQueryColumns(context.Context, string) (*osqgen.ExtensionResponse, error) {
	return nil, errors.New("not implemented")
}

// TestPollOverRealSocket runs the real osquery-go client and the ownership
// check against a Thrift server on a unix socket.
func TestPollOverRealSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "o.em")
	if len(sock) > 100 {
		t.Skipf("temp dir too deep for a unix socket (%d bytes)", len(sock))
	}
	fake := newFake()
	now := time.Now().Unix()
	fake.add("process_events",
		auditRow(1, now-2, 200, 100, "/usr/bin/bash", "bash -c ls"),
		auditRow(2, now-2, 300, 200, "/usr/bin/ls", "ls --color=auto"),
		auditRow(3, now-1, 400, 1, "/usr/sbin/cron", "cron"),
	)
	mgr := &thriftManager{fake: fake}
	st, err := transport.OpenServer(sock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server := thrift.NewTSimpleServer4(osqgen.NewExtensionManagerProcessor(mgr), st,
		thrift.NewTTransportFactory(), thrift.NewTBinaryProtocolFactoryDefault())
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.AcceptLoop()
	}()
	t.Cleanup(func() {
		_ = server.Stop()
		<-done
	})

	s := New(Options{Socket: sock, Attribute: agentTree})
	s.disabled = func() bool { return false }
	defer s.Close()
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v (status %s: %s)", err, s.Status(), s.Detail())
	}
	if got := names(evs); len(got) != 2 || got[0] != "bash" || got[1] != "ls" {
		t.Fatalf("events = %v, want bash and ls", got)
	}
	if st := s.Stats(); st.Socket != sock || st.Table != "process_events" {
		t.Fatalf("stats = %+v", st)
	}

	// A second poll reuses the connection and finds the new row only.
	fake.add("process_events", auditRow(4, time.Now().Unix(), 201, 100, "/usr/bin/git", "git status --token "+strconv.Itoa(123456789)))
	evs, err = s.Poll(context.Background())
	if err != nil || len(evs) != 1 || evs[0].Process.Name != "git" {
		t.Fatalf("second poll: %v, err %v", names(evs), err)
	}

	// A socket that vanishes turns into "unavailable", not into a hang.
	s.Close()
	_ = server.Stop()
	<-done
	_ = os.Remove(sock)
	start := time.Now()
	_, err = s.Poll(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after the socket vanished: err = %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("poll took %v with no socket", d)
	}
}
