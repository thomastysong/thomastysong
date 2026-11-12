package procmon

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func TestRunWithHostRoot(t *testing.T) {
	h := newFakeHost(t)
	lifecycleTree(h)
	var mu sync.Mutex
	var evs []*event.Event
	m := New(Options{Catalog: loadCatalog(t), HostRoot: h.root, NoOsquery: true, Idle: 30 * time.Millisecond, Active: 10 * time.Millisecond,
		Emit: func(e *event.Event) {
			mu.Lock()
			evs = append(evs, e)
			mu.Unlock()
		}})
	if runtime.GOOS != "linux" {
		if err := m.Run(context.Background()); err == nil {
			t.Fatal("HostRoot must be refused off Linux")
		}
		return
	}
	m.disabled = func() bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	waitFor(t, 5*time.Second, "the start event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(ofType(evs, event.TypeAgentProcessStart)) == 1
	})
	if err := m.Run(ctx); !errors.Is(err, errAlreadyRunning) {
		t.Errorf("second Run = %v", err)
	}
	if m.Source() != SourcePoll {
		t.Errorf("source = %s", m.Source())
	}
	h.remove(400)
	waitFor(t, 5*time.Second, "the stop event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(ofType(evs, event.TypeAgentProcessStop)) == 1
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewSource(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := newSource("/host"); err == nil {
			t.Error("HostRoot accepted off Linux")
		}
		if s, err := newSource(""); err != nil || s.kind() != "platform" {
			t.Errorf("default source = %v %v", s, err)
		}
		return
	}
	if s, err := newSource(""); err != nil || s.kind() != "procfs" {
		t.Errorf("default = %v %v", s, err)
	}
	if s, err := newSource("/"); err != nil || s.kind() != "procfs" {
		t.Errorf("slash = %v %v", s, err)
	}
	dir := t.TempDir()
	if _, err := newSource(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing host root accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "proc"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newSource(dir); err == nil {
		t.Error("host root whose proc is a file accepted")
	}
}

func TestEmitterSurvivesAndQueueBounds(t *testing.T) {
	calls := 0
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true, Emit: func(*event.Event) {
		calls++
		panic("consumer bug")
	}})
	stop, done := make(chan struct{}), make(chan struct{})
	go m.emitLoop(stop, done)
	m.enqueue([]*event.Event{{Type: "a"}, nil, {Type: "b"}})
	waitFor(t, 2*time.Second, "both events", func() bool { return m.Stats().Errors == 2 })
	close(stop)
	<-done
	if calls != 2 {
		t.Errorf("Emit called %d times", calls)
	}
	// Without a running emitter the queue fills and then drops.
	evs := make([]*event.Event, queueCap+5)
	for i := range evs {
		evs[i] = &event.Event{Type: "x"}
	}
	m.enqueue(evs)
	if got := m.Stats().QueueDropped; got != 5 {
		t.Errorf("queue dropped %d", got)
	}
	// No Emit configured: nothing is queued at all.
	q := New(Options{Catalog: loadCatalog(t), NoOsquery: true})
	q.enqueue(evs[:3])
	if len(q.queue) != 0 {
		t.Error("events queued without a consumer")
	}
}

func TestZeroAndBadInput(t *testing.T) {
	var z Monitor
	if z.Source() != SourcePoll || z.ExecHealthy() || len(z.Agents()) != 0 {
		t.Error("zero Monitor")
	}
	if _, ok := z.Attribute(5); ok {
		t.Error("zero Monitor attributes")
	}
	if err := z.Run(context.Background()); err == nil {
		t.Error("zero Monitor runs")
	}
	_ = z.Stats()
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true})
	for _, pid := range []int{-1, 0, maxPID + 1} {
		if _, ok := m.Attribute(pid); ok {
			t.Errorf("Attribute(%d) = true", pid)
		}
	}
}

// TestNoExecImport enforces design decision 7: nothing on the collection
// path imports os/exec. The self-test process is started with
// os.StartProcess on a fixed system path.
func TestNoExecImport(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fs, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" {
				t.Errorf("%s imports os/exec", f)
			}
		}
	}
}
