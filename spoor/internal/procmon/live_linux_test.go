//go:build linux

package procmon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// These tests run real processes on the build host. The fake agent is a
// shell script named like a catalog binary ("codex"): the kernel names the
// process after the script, which is what the catalog matches.

func writeAgentScript(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "codex")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

type collector struct {
	mu  sync.Mutex
	evs []*event.Event
}

func (c *collector) emit(e *event.Event) {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
}

func (c *collector) find(f func(*event.Event) bool) *event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.evs {
		if f(e) {
			return e
		}
	}
	return nil
}

func (c *collector) all() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*event.Event(nil), c.evs...)
}


func startMonitor(t *testing.T, o Options, tune func(*Monitor)) (*Monitor, *collector) {
	t.Helper()
	c := &collector{}
	o.Catalog = loadCatalog(t)
	o.Emit = c.emit
	m := New(o)
	m.disabled = func() bool { return false }
	if tune != nil {
		tune(m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	})
	return m, c
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}
}

func TestLivePollAgentTree(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := writeAgentScript(t, `CODEX_THREAD_ID=live-thread-1 sleep 60 &
echo $! > `+pidFile+`
wait`)
	m, c := startMonitor(t, Options{Idle: 100 * time.Millisecond, Active: 50 * time.Millisecond, NoOsquery: true}, nil)
	cmd := exec.Command(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	root := cmd.Process.Pid
	waitFor(t, 5*time.Second, "the agent root", func() bool {
		for _, a := range m.Agents() {
			if a.PID == root {
				return true
			}
		}
		return false
	})
	if m.Source() != SourcePoll || m.ExecHealthy() {
		t.Errorf("source %s healthy %v", m.Source(), m.ExecHealthy())
	}
	var child int
	waitFor(t, 5*time.Second, "the child pid", func() bool {
		b, err := os.ReadFile(pidFile)
		child, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && child > 0
	})
	waitFor(t, 5*time.Second, "the child's exec event", func() bool {
		return c.find(func(e *event.Event) bool {
			return e.Type == event.TypeProcessExec && e.Process.PID == child && e.Agent.PID == root
		}) != nil
	})
	ap, ok := m.Attribute(child)
	if !ok || ap.PID != root || ap.AgentID != "codex" || !contains(ap.SessionIDs, "live-thread-1") {
		t.Fatalf("Attribute(child) = %+v %v", ap, ok)
	}
	start := c.find(func(e *event.Event) bool { return e.Type == event.TypeAgentProcessStart && e.Process.PID == root })
	if start == nil || start.Agent.ID != "codex" || start.Process.StartTime.IsZero() {
		t.Fatalf("start event = %+v", start)
	}
	killGroup(cmd)
	waitFor(t, 5*time.Second, "the stop event", func() bool {
		return c.find(func(e *event.Event) bool { return e.Type == event.TypeAgentProcessStop && e.Process.PID == root }) != nil
	})
}

func TestLiveProcessConnector(t *testing.T) {
	cn, err := openCNProc()
	if err != nil {
		t.Skipf("process connector unavailable here: %v", err)
	}
	cn.close()
	m, c := startMonitor(t, Options{ExecEvents: true, NoOsquery: true, Idle: 500 * time.Millisecond}, func(m *Monitor) {
		// The rate cap has its own test; here every exec is counted.
		m.rate, m.burst = 1e6, 1e6
		m.canaryFirst = 100 * time.Millisecond
	})
	waitFor(t, 5*time.Second, "cn_proc", func() bool { return m.Source() == SourceCNProc })
	const n = 100
	script := writeAgentScript(t, `i=1
while [ $i -le `+strconv.Itoa(n)+` ]; do
  sh -c ": spoor-live-$i; sleep 0.05; :"
  i=$((i+1))
done`)
	cmd := exec.Command(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	root := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	re := regexp.MustCompile(`spoor-live-(\d+);`)
	seen := map[string]bool{}
	sleeps := 0
	for _, e := range c.all() {
		if e.Type != event.TypeProcessExec || e.Agent == nil || e.Agent.PID != root {
			continue
		}
		if e.Labels["exec_source"] != SourceCNProc {
			continue
		}
		joined := strings.Join(e.Process.Args, " ")
		if mt := re.FindStringSubmatch(joined); mt != nil {
			seen[mt[1]] = true
		}
		if e.Process.Name == "sleep" {
			sleeps++
		}
	}
	st := m.Stats()
	t.Logf("attributed %d of %d short-lived children (%d sleep execs); stats %+v", len(seen), n, sleeps, st)
	if len(seen) < n*95/100 {
		t.Fatalf("only %d of %d short-lived children attributed", len(seen), n)
	}
	if c.find(func(e *event.Event) bool { return e.Type == event.TypeAgentProcessStart && e.Process.PID == root }) == nil {
		t.Error("no start event for the agent")
	}
	waitFor(t, 5*time.Second, "the agent's stop event", func() bool {
		e := c.find(func(e *event.Event) bool { return e.Type == event.TypeAgentProcessStop && e.Process.PID == root })
		return e != nil && e.Outcome != nil && e.Outcome.Status == "ok"
	})
	waitFor(t, 10*time.Second, "a passed exec self-test", m.ExecHealthy)
	for _, e := range c.all() {
		if e.Process != nil && strings.Contains(strings.Join(e.Process.Args, " "), canaryPrefix) {
			t.Fatal("the self-test process was emitted")
		}
	}
}

// TestLiveHostRootReaderAgreesWithPlatform reads the real /proc in
// host-root mode and checks it against internal/platform.
func TestLiveHostRootReaderAgreesWithPlatform(t *testing.T) {
	own := newProcfsSource("/proc", "/etc/passwd")
	self := os.Getpid()
	got, id, ok := own.read(self)
	if !ok {
		t.Fatal("cannot read self")
	}
	want, err := platform.ProcessByPID(self)
	if err != nil {
		t.Fatal(err)
	}
	if got.PPID != want.PPID || got.Exe != want.Exe || strings.Join(got.Args, "\x00") != strings.Join(want.Args, "\x00") ||
		got.UID != want.UID || got.Name != want.Name || !got.Start.Equal(want.Start) {
		t.Fatalf("host-root reader %+v\nplatform        %+v", got, want)
	}
	if want.User != "" && got.User != want.User {
		t.Errorf("user %q vs %q", got.User, want.User)
	}
	if id.key == 0 || id.comm == "" {
		t.Errorf("ident = %+v", id)
	}
	env, err := own.env(self, nil)
	if err != nil || len(env) == 0 {
		t.Fatalf("env: %v", err)
	}
	if own.cwd(self) == "" {
		t.Error("no cwd")
	}
	kids, ok := own.children(self)
	if !ok {
		t.Skip("kernel without CONFIG_PROC_CHILDREN")
	}
	_ = kids
	// Container ids from the own cgroup parser match platform's for every
	// visible process (this host runs Docker containers when available).
	ids, _, err := own.list()
	if err != nil {
		t.Fatal(err)
	}
	containers := 0
	for _, i := range ids {
		cid, rt, pod := own.workload(i.pid)
		pid2, rt2 := platform.ContainerOf(i.pid)
		if cid != pid2 || (cid != "" && rt != rt2) || pod != platform.PodOf(i.pid) {
			t.Errorf("pid %d: own %q/%q/%q platform %q/%q", i.pid, cid, rt, pod, pid2, rt2)
		}
		if cid != "" {
			containers++
		}
	}
	t.Logf("%d processes, %d in containers", len(ids), containers)
}

func TestLiveAttributeOnDemand(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := writeAgentScript(t, `CODEX_THREAD_ID=on-demand sleep 60 &
echo $! > `+pidFile+`
wait`)
	cmd := exec.Command(script, "--dangerously-bypass-approvals-and-sandbox")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	var child int
	waitFor(t, 5*time.Second, "the child pid", func() bool {
		b, err := os.ReadFile(pidFile)
		child, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && child > 0
	})
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true})
	ap, ok := m.Attribute(child)
	if !ok || ap.PID != cmd.Process.Pid || ap.AgentID != "codex" || !contains(ap.Flags, "--dangerously-bypass-approvals-and-sandbox") {
		t.Fatalf("Attribute = %+v %v", ap, ok)
	}
	if _, ok := m.Attribute(1 << 29); ok {
		t.Error("a pid that does not exist is attributed")
	}
}

func BenchmarkPrepareSelf(b *testing.B) {
	m := New(Options{Catalog: loadCatalog(b), NoOsquery: true})
	self := os.Getpid()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if m.prepare(ident{pid: self}, nil, viaCNProc, time.Time{}) == nil {
			b.Fatal("prepare failed")
		}
	}
}

func BenchmarkFullScan(b *testing.B) {
	m := New(Options{Catalog: loadCatalog(b), NoOsquery: true})
	m.fullScan(time.Now())
	drain(m)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.fullScan(time.Now())
		drain(m)
	}
}
