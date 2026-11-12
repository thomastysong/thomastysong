package procmon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// fakeProc describes one process of a fixture procfs tree.
type fakeProc struct {
	pid, ppid int
	comm      string
	state     byte
	ticks     uint64 // start ticks since boot
	args      []string
	exe       string
	uid       string
	env       map[string]string
	rawEnv    []byte // overrides env when set
	cgroup    string
	cwd       string
	children  []int
	flags     uint64 // stat field 9; 0 means an ordinary user process
}

const fixtureBoot = 1_800_000_000 // btime of the fixture host

// fakeHost is a HostRoot directory with a proc/ tree and etc/passwd.
type fakeHost struct {
	t    *testing.T
	root string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture trees use symlinks")
	}
	root := t.TempDir()
	h := &fakeHost{t: t, root: root}
	h.write("proc/stat", fmt.Sprintf("cpu  1 2 3 4\nintr 0\nbtime %d\nprocesses 9\n", fixtureBoot))
	h.write("etc/passwd", "root:x:0:0:root:/root:/bin/sh\ndev:x:1000:1000:Dev:/home/dev:/bin/bash\n")
	return h
}

func (h *fakeHost) write(rel, content string) {
	h.t.Helper()
	p := filepath.Join(h.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) dir(pid int) string { return filepath.Join(h.root, "proc", strconv.Itoa(pid)) }

func (h *fakeHost) add(p fakeProc) {
	h.t.Helper()
	if p.state == 0 {
		p.state = 'S'
	}
	if p.uid == "" {
		p.uid = "1000"
	}
	d := h.dir(p.pid)
	_ = os.RemoveAll(d)
	if err := os.MkdirAll(filepath.Join(d, "task", strconv.Itoa(p.pid)), 0o755); err != nil {
		h.t.Fatal(err)
	}
	// Fields after the name: state ppid pgrp session tty tpgid flags minflt
	// cminflt majflt cmajflt utime stime cutime cstime priority nice
	// threads itreal starttime ...
	if p.flags == 0 {
		p.flags = 4194560 // PF_RANDOMIZE | PF_SUPERPRIV, as an ordinary shell has
	}
	stat := fmt.Sprintf("%d (%s) %c %d %d %d 0 -1 %d 0 0 0 0 0 0 0 0 20 0 1 0 %d 1000 10 18446744073709551615\n",
		p.pid, p.comm, p.state, p.ppid, p.pid, p.pid, p.flags, p.ticks)
	h.write(rel(d, h.root, "stat"), stat)
	h.write(rel(d, h.root, "cmdline"), strings.Join(p.args, "\x00")+"\x00")
	h.write(rel(d, h.root, "status"), fmt.Sprintf("Name:\t%s\nState:\t%c\nPPid:\t%d\nUid:\t%s\t%s\t%s\t%s\n", p.comm, p.state, p.ppid, p.uid, p.uid, p.uid, p.uid))
	env := p.rawEnv
	if env == nil {
		keys := make([]string, 0, len(p.env))
		for k := range p.env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + "=" + p.env[k] + "\x00")
		}
		env = []byte(b.String())
	}
	if err := os.WriteFile(filepath.Join(d, "environ"), env, 0o644); err != nil {
		h.t.Fatal(err)
	}
	cg := p.cgroup
	if cg == "" {
		cg = "0::/user.slice/user-1000.slice/session-1.scope\n"
	}
	h.write(rel(d, h.root, "cgroup"), cg)
	h.write(rel(d, h.root, "task/"+strconv.Itoa(p.pid)+"/children"), joinInts(p.children))
	if p.exe != "" {
		if err := os.Symlink(p.exe, filepath.Join(d, "exe")); err != nil {
			h.t.Fatal(err)
		}
	}
	if p.cwd != "" {
		if err := os.Symlink(p.cwd, filepath.Join(d, "cwd")); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *fakeHost) remove(pid int) { _ = os.RemoveAll(h.dir(pid)) }

func rel(dir, root, name string) string {
	r, _ := filepath.Rel(root, filepath.Join(dir, name))
	return filepath.ToSlash(r)
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	if len(s) == 0 {
		return ""
	}
	return strings.Join(s, " ") + " "
}

var (
	testCatOnce sync.Once
	testCat     *catalog.Catalog
	testCatErr  error
)

func loadCatalog(t testing.TB) *catalog.Catalog {
	t.Helper()
	testCatOnce.Do(func() { testCat, testCatErr = catalog.Load() })
	if testCatErr != nil {
		t.Fatal(testCatErr)
	}
	return testCat
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newFixtureMonitor builds a Monitor over a fixture tree with the network
// providers off and a controllable clock. Events are read with drain.
func newFixtureMonitor(t *testing.T, h *fakeHost) (*Monitor, *fakeClock) {
	t.Helper()
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true, Emit: func(*event.Event) {}})
	m.src = newProcfsSource(filepath.Join(h.root, "proc"), filepath.Join(h.root, "etc", "passwd"))
	m.initErr = nil
	clk := &fakeClock{t: time.Unix(fixtureBoot+10_000, 0)}
	m.now = clk.now
	m.disabled = func() bool { return false }
	m.openCN = func() (cnConn, error) { return nil, fmt.Errorf("no connector in fixtures") }
	m.self = -1
	return m, clk
}

// drain returns the queued events.
func drain(m *Monitor) []*event.Event {
	var out []*event.Event
	for {
		select {
		case ev := <-m.queue:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func ofType(evs []*event.Event, typ string) []*event.Event {
	var out []*event.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func byPID(evs []*event.Event, pid int) *event.Event {
	for _, e := range evs {
		if e.Process != nil && e.Process.PID == pid {
			return e
		}
	}
	return nil
}

// marshalAll serialises events the way the sinks do.
func marshalAll(t *testing.T, evs []*event.Event) string {
	t.Helper()
	var b strings.Builder
	for _, e := range evs {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	return b.String()
}

func procRec(name, exe string, args []string) *platform.Proc {
	return &platform.Proc{Name: name, Exe: exe, Args: args}
}
