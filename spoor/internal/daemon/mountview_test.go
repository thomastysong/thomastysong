package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// fakeMountProc is a procfs tree with ns/mnt and root links, as the kernel
// shows them: ns/mnt is a link whose text names the namespace, root a link
// to the process's root directory.
type fakeMountProc struct {
	t    *testing.T
	proc string
}

func newFakeMountProc(t *testing.T) *fakeMountProc {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture trees use symlinks")
	}
	return &fakeMountProc{t: t, proc: filepath.Join(t.TempDir(), "proc")}
}

// add creates /proc/<name> with the given namespace text and root
// directory ("" leaves the link out, as for a process that is gone or that
// the sensor may not look into).
func (f *fakeMountProc) add(name, ns, root string) {
	f.t.Helper()
	d := filepath.Join(f.proc, name)
	if err := os.MkdirAll(filepath.Join(d, "ns"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if ns != "" {
		if err := os.Symlink(ns, filepath.Join(d, "ns", "mnt")); err != nil {
			f.t.Fatal(err)
		}
	}
	if root != "" {
		if err := os.Symlink(root, filepath.Join(d, "root")); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestMountViewFakeProcfs(t *testing.T) {
	f := newFakeMountProc(t)
	roots := t.TempDir()
	hostRoot := filepath.Join(roots, "host")
	sensorRoot := filepath.Join(roots, "sensor-overlay")
	agentRoot := filepath.Join(roots, "agent-overlay")
	for _, d := range []string{hostRoot, sensorRoot, agentRoot} {
		mustMkdir(t, d, 0o755)
	}
	// Node mode: the sensor in its own container, the host's pids visible.
	f.add("self", "mnt:[4026532300]", sensorRoot)
	f.add("1", "mnt:[4026531841]", hostRoot)         // the host's init
	f.add("200", "mnt:[4026532400]", agentRoot)      // an agent in another container
	f.add("201", "mnt:[4026532300]", sensorRoot)     // a process of the sensor's own container
	f.add("202", "", "")                             // gone, or not ours to read
	f.add("203", "mnt:[4026532300]", "")             // namespace readable, root not
	f.add("204", "", sensorRoot)                     // root readable, namespace not
	f.add("205", "mnt:[4026532500]", "/nonexistent") // a root that does not resolve
	v := newMountView(f.proc)
	for pid, want := range map[int]bool{1: false, 200: false, 201: true, 202: false, 203: true, 204: true, 205: false, 999: false, 0: false, -1: false} {
		if got := v.same(pid); got != want {
			t.Errorf("node mode: same(%d) = %v, want %v", pid, got, want)
		}
	}

	// A systemd unit: a private mount namespace over the host's root.
	g := newFakeMountProc(t)
	g.add("self", "mnt:[4026532900]", hostRoot)
	g.add("300", "mnt:[4026531841]", hostRoot)  // a user's agent on the host
	g.add("301", "mnt:[4026532400]", agentRoot) // a containerised agent
	v = newMountView(g.proc)
	if !v.same(300) {
		t.Error("systemd sandbox: an agent on the host's root was refused")
	}
	if v.same(301) {
		t.Error("systemd sandbox: a containerised agent's path was taken for the host's")
	}

	// No procfs (macOS, Windows): one view.
	if !newMountView(filepath.Join(t.TempDir(), "none")).same(42) {
		t.Error("without procfs every process must share the view")
	}
}

// TestNodeModeProjectScanSkipsForeignNamespace is the regression test for
// the confused deputy in node mode: an agent in another container, whose
// uid matches an account of the sensor image, has its working directory
// ("/etc", "/var/lib/spoor") scanned in the SENSOR's mount namespace.
// Project scans are only queued for processes that share the sensor's view.
func TestNodeModeProjectScanSkipsForeignNamespace(t *testing.T) {
	f := newFixture(t)
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	s := d.scans
	p := newFakeMountProc(t)
	roots := t.TempDir()
	sensorRoot, agentRoot := filepath.Join(roots, "sensor"), filepath.Join(roots, "agent")
	mustMkdir(t, sensorRoot, 0o755)
	mustMkdir(t, agentRoot, 0o755)
	p.add("self", "mnt:[4026532300]", sensorRoot)
	p.add("200", "mnt:[4026532400]", agentRoot)  // agent in another container
	p.add("201", "mnt:[4026532300]", sensorRoot) // same namespace
	p.add("202", "mnt:[4026532401]", sensorRoot) // same root, own namespace
	s.mnt = newMountView(p.proc)

	uid := f.user.UID
	user := event.User{Name: f.user.Name, ID: uid}
	foreign := filepath.Join(f.user.Home, "in-container")
	s.noteAgents([]agentCWD{
		{agent: "claude-code", cwd: foreign, user: user, pid: 200},
		{agent: "claude-code", cwd: filepath.Join(f.user.Home, "same-ns"), user: user, pid: 201},
		{agent: "claude-code", cwd: filepath.Join(f.user.Home, "same-root"), user: user, pid: 202},
		{agent: "claude-code", cwd: filepath.Join(f.user.Home, "gone"), user: user, pid: 203},
	})
	got := map[string]bool{}
	for len(s.projQ) > 0 {
		got[(<-s.projQ).dir] = true
	}
	want := map[string]bool{filepath.Join(f.user.Home, "same-ns"): true, filepath.Join(f.user.Home, "same-root"): true}
	if len(got) != len(want) || !got[filepath.Join(f.user.Home, "same-ns")] || !got[filepath.Join(f.user.Home, "same-root")] {
		t.Errorf("queued %v, want %v", got, want)
	}
	if n := d.board.get("scan.project_foreign_ns"); n != 2 {
		t.Errorf("scan.project_foreign_ns = %d, want 2", n)
	}
	// Seen again every tick: refused once, not re-read every time.
	s.noteAgents([]agentCWD{{agent: "claude-code", cwd: foreign, user: user, pid: 200}})
	if n := d.board.get("scan.project_foreign_ns"); n != 2 {
		t.Errorf("a refused process was checked again: %d", n)
	}
	// The same path from a process that shares the view is still scanned.
	s.noteAgents([]agentCWD{{agent: "claude-code", cwd: foreign, user: user, pid: 201}})
	if len(s.projQ) != 1 {
		t.Errorf("the path refused for a foreign process was not queued for a local one")
	}
	// Session records from this sensor's own spools and logs carry no
	// process: they are queued as before.
	s.noteSessions([]*event.Event{sessionEvent(uid, filepath.Join(f.user.Home, "hooked"))})
	if len(s.projQ) != 2 {
		t.Errorf("a hook session's project was not queued (%d queued)", len(s.projQ))
	}
}
