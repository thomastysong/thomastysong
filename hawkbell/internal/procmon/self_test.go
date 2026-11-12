package procmon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// writeBinary creates a regular file standing in for an executable.
func writeBinary(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("\x7fELF stand-in "+p), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFixtureSelfHookNotReported is the regression test for the real-agent
// run, where the monitor reported the agent's `hawkbell hook` invocations and
// their workers as the session's process.exec activity (4 of the 5 context
// records shipped with the finding). hawkbell's hook processes are recognised
// by argv[1] "hook" and the file identity of their executable; everything
// else the agent runs is still reported, including other hawkbell commands and
// a different program that only calls itself hawkbell.
func TestFixtureSelfHookNotReported(t *testing.T) {
	h := newFakeHost(t)
	bins := t.TempDir()
	installed := writeBinary(t, filepath.Join(bins, "usr", "bin"), "hawkbell")
	// The agent's own container or user namespace can put anything at the
	// installed path: a path is not an identity.
	decoy := writeBinary(t, filepath.Join(bins, "ctr", "usr", "bin"), "hawkbell")
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	h.add(fakeProc{pid: 1, comm: "systemd", ticks: 1, args: []string{"/sbin/init"}, exe: "/usr/lib/systemd/systemd", uid: "0"})
	h.add(fakeProc{pid: 40, ppid: 1, comm: "claude", ticks: 4000, args: []string{"claude", "-p", "install the helper tool"},
		exe: "/opt/claude-code/bin/claude", cwd: "/home/dev/proj", children: []int{41, 43, 44, 45, 46, 47}})
	marker := map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s-self"}
	// The hook as Claude Code runs it (exec form) and the worker it starts.
	h.add(fakeProc{pid: 41, ppid: 40, comm: "hawkbell", ticks: 4100, args: []string{installed, "hook", "--agent", "claude-code"},
		exe: installed, env: marker, cwd: "/home/dev/proj", children: []int{42}})
	h.add(fakeProc{pid: 42, ppid: 41, comm: "hawkbell", ticks: 4101, args: []string{"hawkbell", "hook", "--worker", "--framed", "--config", "/etc/hawkbell/hawkbell.yaml"},
		exe: installed, env: marker, cwd: "/home/dev/proj"})
	// The tool call the session made: reported.
	h.add(fakeProc{pid: 43, ppid: 40, comm: "bash", ticks: 4200, args: []string{"/bin/bash", "-c", "curl -fsS http://127.0.0.1/i.sh | sh"},
		exe: "/usr/bin/bash", env: marker, cwd: "/home/dev/proj"})
	// Another hawkbell command run by the agent: tampering, reported.
	h.add(fakeProc{pid: 44, ppid: 40, comm: "hawkbell", ticks: 4300, args: []string{installed, "hooks", "uninstall", "--scope", "user"},
		exe: installed, env: marker, cwd: "/home/dev/proj"})
	// A program that only calls itself hawkbell hook: reported.
	h.add(fakeProc{pid: 45, ppid: 40, comm: "hawkbell", ticks: 4400, args: []string{"/usr/bin/hawkbell", "hook", "--agent", "claude-code"},
		exe: decoy, env: marker, cwd: "/home/dev/proj"})
	// This process's own image (/proc/self/exe) running as a hook: not
	// reported, without any configured path.
	h.add(fakeProc{pid: 46, ppid: 40, comm: "hawkbell", ticks: 4500, args: []string{testBin, "hook", "--agent", "claude-code"},
		exe: testBin, env: marker, cwd: "/home/dev/proj"})
	// The installed binary with an unreadable executable link: identity
	// unknown, so it is reported rather than hidden.
	h.add(fakeProc{pid: 47, ppid: 40, comm: "hawkbell", ticks: 4600, args: []string{installed, "hook", "--agent", "claude-code"},
		env: marker, cwd: "/home/dev/proj"})

	m, _ := newFixtureMonitor(t, h)
	m.o.SelfExes = []string{installed, "relative/ignored"}
	// The fixture binaries live under the test's temporary directory,
	// which only this test writes to (TestSelfExesUntrustedPath covers the
	// path check itself).
	m.trusted = func(string) bool { return true }
	m.fullScan(m.now())
	evs := drain(m)
	execs := ofType(evs, event.TypeProcessExec)
	for _, pid := range []int{41, 42, 46} {
		if e := byPID(execs, pid); e != nil {
			t.Errorf("hawkbell's own hook process %d reported: %v", pid, e.Process.Args)
		}
	}
	for _, pid := range []int{43, 44, 45, 47} {
		if e := byPID(execs, pid); e == nil {
			t.Errorf("process %d of the agent was not reported", pid)
		} else if e.Agent == nil || e.Agent.PID != 40 {
			t.Errorf("process %d attributed to %+v", pid, e.Agent)
		}
	}
	if got := m.Stats().SelfExcluded; got != 3 {
		t.Errorf("SelfExcluded = %d, want 3", got)
	}
	// Still part of the agent for attribution (whatever it starts belongs
	// to the session), but never an osquery exec row.
	if ap, ok := m.Attribute(41); !ok || ap.PID != 40 {
		t.Errorf("Attribute(hook) = %+v %v", ap, ok)
	}
	if a, _, ok := m.osqAttribute(41, 40); ok {
		t.Errorf("osquery row of hawkbell's hook attributed to %q", a)
	}
	if a, _, ok := m.osqAttribute(43, 40); !ok || a != "claude-code" {
		t.Errorf("osquery row of the tool call = %q %v", a, ok)
	}
	// The hook exits; its late osquery row is still recognised.
	h.remove(42)
	h.remove(41)
	m.fullScan(m.now())
	drain(m)
	if _, _, ok := m.osqAttribute(41, 40); ok {
		t.Error("osquery row of an exited hawkbell hook attributed")
	}
}

// TestSelfIDsFollowUpgrade: an upgrade replaces the installed file (a new
// inode). The running sensor's own image keeps its identity, and the new
// file is recognised once the identity set is refreshed.
func TestSelfIDsFollowUpgrade(t *testing.T) {
	dir := t.TempDir()
	installed := writeBinary(t, dir, "hawkbell")
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true, SelfExes: []string{installed}})
	m.trusted = func(string) bool { return true }
	clk := &fakeClock{t: time.Unix(fixtureBoot, 0)}
	m.now = clk.now
	fi, _ := os.Stat(installed)
	oldID := idOf(t, fi, installed)
	if !m.selfIDs(m.now()).ids[oldID] {
		t.Fatal("the configured binary is not in the identity set")
	}
	next := installed + ".new"
	writeBinary(t, dir, "hawkbell.new")
	if err := os.Rename(next, installed); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(installed)
	newID := idOf(t, fi, installed)
	if newID == oldID {
		t.Skip("file system reused the inode")
	}
	if m.selfIDs(m.now()).ids[newID] {
		t.Error("identity set refreshed before selfRefresh")
	}
	clk.add(selfRefresh)
	if !m.selfIDs(m.now()).ids[newID] {
		t.Error("the upgraded binary is not recognised after selfRefresh")
	}
}

// denySource refuses the environment of some processes with EACCES, as the
// kernel does for another account's process without CAP_SYS_PTRACE.
type denySource struct {
	source
	deny map[int]bool
}

func (d denySource) env(pid int, keep map[string]bool) (map[string]string, error) {
	if d.deny[pid] {
		return nil, &fs.PathError{Op: "open", Path: "/proc/" + strconv.Itoa(pid) + "/environ", Err: syscall.EACCES}
	}
	return d.source.env(pid, keep)
}

// TestFixtureReadabilityCounts: procs_unreadable counts EACCES/EPERM on
// live user-space processes only; kernel threads, processes that went away
// and readable ones are not counted, and the counts follow the table.
func TestFixtureReadabilityCounts(t *testing.T) {
	h := newFakeHost(t)
	h.add(fakeProc{pid: 1, comm: "systemd", ticks: 1, args: []string{"/sbin/init"}, exe: "/usr/lib/systemd/systemd", uid: "0"})
	h.add(fakeProc{pid: 2, comm: "kthreadd", ticks: 1, uid: "0", flags: 0x00208040})
	h.add(fakeProc{pid: 3, ppid: 2, comm: "rcu_gp", ticks: 2, uid: "0", flags: 0x04208060})
	h.add(fakeProc{pid: 100, ppid: 1, comm: "sshd", ticks: 50, args: []string{"sshd"}, exe: "/usr/sbin/sshd", uid: "0"})
	h.add(fakeProc{pid: 200, ppid: 1, comm: "bash", ticks: 60, args: []string{"-bash"}, exe: "/usr/bin/bash"})
	h.add(fakeProc{pid: 300, ppid: 200, comm: "node", ticks: 70, args: []string{"node", "x.js"}, exe: "/usr/bin/node", uid: "1001"})
	h.add(fakeProc{pid: 400, ppid: 1, comm: "zombie", ticks: 80, state: 'Z', uid: "0"})
	m, clk := newFixtureMonitor(t, h)
	// Root's and another account's processes (and the kernel threads,
	// which the kernel also refuses an unprivileged reader) are denied.
	m.src = denySource{source: m.src, deny: map[int]bool{1: true, 2: true, 3: true, 100: true, 300: true, 400: true}}
	m.fullScan(m.now())
	drain(m)
	st := m.Stats()
	if st.ProcsTotal != 4 || st.ProcsUnreadable != 3 {
		t.Errorf("total %d unreadable %d, want 4 and 3 (systemd, sshd, node; bash readable; kernel threads and the zombie left out)", st.ProcsTotal, st.ProcsUnreadable)
	}
	h.remove(300)
	clk.add(defaultIdle)
	m.fullScan(m.now())
	if st := m.Stats(); st.ProcsTotal != 3 || st.ProcsUnreadable != 2 {
		t.Errorf("after an exit: total %d unreadable %d, want 3 and 2", st.ProcsTotal, st.ProcsUnreadable)
	}
	// A sensor that can read everything reports zero.
	m2, _ := newFixtureMonitor(t, h)
	m2.fullScan(m2.now())
	if st := m2.Stats(); st.ProcsUnreadable != 0 || st.ProcsTotal != 3 {
		t.Errorf("privileged view: total %d unreadable %d", st.ProcsTotal, st.ProcsUnreadable)
	}
}

func TestParseStatKernelThread(t *testing.T) {
	for _, c := range []struct {
		line    string
		kthread bool
		ok      bool
	}{
		{"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 18446744073709551615", true, true},
		{"3 (rcu_gp) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 0 -20 1 0 1 0 0 18446744073709551615", true, true},
		{"812 (bash) S 1 812 812 34816 812 4194560 0 0 0 0 0 0 0 0 20 0 1 0 900 0 0 18446744073709551615", false, true},
		// A process named to look like a kernel thread's stat cannot reach
		// the flags field: the name ends at the last ")".
		{"900 (x) S 2 0 0 0 -1 2129984 ) S 1 900 900 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 950 0 0 0", false, true},
		{"901 (bad) S 1 0 0 0 -1 notanumber 0 0 0 0 0 0 0 0 20 0 1 0 950 0 0 0", false, true},
		{"902 (short) S 1", false, false},
	} {
		st, ok := parseStatFields([]byte(c.line))
		if ok != c.ok || (ok && st.kthread != c.kthread) {
			t.Errorf("%q: kthread %v ok %v, want %v %v", c.line, st.kthread, ok, c.kthread, c.ok)
		}
	}
}

// TestArgsDigestKeyed: the process.exec id's argument digest is a
// domain-separated HMAC under the monitor's key (Options.IDKey, or a
// per-process random key), never the plain SHA-256 a reader of the
// shipped record could recompute for guessed arguments.
func TestArgsDigestKeyed(t *testing.T) {
	k := argsKey()
	if len(k) != 32 {
		t.Fatalf("key length %d", len(k))
	}
	zero := true
	for _, b := range k {
		zero = zero && b == 0
	}
	if zero {
		t.Fatal("key is all zero")
	}
	if &argsKey()[0] != &k[0] {
		t.Error("key drawn more than once")
	}
	args := []string{"mysql", "-u", "root", "-p[REDACTED:password]", "prod"}
	plain := sha256.New()
	keyed := hmac.New(sha256.New, k)
	keyed.Write([]byte(argsDomain))
	keyed.Write([]byte{0})
	for _, a := range args {
		plain.Write([]byte(a))
		plain.Write([]byte{0})
		keyed.Write([]byte(a))
		keyed.Write([]byte{0})
	}
	got := argsDigest(k, args)
	if got == hex.EncodeToString(plain.Sum(nil)[:8]) {
		t.Error("digest is the unkeyed SHA-256: a guessing oracle for what privacy redacts")
	}
	if got != hex.EncodeToString(keyed.Sum(nil)[:8]) {
		t.Error("digest is not the domain-separated HMAC under the key")
	}
	if argsDigest(k, args) != got {
		t.Error("digest not stable within the process")
	}
	// The monitor's key: Options.IDKey copied, or the per-process key.
	if m := New(Options{NoOsquery: true}); &m.idKey[0] != &k[0] {
		t.Error("a monitor without IDKey does not use the per-process key")
	}
	if m := New(Options{NoOsquery: true, IDKey: []byte("short")}); &m.idKey[0] != &k[0] {
		t.Error("a too-short IDKey was used")
	}
	stored := bytes.Repeat([]byte{7}, 32)
	m := New(Options{NoOsquery: true, IDKey: stored})
	stored[0] = 8
	if !bytes.Equal(m.idKey, bytes.Repeat([]byte{7}, 32)) {
		t.Error("IDKey not copied")
	}
	if argsDigest(m.idKey, args) == got {
		t.Error("IDKey not used")
	}
}

func idOf(t *testing.T, fi os.FileInfo, p string) string {
	t.Helper()
	id := platform.FileID(fi, p)
	if id == "" {
		t.Skip("no file ids here")
	}
	return id
}

// hideSource lists some pids as denied, as procfs does under hidepid=1:
// the pid is listed, nothing under it can be read.
type hideSource struct {
	source
	hide map[int]string // pid -> owner uid
}

func (d hideSource) list() ([]ident, map[int]*platform.Proc, error) {
	ids, recs, err := d.source.list()
	for i := range ids {
		if uid, ok := d.hide[ids[i].pid]; ok {
			ids[i] = ident{pid: ids[i].pid, denied: true, uid: uid}
		}
	}
	return ids, recs, err
}

func (d hideSource) identOf(pid int) (ident, bool) {
	if _, ok := d.hide[pid]; ok {
		return ident{}, false
	}
	return d.source.identOf(pid)
}

func (d hideSource) read(pid int) (platform.Proc, ident, bool) {
	if _, ok := d.hide[pid]; ok {
		return platform.Proc{}, ident{}, false
	}
	return d.source.read(pid)
}

// TestFixtureHiddenPidsCounted: pids the listing found but could not read
// even the stat of (hidepid=1) count as total, unreadable and hidden; a
// process the table knew that becomes hidden stays (no false exit) and
// counts as unreadable; nothing is protected without the read privilege.
func TestFixtureHiddenPidsCounted(t *testing.T) {
	h := newFakeHost(t)
	h.add(fakeProc{pid: 1, comm: "systemd", ticks: 1, args: []string{"/sbin/init"}, exe: "/usr/lib/systemd/systemd", uid: "0"})
	h.add(fakeProc{pid: 200, ppid: 1, comm: "bash", ticks: 60, args: []string{"-bash"}, exe: "/usr/bin/bash"})
	h.add(fakeProc{pid: 300, ppid: 1, comm: "codex", ticks: 70, args: []string{"codex"}, exe: "/usr/local/bin/codex", uid: "1001"})
	m, clk := newFixtureMonitor(t, h)
	m.privileged = false
	m.fullScan(m.now())
	drain(m)
	if st := m.Stats(); st.ProcsTotal != 3 || st.ProcsUnreadable != 0 || st.ProcsHidden != 0 {
		t.Fatalf("readable host: %+v", st)
	}
	// /proc remounted hidepid=1: the agent of uid 1001 and root's init are
	// hidden now, and two processes never seen before are hidden too.
	h.add(fakeProc{pid: 500, ppid: 1, comm: "node", ticks: 90, uid: "1001"})
	h.add(fakeProc{pid: 600, ppid: 2, comm: "kworker/0:1", ticks: 95, uid: "0"})
	m.src = hideSource{source: m.src, hide: map[int]string{1: "0", 300: "1001", 500: "1001", 600: "0"}}
	clk.add(defaultIdle)
	m.fullScan(m.now())
	evs := drain(m)
	st := m.Stats()
	if st.ProcsTotal != 5 || st.ProcsUnreadable != 4 || st.ProcsHidden != 4 || st.ProcsProtected != 0 {
		t.Errorf("hidepid: total %d unreadable %d hidden %d protected %d, want 5 4 4 0",
			st.ProcsTotal, st.ProcsUnreadable, st.ProcsHidden, st.ProcsProtected)
	}
	if len(ofType(evs, event.TypeAgentProcessStop)) != 0 {
		t.Error("a hidden but live agent was reported as stopped")
	}
	m.mu.Lock()
	n := m.nodes[300]
	m.mu.Unlock()
	if n == nil || !n.unreadable {
		t.Errorf("known process that became hidden: %+v", n)
	}
	// A privileged monitor (root, the reader capabilities) is not stopped
	// by hidepid; if root-owned pids still refuse it, they are protected.
	m.privileged = true
	clk.add(defaultIdle)
	m.fullScan(m.now())
	if st := m.Stats(); st.ProcsProtected != 2 {
		t.Errorf("privileged: protected %d, want 2 (root's init and the kernel worker)", st.ProcsProtected)
	}
	// Gone from the listing: no longer counted.
	h.remove(500)
	clk.add(defaultIdle)
	m.fullScan(m.now())
	if st := m.Stats(); st.ProcsHidden != 3 || st.ProcsTotal != 4 {
		t.Errorf("after an exit: %+v", st)
	}
}

// TestFixtureProtectedProcesses: a process that refuses a monitor holding
// the read privilege and runs as the system account is protected (counted
// in ProcsUnreadable and ProcsProtected); one of any other account is not,
// and without the privilege nothing is protected.
func TestFixtureProtectedProcesses(t *testing.T) {
	h := newFakeHost(t)
	h.add(fakeProc{pid: 1, comm: "process_api", ticks: 1, args: []string{"/process_api"}, exe: "/process_api", uid: "0"})
	h.add(fakeProc{pid: 200, ppid: 1, comm: "bash", ticks: 60, args: []string{"-bash"}, exe: "/usr/bin/bash"})
	h.add(fakeProc{pid: 300, ppid: 1, comm: "node", ticks: 70, args: []string{"node", "x.js"}, exe: "/usr/bin/node", uid: "1001"})
	for _, c := range []struct {
		privileged bool
		deny       map[int]bool
		unreadable uint64
		protected  uint64
	}{
		{true, map[int]bool{1: true}, 1, 1},
		{true, map[int]bool{1: true, 300: true}, 2, 1},
		{false, map[int]bool{1: true}, 1, 0},
		{false, map[int]bool{1: true, 300: true}, 2, 0},
	} {
		m, _ := newFixtureMonitor(t, h)
		m.privileged = c.privileged
		m.src = denySource{source: m.src, deny: c.deny}
		m.fullScan(m.now())
		drain(m)
		if st := m.Stats(); st.ProcsUnreadable != c.unreadable || st.ProcsProtected != c.protected {
			t.Errorf("privileged %v deny %v: unreadable %d protected %d, want %d %d",
				c.privileged, c.deny, st.ProcsUnreadable, st.ProcsProtected, c.unreadable, c.protected)
		}
	}
}

// TestFixtureSelfHookUntrustedInstallReported: an installed hawkbell binary on
// a path accounts other than root can change (here under the
// world-writable temporary directory) is not trusted, so a process
// running it as `hawkbell hook` is reported like any program: whoever can
// write there could put their own program in its place.
func TestFixtureSelfHookUntrustedInstallReported(t *testing.T) {
	h := newFakeHost(t)
	installed := writeBinary(t, filepath.Join(t.TempDir(), "usr", "bin"), "hawkbell")
	if platform.TrustedPath(installed) {
		t.Skipf("%s is trusted here (temporary directory not writable by others)", installed)
	}
	h.add(fakeProc{pid: 1, comm: "systemd", ticks: 1, args: []string{"/sbin/init"}, exe: "/usr/lib/systemd/systemd", uid: "0"})
	h.add(fakeProc{pid: 40, ppid: 1, comm: "claude", ticks: 4000, args: []string{"claude", "-p", "x"},
		exe: "/opt/claude-code/bin/claude", cwd: "/home/dev/proj", children: []int{41}})
	h.add(fakeProc{pid: 41, ppid: 40, comm: "hawkbell", ticks: 4100, args: []string{installed, "hook", "--agent", "claude-code"},
		exe: installed, env: map[string]string{"CLAUDECODE": "1"}, cwd: "/home/dev/proj"})
	m, _ := newFixtureMonitor(t, h)
	m.o.SelfExes = []string{installed}
	fi, _ := os.Stat(installed)
	if m.selfIDs(m.now()).ids[idOf(t, fi, installed)] {
		t.Fatal("an installed binary on an untrusted path is in the identity set")
	}
	m.selfSet.Store(nil)
	m.fullScan(m.now())
	if byPID(ofType(drain(m), event.TypeProcessExec), 41) == nil {
		t.Error("a hook process running a binary from an untrusted path was hidden")
	}
}

// TestFixtureExecIDStable: with the daemon's persisted key (Options.IDKey)
// the process.exec id of a live process is the same in two runs of the
// sensor (a restart reports every live process again), and the
// connector's record of an exec gets the id a rescan gives the same
// process. A monitor with its own random key gives another id.
func TestFixtureExecIDStable(t *testing.T) {
	h := newFakeHost(t)
	h.add(fakeProc{pid: 1, comm: "init", ticks: 1, args: []string{"/sbin/init"}, exe: "/sbin/init", uid: "0"})
	h.add(fakeProc{pid: 300, ppid: 1, comm: "codex", ticks: 100, args: []string{"codex", "--yolo"}, exe: "/usr/local/bin/codex"})
	child := fakeProc{pid: 301, ppid: 300, comm: "git", ticks: 200, args: []string{"git", "push", "--force"}, exe: "/usr/bin/git",
		env: map[string]string{"CODEX_THREAD_ID": "th-1"}}
	h.add(child)
	key := bytes.Repeat([]byte{0x5a}, 32)
	scanID := func(k []byte) string {
		t.Helper()
		m, _ := newFixtureMonitor(t, h)
		m.idKey = argsKeyFor(k)
		m.fullScan(m.now())
		ex := byPID(ofType(drain(m), event.TypeProcessExec), 301)
		if ex == nil {
			t.Fatal("no process.exec for the agent's child")
		}
		return ex.ID
	}
	first, second := scanID(key), scanID(key)
	if first != second {
		t.Errorf("two runs with the stored key: %s and %s", first, second)
	}
	if other := scanID(nil); other == first {
		t.Error("the per-process key gave the stored key's id")
	}
	// The connector sees the exec, at its own time.
	h.remove(301)
	m, _ := newFixtureMonitor(t, h)
	m.idKey = argsKeyFor(key)
	m.fullScan(m.now())
	drain(m)
	h.add(child)
	m.cnExec(301, time.Unix(fixtureBoot+20_000, 0))
	ex := byPID(ofType(drain(m), event.TypeProcessExec), 301)
	if ex == nil {
		t.Fatal("no process.exec from the connector")
	}
	if !ex.TS.Equal(time.Unix(fixtureBoot+20_000, 0)) {
		t.Errorf("exec TS = %v, want the connector's time", ex.TS)
	}
	if ex.ID != first {
		t.Errorf("connector id %s, rescan id %s: one process, two ids", ex.ID, first)
	}
}
