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

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
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
// run, where the monitor reported the agent's `spoor hook` invocations and
// their workers as the session's process.exec activity (4 of the 5 context
// records shipped with the finding). spoor's hook processes are recognised
// by argv[1] "hook" and the file identity of their executable; everything
// else the agent runs is still reported, including other spoor commands and
// a different program that only calls itself spoor.
func TestFixtureSelfHookNotReported(t *testing.T) {
	h := newFakeHost(t)
	bins := t.TempDir()
	installed := writeBinary(t, filepath.Join(bins, "usr", "bin"), "spoor")
	// The agent's own container or user namespace can put anything at the
	// installed path: a path is not an identity.
	decoy := writeBinary(t, filepath.Join(bins, "ctr", "usr", "bin"), "spoor")
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	h.add(fakeProc{pid: 1, comm: "systemd", ticks: 1, args: []string{"/sbin/init"}, exe: "/usr/lib/systemd/systemd", uid: "0"})
	h.add(fakeProc{pid: 40, ppid: 1, comm: "claude", ticks: 4000, args: []string{"claude", "-p", "install the helper tool"},
		exe: "/opt/claude-code/bin/claude", cwd: "/home/dev/proj", children: []int{41, 43, 44, 45, 46, 47}})
	marker := map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s-self"}
	// The hook as Claude Code runs it (exec form) and the worker it starts.
	h.add(fakeProc{pid: 41, ppid: 40, comm: "spoor", ticks: 4100, args: []string{installed, "hook", "--agent", "claude-code"},
		exe: installed, env: marker, cwd: "/home/dev/proj", children: []int{42}})
	h.add(fakeProc{pid: 42, ppid: 41, comm: "spoor", ticks: 4101, args: []string{"spoor", "hook", "--worker", "--framed", "--config", "/etc/spoor/spoor.yaml"},
		exe: installed, env: marker, cwd: "/home/dev/proj"})
	// The tool call the session made: reported.
	h.add(fakeProc{pid: 43, ppid: 40, comm: "bash", ticks: 4200, args: []string{"/bin/bash", "-c", "curl -fsS http://127.0.0.1/i.sh | sh"},
		exe: "/usr/bin/bash", env: marker, cwd: "/home/dev/proj"})
	// Another spoor command run by the agent: tampering, reported.
	h.add(fakeProc{pid: 44, ppid: 40, comm: "spoor", ticks: 4300, args: []string{installed, "hooks", "uninstall", "--scope", "user"},
		exe: installed, env: marker, cwd: "/home/dev/proj"})
	// A program that only calls itself spoor hook: reported.
	h.add(fakeProc{pid: 45, ppid: 40, comm: "spoor", ticks: 4400, args: []string{"/usr/bin/spoor", "hook", "--agent", "claude-code"},
		exe: decoy, env: marker, cwd: "/home/dev/proj"})
	// This process's own image (/proc/self/exe) running as a hook: not
	// reported, without any configured path.
	h.add(fakeProc{pid: 46, ppid: 40, comm: "spoor", ticks: 4500, args: []string{testBin, "hook", "--agent", "claude-code"},
		exe: testBin, env: marker, cwd: "/home/dev/proj"})
	// The installed binary with an unreadable executable link: identity
	// unknown, so it is reported rather than hidden.
	h.add(fakeProc{pid: 47, ppid: 40, comm: "spoor", ticks: 4600, args: []string{installed, "hook", "--agent", "claude-code"},
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
			t.Errorf("spoor's own hook process %d reported: %v", pid, e.Process.Args)
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
		t.Errorf("osquery row of spoor's hook attributed to %q", a)
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
		t.Error("osquery row of an exited spoor hook attributed")
	}
}

// TestSelfIDsFollowUpgrade: an upgrade replaces the installed file (a new
// inode). The running sensor's own image keeps its identity, and the new
// file is recognised once the identity set is refreshed.
func TestSelfIDsFollowUpgrade(t *testing.T) {
	dir := t.TempDir()
	installed := writeBinary(t, dir, "spoor")
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
	writeBinary(t, dir, "spoor.new")
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
