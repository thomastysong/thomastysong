//go:build linux

package procmon

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// TestLiveSelfHookNotReported runs the real shape on the build host: an
// agent root ("codex") starts this package's test binary as `<bin> hook
// --agent codex`, the same binary as `<bin> hooks status`, and a plain
// command. The monitor's own image is the test binary, so the first is
// hawkbell's hook by file identity and is not reported; the other two are.
func TestLiveSelfHookNotReported(t *testing.T) {
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pf := func(n string) string { return filepath.Join(dir, n+".pid") }
	q := "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	script := writeAgentScript(t, helperEnv+"=hook "+q+" hook --agent codex &\necho $! > "+pf("hook")+"\n"+
		helperEnv+"=hook "+q+" hooks status &\necho $! > "+pf("other")+"\n"+
		"sleep 60 &\necho $! > "+pf("sleep")+"\nwait")
	m, c := startMonitor(t, Options{Idle: 100 * time.Millisecond, Active: 50 * time.Millisecond, NoOsquery: true}, nil)
	cmd := exec.Command(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	pids := map[string]int{}
	waitFor(t, 5*time.Second, "the child pids", func() bool {
		for _, n := range []string{"hook", "other", "sleep"} {
			b, err := os.ReadFile(pf(n))
			if err != nil {
				return false
			}
			pids[n], _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		return pids["hook"] > 0 && pids["other"] > 0 && pids["sleep"] > 0
	})
	execOf := func(pid int) *event.Event {
		return c.find(func(e *event.Event) bool { return e.Type == event.TypeProcessExec && e.Process.PID == pid })
	}
	waitFor(t, 5*time.Second, "the exec events of the other children", func() bool {
		return execOf(pids["sleep"]) != nil && execOf(pids["other"]) != nil
	})
	// One more scan cycle for the hook process to have been looked at.
	waitFor(t, 5*time.Second, "the hook process in the table", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		n := m.nodes[pids["hook"]]
		return n != nil && n.resolved
	})
	if e := execOf(pids["hook"]); e != nil {
		t.Errorf("hawkbell's own hook process reported as the agent's activity: %v", e.Process.Args)
	}
	if st := m.Stats(); st.SelfExcluded == 0 {
		t.Errorf("SelfExcluded = 0")
	}
	if ap, ok := m.Attribute(pids["hook"]); !ok || ap.PID != cmd.Process.Pid {
		t.Errorf("Attribute(hook) = %+v %v; the hook still belongs to its agent", ap, ok)
	}
}

// TestLiveReadabilityCounts: the same scan as root and as uid nobody. As
// nobody, root's processes refuse the environment read with EACCES and are
// counted; as root almost nothing is (a sandbox's protected init can still
// refuse root, as the build host's pid 1 does).
func TestLiveReadabilityCounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to compare with an unprivileged account")
	}
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true})
	m.fullScan(time.Now())
	drain(m)
	st := m.Stats()
	t.Logf("as root: %d user-space processes, %d unreadable, %d of them protected", st.ProcsTotal, st.ProcsUnreadable, st.ProcsProtected)
	if st.ProcsTotal == 0 || st.ProcsUnreadable*4 > st.ProcsTotal {
		t.Errorf("as root: total %d unreadable %d", st.ProcsTotal, st.ProcsUnreadable)
	}
	// Root holds the read privilege: whatever still refuses it and runs as
	// root (this host's sandboxed pid 1) is protected, and does not by
	// itself make the processes surface degraded.
	if st.ProcsProtected > st.ProcsUnreadable || st.ProcsHidden != 0 {
		t.Errorf("as root: protected %d hidden %d of %d unreadable", st.ProcsProtected, st.ProcsHidden, st.ProcsUnreadable)
	}
	if _, err := os.ReadFile("/proc/1/environ"); errors.Is(err, fs.ErrPermission) && st.ProcsProtected == 0 {
		t.Errorf("pid 1 refuses root (%v) but no protected process was counted", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()
	const nobody = 65534
	cmd := exec.Command("/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{bin}
	cmd.Dir = "/"
	cmd.Env = []string{helperEnv + "=readability", "PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("cannot run as uid %d here: %v", nobody, err)
	}
	var r readabilityReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	t.Logf("as nobody: %+v", r)
	if r.Euid != nobody || r.Total == 0 || r.Unreadable <= st.ProcsUnreadable || r.Unreadable >= r.Total {
		t.Errorf("as nobody: %+v (root: %d unreadable); want root's processes counted unreadable and its own readable", r, st.ProcsUnreadable)
	}
	// Without the read privilege a refusal is never "protected": it is the
	// missing privilege the counter exists to show.
	if r.Protected != 0 || r.Hidden != 0 {
		t.Errorf("as nobody on a plain /proc: %+v", r)
	}
}

// runReadabilityHelper runs the readability helper (TestMain) as uid
// nobody inside a private mount namespace, after script has set /proc up.
func runReadabilityHelper(t *testing.T, script string) readabilityReport {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount a procfs instance and drop to nobody")
	}
	for _, tool := range []string{"unshare", "setpriv", "mount"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()
	cmd := exec.Command("unshare", "-m", "sh", "-c", script+"; "+
		"exec setpriv --reuid=65534 --regid=65534 --clear-groups env "+helperEnv+"=readability /proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{bin}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Skipf("cannot run the helper here: %v %s", err, stderr)
	}
	var r readabilityReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	if r.Euid != 65534 {
		t.Skipf("helper ran as %d", r.Euid)
	}
	return r
}

// TestLiveHidepidUnreadableCounted: /proc mounted with hidepid=1
// ("noaccess", a common hardening) lists every pid but answers EPERM for
// every file under another account's /proc/<pid>/, stat included. A
// monitor without CAP_SYS_PTRACE must still count those processes as
// unreadable (and hidden): before the fix the listing dropped them and an
// unprivileged sensor reported total 1, unreadable 0 and an "ok" processes
// surface, exactly the missing-privilege case procs_unreadable exists to
// show.
func TestLiveHidepidUnreadableCounted(t *testing.T) {
	r := runReadabilityHelper(t, "mount -t proc -o hidepid=1 proc /proc || exit 99")
	t.Logf("as nobody under hidepid=noaccess: %+v", r)
	if r.Unreadable == 0 || r.Hidden == 0 {
		t.Fatalf("hidepid=noaccess: other accounts' pids answered EPERM, yet unreadable=%d hidden=%d (total %d)", r.Unreadable, r.Hidden, r.Total)
	}
	if r.Hidden > r.Unreadable || r.Unreadable >= r.Total || r.Protected != 0 {
		t.Errorf("counts out of shape: %+v (want hidden <= unreadable < total, its own process readable, nothing protected)", r)
	}
	// The plain mount for comparison: nothing hidden.
	plain := runReadabilityHelper(t, "mount -t proc proc /proc || exit 99")
	t.Logf("as nobody on a fresh plain procfs: %+v", plain)
	if plain.Hidden != 0 || plain.Unreadable == 0 {
		t.Errorf("plain procfs: %+v", plain)
	}
}

// startNamed runs a copy of tail(1) at dir/name with argv[1] "hook" (the
// argument shape of hawkbell's hook), and returns its pid.
func startNamed(t *testing.T, dir, name string) (string, int) {
	t.Helper()
	tail, err := exec.LookPath("tail")
	if err != nil {
		t.Skip("no tail")
	}
	b, err := os.ReadFile(tail)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hook"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(p, "hook", "-f") // argv[1] == "hook"
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 5*time.Second, name+" running", func() bool {
		l, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
		return err == nil && l == p
	})
	return p, cmd.Process.Pid
}

// selfHookWith asks m, with source src, whether pid is hawkbell's own hook.
func selfHookWith(t *testing.T, m *Monitor, src source, pid int) bool {
	t.Helper()
	rec, err := platform.ProcessByPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	m.src = src
	m.selfSet.Store(nil)
	id := ident{pid: pid}
	if pf, ok := src.(*procfsSource); ok {
		if id, ok = pf.identOf(pid); !ok {
			t.Fatalf("pid %d gone", pid)
		}
	}
	return m.isSelfHook(id, &rec)
}

// TestLivePlatformSourceSelfHookByPathSwap is the regression test for the
// macOS and Windows self-hook test, which once compared the file at the
// process's path at check time with hawkbell's binary. A program started
// under a path its user controls, with argv[1] "hook", then renames a hard
// link of hawkbell's binary over that path (macOS has no protected_hardlinks)
// and would be taken for hawkbell's own hook and never reported. The
// platform source now requires the kernel's name of the image to be one of
// hawkbell's own trusted paths. Run on Linux through the same code path; the
// macOS kernel's answer (the swapped name, which still resolves) is
// simulated.
func TestLivePlatformSourceSelfHookByPathSwap(t *testing.T) {
	dir := t.TempDir()
	// Stand-in for hawkbell's installed binary (Options.SelfExes).
	hawkbell := writeBinary(t, dir, "hawkbell")
	evil, pid := startNamed(t, dir, "evil")
	// Swap: a hard link of hawkbell's binary renamed over the running program.
	if err := os.Link(hawkbell, evil+".new"); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := os.Rename(evil+".new", evil); err != nil {
		t.Fatal(err)
	}
	m := New(Options{NoOsquery: true, SelfExes: []string{hawkbell}})
	// The real path rule: a test directory under the world-writable /tmp
	// is not a place only root controls.
	if selfHookWith(t, m, platformSource{}, pid) {
		t.Errorf("platformSource: pid %d runs %s's original image but is taken for hawkbell's own hook", pid, evil)
	}
	// Even with the stand-in's directory trusted: Linux's image name ends
	// in " (deleted)" ...
	m.trusted = func(string) bool { return true }
	if selfHookWith(t, m, platformSource{}, pid) {
		t.Errorf("platformSource with trusted paths: pid %d taken for hawkbell's own hook", pid)
	}
	// ... and macOS answers with the swapped name, which now resolves to
	// hawkbell's binary: it is not one of hawkbell's paths.
	macOS := platformSource{image: func(p int, _ time.Time) (string, error) {
		if p != pid {
			return "", os.ErrNotExist
		}
		return evil, nil
	}}
	if selfHookWith(t, m, macOS, pid) {
		t.Errorf("platformSource with the macOS answer: pid %d taken for hawkbell's own hook", pid)
	}
	// The Linux source looks at the image itself.
	if selfHookWith(t, m, &procfsSource{dir: "/proc", viaPlatform: true}, pid) {
		t.Errorf("procfsSource fooled by the swap")
	}
}

// TestLiveSelfHookRecognisedOnTrustedPath is the positive control: a
// process that really runs the binary at hawkbell's trusted path, with
// argv[1] "hook", is hawkbell's hook for both sources, and for neither when
// the path is not trusted.
func TestLiveSelfHookRecognisedOnTrustedPath(t *testing.T) {
	dir := t.TempDir()
	hawkbell, pid := startNamed(t, dir, "hawkbell")
	m := New(Options{NoOsquery: true, SelfExes: []string{hawkbell}})
	m.trusted = func(p string) bool { return p == hawkbell }
	if !selfHookWith(t, m, platformSource{}, pid) {
		t.Error("platformSource: hawkbell's hook on its trusted path not recognised")
	}
	if !selfHookWith(t, m, &procfsSource{dir: "/proc", viaPlatform: true}, pid) {
		t.Error("procfsSource: hawkbell's hook on its trusted path not recognised")
	}
	m.trusted = platform.TrustedPath
	if platform.TrustedPath(hawkbell) {
		t.Skipf("%s is trusted here", hawkbell)
	}
	if selfHookWith(t, m, platformSource{}, pid) || selfHookWith(t, m, &procfsSource{dir: "/proc", viaPlatform: true}, pid) {
		t.Error("a binary on an untrusted path was taken for hawkbell's")
	}
}
