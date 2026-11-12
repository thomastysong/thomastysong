//go:build linux

package procmon

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// TestLiveSelfHookNotReported runs the real shape on the build host: an
// agent root ("codex") starts this package's test binary as `<bin> hook
// --agent codex`, the same binary as `<bin> hooks status`, and a plain
// command. The monitor's own image is the test binary, so the first is
// spoor's hook by file identity and is not reported; the other two are.
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
		t.Errorf("spoor's own hook process reported as the agent's activity: %v", e.Process.Args)
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
	t.Logf("as root: %d user-space processes, %d unreadable", st.ProcsTotal, st.ProcsUnreadable)
	if st.ProcsTotal == 0 || st.ProcsUnreadable*4 > st.ProcsTotal {
		t.Errorf("as root: total %d unreadable %d", st.ProcsTotal, st.ProcsUnreadable)
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
}
