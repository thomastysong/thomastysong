//go:build linux

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startInNamespace runs script under unshare -m (a private mount
// namespace) and waits until the process it execs is sleep(1) in a mount
// namespace other than this process's; it returns that pid.
func startInNamespace(t *testing.T, script string) int {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for a mount namespace")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare(1)")
	}
	cmd := exec.Command("unshare", "-m", "--propagation", "private", "sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); _ = cmd.Wait() })
	self, _ := os.Readlink("/proc/self/ns/mnt")
	deadline := time.Now().Add(5 * time.Second)
	pid := cmd.Process.Pid
	for {
		comm, _ := os.ReadFile("/proc/" + itoa(int64(pid)) + "/comm")
		ns, _ := os.Readlink("/proc/" + itoa(int64(pid)) + "/ns/mnt")
		if strings.TrimSpace(string(comm)) == "sleep" && ns != "" && ns != self {
			return pid
		}
		if time.Now().After(deadline) {
			t.Skipf("the namespace was not set up here (comm %q ns %q)", comm, ns)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMountViewLive checks the shapes on the real kernel: this process is
// in its own view; a process in a private mount namespace whose root is a
// bind of the host's root moved over "/" (what systemd does for a unit
// with ProtectHome= or ReadWritePaths=, mount_move_root in its namespace.c)
// names the same directory by the same path although its namespace
// differs; and a process in a namespace with its own file system mounted
// over a directory (PrivateTmp=, ProtectHome=tmpfs) is refused for that
// path, although its root is the same. A container's root is another file
// system (checked by hand with Docker: 43:2745694 against the host's
// 65024:2), which the fixture test covers.
func TestMountViewLive(t *testing.T) {
	v := newMountView("/proc")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !v.same(os.Getpid(), wd) {
		t.Fatal("this process is not in its own view")
	}
	if v.same(1<<29, "/") || v.same(-1, "/") {
		t.Error("a pid that does not exist is in the view")
	}
	dir := t.TempDir()
	pid := startInNamespace(t, "mount --bind / '"+dir+"' && cd '"+dir+"' && mount --move . / && exec chroot . sleep 30")
	if !v.same(pid, "/") {
		t.Error("a process in a systemd-style private namespace over the same root is not in the view")
	}
	// PrivateTmp shape: a tmpfs over proj in the process's namespace only.
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.Mkdir(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	pid = startInNamespace(t, "mount -t tmpfs tmpfs '"+proj+"' && cd '"+proj+"' && exec sleep 30")
	if v.same(pid, proj) {
		t.Errorf("%s names the process's private file system there and an empty directory here, yet it is in the view", proj)
	}
}
