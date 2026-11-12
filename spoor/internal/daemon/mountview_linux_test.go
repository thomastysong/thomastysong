//go:build linux

package daemon

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMountViewLive checks the two shapes on the real kernel: this process
// is in its own view, and a process in a private mount namespace whose root
// is a bind of the host's root moved over "/" (what systemd does for a unit
// with ProtectHome= or ReadWritePaths=, mount_move_root in its namespace.c)
// is in the same view although its namespace differs. A container's root is
// another file system (checked by hand with Docker: 43:2745694 against the
// host's 65024:2), which the fixture test covers.
func TestMountViewLive(t *testing.T) {
	v := newMountView("/proc")
	if !v.same(os.Getpid()) {
		t.Fatal("this process is not in its own view")
	}
	if v.same(1<<29) || v.same(-1) {
		t.Error("a pid that does not exist is in the view")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for a mount namespace")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare(1)")
	}
	dir := t.TempDir()
	cmd := exec.Command("unshare", "-m", "--propagation", "private", "sh", "-c",
		"mount --bind / '"+dir+"' && cd '"+dir+"' && mount --move . / && exec chroot . sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); _ = cmd.Wait() }()
	self, _ := os.Readlink("/proc/self/ns/mnt")
	deadline := time.Now().Add(5 * time.Second)
	pid := cmd.Process.Pid
	for {
		comm, _ := os.ReadFile("/proc/" + itoa(int64(pid)) + "/comm")
		ns, _ := os.Readlink("/proc/" + itoa(int64(pid)) + "/ns/mnt")
		if strings.TrimSpace(string(comm)) == "sleep" && ns != "" && ns != self {
			break
		}
		if time.Now().After(deadline) {
			t.Skipf("the namespace was not set up here (comm %q ns %q)", comm, ns)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !v.same(pid) {
		t.Error("a process in a systemd-style private namespace over the same root is not in the view")
	}
}
