//go:build linux

package platform

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fileCapsReader is the security.capability xattr setcap(8) writes for
// "cap_dac_read_search,cap_sys_ptrace=ep" (VFS_CAP_REVISION_2, effective
// flag set, permitted 0x80004): the bytes the container image's build stage
// writes (packaging/container/filecap/filecap_test.go).
var fileCapsReader = []byte{
	0x01, 0x00, 0x00, 0x02, // magic: revision 2 | effective
	0x04, 0x00, 0x08, 0x00, // permitted, low word: bits 2 and 19
	0x00, 0x00, 0x00, 0x00, // inheritable, low word
	0x00, 0x00, 0x00, 0x00, // permitted, high word
	0x00, 0x00, 0x00, 0x00, // inheritable, high word
}

// TestIsPrivilegedFileCapabilities runs the package, as uid 65532, from a
// copy of the test binary carrying the node sensor's file capabilities: the
// exact shape of the Kubernetes sensor. It must count as privileged for
// reading (every account listed, another account's process environment
// readable) and not as an administrator. The kernel ignores file
// capabilities on nosuid mounts and outside the bounding set; the test then
// skips, saying so.
func TestIsPrivilegedFileCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set file capabilities and switch accounts")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	copyPath := filepath.Join(t.TempDir(), "spoor-captest")
	dst, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(copyPath, "security.capability", fileCapsReader, 0); err != nil {
		t.Skipf("cannot set file capabilities here: %v", err)
	}
	// Executed through a descriptor so the root-only temporary directory
	// is not in the way (see TestUnprivilegedView).
	bin, err := os.Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()
	const sensorUID = 65532
	cmd := exec.Command("/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{bin}
	cmd.Dir = "/"
	cmd.Env = []string{helperEnv + "=report", "HOME=/tmp", "PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: sensorUID, Gid: sensorUID}}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) || errors.Is(err, syscall.EPERM) {
			t.Skipf("the capability-carrying binary cannot run as uid %d here (bounding set?): %v", sensorUID, err)
		}
		t.Skipf("cannot run as uid %d here: %v", sensorUID, err)
	}
	var r unprivReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	t.Logf("uid %d with file capabilities: CapEff %s privileged %v admin %v", sensorUID, r.CapEff, r.Privileged, r.IsAdmin)
	if r.CapEff != "0000000000080004" {
		t.Skipf("file capabilities were not honoured here (CapEff %q; nosuid mount?)", r.CapEff)
	}
	if !r.Privileged {
		t.Error("uid 65532 with CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE effective: IsPrivileged() = false")
	}
	if r.IsAdmin {
		t.Error("a capability-only process claims IsAdmin: it cannot chown other accounts' files")
	}
	if r.ParentEnvPerm || r.ParentEnvErr != "" {
		t.Errorf("CAP_SYS_PTRACE did not open a root process's environment: %q", r.ParentEnvErr)
	}
	if r.Current.UID != "65532" {
		t.Errorf("CurrentUser = %+v", r.Current)
	}
}
