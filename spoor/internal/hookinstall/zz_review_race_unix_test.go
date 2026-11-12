//go:build unix

package hookinstall

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// Apply, run as root on a user's settings file, calls os.Root.Chmod on the
// temporary file by name after closing it. The directory belongs to the
// user, who can swap that name for a symbolic link. Go documents that
// Root.Chmod races with such a swap, and on Linux the raw fchmodat ignores
// AT_SYMLINK_NOFOLLOW, so the chmod lands on the link target OUTSIDE the
// root. The mode applied is the mode of the user's own settings file.
func TestReviewApplyChmodRaceEscapesUserDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const victimUID = 65534
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	dir := filepath.Dir(path)
	home := filepath.Dir(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{home, dir} {
		if err := os.Chown(d, victimUID, victimUID); err != nil {
			t.Fatal(err)
		}
	}
	// A root-only file outside the user's tree (stands in for /etc/shadow).
	secret := filepath.Join(t.TempDir(), "shadow")
	writeFile(t, secret, []byte("root:$6$hash"), 0o600)

	resetSettings := func() {
		_ = os.Remove(path)
		writeFile(t, path, []byte("{}\n"), 0o666) // the user chooses the mode
		_ = os.Chown(path, victimUID, victimUID)
	}
	resetSettings()

	var stop atomic.Bool
	done := make(chan struct{})
	go func() { // the user, racing in their own directory
		defer close(done)
		lnk := filepath.Join(dir, "x.lnk")
		reg := filepath.Join(dir, "x.reg")
		for !stop.Load() {
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				n := e.Name()
				if !strings.HasSuffix(n, ".tmp") {
					continue
				}
				target := filepath.Join(dir, n)
				end := time.Now().Add(30 * time.Millisecond)
				for time.Now().Before(end) && !stop.Load() {
					_ = os.Symlink(secret, lnk)
					_ = os.Rename(lnk, target)
					_ = os.WriteFile(reg, nil, 0o600)
					_ = os.Rename(reg, target)
				}
			}
		}
	}()
	deadline := time.Now().Add(45 * time.Second)
	tries := 0
	escaped := false
	for time.Now().Before(deadline) {
		tries++
		plans, err := PlanInstall(c, o)
		if err == nil {
			_ = Apply(plans)
		}
		if fi, err := os.Stat(secret); err == nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("after %d installs, a file outside the user's directory changed mode to %v: Apply's Root.Chmod followed a swapped-in symlink", tries, fi.Mode().Perm())
			escaped = true
			break
		}
		resetSettings()
		// Clear backups so freeName does not run out.
		for _, b := range backups(t, dir) {
			_ = os.Remove(b)
		}
	}
	stop.Store(true)
	<-done
	if !escaped {
		t.Logf("no escape in %d installs", tries)
	}
}
