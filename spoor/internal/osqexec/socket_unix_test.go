//go:build unix

package osqexec

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// listenUnix creates a socket file. Unix socket paths are limited to about
// 100 bytes, so a test whose temp dir is deeper than that is skipped.
func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	if len(path) > 100 {
		t.Skipf("temp dir too deep for a unix socket (%d bytes)", len(path))
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestCheckSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(filepath.Join(dir, "absent.em")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absent socket: err = %v, want fs.ErrNotExist", err)
	}

	file := filepath.Join(dir, "file.em")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(file); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("regular file accepted as a socket: %v", err)
	}

	good := filepath.Join(dir, "o.em")
	listenUnix(t, good)
	if err := checkSocket(good); err != nil {
		t.Fatalf("own socket in own 0755 directory rejected: %v", err)
	}

	// A symlink to a good socket is not the socket.
	link := filepath.Join(dir, "link.em")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(link); err == nil {
		t.Fatal("symlink accepted as a socket")
	}

	// A directory anyone can write to lets anyone replace the socket.
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	inOpen := filepath.Join(open, "o.em")
	listenUnix(t, inOpen)
	if err := checkSocket(inOpen); err == nil {
		t.Fatal("socket in a world-writable directory accepted")
	}
	// The sticky bit (as on /tmp) makes that directory acceptable again.
	if err := os.Chmod(open, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(inOpen); err != nil {
		t.Fatalf("socket in a sticky directory rejected: %v", err)
	}

	if os.Geteuid() != 0 {
		t.Log("not root: skipping the foreign-owner cases")
		return
	}
	// Another user's socket, and another user's directory.
	foreign := filepath.Join(dir, "foreign.em")
	listenUnix(t, foreign)
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(foreign); err == nil {
		t.Fatal("socket owned by another user accepted")
	}
	theirs := filepath.Join(dir, "theirs")
	if err := os.Mkdir(theirs, 0o755); err != nil {
		t.Fatal(err)
	}
	inTheirs := filepath.Join(theirs, "o.em")
	listenUnix(t, inTheirs)
	if err := os.Chown(theirs, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(inTheirs); err == nil {
		t.Fatal("root socket in another user's directory accepted")
	}
}
