//go:build linux || darwin

package platform

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// within fails the test if fn has not returned in time: opening a FIFO or a
// device must fail fast, not hang the sensor.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s blocked for more than %v", what, d)
	}
}

func TestOpenNoFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeFile(t, target, "secret")

	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenNoFollow(link); err == nil {
		f.Close()
		t.Fatal("followed a symlink on the final component")
	} else if !errors.Is(err, ErrSymlink) {
		t.Errorf("symlink: %v, want ErrSymlink", err)
	}
	// Relative, dangling, to a directory, and chained links are all refused.
	for name, to := range map[string]string{"rel": "target", "dangling": "nowhere", "todir": dir, "chain": link, "etc": "/etc/passwd"} {
		p := filepath.Join(dir, name)
		if err := os.Symlink(to, p); err != nil {
			t.Fatal(err)
		}
		if f, err := OpenNoFollow(p); err == nil {
			f.Close()
			t.Errorf("%s: followed symlink to %q", name, to)
		} else if !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: %v, want ErrSymlink", name, err)
		}
	}
	// A hard link is the same file, not a redirection: allowed.
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	f, err := OpenNoFollow(hard)
	if err != nil {
		t.Fatalf("hard link: %v", err)
	}
	f.Close()

	// Documented limit: only the LAST component is guarded. A symlinked
	// parent directory is followed, which is what OpenBeneath is for.
	realDir := filepath.Join(dir, "real")
	writeFile(t, filepath.Join(realDir, "inner"), "via parent")
	if err := os.Symlink(realDir, filepath.Join(dir, "parentlink")); err != nil {
		t.Fatal(err)
	}
	f, err = OpenNoFollow(filepath.Join(dir, "parentlink", "inner"))
	if err != nil {
		t.Fatalf("symlinked parent: %v", err)
	}
	f.Close()
}

func TestOpenNoFollowSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Opening a FIFO for reading blocks until a writer appears. A user can
	// plant one where a config file is expected to stall a root scanner.
	within(t, 5*time.Second, "OpenNoFollow on a FIFO", func() {
		if f, err := OpenNoFollow(fifo); err == nil {
			f.Close()
			t.Error("opened a FIFO")
		} else if !errors.Is(err, ErrNotRegular) {
			t.Errorf("fifo: %v, want ErrNotRegular", err)
		}
	})
	within(t, 5*time.Second, "OpenBeneath on a FIFO", func() {
		if f, err := OpenBeneath(dir, "fifo"); err == nil {
			f.Close()
			t.Error("OpenBeneath opened a FIFO")
		} else if !errors.Is(err, ErrNotRegular) {
			t.Errorf("OpenBeneath fifo: %v, want ErrNotRegular", err)
		}
	})

	// A relative name keeps the socket path under the sockaddr_un limit.
	t.Chdir(dir)
	l, err := net.Listen("unix", "s.sock")
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	defer l.Close()
	if f, err := OpenNoFollow(filepath.Join(dir, "s.sock")); err == nil {
		f.Close()
		t.Error("opened a socket")
	}
	for _, dev := range []string{"/dev/null", "/dev/zero", "/dev/tty"} {
		within(t, 5*time.Second, "OpenNoFollow on "+dev, func() {
			if f, err := OpenNoFollow(dev); err == nil {
				f.Close()
				t.Errorf("opened device %s", dev)
			}
		})
	}
}

func TestOpenBeneathSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret"), "outside")
	writeFile(t, filepath.Join(root, "skills", "shared", "SKILL.md"), "inside")

	mustLink := func(target, name string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	// The whole agent directory is a link out of the tree: the classic way
	// to make a root scanner read /etc or another user's files.
	mustLink(outside, ".claude")
	mustLink(filepath.Join(outside, "secret"), "abs-file")
	mustLink(filepath.Join("..", filepath.Base(outside), "secret"), "rel-file")
	mustLink("/etc/passwd", "passwd")
	for _, rel := range []string{filepath.Join(".claude", "secret"), "abs-file", "rel-file", "passwd"} {
		if f, err := OpenBeneath(root, rel); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Errorf("OpenBeneath(root, %q) left the tree and read %q", rel, b)
		}
	}
	// Links that stay inside the tree keep working (skills are often linked).
	mustLink(filepath.Join("skills", "shared"), "linked")
	f, err := OpenBeneath(root, filepath.Join("linked", "SKILL.md"))
	if err != nil {
		t.Fatalf("link inside the tree refused: %v", err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "inside" {
		t.Errorf("read %q", b)
	}
	// A link loop ends in an error, not a hang.
	mustLink("loop-b", "loop-a")
	mustLink("loop-a", "loop-b")
	within(t, 5*time.Second, "OpenBeneath on a symlink loop", func() {
		if f, err := OpenBeneath(root, "loop-a"); err == nil {
			f.Close()
			t.Error("opened a symlink loop")
		}
	})
}

func TestFileIDAndOwnerUnix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, path, "x")
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	want := strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
	if got := FileID(fi, ""); got != want {
		t.Errorf("FileID = %q, want dev:inode %q", got, want)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if got := FileID(nil, hard); got != want {
		t.Errorf("hard link id %q, want %q", got, want)
	}
	// A symlink has its own identity; the path form does not follow it.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got := FileID(nil, link); got == want || got == "" {
		t.Errorf("symlink id %q must differ from its target %q", got, want)
	}
	uid, ok := OwnerUID(fi)
	if !ok || uid != strconv.Itoa(os.Getuid()) {
		t.Errorf("OwnerUID = %q %v, want %d", uid, ok, os.Getuid())
	}
	if _, ok := OwnerUID(fakeInfo{}); ok {
		t.Error("OwnerUID answered for a FileInfo without system data")
	}
	if got := FileID(fakeInfo{}, path); got != want {
		t.Errorf("FileID with synthetic FileInfo = %q, want fallback to the path (%q)", got, want)
	}
}

type fakeInfo struct{ os.FileInfo }

func (fakeInfo) Sys() any { return nil }

func TestHostIDFileTrust(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, HostIDFileName)
	writeFile(t, path, "trusted-id\n")
	user := hostIDOverrideFile{path: path}
	if got := readHostIDFile(user); got != "trusted-id" {
		t.Fatalf("own 0644 file: %q", got)
	}
	// Writable by group or others: anyone could have planted the id.
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666, 0o777} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got := readHostIDFile(user); got != "" {
			t.Errorf("mode %o accepted: %q", mode, got)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readHostIDFile(user); got != "trusted-id" {
		t.Errorf("0600: %q", got)
	}
	// The system file must be root's; a user-owned file there is ignored.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && hostIDFileTrusted(fi, true) {
		t.Error("a non-root file was trusted as the system override")
	}
	if os.Geteuid() == 0 && !hostIDFileTrusted(fi, true) {
		t.Error("root's own file was not trusted as the system override")
	}
	// A symlink in place of the file is never followed.
	real := filepath.Join(dir, "real")
	writeFile(t, real, "via-symlink\n")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if got := readHostIDFile(user); got != "" {
		t.Errorf("followed a symlinked host_id: %q", got)
	}
	// Nor is a FIFO read (which would block HostInfo forever).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o644); err == nil {
		within(t, 5*time.Second, "reading a FIFO host_id", func() {
			if got := readHostIDFile(user); got != "" {
				t.Errorf("read a FIFO: %q", got)
			}
		})
	}
}

func TestWriteHostIDFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHostIDFile(dir, "abc"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, HostIDFileName))
	if err != nil {
		t.Fatal(err)
	}
	// World-readable (hook processes read it), writable by the owner only.
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %o, want 0644", fi.Mode().Perm())
	}
}
