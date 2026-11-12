//go:build unix

package state

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// asPrivileged runs fn with the privileged checks forced on or off, so both
// behaviours are tested whoever runs the suite.
func asPrivileged(t *testing.T, on bool) {
	t.Helper()
	prev := privileged
	privileged = func() bool { return on }
	t.Cleanup(func() { privileged = prev })
}

func TestOpenRefusesWritableDirectoryWhenPrivileged(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{"private", 0o700, true},
		{"group-readable", 0o750, true},
		{"world-readable", 0o755, true},
		{"group-writable", 0o770, false},
		{"world-writable", 0o777, false},
		{"sticky world-writable", 0o777 | os.ModeSticky, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asPrivileged(t, true)
			dir := filepath.Join(t.TempDir(), "d")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "state.db")
			s, err := Open(path)
			if tc.ok {
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				s.Close()
				ro, err := OpenReadOnly(path)
				if err != nil {
					t.Fatalf("OpenReadOnly: %v", err)
				}
				ro.Close()
				return
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Open in mode %v = %v, want ErrUnsafePath", tc.mode, err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatal("database was created in an unsafe directory")
			}

			// An unprivileged writer has no one to defend against but
			// itself; the same directory is accepted.
			asPrivileged(t, false)
			s, err = Open(path)
			if err != nil {
				t.Fatalf("unprivileged Open: %v", err)
			}
			s.Close()
			// And a privileged reader refuses it again.
			asPrivileged(t, true)
			if _, err := OpenReadOnly(path); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("privileged OpenReadOnly in mode %v = %v, want ErrUnsafePath", tc.mode, err)
			}
		})
	}
}

func TestOpenRefusesForeignOwnerWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to change ownership")
	}
	dir := filepath.Join(t.TempDir(), "d")
	os.Mkdir(dir, 0o700)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("chown: %v", err)
	}
	path := filepath.Join(dir, "state.db")
	if _, err := Open(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open in a directory owned by another uid = %v, want ErrUnsafePath", err)
	}

	// A root-owned directory holding a database owned by someone else.
	dir2 := filepath.Join(t.TempDir(), "d2")
	os.Mkdir(dir2, 0o700)
	path2 := filepath.Join(dir2, "state.db")
	s, err := Open(path2)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Chown(path2, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path2); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open of a database owned by another uid = %v, want ErrUnsafePath", err)
	}
	if _, err := OpenReadOnly(path2); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenReadOnly of a database owned by another uid = %v, want ErrUnsafePath", err)
	}
}

func TestOpenRefusesWritableFileWhenPrivileged(t *testing.T) {
	asPrivileged(t, true)
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	os.Chmod(path, 0o666)
	if _, err := Open(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open(world-writable file) = %v, want ErrUnsafePath", err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenReadOnly(world-writable file) = %v, want ErrUnsafePath", err)
	}
	// Merely too readable is repaired, not refused.
	os.Chmod(path, 0o644)
	s, err = Open(path)
	if err != nil {
		t.Fatalf("Open(0644 file): %v", err)
	}
	s.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after reopen %04o, want 0600", fi.Mode().Perm())
	}
}

func TestOpenRefusesLinksAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.db")
	os.WriteFile(target, nil, 0o600)

	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open(symlink) = %v, want ErrUnsafePath", err)
	}
	if _, err := OpenReadOnly(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenReadOnly(symlink) = %v, want ErrUnsafePath", err)
	}
	dangling := filepath.Join(dir, "dangling.db")
	os.Symlink(filepath.Join(dir, "nowhere"), dangling)
	if _, err := Open(dangling); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open(dangling symlink) = %v, want ErrUnsafePath", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !os.IsNotExist(err) {
		t.Fatal("Open created a file through a dangling symlink")
	}

	// A FIFO where the database should be must be refused without blocking.
	fifo := filepath.Join(dir, "fifo.db")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 2)
	go func() { _, err := Open(fifo); done <- err }()
	go func() { _, err := OpenReadOnly(fifo); done <- err }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("open of a FIFO = %v, want ErrUnsafePath", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("open of a FIFO blocked")
		}
	}

	// A symlinked WAL sidecar would make SQLite write through the link.
	real := filepath.Join(dir, "real.db")
	s, err := Open(real)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	os.Remove(real + "-wal")
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	if err := os.Symlink(victim, real+"-wal"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(real); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Open with a symlinked -wal = %v, want ErrUnsafePath", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("the symlink target was written")
	}
}
