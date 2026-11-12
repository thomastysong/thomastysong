//go:build unix

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const dirPack = "pack: d\nversion: \"7\"\nrules:\n" + goodRule

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // umask-independent
		t.Fatal(err)
	}
}

func rulesDir(t *testing.T) string {
	d := filepath.Join(t.TempDir(), "rules-root")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)
	return d
}

func TestLoadDirFlat(t *testing.T) {
	d := rulesDir(t)
	writeFile(t, filepath.Join(d, "a.yaml"), dirPack, 0o644)
	writeFile(t, filepath.Join(d, "lists.yaml"), "lists:\n  l: [x]\n", 0o644)
	writeFile(t, filepath.Join(d, "notes.txt"), "not a pack", 0o644)
	writeFile(t, filepath.Join(d, ".hidden.yaml"), "garbage: [", 0o644)
	s, err := LoadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 1 || s.Version() != "d@7" || s.lists["l"] == nil {
		t.Fatalf("count %d version %s lists %v", s.Count(), s.Version(), s.lists)
	}
}

func TestLoadDirBundleLayout(t *testing.T) {
	d := rulesDir(t)
	writeFile(t, filepath.Join(d, "rules", "a.yaml"), dirPack, 0o644)
	os.Chmod(filepath.Join(d, "rules"), 0o755)
	writeFile(t, filepath.Join(d, "lists.yaml"), "lists:\n  l: [x]\n", 0o644)
	writeFile(t, filepath.Join(d, "suppressions.yaml"), "suppressions:\n  - {rule: '*', reason: test}\n", 0o644)
	// In bundle layout top-level packs are not content.
	writeFile(t, filepath.Join(d, "stray.yaml"), "garbage: [", 0o644)
	s, err := LoadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 1 || len(s.Suppressions()) != 1 || s.lists["l"] == nil {
		t.Fatalf("count %d sups %d", s.Count(), len(s.Suppressions()))
	}
}

func TestLoadDirRefusesInsecureContent(t *testing.T) {
	type setup func(t *testing.T, d string)
	cases := []struct {
		name string
		mk   setup
	}{
		{"group-writable dir", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "a.yaml"), dirPack, 0o644)
			os.Chmod(d, 0o775)
		}},
		{"world-writable file", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "a.yaml"), dirPack, 0o646)
		}},
		{"symlinked pack", func(t *testing.T, d string) {
			target := filepath.Join(t.TempDir(), "real.yaml")
			writeFile(t, target, dirPack, 0o644)
			if err := os.Symlink(target, filepath.Join(d, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked rules dir", func(t *testing.T, d string) {
			real := t.TempDir()
			os.Chmod(real, 0o755)
			writeFile(t, filepath.Join(real, "a.yaml"), dirPack, 0o644)
			if err := os.Symlink(real, filepath.Join(d, "rules")); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory named like a pack", func(t *testing.T, d string) {
			os.Mkdir(filepath.Join(d, "a.yaml"), 0o755)
		}},
		{"oversized pack", func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "a.yaml"), dirPack+"#"+strings.Repeat("x", MaxPackBytes), 0o644)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := rulesDir(t)
			c.mk(t, d)
			if _, err := LoadDir(d); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	// The root directory itself as a symlink.
	d := rulesDir(t)
	writeFile(t, filepath.Join(d, "a.yaml"), dirPack, 0o644)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(d, link)
	if _, err := LoadDir(link); err == nil {
		t.Error("symlinked rules directory accepted")
	}
	if _, err := LoadDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing directory accepted")
	}
}

// A FIFO planted under a pack name must not hang the loader.
func TestLoadDirFIFODoesNotHang(t *testing.T) {
	d := rulesDir(t)
	if err := syscall.Mkfifo(filepath.Join(d, "a.yaml"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadDir(d); done <- err }()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, ErrInsecureDir) {
			t.Fatalf("FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadDir blocked on a FIFO")
	}
}

func TestLoadDirRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by another uid")
	}
	d := rulesDir(t)
	p := filepath.Join(d, "a.yaml")
	writeFile(t, p, dirPack, 0o644)
	if err := os.Chown(p, 65534, 65534); err != nil {
		t.Skip(err)
	}
	_, err := LoadDir(d)
	if err == nil || !errors.Is(err, ErrInsecureDir) || !strings.Contains(err.Error(), "uid 65534") {
		t.Fatalf("foreign-owned pack: %v", err)
	}
	os.Chown(p, 0, 0)
	if err := os.Chown(d, 65534, 65534); err != nil {
		t.Skip(err)
	}
	if _, err := LoadDir(d); err == nil {
		t.Fatal("foreign-owned directory accepted")
	}
}
