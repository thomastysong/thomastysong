//go:build unix

package procmon

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRootOnlyExecutable checks the rule for the self-test program: only a
// file that nobody but root can have planted or replaced is ever started.
func TestRootOnlyExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership checks need files owned by root")
	}
	dir := t.TempDir() // root-owned, 0700
	write := func(name string, perm os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, perm); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(name, target string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("busybox", 0o755)
	shared := write("shared", 0o775)
	noexec := write("data", 0o644)
	openDir := filepath.Join(dir, "open")
	if err := os.Mkdir(openDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	inOpen := filepath.Join(openDir, "true")
	if err := os.WriteFile(inOpen, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path string
		want       bool
	}{
		{"root-owned 0755", good, true},
		{"group-writable", shared, false},
		{"not executable", noexec, false},
		{"symlink to a good file (busybox)", link("true", good), true},
		{"symlink to a shared file", link("true2", shared), false},
		{"symlink into a world-writable directory", link("true3", inOpen), false},
		{"file in a world-writable directory", inOpen, false},
		{"dangling symlink", link("true4", filepath.Join(dir, "missing")), false},
		{"missing", filepath.Join(dir, "nope"), false},
		{"directory", openDir, false},
	}
	for _, tc := range tests {
		if got := rootOnlyExecutable(tc.path); got != tc.want {
			t.Errorf("%s: rootOnlyExecutable(%s) = %v", tc.name, tc.path, got)
		}
	}
	if p, args, ok := canaryCommand(); ok && (len(args) != 1 || args[0] != p) {
		t.Errorf("canaryCommand = %q %q", p, args)
	}
}
