//go:build linux || darwin

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTrustedPathModes runs the real owner and mode rule on files under a
// test directory (its ancestors, outside the test's control, are taken as
// given): group- or world-writable directories and files, a sticky
// world-writable directory, another account's directory and links into
// any of them are refused.
func TestTrustedPathModes(t *testing.T) {
	base := t.TempDir()
	euid := os.Geteuid()
	check := func(p string) bool {
		return walkTrusted(p, os.Lstat, os.Readlink, func(q string, fi os.FileInfo) bool {
			if q != base && !strings.HasPrefix(q, base+"/") {
				return true
			}
			return safelyOwned(fi, euid)
		})
	}
	mk := func(dir string, mode os.FileMode) string {
		t.Helper()
		d := filepath.Join(base, dir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(d, "spoor")
		if err := os.WriteFile(f, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, 0o755); err != nil {
			t.Fatal(err)
		}
		return f
	}
	ok := mk("ok", 0o755)
	gw := mk("gw", 0o775)
	ow := mk("ow", 0o757)
	sticky := mk("sticky", 0o1777)
	gwFile := mk("gwfile", 0o755)
	if err := os.Chmod(gwFile, 0o775); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{ok: true, gw: false, ow: false, sticky: false, gwFile: false} {
		if got := check(p); got != want {
			t.Errorf("%s: %v, want %v", strings.TrimPrefix(p, base), got, want)
		}
	}
	// Links: into the safe directory, and into the group-writable one.
	good, bad := filepath.Join(base, "ok", "good"), filepath.Join(base, "ok", "bad")
	if err := os.Symlink("spoor", good); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../gw/spoor", bad); err != nil {
		t.Fatal(err)
	}
	if !check(good) || check(bad) {
		t.Errorf("links: good %v bad %v", check(good), check(bad))
	}
	if euid == 0 {
		other := mk("other", 0o755)
		if err := os.Chown(filepath.Dir(other), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if check(other) {
			t.Error("a directory another account owns was trusted")
		}
	}
}

// TestTrustedPathReal: system binaries are trusted; anything under a
// world-writable temporary directory is not.
func TestTrustedPathReal(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/usr/bin/env"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if !TrustedPath(p) {
			t.Errorf("TrustedPath(%s) = false", p)
		}
	}
	if fi, err := os.Stat(os.TempDir()); err != nil || fi.Mode().Perm()&0o002 == 0 {
		t.Skip("temporary directory not world-writable here")
	}
	f := filepath.Join(t.TempDir(), "spoor")
	if err := os.WriteFile(f, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if TrustedPath(f) {
		t.Errorf("TrustedPath(%s) = true under a world-writable directory", f)
	}
	if TrustedPath("relative/spoor") || TrustedPath("/") {
		t.Error("relative path or directory trusted")
	}
}

func TestIsSystemAccount(t *testing.T) {
	if !IsSystemAccount("0") || IsSystemAccount("1000") || IsSystemAccount("") || IsSystemAccount("65534") {
		t.Error("IsSystemAccount")
	}
}
