//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Managed and system hooks run as whichever account starts the agent, and
// the guard `[ -x BIN ] || exit 0` runs as that account: binaryProblem
// requires that every account can execute the binary and search every
// directory on the way to it (through a symbolic link too); a user-scope
// hook only needs its own account to.
func TestBinaryProblemNeedsEveryAccount(t *testing.T) {
	if !permsChecked {
		t.Skip("mode bits mean nothing here")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root-owned binaries and another uid")
	}
	base := t.TempDir()
	// t.TempDir's directories are 0700: open the path for the cases.
	for d := base; d != filepath.Dir(d) && d != os.TempDir(); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(base, rel)
		writeTestFile(t, p, "#!/bin/sh\nexit 0\n", mode)
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := mk("open/spoor", 0o755)
	ownerOnly := mk("owneronly/spoor", 0o750) // cp under a CIS umask 027
	hidden := mk("closed/bin/spoor", 0o755)
	if err := os.Chmod(filepath.Join(base, "closed"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "open", "via-link")
	if err := os.Symlink(hidden, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		bin, want string
	}{
		{ok, ""},
		{ownerOnly, "not executable by every account (mode 0750, owner uid 0, group gid 0)"},
		{hidden, "which every account cannot search"},
		{link, "which every account cannot search"},
		{mk("noexec/spoor", 0o644), "not executable"},
		{filepath.Join(base, "missing", "spoor"), "not found"},
	} {
		got := binaryProblem(tc.bin)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("binaryProblem(%s) = %q, want %q", tc.bin, got, tc.want)
		}
	}
	// A user-scope hook runs as its account: its own 0700 binary is fine,
	// root's 0750 one is not, and root may run anything with an x bit.
	own := mk("dev/spoor", 0o700)
	if err := os.Chown(own, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	dev := &accessor{name: "dev", uid: 4242, groups: map[int]bool{4242: true}}
	if got := binaryProblemAs(own, dev); got != "" {
		t.Errorf("the account's own 0700 binary: %q", got)
	}
	if got := binaryProblemAs(ownerOnly, dev); !strings.Contains(got, "not executable by dev") {
		t.Errorf("root's 0750 binary for dev: %q", got)
	}
	if got := binaryProblemAs(ownerOnly, &accessor{name: "root", uid: 0, groups: map[int]bool{0: true}}); got != "" {
		t.Errorf("root's 0750 binary for root: %q", got)
	}
}

// A home whose owner the account database does not list still yields that
// uid as the account a user-scope hook runs as.
func TestAccessorForUnlistedHomeOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs chown")
	}
	home := t.TempDir()
	if err := os.Chown(home, 4243, 4243); err != nil {
		t.Fatal(err)
	}
	a := accessorForHome("", home)
	if a == nil || a.uid != 4243 || a.name != "uid 4243" || len(a.groups) != 0 {
		t.Fatalf("accessor %+v", a)
	}
}
