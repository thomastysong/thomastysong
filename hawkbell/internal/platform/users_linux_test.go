//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// withAccountFixtures points the account database and home root at a
// temporary tree and returns that tree's root.
func withAccountFixtures(t *testing.T, passwd string) string {
	t.Helper()
	root := t.TempDir()
	oldPasswd, oldDefs, oldRoots, oldRootHome := etcPasswdPath, etcLoginDefsPath, homeRoots, rootHomePath
	etcPasswdPath = filepath.Join(root, "passwd")
	etcLoginDefsPath = filepath.Join(root, "login.defs")
	homeRoots = []string{filepath.Join(root, "home")}
	rootHomePath = filepath.Join(root, "root")
	t.Cleanup(func() {
		etcPasswdPath, etcLoginDefsPath, homeRoots, rootHomePath = oldPasswd, oldDefs, oldRoots, oldRootHome
	})
	if passwd != "" {
		if err := os.WriteFile(etcPasswdPath, []byte(passwd), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(homeRoots[0], 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLinuxAccountEnumeration(t *testing.T) {
	root := withAccountFixtures(t, "")
	home := filepath.Join(root, "home")
	uid := strconv.Itoa(os.Getuid())
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ana := mk("home", "ana")
	mk("home", "ldapuser") // has a home, no passwd entry
	mk("home", "lost+found")
	mk("home", ".snapshots")
	outside := mk("srv", "ben") // home outside /home, only passwd knows
	mk("var", "svc")
	rootHome := mk("root")
	if err := os.WriteFile(filepath.Join(home, "README"), []byte("a file, not a home"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlinked home (admin-configured) and a dangling one.
	real := mk("mnt", "nfs", "carol")
	if err := os.Symlink(real, filepath.Join(home, "carol")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(home, "ghost")); err != nil {
		t.Fatal(err)
	}
	passwd := "root:x:0:0::" + rootHome + ":/bin/bash\n" +
		"ana:x:" + uid + ":1::" + ana + ":/bin/bash\n" +
		"ben:x:2001:2001::" + outside + ":/bin/zsh\n" +
		"svc:x:2002:2002::" + filepath.Join(root, "var", "svc") + ":/usr/sbin/nologin\n" +
		"gone:x:2003:2003::" + filepath.Join(root, "home", "gone") + ":/bin/bash\n"
	if err := os.WriteFile(etcPasswdPath, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}

	accounts := listAccounts()
	scanned := scanHomeRoot(home)
	all := dedupeUsers("linux", append(accounts, scanned...))
	homes := map[string]UserHome{}
	for _, u := range all {
		homes[u.Home] = u
	}
	wantHomes := []string{ana, filepath.Join(home, "carol"), filepath.Join(home, "ldapuser"), outside, rootHome}
	var gotHomes []string
	for _, u := range all {
		gotHomes = append(gotHomes, u.Home)
	}
	wantSorted := append([]string(nil), wantHomes...)
	sortStrings(wantSorted)
	if !reflect.DeepEqual(gotHomes, wantSorted) {
		t.Fatalf("homes = %v\n want %v", gotHomes, wantSorted)
	}
	if u := homes[outside]; u.Name != "ben" || u.UID != "2001" {
		t.Errorf("passwd account outside /home: %+v", u)
	}
	if u := homes[rootHome]; u.Name != "root" || u.UID != "0" {
		t.Errorf("root: %+v", u)
	}
	// No passwd entry: the directory name is the label, the owner the uid.
	if u := homes[filepath.Join(home, "ldapuser")]; u.Name != "ldapuser" || u.UID != uid {
		t.Errorf("directory-only account: %+v", u)
	}
	if u := homes[ana]; u.Name != "ana" || u.UID != uid {
		t.Errorf("ana: %+v", u)
	}

	// The account name wins over the directory name only when the owner's
	// registered home is that very directory.
	for _, u := range scanned {
		if u.Home == filepath.Join(home, "ldapuser") && u.Name != "ldapuser" {
			t.Errorf("owner's name leaked onto a directory that is not their home: %+v", u)
		}
	}

	// Lookups by uid use the same database, first entry winning.
	if name, h, ok := lookupUID(2001); !ok || name != "ben" || h != outside {
		t.Errorf("lookupUID(2001) = %q %q %v", name, h, ok)
	}
	if _, _, ok := lookupUID(4000000); ok {
		t.Error("lookupUID found an account that does not exist")
	}

	// The cache notices a rewritten passwd file.
	if err := os.WriteFile(etcPasswdPath, []byte(passwd+"new:x:2004:2004::"+ana+":/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, _, ok := lookupUID(2004); !ok || name != "new" {
		t.Errorf("stale passwd cache: %q %v", name, ok)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestLinuxAccountsWithoutPasswd(t *testing.T) {
	root := withAccountFixtures(t, "")
	if err := os.MkdirAll(filepath.Join(root, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := listAccounts()
	if len(got) != 1 || got[0].Name != "root" || got[0].UID != "0" {
		t.Errorf("image without passwd: %+v, want root only", got)
	}
	if _, _, ok := lookupUID(0); ok {
		t.Error("lookupUID answered without a passwd file")
	}
	names := newUserNames()
	if got := names.lookup("0"); got != "" {
		t.Errorf("name for uid 0 without passwd: %q", got)
	}
	if got := names.lookup("not-a-uid"); got != "" {
		t.Errorf("name for a malformed uid: %q", got)
	}
}

func TestCurrentUserFallsBackToEnvironment(t *testing.T) {
	// An arbitrary-uid container: no passwd entry for the running uid.
	withAccountFixtures(t, "someoneelse:x:4000001:4000001::/home/else:/bin/sh\n")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USER", "ci-runner")
	cur := CurrentUser()
	if cur.Name != "ci-runner" || cur.Home != home || cur.UID != strconv.Itoa(os.Getuid()) {
		t.Errorf("CurrentUser = %+v", cur)
	}
	t.Setenv("USER", "evil\nname")
	t.Setenv("LOGNAME", "")
	if cur := CurrentUser(); cur.Name != "" {
		t.Errorf("hostile USER accepted: %q", cur.Name)
	}
	t.Setenv("HOME", "relative/home")
	if cur := CurrentUser(); cur.Home != "" {
		t.Errorf("relative HOME accepted: %q", cur.Home)
	}
	t.Setenv("HOME", filepath.Join(home, "missing"))
	if cur := CurrentUser(); cur.Home != "" {
		t.Errorf("nonexistent HOME accepted: %q", cur.Home)
	}
	if _, err := Users(); err == nil && !IsPrivileged() {
		t.Error("Users() succeeded with no home at all")
	}
}

func TestUsersIncludesRelocatedHOME(t *testing.T) {
	root := withAccountFixtures(t, "")
	dbHome := filepath.Join(root, "home", "me")
	if err := os.MkdirAll(dbHome, 0o755); err != nil {
		t.Fatal(err)
	}
	uid := strconv.Itoa(os.Getuid())
	if err := os.WriteFile(etcPasswdPath, []byte("me:x:"+uid+":1::"+dbHome+":/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// CI containers run agents with HOME pointing somewhere else entirely;
	// that is where the agent's files are.
	ciHome := t.TempDir()
	t.Setenv("HOME", ciHome)
	cur := CurrentUser()
	if cur.Home != dbHome || cur.Name != "me" {
		t.Fatalf("CurrentUser = %+v, want the account database's home", cur)
	}
	users, err := Users()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range users {
		if u.UID == uid && u.Name == "me" {
			got = append(got, u.Home)
		}
	}
	want := []string{dbHome, ciHome}
	sortStrings(want)
	sortStrings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("homes of the current user = %v, want %v", got, want)
	}
}
