package platform

import (
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSkipHomeName(t *testing.T) {
	tests := []struct {
		goos, name string
		skip       bool
	}{
		{"linux", "ana", false},
		{"linux", "lost+found", true},
		{"linux", ".snapshots", true},
		{"linux", "", true},
		{"linux", "Shared", false}, // a perfectly good Linux user name
		{"darwin", "ana", false},
		{"darwin", "Shared", true},
		{"darwin", "shared", true},
		{"darwin", "Guest", true},
		{"darwin", ".localized", true},
		{"windows", "ana", false},
		{"windows", "Public", true},
		{"windows", "PUBLIC", true},
		{"windows", "Default", true},
		{"windows", "Default User", true},
		{"windows", "defaultuser0", true},
		{"windows", "DefaultAppPool", true},
		{"windows", "All Users", true},
		{"windows", ".NET v4.5", true},
		{"windows", "Administrator", false},
	}
	for _, tt := range tests {
		if got := skipHomeName(tt.goos, tt.name); got != tt.skip {
			t.Errorf("skipHomeName(%q, %q) = %v, want %v", tt.goos, tt.name, got, tt.skip)
		}
	}
}

const passwdFixture = `# comment
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ana:x:1000:1000:Ana,,,:/home/ana:/bin/zsh
ben:x:1001:1001::/data/home/ben:
svc:x:1002:1002::/var/lib/svc:/usr/sbin/nologin
git:x:1003:1003::/home/git:/bin/false
dup:x:1000:1000::/home/dup:/bin/sh
+::::::
-baduser
short:x:5
:x:7:7::/home/noname:/bin/sh
neg:x:-1:0::/home/neg:/bin/sh
big:x:4294967296:0::/home/big:/bin/sh
text:x:abc:0::/home/text:/bin/sh
crlf:x:1004:1004::/home/crlf:/bin/bash` + "\r\n" + `rooted:x:1005:1005::/:/bin/sh
rel:x:1006:1006::home/rel:/bin/sh
nfsnobody:x:4294967294:4294967294::/var/lib/nfs:/bin/sh
legacy:x:500:500::/home/legacy:/bin/bash
`

func TestParsePasswd(t *testing.T) {
	entries := parsePasswd([]byte(passwdFixture))
	var names []string
	for _, e := range entries {
		names = append(names, e.name)
	}
	want := []string{"root", "daemon", "nobody", "ana", "ben", "svc", "git", "dup", "crlf", "rooted", "rel", "nfsnobody", "legacy"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v\n want %v", names, want)
	}
	byName := map[string]passwdEntry{}
	for _, e := range entries {
		byName[e.name] = e
	}
	if e := byName["ana"]; e.uid != 1000 || e.home != "/home/ana" || e.shell != "/bin/zsh" {
		t.Errorf("ana = %+v", e)
	}
	if e := byName["crlf"]; e.shell != "/bin/bash" {
		t.Errorf("CR not stripped: %q", e.shell)
	}

	var human []string
	for _, e := range entries {
		if humanAccount(e, 1000) {
			human = append(human, e.name)
		}
	}
	// root always; service accounts, nologin shells, "/" and relative homes,
	// and uids below UID_MIN never.
	if want := []string{"root", "ana", "ben", "dup", "crlf"}; !reflect.DeepEqual(human, want) {
		t.Errorf("human accounts = %v, want %v", human, want)
	}
	if !humanAccount(byName["legacy"], 500) {
		t.Error("UID_MIN 500 must admit uid 500")
	}

	// Hostile sizes: one enormous line, and a file with no newline at all.
	huge := append([]byte(strings.Repeat("x", 1<<20)+"\n"), []byte("ok:x:1:1::/home/ok:/bin/sh\n")...)
	if got := parsePasswd(huge); len(got) != 1 || got[0].name != "ok" {
		t.Errorf("after an oversized line: %+v", got)
	}
	if got := parsePasswd([]byte(strings.Repeat(":", 1<<16))); len(got) != 0 {
		t.Errorf("colon soup parsed: %d entries", len(got))
	}
	if got := parsePasswd([]byte("a\xff:x:1:1::/home/\xfe:/bin/sh")); len(got) != 1 || got[0].name != "a\xff" {
		t.Errorf("invalid utf8 line: %+v", got)
	}
}

func TestParseUIDMin(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{"", 1000},
		{"# UID_MIN 5\nUID_MIN\t\t 500\nUID_MAX 60000\n", 500},
		{"UID_MIN 1000\n", 1000},
		{"UID_MIN abc\n", 1000},
		{"UID_MIN 0\n", 1000},
		{"UID_MIN 99999999999\n", 1000},
		{"SYS_UID_MIN 100\n", 1000},
	}
	for _, tt := range tests {
		if got := parseUIDMin([]byte(tt.in)); got != tt.want {
			t.Errorf("parseUIDMin(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestDedupeUsers(t *testing.T) {
	in := []UserHome{
		{Name: "zed", UID: "1002", Home: "/home/zed"},
		{Name: "ana", UID: "1000", Home: "/home/ana"},
		{Name: "ana-dir", UID: "", Home: "/home/ana/"}, // same home, later: dropped
		{Name: "nohome", UID: "1003", Home: ""},
		{Name: "root", UID: "0", Home: "/root"},
	}
	got := dedupeUsers("linux", in)
	want := []UserHome{
		{Name: "ana", UID: "1000", Home: "/home/ana"},
		{Name: "zed", UID: "1002", Home: "/home/zed"},
		{Name: "root", UID: "0", Home: "/root"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	win := dedupeUsers("windows", []UserHome{
		{Name: "ana", UID: "S-1-5-21-1-2-3-1001", Home: `C:\Users\Ana`},
		{Name: "Ana", Home: `c:\users\ana\`},
	})
	if len(win) != 1 || win[0].UID == "" {
		t.Errorf("windows homes compare case-insensitively: %+v", win)
	}
}

func TestCleanAccountName(t *testing.T) {
	for in, want := range map[string]string{
		"ana":                    "ana",
		"CORP-user.name":         "CORP-user.name",
		"":                       "",
		"a\nb":                   "",
		"a/b":                    "",
		"a:b":                    "",
		"a\x00":                  "",
		strings.Repeat("a", 300): "",
	} {
		if got := cleanAccountName(in); got != want {
			t.Errorf("cleanAccountName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCurrentUserAndUsersReal(t *testing.T) {
	cur := CurrentUser()
	if cur.UID == "" {
		t.Error("CurrentUser has no UID")
	}
	if runtime.GOOS != "windows" {
		if want := itoa(os.Getuid()); cur.UID != want {
			t.Errorf("UID = %q, want %q", cur.UID, want)
		}
	}
	if cur.Home != "" && !isDir(cur.Home) {
		t.Errorf("CurrentUser().Home = %q is not a directory", cur.Home)
	}
	if again := CurrentUser(); again != cur {
		t.Errorf("CurrentUser not stable: %+v then %+v", cur, again)
	}
	users, err := Users()
	if err != nil {
		if cur.Home == "" {
			t.Skipf("no home directory in this environment: %v", err)
		}
		t.Fatal(err)
	}
	seen := map[string]bool{}
	foundCurrent := false
	for _, u := range users {
		if !isDir(u.Home) {
			t.Errorf("listed home %q does not exist", u.Home)
		}
		if seen[u.Home] {
			t.Errorf("home %q listed twice", u.Home)
		}
		seen[u.Home] = true
		if u.Home == cur.Home {
			foundCurrent = true
		}
	}
	if cur.Home != "" && !foundCurrent {
		t.Errorf("current user's home %q missing from %+v", cur.Home, users)
	}
	if !IsPrivileged() {
		for _, u := range users {
			if u.UID != cur.UID {
				t.Errorf("unprivileged caller was given another account: %+v", u)
			}
		}
	}
	t.Logf("privileged=%v current=%+v users=%+v", IsPrivileged(), cur, users)
}
