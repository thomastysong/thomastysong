package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestHomeRelativeAllOSStyles(t *testing.T) {
	cases := []struct {
		goos, user, in, want string
	}{
		{"linux", "bob", "/home/bob/work/x.go", "~/work/x.go"},
		{"linux", "bob", "/home/bob", "~"},
		{"linux", "bob", "cat /home/bob/.ssh/id_rsa /home/bobby/x", "cat ~/.ssh/id_rsa /home/bobby/x"},
		{"linux", "bob", "/mnt/home/bob/x", "/mnt/home/bob/x"},
		{"linux", "bob", "file:///home/bob/x", "file:/~/x"},
		{"linux", "bob", "/home/bob:/home/bob/bin", "~:~/bin"},
		{"linux", "root", "/root/.bashrc", "~/.bashrc"},
		{"linux", "bob", "/HOME/BOB/x", "/HOME/BOB/x"}, // case-sensitive on Linux
		{"darwin", "bob", "/Users/bob/Library/x", "~/Library/x"},
		{"darwin", "bob", "/users/BOB/x", "~/x"},
		{"darwin", "root", "/var/root/x", "~/x"},
		{"windows", "bob", `C:\Users\bob\AppData\x.json`, `~\AppData\x.json`},
		{"windows", "bob", `c:/users/BOB/x`, `~/x`},
		{"windows", "bob", `"C:\\Users\\bob\\x"`, `"~\\x"`},
		{"windows", `CORP\bob`, `C:\Users\bob\x`, `~\x`},
		{"windows", "bob", `C:\Users\bobby\x`, `C:\Users\bobby\x`},
	}
	for _, c := range cases {
		p := &Policy{}
		h := newHomeRewriter(p.homeOf(c.user, c.goos), c.goos, nil)
		if got := h.rewrite(c.in); got != c.want {
			t.Errorf("%s %s %q -> %q, want %q", c.goos, c.user, c.in, got, c.want)
		}
	}
}

func TestHomeOfOverrideAndUnsafe(t *testing.T) {
	p := &Policy{HomeOf: func(u string) string {
		switch u {
		case "svc":
			return "/var/lib/svc"
		case "weird":
			return "/"
		}
		return ""
	}}
	if got := p.homeOf("svc", "linux"); got != "/var/lib/svc" {
		t.Errorf("override: %q", got)
	}
	if got := p.homeOf("weird", "linux"); got != "/home/weird" {
		t.Errorf("unsafe home must fall back to convention: %q", got)
	}
	for _, bad := range []string{"../etc", "a/b", "", "x\x00y"} {
		if got := (&Policy{}).homeOf(bad, "linux"); got != "" {
			t.Errorf("homeOf(%q) = %q", bad, got)
		}
	}
	h := newHomeRewriter("/", "linux", nil)
	if got := h.rewrite("/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("root home must not rewrite: %q", got)
	}
}

func TestHomeRelativeInEmit(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		home := map[string]string{"linux": "/home/bob", "darwin": "/Users/bob", "windows": `C:\Users\bob`}[goos]
		e := activity(event.TypeToolPre)
		e.Host.OS = goos
		e.Session.CWD = home + "/proj"
		e.Tool = &event.Tool{Name: "Read", Kind: event.ToolFileRead}
		e.Target = &event.Target{Path: home + "/proj/main.go", Command: "cat " + home + "/.aws/credentials"}
		e.Process = &event.Process{Exe: home + "/bin/tool", Args: []string{home + "/bin/tool", "--config=" + home + "/c.yml"}}
		e.Repo = &event.Repo{Root: home + "/proj"}
		out, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
		out.User = nil // the account itself is emitted by design
		l := line(t, out)
		if strings.Contains(l, "bob") {
			t.Errorf("%s: account name in a path:\n%s", goos, l)
		}
		if !strings.Contains(l, "~") {
			t.Errorf("%s: no home-relative path:\n%s", goos, l)
		}
	}
}
