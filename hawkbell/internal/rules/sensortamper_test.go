package rules

import (
	"slices"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TestSensorTamperSpellings runs HB-EVADE-002 of the embedded packs over
// spellings of a change to the sensor's files that need more than the
// anchored path list: globs, paths relative to the session directory,
// process roots behind a variable, a colon or a literal "$" in a name on a
// POSIX host, and Windows forms. The pack keeps one test of each kind; the
// rule's test limit leaves the rest here.
func TestSensorTamperSpellings(t *testing.T) {
	s, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	win := func(cmd string) func(*event.Event) {
		return func(e *event.Event) {
			e.Host.OS = "windows"
			e.Session.CWD = `C:\Users\u\repo`
			e.Tool = &event.Tool{Kind: event.ToolShell, Name: "PowerShell"}
			e.Target = &event.Target{Command: cmd}
		}
	}
	cwd := func(d string) func(*event.Event) { return func(e *event.Event) { e.Session.CWD = d } }
	for i, tc := range []struct {
		name string
		mods []func(*event.Event)
		want bool
	}{
		{"bracket globs on several characters", []func(*event.Event){shell("touch /etc/[h][a]wkbel[l]/disabled")}, true},
		{"star glob after the name", []func(*event.Event){shell("touch /etc/hawkbell*/disabled")}, true},
		{"state removed through a star glob", []func(*event.Event){shell("rm -rf /var/lib/ha*l")}, true},
		{"quoted brackets are a literal name", []func(*event.Event){shell("touch '/etc/[h]awkbell/disabled'")}, true},
		{"relative cd from the home directory", []func(*event.Event){cwd("/home/alice"), shell("cd .local/state/hawkbell && rm -f state.db")}, true},
		{"the shell's working directory link", []func(*event.Event){cwd("/var/lib/hawkbell"), shell("rm -f /proc/self/cwd/state.db")}, true},
		{"relative to the root", []func(*event.Event){cwd("/"), shell("rm -rf etc/hawkbell")}, true},
		{"configuration rewritten through dot segments", []func(*event.Event){cwd("/home/u/proj"), shell("echo 'data_dir: /dev/null' > ../../../etc/hawkbell/hawkbell.yaml")}, true},
		{"process root found with pgrep", []func(*event.Event){shell("rm -rf /proc/$(pgrep -n sshd)/root/etc/hawkbell")}, true},
		{"a name with a colon on a POSIX host", []func(*event.Event){cwd("/tmp"), shell("mkdir -p a: && touch a:/../../etc/hawkbell/disabled")}, true},
		{"after a literal dollar sign", []func(*event.Event){shell("cd /tmp && touch 'q$x/../../etc/hawkbell/disabled'")}, true},
		{"another user's home", []func(*event.Event){shell("touch ~x/../../etc/hawkbell/disabled")}, true},
		{"Windows mkdir", []func(*event.Event){win(`mkdir C:\ProgramData\hawkbell\disabled`)}, true},
		{"Windows cmd md from PowerShell", []func(*event.Event){win(`cmd /c md C:\ProgramData\hawkbell\disabled`)}, true},
		{"Windows cmd mkdir quoted", []func(*event.Event){win(`cmd.exe /c "md C:\ProgramData\hawkbell\disabled"`)}, true},
		{"Windows cd to the drive root", []func(*event.Event){win(`cd \; Remove-Item -Recurse ProgramData\hawkbell`)}, true},
		{"Windows bracket wildcard", []func(*event.Event){win(`Remove-Item -Recurse C:\ProgramData\[h]awkbell`)}, true},
		// Not a change to the sensor.
		{"a glob over a project directory", []func(*event.Event){shell("rm -rf build/hawkbell*")}, false},
		{"every log rotated away", []func(*event.Event){shell("rm -rf /var/log/*")}, false},
		{"every directory under /opt chowned", []func(*event.Event){shell("chown -R app /opt/*")}, false},
		{"a relative path in a project", []func(*event.Event){cwd("/home/u/proj"), shell("cd hawkbell && rm -f state.db")}, false},
		// A link or bind mount that reaches the sensor's writable files,
		// made in one tool call and written through in a later one.
		{"a hard link of the configuration", []func(*event.Event){shell("ln /etc/hawkbell/hawkbell.yaml /tmp/c.yaml")}, true},
		{"a relative symlink to the configuration directory", []func(*event.Event){shell("cd /tmp && ln -s ../etc/hawkbell s")}, true},
		{"Windows symbolic link", []func(*event.Event){win(`New-Item -ItemType SymbolicLink -Path C:\x -Target C:\ProgramData\hawkbell`)}, true},
		{"Windows junction", []func(*event.Event){win(`New-Item -ItemType Junction -Path C:\x -Value C:\ProgramData\hawkbell`)}, true},
		{"Windows hard link", []func(*event.Event){win(`New-Item -ItemType HardLink -Path C:\x -Target C:\ProgramData\hawkbell\hawkbell.yaml`)}, true},
		{"mklink from PowerShell", []func(*event.Event){win(`cmd /c mklink /D C:\x C:\ProgramData\hawkbell`)}, true},
		// The binary and the logs: linked elsewhere to be used.
		{"the CLI linked onto the PATH", []func(*event.Event){shell("ln -sf /usr/bin/hawkbell ~/.local/bin/hawkbell")}, false},
		{"the log linked into a scratch directory", []func(*event.Event){shell("ln -sf /var/log/hawkbell/hawkbell.log /tmp/hawkbell.log")}, false},
		{"Windows link to the program directory", []func(*event.Event){win(`New-Item -ItemType SymbolicLink -Path C:\x -Target 'C:\Program Files\hawkbell'`)}, false},
	} {
		mods := append([]func(*event.Event){session(string(rune('a' + i)))}, tc.mods...)
		x := ev(event.TypeToolPre, mods...)
		o := Options{Home: "/home/u", OS: "linux"}
		if x.Host.OS == "windows" {
			o = Options{Home: `C:\Users\u`, OS: "windows"}
		}
		r := NewEngine(s, o).Eval(x)
		if got := slices.Contains(ids(r.Detections), "HB-EVADE-002"); got != tc.want {
			t.Errorf("%s: HB-EVADE-002 = %v, want %v (detections %v)", tc.name, got, tc.want, ids(r.Detections))
		}
	}
}
