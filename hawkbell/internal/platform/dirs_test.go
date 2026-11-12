package platform

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSystemDirs(t *testing.T) {
	tests := []struct {
		goos, programData string
		want              Dirs
	}{
		{"linux", "", Dirs{
			Config: "/etc/hawkbell", Data: "/var/lib/hawkbell", Events: "/var/lib/hawkbell/events", Spool: "/var/lib/hawkbell/spool",
			Run: "/run/hawkbell", Socket: "/run/hawkbell/hook.sock", StateDB: "/var/lib/hawkbell/state.db",
		}},
		{"darwin", "", Dirs{
			Config: "/Library/Application Support/hawkbell", Data: "/Library/Application Support/hawkbell",
			Events: "/Library/Application Support/hawkbell/events", Spool: "/Library/Application Support/hawkbell/spool",
			Run: "/var/run/hawkbell", Socket: "/var/run/hawkbell/hook.sock", StateDB: "/Library/Application Support/hawkbell/state.db",
		}},
		{"windows", `C:\ProgramData`, Dirs{
			Config: `C:\ProgramData\hawkbell`, Data: `C:\ProgramData\hawkbell`,
			Events: `C:\ProgramData\hawkbell\events`, Spool: `C:\ProgramData\hawkbell\spool`,
			Run: `C:\ProgramData\hawkbell\run`, Socket: `C:\ProgramData\hawkbell\run\hook.sock`, StateDB: `C:\ProgramData\hawkbell\state.db`,
		}},
		{"windows", `D:\PD\`, Dirs{
			Config: `D:\PD\hawkbell`, Data: `D:\PD\hawkbell`, Events: `D:\PD\hawkbell\events`, Spool: `D:\PD\hawkbell\spool`,
			Run: `D:\PD\hawkbell\run`, Socket: `D:\PD\hawkbell\run\hook.sock`, StateDB: `D:\PD\hawkbell\state.db`,
		}},
		{"windows", "", Dirs{
			Config: `C:\ProgramData\hawkbell`, Data: `C:\ProgramData\hawkbell`, Events: `C:\ProgramData\hawkbell\events`, Spool: `C:\ProgramData\hawkbell\spool`,
			Run: `C:\ProgramData\hawkbell\run`, Socket: `C:\ProgramData\hawkbell\run\hook.sock`, StateDB: `C:\ProgramData\hawkbell\state.db`,
		}},
		// Any other unix uses the Linux layout.
		{"freebsd", "", Dirs{
			Config: "/etc/hawkbell", Data: "/var/lib/hawkbell", Events: "/var/lib/hawkbell/events", Spool: "/var/lib/hawkbell/spool",
			Run: "/run/hawkbell", Socket: "/run/hawkbell/hook.sock", StateDB: "/var/lib/hawkbell/state.db",
		}},
	}
	for _, tt := range tests {
		got := systemDirs(tt.goos, tt.programData)
		if got != tt.want {
			t.Errorf("systemDirs(%q, %q)\n got %+v\nwant %+v", tt.goos, tt.programData, got, tt.want)
		}
		if len(got.Socket) > MaxSocketPath {
			t.Errorf("%s: default socket path is %d bytes, over the sockaddr_un limit", tt.goos, len(got.Socket))
		}
	}
}

func TestUserDirs(t *testing.T) {
	tests := []struct {
		goos, home string
		want       Dirs
	}{
		{"linux", "/home/ana", Dirs{
			Config: "/home/ana/.local/state/hawkbell", Data: "/home/ana/.local/state/hawkbell",
			Events: "/home/ana/.local/state/hawkbell/events", Spool: "/home/ana/.local/state/hawkbell/spool",
			Run: "/home/ana/.local/state/hawkbell/run", Socket: "/home/ana/.local/state/hawkbell/run/hook.sock",
			StateDB: "/home/ana/.local/state/hawkbell/state.db",
		}},
		{"linux", "/", Dirs{
			Config: "/.local/state/hawkbell", Data: "/.local/state/hawkbell", Events: "/.local/state/hawkbell/events", Spool: "/.local/state/hawkbell/spool",
			Run: "/.local/state/hawkbell/run", Socket: "/.local/state/hawkbell/run/hook.sock", StateDB: "/.local/state/hawkbell/state.db",
		}},
		{"darwin", "/Users/ana", Dirs{
			Config: "/Users/ana/Library/Application Support/hawkbell", Data: "/Users/ana/Library/Application Support/hawkbell",
			Events: "/Users/ana/Library/Application Support/hawkbell/events", Spool: "/Users/ana/Library/Application Support/hawkbell/spool",
			Run: "/Users/ana/Library/Application Support/hawkbell/run", Socket: "/Users/ana/Library/Application Support/hawkbell/run/hook.sock",
			StateDB: "/Users/ana/Library/Application Support/hawkbell/state.db",
		}},
		{"windows", `C:\Users\ana`, Dirs{
			Config: `C:\Users\ana\AppData\Local\hawkbell`, Data: `C:\Users\ana\AppData\Local\hawkbell`,
			Events: `C:\Users\ana\AppData\Local\hawkbell\events`, Spool: `C:\Users\ana\AppData\Local\hawkbell\spool`,
			Run: `C:\Users\ana\AppData\Local\hawkbell\run`, Socket: `C:\Users\ana\AppData\Local\hawkbell\run\hook.sock`,
			StateDB: `C:\Users\ana\AppData\Local\hawkbell\state.db`,
		}},
	}
	for _, tt := range tests {
		if got := userDirs(tt.goos, tt.home); got != tt.want {
			t.Errorf("userDirs(%q, %q)\n got %+v\nwant %+v", tt.goos, tt.home, got, tt.want)
		}
	}
}

func TestExpandSystemDrive(t *testing.T) {
	tests := []struct{ value, drive, want string }{
		{`%SystemDrive%\ProgramData`, "C:", `C:\ProgramData`},
		{`%systemdrive%\ProgramData`, "D:", `D:\ProgramData`},
		{`E:\Shared\PD`, "C:", `E:\Shared\PD`},
		{`%SystemDrive%\a\%SYSTEMDRIVE%`, "C:", `C:\a\C:`},
		{`%SystemDrive%\ProgramData`, "", ""}, // drive unknown
		{`%ProgramFiles%\x`, "C:", ""},        // any other variable: refuse, do not consult the environment
		{`%SystemDrive%\%USERNAME%`, "C:", ""},
		{`100%`, "C:", ""},
		{``, "C:", ``},
	}
	for _, tt := range tests {
		if got := expandSystemDrive(tt.value, tt.drive); got != tt.want {
			t.Errorf("expandSystemDrive(%q, %q) = %q, want %q", tt.value, tt.drive, got, tt.want)
		}
	}
	// A drive value that itself contains the variable name must not loop.
	done := make(chan string, 1)
	go func() { done <- expandSystemDrive(`%SystemDrive%\x`, `%SystemDrive%`) }()
	select {
	case got := <-done:
		if got != `%SystemDrive%\x` {
			t.Errorf("self-referential drive: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expandSystemDrive did not terminate")
	}
	// Letters whose lower-case form has a different byte length must not
	// shift the replacement.
	if got, want := expandSystemDrive("\u0130\u0130%SystemDrive%\\x", "C:"), "\u0130\u0130C:\\x"; got != want {
		t.Errorf("non-ASCII prefix: %q, want %q", got, want)
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		goos string
		elem []string
		want string
	}{
		{"linux", []string{"/a", "b", "c"}, "/a/b/c"},
		{"linux", []string{"/", "b"}, "/b"},
		{"linux", []string{"/a/", "/b"}, "/a/b"},
		{"linux", []string{"", "a", "", "b"}, "a/b"},
		{"windows", []string{`C:\a`, "b"}, `C:\a\b`},
		{"windows", []string{`C:\`, "b"}, `C:\b`},
		{"windows", []string{`C:\a\`, `\b`}, `C:\a\b`},
		{"linux", nil, ""},
	}
	for _, tt := range tests {
		if got := joinPath(tt.goos, tt.elem...); got != tt.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tt.goos, tt.elem, got, tt.want)
		}
	}
}

func TestDefaultAndUserDirsOnThisOS(t *testing.T) {
	d := DefaultDirs()
	for name, v := range map[string]string{"Config": d.Config, "Data": d.Data, "Events": d.Events, "Spool": d.Spool, "Run": d.Run, "Socket": d.Socket, "StateDB": d.StateDB} {
		if !filepath.IsAbs(v) {
			t.Errorf("DefaultDirs().%s = %q is not absolute", name, v)
		}
	}
	if filepath.Dir(d.Socket) != filepath.Clean(d.Run) || filepath.Base(d.Socket) != "hook.sock" {
		t.Errorf("socket %q is not hook.sock inside %q", d.Socket, d.Run)
	}
	if d != DefaultDirs() {
		t.Error("DefaultDirs is not deterministic")
	}

	home := t.TempDir()
	u := UserDirs(home)
	for name, v := range map[string]string{"Config": u.Config, "Data": u.Data, "Events": u.Events, "Spool": u.Spool, "Run": u.Run, "Socket": u.Socket, "StateDB": u.StateDB} {
		if !strings.HasPrefix(v, home) {
			t.Errorf("UserDirs(home).%s = %q is outside %q", name, v, home)
		}
	}
	if u == d {
		t.Error("user and system layouts are identical")
	}
	// "" means the current user, and must not depend on variables an agent
	// can change for the hook process.
	before := UserDirs("")
	if runtime.GOOS != "windows" {
		t.Setenv("XDG_STATE_HOME", "/tmp/elsewhere")
		t.Setenv("XDG_RUNTIME_DIR", "/tmp/elsewhere")
		t.Setenv("TMPDIR", "/tmp/elsewhere")
	}
	if after := UserDirs(""); after != before {
		t.Errorf("UserDirs(\"\") changed with the environment: %+v then %+v", before, after)
	}
	if cur := CurrentUser(); cur.Home != "" && !strings.HasPrefix(before.Config, cur.Home) {
		t.Errorf("UserDirs(\"\").Config = %q is outside the current home %q", before.Config, cur.Home)
	}
}
