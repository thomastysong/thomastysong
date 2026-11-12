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
			Config: "/etc/spoor", Data: "/var/lib/spoor", Events: "/var/lib/spoor/events", Spool: "/var/lib/spoor/spool",
			Run: "/run/spoor", Socket: "/run/spoor/hook.sock", StateDB: "/var/lib/spoor/state.db",
		}},
		{"darwin", "", Dirs{
			Config: "/Library/Application Support/spoor", Data: "/Library/Application Support/spoor",
			Events: "/Library/Application Support/spoor/events", Spool: "/Library/Application Support/spoor/spool",
			Run: "/var/run/spoor", Socket: "/var/run/spoor/hook.sock", StateDB: "/Library/Application Support/spoor/state.db",
		}},
		{"windows", `C:\ProgramData`, Dirs{
			Config: `C:\ProgramData\spoor`, Data: `C:\ProgramData\spoor`,
			Events: `C:\ProgramData\spoor\events`, Spool: `C:\ProgramData\spoor\spool`,
			Run: `C:\ProgramData\spoor\run`, Socket: `C:\ProgramData\spoor\run\hook.sock`, StateDB: `C:\ProgramData\spoor\state.db`,
		}},
		{"windows", `D:\PD\`, Dirs{
			Config: `D:\PD\spoor`, Data: `D:\PD\spoor`, Events: `D:\PD\spoor\events`, Spool: `D:\PD\spoor\spool`,
			Run: `D:\PD\spoor\run`, Socket: `D:\PD\spoor\run\hook.sock`, StateDB: `D:\PD\spoor\state.db`,
		}},
		{"windows", "", Dirs{
			Config: `C:\ProgramData\spoor`, Data: `C:\ProgramData\spoor`, Events: `C:\ProgramData\spoor\events`, Spool: `C:\ProgramData\spoor\spool`,
			Run: `C:\ProgramData\spoor\run`, Socket: `C:\ProgramData\spoor\run\hook.sock`, StateDB: `C:\ProgramData\spoor\state.db`,
		}},
		// Any other unix uses the Linux layout.
		{"freebsd", "", Dirs{
			Config: "/etc/spoor", Data: "/var/lib/spoor", Events: "/var/lib/spoor/events", Spool: "/var/lib/spoor/spool",
			Run: "/run/spoor", Socket: "/run/spoor/hook.sock", StateDB: "/var/lib/spoor/state.db",
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
			Config: "/home/ana/.local/state/spoor", Data: "/home/ana/.local/state/spoor",
			Events: "/home/ana/.local/state/spoor/events", Spool: "/home/ana/.local/state/spoor/spool",
			Run: "/home/ana/.local/state/spoor/run", Socket: "/home/ana/.local/state/spoor/run/hook.sock",
			StateDB: "/home/ana/.local/state/spoor/state.db",
		}},
		{"linux", "/", Dirs{
			Config: "/.local/state/spoor", Data: "/.local/state/spoor", Events: "/.local/state/spoor/events", Spool: "/.local/state/spoor/spool",
			Run: "/.local/state/spoor/run", Socket: "/.local/state/spoor/run/hook.sock", StateDB: "/.local/state/spoor/state.db",
		}},
		{"darwin", "/Users/ana", Dirs{
			Config: "/Users/ana/Library/Application Support/spoor", Data: "/Users/ana/Library/Application Support/spoor",
			Events: "/Users/ana/Library/Application Support/spoor/events", Spool: "/Users/ana/Library/Application Support/spoor/spool",
			Run: "/Users/ana/Library/Application Support/spoor/run", Socket: "/Users/ana/Library/Application Support/spoor/run/hook.sock",
			StateDB: "/Users/ana/Library/Application Support/spoor/state.db",
		}},
		{"windows", `C:\Users\ana`, Dirs{
			Config: `C:\Users\ana\AppData\Local\spoor`, Data: `C:\Users\ana\AppData\Local\spoor`,
			Events: `C:\Users\ana\AppData\Local\spoor\events`, Spool: `C:\Users\ana\AppData\Local\spoor\spool`,
			Run: `C:\Users\ana\AppData\Local\spoor\run`, Socket: `C:\Users\ana\AppData\Local\spoor\run\hook.sock`,
			StateDB: `C:\Users\ana\AppData\Local\spoor\state.db`,
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
