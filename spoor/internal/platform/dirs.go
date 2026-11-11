package platform

import (
	"os"
	"runtime"
	"strings"
)

// Dirs is the set of paths one spoor installation uses.
//
// Config holds settings, rules and the host_id override and must be readable
// by every user, because the unprivileged hook process reads it. Events is
// what Fluent Bit tails; Spool and StateDB are private to the sensor. On
// macOS and Windows Config and Data are the same directory, so access has to
// be restricted on Events, Spool and StateDB individually.
type Dirs struct{ Config, Data, Events, Spool, Run, Socket, StateDB string }

// MaxSocketPath is the longest socket path that works on every supported OS:
// sockaddr_un holds 104 bytes on macOS and 108 on Linux and Windows,
// including the terminating NUL. Check Dirs.Socket against it before
// listening; a deep home directory can exceed it.
const MaxSocketPath = 103

// DefaultDirs returns the system-wide locations used by a root or
// administrator install.
func DefaultDirs() Dirs {
	return systemDirs(runtime.GOOS, programDataDir())
}

// UserDirs returns the per-user locations used when spoor runs without
// privilege. home selects the account; "" means the current user. The result
// depends on home alone (not on XDG or TMPDIR variables) because the daemon
// and the hook process, which inherits whatever environment the agent passes
// on, must agree on the socket path.
func UserDirs(home string) Dirs {
	if home == "" {
		home = CurrentUser().Home
	}
	if home == "" {
		// No passwd entry and no HOME (arbitrary-uid container). The caller
		// must create this 0700 and verify ownership: the name is guessable.
		return layout(runtime.GOOS, joinPath(runtime.GOOS, os.TempDir(), "spoor-"+firstNonEmpty(CurrentUser().UID, "user")), "")
	}
	return userDirs(runtime.GOOS, home, localAppDataDir(home))
}

func systemDirs(goos, programData string) Dirs {
	switch goos {
	case "darwin":
		// /var/run is the real directory; /run does not exist on macOS.
		return layout(goos, "/Library/Application Support/spoor", "/var/run/spoor")
	case "windows":
		if programData == "" {
			programData = `C:\ProgramData`
		}
		// AF_UNIX sockets work on Windows 10 1803 and later, as files.
		return layout(goos, joinPath(goos, programData, "spoor"), "")
	default:
		return Dirs{
			Config:  "/etc/spoor",
			Data:    "/var/lib/spoor",
			Events:  "/var/lib/spoor/events",
			Spool:   "/var/lib/spoor/spool",
			Run:     "/run/spoor",
			Socket:  "/run/spoor/hook.sock",
			StateDB: "/var/lib/spoor/state.db",
		}
	}
}

func userDirs(goos, home, localAppData string) Dirs {
	switch goos {
	case "darwin":
		return layout(goos, joinPath(goos, home, "Library", "Application Support", "spoor"), "")
	case "windows":
		if localAppData == "" {
			localAppData = joinPath(goos, home, "AppData", "Local")
		}
		return layout(goos, joinPath(goos, localAppData, "spoor"), "")
	default:
		return layout(goos, joinPath(goos, home, ".local", "state", "spoor"), "")
	}
}

// layout places everything under base; run overrides the runtime directory.
func layout(goos, base, run string) Dirs {
	if run == "" {
		run = joinPath(goos, base, "run")
	}
	return Dirs{
		Config:  base,
		Data:    base,
		Events:  joinPath(goos, base, "events"),
		Spool:   joinPath(goos, base, "spool"),
		Run:     run,
		Socket:  joinPath(goos, run, "hook.sock"),
		StateDB: joinPath(goos, base, "state.db"),
	}
}

// joinPath joins with the separator of goos rather than of the build host,
// so the layout of every OS can be computed (and tested) anywhere.
func joinPath(goos string, elem ...string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	var b strings.Builder
	for _, e := range elem {
		if e == "" {
			continue
		}
		if b.Len() > 0 {
			prev := b.String()
			e = strings.TrimLeft(e, `/\`)
			if !strings.HasSuffix(prev, "/") && !strings.HasSuffix(prev, `\`) {
				b.WriteString(sep)
			}
		}
		b.WriteString(e)
	}
	return b.String()
}
