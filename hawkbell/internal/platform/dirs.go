package platform

import (
	"os"
	"runtime"
	"strings"
)

// Dirs is the set of paths one hawkbell installation uses.
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

// UserDirs returns the per-user locations used when hawkbell runs without
// privilege. home selects the account; "" means the current user. The result
// depends on home alone (not on XDG or TMPDIR variables) because the daemon
// and the hook process, which inherits whatever environment the agent passes
// on, must agree on the socket path.
func UserDirs(home string) Dirs {
	if home == "" {
		home = currentHome()
	}
	if home == "" {
		// No passwd entry and no HOME (arbitrary-uid container). The caller
		// must create this 0700 and verify ownership: the name is guessable.
		return layout(runtime.GOOS, joinPath(runtime.GOOS, os.TempDir(), "hawkbell-"+firstNonEmpty(CurrentUser().UID, "user")), "")
	}
	return userDirs(runtime.GOOS, home)
}

func systemDirs(goos, programData string) Dirs {
	switch goos {
	case "darwin":
		// /var/run is the real directory; /run does not exist on macOS.
		return layout(goos, "/Library/Application Support/hawkbell", "/var/run/hawkbell")
	case "windows":
		if programData == "" {
			programData = `C:\ProgramData`
		}
		// AF_UNIX sockets work on Windows 10 1803 and later, as files.
		return layout(goos, joinPath(goos, programData, "hawkbell"), "")
	default:
		return Dirs{
			Config:  "/etc/hawkbell",
			Data:    "/var/lib/hawkbell",
			Events:  "/var/lib/hawkbell/events",
			Spool:   "/var/lib/hawkbell/spool",
			Run:     "/run/hawkbell",
			Socket:  "/run/hawkbell/hook.sock",
			StateDB: "/var/lib/hawkbell/state.db",
		}
	}
}

func userDirs(goos, home string) Dirs {
	switch goos {
	case "darwin":
		return layout(goos, joinPath(goos, home, "Library", "Application Support", "hawkbell"), "")
	case "windows":
		// The default location of %LOCALAPPDATA%. The variable itself is not
		// consulted (see UserDirs), and asking the shell would load shell32
		// into the hook process on every tool call.
		return layout(goos, joinPath(goos, home, "AppData", "Local", "hawkbell"), "")
	default:
		return layout(goos, joinPath(goos, home, ".local", "state", "hawkbell"), "")
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

// expandSystemDrive resolves a registry path such as
// "%SystemDrive%\ProgramData" using a drive obtained from the system, not
// from the environment. It returns "" when the value uses any other
// variable.
func expandSystemDrive(value, drive string) string {
	const name = "%systemdrive%"
	var out strings.Builder
	for {
		// Matched on the original bytes: lower-casing the whole string first
		// can change its length and misplace the cut.
		i := -1
		for j := 0; j+len(name) <= len(value); j++ {
			if strings.EqualFold(value[j:j+len(name)], name) {
				i = j
				break
			}
		}
		literal := value
		if i >= 0 {
			literal = value[:i]
		}
		if strings.Contains(literal, "%") {
			return ""
		}
		out.WriteString(literal)
		if i < 0 {
			return out.String()
		}
		if drive == "" {
			return ""
		}
		// The drive is appended, never rescanned, so it cannot recurse.
		out.WriteString(drive)
		value = value[i+len(name):]
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
