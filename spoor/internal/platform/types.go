package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// UserHome is one OS account with a home directory on this machine.
// UID is the numeric uid on POSIX and the SID string on Windows.
type UserHome struct{ Name, UID, Home string }

// Proc is one row of the process table. Fields the caller may not read, or
// that the OS does not have, are left empty.
type Proc struct {
	PID, PPID int
	Name, Exe string
	Args      []string
	Start     time.Time
	UID, User string
}

// ErrUnsupported is returned when the running OS has no way to answer.
var ErrUnsupported = errors.New("unsupported on this platform")

// ErrNotRegular is returned by the safe open helpers for anything that is not
// a regular file (directories, FIFOs, sockets, devices).
var ErrNotRegular = errors.New("not a regular file")

// ErrSymlink is returned by the safe open helpers when the path is a symbolic
// link (or, on Windows, any reparse point).
var ErrSymlink = errors.New("refusing to follow a symbolic link")

// Bounds on attacker-influenced input. A process can make its command line
// and environment as large as the kernel allows, and a hostile tree can hold
// any number of entries, so every reader stops at one of these.
const (
	maxCmdlineBytes = 256 << 10
	maxEnvBytes     = 1 << 20
	maxArgs         = 4096
	maxEnvVars      = 8192
	maxProcs        = 1 << 20
	maxHomeEntries  = 1 << 16
	maxSmallFile    = 64 << 10
)

// guard converts a panic into an error at the package boundary: the sensor
// must survive whatever a hostile process table or file tree throws at it.
func guard(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("platform: internal error: %v", r)
	}
}

// readFileLimit reads at most max bytes. procfs and sysfs files report size
// zero, so the size cannot be trusted and the read itself must be capped.
func readFileLimit(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// cstring returns the bytes before the first NUL.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
