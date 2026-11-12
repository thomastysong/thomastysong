//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// fileOwner returns the numeric owner of fi.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func lookupUID(name string) string {
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.Uid
}

// permsChecked says whether mode bits mean anything on this OS.
const permsChecked = true

// accessor is an account as the kernel checks file access: uid and every
// group it belongs to.
type accessor struct {
	name   string
	uid    int
	groups map[int]bool
}

func lookupAccessor(name string) (*accessor, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("user %s: uid %q", name, u.Uid)
	}
	a := &accessor{name: name, uid: uid, groups: map[int]bool{}}
	if g, err := strconv.Atoi(u.Gid); err == nil {
		a.groups[g] = true
	}
	gids, _ := u.GroupIds()
	for _, s := range gids {
		if g, err := strconv.Atoi(s); err == nil {
			a.groups[g] = true
		}
	}
	return a, nil
}

// may reports whether the account has the permission bits want (4 read,
// 2 write, 1 execute/search) on fi, by owner, group and other classes as
// the kernel evaluates them (ACLs and capabilities are not considered).
func (a *accessor) may(fi os.FileInfo, want os.FileMode) bool {
	if a.uid == 0 {
		return true
	}
	uid, gid, ok := fileOwner(fi)
	if !ok {
		return false
	}
	perm := fi.Mode().Perm()
	switch {
	case uid == a.uid:
		return (perm>>6)&want == want
	case a.groups[gid]:
		return (perm>>3)&want == want
	}
	return perm&want == want
}

// canRead checks that the account can reach dir (search permission on
// every ancestor), list it, and read the given files in it.
func (a *accessor) canRead(dir string, files []string) (bool, string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false, err.Error()
	}
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return false, err.Error()
		}
		if !a.may(fi, 1) {
			return false, fmt.Sprintf("%s cannot traverse %s (mode %s)", a.name, p, fi.Mode().Perm())
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return false, err.Error()
	}
	if !a.may(fi, 5) {
		return false, fmt.Sprintf("%s cannot list %s (mode %s)", a.name, abs, fi.Mode().Perm())
	}
	for _, f := range files {
		ffi, err := os.Lstat(filepath.Join(abs, f))
		if err != nil {
			continue
		}
		if !a.may(ffi, 4) {
			return false, fmt.Sprintf("%s cannot read %s (mode %s)", a.name, f, ffi.Mode().Perm())
		}
	}
	return true, ""
}

// rewriteFlags are added when purge opens a spool file for writing: a FIFO
// planted where a spool file belongs must not block the open, and a tty must
// not become the controlling terminal.
const rewriteFlags = syscall.O_NONBLOCK | syscall.O_NOCTTY

// linkCount is the number of names of the file fi describes.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// prepareOutbox creates what a daemonless `scan --outbox` (tier 2) writes
// into with the modes the daemon gives them, so that the shipper can read
// it: the data directory traversable by everyone (0711, hooks reach their
// spool through it) and the outbox 2750 owned by output.group, whose setgid
// bit gives every new segment that group. Directories that exist are left
// as they are: the daemon owns them and doctor reports their modes.
func prepareOutbox(dataDir, outbox, group string) []string {
	var notes []string
	if _, err := os.Lstat(dataDir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dataDir), 0o755); err == nil {
			if err := os.Mkdir(dataDir, 0o711); err == nil {
				_ = os.Chmod(dataDir, 0o711) // the umask narrowed Mkdir's mode
			}
		}
	}
	if _, err := os.Lstat(outbox); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := os.Mkdir(outbox, 0o750); err != nil {
		return nil // the sink reports why it cannot create it
	}
	_ = os.Chmod(outbox, 0o750|os.ModeSetgid)
	if group == "" {
		return nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return append(notes, fmt.Sprintf("output.group %q does not exist: the outbox is readable by its owner only", group))
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return notes
	}
	if err := os.Chown(outbox, -1, gid); err != nil {
		notes = append(notes, fmt.Sprintf("cannot give the outbox to group %q: %v", group, err))
	}
	return notes
}
