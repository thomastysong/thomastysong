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

// execProblem reports why acc (nil: every account) cannot execute bin, or
// "": the file needs execute permission for it, and every directory on
// the way, along the path as written and along the path a symbolic link
// leads to, needs search permission. ACLs are not read.
func execProblem(bin string, acc *accessor) string {
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "not found"
	}
	who := "every account"
	if acc != nil {
		who = acc.name
	}
	can := func(fi os.FileInfo) bool {
		if acc != nil {
			return acc.may(fi, 1)
		}
		return fi.Mode().Perm()&0o001 != 0
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "not found"
	}
	if !can(fi) {
		return fmt.Sprintf("not executable by %s (%s)", who, modeOwner(fi))
	}
	for _, p := range []string{bin, real} {
		for d := filepath.Dir(p); ; d = filepath.Dir(d) {
			dfi, err := os.Stat(d)
			if err != nil {
				return "not found"
			}
			if !can(dfi) {
				return fmt.Sprintf("in %s, which %s cannot search (%s)", d, who, modeOwner(dfi))
			}
			if d == filepath.Dir(d) {
				break
			}
		}
	}
	return ""
}

func modeOwner(fi os.FileInfo) string {
	if uid, gid, ok := fileOwner(fi); ok {
		return fmt.Sprintf("mode %04o, owner uid %d, group gid %d", uint32(fi.Mode().Perm()), uid, gid)
	}
	return fmt.Sprintf("mode %04o", uint32(fi.Mode().Perm()))
}

// accessorForHome is the account a user-scope hook in home runs as: the
// owner of the home directory, else the account called name; nil when
// neither resolves (the caller then requires access for every account).
// An owner the account database does not list (os/user without cgo reads
// only /etc/passwd, which misses directory-service accounts on macOS) is
// still known by uid: its own files by owner bits, others by other bits;
// its groups are unknown, so group bits are not credited (this process's
// own groups are, when it is that account).
func accessorForHome(name, home string) *accessor {
	if fi, err := os.Stat(home); err == nil {
		if uid, _, ok := fileOwner(fi); ok {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				if a, err := lookupAccessor(u.Username); err == nil {
					return a
				}
			}
			a := &accessor{name: firstNonEmpty(name, "uid "+strconv.Itoa(uid)), uid: uid, groups: map[int]bool{}}
			if uid == os.Geteuid() {
				a.groups[os.Getegid()] = true
				if gs, err := os.Getgroups(); err == nil {
					for _, g := range gs {
						a.groups[g] = true
					}
				}
			}
			return a
		}
	}
	if name == "" {
		return nil
	}
	a, err := lookupAccessor(name)
	if err != nil {
		return nil
	}
	return a
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

// prepareDataDir creates the data directory, when it does not exist yet,
// with the mode the daemon gives it: traversable by everyone (0711), so
// that hooks reach their spool and read the bundle through it. A
// daemonless `scan --state` or `scan --outbox` (tier 2) is often the first
// thing to write there. An existing directory is left alone: the daemon
// owns it and doctor reports its mode.
func prepareDataDir(dataDir string) {
	if _, err := os.Lstat(dataDir); !errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(dataDir), 0o755); err != nil {
		return
	}
	if err := os.Mkdir(dataDir, 0o711); err == nil {
		_ = os.Chmod(dataDir, 0o711) // the umask narrowed Mkdir's mode
	}
}

// prepareOutbox creates the outbox for a daemonless `scan --outbox` with
// the daemon's mode and group, so that the shipper can read it: 2750 owned
// by output.group, whose setgid bit gives every new segment that group. An
// existing outbox is left alone (see prepareDataDir).
func prepareOutbox(outbox, group string) []string {
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
		return []string{fmt.Sprintf("output.group %q does not exist: the outbox is readable by its owner only", group)}
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil
	}
	if err := os.Chown(outbox, -1, gid); err != nil {
		return []string{fmt.Sprintf("cannot give the outbox to group %q: %v", group, err)}
	}
	return nil
}

// replaceKeepingACL is the Windows configuration-file replacement
// (perm_windows.go); POSIX keeps the mode and owner across a rename.
func replaceKeepingACL(path string, data []byte) error {
	return errors.New("replaceKeepingACL: Windows only")
}

// hooksCannotRead says why hooks, which run as the developer, could not
// read the configuration at path, or "": the file must be readable and
// its directory searchable by every account (the directories above it are
// the system's /etc or /Library, or a --root prefix).
func hooksCannotRead(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return err.Error()
	}
	if fi.Mode().Perm()&0o004 == 0 {
		return fmt.Sprintf("other accounts cannot read it (%s), so no hook would apply guard mode; make it readable first: chmod o+r '%s'", modeOwner(fi), path)
	}
	dir := filepath.Dir(path)
	if dfi, err := os.Stat(dir); err == nil && dfi.Mode().Perm()&0o001 == 0 {
		return fmt.Sprintf("other accounts cannot search %s (%s), so no hook would read the file; make it searchable first: chmod o+x '%s'", dir, modeOwner(dfi), dir)
	}
	return ""
}
