//go:build unix

package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func currentUID() string { return strconv.Itoa(os.Geteuid()) }

// lookupGroup resolves a group name through os/user. The release builds set
// CGO_ENABLED=0 (Makefile, .goreleaser.yaml, Dockerfile), which selects a
// different resolver per system (Go 1.26 source, os/user build
// constraints):
//
//   - Linux and the other Unix systems: the pure-Go reader of /etc/group
//     (os/user/lookup_unix.go, "(!cgo && !darwin) || osusergo"). A group
//     that exists only in LDAP, SSSD or NIS is not found, and the outbox
//     then stays readable by root only.
//   - macOS: libSystem's getgrnam_r, called without cgo
//     (os/user/cgo_lookup_syscall.go, "!osusergo && darwin"), the system's
//     own lookup, which consults Open Directory (as lookupUID in
//     internal/platform/users_darwin.go relies on). Not run on a Mac.
//
// A build with cgo (a plain `go install` or `go build` on a Linux host with
// a C compiler, where Go enables cgo by default) uses libc's getgrnam_r
// instead (os/user/cgo_lookup_cgo.go, "cgo && !osusergo && unix && !android
// && !darwin"), which follows nsswitch.conf and so can find LDAP and SSSD
// groups (not tested). No build sets the osusergo tag, which would select
// the /etc/group reader everywhere.
func lookupGroup(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil || gid < 0 {
		return -1, false
	}
	return gid, true
}

// primaryGID returns an account's primary group, or -1 (leave the group).
func primaryGID(uid string) int {
	u, err := user.LookupId(uid)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil || gid < 0 {
		return -1
	}
	return gid
}

// secureDataDir makes the data directory exist, traversable by everyone
// (hooks reach their spool and read the bundle through it) and writable by
// the sensor only. A symbolic link in its place is a deliberate relocation by
// root (only root can create entries in /var/lib) and is followed, but its
// target is checked, not changed: the daemon did not make it.
func secureDataDir(path string, privileged bool) error {
	fi, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o711); err != nil {
			return err
		}
		created = true
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Stat(path)
		if err != nil || !t.IsDir() {
			return errSymlinkDir
		}
		if privileged {
			if st, ok := t.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
				return fmt.Errorf("link target is owned by uid %d, not by the sensor", st.Uid)
			}
			if t.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("link target is group- or world-writable (mode %04o)", t.Mode().Perm())
			}
		}
		return nil
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	want := fi.Mode().Perm()&^0o022 | 0o111
	if created {
		want = 0o711
	}
	return fixDir(path, fi, want, os.Geteuid(), -1, privileged)
}

// secureDir creates or repairs one directory of the layout. ownerUID is the
// account that owns it ("" = the sensor); gid is the group (-1 = leave).
func secureDir(path string, kind dirKind, privileged bool, ownerUID string, gid int) error {
	mode, ok := unixModes[kind]
	if !ok {
		return fmt.Errorf("unknown directory kind %d", kind)
	}
	uid := os.Geteuid()
	if ownerUID != "" {
		n, err := strconv.Atoi(ownerUID)
		if err != nil || n < 0 {
			return fmt.Errorf("account id %q is not numeric", ownerUID)
		}
		uid = n
		gid = primaryGID(ownerUID)
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode.Perm()); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errSymlinkDir
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	return fixDir(path, fi, mode, uid, gid, privileged)
}

// fixDir sets owner, group and mode. The owner first: changing it can clear
// the set-group-id bit on some systems.
func fixDir(path string, fi os.FileInfo, mode os.FileMode, uid, gid int, privileged bool) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && privileged {
		wantGID := gid
		if wantGID < 0 {
			wantGID = int(st.Gid)
		}
		if int(st.Uid) != uid || int(st.Gid) != wantGID {
			if err := os.Lchown(path, uid, wantGID); err != nil {
				return fmt.Errorf("chown: %w", err)
			}
		}
	}
	cur := fi.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
	if cur != mode || privileged {
		// Re-applied even when it looks right after a chown, which may
		// have dropped the set-group-id bit.
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}
	return nil
}

// secureSegmentFile gives an outbox segment mode 0640 and the outbox group.
func secureSegmentFile(path string, privileged bool, gid int) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil // only regular files are segments; the sink refuses the rest
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && privileged && gid >= 0 && int(st.Gid) != gid {
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
	}
	if fi.Mode().Perm() != 0o640 {
		return os.Chmod(path, 0o640)
	}
	return nil
}
