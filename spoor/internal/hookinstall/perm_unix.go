//go:build unix

package hookinstall

import (
	"fmt"
	"os"
	"syscall"
)

// trustedUID is a second uid, besides root, that may own managed files.
// It exists for tests that run unprivileged; production leaves it at 0.
var trustedUID = 0

func ownerIDs(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// writableByOthers explains why a managed file or directory can be changed
// by a non-admin, or returns "".
func writableByOthers(path string, fi os.FileInfo) string {
	if fi.Mode()&os.ModeSymlink != 0 {
		return "is a symbolic link"
	}
	if uid, _, ok := ownerIDs(fi); ok && uid != 0 && uid != trustedUID {
		return fmt.Sprintf("is owned by uid %d, not root", uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("is group- or world-writable (mode %04o)", fi.Mode().Perm())
	}
	return ""
}

// hardenIn makes name (a file or directory in r, or "." for the directory
// itself) root-owned and not writable by group or others. Ownership can
// only be repaired by root; an unprivileged caller gets the mode fixed and
// Status reports the rest. dir only matters on Windows, where files and
// directories get different access lists.
func hardenIn(r *os.Root, name string, dir bool) error {
	fi, err := r.Lstat(name)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", name)
	}
	if uid, _, ok := ownerIDs(fi); ok && uid != 0 && os.Geteuid() == 0 {
		if err := r.Lchown(name, 0, -1); err != nil {
			return err
		}
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return r.Chmod(name, perm&^0o022)
	}
	return nil
}

// linkTrusted reports whether a symbolic link found on the way to a target
// directory may be followed: links made by root are system layout (/etc on
// macOS, /home on some distributions); an unprivileged caller may also
// follow its own. A link made by the monitored user must never steer a
// privileged write.
func linkTrusted(path string, fi os.FileInfo) bool {
	uid, _, ok := ownerIDs(fi)
	if !ok {
		return false
	}
	if uid == 0 {
		return true
	}
	euid := os.Geteuid()
	return euid != 0 && uid == euid
}

// giveTo hands a file or directory that root just created inside another
// user's directory to that user, so the agent can keep editing its own
// settings.
func giveTo(r *os.Root, name string, uid, gid int) error {
	if os.Geteuid() != 0 || uid == 0 {
		return nil
	}
	return r.Lchown(name, uid, gid)
}
