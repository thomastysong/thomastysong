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

// hardenIn makes name (a file or directory in r) root-owned and not
// writable by group or others. Ownership can only be repaired by root; an
// unprivileged caller gets the mode fixed and Status reports the rest. The
// change is made on a descriptor opened without following a link and
// checked against what lstat saw, never by name: the directory may have
// belonged to a standard user a moment ago, and a name can be swapped for a
// link (symbolic or hard) to any other file between two calls. A file with
// more than one hard link is refused for the same reason.
func hardenIn(r *os.Root, name string, dir bool) error {
	f, fi, err := openEntry(r, name, dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if !dir && linkCount(fi) > 1 {
		return fmt.Errorf("%s has more than one hard link", name)
	}
	if uid, _, ok := ownerIDs(fi); ok && uid != 0 && os.Geteuid() == 0 {
		if err := f.Chown(0, -1); err != nil {
			return err
		}
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return f.Chmod(perm &^ 0o022)
	}
	return nil
}

// openEntry opens name in r, a directory when dir is set and a regular
// file otherwise, and checks that the descriptor is what lstat saw (os.Root
// follows a link inside the root, so a link swapped in after the lstat
// shows up as a different file).
func openEntry(r *os.Root, name string, dir bool) (*os.File, os.FileInfo, error) {
	li, err := r.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		return nil, nil, fmt.Errorf("%w: %s", ErrSymlink, name)
	case dir && !li.IsDir():
		return nil, nil, fmt.Errorf("%s: %w", name, errNotDir)
	case !dir && !li.Mode().IsRegular():
		return nil, nil, fmt.Errorf("%s is not a regular file", name)
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if dir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := r.OpenFile(name, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened", name)
	}
	return f, fi, nil
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

// linkCount is the number of hard links to a file, or 1 when unknown.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		return uint64(st.Nlink)
	}
	return 1
}

// chownFile hands a file that root just created inside another user's
// directory to that user, so the agent can keep editing its own settings.
// It works on the open descriptor: a name in that directory is the user's
// to swap.
func chownFile(f *os.File, uid, gid int) error {
	if os.Geteuid() != 0 || uid == 0 {
		return nil
	}
	return f.Chown(uid, gid)
}

// fixNewDir sets mode 0755 on a directory just created in r, whatever the
// umask, and hands it to uid:gid when give is set, through a descriptor.
func fixNewDir(r *os.Root, name string, uid, gid int, give bool) error {
	f, _, err := openEntry(r, name, true)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o755); err != nil {
		return err
	}
	if give {
		return chownFile(f, uid, gid)
	}
	return nil
}
