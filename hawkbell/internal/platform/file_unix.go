//go:build linux || darwin

package platform

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// openNonblock keeps open(2) from blocking forever on a FIFO a user planted
// where a config file was expected.
const openNonblock = syscall.O_NONBLOCK

// OpenNoFollow opens path for reading. It fails with ErrSymlink when the
// final component is a symbolic link and with ErrNotRegular for anything but
// a regular file. Intermediate components are resolved normally; see
// OpenBeneath for whole-path containment.
func OpenNoFollow(path string) (*os.File, error) {
	var fd int
	var err error
	for {
		// O_NONBLOCK: a FIFO would otherwise block until a writer shows up,
		// and a tty would become our controlling terminal without O_NOCTTY.
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		// With O_NOFOLLOW the kernel reports a final-component symlink as
		// ELOOP (EMLINK on some BSDs).
		if err == unix.ELOOP || err == unix.EMLINK {
			return nil, &os.PathError{Op: "open", Path: path, Err: ErrSymlink}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	// A regular file never blocks; clear the flag so the runtime treats the
	// descriptor as an ordinary blocking file.
	_ = unix.SetNonblock(fd, false)
	return os.NewFile(uintptr(fd), path), nil
}

// FileID returns "device:inode" for fi, which identifies a file across
// renames. When fi carries no system data (a synthetic FileInfo) the path is
// examined instead, without following a final symlink. It returns "" when
// neither yields an identity.
func FileID(fi os.FileInfo, path string) string {
	if fi != nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
			return statID(uint64(st.Dev), uint64(st.Ino))
		}
	}
	if path == "" {
		return ""
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return ""
	}
	return statID(uint64(st.Dev), uint64(st.Ino))
}

func statID(dev, ino uint64) string {
	return strconv.FormatUint(dev, 10) + ":" + strconv.FormatUint(ino, 10)
}

func fileIDOfHandle(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	id := FileID(fi, "")
	if id == "" {
		return "", fmt.Errorf("no inode information: %w", ErrUnsupported)
	}
	return id, nil
}

// OwnerUID returns the uid that owns the file described by fi.
func OwnerUID(fi os.FileInfo) (string, bool) {
	if fi == nil {
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Uid), 10), true
}

// PathOwner returns the uid that owns path, without following a final
// symlink.
func PathOwner(path string) (string, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Uid), 10), true
}

// hostIDFileTrusted decides whether an override file may set the host id.
// The system file must belong to root; the per-user file to the caller. In
// both cases nobody else may be able to rewrite it.
func hostIDFileTrusted(fi os.FileInfo, system bool) bool {
	if fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return false
	}
	if st.Uid == 0 {
		return true
	}
	return !system && int(st.Uid) == os.Geteuid()
}

// TrustedPath reports whether only root, or the account this process runs
// as, can change what the absolute path names. The path must name a
// regular file. That file, and every directory the kernel looks a name up
// in to reach it (through every symbolic link), must be owned by uid 0 or
// by the effective uid, and none of them may be writable by group or
// others. A sticky world-writable directory such as /tmp does not pass.
// Its owners-only rule covers renaming and removing names, not adding
// them, and on macOS (no protected_hardlinks) anyone may add a hard link
// there to a root-owned file. POSIX ACLs on Linux show in the group
// permission bits and are covered. macOS extended ACLs are not examined
// (UNVERIFIED on macOS: compiled, not executed in the build environment).
func TrustedPath(p string) bool {
	euid := os.Geteuid()
	return walkTrusted(p, os.Lstat, os.Readlink, func(_ string, fi os.FileInfo) bool {
		return safelyOwned(fi, euid)
	})
}

// safelyOwned: owned by root or euid, and not writable by group or others.
func safelyOwned(fi os.FileInfo, euid int) bool {
	if fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return false
	}
	return st.Uid == 0 || int(st.Uid) == euid
}
