//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// statLazy is true on platforms where path-based metadata can lag behind a
// file that is still open for writing.
const statLazy = false

func metaFromStat(st *unix.Stat_t) fileMeta {
	typ := uint32(st.Mode) & unix.S_IFMT
	return fileMeta{
		size:    int64(st.Size),
		mtime:   st.Mtim.Nano(),
		id:      strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10),
		owner:   strconv.FormatUint(uint64(st.Uid), 10),
		regular: typ == unix.S_IFREG,
		symlink: typ == unix.S_IFLNK,
		dir:     typ == unix.S_IFDIR,
	}
}

// lstatMeta describes path without following a final symlink.
func lstatMeta(path string) (fileMeta, error) {
	var st unix.Stat_t
	for {
		err := unix.Lstat(path, &st)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fileMeta{}, &os.PathError{Op: "lstat", Path: path, Err: err}
		}
		return metaFromStat(&st), nil
	}
}

func openRetry(open func() (int, error)) (int, error) {
	for {
		fd, err := open()
		if err != unix.EINTR {
			return fd, err
		}
	}
}

// openBeneath opens base/rel for reading without following a symlink in any
// component of rel, walking it with openat so a directory swapped for a link
// between discovery and open cannot redirect the read. base itself is the
// operator-chosen root and is resolved normally. O_NONBLOCK keeps a FIFO
// planted at a transcript path from blocking the daemon; the fstat that
// follows rejects it. rel "" opens base itself as the file.
func openBeneath(base, rel string) (*os.File, fileMeta, error) {
	const dirFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW
	const fileFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
	full := base
	if rel != "" {
		full = filepath.Join(base, rel)
	}
	fail := func(at string, err error) (*os.File, fileMeta, error) {
		// The errno for "that was a symlink" differs by kernel (ELOOP,
		// EMLINK, EFTYPE, ENOTDIR with O_DIRECTORY); ask what is there.
		if !errors.Is(err, unix.ENOENT) {
			if m, lerr := lstatMeta(at); lerr == nil && m.symlink {
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errSymlink}
			}
		}
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: err}
	}

	var fd int
	var err error
	if rel == "" {
		fd, err = openRetry(func() (int, error) { return unix.Open(base, fileFlags, 0) })
		if err != nil {
			return fail(base, err)
		}
	} else {
		dirfd, derr := openRetry(func() (int, error) {
			return unix.Open(base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		})
		if derr != nil {
			return fail(base, derr)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		at := base
		for _, part := range parts[:len(parts)-1] {
			if part == "" || part == "." {
				continue
			}
			at = filepath.Join(at, part)
			if part == ".." {
				unix.Close(dirfd)
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errors.New("path escapes its root")}
			}
			next, nerr := openRetry(func() (int, error) { return unix.Openat(dirfd, part, dirFlags, 0) })
			unix.Close(dirfd)
			if nerr != nil {
				return fail(at, nerr)
			}
			dirfd = next
		}
		name := parts[len(parts)-1]
		if name == "" || name == "." || name == ".." {
			unix.Close(dirfd)
			return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errNotRegular}
		}
		fd, err = openRetry(func() (int, error) { return unix.Openat(dirfd, name, fileFlags, 0) })
		unix.Close(dirfd)
		if err != nil {
			return fail(full, err)
		}
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fileMeta{}, &os.PathError{Op: "fstat", Path: full, Err: err}
	}
	m := metaFromStat(&st)
	if !m.regular {
		unix.Close(fd)
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errNotRegular}
	}
	return os.NewFile(uintptr(fd), full), m, nil
}

// ownerOK reports whether the file's owner is the expected account. An empty
// expectation means the caller did not ask for the check.
func ownerOK(m fileMeta, want string) bool {
	return want == "" || m.owner == want
}
