//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package discovery

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// unixOpener confines every open to a root directory. On Linux it uses
// openat2: RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS to reach a directory inside
// HostRoot (a symlink in a container resolves inside the container, never on
// the node) and RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS below a home or project
// root (a link may not climb out of the user's tree). Where openat2 is
// missing (other unix systems, kernels before 5.6, seccomp filters that
// reject it) it walks the path one component at a time with O_NOFOLLOW,
// which refuses every symlink below the root: stricter, never weaker.
type unixOpener struct {
	hostRoot string
	hostFD   int

	mu        sync.Mutex
	roots     map[string]int
	useOpenat atomic.Bool
}

const maxRootFDs = 128

func newOpener(hostRoot string) (opener, error) {
	o := &unixOpener{hostRoot: hostRoot, hostFD: -1, roots: map[string]int{}}
	o.useOpenat.Store(openat2Supported)
	if hostRoot != "" {
		fd, err := retryEINTR(func() (int, error) {
			return unix.Open(hostRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		})
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: hostRoot, Err: err}
		}
		o.hostFD = fd
	}
	return o, nil
}

func (o *unixOpener) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, fd := range o.roots {
		unix.Close(fd)
		delete(o.roots, k)
	}
	if o.hostFD >= 0 {
		unix.Close(o.hostFD)
		o.hostFD = -1
	}
}

func retryEINTR(f func() (int, error)) (int, error) {
	for {
		fd, err := f()
		if err != unix.EINTR {
			return fd, err
		}
	}
}

// rootFD returns a cached descriptor for a confinement root. The caller
// must not close it.
func (o *unixOpener) rootFD(root string) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if fd, ok := o.roots[root]; ok {
		return fd, nil
	}
	if len(o.roots) >= maxRootFDs {
		for k, fd := range o.roots {
			unix.Close(fd)
			delete(o.roots, k)
		}
	}
	var fd int
	var err error
	if o.hostFD < 0 {
		fd, err = retryEINTR(func() (int, error) {
			return unix.Open(root, dirOpenFlags|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		})
	} else {
		rel := strings.TrimPrefix(cleanLogical(root), "/")
		if rel == "" {
			fd, err = retryEINTR(func() (int, error) {
				return unix.Openat(o.hostFD, ".", dirOpenFlags|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			})
		} else {
			fd, err = o.resolve(o.hostFD, rel, dirOpenFlags|unix.O_DIRECTORY, true)
		}
	}
	if err != nil {
		return -1, mapErr("open", root, err)
	}
	o.roots[root] = fd
	return fd, nil
}

// resolve opens rel below dirfd. inRoot selects RESOLVE_IN_ROOT (container
// root: absolute links are re-rooted, the final component may be a link)
// instead of RESOLVE_BENEATH with O_NOFOLLOW on the final component.
func (o *unixOpener) resolve(dirfd int, rel string, flags int, inRoot bool) (int, error) {
	if !inRoot {
		flags |= unix.O_NOFOLLOW
	}
	flags |= unix.O_CLOEXEC
	if o.useOpenat.Load() {
		fd, err, ok := openat2(dirfd, rel, flags, inRoot)
		if ok {
			return fd, err
		}
		// The kernel or a seccomp filter refused the call itself; the
		// component walk is stricter, so falling back never weakens.
		o.useOpenat.Store(false)
	}
	return walkNoFollow(dirfd, rel, flags)
}

// walkNoFollow opens rel one component at a time, refusing any symlink.
func walkNoFollow(dirfd int, rel string, flags int) (int, error) {
	comps := strings.Split(rel, "/")
	cur := dirfd
	closeCur := func() {
		if cur != dirfd {
			unix.Close(cur)
		}
	}
	for i, c := range comps {
		last := i == len(comps)-1
		f := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			f = flags | unix.O_NOFOLLOW
		}
		nfd, err := retryEINTR(func() (int, error) { return unix.Openat(cur, c, f, 0) })
		if err != nil {
			if err == unix.ENOTDIR || err == unix.ELOOP || err == unix.EMLINK {
				var st unix.Stat_t
				if unix.Fstatat(cur, c, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
					err = unix.ELOOP
				}
			}
			closeCur()
			return -1, err
		}
		closeCur()
		cur = nfd
	}
	return cur, nil
}

func (o *unixOpener) beneath(root, rel string, flags int) (int, error) {
	rfd, err := o.rootFD(root)
	if err != nil {
		return -1, err
	}
	fd, err := o.resolve(rfd, rel, flags, false)
	if err != nil {
		return -1, mapErr("open", joinLogical(root, rel), err)
	}
	return fd, nil
}

func (o *unixOpener) openFile(root, rel string) (*os.File, error) {
	fd, err := o.beneath(root, rel, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, mapErr("fstat", joinLogical(root, rel), err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: joinLogical(root, rel), Err: errNotReg}
	}
	// O_NONBLOCK kept a FIFO from hanging the open; a regular file never
	// blocks, so the descriptor goes back to ordinary blocking mode.
	_ = unix.SetNonblock(fd, false)
	return os.NewFile(uintptr(fd), realPath(o.hostRoot, joinLogical(root, rel))), nil
}

func (o *unixOpener) openDir(root, rel string) (*os.File, error) {
	var fd int
	var err error
	if rel == "" {
		rfd, rerr := o.rootFD(root)
		if rerr != nil {
			return nil, rerr
		}
		fd, err = retryEINTR(func() (int, error) {
			return unix.Openat(rfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		})
		if err != nil {
			return nil, mapErr("open", root, err)
		}
	} else {
		fd, err = o.beneath(root, rel, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
	}
	return os.NewFile(uintptr(fd), realPath(o.hostRoot, joinLogical(root, rel))), nil
}

// parent opens the directory holding rel; close reports whether the caller
// must close the returned descriptor.
func (o *unixOpener) parent(root, rel string) (fd int, base string, closeIt bool, err error) {
	dir, base := path.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		fd, err = o.rootFD(root)
		return fd, base, false, err
	}
	fd, err = o.beneath(root, dir, dirOpenFlags|unix.O_DIRECTORY)
	return fd, base, true, err
}

func (o *unixOpener) lstat(root, rel string) (fmeta, error) {
	var st unix.Stat_t
	if rel == "" {
		rfd, err := o.rootFD(root)
		if err != nil {
			return fmeta{}, err
		}
		if err := unix.Fstat(rfd, &st); err != nil {
			return fmeta{}, mapErr("fstat", root, err)
		}
		return metaOfStat(&st), nil
	}
	pfd, base, closeIt, err := o.parent(root, rel)
	if err != nil {
		return fmeta{}, err
	}
	if closeIt {
		defer unix.Close(pfd)
	}
	if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmeta{}, mapErr("lstat", joinLogical(root, rel), err)
	}
	return metaOfStat(&st), nil
}

func (o *unixOpener) readlink(root, rel string) (string, error) {
	pfd, base, closeIt, err := o.parent(root, rel)
	if err != nil {
		return "", err
	}
	if closeIt {
		defer unix.Close(pfd)
	}
	buf := make([]byte, 4097)
	n, err := unix.Readlinkat(pfd, base, buf)
	if err != nil {
		return "", mapErr("readlink", joinLogical(root, rel), err)
	}
	if n > 4096 {
		return "", errBadPath
	}
	return string(buf[:n]), nil
}

// mapErr turns errno values into the gate's refusal classes while keeping
// errors.Is(err, fs.ErrNotExist / fs.ErrPermission) working.
func mapErr(op, p string, err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return err
	}
	switch err {
	case unix.ELOOP, unix.EMLINK:
		err = errSymlink
	case unix.EXDEV:
		err = errEscape
	case unix.ENOTDIR:
		err = errNotDir
	}
	return &os.PathError{Op: op, Path: p, Err: err}
}

func metaOfStat(st *unix.Stat_t) fmeta {
	m := fmeta{
		size:     st.Size,
		perm:     os.FileMode(st.Mode & 0o7777),
		owner:    strconv.FormatUint(uint64(st.Uid), 10),
		hasOwner: true,
		nlink:    uint64(st.Nlink),
		mtime:    timespecTime(st),
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		m.kind = kindRegular
	case unix.S_IFDIR:
		m.kind = kindDir
	case unix.S_IFLNK:
		m.kind = kindSymlink
	default:
		m.kind = kindOther
	}
	return m
}

func metaOf(fi os.FileInfo) fmeta {
	m := fmeta{kind: kindOfMode(fi.Mode().Type()), size: fi.Size(), perm: fi.Mode().Perm(), mtime: fi.ModTime()}
	if fi.Mode().IsRegular() {
		m.kind = kindRegular
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		m.owner = strconv.FormatUint(uint64(st.Uid), 10)
		m.hasOwner = true
		m.nlink = uint64(st.Nlink)
	}
	return m
}
