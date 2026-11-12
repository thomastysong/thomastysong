//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package discovery

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
)

// rootOpener confines opens with os.Root, which refuses any path (".." or a
// link) that leaves the root. The final component is checked with Lstat
// first and compared with the opened file, so a link there is refused rather
// than followed. On Windows regular files are then opened with
// FILE_SHARE_DELETE (see openShared) so an agent's own rename or delete of
// the file never fails because the scanner is reading it. Windows ACL
// ownership is not checked (fmeta.hasOwner is false), see the package
// documentation.
//
// UNVERIFIED: compiled for windows/amd64 and windows/arm64, not executed.
type rootOpener struct {
	hostRoot string

	mu    sync.Mutex
	roots map[string]*os.Root
	final map[string]string // root -> its final path (Windows share-delete opens)
}

func newOpener(hostRoot string) (opener, error) {
	if hostRoot != "" {
		fi, err := os.Stat(hostRoot)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, &os.PathError{Op: "open", Path: hostRoot, Err: errNotDir}
		}
	}
	return &rootOpener{hostRoot: hostRoot, roots: map[string]*os.Root{}, final: map[string]string{}}, nil
}

func (o *rootOpener) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, r := range o.roots {
		r.Close()
		delete(o.roots, k)
	}
}

func (o *rootOpener) rootOf(root string) (*os.Root, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r, ok := o.roots[root]; ok {
		return r, nil
	}
	if len(o.roots) >= 128 {
		for k, r := range o.roots {
			r.Close()
			delete(o.roots, k)
		}
	}
	var r *os.Root
	var err error
	if o.hostRoot == "" {
		r, err = os.OpenRoot(fromLogical(root))
	} else {
		var hr *os.Root
		hr, err = os.OpenRoot(o.hostRoot)
		if err == nil {
			rel := strings.TrimPrefix(cleanLogical(root), "/")
			if rel == "" {
				r = hr
			} else {
				r, err = hr.OpenRoot(fromLogical(rel))
				hr.Close()
			}
		}
	}
	if err != nil {
		return nil, mapRootErr(err)
	}
	o.roots[root] = r
	return r, nil
}

func fromLogical(p string) string { return strings.ReplaceAll(p, "/", string(os.PathSeparator)) }

func (o *rootOpener) check(r *os.Root, rel string, wantDir bool) (os.FileInfo, error) {
	if strings.Contains(rel, ":") {
		// On Windows "name:stream" opens an alternate data stream and "C:"
		// a drive: neither is a file below the root.
		return nil, errBadPath
	}
	li, err := r.Lstat(fromLogical(rel))
	if err != nil {
		return nil, mapRootErr(err)
	}
	if li.Mode()&fs.ModeSymlink != 0 || li.Mode()&fs.ModeIrregular != 0 {
		// ModeIrregular is how Go reports a reparse point that is not a
		// plain symlink (junctions, cloud placeholders) on Windows.
		return nil, errSymlink
	}
	if wantDir && !li.IsDir() {
		return nil, errNotDir
	}
	if !wantDir && !li.Mode().IsRegular() {
		return nil, errNotReg
	}
	return li, nil
}

func (o *rootOpener) openFile(root, rel string) (*os.File, error) {
	r, err := o.rootOf(root)
	if err != nil {
		return nil, err
	}
	li, err := o.check(r, rel, false)
	if err != nil {
		return nil, err
	}
	if f, handled, err := o.openShared(root, rel, li); handled {
		return f, err
	}
	f, err := r.Open(fromLogical(rel))
	if err != nil {
		return nil, mapRootErr(err)
	}
	fi, err := f.Stat()
	// The entry was a regular file at Lstat time; a different size or
	// mtime now means it was swapped (possibly for a link) in between.
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != li.Size() || !fi.ModTime().Equal(li.ModTime()) {
		f.Close()
		return nil, errSymlink
	}
	return f, nil
}

func (o *rootOpener) openDir(root, rel string) (*os.File, error) {
	r, err := o.rootOf(root)
	if err != nil {
		return nil, err
	}
	if rel == "" {
		f, err := r.Open(".")
		return f, mapRootErr(err)
	}
	if _, err := o.check(r, rel, true); err != nil {
		return nil, err
	}
	f, err := r.Open(fromLogical(rel))
	return f, mapRootErr(err)
}

func (o *rootOpener) lstat(root, rel string) (fmeta, error) {
	r, err := o.rootOf(root)
	if err != nil {
		return fmeta{}, err
	}
	name := "."
	if rel != "" {
		name = fromLogical(rel)
	}
	fi, err := r.Lstat(name)
	if err != nil {
		return fmeta{}, mapRootErr(err)
	}
	return metaOf(fi), nil
}

func (o *rootOpener) readlink(root, rel string) (string, error) {
	r, err := o.rootOf(root)
	if err != nil {
		return "", err
	}
	t, err := r.Readlink(fromLogical(rel))
	return t, mapRootErr(err)
}

func mapRootErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return err
	}
	if strings.Contains(err.Error(), "escapes") {
		return errEscape
	}
	return err
}

func metaOf(fi os.FileInfo) fmeta {
	m := fmeta{kind: kindOfMode(fi.Mode().Type()), size: fi.Size(), perm: fi.Mode().Perm(), mtime: fi.ModTime()}
	if fi.Mode().IsRegular() {
		m.kind = kindRegular
	}
	return m
}
