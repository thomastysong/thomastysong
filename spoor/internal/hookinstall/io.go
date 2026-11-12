package hookinstall

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxFileSize bounds every file this package reads. Hook and settings files
// are a few kilobytes; anything near the cap is not one.
const maxFileSize = 4 << 20

// fileState is what is known about a file after one safe read.
type fileState struct {
	exists bool
	data   []byte
	// refused, when set, is why the file was not read: it is a symbolic
	// link, not a regular file, too large or not accessible.
	refused string
	// info is the file's lstat result and dir that of the directory that
	// holds it, when the file exists.
	info, dir os.FileInfo
}

// Refusal texts that callers test for.
const (
	refusedSymlink  = "is a symbolic link"
	refusedLinkPath = "is reached through a symbolic link or reparse point spoor does not follow"
)

// readFile reads path the way Apply reaches it: every directory from the
// file-system root (or from root, a host root) is opened one handle at a
// time, following only trusted links and none below root (see
// openDirChain), and the file is opened relative to the last one without
// following a link. A link that leads out of the tree being read therefore
// never makes this process read another file. The handle is not kept:
// agents rewrite these files and, on Windows, an open handle would make
// their rename fail.
//
// A path that is not absolute on this host (a plan rendered for another OS
// without a Root) reads as absent.
func readFile(path, root string) fileState {
	if !filepath.IsAbs(path) {
		return fileState{}
	}
	r, err := openDirChain(filepath.Dir(path), root, dirPolicy{})
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, errNotDir):
			return fileState{}
		case errors.Is(err, ErrSymlink):
			return fileState{exists: true, refused: refusedLinkPath}
		}
		return fileState{exists: true, refused: "cannot be reached (" + errClass(err) + ")"}
	}
	defer r.Close()
	return readAt(r, filepath.Base(path))
}

// readAt reads name in the pinned directory r without following a link.
func readAt(r *os.Root, name string) fileState {
	li, err := r.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || isNotDir(err) {
			return fileState{}
		}
		return fileState{exists: true, refused: "cannot be inspected (" + errClass(err) + ")"}
	}
	st := fileState{exists: true, info: li}
	st.dir, _ = r.Stat(".")
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		st.refused = refusedSymlink
		return st
	case !li.Mode().IsRegular():
		st.refused = "is not a regular file"
		return st
	case li.Size() > maxFileSize:
		st.refused = "is larger than 4 MiB"
		return st
	}
	f, err := r.OpenFile(name, readFlags, 0)
	if err != nil {
		st.refused = "cannot be opened (" + errClass(err) + ")"
		return st
	}
	defer f.Close()
	return readOpen(f, li, st)
}

// lstatIn returns the lstat result of path, reached the way readFile
// reaches it, or an error.
func lstatIn(path, root string) (os.FileInfo, error) {
	if !filepath.IsAbs(path) {
		return nil, fs.ErrNotExist
	}
	r, err := openDirChain(filepath.Dir(path), root, dirPolicy{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Lstat(filepath.Base(path))
}

// maxListed bounds how many entries of one directory are looked at. A
// configuration directory with more is not one.
const maxListed = 512

// listDir returns the entries of dir, reached the way readFile reaches a
// file, in name order. Entry types come from the directory itself: links
// are reported as links, not followed.
func listDir(dir, root string) []fs.DirEntry {
	if !filepath.IsAbs(dir) {
		return nil
	}
	r, err := openDirChain(dir, root, dirPolicy{})
	if err != nil {
		return nil
	}
	defer r.Close()
	f, err := r.Open(".")
	if err != nil {
		return nil
	}
	defer f.Close()
	ents, _ := f.ReadDir(maxListed)
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents
}

// readOpen finishes a read on an open handle after checking that it is the
// file that was examined (a swap between the two calls shows up here).
func readOpen(f *os.File, li os.FileInfo, st fileState) fileState {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		st.refused = "changed while it was being opened"
		return st
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		st.refused = "cannot be read (" + errClass(err) + ")"
		return st
	}
	if len(b) > maxFileSize {
		st.refused = "is larger than 4 MiB"
		return st
	}
	st.data = b
	return st
}

// errClass reduces an OS error to a short class. The full text would repeat
// a path that the reader of a Plan or State already has, and on some
// systems more than that.
func errClass(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrExist):
		return "already exists"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err.Error()
	}
	return "I/O error"
}

// jsonSiblings lists the regular *.json files of a drop-in directory in
// name order, without hidden files, the way Claude Code and Copilot CLI
// enumerate theirs. The list is capped: a directory with thousands of
// entries is not a policy directory.
func jsonSiblings(dir, root string) []string {
	const maxSiblings = 64
	var out []string
	for _, e := range listDir(dir, root) {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.EqualFold(filepath.Ext(name), ".json") {
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		out = append(out, filepath.Join(dir, name))
		if len(out) >= maxSiblings {
			break
		}
	}
	return out
}
