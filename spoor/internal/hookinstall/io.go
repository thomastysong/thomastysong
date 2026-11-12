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
}

// readFile reads path without following a symbolic link at the last path
// element and without holding the handle: agents rewrite these files and, on
// Windows, an open handle would make their rename fail.
func readFile(path string) fileState {
	li, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || isNotDir(err) {
			return fileState{}
		}
		return fileState{exists: true, refused: "cannot be inspected (" + errClass(err) + ")"}
	}
	st := fileState{exists: true}
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		st.refused = "is a symbolic link"
		return st
	case !li.Mode().IsRegular():
		st.refused = "is not a regular file"
		return st
	case li.Size() > maxFileSize:
		st.refused = "is larger than 4 MiB"
		return st
	}
	f, err := openNoFollow(path)
	if err != nil {
		st.refused = "cannot be opened (" + errClass(err) + ")"
		return st
	}
	defer f.Close()
	return readOpen(f, li, st)
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
func jsonSiblings(dir string) []string {
	const maxSiblings = 64
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
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
	sort.Strings(out)
	return out
}
