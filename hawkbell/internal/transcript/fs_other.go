//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const statLazy = false

// On platforms without openat and stable file ids the tailer still refuses
// symlinks, by checking each component with Lstat and confirming afterwards
// that the opened file is the one that was checked. File identity and owner
// are unknown, so replacement detection and the ownership check are
// unsupported here.
func lstatMeta(path string) (fileMeta, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileMeta{}, err
	}
	mode := fi.Mode()
	return fileMeta{
		size:    fi.Size(),
		mtime:   fi.ModTime().UnixNano(),
		symlink: mode&(os.ModeSymlink|os.ModeIrregular) != 0,
		regular: mode.IsRegular(),
		dir:     mode.IsDir(),
	}, nil
}

func openBeneath(base, rel string) (*os.File, fileMeta, error) {
	full := base
	if rel != "" {
		full = filepath.Join(base, rel)
		at := base
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for _, part := range parts[:len(parts)-1] {
			if part == "" || part == "." {
				continue
			}
			at = filepath.Join(at, part)
			if part == ".." {
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errors.New("path escapes its root")}
			}
			m, err := lstatMeta(at)
			if err != nil {
				return nil, fileMeta{}, err
			}
			if m.symlink || !m.dir {
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errSymlink}
			}
		}
	}
	before, err := os.Lstat(full)
	if err != nil {
		return nil, fileMeta{}, err
	}
	if before.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errSymlink}
	}
	if !before.Mode().IsRegular() {
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errNotRegular}
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, fileMeta{}, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		f.Close()
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errSymlink}
	}
	return f, fileMeta{size: after.Size(), mtime: after.ModTime().UnixNano(), regular: true}, nil
}

func ownerOK(m fileMeta, want string) bool { return true }
